//! Health checks and repairs.

use rusqlite::Connection;
use serde::Serialize;
use serde_json::json;

use crate::claims;
use crate::config;
use crate::error::Result;
use crate::graph;
use crate::schema;
use crate::store::{Store, WriteCtx};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub severity: Severity,
    pub detail: String,
    /// True when `--fix` repaired the problem.
    pub fixed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<Check>,
}

fn check(name: &'static str, severity: Severity, detail: impl Into<String>) -> Check {
    Check { name, severity, detail: detail.into(), fixed: false }
}

fn strings(conn: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn preview(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(10).map(String::as_str).collect();
    let more = items.len().saturating_sub(shown.len());
    if more > 0 { format!("{} (+{more} more)", shown.join(", ")) } else { shown.join(", ") }
}

/// Run every check; with `fix`, repair what can be repaired safely in one
/// transaction (missing/stray leases, blocked-flag drift). `full` runs
/// `PRAGMA integrity_check` instead of the faster `quick_check`.
pub fn diagnose(store: &mut Store, fix: bool, full: bool) -> Result<DoctorReport> {
    let mut checks = Vec::new();
    let conn = store.connection();

    let pragma = if full { "integrity_check" } else { "quick_check" };
    let integrity = strings(conn, &format!("PRAGMA {pragma}"))?;
    checks.push(if integrity == ["ok"] {
        check("sqlite_integrity", Severity::Ok, format!("{pragma}: ok"))
    } else {
        check("sqlite_integrity", Severity::Error, preview(&integrity))
    });

    let fk: Vec<String> = {
        let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
        let rows = stmt.query_map([], |r| {
            Ok(format!("{}:{}", r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0)))
        })?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    checks.push(if fk.is_empty() {
        check("foreign_keys", Severity::Ok, "no dangling references")
    } else {
        check("foreign_keys", Severity::Error, format!("{} dangling rows: {}", fk.len(), preview(&fk)))
    });

    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    checks.push(if mode.eq_ignore_ascii_case("wal") {
        check("journal_mode", Severity::Ok, "wal")
    } else {
        check("journal_mode", Severity::Error, format!("{mode} (expected wal)"))
    });

    let version = schema::user_version(conn)?;
    checks.push(if version == schema::LATEST_VERSION {
        check("schema_version", Severity::Ok, format!("v{version}"))
    } else {
        check("schema_version", Severity::Error, format!("v{version}, expected v{}", schema::LATEST_VERSION))
    });

    let bad_closed = strings(
        conn,
        "SELECT id FROM issues WHERE (status = 'closed') <> (closed_at IS NOT NULL)
            OR (status = 'in_progress' AND assignee IS NULL) ORDER BY id",
    )?;
    checks.push(if bad_closed.is_empty() {
        check("status_invariants", Severity::Ok, "closed_at and assignee consistent with status")
    } else {
        check("status_invariants", Severity::Error, preview(&bad_closed))
    });

    let missing_leases = strings(
        conn,
        "SELECT i.id FROM issues i LEFT JOIN leases l ON l.issue_id = i.id
         WHERE i.status = 'in_progress' AND l.issue_id IS NULL ORDER BY i.id",
    )?;
    let stray_leases = strings(
        conn,
        "SELECT l.issue_id FROM leases l JOIN issues i ON i.id = l.issue_id
         WHERE i.status <> 'in_progress' OR i.assignee IS NULL OR i.assignee <> l.holder ORDER BY l.issue_id",
    )?;
    let drift = graph::blocked_drift(conn)?;
    let drift_ids: Vec<String> = drift.iter().map(|d| d.id.clone()).collect();

    let cycles = graph::find_cycles(conn)?;
    let cycle_text: Vec<String> = cycles.iter().map(|c| c.join(" -> ")).collect();

    let (count, min, max): (i64, Option<i64>, Option<i64>) =
        conn.query_row("SELECT COUNT(*), MIN(seq), MAX(seq) FROM events", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    let gaps = match (min, max) {
        (Some(lo), Some(hi)) => (hi - lo + 1) - count,
        _ => 0,
    };

    let grace_ms = crate::time::duration_ms(config::lease_grace(conn)?);
    let now = store.now();
    let reclaimable = {
        let mut stmt = conn.prepare(
            "SELECT l.issue_id FROM leases l JOIN issues i ON i.id = l.issue_id
             WHERE i.status = 'in_progress' AND l.expires_at <= ?1 ORDER BY l.issue_id",
        )?;
        let rows = stmt.query_map([now.millis() - grace_ms], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut lease_check = if missing_leases.is_empty() {
        check("claims_have_leases", Severity::Ok, "every in_progress issue has a lease")
    } else {
        check("claims_have_leases", Severity::Error, format!("in_progress without lease: {}", preview(&missing_leases)))
    };
    let mut stray_check = if stray_leases.is_empty() {
        check("leases_match_claims", Severity::Ok, "every lease matches its claim")
    } else {
        check("leases_match_claims", Severity::Error, format!("stray leases: {}", preview(&stray_leases)))
    };
    let mut drift_check = if drift.is_empty() {
        check("blocked_state", Severity::Ok, "materialized is_blocked matches a full recompute")
    } else {
        check("blocked_state", Severity::Error, format!("{} drifted flags: {}", drift.len(), preview(&drift_ids)))
    };

    if fix && (!missing_leases.is_empty() || !stray_leases.is_empty() || !drift.is_empty()) {
        store.write("doctor", "doctor", |tx| {
            repair_leases(tx, &missing_leases, &stray_leases)?;
            graph::recompute_all(tx)?;
            Ok(())
        })?;
        for c in [&mut lease_check, &mut stray_check, &mut drift_check] {
            if c.severity != Severity::Ok {
                c.fixed = true;
            }
        }
    }
    checks.push(lease_check);
    checks.push(stray_check);
    checks.push(drift_check);

    checks.push(if cycles.is_empty() {
        check("dependency_cycles", Severity::Ok, "scheduling graph is acyclic")
    } else {
        check("dependency_cycles", Severity::Error, preview(&cycle_text))
    });
    checks.push(if gaps == 0 {
        check("event_sequence", Severity::Ok, format!("{count} events, contiguous"))
    } else {
        check("event_sequence", Severity::Error, format!("{gaps} missing sequence numbers between {min:?} and {max:?}"))
    });
    checks.push(if reclaimable.is_empty() {
        check("stale_leases", Severity::Ok, "no leases past the grace window")
    } else {
        check(
            "stale_leases",
            Severity::Warn,
            format!("{} lease(s) expired past grace (run `bd reclaim`): {}", reclaimable.len(), preview(&reclaimable)),
        )
    });

    let ok = checks.iter().all(|c| c.severity != Severity::Error || c.fixed);
    Ok(DoctorReport { ok, checks })
}

fn repair_leases(tx: &mut WriteCtx<'_>, missing: &[String], stray: &[String]) -> Result<()> {
    let ttl = config::lease_ttl(tx.conn())?;
    for id in stray {
        claims::delete_lease(tx.conn(), id)?;
    }
    for id in missing.iter().chain(stray.iter()) {
        let (status, assignee): (String, Option<String>) =
            tx.conn()
                .query_row("SELECT status, assignee FROM issues WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        if status == "in_progress"
            && let Some(holder) = assignee
        {
            let seq = tx.emit("lease_granted", Some(id), json!({ "reason": "doctor" }))?;
            let now = tx.now();
            claims::upsert_lease(tx.conn(), id, &holder, seq, now, ttl)?;
        }
    }
    Ok(())
}
