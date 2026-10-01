//! Workspace statistics and operational metrics (all computed locally from
//! the database; nothing is exported anywhere).

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use crate::config;
use crate::error::Result;
use crate::events;
use crate::ready;
use crate::schema;
use crate::time::Timestamp;

#[derive(Clone, Debug, Serialize)]
pub struct Stats {
    pub total: i64,
    pub by_status: BTreeMap<String, i64>,
    pub ready: i64,
    /// Live issues held back by dependencies (materialized flag).
    pub blocked: i64,
    /// Live issues hidden by a deferral (own or an ancestor's).
    pub deferred: i64,
    pub leases_active: i64,
    pub leases_expired: i64,
    /// Open epics whose children are all closed.
    pub closable_epics: Vec<String>,
}

pub fn stats(conn: &Connection, now: Timestamp) -> Result<Stats> {
    let mut by_status = BTreeMap::new();
    for s in crate::model::Status::ALL {
        by_status.insert(s.as_str().to_string(), 0);
    }
    let mut total = 0;
    {
        let mut stmt = conn.prepare_cached("SELECT status, COUNT(*) FROM issues GROUP BY status")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (s, n) = row?;
            total += n;
            by_status.insert(s, n);
        }
    }
    let blocked: i64 = conn
        .prepare_cached("SELECT COUNT(*) FROM issues WHERE is_blocked = 1 AND status NOT IN ('closed','pinned')")?
        .query_row([], |r| r.get(0))?;
    let (leases_active, leases_expired): (i64, i64) = conn
        .prepare_cached("SELECT COUNT(*), COALESCE(SUM(expires_at <= ?1), 0) FROM leases")?
        .query_row([now.millis()], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let closable_epics = {
        let mut stmt = conn.prepare_cached(
            "SELECT e.id FROM issues e
             WHERE e.issue_type = 'epic' AND e.status <> 'closed'
               AND EXISTS (SELECT 1 FROM dependencies d WHERE d.depends_on_id = e.id AND d.dep_type = 'parent-child')
               AND NOT EXISTS (SELECT 1 FROM dependencies d JOIN issues c ON c.id = d.issue_id
                               WHERE d.depends_on_id = e.id AND d.dep_type = 'parent-child' AND c.status <> 'closed')
             ORDER BY e.id",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(Stats {
        total,
        by_status,
        ready: ready::count_ready(conn, now)?,
        blocked,
        deferred: ready::count_deferred(conn, now)?,
        leases_active,
        leases_expired,
        closable_epics,
    })
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Percentiles {
    pub count: usize,
    pub p50_ms: Option<i64>,
    pub p90_ms: Option<i64>,
    pub p99_ms: Option<i64>,
    pub max_ms: Option<i64>,
}

impl Percentiles {
    pub fn from_samples(mut v: Vec<i64>) -> Self {
        if v.is_empty() {
            return Percentiles::default();
        }
        v.sort_unstable();
        let pick = |q: f64| v[(((v.len() - 1) as f64) * q).round() as usize];
        Percentiles {
            count: v.len(),
            p50_ms: Some(pick(0.50)),
            p90_ms: Some(pick(0.90)),
            p99_ms: Some(pick(0.99)),
            max_ms: v.last().copied(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaseHealth {
    pub active: i64,
    pub expired: i64,
    /// Expiring within 60 seconds.
    pub expiring_soon: i64,
    /// Expired for longer than `lease.grace`: `bd reclaim` would revert these.
    pub reclaimable: i64,
    pub oldest_heartbeat_age_ms: Option<i64>,
    pub max_renewals: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DbStats {
    pub schema_version: i64,
    pub journal_mode: String,
    pub page_size: i64,
    pub page_count: i64,
    pub freelist_count: i64,
    pub size_bytes: i64,
    pub wal_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Metrics {
    pub generated_at: Timestamp,
    pub stats: Stats,
    pub ready_by_priority: BTreeMap<String, i64>,
    pub leases: LeaseHealth,
    pub events_head: i64,
    pub events_floor: i64,
    pub events_retained: i64,
    /// Retained events by op (all time, within retention).
    pub ops_total: BTreeMap<String, i64>,
    pub ops_24h: BTreeMap<String, i64>,
    /// Durable counters: contention (claim_conflicts, cas_conflicts,
    /// lease_lost, not_owner), reclaims, slow_writes, auto_prunes.
    pub counters: BTreeMap<String, i64>,
    /// created -> closed, for issues closed in the last 30 days.
    pub lead_time: Percentiles,
    /// started -> closed, for issues closed in the last 30 days.
    pub cycle_time: Percentiles,
    /// created -> started, for issues started in the last 30 days.
    pub queue_wait: Percentiles,
    pub db: DbStats,
}

const DAY_MS: i64 = 86_400_000;

fn samples(conn: &Connection, sql: &str, since: i64) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map([since], |r| r.get::<_, i64>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn metrics(conn: &Connection, now: Timestamp, db_path: Option<&Path>) -> Result<Metrics> {
    let stats = stats(conn, now)?;
    let mut ready_by_priority = BTreeMap::new();
    for p in 0..=4 {
        ready_by_priority.insert(format!("p{p}"), 0);
    }
    for issue in ready::ready(conn, &Default::default(), now)? {
        *ready_by_priority.entry(format!("p{}", issue.priority)).or_insert(0) += 1;
    }
    let grace_ms = crate::time::duration_ms(config::lease_grace(conn)?);
    let leases = conn
        .prepare_cached(
            "SELECT COUNT(*),
                    COALESCE(SUM(expires_at <= ?1), 0),
                    COALESCE(SUM(expires_at > ?1 AND expires_at <= ?1 + 60000), 0),
                    COALESCE(SUM(expires_at <= ?1 - ?2), 0),
                    MIN(heartbeat_at),
                    COALESCE(MAX(renewals), 0)
             FROM leases",
        )?
        .query_row([now.millis(), grace_ms], |r| {
            Ok(LeaseHealth {
                active: r.get(0)?,
                expired: r.get(1)?,
                expiring_soon: r.get(2)?,
                reclaimable: r.get(3)?,
                oldest_heartbeat_age_ms: r.get::<_, Option<i64>>(4)?.map(|h| now.millis() - h),
                max_renewals: r.get(5)?,
            })
        })?;
    let ops_total: BTreeMap<String, i64> = events::op_counts(conn, None)?.into_iter().collect();
    let ops_24h: BTreeMap<String, i64> = events::op_counts(conn, Some(now.millis() - DAY_MS))?.into_iter().collect();
    let counters: BTreeMap<String, i64> = {
        let mut stmt = conn.prepare_cached(
            "SELECT name, value FROM counters WHERE name NOT IN ('issue_seq','events_prune_mark') ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let month_ago = now.millis() - 30 * DAY_MS;
    let lead_time = Percentiles::from_samples(samples(
        conn,
        "SELECT closed_at - created_at FROM issues WHERE status = 'closed' AND closed_at >= ?1",
        month_ago,
    )?);
    let cycle_time = Percentiles::from_samples(samples(
        conn,
        "SELECT closed_at - started_at FROM issues WHERE status = 'closed' AND started_at IS NOT NULL AND closed_at >= ?1",
        month_ago,
    )?);
    let queue_wait = Percentiles::from_samples(samples(
        conn,
        "SELECT started_at - created_at FROM issues WHERE started_at IS NOT NULL AND started_at >= ?1",
        month_ago,
    )?);
    let pragma = |name: &str| -> Result<i64> { Ok(conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?) };
    let page_size = pragma("page_size")?;
    let page_count = pragma("page_count")?;
    let db = DbStats {
        schema_version: schema::user_version(conn)?,
        journal_mode: conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
        page_size,
        page_count,
        freelist_count: pragma("freelist_count")?,
        size_bytes: page_size * page_count,
        wal_bytes: db_path.and_then(|p| {
            let mut wal = p.as_os_str().to_owned();
            wal.push("-wal");
            std::fs::metadata(wal).ok().map(|m| m.len())
        }),
    };
    let events_head = events::head(conn)?;
    let events_floor = events::floor(conn)?;
    Ok(Metrics {
        generated_at: now,
        stats,
        ready_by_priority,
        leases,
        events_head,
        events_floor,
        events_retained: (events_head - events_floor + 1).max(0),
        ops_total,
        ops_24h,
        counters,
        lead_time,
        cycle_time,
        queue_wait,
        db,
    })
}
