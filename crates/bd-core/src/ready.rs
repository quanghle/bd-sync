//! Deterministic ready-work calculation.
//!
//! An issue is ready iff it is `open`, not blocked (materialized flag), not
//! deferred (neither it nor any ancestor has status `deferred` or a future
//! `defer_until`), and not an epic (unless asked). Results are totally
//! ordered by the sort policy with `id` as the final tiebreaker, so the same
//! database state and clock always yield the same queue.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params_from_iter};
use serde::Serialize;

use crate::error::Result;
use crate::filter::{QueryParts, apply_work_filter, placeholders, text_values};
use crate::graph;
use crate::issues::{ISSUE_COLUMNS, issue_from_row};
use crate::model::{Blocker, GATE_TYPE, Issue, ReadyQuery, SortPolicy, Status, WorkFilter};
use crate::time::{Timestamp, format_duration_ms};

const HYBRID_WINDOW: Duration = Duration::from_secs(48 * 3600);

// The two seed selects are separate so each uses an index (status prefix of
// idx_issues_ready, partial idx_issues_deferral) instead of a table scan, and
// each step looks up the edges below one issue: plans fixed whatever the
// statistics say (see `graph`'s module docs).
const DEFERRED_CTE: &str = "deferred(id) AS (
    SELECT id FROM issues INDEXED BY idx_issues_ready WHERE status = 'deferred'
    UNION
    SELECT id FROM issues INDEXED BY idx_issues_deferral WHERE defer_until > ?
    UNION
    SELECT d.issue_id FROM deferred x CROSS JOIN dependencies d ON d.depends_on_id = x.id
    WHERE d.dep_type = 'parent-child')";

/// Cheap probe (two index lookups) so the deferred-subtree CTE is only built
/// when something is actually deferred.
fn any_deferred(conn: &Connection, now: Timestamp) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM issues WHERE status = 'deferred')
                 OR EXISTS (SELECT 1 FROM issues WHERE defer_until > ?1)",
        )?
        .query_row([now.millis()], |r| r.get(0))?)
}

pub fn ready(conn: &Connection, q: &ReadyQuery, now: Timestamp) -> Result<Vec<Issue>> {
    ready_for(conn, q, now, None)
}

/// Ready issues; with `claimant = Some((actor, pools))` only those the actor
/// may claim (unassigned, reserved for the actor, or held by a pool).
pub(crate) fn ready_for(
    conn: &Connection,
    q: &ReadyQuery,
    now: Timestamp,
    claimant: Option<(&str, &[String])>,
) -> Result<Vec<Issue>> {
    let mut parts = QueryParts::default();
    parts.cond("i.status = 'open'", []);
    parts.cond("i.is_blocked = 0", []);
    if !q.include_deferred && any_deferred(conn, now)? {
        parts.cte(DEFERRED_CTE, [SqlValue::Integer(now.millis())]);
        parts.cond("i.id NOT IN (SELECT id FROM deferred)", []);
    }
    if !q.include_epics && !q.filter.types.iter().any(|t| t == "epic") {
        parts.cond("i.issue_type <> 'epic'", []);
    }
    // Gates are wait conditions resolved by `bd gate`, never work to claim.
    if !q.filter.types.iter().any(|t| t == GATE_TYPE) {
        parts.cond("i.issue_type <> 'gate'", []);
    }
    apply_work_filter(&mut parts, &q.filter);
    if let Some((actor, pools)) = claimant {
        let mut cond = String::from("(i.assignee IS NULL OR i.assignee = ?");
        let mut params = vec![SqlValue::Text(actor.to_string())];
        if !pools.is_empty() {
            cond.push_str(&format!(" OR i.assignee IN {}", placeholders(pools.len())));
            params.extend(text_values(pools));
        }
        cond.push(')');
        parts.cond(&cond, params);
    }
    let mut tail_params = Vec::new();
    let mut tail = match q.sort {
        SortPolicy::Priority => "ORDER BY i.priority, i.created_at, i.id".to_string(),
        SortPolicy::Oldest => "ORDER BY i.created_at, i.id".to_string(),
        SortPolicy::Hybrid => {
            let cutoff = SqlValue::Integer(now.minus(HYBRID_WINDOW).millis());
            tail_params.push(cutoff.clone());
            tail_params.push(cutoff);
            "ORDER BY CASE WHEN i.created_at >= ? THEN 0 ELSE 1 END,
                      CASE WHEN i.created_at >= ? THEN i.priority ELSE 999 END,
                      i.created_at, i.id"
                .to_string()
        }
    };
    // A literal, not a parameter: SQLite (built with STAT4) plans with a bound
    // LIMIT's value, and so prepares the statement again each time it is bound,
    // which `claim --next` would pay on every claim.
    if let Some(n) = q.limit {
        tail.push_str(&format!(" LIMIT {}", i64::try_from(n).unwrap_or(i64::MAX)));
    }
    let (sql, params) = parts.build(&format!("SELECT {ISSUE_COLUMNS} FROM issues i"), &tail, tail_params);
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params_from_iter(params), issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The issue (itself or the nearest ancestor) whose deferral hides `id` from
/// the ready queue, if any.
pub fn deferral_source(conn: &Connection, id: &str, now: Timestamp) -> Result<Option<String>> {
    DeferralSources::new(now).get(conn, id)
}

/// [`deferral_source`] for many issues of one hierarchy: remembers the
/// answer for every issue on the way up, so asking for each issue of a
/// subtree costs one step per issue instead of one per ancestor.
pub(crate) struct DeferralSources {
    now: Timestamp,
    known: HashMap<String, Option<String>>,
}

impl DeferralSources {
    pub(crate) fn new(now: Timestamp) -> DeferralSources {
        DeferralSources { now, known: HashMap::new() }
    }

    pub(crate) fn get(&mut self, conn: &Connection, id: &str) -> Result<Option<String>> {
        let mut stmt = conn.prepare_cached("SELECT status, defer_until FROM issues WHERE id = ?1")?;
        // Up the parents until an issue whose answer is known or that is
        // deferred itself: every issue on the way has that answer. A parent
        // cycle (a damaged database) ends the climb with no answer.
        let mut path: Vec<String> = Vec::new();
        let mut on_path = HashSet::new();
        let mut cur = id.to_string();
        let found = loop {
            if let Some(known) = self.known.get(&cur) {
                break known.clone();
            }
            if !on_path.insert(cur.clone()) {
                break None;
            }
            let row: Option<(Status, Option<Timestamp>)> =
                stmt.query_row([&cur], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            if row.is_some_and(|(status, until)| status == Status::Deferred || until.is_some_and(|t| t > self.now)) {
                path.push(cur.clone());
                break Some(cur);
            }
            let parent = graph::parent_of(conn, &cur)?;
            path.push(cur);
            match parent {
                Some(p) => cur = p,
                None => break None,
            }
        };
        for issue in path {
            self.known.insert(issue, found.clone());
        }
        Ok(found)
    }
}

/// Human-readable reasons an open issue is not ready (empty = ready).
pub fn not_ready_reasons(conn: &Connection, issue: &Issue, now: Timestamp) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    if issue.status != Status::Open {
        reasons.push(format!("status is {}", issue.status));
    }
    for b in graph::blockers(conn, &issue.id)? {
        reasons.push(format!("blocked by {} ({})", b.id, b.detail));
    }
    if let Some(src) = deferral_source(conn, &issue.id, now)? {
        let until: Option<Timestamp> =
            conn.prepare_cached("SELECT defer_until FROM issues WHERE id = ?1")?.query_row([&src], |r| r.get(0))?;
        let what = if src == issue.id { "deferred".to_string() } else { format!("ancestor {src} is deferred") };
        match until.filter(|t| *t > now) {
            Some(t) => reasons.push(format!("{what} until {t} (in {})", format_duration_ms(t.since(now)))),
            None => reasons.push(what),
        }
    }
    Ok(reasons)
}

/// A blocked issue with the reasons it is blocked.
#[derive(Clone, Debug, Serialize)]
pub struct BlockedIssue {
    #[serde(flatten)]
    pub issue: Issue,
    pub blockers: Vec<Blocker>,
}

pub fn blocked(conn: &Connection, filter: &WorkFilter, limit: Option<usize>) -> Result<Vec<BlockedIssue>> {
    let mut parts = QueryParts::default();
    parts.cond("i.is_blocked = 1", []);
    parts.cond("i.status NOT IN ('closed','pinned')", []);
    apply_work_filter(&mut parts, filter);
    let mut tail = String::from("ORDER BY i.priority, i.created_at, i.id");
    let mut tail_params = Vec::new();
    if let Some(n) = limit {
        tail.push_str(" LIMIT ?");
        tail_params.push(SqlValue::Integer(n as i64));
    }
    let (sql, params) = parts.build(&format!("SELECT {ISSUE_COLUMNS} FROM issues i"), &tail, tail_params);
    let issues: Vec<Issue> = {
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params_from_iter(params), issue_from_row)?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    issues.into_iter().map(|issue| Ok(BlockedIssue { blockers: graph::blockers(conn, &issue.id)?, issue })).collect()
}

// The counts `bd prime` and `bd stats` print read the ready issues through
// idx_issues_ready, and the deferred ones by id, whatever the statistics say.
pub fn count_ready(conn: &Connection, now: Timestamp) -> Result<i64> {
    if !any_deferred(conn, now)? {
        return Ok(conn
            .prepare_cached(
                "SELECT COUNT(*) FROM issues INDEXED BY idx_issues_ready
                 WHERE status = 'open' AND is_blocked = 0 AND issue_type NOT IN ('epic','gate')",
            )?
            .query_row([], |r| r.get(0))?);
    }
    let sql = format!(
        "WITH RECURSIVE {DEFERRED_CTE}
         SELECT COUNT(*) FROM issues i INDEXED BY idx_issues_ready
         WHERE i.status = 'open' AND i.is_blocked = 0 AND i.issue_type NOT IN ('epic','gate')
           AND i.id NOT IN (SELECT id FROM deferred)"
    );
    Ok(conn.prepare_cached(&sql)?.query_row([now.millis()], |r| r.get(0))?)
}

pub fn count_deferred(conn: &Connection, now: Timestamp) -> Result<i64> {
    if !any_deferred(conn, now)? {
        return Ok(0);
    }
    let sql = format!(
        "WITH RECURSIVE {DEFERRED_CTE}
         SELECT COUNT(*) FROM issues i INDEXED BY sqlite_autoindex_issues_1
         WHERE i.status NOT IN ('closed','pinned') AND i.id IN (SELECT id FROM deferred)"
    );
    Ok(conn.prepare_cached(&sql)?.query_row([now.millis()], |r| r.get(0))?)
}
