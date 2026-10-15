//! Deterministic ready-work calculation.
//!
//! An issue is ready iff it is `open`, not blocked (materialized flag), not
//! deferred (neither it nor any ancestor has status `deferred` or a future
//! `defer_until`), not waiting on its children, and not an epic (unless
//! asked). A parent's children come first, whatever its type: one with a
//! child that is not closed waits on its children, exactly when `bd close`
//! refuses to close it for them, so it is claimable with no children, or
//! again once every child has closed, to wrap it up (or with
//! `allow_blocked`). A spawner, which others wait on through a `waits-for`
//! edge, never waits on its children: it may finish before the work it
//! spawned, which the waits-for gate tracks. Waiting is no block: the
//! children are ready as before. Results are totally ordered by the sort
//! policy with `id` as the final tiebreaker, so the same database state and
//! clock always yield the same queue.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params_from_iter};
use serde::Serialize;

use crate::claims;
use crate::error::Result;
use crate::filter::{QueryParts, apply_work_filter, placeholders, text_values};
use crate::gates;
use crate::graph;
use crate::issues::{self, ISSUE_COLUMNS, issue_from_row};
use crate::model::{Blocker, BlockerKind, GATE_TYPE, Issue, ReadyQuery, SortPolicy, Status, WorkFilter};
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

/// Issue `i` waits on its children (see the module docs): it has a child
/// that is not closed, and no `waits-for` edge on it, as `bd close` checks
/// them. Index lookups of the edges below `i` and of each child, whatever the
/// statistics say; an issue without children needs only the first.
const WAITS_ON_CHILDREN: &str = "(EXISTS (
    SELECT 1 FROM dependencies d CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
    WHERE d.depends_on_id = i.id AND d.dep_type = 'parent-child' AND c.status <> 'closed')
  AND NOT EXISTS (SELECT 1 FROM dependencies w WHERE w.depends_on_id = i.id AND w.dep_type = 'waits-for'))";

/// Children of a parent named in its not-ready reason; the rest are counted.
const CHILDREN_SHOWN: usize = 5;

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
    parts.cond(&format!("NOT {WAITS_ON_CHILDREN}"), []);
    if !q.include_deferred && any_deferred(conn, now)? {
        parts.cte(DEFERRED_CTE, [SqlValue::Integer(now.millis())]);
        parts.cond("i.id NOT IN (SELECT id FROM deferred)", []);
    }
    type_rules(&mut parts, q);
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
    if let Some(n) = q.limit {
        tail.push_str(" LIMIT ?");
        tail_params.push(SqlValue::Integer(i64::try_from(n).unwrap_or(i64::MAX)));
    }
    let (sql, params) = parts.build(&format!("SELECT {ISSUE_COLUMNS} FROM issues i"), &tail, tail_params);
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params_from_iter(params), issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Epics are left out unless asked for; gates, wait conditions resolved by
/// `bd gate`, unless `-t gate` asks for them: never work to claim.
fn type_rules(parts: &mut QueryParts, q: &ReadyQuery) {
    if !q.include_epics && !q.filter.types.iter().any(|t| t == "epic") {
        parts.cond("i.issue_type <> 'epic'", []);
    }
    if !q.filter.types.iter().any(|t| t == GATE_TYPE) {
        parts.cond("i.issue_type <> 'gate'", []);
    }
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

/// One reason an issue is not in the ready queue, as [`explain`] finds it.
/// A lease is described by its holder and expiry, never its token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotReady {
    /// Only `open` issues are ready.
    Status { status: Status },
    /// A lease on the issue: `live` until it expires, `reclaimable` once
    /// `lease.grace` has passed since.
    Claimed { holder: String, expires_at: Timestamp, live: bool, reclaimable: bool },
    /// What blocks it (see [`graph::blockers`]); `gate` names a `waits-for`
    /// edge's gate, or the kind of a gate issue that `blocks` it.
    Blocked {
        id: String,
        title: String,
        status: Status,
        via: BlockerKind,
        detail: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        gate: Option<String>,
    },
    /// Deferred, itself (`source` is the issue) or through an ancestor;
    /// `until` when the deferral has an end still to come.
    Deferred {
        source: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        until: Option<Timestamp>,
    },
    /// Its children come first: `open` of them are not closed, the first
    /// few listed.
    WaitsOnChildren { open: usize, children: Vec<OpenChild> },
    /// Epics and gates are left out of the ready queue unless asked for.
    ExcludedType { issue_type: String },
}

/// A child that is not closed, as a parent's [`NotReady::WaitsOnChildren`] names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OpenChild {
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
}

impl NotReady {
    /// The reason in words, for the issue `id`. The kinds that
    /// [`not_ready_reasons`] reports read exactly as they always have.
    pub fn text(&self, id: &str, now: Timestamp) -> String {
        match self {
            NotReady::Status { status } => format!("status is {status}"),
            NotReady::Claimed { holder, expires_at, live: true, .. } => {
                format!(
                    "claimed by {holder} (lease expires {expires_at}, in {})",
                    format_duration_ms(expires_at.since(now))
                )
            }
            NotReady::Claimed { holder, expires_at, reclaimable, .. } => {
                let then = if *reclaimable { "reclaimable" } else { "reclaimable once lease.grace passes" };
                format!("claimed by {holder} (lease expired {expires_at}, {then})")
            }
            NotReady::Blocked { id: blocker, detail, .. } => format!("blocked by {blocker} ({detail})"),
            NotReady::Deferred { source, until } => {
                let what = if source == id { "deferred".to_string() } else { format!("ancestor {source} is deferred") };
                match until.filter(|t| *t > now) {
                    Some(t) => format!("{what} until {t} (in {})", format_duration_ms(t.since(now))),
                    None => what,
                }
            }
            NotReady::WaitsOnChildren { open, children } => {
                let mut shown: Vec<String> = children
                    .iter()
                    .map(|c| match (c.status, &c.assignee) {
                        (Status::InProgress, Some(a)) => format!("{} claimed by {a}", c.id),
                        (s, Some(a)) => format!("{} {s}, assigned to {a}", c.id),
                        (s, None) => format!("{} {s}", c.id),
                    })
                    .collect();
                if *open > children.len() {
                    shown.push(format!("{} more", open - children.len()));
                }
                let are = if *open == 1 { "is" } else { "are" };
                format!(
                    "its children come first, and {open} {are} open ({}): claim one of them (`bd claim --next --parent {id}`)",
                    shown.join(", ")
                )
            }
            NotReady::ExcludedType { issue_type } if issue_type == GATE_TYPE => {
                format!("a gate: it opens through bd gate check or bd gate resolve {id}, never as ready work")
            }
            NotReady::ExcludedType { .. } => {
                "epics are left out of the ready queue (--include-epics or -t epic)".into()
            }
        }
    }
}

/// What [`explain`] counts as a reason: the ready queue's own options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExplainOptions {
    /// Deferral is no reason (`bd ready --include-deferred`).
    pub include_deferred: bool,
    /// Being an epic is no reason (`--include-epics`, `-t epic`).
    pub include_epics: bool,
    /// Being a gate is no reason (`-t gate`).
    pub include_gates: bool,
}

/// Whether an issue is ready and, if not, why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub id: String,
    pub ready: bool,
    pub reasons: Vec<NotReady>,
}

/// Every reason `issue` is not in the ready queue (empty = ready), from a few
/// index lookups on it, its edges and its ancestors: the predicates
/// `graph::recompute` uses, read with the stored blocked flags of parents,
/// never a recompute. In order: status, lease, blockers, deferral, children,
/// type.
pub fn explain(conn: &Connection, issue: &Issue, now: Timestamp, opts: ExplainOptions) -> Result<Vec<NotReady>> {
    let mut reasons = Vec::new();
    if issue.status != Status::Open {
        reasons.push(NotReady::Status { status: issue.status });
    }
    if let Some(lease) = claims::get_lease(conn, &issue.id)? {
        reasons.push(NotReady::Claimed {
            live: !lease.is_expired(now),
            reclaimable: claims::is_reclaimable(conn, &lease, now)?,
            holder: lease.holder,
            expires_at: lease.expires_at,
        });
    }
    for b in graph::blockers(conn, &issue.id)? {
        let gate = match b.kind {
            BlockerKind::WaitsFor => Some(
                graph::load_edge(conn, &issue.id, &b.id)?
                    .and_then(|e| e.metadata.get("gate").and_then(|g| g.as_str()).map(String::from))
                    .unwrap_or_else(|| "all-children".into()),
            ),
            BlockerKind::Blocks => issues::get(conn, &b.id)?
                .filter(|t| t.issue_type == GATE_TYPE)
                .and_then(|t| gates::spec_of(&t).ok())
                .map(|s| s.kind.as_str().to_string()),
            BlockerKind::Conditional | BlockerKind::Parent => None,
        };
        reasons.push(NotReady::Blocked {
            id: b.id,
            title: b.title,
            status: b.status,
            via: b.kind,
            detail: b.detail,
            gate,
        });
    }
    if !opts.include_deferred
        && let Some(source) = deferral_source(conn, &issue.id, now)?
    {
        let until: Option<Timestamp> =
            conn.prepare_cached("SELECT defer_until FROM issues WHERE id = ?1")?.query_row([&source], |r| r.get(0))?;
        reasons.push(NotReady::Deferred { source, until: until.filter(|t| *t > now) });
    }
    let open = open_children(conn, &issue.id)?;
    if !open.is_empty() && graph::waiters_on(conn, &issue.id)?.is_empty() {
        let count = open.len();
        let children = open
            .into_iter()
            .take(CHILDREN_SHOWN)
            .map(|(id, status, assignee)| OpenChild { id, status, assignee })
            .collect();
        reasons.push(NotReady::WaitsOnChildren { open: count, children });
    }
    let excluded = match issue.issue_type.as_str() {
        "epic" => !opts.include_epics,
        GATE_TYPE => !opts.include_gates,
        _ => false,
    };
    if excluded {
        reasons.push(NotReady::ExcludedType { issue_type: issue.issue_type.clone() });
    }
    Ok(reasons)
}

/// Human-readable reasons an issue is not ready to claim (empty = ready):
/// [`explain`]'s status, blockers, deferral and children, in words. A lease
/// or a type is no such reason: claiming checks those itself.
pub fn not_ready_reasons(conn: &Connection, issue: &Issue, now: Timestamp) -> Result<Vec<String>> {
    Ok(explain(conn, issue, now, ExplainOptions::default())?
        .into_iter()
        .filter(|r| !matches!(r, NotReady::Claimed { .. } | NotReady::ExcludedType { .. }))
        .map(|r| r.text(&issue.id, now))
        .collect())
}

/// Open issues that are not ready, by priority, then age, then id: blocked,
/// waiting on their children or (unless `q.include_deferred`) deferred, with
/// `q`'s filters and the ready queue's rules for epics and gates. One query;
/// [`explain`] says why for each.
pub fn not_ready(conn: &Connection, q: &ReadyQuery, now: Timestamp) -> Result<Vec<Issue>> {
    let mut parts = QueryParts::default();
    parts.cond("i.status = 'open'", []);
    let mut why = format!("(i.is_blocked = 1 OR {WAITS_ON_CHILDREN}");
    if !q.include_deferred && any_deferred(conn, now)? {
        parts.cte(DEFERRED_CTE, [SqlValue::Integer(now.millis())]);
        why.push_str(" OR i.id IN (SELECT id FROM deferred)");
    }
    why.push(')');
    parts.cond(&why, []);
    type_rules(&mut parts, q);
    apply_work_filter(&mut parts, &q.filter);
    let mut tail = String::from("ORDER BY i.priority, i.created_at, i.id");
    let mut tail_params = Vec::new();
    if let Some(n) = q.limit {
        tail.push_str(" LIMIT ?");
        tail_params.push(SqlValue::Integer(i64::try_from(n).unwrap_or(i64::MAX)));
    }
    let (sql, params) = parts.build(&format!("SELECT {ISSUE_COLUMNS} FROM issues i"), &tail, tail_params);
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params_from_iter(params), issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Why a ready issue sits where it does in the queue under `sort`: the keys
/// it is ordered by (the id breaks ties).
pub fn order_key(issue: &Issue, sort: SortPolicy, now: Timestamp) -> String {
    let created = issue.created_at;
    match sort {
        SortPolicy::Priority => format!("P{}, created {created}", issue.priority),
        SortPolicy::Oldest => format!("created {created}"),
        SortPolicy::Hybrid if created >= now.minus(HYBRID_WINDOW) => {
            format!("recent (last 48h): P{}, created {created}", issue.priority)
        }
        SortPolicy::Hybrid => format!("older: created {created}"),
    }
}

/// The children of `id` that are not closed, by id, with their status and
/// assignee: what makes a parent wait on its children (unless it is a spawner).
fn open_children(conn: &Connection, id: &str) -> Result<Vec<(String, Status, Option<String>)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT c.id, c.status, c.assignee
         FROM dependencies d CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' AND c.status <> 'closed'
         ORDER BY c.id",
    )?;
    let rows = stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Whether `id` waits on its children (see the module docs), so that it is not ready.
pub(crate) fn waits_on_children(conn: &Connection, id: &str) -> Result<bool> {
    Ok(!open_children(conn, id)?.is_empty() && graph::waiters_on(conn, id)?.is_empty())
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

// The counts `bd prime` and `bd stats` print read the open issues through
// idx_issues_ready, the deferred ones by id, and the children of each by
// index, whatever the statistics say.
pub fn count_ready(conn: &Connection, now: Timestamp) -> Result<i64> {
    count_work(conn, now, &format!("NOT {WAITS_ON_CHILDREN}"))
}

/// Issues that would be ready but wait on their children (see the module docs).
pub fn count_waiting(conn: &Connection, now: Timestamp) -> Result<i64> {
    count_work(conn, now, WAITS_ON_CHILDREN)
}

/// Open, unblocked and undeferred issues, epics and gates aside, that meet `cond` too.
fn count_work(conn: &Connection, now: Timestamp, cond: &str) -> Result<i64> {
    let work = "i.status = 'open' AND i.is_blocked = 0 AND i.issue_type NOT IN ('epic','gate')";
    if !any_deferred(conn, now)? {
        let sql = format!("SELECT COUNT(*) FROM issues i INDEXED BY idx_issues_ready WHERE {work} AND {cond}");
        return Ok(conn.prepare_cached(&sql)?.query_row([], |r| r.get(0))?);
    }
    let sql = format!(
        "WITH RECURSIVE {DEFERRED_CTE}
         SELECT COUNT(*) FROM issues i INDEXED BY idx_issues_ready
         WHERE {work} AND i.id NOT IN (SELECT id FROM deferred) AND {cond}"
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
