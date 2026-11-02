//! Typed dependency graph and the materialized `is_blocked` state.
//!
//! An issue is blocked iff it is not terminal (closed/pinned) and at least one
//! of these holds:
//! * a `blocks` edge points at a non-terminal issue;
//! * a `conditional-blocks` edge points at an issue that has not closed with
//!   outcome `failed` (the dependent is an error path);
//! * a `waits-for` gate is shut: the spawner still has live children (gate
//!   `all-children`, the default) or has live children and none closed yet
//!   (gate `any-children`), or `also_blocks` is set and the spawner is live;
//! * its parent (via `parent-child`) is blocked — blocking flows down the
//!   hierarchy, never up.
//!
//! The flag is recomputed inside the same transaction as every mutation that
//! can change it, for the affected issues and their subtrees, down to the
//! terminal, unblocked issues there (whose flag, all their children see of
//! them, cannot change).
//!
//! Query plans: queries run once per issue of a walk (recomputing a subtree,
//! a tree's edges, blockers, descendants, ...) fix their plan instead of
//! leaving it to the planner. bd keeps no planner statistics (see `store`),
//! but statistics recorded anyway (`ANALYZE` run by hand, or an older bd's
//! `PRAGMA optimize`) can be badly stale: taken while a young workspace held
//! an issue or two, and kept by a long-lived connection (`bd serve`'s) until
//! it opens the database again. Believing a table holds a row, SQLite scans
//! all of it per lookup, and the walk turns quadratic. Such a query starts
//! from the edges, its `CROSS JOIN`s keeping the tables in the order written,
//! and reaches every issue by its id through `issues INDEXED BY
//! sqlite_autoindex_issues_1` (the primary key's index). `tests/plans.rs`
//! checks the plans of what the walks prepare under stale statistics.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::{Blocker, BlockerKind, DepType, Dependency, Edge, Status, empty_object};
use crate::store::WriteCtx;
use crate::time::Timestamp;

const WAITS_GATE_SHUT: &str = "(
    (EXISTS (SELECT 1 FROM dependencies c
             CROSS JOIN issues ci INDEXED BY sqlite_autoindex_issues_1 ON ci.id = c.issue_id
             WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
               AND ci.status NOT IN ('closed','pinned'))
     AND NOT (COALESCE(json_extract(w.metadata, '$.gate'), 'all-children') = 'any-children'
              AND EXISTS (SELECT 1 FROM dependencies c
                          CROSS JOIN issues ci INDEXED BY sqlite_autoindex_issues_1 ON ci.id = c.issue_id
                          WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
                            AND ci.status = 'closed')))
    OR (json_extract(w.metadata, '$.also_blocks') IN (1, 'true') AND s.status NOT IN ('closed','pinned'))
)";

fn direct_block_predicate(alias: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM dependencies d
                  CROSS JOIN issues t INDEXED BY sqlite_autoindex_issues_1 ON t.id = d.depends_on_id
                  WHERE d.issue_id = {a}.id AND d.dep_type = 'blocks'
                    AND t.status NOT IN ('closed','pinned'))
          OR EXISTS (SELECT 1 FROM dependencies d
                  CROSS JOIN issues t INDEXED BY sqlite_autoindex_issues_1 ON t.id = d.depends_on_id
                  WHERE d.issue_id = {a}.id AND d.dep_type = 'conditional-blocks'
                    AND NOT (t.status = 'closed' AND t.close_outcome = 'failed'))
          OR EXISTS (SELECT 1 FROM dependencies w
                  CROSS JOIN issues s INDEXED BY sqlite_autoindex_issues_1 ON s.id = w.depends_on_id
                  WHERE w.issue_id = {a}.id AND w.dep_type = 'waits-for' AND {gate}))",
        a = alias,
        gate = WAITS_GATE_SHUT
    )
}

fn should_block_sql() -> String {
    format!(
        "SELECT CASE WHEN i.status IN ('closed','pinned') THEN 0 ELSE (
            {direct}
            OR EXISTS (SELECT 1 FROM dependencies d
                       CROSS JOIN issues p INDEXED BY sqlite_autoindex_issues_1 ON p.id = d.depends_on_id
                       WHERE d.issue_id = i.id AND d.dep_type = 'parent-child' AND p.is_blocked = 1)
         ) END
         FROM issues i WHERE i.id = ?1",
        direct = direct_block_predicate("i")
    )
}

/// The blocked set computed from scratch, propagating through the hierarchy
/// recursively instead of reading stored parent flags. Used to verify and
/// repair the incrementally maintained column.
fn full_blocked_sql() -> String {
    format!(
        "WITH RECURSIVE direct(id) AS (
             SELECT i.id FROM issues i
             WHERE i.status NOT IN ('closed','pinned') AND {direct}
         ),
         blocked(id) AS (
             SELECT id FROM direct
             UNION
             SELECT d.issue_id FROM blocked b
             CROSS JOIN dependencies d ON d.depends_on_id = b.id
             CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
             WHERE d.dep_type = 'parent-child' AND c.status NOT IN ('closed','pinned')
         )
         SELECT id FROM blocked",
        direct = direct_block_predicate("i")
    )
}

/// A change of an issue's materialized blocked flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlockChange {
    pub id: String,
    pub blocked: bool,
}

pub(crate) fn should_block(conn: &Connection, id: &str) -> Result<bool> {
    let sql = should_block_sql();
    Ok(conn.prepare_cached(&sql)?.query_row([id], |r| r.get::<_, i64>(0)).optional()?.unwrap_or(0) != 0)
}

pub fn full_blocked_set(conn: &Connection) -> Result<BTreeSet<String>> {
    let sql = full_blocked_sql();
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Stored flags that disagree with a from-scratch computation.
pub fn blocked_drift(conn: &Connection) -> Result<Vec<BlockChange>> {
    let truth = full_blocked_set(conn)?;
    let mut stmt = conn.prepare_cached("SELECT id, is_blocked FROM issues ORDER BY id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?;
    let mut drift = Vec::new();
    for row in rows {
        let (id, stored) = row?;
        let want = truth.contains(&id);
        if want != stored {
            drift.push(BlockChange { id, blocked: want });
        }
    }
    Ok(drift)
}

fn children(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child' ORDER BY issue_id",
    )?;
    let rows = stmt.query_map([id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn parent_of(conn: &Connection, id: &str) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached(
            "SELECT depends_on_id FROM dependencies WHERE issue_id = ?1 AND dep_type = 'parent-child'
             ORDER BY depends_on_id LIMIT 1",
        )?
        .query_row([id], |r| r.get(0))
        .optional()?)
}

pub(crate) fn ancestors(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = id.to_string();
    while let Some(p) = parent_of(conn, &cur)? {
        if !seen.insert(p.clone()) {
            break;
        }
        out.push(p.clone());
        cur = p;
    }
    Ok(out)
}

/// `ancestors(id).len()` for each of `ids`, in one pass: walks up from each id
/// only until an issue whose depth is already known, so ids sharing a chain
/// cost one parent lookup per issue in the chain rather than one per id and
/// ancestor.
pub(crate) fn depths(conn: &Connection, ids: &[String]) -> Result<Vec<usize>> {
    let mut known: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(&d) = known.get(id) {
            out.push(d);
            continue;
        }
        let mut path = vec![id.clone()];
        let mut on_path: HashSet<String> = HashSet::from([id.clone()]);
        let mut cur = id.clone();
        // Depth of the last issue on `path`: 0 for a root, else one below a known issue.
        let mut base = Some(0);
        while let Some(p) = parent_of(conn, &cur)? {
            if let Some(&d) = known.get(&p) {
                base = Some(d + 1);
                break;
            }
            if !on_path.insert(p.clone()) {
                // A cycle: no depth to share; count it the way `ancestors` does.
                base = None;
                break;
            }
            path.push(p.clone());
            cur = p;
        }
        match base {
            Some(base) => {
                let n = path.len();
                for (i, node) in path.into_iter().enumerate() {
                    known.insert(node, base + (n - 1 - i));
                }
                out.push(known[id]);
            }
            None => out.push(ancestors(conn, id)?.len()),
        }
    }
    Ok(out)
}

pub(crate) fn waiters_on(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare_cached("SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'waits-for'")?;
    let rows = stmt.query_map([id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Issues whose blocked state may change when `id` becomes (non-)terminal.
pub(crate) fn seeds_for_terminal_flip(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut seeds = vec![id.to_string()];
    let mut stmt = conn.prepare_cached(
        "SELECT issue_id FROM dependencies
         WHERE depends_on_id = ?1 AND dep_type IN ('blocks','conditional-blocks','waits-for')",
    )?;
    for row in stmt.query_map([id], |r| r.get::<_, String>(0))? {
        seeds.push(row?);
    }
    if let Some(parent) = parent_of(conn, id)? {
        seeds.extend(waiters_on(conn, &parent)?);
    }
    Ok(seeds)
}

/// Issues whose blocked state may change when an edge is added or removed.
pub(crate) fn seeds_for_edge(conn: &Connection, issue: &str, target: &str, dep_type: &DepType) -> Result<Vec<String>> {
    if !dep_type.affects_ready() {
        return Ok(Vec::new());
    }
    let mut seeds = vec![issue.to_string()];
    if *dep_type == DepType::ParentChild {
        seeds.extend(waiters_on(conn, target)?);
    }
    Ok(seeds)
}

/// Recompute `is_blocked` for `seeds` and their descendants, inside the
/// caller's transaction. Emits `blocked` / `unblocked` events for net changes
/// on live issues and returns them.
pub(crate) fn recompute(ctx: &mut WriteCtx<'_>, seeds: Vec<String>) -> Result<Vec<BlockChange>> {
    recompute_above(ctx, seeds, None)
}

/// [`recompute`], without descending below `settled`: an issue that just
/// turned terminal with nothing live below it, so every issue there is
/// terminal, unblocked, and stays so. Keeps a run closing up a deep chain of
/// groups linear.
pub(crate) fn recompute_above(
    ctx: &mut WriteCtx<'_>,
    seeds: Vec<String>,
    settled: Option<&str>,
) -> Result<Vec<BlockChange>> {
    let changes = settle(ctx.conn(), seeds, settled)?;
    publish(ctx, changes)
}

/// [`recompute`] for `seeds` when the subtree below `current`, a child of an
/// issue among them, is up to date but for what the seeds change: an issue
/// there can only flip if one of the seeds inside it does, or `current`
/// does. Unless one of them flips, nothing below `current` is visited, and
/// the changes and their events are exactly [`recompute`]'s: the other
/// issues are visited in the same order. Otherwise it recomputes in full.
/// Keeps a reopen cascading up a deep chain of groups linear.
pub(crate) fn recompute_beside(ctx: &mut WriteCtx<'_>, seeds: Vec<String>, current: &str) -> Result<Vec<BlockChange>> {
    let conn = ctx.conn();
    let mut changes = settle(conn, seeds.clone(), Some(current))?;
    let mut descend = false;
    for (c, _) in &changes {
        if c.id == current || (seeds.contains(&c.id) && is_below(conn, &c.id, current)?) {
            descend = true;
            break;
        }
    }
    if descend {
        let mut undo = conn.prepare_cached("UPDATE issues SET is_blocked = ?1 WHERE id = ?2")?;
        for (c, _) in &changes {
            undo.execute(params![!c.blocked as i64, c.id])?;
        }
        drop(undo);
        changes = settle(conn, seeds, None)?;
    }
    publish(ctx, changes)
}

/// Whether `id` is a descendant of `ancestor`. Stops at `ancestor`'s parent:
/// the hierarchy has no cycles, so nothing above it is below `ancestor`.
fn is_below(conn: &Connection, id: &str, ancestor: &str) -> Result<bool> {
    let stop = parent_of(conn, ancestor)?;
    let mut seen = HashSet::new();
    let mut cur = id.to_string();
    while Some(&cur) != stop.as_ref() && seen.insert(cur.clone()) {
        match parent_of(conn, &cur)? {
            Some(p) if p == ancestor => return Ok(true),
            Some(p) => cur = p,
            None => break,
        }
    }
    Ok(false)
}

/// Brings `is_blocked` up to date for `seeds` and their descendants (not
/// below `stop`). Returns the net changes, in visiting order, with each
/// issue's status.
fn settle(conn: &Connection, seeds: Vec<String>, stop: Option<&str>) -> Result<Vec<(BlockChange, Status)>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }
    // BFS from the seeds down the hierarchy: parents precede children, so
    // one pass usually converges; the loop below guarantees a fixpoint.
    //
    // A terminal issue below the seeds that is unblocked stays so (terminal
    // issues never block), and its children see only that flag: the walk
    // stops there. Closing a chain bottom-up then costs one step per close,
    // not one per issue already closed below it.
    let seed_set: HashSet<String> = seeds.iter().cloned().collect();
    let mut order: Vec<String> = Vec::new();
    let mut state: HashMap<String, (bool, Status)> = HashMap::new();
    let mut queue: VecDeque<String> = seeds.into_iter().collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut load = conn.prepare_cached("SELECT is_blocked, status FROM issues WHERE id = ?1")?;
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some((blocked, status)) =
            load.query_row([&id], |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, Status>(1)?))).optional()?
        else {
            continue;
        };
        if !blocked && status.is_terminal() && !seed_set.contains(&id) {
            continue;
        }
        state.insert(id.clone(), (blocked, status));
        if stop != Some(id.as_str()) {
            queue.extend(children(conn, &id)?);
        }
        order.push(id);
    }
    drop(load);
    let original: HashMap<String, bool> = state.iter().map(|(k, v)| (k.clone(), v.0)).collect();
    let mut update = conn.prepare_cached("UPDATE issues SET is_blocked = ?1 WHERE id = ?2")?;
    for _round in 0..=order.len() {
        let mut changed = false;
        for id in &order {
            let want = should_block(conn, id)?;
            let entry = state.get_mut(id).expect("loaded above");
            if entry.0 != want {
                update.execute(params![want as i64, id])?;
                entry.0 = want;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    drop(update);
    let mut changes = Vec::new();
    for id in order {
        let (now_blocked, status) = state[&id];
        if original[&id] != now_blocked {
            changes.push((BlockChange { id, blocked: now_blocked }, status));
        }
    }
    Ok(changes)
}

/// Emits `blocked` / `unblocked` events for `changes` on live issues and
/// arms or disarms the gates among them.
fn publish(ctx: &mut WriteCtx<'_>, changes: Vec<(BlockChange, Status)>) -> Result<Vec<BlockChange>> {
    let mut out = Vec::with_capacity(changes.len());
    for (change, status) in changes {
        if !status.is_terminal() {
            let op = if change.blocked { "blocked" } else { "unblocked" };
            ctx.emit(op, Some(&change.id), json!({}))?;
        }
        out.push(change);
    }
    crate::gates::note_block_changes(ctx, &out)?;
    Ok(out)
}

/// Rebuild every flag from scratch (repair path for `doctor --fix`).
pub(crate) fn recompute_all(ctx: &mut WriteCtx<'_>) -> Result<Vec<BlockChange>> {
    let drift = blocked_drift(ctx.conn())?;
    for change in &drift {
        ctx.conn()
            .prepare_cached("UPDATE issues SET is_blocked = ?1 WHERE id = ?2")?
            .execute(params![change.blocked as i64, change.id])?;
        let status: Status = ctx
            .conn()
            .prepare_cached("SELECT status FROM issues WHERE id = ?1")?
            .query_row([&change.id], |r| r.get(0))?;
        if !status.is_terminal() {
            let op = if change.blocked { "blocked" } else { "unblocked" };
            ctx.emit(op, Some(&change.id), json!({ "repair": true }))?;
        }
    }
    crate::gates::note_block_changes(ctx, &drift)?;
    Ok(drift)
}

/// Explain why `id` is blocked (empty when it is not). Its queries fix their
/// plan (see the module docs), so callers can ask once per issue of a large
/// hierarchy.
pub fn blockers(conn: &Connection, id: &str) -> Result<Vec<Blocker>> {
    let status: Option<Status> =
        conn.prepare_cached("SELECT status FROM issues WHERE id = ?1")?.query_row([id], |r| r.get(0)).optional()?;
    match status {
        None => return Err(Error::not_found("issue", id)),
        Some(s) if s.is_terminal() => return Ok(Vec::new()),
        _ => {}
    }
    let mut out = Vec::new();
    {
        let mut stmt = conn.prepare_cached(
            "SELECT t.id, t.title, t.status FROM dependencies d
             CROSS JOIN issues t INDEXED BY sqlite_autoindex_issues_1 ON t.id = d.depends_on_id
             WHERE d.issue_id = ?1 AND d.dep_type = 'blocks' AND t.status NOT IN ('closed','pinned')
             ORDER BY t.id",
        )?;
        for row in
            stmt.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Status>(2)?)))?
        {
            let (bid, title, st) = row?;
            out.push(Blocker {
                id: bid,
                title,
                status: st,
                kind: BlockerKind::Blocks,
                detail: format!("blocker is {st}"),
            });
        }
    }
    {
        let mut stmt = conn.prepare_cached(
            "SELECT t.id, t.title, t.status FROM dependencies d
             CROSS JOIN issues t INDEXED BY sqlite_autoindex_issues_1 ON t.id = d.depends_on_id
             WHERE d.issue_id = ?1 AND d.dep_type = 'conditional-blocks'
               AND NOT (t.status = 'closed' AND t.close_outcome = 'failed')
             ORDER BY t.id",
        )?;
        for row in
            stmt.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Status>(2)?)))?
        {
            let (bid, title, st) = row?;
            let detail = if st == Status::Closed {
                "condition not met: it succeeded (this runs only if it fails)".to_string()
            } else {
                format!("runs only if it fails (currently {st})")
            };
            out.push(Blocker { id: bid, title, status: st, kind: BlockerKind::Conditional, detail });
        }
    }
    {
        let sql = format!(
            "SELECT s.id, s.title, s.status, COALESCE(json_extract(w.metadata, '$.gate'), 'all-children'),
                    (SELECT COUNT(*) FROM dependencies c
                     CROSS JOIN issues ci INDEXED BY sqlite_autoindex_issues_1 ON ci.id = c.issue_id
                     WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
                       AND ci.status NOT IN ('closed','pinned'))
             FROM dependencies w CROSS JOIN issues s INDEXED BY sqlite_autoindex_issues_1 ON s.id = w.depends_on_id
             WHERE w.issue_id = ?1 AND w.dep_type = 'waits-for' AND {WAITS_GATE_SHUT}
             ORDER BY s.id"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        for row in stmt.query_map([id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Status>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })? {
            let (bid, title, st, gate, live) = row?;
            let detail = if live > 0 {
                format!("waiting on {live} live child issue(s) (gate {gate})")
            } else {
                format!("spawner is {st} (also_blocks)")
            };
            out.push(Blocker { id: bid, title, status: st, kind: BlockerKind::WaitsFor, detail });
        }
    }
    {
        let mut stmt = conn.prepare_cached(
            "SELECT p.id, p.title, p.status FROM dependencies d
             CROSS JOIN issues p INDEXED BY sqlite_autoindex_issues_1 ON p.id = d.depends_on_id
             WHERE d.issue_id = ?1 AND d.dep_type = 'parent-child' AND p.is_blocked = 1
             ORDER BY p.id",
        )?;
        for row in
            stmt.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Status>(2)?)))?
        {
            let (bid, title, st) = row?;
            out.push(Blocker {
                id: bid,
                title,
                status: st,
                kind: BlockerKind::Parent,
                detail: "parent is blocked".into(),
            });
        }
    }
    Ok(out)
}

/// Outcome of adding an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepChange {
    Added,
    MetadataUpdated,
    Unchanged,
}

fn scheduling_neighbors(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT depends_on_id FROM dependencies
         WHERE issue_id = ?1 AND dep_type IN ('blocks','conditional-blocks','parent-child')
         ORDER BY depends_on_id",
    )?;
    let rows = stmt.query_map([id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Shortest path `from -> ... -> to` over scheduling edges, if any.
fn scheduling_path(conn: &Connection, from: &str, to: &str) -> Result<Option<Vec<String>>> {
    let mut prev: HashMap<String, String> = HashMap::new();
    let mut queue = VecDeque::from([from.to_string()]);
    let mut seen = HashSet::from([from.to_string()]);
    while let Some(cur) = queue.pop_front() {
        if cur == to {
            let mut path = vec![cur.clone()];
            let mut at = cur;
            while let Some(p) = prev.get(&at) {
                path.push(p.clone());
                at = p.clone();
            }
            path.reverse();
            return Ok(Some(path));
        }
        for next in scheduling_neighbors(conn, &cur)? {
            if seen.insert(next.clone()) {
                prev.insert(next.clone(), cur.clone());
                queue.push_back(next);
            }
        }
    }
    Ok(None)
}

/// The edge that makes putting `moved` under `target` a deadlock, if any: a
/// `blocks` or `conditional-blocks` edge held by `moved` or a descendant of it,
/// to `target` or an ancestor of `target`. That issue would then wait on its
/// own ancestor, which can't close before it. Returned as (holder, blocker,
/// type): the first found from `moved` down, children by id, blockers by id.
/// Statuses don't matter: the shape is refused as the direct edges are.
fn moved_edge_to_chain(conn: &Connection, moved: &str, target: &str) -> Result<Option<(String, String, DepType)>> {
    // `target` and its ancestors, read once a blocking edge turns up: most
    // moves, and every new issue, have none.
    let mut chain: HashSet<String> = HashSet::new();
    let mut queue = VecDeque::from([moved.to_string()]);
    let mut seen = HashSet::from([moved.to_string()]);
    while let Some(holder) = queue.pop_front() {
        let edges: Vec<(String, DepType)> = conn
            .prepare_cached(
                "SELECT depends_on_id, dep_type FROM dependencies
                 WHERE issue_id = ?1 AND dep_type IN ('blocks','conditional-blocks')
                 ORDER BY depends_on_id",
            )?
            .query_map([&holder], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if chain.is_empty() && !edges.is_empty() {
            chain.insert(target.to_string());
            chain.extend(ancestors(conn, target)?);
        }
        if let Some((blocker, via)) = edges.into_iter().find(|(blocker, _)| chain.contains(blocker)) {
            return Ok(Some((holder, blocker, via)));
        }
        for child in children(conn, &holder)? {
            if seen.insert(child.clone()) {
                queue.push_back(child);
            }
        }
    }
    Ok(None)
}

pub(crate) fn load_edge(conn: &Connection, issue: &str, target: &str) -> Result<Option<Dependency>> {
    Ok(conn
        .prepare_cached(
            "SELECT issue_id, depends_on_id, dep_type, created_at, created_by, metadata
             FROM dependencies WHERE issue_id = ?1 AND depends_on_id = ?2",
        )?
        .query_row([issue, target], dependency_from_row)
        .optional()?)
}

fn dependency_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Dependency> {
    let metadata: String = r.get(5)?;
    Ok(Dependency {
        issue_id: r.get(0)?,
        depends_on_id: r.get(1)?,
        dep_type: r.get(2)?,
        created_at: r.get::<_, Timestamp>(3)?,
        created_by: r.get(4)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_else(|_| empty_object()),
    })
}

fn validate_edge_metadata(dep_type: &DepType, metadata: &Value) -> Result<()> {
    if !metadata.is_object() {
        return Err(Error::invalid("dependency metadata must be a JSON object"));
    }
    if *dep_type == DepType::WaitsFor
        && let Some(gate) = metadata.get("gate")
    {
        match gate.as_str() {
            Some("all-children") | Some("any-children") => {}
            _ => return Err(Error::invalid("waits-for gate must be \"all-children\" or \"any-children\"")),
        }
    }
    Ok(())
}

/// Validate and insert one edge, recording a `dep_added` event. Does not
/// recompute blocked state; callers do that once for all their seeds.
pub(crate) fn insert_edge_checked(
    ctx: &mut WriteCtx<'_>,
    issue: &str,
    target: &str,
    dep_type: &DepType,
    metadata: Value,
) -> Result<DepChange> {
    let conn = ctx.conn();
    if issue == target {
        return Err(Error::invalid(format!("{issue} cannot depend on itself")));
    }
    let status_of = |id: &str| -> Result<Status> {
        conn.prepare_cached("SELECT status FROM issues WHERE id = ?1")?
            .query_row([id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::not_found("issue", id))
    };
    let issue_status = status_of(issue)?;
    let target_status = status_of(target)?;
    validate_edge_metadata(dep_type, &metadata)?;

    if let Some(existing) = load_edge(conn, issue, target)? {
        if existing.dep_type != *dep_type {
            return Err(Error::Refused(format!(
                "{issue} already depends on {target} via {}; remove that edge first",
                existing.dep_type
            )));
        }
        if existing.metadata == metadata {
            return Ok(DepChange::Unchanged);
        }
        conn.prepare_cached("UPDATE dependencies SET metadata = ?1 WHERE issue_id = ?2 AND depends_on_id = ?3")?
            .execute(params![metadata.to_string(), issue, target])?;
        ctx.emit(
            "dep_updated",
            Some(issue),
            json!({ "target": target, "type": dep_type, "metadata": metadata, "previous": existing.metadata }),
        )?;
        return Ok(DepChange::MetadataUpdated);
    }

    if *dep_type == DepType::ParentChild {
        if let Some(existing) = parent_of(conn, issue)? {
            return Err(Error::Refused(format!(
                "{issue} already has parent {existing}; reparent with `bd update {issue} --parent {target}`"
            )));
        }
        if target_status == Status::Closed && issue_status != Status::Closed {
            return Err(Error::Refused(format!("parent {target} is closed; reopen it before adding open children")));
        }
    }
    if dep_type.is_scheduling()
        && let Some(path) = scheduling_path(conn, target, issue)?
    {
        let mut cycle = vec![issue.to_string()];
        cycle.extend(path);
        return Err(Error::Cycle { path: cycle });
    }
    if matches!(dep_type, DepType::Blocks | DepType::ConditionalBlocks) {
        // An ancestor/descendant blocking edge is a deadlock: a parent can't
        // close before its children, and a blocked parent blocks its subtree.
        if ancestors(conn, issue)?.iter().any(|a| a == target) {
            return Err(Error::Refused(format!(
                "{target} is an ancestor of {issue}; a {dep_type} edge between them would deadlock"
            )));
        }
        if ancestors(conn, target)?.iter().any(|a| a == issue) {
            return Err(Error::Refused(format!(
                "{target} is a descendant of {issue}; a {dep_type} edge between them would deadlock"
            )));
        }
    }
    // The same deadlock, reached by adding the parent edge last.
    if *dep_type == DepType::ParentChild
        && let Some((holder, blocker, via)) = moved_edge_to_chain(conn, issue, target)?
    {
        return Err(Error::Refused(format!(
            "{holder} depends on {blocker} via {via}; moving {issue} under {target} would make {blocker} an ancestor of {holder} and deadlock; remove that edge first"
        )));
    }

    conn.prepare_cached(
        "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at, created_by, metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![issue, target, dep_type, ctx.now(), ctx.actor(), metadata.to_string()])?;
    ctx.emit("dep_added", Some(issue), json!({ "target": target, "type": dep_type, "metadata": metadata }))?;
    Ok(DepChange::Added)
}

/// Delete one edge (any type), recording a `dep_removed` event.
pub(crate) fn delete_edge(ctx: &mut WriteCtx<'_>, issue: &str, target: &str) -> Result<Option<Dependency>> {
    let Some(edge) = load_edge(ctx.conn(), issue, target)? else {
        return Ok(None);
    };
    ctx.conn()
        .prepare_cached("DELETE FROM dependencies WHERE issue_id = ?1 AND depends_on_id = ?2")?
        .execute([issue, target])?;
    ctx.emit(
        "dep_removed",
        Some(issue),
        json!({ "target": target, "type": edge.dep_type, "metadata": edge.metadata }),
    )?;
    Ok(Some(edge))
}

impl WriteCtx<'_> {
    /// Add `issue -> target` ("issue depends on target") with the given type.
    pub fn add_dependency(
        &mut self,
        issue: &str,
        target: &str,
        dep_type: DepType,
        metadata: Option<Value>,
    ) -> Result<DepChange> {
        let change = insert_edge_checked(self, issue, target, &dep_type, metadata.unwrap_or_else(empty_object))?;
        if change != DepChange::Unchanged {
            let seeds = seeds_for_edge(self.conn(), issue, target, &dep_type)?;
            recompute(self, seeds)?;
        }
        Ok(change)
    }

    /// Remove the edge between `issue` and `target`; returns it if it existed.
    pub fn remove_dependency(&mut self, issue: &str, target: &str) -> Result<Option<Dependency>> {
        for id in [issue, target] {
            if !crate::ids::exists(self.conn(), id)? {
                return Err(Error::not_found("issue", id));
            }
        }
        if let Some(edge) = load_edge(self.conn(), issue, target)? {
            self.check_edge_removal(issue, target, &edge.dep_type)?;
        }
        let removed = delete_edge(self, issue, target)?;
        if let Some(edge) = &removed {
            let seeds = seeds_for_edge(self.conn(), issue, target, &edge.dep_type)?;
            recompute(self, seeds)?;
        }
        Ok(removed)
    }

    /// Repair every materialized blocked flag; returns the corrections.
    pub fn recompute_blocked(&mut self) -> Result<Vec<BlockChange>> {
        recompute_all(self)
    }
}

/// Outgoing edges: what `id` depends on.
pub fn dependencies_of(conn: &Connection, id: &str) -> Result<Vec<Edge>> {
    edges(conn, id, true)
}

/// Incoming edges: what depends on `id`.
pub fn dependents_of(conn: &Connection, id: &str) -> Result<Vec<Edge>> {
    edges(conn, id, false)
}

fn edges(conn: &Connection, id: &str, outgoing: bool) -> Result<Vec<Edge>> {
    let sql = if outgoing {
        "SELECT o.id, o.title, o.status, o.priority, d.dep_type, d.metadata
         FROM dependencies d CROSS JOIN issues o INDEXED BY sqlite_autoindex_issues_1 ON o.id = d.depends_on_id
         WHERE d.issue_id = ?1 ORDER BY d.dep_type, o.id"
    } else {
        "SELECT o.id, o.title, o.status, o.priority, d.dep_type, d.metadata
         FROM dependencies d CROSS JOIN issues o INDEXED BY sqlite_autoindex_issues_1 ON o.id = d.issue_id
         WHERE d.depends_on_id = ?1 ORDER BY d.dep_type, o.id"
    };
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map([id], |r| {
        let metadata: String = r.get(5)?;
        Ok(Edge {
            id: r.get(0)?,
            title: r.get(1)?,
            status: r.get(2)?,
            priority: r.get::<_, i64>(3)? as u8,
            dep_type: r.get(4)?,
            metadata: serde_json::from_str(&metadata).unwrap_or_else(|_| empty_object()),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    /// Follow what the issue depends on.
    #[default]
    Down,
    /// Follow what depends on the issue.
    Up,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TreeNode {
    pub depth: usize,
    pub id: String,
    pub title: String,
    pub status: Status,
    pub priority: u8,
    pub is_blocked: bool,
    /// Edge type from the parent node in the tree (None for the root).
    pub via: Option<DepType>,
    /// True when the node was already printed elsewhere in the tree.
    pub repeated: bool,
}

/// Indentation levels text output draws for a hierarchy: past this depth
/// lines stay at this indentation and say their depth instead, so the
/// output of a deep chain grows linearly with it, not quadratically.
pub const MAX_INDENT: usize = 64;

/// Two spaces per level of `depth`, at most [`MAX_INDENT`] levels; a deeper
/// line gets `[depth N] ` after them.
pub fn indent(depth: usize) -> String {
    if depth <= MAX_INDENT { "  ".repeat(depth) } else { format!("{}[depth {depth}] ", "  ".repeat(MAX_INDENT)) }
}

/// Depth-first dependency tree from `root`, cycle-safe (each node expands once).
/// Symmetric `related` links are skipped.
pub fn dep_tree(conn: &Connection, root: &str, direction: Direction, max_depth: usize) -> Result<Vec<TreeNode>> {
    // A fixed plan (see the module docs): index lookups per node, whatever the statistics.
    let sql_out = "SELECT o.id, o.title, o.status, o.priority, o.is_blocked, d.dep_type
                   FROM dependencies d
                   CROSS JOIN issues o INDEXED BY sqlite_autoindex_issues_1 ON o.id = d.depends_on_id
                   WHERE d.issue_id = ?1 AND d.dep_type <> 'related' ORDER BY d.dep_type, o.id";
    let sql_in = "SELECT o.id, o.title, o.status, o.priority, o.is_blocked, d.dep_type
                  FROM dependencies d
                  CROSS JOIN issues o INDEXED BY sqlite_autoindex_issues_1 ON o.id = d.issue_id
                  WHERE d.depends_on_id = ?1 AND d.dep_type <> 'related' ORDER BY d.dep_type, o.id";
    let root_issue = crate::issues::require(conn, root)?;
    let mut out = vec![TreeNode {
        depth: 0,
        id: root_issue.id.clone(),
        title: root_issue.title.clone(),
        status: root_issue.status,
        priority: root_issue.priority,
        is_blocked: root_issue.is_blocked,
        via: None,
        repeated: false,
    }];
    let mut expanded = HashSet::from([root.to_string()]);
    let sql = if direction == Direction::Down { sql_out } else { sql_in };
    let neighbors = |id: &str, depth: usize| -> Result<Vec<TreeNode>> {
        if depth >= max_depth {
            return Ok(Vec::new());
        }
        let mut stmt = conn.prepare_cached(sql)?;
        let kids = stmt
            .query_map([id], |r| {
                Ok(TreeNode {
                    depth: depth + 1,
                    id: r.get(0)?,
                    title: r.get(1)?,
                    status: r.get(2)?,
                    priority: r.get::<_, i64>(3)? as u8,
                    is_blocked: r.get::<_, i64>(4)? != 0,
                    via: Some(r.get(5)?),
                    repeated: false,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(kids)
    };
    // Depth first with an explicit stack of the neighbors left to visit:
    // `max_depth` comes from the caller and chains can be arbitrarily long.
    let mut stack = vec![neighbors(root, 0)?.into_iter()];
    while let Some(kids) = stack.last_mut() {
        let Some(mut kid) = kids.next() else {
            stack.pop();
            continue;
        };
        let first = expanded.insert(kid.id.clone());
        kid.repeated = !first;
        let below = if first { neighbors(&kid.id, kid.depth)? } else { Vec::new() };
        out.push(kid);
        stack.push(below.into_iter());
    }
    Ok(out)
}

/// Every cycle among scheduling edges (blocks, conditional-blocks,
/// parent-child), each rotated to start at its smallest id. Empty iff acyclic.
pub fn find_cycles(conn: &Connection) -> Result<Vec<Vec<String>>> {
    let mut stmt = conn.prepare_cached(
        "SELECT issue_id, depends_on_id FROM dependencies
         WHERE dep_type IN ('blocks','conditional-blocks','parent-child')
         ORDER BY issue_id, depends_on_id",
    )?;
    let edges = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    Ok(cycles_of(edges.collect::<rusqlite::Result<Vec<_>>>()?))
}

/// [`find_cycles`] over `edges`, sorted and distinct: a depth-first search
/// from each issue with edges, in id order, reporting the path from where an
/// edge meets it back to that edge's start. The path holds numbers, and each
/// issue knows its place on it, so a cycle costs its own length, not the
/// path's.
fn cycles_of(edges: Vec<(String, String)>) -> Vec<Vec<String>> {
    // Issues by number, numbered in id order: comparing numbers compares ids.
    let ids: Vec<String> =
        edges.iter().flat_map(|(a, b)| [a, b]).collect::<BTreeSet<_>>().into_iter().cloned().collect();
    let number: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); ids.len()];
    for (a, b) in &edges {
        adj[number[a.as_str()]].push(number[b.as_str()]);
    }
    // Each issue's position on the current path, or whether it is new or done.
    const NEW: usize = usize::MAX;
    const DONE: usize = usize::MAX - 1;
    let mut at = vec![NEW; ids.len()];
    let mut cycles: BTreeSet<Vec<usize>> = BTreeSet::new();
    for start in 0..ids.len() {
        if at[start] != NEW || adj[start].is_empty() {
            continue;
        }
        // Iterative DFS: the path, and how many edges of each issue on it
        // were followed.
        let mut path = vec![start];
        let mut followed = vec![0];
        at[start] = 0;
        while let Some(&node) = path.last() {
            let k = followed.last_mut().expect("parallel stacks");
            let Some(&n) = adj[node].get(*k) else {
                at[node] = DONE;
                path.pop();
                followed.pop();
                continue;
            };
            *k += 1;
            match at[n] {
                NEW => {
                    at[n] = path.len();
                    path.push(n);
                    followed.push(0);
                }
                DONE => {}
                pos => {
                    let cycle = &path[pos..];
                    let min = (0..cycle.len()).min_by_key(|&i| cycle[i]).unwrap_or(0);
                    cycles.insert([&cycle[min..], &cycle[..min]].concat());
                }
            }
        }
    }
    cycles.into_iter().map(|cycle| cycle.into_iter().map(|i| ids[i].clone()).collect()).collect()
}

/// A `blocks` or `conditional-blocks` edge that keeps an issue waiting on its
/// own ancestor for good: see [`stuck_ancestor_edges`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StuckEdge {
    pub issue: String,
    pub target: String,
    pub dep_type: DepType,
}

/// The edges no issue can get past, sorted by issue, then target. T can't
/// close before its children, each of them before theirs, down to X, which
/// waits on T. The edge from X to T is reported when all of these hold:
///
/// * it is a `blocks` or `conditional-blocks` edge and T is an ancestor of X,
///   by each issue's first parent by id ([`parent_of`]);
/// * neither X nor T is closed or pinned: the edge holds nothing up then;
/// * no issue from X up to just below T is closed: closing and claiming count
///   only children that are not closed as open (`open_children`, for which a
///   pinned child is open), so a closed one frees the issue above it;
/// * no issue from X's parent up to T has waiters: a spawner may close and be
///   claimed before its children ([`waiters_on`], whatever the waiter's status).
///
/// One pass over the edges, however deep the hierarchy. Issues on a parent
/// cycle, and below one, have no root and are left out: [`find_cycles`] reports
/// those.
pub fn stuck_ancestor_edges(conn: &Connection) -> Result<Vec<StuckEdge>> {
    let mut stmt = conn.prepare_cached(
        "SELECT d.issue_id, d.depends_on_id, d.dep_type FROM dependencies d
         CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = d.issue_id
         CROSS JOIN issues t INDEXED BY sqlite_autoindex_issues_1 ON t.id = d.depends_on_id
         WHERE d.dep_type IN ('blocks','conditional-blocks')
           AND i.status NOT IN ('closed','pinned') AND t.status NOT IN ('closed','pinned')",
    )?;
    let rows = stmt.query_map([], |r| Ok(StuckEdge { issue: r.get(0)?, target: r.get(1)?, dep_type: r.get(2)? }))?;
    let candidates = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare_cached(
        "SELECT d.issue_id, d.depends_on_id, c.status = 'closed',
                EXISTS (SELECT 1 FROM dependencies w INDEXED BY idx_deps_target
                        WHERE w.depends_on_id = d.depends_on_id AND w.dep_type = 'waits-for')
         FROM dependencies d
         CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
         WHERE d.dep_type = 'parent-child'
         ORDER BY d.issue_id, d.depends_on_id",
    )?;
    let rows = stmt.query_map([], |r| {
        let (closed, waiters): (bool, bool) = (r.get(2)?, r.get(3)?);
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, !closed && !waiters))
    })?;
    // Each child's first parent only, which is what `parent_of` reads.
    let mut links: Vec<(String, String, bool)> = Vec::new();
    for row in rows {
        let link = row?;
        if links.last().is_none_or(|last| last.0 != link.0) {
            links.push(link);
        }
    }
    Ok(stuck_among(&candidates, &links))
}

/// [`stuck_ancestor_edges`] over `links` (child, parent, whether the link is
/// unbroken: a stuck edge can run up it), each child once: a depth-first search
/// from each root, in numbers as in [`cycles_of`]. Each issue on the path knows
/// its depth, and `top`, how far up its unbroken links go, so an edge costs one
/// comparison and no walk up. The result is sorted.
fn stuck_among(candidates: &[StuckEdge], links: &[(String, String, bool)]) -> Vec<StuckEdge> {
    let mut number: HashMap<&str, usize> = HashMap::new();
    for id in links.iter().flat_map(|(child, parent, _)| [child, parent]) {
        let next = number.len();
        number.entry(id).or_insert(next);
    }
    let mut up: Vec<Option<(usize, bool)>> = vec![None; number.len()];
    let mut kids: Vec<Vec<usize>> = vec![Vec::new(); number.len()];
    for (child, parent, unbroken) in links {
        let (child, parent) = (number[child.as_str()], number[parent.as_str()]);
        up[child] = Some((parent, *unbroken));
        kids[parent].push(child);
    }
    // Each issue's candidates, with their targets' numbers. An edge with an
    // end in no link can't be between an issue and its ancestor.
    let mut held: Vec<Vec<(usize, &StuckEdge)>> = vec![Vec::new(); number.len()];
    for edge in candidates {
        if let (Some(&issue), Some(&target)) = (number.get(edge.issue.as_str()), number.get(edge.target.as_str())) {
            held[issue].push((target, edge));
        }
    }
    // Each issue's depth while it is on the current path, and the smallest
    // depth its unbroken links reach, which also says it was seen.
    const OFF_PATH: usize = usize::MAX;
    const UNSET: usize = usize::MAX;
    let mut at = vec![OFF_PATH; number.len()];
    let mut top = vec![UNSET; number.len()];
    let mut stuck = Vec::new();
    for root in (0..number.len()).filter(|&n| up[n].is_none()) {
        // Iterative DFS: the path, and how many kids of each issue on it were followed.
        let mut path = vec![(root, 0)];
        while let Some(&(node, followed)) = path.last() {
            let depth = path.len() - 1;
            if followed == 0 {
                if top[node] != UNSET {
                    path.pop();
                    continue;
                }
                at[node] = depth;
                top[node] = match up[node] {
                    Some((parent, true)) => top[parent],
                    _ => depth,
                };
                for &(target, edge) in &held[node] {
                    if at[target] < depth && at[target] >= top[node] {
                        stuck.push(edge.clone());
                    }
                }
            }
            if let Some(&kid) = kids[node].get(followed) {
                path[depth].1 += 1;
                path.push((kid, 0));
            } else {
                at[node] = OFF_PATH;
                path.pop();
            }
        }
    }
    stuck.sort();
    stuck
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depths_match_walking_each_ids_ancestors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE dependencies (issue_id TEXT, depends_on_id TEXT, dep_type TEXT,
                                        PRIMARY KEY (issue_id, depends_on_id)) WITHOUT ROWID;",
        )
        .unwrap();
        // r <- a <- a1 <- a2, r <- b <- b1, c alone; x1 -> x2 -> x3 -> x1 a cycle with y below it;
        // m has two parents (the first by id counts).
        let edges = [
            ("a", "r"),
            ("a1", "a"),
            ("a2", "a1"),
            ("b", "r"),
            ("b1", "b"),
            ("x1", "x2"),
            ("x2", "x3"),
            ("x3", "x1"),
            ("y", "x1"),
            ("m", "a2"),
            ("m", "b"),
        ];
        for (i, p) in edges {
            conn.execute("INSERT INTO dependencies VALUES (?1, ?2, 'parent-child')", [i, p]).unwrap();
        }
        conn.execute("INSERT INTO dependencies VALUES ('b1', 'c', 'blocks')", []).unwrap();
        let ids: Vec<String> = ["a2", "b1", "a", "r", "c", "a1", "y", "x2", "x1", "m", "a2", "zz", "b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let expected: Vec<usize> = ids.iter().map(|id| ancestors(&conn, id).unwrap().len()).collect();
        assert_eq!(depths(&conn, &ids).unwrap(), expected);
        assert_eq!(expected[..6], [3, 2, 1, 0, 0, 2]);
    }

    /// The tables [`stuck_ancestor_edges`] reads, with the indexes it names.
    fn stuck_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE issues (id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'open');
             CREATE TABLE dependencies (issue_id TEXT, depends_on_id TEXT, dep_type TEXT,
                                        PRIMARY KEY (issue_id, depends_on_id)) WITHOUT ROWID;
             CREATE INDEX idx_deps_target ON dependencies(depends_on_id, dep_type, issue_id);",
        )
        .unwrap();
        conn
    }

    const NONE: [&str; 0] = [];

    /// x under q under p under t.
    const CHAIN: [(&str, &str, &str); 3] =
        [("x", "q", "parent-child"), ("q", "p", "parent-child"), ("p", "t", "parent-child")];

    /// A database of `edges` (issue, target, type), its issues open unless
    /// `statuses` says otherwise.
    fn seeded(edges: &[(&str, &str, &str)], statuses: &[(&str, &str)]) -> Connection {
        let conn = stuck_db();
        for (issue, target, dep_type) in edges {
            conn.execute("INSERT OR IGNORE INTO issues (id) VALUES (?1), (?2)", [issue, target]).unwrap();
            conn.execute("INSERT INTO dependencies VALUES (?1, ?2, ?3)", [issue, target, dep_type]).unwrap();
        }
        for (id, status) in statuses {
            conn.execute("UPDATE issues SET status = ?2 WHERE id = ?1", [id, status]).unwrap();
        }
        conn
    }

    fn stuck(conn: &Connection) -> Vec<String> {
        let edges = stuck_ancestor_edges(conn).unwrap();
        edges.iter().map(|e| format!("{} -> {} ({})", e.issue, e.target, e.dep_type)).collect()
    }

    #[test]
    fn stuck_edges_are_reported_sorted() {
        // The nearest an ancestor can be: a parent's own pair holds its parent-child edge.
        let nearest = [("x", "p", "parent-child"), ("p", "t", "parent-child"), ("x", "t", "blocks")];
        assert_eq!(stuck(&seeded(&nearest, &[])), ["x -> t (blocks)"]);

        let with = |extra: &[(&'static str, &'static str, &'static str)]| [&CHAIN[..], extra].concat();
        let deep = with(&[("x", "t", "blocks")]);
        assert_eq!(stuck(&seeded(&deep, &[])), ["x -> t (blocks)"]);
        let conditional = with(&[("x", "t", "conditional-blocks")]);
        assert_eq!(stuck(&seeded(&conditional, &[])), ["x -> t (conditional-blocks)"]);
        let several = with(&[("x", "t", "blocks"), ("x", "p", "blocks"), ("q", "t", "conditional-blocks")]);
        assert_eq!(
            stuck(&seeded(&several, &[("x", "in_progress"), ("t", "blocked")])),
            ["q -> t (conditional-blocks)", "x -> p (blocks)", "x -> t (blocks)"]
        );

        // What does not free anyone: a pinned issue between, which close and claim count as an
        // open child; waiters on X itself; a broken link above T.
        assert_eq!(stuck(&seeded(&deep, &[("q", "pinned")])), ["x -> t (blocks)"]);
        let waiter_on_x = with(&[("x", "t", "blocks"), ("w", "x", "waits-for")]);
        assert_eq!(stuck(&seeded(&waiter_on_x, &[])), ["x -> t (blocks)"]);
        let above = with(&[("x", "t", "blocks"), ("t", "r", "parent-child"), ("w", "r", "waits-for")]);
        assert_eq!(stuck(&seeded(&above, &[])), ["x -> t (blocks)"]);
    }

    #[test]
    fn edges_something_can_finish_are_not_stuck() {
        let with = |extra: &[(&'static str, &'static str, &'static str)]| [&CHAIN[..], extra].concat();
        let edge = with(&[("x", "t", "blocks")]);
        for (name, status) in
            [("x", "closed"), ("x", "pinned"), ("t", "closed"), ("t", "pinned"), ("q", "closed"), ("p", "closed")]
        {
            assert_eq!(stuck(&seeded(&edge, &[(name, status)])), NONE, "{name} {status}");
        }

        // A spawner at T, in the middle, or at X's parent, whatever its waiter's status.
        for spawner in ["t", "p", "q"] {
            let waited = with(&[("x", "t", "blocks"), ("w", spawner, "waits-for")]);
            assert_eq!(stuck(&seeded(&waited, &[])), NONE, "{spawner}");
            assert_eq!(stuck(&seeded(&waited, &[("w", "closed")])), NONE, "{spawner}");
        }

        // Not an ancestor: an issue beside the chain, a descendant, an issue in no link; an X in no link.
        let sibling = with(&[("s", "t", "parent-child"), ("x", "s", "blocks")]);
        assert_eq!(stuck(&seeded(&sibling, &[])), NONE);
        assert_eq!(stuck(&seeded(&with(&[("t", "x", "blocks")]), &[])), NONE);
        assert_eq!(stuck(&seeded(&with(&[("x", "u", "blocks"), ("u", "t", "blocks")]), &[])), NONE);
    }

    #[test]
    fn stuck_edges_follow_the_first_parent_by_id() {
        let edges = [
            ("x", "a", "parent-child"),
            ("x", "z", "parent-child"),
            ("a", "r", "parent-child"),
            ("z", "t", "parent-child"),
            ("x", "r", "blocks"),
            ("x", "t", "blocks"),
        ];
        assert_eq!(stuck(&seeded(&edges, &[])), ["x -> r (blocks)"]);
        // A closed second parent's waiters and status don't matter either.
        let conn = seeded(&[&edges[..], &[("w", "z", "waits-for")]].concat(), &[("z", "closed")]);
        assert_eq!(stuck(&conn), ["x -> r (blocks)"]);
    }

    #[test]
    fn a_parent_cycle_ends_the_walk() {
        // x1 -> x2 -> x3 -> x1 with y below it: no root reaches them, and the forest beside
        // them still answers.
        let edges = [
            ("x1", "x2", "parent-child"),
            ("x2", "x3", "parent-child"),
            ("x3", "x1", "parent-child"),
            ("y", "x1", "parent-child"),
            ("y", "x2", "blocks"),
            ("x1", "x3", "blocks"),
        ];
        assert_eq!(stuck(&seeded(&edges, &[])), NONE);
        let conn = seeded(&[&edges[..], &CHAIN[..], &[("x", "t", "blocks")]].concat(), &[]);
        assert_eq!(stuck(&conn), ["x -> t (blocks)"]);
    }

    /// [`stuck_ancestor_edges`]'s conditions, read off the helpers themselves
    /// by a walk up from each edge.
    fn naive_stuck(conn: &Connection) -> Vec<StuckEdge> {
        let status = |id: &str| -> String {
            conn.query_row("SELECT status FROM issues WHERE id = ?1", [id], |r| r.get(0)).unwrap()
        };
        let live = |id: &str| !matches!(status(id).as_str(), "closed" | "pinned");
        let mut stmt = conn
            .prepare(
                "SELECT issue_id, depends_on_id, dep_type FROM dependencies
                 WHERE dep_type IN ('blocks','conditional-blocks')",
            )
            .unwrap();
        let rows = stmt.query_map([], |r| Ok(StuckEdge { issue: r.get(0)?, target: r.get(1)?, dep_type: r.get(2)? }));
        let mut out = Vec::new();
        for edge in rows.unwrap() {
            let edge = edge.unwrap();
            let up = ancestors(conn, &edge.issue).unwrap();
            let Some(k) = up.iter().position(|a| *a == edge.target) else { continue };
            if live(&edge.issue)
                && live(&edge.target)
                && up[..k].iter().all(|a| status(a) != "closed")
                && up[..=k].iter().all(|a| waiters_on(conn, a).unwrap().is_empty())
            {
                out.push(edge);
            }
        }
        out.sort();
        out
    }

    /// A linear congruential generator: enough for seeded shapes, with no dependency.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: usize) -> usize {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as usize % n
        }
    }

    #[test]
    fn stuck_edges_match_a_naive_walk_on_seeded_forests() {
        const ISSUES: usize = 60;
        const STATUSES: [&str; 8] = ["open", "open", "open", "open", "in_progress", "blocked", "closed", "pinned"];
        let id = |n: usize| format!("i{n:02}");
        let (mut reported, mut blocking) = (0, 0);
        for seed in 1..=40 {
            let mut rng = Lcg(seed);
            let conn = stuck_db();
            let insert = |issue: usize, target: usize, dep_type: &str| {
                conn.execute(
                    "INSERT OR IGNORE INTO dependencies VALUES (?1, ?2, ?3)",
                    params![id(issue), id(target), dep_type],
                )
                .unwrap();
            };
            for n in 0..ISSUES {
                let status = STATUSES[rng.below(STATUSES.len())];
                conn.execute("INSERT INTO issues VALUES (?1, ?2)", params![id(n), status]).unwrap();
            }
            // Parents numbered lower, and near, for long chains; every so often a root or
            // a second parent row, which may be the one that counts.
            for n in 1..ISSUES {
                if rng.below(8) != 0 {
                    insert(n, n.saturating_sub(1 + rng.below(4)), "parent-child");
                }
                if rng.below(16) == 0 {
                    insert(n, rng.below(n), "parent-child");
                }
            }
            for _ in 0..30 {
                let issue = rng.below(ISSUES);
                let up = ancestors(&conn, &id(issue)).unwrap();
                let target = if !up.is_empty() && rng.below(4) != 0 {
                    up[rng.below(up.len())][1..].parse().unwrap()
                } else {
                    rng.below(ISSUES)
                };
                if target != issue {
                    insert(issue, target, ["blocks", "conditional-blocks"][rng.below(2)]);
                }
            }
            for _ in 0..3 {
                let (issue, target) = (rng.below(ISSUES), rng.below(ISSUES));
                if target != issue {
                    insert(issue, target, "waits-for");
                }
            }
            let want = naive_stuck(&conn);
            assert_eq!(stuck_ancestor_edges(&conn).unwrap(), want, "seed {seed}");
            reported += want.len();
            blocking += conn
                .query_row("SELECT COUNT(*) FROM dependencies WHERE dep_type LIKE '%blocks'", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap();
        }
        // The seeds reach both answers.
        assert!(reported > 40, "{reported} reported");
        assert!(reported as i64 * 2 < blocking, "{reported} of {blocking}");
    }

    #[test]
    fn stuck_edges_of_a_deep_chain_take_one_pass() {
        const LEVELS: usize = 20_000;
        let conn = stuck_db();
        // Level 1 holds the pair with the root in its parent-child edge, so the blocks edges
        // start at level 2: to the root, the worst case for a walk up per edge.
        conn.execute_batch(&format!(
            "WITH RECURSIVE n(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM n WHERE k < {last})
             INSERT INTO issues (id) SELECT printf('l%06d', k) FROM n;
             WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < {last})
             INSERT INTO dependencies SELECT printf('l%06d', k), printf('l%06d', k - 1), 'parent-child' FROM n;
             WITH RECURSIVE n(k) AS (SELECT 2 UNION ALL SELECT k + 1 FROM n WHERE k < {last})
             INSERT INTO dependencies SELECT printf('l%06d', k), 'l000000', 'blocks' FROM n;",
            last = LEVELS - 1
        ))
        .unwrap();
        let levels = |range: std::ops::Range<usize>| -> Vec<StuckEdge> {
            range
                .map(|k| StuckEdge { issue: format!("l{k:06}"), target: "l000000".into(), dep_type: DepType::Blocks })
                .collect()
        };

        let started = std::time::Instant::now();
        let every_level = stuck_ancestor_edges(&conn).unwrap();
        // Closed halfway: that level's edge is not live, and its link no longer holds the root.
        conn.execute("UPDATE issues SET status = 'closed' WHERE id = 'l010000'", []).unwrap();
        let above_the_closed_level = stuck_ancestor_edges(&conn).unwrap();
        let took = started.elapsed();

        assert_eq!(every_level.len(), LEVELS - 2);
        assert_eq!(every_level, levels(2..LEVELS));
        assert_eq!(above_the_closed_level.len(), 9_998);
        assert_eq!(above_the_closed_level, levels(2..10_000));
        assert!(took < std::time::Duration::from_secs(60), "stuck edges took {took:?}");
    }
}
