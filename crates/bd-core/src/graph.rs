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
//! can change it, for the affected issues and their whole subtrees.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::{Blocker, BlockerKind, DepType, Dependency, Edge, Status, empty_object};
use crate::store::WriteCtx;
use crate::time::Timestamp;

const WAITS_GATE_SHUT: &str = "(
    (EXISTS (SELECT 1 FROM dependencies c JOIN issues ci ON ci.id = c.issue_id
             WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
               AND ci.status NOT IN ('closed','pinned'))
     AND NOT (COALESCE(json_extract(w.metadata, '$.gate'), 'all-children') = 'any-children'
              AND EXISTS (SELECT 1 FROM dependencies c JOIN issues ci ON ci.id = c.issue_id
                          WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
                            AND ci.status = 'closed')))
    OR (json_extract(w.metadata, '$.also_blocks') IN (1, 'true') AND s.status NOT IN ('closed','pinned'))
)";

fn direct_block_predicate(alias: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM dependencies d JOIN issues t ON t.id = d.depends_on_id
                  WHERE d.issue_id = {a}.id AND d.dep_type = 'blocks'
                    AND t.status NOT IN ('closed','pinned'))
          OR EXISTS (SELECT 1 FROM dependencies d JOIN issues t ON t.id = d.depends_on_id
                  WHERE d.issue_id = {a}.id AND d.dep_type = 'conditional-blocks'
                    AND NOT (t.status = 'closed' AND t.close_outcome = 'failed'))
          OR EXISTS (SELECT 1 FROM dependencies w JOIN issues s ON s.id = w.depends_on_id
                  WHERE w.issue_id = {a}.id AND w.dep_type = 'waits-for' AND {gate}))",
        a = alias,
        gate = WAITS_GATE_SHUT
    )
}

fn should_block_sql() -> String {
    format!(
        "SELECT CASE WHEN i.status IN ('closed','pinned') THEN 0 ELSE (
            {direct}
            OR EXISTS (SELECT 1 FROM dependencies d JOIN issues p ON p.id = d.depends_on_id
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
             SELECT d.issue_id FROM dependencies d
             JOIN blocked b ON d.depends_on_id = b.id
             JOIN issues c ON c.id = d.issue_id
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

/// Recompute `is_blocked` for `seeds` and all their descendants, inside the
/// caller's transaction. Emits `blocked` / `unblocked` events for net changes
/// on live issues and returns them.
pub(crate) fn recompute(ctx: &mut WriteCtx<'_>, seeds: Vec<String>) -> Result<Vec<BlockChange>> {
    if seeds.is_empty() {
        return Ok(Vec::new());
    }
    let conn = ctx.conn();
    // BFS from the seeds down the hierarchy: parents precede children, so
    // one pass usually converges; the loop below guarantees a fixpoint.
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
        state.insert(id.clone(), (blocked, status));
        queue.extend(children(conn, &id)?);
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
    for id in &order {
        let (now_blocked, status) = state[id];
        if original[id] != now_blocked {
            changes.push(BlockChange { id: id.clone(), blocked: now_blocked });
            if !status.is_terminal() {
                let op = if now_blocked { "blocked" } else { "unblocked" };
                ctx.emit(op, Some(id), json!({}))?;
            }
        }
    }
    crate::gates::note_block_changes(ctx, &changes)?;
    Ok(changes)
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

/// Explain why `id` is blocked (empty when it is not).
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
            "SELECT t.id, t.title, t.status FROM dependencies d JOIN issues t ON t.id = d.depends_on_id
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
            "SELECT t.id, t.title, t.status FROM dependencies d JOIN issues t ON t.id = d.depends_on_id
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
                    (SELECT COUNT(*) FROM dependencies c JOIN issues ci ON ci.id = c.issue_id
                     WHERE c.depends_on_id = s.id AND c.dep_type = 'parent-child'
                       AND ci.status NOT IN ('closed','pinned'))
             FROM dependencies w JOIN issues s ON s.id = w.depends_on_id
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
            "SELECT p.id, p.title, p.status FROM dependencies d JOIN issues p ON p.id = d.depends_on_id
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
    if *dep_type == DepType::WaitsFor {
        if let Some(gate) = metadata.get("gate") {
            match gate.as_str() {
                Some("all-children") | Some("any-children") => {}
                _ => return Err(Error::invalid("waits-for gate must be \"all-children\" or \"any-children\"")),
            }
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
    if dep_type.is_scheduling() {
        if let Some(path) = scheduling_path(conn, target, issue)? {
            let mut cycle = vec![issue.to_string()];
            cycle.extend(path);
            return Err(Error::Cycle { path: cycle });
        }
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
         FROM dependencies d JOIN issues o ON o.id = d.depends_on_id
         WHERE d.issue_id = ?1 ORDER BY d.dep_type, o.id"
    } else {
        "SELECT o.id, o.title, o.status, o.priority, d.dep_type, d.metadata
         FROM dependencies d JOIN issues o ON o.id = d.issue_id
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

/// Depth-first dependency tree from `root`, cycle-safe (each node expands once).
/// Symmetric `related` links are skipped.
pub fn dep_tree(conn: &Connection, root: &str, direction: Direction, max_depth: usize) -> Result<Vec<TreeNode>> {
    let sql_out = "SELECT o.id, o.title, o.status, o.priority, o.is_blocked, d.dep_type
                   FROM dependencies d JOIN issues o ON o.id = d.depends_on_id
                   WHERE d.issue_id = ?1 AND d.dep_type <> 'related' ORDER BY d.dep_type, o.id";
    let sql_in = "SELECT o.id, o.title, o.status, o.priority, o.is_blocked, d.dep_type
                  FROM dependencies d JOIN issues o ON o.id = d.issue_id
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
    let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut stmt = conn.prepare_cached(
        "SELECT issue_id, depends_on_id FROM dependencies
         WHERE dep_type IN ('blocks','conditional-blocks','parent-child')
         ORDER BY issue_id, depends_on_id",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (a, b) = row?;
        adj.entry(a).or_default().push(b);
    }
    let nodes: Vec<String> = adj.keys().cloned().collect();
    let mut color: HashMap<String, u8> = HashMap::new(); // 0 new, 1 on stack, 2 done
    let mut cycles: BTreeSet<Vec<String>> = BTreeSet::new();
    for start in nodes {
        if color.get(&start).copied().unwrap_or(0) != 0 {
            continue;
        }
        // Iterative DFS keeping the current path for cycle extraction.
        let mut path: Vec<String> = Vec::new();
        let mut iters: Vec<usize> = Vec::new();
        path.push(start.clone());
        iters.push(0);
        color.insert(start.clone(), 1);
        while let Some(node) = path.last().cloned() {
            let idx = *iters.last().expect("parallel stacks");
            let next = adj.get(&node).and_then(|v| v.get(idx)).cloned();
            match next {
                Some(n) => {
                    *iters.last_mut().expect("parallel stacks") += 1;
                    match color.get(&n).copied().unwrap_or(0) {
                        0 => {
                            color.insert(n.clone(), 1);
                            path.push(n);
                            iters.push(0);
                        }
                        1 => {
                            let pos = path.iter().position(|x| *x == n).expect("on stack");
                            let mut cycle: Vec<String> = path[pos..].to_vec();
                            let min = cycle.iter().enumerate().min_by(|a, b| a.1.cmp(b.1)).map(|(i, _)| i).unwrap_or(0);
                            cycle.rotate_left(min);
                            cycles.insert(cycle);
                        }
                        _ => {}
                    }
                }
                None => {
                    color.insert(node, 2);
                    path.pop();
                    iters.pop();
                }
            }
        }
    }
    Ok(cycles.into_iter().collect())
}
