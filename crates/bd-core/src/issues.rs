//! Issue lifecycle: create, read, list, update, close, reopen, defer, delete.

use std::collections::{BTreeSet, HashSet, VecDeque};

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::claims;
use crate::comments;
use crate::config;
use crate::error::{Error, Result};
use crate::filter::{QueryParts, apply_work_filter, like_escape, placeholders};
use crate::graph;
use crate::ids;
use crate::model::{
    BUILTIN_TYPES, DepType, GATE_TYPE, Guard, Issue, IssueDetails, IssuePatch, IssueRef, ListQuery, ListSort,
    MAX_TITLE_CHARS, NewIssue, Outcome, Status, empty_object,
};
use crate::ready;
use crate::store::{WriteCtx, validate_actor};
use crate::time::Timestamp;

pub(crate) const ISSUE_COLUMNS: &str = "i.id, i.title, i.description, i.design, i.acceptance_criteria, i.notes,
    i.status, i.priority, i.issue_type, i.assignee, i.created_by, i.external_ref, i.estimated_minutes,
    i.metadata, i.created_at, i.updated_at, i.started_at, i.closed_at, i.close_reason, i.close_outcome,
    i.due_at, i.defer_until, i.is_blocked, i.revision, i.ephemeral,
    (SELECT json_group_array(label) FROM (SELECT label FROM labels l WHERE l.issue_id = i.id ORDER BY label))";

pub(crate) fn issue_from_row(r: &Row<'_>) -> rusqlite::Result<Issue> {
    let metadata: String = r.get(13)?;
    let labels: String = r.get(25)?;
    Ok(Issue {
        id: r.get(0)?,
        title: r.get(1)?,
        description: r.get(2)?,
        design: r.get(3)?,
        acceptance_criteria: r.get(4)?,
        notes: r.get(5)?,
        status: r.get(6)?,
        priority: r.get::<_, i64>(7)? as u8,
        issue_type: r.get(8)?,
        assignee: r.get(9)?,
        created_by: r.get(10)?,
        external_ref: r.get(11)?,
        estimated_minutes: r.get(12)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_else(|_| empty_object()),
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
        started_at: r.get(16)?,
        closed_at: r.get(17)?,
        close_reason: r.get(18)?,
        close_outcome: r.get(19)?,
        due_at: r.get(20)?,
        defer_until: r.get(21)?,
        is_blocked: r.get::<_, i64>(22)? != 0,
        revision: r.get(23)?,
        ephemeral: r.get::<_, i64>(24)? != 0,
        labels: serde_json::from_str(&labels).unwrap_or_default(),
    })
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Issue>> {
    let sql = format!("SELECT {ISSUE_COLUMNS} FROM issues i WHERE i.id = ?1");
    Ok(conn.prepare_cached(&sql)?.query_row([id], issue_from_row).optional()?)
}

pub fn require(conn: &Connection, id: &str) -> Result<Issue> {
    get(conn, id)?.ok_or_else(|| Error::not_found("issue", id))
}

/// Resolve user input to an issue id: exact id, then `<prefix>-<input>`, then
/// a unique id prefix.
pub fn resolve_id(conn: &Connection, input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::invalid("issue id must not be empty"));
    }
    if ids::exists(conn, input)? {
        return Ok(input.to_string());
    }
    let prefixed = format!("{}-{input}", config::prefix(conn)?);
    if ids::exists(conn, &prefixed)? {
        return Ok(prefixed);
    }
    let mut matches: Vec<String> = Vec::new();
    for candidate in [input, prefixed.as_str()] {
        let mut stmt = conn.prepare_cached("SELECT id FROM issues WHERE id LIKE ?1 ESCAPE '\\' ORDER BY id LIMIT 6")?;
        for row in stmt.query_map([format!("{}%", like_escape(candidate))], |r| r.get::<_, String>(0))? {
            let id = row?;
            if !matches.contains(&id) {
                matches.push(id);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Error::not_found("issue", input)),
        _ => Err(Error::invalid(format!("ambiguous id {input:?}: matches {}", matches.join(", ")))),
    }
}

pub fn list(conn: &Connection, q: &ListQuery) -> Result<Vec<Issue>> {
    let mut issues = Vec::new();
    for_each(conn, q, |issue| {
        issues.push(issue);
        Ok(())
    })?;
    Ok(issues)
}

/// The issues [`list`] returns, passed to `f` one at a time instead of held
/// all at once (an export of a large workspace).
pub fn for_each(conn: &Connection, q: &ListQuery, mut f: impl FnMut(Issue) -> Result<()>) -> Result<()> {
    let mut parts = QueryParts::default();
    if !q.statuses.is_empty() {
        parts.cond(
            &format!("i.status IN {}", placeholders(q.statuses.len())),
            q.statuses.iter().map(|s| SqlValue::Text(s.as_str().into())),
        );
    } else if !q.all {
        parts.cond("i.status NOT IN ('closed','pinned')", []);
    }
    apply_work_filter(&mut parts, &q.filter);
    if q.blocked_only {
        parts.cond("i.is_blocked = 1", []);
    }
    if let Some(s) = q.search.as_deref().filter(|s| !s.trim().is_empty()) {
        let pat = SqlValue::Text(format!("%{}%", like_escape(s.trim())));
        parts.cond(
            "(i.id LIKE ? ESCAPE '\\' OR i.title LIKE ? ESCAPE '\\' OR i.description LIKE ? ESCAPE '\\' OR i.notes LIKE ? ESCAPE '\\')",
            [pat.clone(), pat.clone(), pat.clone(), pat],
        );
    }
    let (asc, desc) = if q.reverse { ("DESC", "ASC") } else { ("ASC", "DESC") };
    let order = match q.sort {
        ListSort::Priority => format!("ORDER BY i.priority {asc}, i.created_at {asc}, i.id {asc}"),
        ListSort::Created => format!("ORDER BY i.created_at {desc}, i.id {desc}"),
        ListSort::Updated => format!("ORDER BY i.updated_at {desc}, i.id {desc}"),
        ListSort::Id => format!("ORDER BY i.id {asc}"),
    };
    let (tail, tail_params) = match q.limit {
        Some(n) => (format!("{order} LIMIT ?"), vec![SqlValue::Integer(n as i64)]),
        None => (order, vec![]),
    };
    let (sql, params) = parts.build(&format!("SELECT {ISSUE_COLUMNS} FROM issues i"), &tail, tail_params);
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params_from_iter(params))?;
    while let Some(row) = rows.next()? {
        f(issue_from_row(row)?)?;
    }
    Ok(())
}

pub(crate) fn refs(conn: &Connection, ids: &[String]) -> Result<Vec<IssueRef>> {
    ids.iter().map(|id| require(conn, id).map(|i| i.to_ref())).collect()
}

pub fn children(conn: &Connection, id: &str) -> Result<Vec<IssueRef>> {
    let mut stmt = conn.prepare_cached(
        "SELECT c.id, c.title, c.status, c.priority, c.issue_type, c.assignee
         FROM dependencies d CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child'
         ORDER BY c.created_at, c.rowid",
    )?;
    let rows = stmt.query_map([id], |r| {
        Ok(IssueRef {
            id: r.get(0)?,
            title: r.get(1)?,
            status: r.get(2)?,
            priority: r.get::<_, i64>(3)? as u8,
            issue_type: r.get(4)?,
            assignee: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn open_children(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT c.id FROM dependencies d CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' AND c.status <> 'closed'
         ORDER BY c.id",
    )?;
    let rows = stmt.query_map([id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// A playbook run or group: an epic that closes itself when its subtree is
/// done. A gate never is, whatever its metadata says: it opens by its condition.
pub(crate) fn is_playbook_container(issue: &Issue) -> bool {
    issue.issue_type != GATE_TYPE
        && matches!(issue.metadata.pointer("/playbook/role").and_then(Value::as_str), Some("run" | "group"))
}

// The subtree drives every join, one edge or issue lookup per issue in it
// (see `graph`'s module docs on query plans): planned from statistics, each
// recursive step could scan every edge, and the final join every issue.
const SUBTREE_CTE: &str = "WITH RECURSIVE sub(id) AS (
    SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child'
    UNION
    SELECT d.issue_id FROM sub s CROSS JOIN dependencies d ON d.depends_on_id = s.id
    WHERE d.dep_type = 'parent-child')";

/// Whether anything below `id` is live (not closed or pinned), leaving out
/// `settled` and its subtree: a terminal issue below `id` with nothing live
/// below it. Planned as [`descendants`].
fn has_live_descendants(conn: &Connection, id: &str, settled: Option<&str>) -> Result<bool> {
    let sql = "WITH RECURSIVE sub(id) AS (
            SELECT issue_id FROM dependencies
            WHERE depends_on_id = ?1 AND dep_type = 'parent-child' AND issue_id IS NOT ?2
            UNION
            SELECT d.issue_id FROM sub s CROSS JOIN dependencies d ON d.depends_on_id = s.id
            WHERE d.dep_type = 'parent-child' AND d.issue_id IS NOT ?2)
        SELECT EXISTS (SELECT 1 FROM sub CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = sub.id
                       WHERE i.status NOT IN ('closed','pinned'))";
    Ok(conn.prepare_cached(sql)?.query_row(params![id, settled], |r| r.get(0))?)
}

/// Every issue below `id` in the hierarchy, in creation order.
pub fn descendants(conn: &Connection, id: &str) -> Result<Vec<Issue>> {
    let sql = format!(
        "{SUBTREE_CTE} SELECT {ISSUE_COLUMNS}
         FROM sub CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = sub.id ORDER BY i.rowid"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([id], issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn details(conn: &Connection, id: &str, now: Timestamp) -> Result<IssueDetails> {
    let issue = require(conn, id)?;
    let mut dependencies = graph::dependencies_of(conn, id)?;
    dependencies.retain(|e| e.dep_type != DepType::ParentChild);
    let mut dependents = graph::dependents_of(conn, id)?;
    dependents.retain(|e| e.dep_type != DepType::ParentChild);
    Ok(IssueDetails {
        parent: graph::parent_of(conn, id)?,
        children: children(conn, id)?,
        dependencies,
        dependents,
        blockers: graph::blockers(conn, id)?,
        lease: claims::get_lease(conn, id)?,
        comments: comments::list(conn, id)?,
        deferred_by: ready::deferral_source(conn, id, now)?,
        issue,
    })
}

/// Distinct labels with usage counts.
pub fn label_counts(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare_cached("SELECT label, COUNT(*) FROM labels GROUP BY label ORDER BY label")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// JSON snapshot of an issue with its outgoing edges (for events and export).
pub(crate) fn snapshot(conn: &Connection, id: &str) -> Result<Value> {
    let issue = require(conn, id)?;
    let mut stmt = conn.prepare_cached(
        "SELECT depends_on_id, dep_type, metadata FROM dependencies WHERE issue_id = ?1 ORDER BY depends_on_id",
    )?;
    let deps: Vec<Value> = stmt
        .query_map([id], |r| {
            let metadata: String = r.get(2)?;
            Ok(json!({
                "target": r.get::<_, String>(0)?,
                "type": r.get::<_, String>(1)?,
                "metadata": serde_json::from_str::<Value>(&metadata).unwrap_or_else(|_| empty_object()),
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut v = serde_json::to_value(issue)?;
    v["dependencies"] = Value::Array(deps);
    Ok(v)
}

pub(crate) fn validate_title(title: &str) -> Result<String> {
    let t = title.trim();
    if t.is_empty() {
        return Err(Error::invalid("title is required"));
    }
    if t.chars().count() > MAX_TITLE_CHARS {
        return Err(Error::invalid(format!("title must be at most {MAX_TITLE_CHARS} characters")));
    }
    Ok(t.to_string())
}

pub(crate) fn validate_priority(p: u8) -> Result<u8> {
    if p > 4 {
        return Err(Error::invalid(format!("priority must be 0-4 (got {p})")));
    }
    Ok(p)
}

pub(crate) fn validate_type(conn: &Connection, t: &str) -> Result<String> {
    let norm = t.trim().to_ascii_lowercase();
    let norm = match norm.as_str() {
        "feat" | "enhancement" => "feature".to_string(),
        "adr" | "dec" => "decision".to_string(),
        _ => norm,
    };
    if BUILTIN_TYPES.contains(&norm.as_str()) || config::custom_types(conn)?.contains(&norm) {
        return Ok(norm);
    }
    Err(Error::invalid(format!(
        "unknown issue type {t:?} (built-in: {}; add more with `bd config set types.custom <a,b>`)",
        BUILTIN_TYPES.join(", ")
    )))
}

/// Trim, drop empties, de-duplicate (first occurrence wins). Case is kept.
pub fn normalize_labels(labels: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for raw in labels {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if l.contains(',') || l.chars().any(char::is_control) || l.chars().count() > 128 {
            return Err(Error::invalid(format!("invalid label {l:?} (no commas or control characters, max 128)")));
        }
        if !out.iter().any(|x| x == l) {
            out.push(l.to_string());
        }
    }
    Ok(out)
}

fn validate_metadata(v: &Value) -> Result<()> {
    if v.is_object() { Ok(()) } else { Err(Error::invalid("metadata must be a JSON object")) }
}

#[derive(Clone, Debug, Default)]
pub struct CloseOptions {
    pub reason: Option<String>,
    pub outcome: Option<Outcome>,
    /// Close despite open children or live blockers. Never past another
    /// actor's live claim: that is `take_over`.
    pub force: bool,
    /// Close another actor's live claim: a takeover, recorded in the
    /// `closed` event (see [`crate::policy`]).
    pub take_over: bool,
    pub guard: Guard,
    /// Fencing token from `claim`: close only while that lease is still held.
    pub token: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CloseOutcome {
    pub issue: Issue,
    pub already_closed: bool,
    /// Issues whose last blocker this close released.
    pub unblocked: Vec<IssueRef>,
    /// Playbook runs and groups that closed because their last open step did.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<IssueRef>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReopenOutcome {
    pub issue: Issue,
    pub already_open: bool,
    /// Dependents that are blocked again because this issue is live.
    pub newly_blocked: Vec<IssueRef>,
    /// Finished playbook runs and groups reopened along with their step.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reopened: Vec<IssueRef>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateOutcome {
    pub issue: Issue,
    /// Names of the fields that changed (empty = no-op, nothing written).
    pub changed: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DeleteOptions {
    /// Also delete everything that transitively depends on the targets
    /// through readiness edges (blocks, conditional-blocks, parent-child, waits-for).
    pub cascade: bool,
    /// Delete even though other issues depend on the targets (drops those
    /// edges). Never past another actor's live claim: that is `take_over`.
    pub force: bool,
    /// Delete issues other actors hold live claims on: a takeover, recorded
    /// in each one's `deleted` event (see [`crate::policy`]).
    pub take_over: bool,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeleteOutcome {
    pub deleted: Vec<String>,
    /// Surviving issues that lost an edge to a deleted issue.
    pub detached: Vec<String>,
    pub dry_run: bool,
}

fn record_change<T: Serialize + PartialEq>(changes: &mut Map<String, Value>, field: &str, old: &T, new: &T) {
    if old != new {
        changes.insert(
            field.to_string(),
            json!({ "old": serde_json::to_value(old).unwrap_or(Value::Null), "new": serde_json::to_value(new).unwrap_or(Value::Null) }),
        );
    }
}

impl WriteCtx<'_> {
    pub fn create_issue(&mut self, new: NewIssue) -> Result<Issue> {
        let title = validate_title(&new.title)?;
        let issue_type = validate_type(self.conn(), new.issue_type.as_deref().unwrap_or("task"))?;
        let priority = validate_priority(new.priority.unwrap_or(2))?;
        let status = new.status.unwrap_or(Status::Open);
        if matches!(status, Status::InProgress | Status::Closed) {
            return Err(Error::invalid(
                "new issues start open, blocked, deferred or pinned; claim or close them afterwards",
            ));
        }
        if let Some(a) = &new.assignee {
            validate_actor(a)?;
        }
        if new.estimated_minutes.is_some_and(|m| m < 0) {
            return Err(Error::invalid("estimate must be non-negative"));
        }
        let labels = normalize_labels(&new.labels)?;
        let metadata = new.metadata.clone().unwrap_or_else(empty_object);
        validate_metadata(&metadata)?;
        self.check_gate_repo(&issue_type, &metadata, None)?;

        let mut parent = new.parent.clone();
        let mut deps: Vec<(DepType, String)> = Vec::new();
        for (t, target) in &new.deps {
            if *t == DepType::ParentChild {
                if parent.as_ref().is_some_and(|p| p != target) {
                    return Err(Error::invalid("an issue can have only one parent"));
                }
                parent = Some(target.clone());
            } else if !deps.iter().any(|(_, x)| x == target) {
                deps.push((t.clone(), target.clone()));
            } else {
                return Err(Error::invalid(format!("duplicate dependency on {target}")));
            }
        }
        for target in parent.iter().chain(deps.iter().map(|(_, t)| t)) {
            if !ids::exists(self.conn(), target)? {
                return Err(Error::not_found("issue", target.as_str()));
            }
        }

        let id = match &new.id {
            Some(id) => {
                ids::validate_explicit_id(id)?;
                if ids::exists(self.conn(), id)? {
                    return Err(Error::invalid(format!("issue {id} already exists")));
                }
                id.clone()
            }
            None => match &parent {
                Some(p) => ids::next_child_id(self.conn(), p)?,
                None => ids::next_issue_id(self.conn(), &title, &new.description, self.actor())?,
            },
        };

        let now = self.now();
        self.conn()
            .prepare_cached(
                "INSERT INTO issues (id, title, description, design, acceptance_criteria, notes, status, priority,
                    issue_type, assignee, created_by, external_ref, estimated_minutes, metadata, created_at,
                    updated_at, due_at, defer_until, ephemeral, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, ?16, ?17, ?18, 1)",
            )?
            .execute(params![
                id,
                title,
                new.description,
                new.design,
                new.acceptance_criteria,
                new.notes,
                status,
                priority,
                issue_type,
                new.assignee,
                self.actor(),
                new.external_ref.clone().filter(|s| !s.trim().is_empty()),
                new.estimated_minutes,
                metadata.to_string(),
                now,
                new.due_at,
                new.defer_until,
                new.ephemeral as i64,
            ])?;
        for label in &labels {
            self.conn()
                .prepare_cached("INSERT INTO labels (issue_id, label) VALUES (?1, ?2)")?
                .execute([&id, label])?;
        }
        let issue_json = serde_json::to_value(require(self.conn(), &id)?)?;
        self.emit("created", Some(&id), json!({ "issue": issue_json }))?;

        let mut seeds = Vec::new();
        if let Some(p) = &parent {
            graph::insert_edge_checked(self, &id, p, &DepType::ParentChild, empty_object())?;
            seeds.extend(graph::seeds_for_edge(self.conn(), &id, p, &DepType::ParentChild)?);
        }
        for (t, target) in &deps {
            graph::insert_edge_checked(self, &id, target, t, empty_object())?;
            seeds.extend(graph::seeds_for_edge(self.conn(), &id, target, t)?);
        }
        graph::recompute(self, seeds)?;
        require(self.conn(), &id)
    }

    /// Apply `patch`. `take_over`: even when that ends or takes over another
    /// actor's live claim (reassigning it, or moving it out of `in_progress`;
    /// recorded in the `updated` event, see [`crate::policy`]).
    pub fn update_issue(
        &mut self,
        id: &str,
        patch: &IssuePatch,
        guard: &Guard,
        take_over: bool,
    ) -> Result<UpdateOutcome> {
        self.update_issue_as(id, patch, guard, take_over, false)
    }

    /// [`WriteCtx::update_issue`]; `playbook` when playbook runs update their
    /// own bookkeeping (`metadata.playbook`), which callers under a policy may not.
    pub(crate) fn update_issue_as(
        &mut self,
        id: &str,
        patch: &IssuePatch,
        guard: &Guard,
        take_over: bool,
        playbook: bool,
    ) -> Result<UpdateOutcome> {
        let old = require(self.conn(), id)?;
        guard.check(&old)?;
        let mut new = old.clone();

        if let Some(t) = &patch.title {
            new.title = validate_title(t)?;
        }
        if let Some(v) = &patch.description {
            new.description = v.clone();
        }
        if let Some(v) = &patch.design {
            new.design = v.clone();
        }
        if let Some(v) = &patch.acceptance_criteria {
            new.acceptance_criteria = v.clone();
        }
        match (&patch.notes, &patch.append_notes) {
            (Some(_), Some(_)) => return Err(Error::invalid("use either notes or append_notes, not both")),
            (Some(n), None) => new.notes = n.clone(),
            (None, Some(a)) => {
                new.notes = if old.notes.is_empty() { a.clone() } else { format!("{}\n{a}", old.notes) };
            }
            (None, None) => {}
        }
        if let Some(p) = patch.priority {
            new.priority = validate_priority(p)?;
        }
        if let Some(t) = &patch.issue_type {
            new.issue_type = validate_type(self.conn(), t)?;
        }
        if let Some(a) = &patch.assignee {
            if let Some(name) = a {
                validate_actor(name)?;
            }
            new.assignee = a.clone();
        }
        if let Some(r) = &patch.external_ref {
            new.external_ref = r.clone().filter(|s| !s.trim().is_empty());
        }
        if let Some(m) = patch.estimated_minutes {
            if m.is_some_and(|v| v < 0) {
                return Err(Error::invalid("estimate must be non-negative"));
            }
            new.estimated_minutes = m;
        }
        if let Some(d) = patch.due_at {
            new.due_at = d;
        }
        if let Some(d) = patch.defer_until {
            new.defer_until = d;
        }
        if let Some(e) = patch.ephemeral {
            new.ephemeral = e;
        }
        if patch.metadata.is_some() || !patch.set_metadata.is_empty() || !patch.unset_metadata.is_empty() {
            let mut meta = patch.metadata.clone().unwrap_or_else(|| old.metadata.clone());
            let obj = meta.as_object_mut().ok_or_else(|| Error::invalid("metadata must be a JSON object"))?;
            for (k, v) in &patch.set_metadata {
                obj.insert(k.clone(), v.clone());
            }
            for k in &patch.unset_metadata {
                obj.remove(k);
            }
            new.metadata = meta;
        }
        if let Some(s) = patch.status {
            if s == Status::Closed && old.status != Status::Closed {
                return Err(Error::invalid("use `bd close` to close an issue"));
            }
            if old.status == Status::Closed && s != Status::Closed {
                return Err(Error::invalid("use `bd reopen` to reopen a closed issue"));
            }
            new.status = s;
        }

        let was_claimed = old.status == Status::InProgress;
        let is_claimed = new.status == Status::InProgress;
        if is_claimed && new.assignee.is_none() {
            return Err(Error::invalid("an in_progress issue needs an assignee; use `bd release` to give up a claim"));
        }
        // Gates are never claimed (see `claim`): they open by their condition.
        if is_claimed && new.issue_type == GATE_TYPE && !(was_claimed && old.issue_type == GATE_TYPE) {
            return Err(Error::Refused(if old.issue_type == GATE_TYPE {
                format!(
                    "{id} is a gate: it is never in progress; it opens through `bd gate check` or `bd gate resolve`"
                )
            } else {
                format!("{id} is in progress: release it before making it a gate, which is never in progress")
            }));
        }
        if was_claimed
            && is_claimed
            && old.assignee != new.assignee
            && !take_over
            && self.others_live_claim(&old)?.is_some()
        {
            return Err(Error::AlreadyClaimed { id: id.to_string(), holder: old.assignee.clone().unwrap_or_default() });
        }
        if is_claimed && new.started_at.is_none() {
            new.started_at = Some(self.now());
        }
        if was_claimed && new.status == Status::Open {
            new.started_at = None;
        }

        let mut labels = match &patch.set_labels {
            Some(set) => normalize_labels(set)?,
            None => old.labels.clone(),
        };
        for l in normalize_labels(&patch.add_labels)? {
            if !labels.contains(&l) {
                labels.push(l);
            }
        }
        let remove = normalize_labels(&patch.remove_labels)?;
        labels.retain(|l| !remove.contains(l));
        labels.sort();
        new.labels = labels;
        let added: Vec<String> = new.labels.iter().filter(|l| !old.labels.contains(l)).cloned().collect();
        let removed: Vec<String> = old.labels.iter().filter(|l| !new.labels.contains(l)).cloned().collect();

        let parent_change = match &patch.parent {
            Some(target) => {
                let current = graph::parent_of(self.conn(), id)?;
                if current.as_deref() == target.as_deref() {
                    None
                } else {
                    if let Some(t) = target {
                        if t == id {
                            return Err(Error::invalid(format!("{id} cannot be its own parent")));
                        }
                        if !ids::exists(self.conn(), t)? {
                            return Err(Error::not_found("issue", t.as_str()));
                        }
                    }
                    Some((current, target.clone()))
                }
            }
            None => None,
        };

        let mut changes = Map::new();
        record_change(&mut changes, "title", &old.title, &new.title);
        record_change(&mut changes, "description", &old.description, &new.description);
        record_change(&mut changes, "design", &old.design, &new.design);
        record_change(&mut changes, "acceptance_criteria", &old.acceptance_criteria, &new.acceptance_criteria);
        record_change(&mut changes, "notes", &old.notes, &new.notes);
        record_change(&mut changes, "status", &old.status, &new.status);
        record_change(&mut changes, "priority", &old.priority, &new.priority);
        record_change(&mut changes, "issue_type", &old.issue_type, &new.issue_type);
        record_change(&mut changes, "assignee", &old.assignee, &new.assignee);
        record_change(&mut changes, "external_ref", &old.external_ref, &new.external_ref);
        record_change(&mut changes, "estimated_minutes", &old.estimated_minutes, &new.estimated_minutes);
        record_change(&mut changes, "due_at", &old.due_at, &new.due_at);
        record_change(&mut changes, "defer_until", &old.defer_until, &new.defer_until);
        record_change(&mut changes, "metadata", &old.metadata, &new.metadata);
        record_change(&mut changes, "ephemeral", &old.ephemeral, &new.ephemeral);
        if !added.is_empty() || !removed.is_empty() {
            changes.insert("labels".into(), json!({ "added": added, "removed": removed }));
        }
        if let Some((o, n)) = &parent_change {
            changes.insert("parent".into(), json!({ "old": o, "new": n }));
        }
        if changes.is_empty() {
            return Ok(UpdateOutcome { issue: old, changed: Vec::new() });
        }
        let moved_from = parent_change.as_ref().and_then(|(from, _)| from.as_deref());
        let claim_override = self.check_update(&old, &new, moved_from, playbook, take_over)?;
        self.check_gate_repo(&new.issue_type, &new.metadata, Some(&old))?;

        self.conn()
            .prepare_cached(
                "UPDATE issues SET title = ?1, description = ?2, design = ?3, acceptance_criteria = ?4, notes = ?5,
                    status = ?6, priority = ?7, issue_type = ?8, assignee = ?9, external_ref = ?10,
                    estimated_minutes = ?11, metadata = ?12, started_at = ?13, due_at = ?14, defer_until = ?15,
                    updated_at = ?16, ephemeral = ?18, revision = revision + 1
                 WHERE id = ?17",
            )?
            .execute(params![
                new.title,
                new.description,
                new.design,
                new.acceptance_criteria,
                new.notes,
                new.status,
                new.priority,
                new.issue_type,
                new.assignee,
                new.external_ref,
                new.estimated_minutes,
                new.metadata.to_string(),
                new.started_at,
                new.due_at,
                new.defer_until,
                self.now(),
                id,
                new.ephemeral as i64,
            ])?;
        for l in &removed {
            self.conn().prepare_cached("DELETE FROM labels WHERE issue_id = ?1 AND label = ?2")?.execute([id, l])?;
        }
        for l in &added {
            self.conn().prepare_cached("INSERT INTO labels (issue_id, label) VALUES (?1, ?2)")?.execute([id, l])?;
        }
        let changed: Vec<String> = changes.keys().cloned().collect();
        let mut data = json!({ "changes": changes });
        if let Some(o) = claim_override {
            data["claim_override"] = o;
        }
        let seq = self.emit("updated", Some(id), data)?;

        let mut seeds = Vec::new();
        if let Some((old_parent, new_parent)) = parent_change {
            if let Some(p) = &old_parent {
                graph::delete_edge(self, id, p)?;
                seeds.extend(graph::seeds_for_edge(self.conn(), id, p, &DepType::ParentChild)?);
            }
            if let Some(p) = &new_parent {
                graph::insert_edge_checked(self, id, p, &DepType::ParentChild, empty_object())?;
                seeds.extend(graph::seeds_for_edge(self.conn(), id, p, &DepType::ParentChild)?);
            }
        }
        if was_claimed && (!is_claimed || old.assignee != new.assignee) {
            claims::delete_lease(self.conn(), id)?;
        }
        if is_claimed && (!was_claimed || old.assignee != new.assignee) {
            let ttl = config::lease_ttl(self.conn())?;
            let holder = new.assignee.clone().expect("checked above");
            claims::upsert_lease(self.conn(), id, &holder, seq, self.now(), ttl)?;
        }
        if old.status.is_terminal() != new.status.is_terminal() {
            seeds.extend(graph::seeds_for_terminal_flip(self.conn(), id)?);
        }
        graph::recompute(self, seeds)?;
        Ok(UpdateOutcome { issue: require(self.conn(), id)?, changed })
    }

    pub fn close_issue(&mut self, id: &str, opts: &CloseOptions) -> Result<CloseOutcome> {
        let old = require(self.conn(), id)?;
        opts.guard.check(&old)?;
        if old.status == Status::Closed {
            return Ok(CloseOutcome { issue: old, already_closed: true, unblocked: Vec::new(), completed: Vec::new() });
        }
        if let Some(token) = opts.token {
            claims::check_token(self.conn(), id, self.actor(), token)?;
        }
        // Someone else's work is named before anything `force` gets past.
        let claim_override = self.check_claim_override(&old, opts.take_over)?;
        if !opts.force {
            let open = open_children(self.conn(), id)?;
            // A spawner (others wait on its children via waits-for) may finish
            // before the work it spawned: the waits-for gate tracks that work.
            if !open.is_empty() && graph::waiters_on(self.conn(), id)?.is_empty() {
                return Err(Error::Refused(format!(
                    "{id} has {} open child issue(s): {}; close them first or pass --force",
                    open.len(),
                    open.join(", ")
                )));
            }
            if old.is_blocked {
                let blockers: Vec<String> = graph::blockers(self.conn(), id)?.into_iter().map(|b| b.id).collect();
                return Err(Error::Refused(format!(
                    "{id} is blocked by {}; pass --force to close it anyway",
                    blockers.join(", ")
                )));
            }
        }
        self.check_close(&old, opts.force)?;
        let reason = opts.reason.clone().filter(|r| !r.trim().is_empty());
        let outcome = opts.outcome.unwrap_or(Outcome::Done);
        let mut freed = self.mark_closed(&old, reason, outcome, false, claim_override)?;
        let (completed, also_freed) = self.close_finished_containers(id)?;
        freed.extend(also_freed);
        let done: HashSet<&String> = completed.iter().collect();
        freed.retain(|f| !done.contains(f));
        Ok(CloseOutcome {
            issue: require(self.conn(), id)?,
            already_closed: false,
            unblocked: refs(self.conn(), &freed)?,
            completed: refs(self.conn(), &completed)?,
        })
    }

    /// Close one issue and recompute what it held back; returns the issues it
    /// freed. `auto`: a run or group closing after its last step; `claim_override`:
    /// the live claim of another actor this close ended.
    fn mark_closed(
        &mut self,
        old: &Issue,
        reason: Option<String>,
        outcome: Outcome,
        auto: bool,
        claim_override: Option<Value>,
    ) -> Result<Vec<String>> {
        let id = old.id.as_str();
        self.conn()
            .prepare_cached(
                "UPDATE issues SET status = 'closed', closed_at = ?1, close_reason = ?2, close_outcome = ?3,
                    updated_at = ?1, revision = revision + 1
                 WHERE id = ?4",
            )?
            .execute(params![self.now(), reason, outcome, id])?;
        claims::delete_lease(self.conn(), id)?;
        let mut data =
            json!({ "reason": reason, "outcome": outcome, "previous_status": old.status, "assignee": old.assignee });
        if auto {
            data["auto"] = json!(true);
        }
        if let Some(o) = claim_override {
            data["claim_override"] = o;
        }
        self.emit("closed", Some(id), data)?;
        let seeds = graph::seeds_for_terminal_flip(self.conn(), id)?;
        // A run or group closes itself only with nothing live below it: every
        // issue there is terminal, hence unblocked, and stays so.
        let settled = auto.then_some(id);
        let changes = graph::recompute_above(self, seeds, settled)?;
        Ok(changes.into_iter().filter(|c| !c.blocked && c.id != id).map(|c| c.id).collect())
    }

    /// Close the playbook runs and groups above `id` whose whole subtree is
    /// now closed (outcome failed when a child failed). Returns the closed
    /// containers and the issues their closing freed.
    ///
    /// Linear in the subtree of the last container it closes, however deep:
    /// each container closed leaves nothing live below it, so the check of
    /// the next one up skips its subtree, and the walk is a loop.
    fn close_finished_containers(&mut self, id: &str) -> Result<(Vec<String>, Vec<String>)> {
        let mut closed = Vec::new();
        let mut freed = Vec::new();
        let mut settled: Option<String> = None;
        let mut clear = HashSet::new();
        let mut cur = id.to_string();
        while let Some(parent) = graph::parent_of(self.conn(), &cur)? {
            let p = require(self.conn(), &parent)?;
            cur = parent.clone();
            if p.status.is_terminal() {
                continue;
            }
            if !is_playbook_container(&p) || has_live_descendants(self.conn(), &parent, settled.as_deref())? {
                break;
            }
            if !self.check_auto_close(&p, &mut clear)? {
                break;
            }
            let failed: bool = self
                .conn()
                .prepare_cached(
                    "SELECT EXISTS (SELECT 1 FROM dependencies d
                     CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
                     WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' AND c.close_outcome = 'failed')",
                )?
                .query_row([&parent], |r| r.get(0))?;
            let (outcome, reason) = if failed {
                (Outcome::Failed, "every step closed; some failed")
            } else {
                (Outcome::Done, "every step closed")
            };
            freed.extend(self.mark_closed(&p, Some(reason.into()), outcome, true, None)?);
            closed.push(parent.clone());
            settled = Some(parent);
        }
        Ok((closed, freed))
    }

    pub fn reopen_issue(&mut self, id: &str, reason: Option<&str>) -> Result<ReopenOutcome> {
        let old = require(self.conn(), id)?;
        if old.status != Status::Closed {
            return Ok(ReopenOutcome {
                issue: old,
                already_open: true,
                newly_blocked: Vec::new(),
                reopened: Vec::new(),
            });
        }
        let reason = reason.map(str::trim).filter(|r| !r.is_empty());
        let mut blocked = self.mark_reopened(id, reason.map(String::from), None)?;
        // A finished run or group is unfinished again once one of its steps
        // is. Linear however deep: each recompute leaves out the subtree
        // reopened just before, unless the flag of its top changes.
        let mut reopened = Vec::new();
        let mut cur = id.to_string();
        while let Some(parent) = graph::parent_of(self.conn(), &cur)? {
            let p = require(self.conn(), &parent)?;
            if p.status != Status::Closed || !is_playbook_container(&p) {
                break;
            }
            blocked.extend(self.mark_reopened(&parent, Some(format!("{id} was reopened")), Some(&cur))?);
            reopened.push(parent.clone());
            cur = parent;
        }
        let done: HashSet<&String> = reopened.iter().collect();
        blocked.retain(|b| !done.contains(b));
        Ok(ReopenOutcome {
            issue: require(self.conn(), id)?,
            already_open: false,
            newly_blocked: refs(self.conn(), &blocked)?,
            reopened: refs(self.conn(), &reopened)?,
        })
    }

    /// Reopen `id`. `current`: its child reopened just before, whose subtree
    /// is up to date.
    fn mark_reopened(&mut self, id: &str, reason: Option<String>, current: Option<&str>) -> Result<Vec<String>> {
        self.conn()
            .prepare_cached(
                "UPDATE issues SET status = 'open', closed_at = NULL, close_reason = NULL, close_outcome = NULL,
                    updated_at = ?1, revision = revision + 1
                 WHERE id = ?2",
            )?
            .execute(params![self.now(), id])?;
        self.emit("reopened", Some(id), json!({ "reason": reason }))?;
        let seeds = graph::seeds_for_terminal_flip(self.conn(), id)?;
        let changes = match current {
            Some(child) => graph::recompute_beside(self, seeds, child)?,
            None => graph::recompute(self, seeds)?,
        };
        Ok(changes.into_iter().filter(|c| c.blocked && c.id != id).map(|c| c.id).collect())
    }

    /// `until = Some(t)`: hide from ready until `t` (status unchanged).
    /// `until = None`: park indefinitely (status `deferred`).
    pub fn defer_issue(&mut self, id: &str, until: Option<Timestamp>) -> Result<UpdateOutcome> {
        let issue = require(self.conn(), id)?;
        match issue.status {
            Status::Closed => return Err(Error::invalid(format!("{id} is closed"))),
            Status::InProgress => {
                return Err(Error::invalid(format!("{id} is in progress; release it first (`bd release {id}`)")));
            }
            _ => {}
        }
        let patch = match until {
            Some(t) => IssuePatch { defer_until: Some(Some(t)), ..Default::default() },
            None => IssuePatch { status: Some(Status::Deferred), ..Default::default() },
        };
        self.update_issue(id, &patch, &Guard::default(), false)
    }

    pub fn undefer_issue(&mut self, id: &str) -> Result<UpdateOutcome> {
        let issue = require(self.conn(), id)?;
        let patch = IssuePatch {
            defer_until: issue.defer_until.map(|_| None),
            status: (issue.status == Status::Deferred).then_some(Status::Open),
            ..Default::default()
        };
        self.update_issue(id, &patch, &Guard::default(), false)
    }

    pub fn delete_issues(&mut self, ids_in: &[String], opts: &DeleteOptions) -> Result<DeleteOutcome> {
        let mut set: BTreeSet<String> = BTreeSet::new();
        for id in ids_in {
            if !ids::exists(self.conn(), id)? {
                return Err(Error::not_found("issue", id.as_str()));
            }
            set.insert(id.clone());
        }
        if opts.cascade {
            let mut queue: VecDeque<String> = set.iter().cloned().collect();
            let mut stmt = self.conn().prepare_cached(
                "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1
                 AND dep_type IN ('blocks','conditional-blocks','parent-child','waits-for')",
            )?;
            while let Some(x) = queue.pop_front() {
                for row in stmt.query_map([&x], |r| r.get::<_, String>(0))? {
                    let d = row?;
                    if set.insert(d.clone()) {
                        queue.push_back(d);
                    }
                }
            }
        }
        // Someone else's work is named before anything `force` gets past.
        let mut overrides =
            self.check_removal_claims(&set, opts.take_over, &format!("deleting {}", ids_in.join(", ")))?;
        let mut detached: BTreeSet<String> = BTreeSet::new();
        {
            let mut stmt = self.conn().prepare_cached("SELECT issue_id FROM dependencies WHERE depends_on_id = ?1")?;
            for s in &set {
                for row in stmt.query_map([s], |r| r.get::<_, String>(0))? {
                    let d = row?;
                    if !set.contains(&d) {
                        detached.insert(d);
                    }
                }
            }
        }
        if !detached.is_empty() && !opts.force && !opts.cascade {
            return Err(Error::Refused(format!(
                "{} other issue(s) depend on the issue(s) being deleted ({}); pass --cascade to delete them too or --force to drop those edges",
                detached.len(),
                detached.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        self.check_removal_gates(&set)?;
        let deleted: Vec<String> = set.iter().cloned().collect();
        let detached: Vec<String> = detached.into_iter().collect();
        if opts.dry_run {
            return Ok(DeleteOutcome { deleted, detached, dry_run: true });
        }
        let mut seeds: Vec<String> = detached.clone();
        for s in &deleted {
            if let Some(p) = graph::parent_of(self.conn(), s)? {
                if !set.contains(&p) {
                    seeds.extend(graph::waiters_on(self.conn(), &p)?);
                }
            }
        }
        for s in &deleted {
            let mut data = json!({ "issue": snapshot(self.conn(), s)? });
            if let Some(o) = overrides.remove(s) {
                data["claim_override"] = o;
            }
            self.emit("deleted", Some(s), data)?;
        }
        for chunk in deleted.chunks(500) {
            let sql = format!(
                "DELETE FROM issues INDEXED BY sqlite_autoindex_issues_1 WHERE id IN {}",
                placeholders(chunk.len())
            );
            self.conn().execute(&sql, params_from_iter(chunk.iter()))?;
        }
        seeds.retain(|x| !set.contains(x));
        graph::recompute(self, seeds)?;
        Ok(DeleteOutcome { deleted, detached, dry_run: false })
    }

    /// Delete `set` recording one summary event instead of a snapshot per
    /// issue (scratch work: purges and compactions). Edges from surviving
    /// issues into the set are dropped; returns those survivors. `take_over`:
    /// despite other actors' live claims (listed in the event).
    pub(crate) fn delete_quietly(
        &mut self,
        set: &BTreeSet<String>,
        op: &str,
        issue_id: Option<&str>,
        mut data: Value,
        take_over: bool,
    ) -> Result<Vec<String>> {
        if set.is_empty() {
            return Ok(Vec::new());
        }
        let what = match issue_id {
            Some(id) => format!("{op} {id}"),
            None => op.to_string(),
        };
        let overrides = self.check_removal_claims(set, take_over, &what)?;
        self.check_removal_gates(set)?;
        if !overrides.is_empty() {
            data["claim_overrides"] = json!(overrides);
        }
        let mut detached: BTreeSet<String> = BTreeSet::new();
        let mut seeds: Vec<String> = Vec::new();
        {
            let mut stmt = self.conn().prepare_cached("SELECT issue_id FROM dependencies WHERE depends_on_id = ?1")?;
            for s in set {
                for row in stmt.query_map([s], |r| r.get::<_, String>(0))? {
                    let d = row?;
                    if !set.contains(&d) {
                        detached.insert(d);
                    }
                }
            }
        }
        seeds.extend(detached.iter().cloned());
        for s in set {
            if let Some(p) = graph::parent_of(self.conn(), s)? {
                if !set.contains(&p) {
                    seeds.extend(graph::waiters_on(self.conn(), &p)?);
                }
            }
        }
        data["ids"] = json!(set);
        data["count"] = json!(set.len());
        if !detached.is_empty() {
            data["detached"] = json!(detached);
        }
        self.emit(op, issue_id, data)?;
        let ids: Vec<&String> = set.iter().collect();
        for chunk in ids.chunks(500) {
            let sql = format!(
                "DELETE FROM issues INDEXED BY sqlite_autoindex_issues_1 WHERE id IN {}",
                placeholders(chunk.len())
            );
            self.conn().execute(&sql, params_from_iter(chunk.iter()))?;
        }
        seeds.retain(|x| !set.contains(x));
        graph::recompute(self, seeds)?;
        Ok(detached.into_iter().collect())
    }

    /// Delete closed ephemeral issues (closed at least `older_than` ago).
    /// Whole runs go together: an issue stays while any part of its
    /// ephemeral tree is still open or too recent, or it has persistent
    /// descendants.
    pub fn purge_ephemeral(&mut self, older_than: Option<std::time::Duration>, dry_run: bool) -> Result<PurgeOutcome> {
        let cutoff = older_than.map(|d| self.now().minus(d)).unwrap_or_else(|| self.now());
        let candidates: BTreeSet<String> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT id FROM issues WHERE ephemeral = 1 AND status = 'closed' AND closed_at <= ?1 ORDER BY id",
            )?;
            let rows = stmt.query_map([cutoff], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut purge: BTreeSet<String> = BTreeSet::new();
        for id in &candidates {
            let subtree_ok = descendants(self.conn(), id)?.iter().all(|d| candidates.contains(&d.id));
            let mut ancestors_ok = true;
            for a in graph::ancestors(self.conn(), id)? {
                let ephemeral: bool = self
                    .conn()
                    .prepare_cached("SELECT ephemeral FROM issues WHERE id = ?1")?
                    .query_row([&a], |r| Ok(r.get::<_, i64>(0)? != 0))?;
                if ephemeral && !candidates.contains(&a) {
                    ancestors_ok = false;
                    break;
                }
            }
            if subtree_ok && ancestors_ok {
                purge.insert(id.clone());
            }
        }
        let deleted: Vec<String> = purge.iter().cloned().collect();
        if dry_run || purge.is_empty() {
            return Ok(PurgeOutcome { deleted, detached: Vec::new(), dry_run });
        }
        let detached = self.delete_quietly(&purge, "purged", None, json!({ "cutoff": cutoff }), false)?;
        Ok(PurgeOutcome { deleted, detached, dry_run })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PurgeOutcome {
    pub deleted: Vec<String>,
    /// Surviving issues that lost an edge to a purged one.
    pub detached: Vec<String>,
    pub dry_run: bool,
}
