//! Runs: creating a run from a [`Plan`] in one transaction, and everything
//! afterwards (status, listing, compaction, discarding).

use std::collections::BTreeSet;

use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::compile::{Plan, Role};
use crate::error::{Error, Result};
use crate::gates::{self, GatePhase};
use crate::graph;
use crate::issues::{self, DeleteOptions, DeleteOutcome, ISSUE_COLUMNS, issue_from_row};
use crate::model::{
    DepType, GATE_TYPE, Guard, Issue, IssuePatch, IssueRef, NewIssue, Outcome, ReadyQuery, Status, WorkFilter,
};
use crate::queries::Queries;
use crate::ready::DeferralSources;
use crate::store::WriteCtx;
use crate::time::{Timestamp, format_duration_ms};

/// The role an issue plays in a playbook run (`metadata.playbook.role`).
pub fn role_of(issue: &Issue) -> Option<Role> {
    issue.metadata.pointer("/playbook/role").and_then(Value::as_str).and_then(Role::parse)
}

/// The run an issue belongs to (`metadata.playbook.run`; a run is its own).
pub fn run_of(issue: &Issue) -> Option<String> {
    match role_of(issue)? {
        Role::Run => Some(issue.id.clone()),
        _ => issue.metadata.pointer("/playbook/run").and_then(Value::as_str).map(String::from),
    }
}

/// Where a run attaches to existing work.
#[derive(Clone, Debug, Default)]
pub struct StartOptions {
    /// Create the run as a child of this issue (e.g. a spawner step).
    pub parent: Option<String>,
    /// The run starts only after these issues close.
    pub after: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunStarted {
    pub run: Issue,
    /// Issues created besides the run issue itself.
    pub created: usize,
    pub steps: usize,
    pub gates: usize,
    pub ephemeral: bool,
    /// Steps that can be claimed right away.
    pub ready: Vec<IssueRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Done,
    Failed,
    /// Claimed and being worked on.
    Active,
    Ready,
    Blocked,
    Deferred,
    /// Gate whose step still has open prerequisites.
    Waiting,
    /// Gate waiting for its condition.
    Armed,
    Escalated,
    /// A run or group with open steps.
    Open,
}

impl StepState {
    pub fn icon(self) -> &'static str {
        match self {
            StepState::Done => "✓",
            StepState::Failed => "✗",
            StepState::Active => "◐",
            StepState::Ready => "○",
            StepState::Blocked => "●",
            StepState::Deferred => "❄",
            StepState::Waiting => "⧗",
            StepState::Armed => "⏳",
            StepState::Escalated => "!",
            StepState::Open => "▸",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Progress {
    /// Work items: everything except groups and gates.
    pub total: usize,
    pub done: usize,
    pub failed: usize,
    pub active: usize,
    pub ready: usize,
    pub blocked: usize,
    /// Gates still shut (waiting, armed, or escalated).
    pub gates_open: usize,
    pub escalated: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusNode {
    pub depth: usize,
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    pub issue_type: String,
    pub status: Status,
    pub state: StepState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunStatus {
    pub run: Issue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook: Option<String>,
    pub progress: Progress,
    pub nodes: Vec<StatusNode>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunSummary {
    pub id: String,
    pub title: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook: Option<String>,
    #[serde(skip_serializing_if = "crate::model::is_false")]
    pub ephemeral: bool,
    pub created_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<Timestamp>,
    pub progress: Progress,
}

#[derive(Clone, Debug, Default)]
pub struct RunsQuery {
    pub include_closed: bool,
    pub playbook: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct CompactOptions {
    /// Your own summary, written above the generated digest.
    pub summary: Option<String>,
    /// Compact even though the run is not finished. Never past another
    /// actor's live claim on a step: that is `take_over`.
    pub force: bool,
    /// Delete steps other actors hold live claims on (recorded in the
    /// `run_compacted` event; see [`crate::policy`]).
    pub take_over: bool,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DiscardOptions {
    /// Discard even though the run has work in progress (the caller's own
    /// claims, or dead ones). Never past another actor's live claim on the
    /// run or a step: that is `take_over`.
    pub force: bool,
    /// Delete the run although other actors hold live claims on it or its
    /// steps (recorded in each `deleted` event; see [`crate::policy`]).
    pub take_over: bool,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompactOutcome {
    pub run: Issue,
    pub removed: Vec<String>,
    pub digest: String,
    pub dry_run: bool,
}

fn children_in_order(conn: &Connection, id: &str) -> Result<Vec<Issue>> {
    // CROSS JOIN keeps this an index lookup of the children whatever the
    // planner's statistics say: stale ones (a `bd serve` pool rarely runs
    // `PRAGMA optimize`) can make it scan every issue instead, per node.
    let sql = format!(
        "SELECT {ISSUE_COLUMNS} FROM dependencies d CROSS JOIN issues i ON i.id = d.issue_id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' ORDER BY i.created_at, i.rowid"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([id], issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// A depth-first walk below an issue, in creation order.
struct Walk {
    /// (depth, issue), parents before their children.
    nodes: Vec<(usize, Issue)>,
    /// Index in `nodes` of each node's parent (None below the root).
    parents: Vec<Option<usize>>,
    /// No issue was reached twice (or back at the root): the walk is the
    /// whole subtree, each issue once under its only parent. Only a damaged
    /// database (a second parent, a parent cycle) breaks this.
    is_tree: bool,
}

/// Depth-first walk below `id` in creation order. Uses an explicit stack
/// (depth, children left to visit, their parent): a hierarchy has no depth
/// limit, and this runs on `bd serve`'s small-stack threads.
fn walk_tree(conn: &Connection, id: &str) -> Result<Walk> {
    let mut walk = Walk { nodes: Vec::new(), parents: Vec::new(), is_tree: true };
    let mut seen = BTreeSet::new();
    let mut stack = vec![(1, children_in_order(conn, id)?.into_iter(), None)];
    while let Some((depth, children, parent)) = stack.last_mut() {
        let (depth, parent) = (*depth, *parent);
        let Some(child) = children.next() else {
            stack.pop();
            continue;
        };
        if !seen.insert(child.id.clone()) {
            walk.is_tree = false;
            continue;
        }
        walk.is_tree &= child.id != id;
        let below = children_in_order(conn, &child.id)?;
        stack.push((depth + 1, below.into_iter(), Some(walk.nodes.len())));
        walk.nodes.push((depth, child));
        walk.parents.push(parent);
    }
    Ok(walk)
}

fn walk(conn: &Connection, id: &str) -> Result<Vec<(usize, Issue)>> {
    Ok(walk_tree(conn, id)?.nodes)
}

fn is_container(issue: &Issue) -> bool {
    role_of(issue).is_some_and(Role::is_container)
}

/// Work items (everything but containers) below `id`, and how many are closed.
fn work_below(conn: &Connection, id: &str) -> Result<(usize, usize)> {
    let kids = issues::descendants(conn, id)?;
    let work: Vec<&Issue> = kids.iter().filter(|k| !is_container(k)).collect();
    Ok((work.len(), work.iter().filter(|k| k.status.is_terminal()).count()))
}

/// An issue's state in its run. `counts` gives an open container's
/// [`work_below`], and `deferrals` remembers deferral sources across the
/// issues of one status, so neither needs a walk of the hierarchy per issue.
fn state_of(
    conn: &Connection,
    issue: &Issue,
    now: Timestamp,
    deferrals: &mut DeferralSources,
    counts: impl FnOnce() -> Result<(usize, usize)>,
) -> Result<(StepState, Option<String>)> {
    if issue.issue_type == GATE_TYPE && !issue.status.is_terminal() {
        let g = gates::view_of(conn, issue)?;
        let kind = g.spec.as_ref().map(|s| s.kind.to_string()).unwrap_or_else(|| "gate".into());
        return Ok(match g.phase {
            GatePhase::Waiting => {
                (StepState::Waiting, Some(format!("{kind}: arms when the step's prerequisites are done")))
            }
            GatePhase::Escalated => (StepState::Escalated, g.escalation.clone()),
            GatePhase::Armed | GatePhase::Resolved => {
                let detail = match (g.spec.as_ref(), g.deadline) {
                    (Some(s), Some(d)) if s.kind == gates::GateKind::Timer => {
                        format!("timer opens in {}", format_duration_ms(d.since(now).max(0)))
                    }
                    (Some(s), _) if s.kind == gates::GateKind::Human => {
                        format!("awaiting approval: bd gate resolve {}", issue.id)
                    }
                    (Some(s), _) => format!("awaiting {} {}", s.kind, s.await_id.as_deref().unwrap_or_default()),
                    (None, _) => g.spec_error.clone().unwrap_or_default(),
                };
                (StepState::Armed, Some(detail))
            }
        });
    }
    Ok(match issue.status {
        Status::Closed if issue.close_outcome == Some(Outcome::Failed) => {
            (StepState::Failed, issue.close_reason.clone())
        }
        Status::Closed | Status::Pinned => (StepState::Done, issue.close_reason.clone()),
        Status::InProgress => (StepState::Active, issue.assignee.as_ref().map(|a| format!("@{a}"))),
        Status::Deferred => (StepState::Deferred, None),
        Status::Blocked => (StepState::Blocked, Some("marked blocked".into())),
        Status::Open if is_container(issue) && !issue.is_blocked => {
            let (work, done) = counts()?;
            (StepState::Open, Some(format!("{done}/{work} closed")))
        }
        Status::Open if issue.is_blocked => {
            let mut on: Vec<String> = Vec::new();
            for b in graph::blockers(conn, &issue.id)? {
                if b.kind != crate::model::BlockerKind::Parent && !on.contains(&b.id) {
                    on.push(b.id);
                }
            }
            let detail = if on.is_empty() {
                "its group is waiting".to_string()
            } else {
                format!("waiting on {}", on.join(", "))
            };
            (StepState::Blocked, Some(detail))
        }
        Status::Open => match deferrals.get(conn, &issue.id)? {
            Some(src) => (StepState::Deferred, Some(format!("deferred by {src}"))),
            None => (StepState::Ready, None),
        },
    })
}

fn tally(progress: &mut Progress, issue: &Issue, state: StepState) {
    if issue.issue_type == GATE_TYPE {
        if !issue.status.is_terminal() {
            progress.gates_open += 1;
        }
        if state == StepState::Escalated {
            progress.escalated += 1;
        }
        return;
    }
    if is_container(issue) {
        return;
    }
    progress.total += 1;
    match state {
        StepState::Done => progress.done += 1,
        StepState::Failed => progress.failed += 1,
        StepState::Active => progress.active += 1,
        StepState::Ready => progress.ready += 1,
        StepState::Blocked | StepState::Deferred => progress.blocked += 1,
        _ => {}
    }
}

/// Every issue of a run (or any issue with children) with its state.
pub fn run_status(conn: &Connection, run: &str, now: Timestamp) -> Result<RunStatus> {
    let root = issues::require(conn, run)?;
    let walk = walk_tree(conn, run)?;
    // Every container's counts in one pass from the leaves up; a damaged
    // hierarchy, where the walk is not the whole subtree, asks the database.
    let below = walk.is_tree.then(|| {
        let mut below = vec![(0, 0); walk.nodes.len()];
        for (i, (_, issue)) in walk.nodes.iter().enumerate().rev() {
            let Some(p) = walk.parents[i] else { continue };
            let (mut work, mut done) = below[i];
            if !is_container(issue) {
                work += 1;
                done += usize::from(issue.status.is_terminal());
            }
            below[p].0 += work;
            below[p].1 += done;
        }
        below
    });
    let mut deferrals = DeferralSources::new(now);
    let mut progress = Progress::default();
    let mut nodes = Vec::new();
    for (i, (depth, issue)) in walk.nodes.into_iter().enumerate() {
        let counts = || match &below {
            Some(below) => Ok(below[i]),
            None => work_below(conn, &issue.id),
        };
        let (state, detail) = state_of(conn, &issue, now, &mut deferrals, counts)?;
        tally(&mut progress, &issue, state);
        nodes.push(StatusNode {
            depth,
            role: role_of(&issue),
            id: issue.id,
            title: issue.title,
            issue_type: issue.issue_type,
            status: issue.status,
            state,
            assignee: issue.assignee,
            detail,
        });
    }
    let playbook = root.metadata.pointer("/playbook/name").and_then(Value::as_str).map(String::from);
    Ok(RunStatus { run: root, playbook, progress, nodes })
}

fn progress_of(conn: &Connection, run: &str, now: Timestamp) -> Result<Progress> {
    let mut deferrals = DeferralSources::new(now);
    let mut progress = Progress::default();
    for issue in issues::descendants(conn, run)? {
        if is_container(&issue) && issue.issue_type != GATE_TYPE {
            continue; // counts nothing whatever its state
        }
        let (state, _) = state_of(conn, &issue, now, &mut deferrals, || work_below(conn, &issue.id))?;
        tally(&mut progress, &issue, state);
    }
    Ok(progress)
}

/// Runs, newest first (open ones only unless asked).
pub fn runs(conn: &Connection, q: &RunsQuery, now: Timestamp) -> Result<Vec<RunSummary>> {
    let mut sql =
        format!("SELECT {ISSUE_COLUMNS} FROM issues i WHERE json_extract(i.metadata, '$.playbook.role') = 'run'");
    if !q.include_closed {
        sql.push_str(" AND i.status NOT IN ('closed','pinned')");
    }
    sql.push_str(" AND (?1 IS NULL OR json_extract(i.metadata, '$.playbook.name') = ?1)");
    sql.push_str(" ORDER BY i.created_at DESC, i.rowid DESC LIMIT ?2");
    let limit = q.limit.map(|n| n as i64).unwrap_or(-1);
    let found: Vec<Issue> = {
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(rusqlite::params![q.playbook, limit], issue_from_row)?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    found
        .into_iter()
        .map(|i| {
            Ok(RunSummary {
                progress: progress_of(conn, &i.id, now)?,
                playbook: i.metadata.pointer("/playbook/name").and_then(Value::as_str).map(String::from),
                id: i.id,
                title: i.title,
                status: i.status,
                outcome: i.close_outcome,
                ephemeral: i.ephemeral,
                created_at: i.created_at,
                closed_at: i.closed_at,
            })
        })
        .collect()
}

fn require_run(conn: &Connection, id: &str) -> Result<Issue> {
    let issue = issues::require(conn, id)?;
    if role_of(&issue) != Some(Role::Run) {
        return Err(Error::invalid(format!(
            "{id} is not a playbook run{}",
            run_of(&issue).map(|r| format!(" (it belongs to run {r})")).unwrap_or_default()
        )));
    }
    Ok(issue)
}

fn digest(root: &Issue, tree: &[(usize, Issue)], summary: Option<&str>, now: Timestamp) -> String {
    let mut out = vec![format!("## Run digest (compacted {now})")];
    if let Some(pb) = root.metadata.pointer("/playbook/name").and_then(Value::as_str) {
        let vars: Vec<String> = root
            .metadata
            .pointer("/playbook/vars")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default())).collect())
            .unwrap_or_default();
        let vars = if vars.is_empty() { String::new() } else { format!(" · vars: {}", vars.join(", ")) };
        out.push(format!("Playbook: {pb}{vars}"));
    }
    if let Some(s) = summary.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(String::new());
        out.push(s.to_string());
    }
    let work: Vec<&Issue> =
        tree.iter().map(|(_, i)| i).filter(|i| !is_container(i) && i.issue_type != GATE_TYPE).collect();
    let failed = work.iter().filter(|i| i.close_outcome == Some(Outcome::Failed)).count();
    let closed = work.iter().filter(|i| i.status.is_terminal()).count();
    out.push(String::new());
    out.push(format!(
        "Steps: {closed}/{} closed{}",
        work.len(),
        if failed > 0 { format!(", {failed} failed") } else { String::new() }
    ));
    for (depth, i) in tree {
        let icon = match (i.status, i.close_outcome) {
            (Status::Closed, Some(Outcome::Failed)) => "✗",
            (Status::Closed | Status::Pinned, _) => "✓",
            _ => "○",
        };
        // Top-level steps are not indented; past the cap the label keeps the
        // line a list item and names the same depth as `playbook status`.
        let level = depth.saturating_sub(1);
        let (pad, label) = match level <= graph::MAX_INDENT {
            true => ("  ".repeat(level), String::new()),
            false => ("  ".repeat(graph::MAX_INDENT), format!("[depth {depth}] ")),
        };
        let mut line = format!("{pad}- {label}{icon} {}: {}", short_key(root, i), i.title);
        let mut extra = Vec::new();
        if let Some(a) = &i.assignee {
            extra.push(format!("@{a}"));
        }
        if let (Some(s), Some(c)) = (i.started_at, i.closed_at) {
            extra.push(format_duration_ms(c.since(s).max(0)));
        }
        if let Some(r) = i.close_reason.as_deref().filter(|r| !r.trim().is_empty()) {
            extra.push(r.replace('\n', " "));
        }
        if !extra.is_empty() {
            line.push_str(&format!(" — {}", extra.join(", ")));
        }
        out.push(line);
    }
    out.join("\n")
}

fn short_key(root: &Issue, i: &Issue) -> String {
    i.id.strip_prefix(&format!("{}.", root.id)).unwrap_or(&i.id).to_string()
}

impl WriteCtx<'_> {
    /// Create a run from `plan`: the run issue, one issue per planned step and
    /// gate (ids `<run>.<key>`), and their edges, all in this transaction.
    pub fn start_run(&mut self, plan: &Plan, opts: &StartOptions) -> Result<RunStarted> {
        let mut meta = Map::new();
        let mut info = json!({ "role": "run", "name": plan.playbook, "vars": plan.vars });
        if let Some(v) = plan.version {
            info["version"] = json!(v);
        }
        if let Some(src) = &plan.source {
            info["source"] = json!(src);
        }
        meta.insert("playbook".into(), info);
        let root = self.create_issue(NewIssue {
            title: plan.run.title.clone(),
            description: plan.run.description.clone(),
            issue_type: Some(plan.run.issue_type.clone()),
            priority: Some(plan.run.priority),
            assignee: plan.run.assignee.clone(),
            labels: plan.run.labels.clone(),
            parent: opts.parent.clone(),
            deps: opts.after.iter().map(|a| (DepType::Blocks, a.clone())).collect(),
            metadata: Some(Value::Object(meta)),
            ephemeral: plan.ephemeral,
            ..Default::default()
        })?;
        let rid = root.id.clone();
        let id_of = |key: &str| if key.is_empty() { rid.clone() } else { format!("{rid}.{key}") };
        for p in &plan.issues {
            let id = id_of(&p.key);
            if id.len() > 255 {
                return Err(Error::invalid(format!("issue id {id} is longer than 255 characters; shorten step ids")));
            }
            let mut meta = p.metadata.clone();
            meta.insert(
                "playbook".into(),
                json!({ "role": p.role.as_str(), "run": rid, "key": p.key, "step": p.step }),
            );
            if let Some(g) = &p.gate {
                meta.insert("gate".into(), g.to_value());
            }
            self.create_issue(NewIssue {
                id: Some(id),
                title: p.title.clone(),
                description: p.description.clone(),
                design: p.design.clone(),
                acceptance_criteria: p.acceptance_criteria.clone(),
                notes: p.notes.clone(),
                issue_type: Some(p.issue_type.clone()),
                priority: Some(p.priority),
                assignee: p.assignee.clone(),
                labels: p.labels.clone(),
                parent: Some(id_of(p.parent.as_deref().unwrap_or_default())),
                estimated_minutes: p.estimate,
                metadata: Some(Value::Object(meta)),
                ephemeral: plan.ephemeral,
                ..Default::default()
            })
            .map_err(|e| Error::invalid(format!("step {}: {e}", p.key)))?;
        }
        for e in &plan.edges {
            self.add_dependency(&id_of(&e.from), &id_of(&e.to), e.dep_type.clone(), Some(e.metadata.clone()))?;
        }
        for p in plan.issues.iter().filter(|p| p.role == Role::Gate) {
            self.arm_gate_if_ready(&id_of(&p.key))?;
        }
        self.emit(
            "run_started",
            Some(&rid),
            json!({
                "playbook": plan.playbook,
                "version": plan.version,
                "vars": plan.vars,
                "issues": plan.issues.len(),
                "ephemeral": plan.ephemeral,
            }),
        )?;
        let ready = self.ready(&ReadyQuery {
            filter: WorkFilter { parent: Some(rid.clone()), ..Default::default() },
            ..Default::default()
        })?;
        Ok(RunStarted {
            run: issues::require(self.conn(), &rid)?,
            created: plan.issues.len(),
            steps: plan.count(Role::Step),
            gates: plan.count(Role::Gate),
            ephemeral: plan.ephemeral,
            ready: ready.iter().map(Issue::to_ref).collect(),
        })
    }

    /// Fold a finished run into its run issue: a digest of every step goes
    /// into its notes, the steps are deleted, and the run issue is kept for
    /// good (no longer ephemeral).
    pub fn compact_run(&mut self, run: &str, opts: &CompactOptions) -> Result<CompactOutcome> {
        let root = require_run(self.conn(), run)?;
        let tree = walk(self.conn(), run)?;
        if tree.is_empty() {
            return Err(Error::invalid(format!("{run} has nothing to compact")));
        }
        // The steps are deleted (the run issue is kept): someone else's claims
        // among them are named before anything `force` gets past.
        let steps = tree.iter().map(|(_, i)| i.clone());
        self.check_claim_overrides(steps, opts.take_over, &format!("compacting {run}"))?;
        let live: Vec<&str> =
            tree.iter().filter(|(_, i)| !i.status.is_terminal()).map(|(_, i)| i.id.as_str()).collect();
        if (!live.is_empty() || !root.status.is_terminal()) && !opts.force {
            let what = if live.is_empty() {
                "the run issue is still open".to_string()
            } else {
                format!("{} open issue(s): {}", live.len(), live.join(", "))
            };
            return Err(Error::Refused(format!(
                "{run} is not finished ({what}); finish it, discard it, or pass --force"
            )));
        }
        let digest = digest(&root, &tree, opts.summary.as_deref(), self.now());
        let removed: Vec<String> = tree.iter().map(|(_, i)| i.id.clone()).collect();
        if opts.dry_run {
            return Ok(CompactOutcome { run: root, removed, digest, dry_run: true });
        }
        let mut pb = root.metadata.get("playbook").cloned().unwrap_or_else(|| json!({}));
        pb["compacted"] = json!({ "at": self.now(), "issues": removed.len() });
        let patch = IssuePatch {
            append_notes: Some(digest.clone()),
            ephemeral: Some(false),
            set_metadata: vec![("playbook".into(), pb)],
            ..Default::default()
        };
        self.update_issue_as(run, &patch, &Guard::default(), false, true)?;
        let set: BTreeSet<String> = removed.iter().cloned().collect();
        self.delete_quietly(&set, "run_compacted", Some(run), json!({}), opts.take_over)?;
        Ok(CompactOutcome { run: issues::require(self.conn(), run)?, removed, digest, dry_run: false })
    }

    /// Delete a run and every issue in it.
    pub fn discard_run(&mut self, run: &str, opts: &DiscardOptions) -> Result<DeleteOutcome> {
        let root = require_run(self.conn(), run)?;
        let all: Vec<Issue> =
            std::iter::once(root).chain(walk(self.conn(), run)?.into_iter().map(|(_, i)| i)).collect();
        // Other actors' live claims, on the run itself or a step, come first.
        let taken = self.check_claim_overrides(all.iter().cloned(), opts.take_over, &format!("discarding {run}"))?;
        let active: Vec<String> = all
            .iter()
            .filter(|i| i.status == Status::InProgress && !taken.contains_key(&i.id))
            .map(|i| format!("{} (@{})", i.id, i.assignee.clone().unwrap_or_default()))
            .collect();
        if !active.is_empty() && !opts.force {
            return Err(Error::Refused(format!(
                "{run} has work in progress: {}; release it or pass --force",
                active.join(", ")
            )));
        }
        let ids: Vec<String> = all.into_iter().map(|i| i.id).collect();
        // `force` here only drops edges from outside the run; claims keep the caller's answer.
        let delete = DeleteOptions { cascade: false, force: true, take_over: opts.take_over, dry_run: opts.dry_run };
        self.delete_issues(&ids, &delete)
    }
}
