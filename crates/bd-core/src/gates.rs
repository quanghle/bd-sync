//! Gates: wait conditions that hold back the issues they block.
//!
//! A gate is an issue of type `gate` whose `metadata.gate` object says what
//! it waits for. The work it holds back depends on it through ordinary
//! `blocks` edges, so a waiting step simply stays out of the ready queue.
//! Gates themselves are never ready and never claimed.
//!
//! A gate **arms** when it becomes unblocked: gates created by playbooks (and
//! ad-hoc gates) carry the prerequisites of the work they hold back, so they
//! arm once that work could otherwise start. [`crate::graph`] records the
//! moment in `metadata.gate.armed_at` in the same transaction, which is what
//! timers and timeouts count from (not the gate's creation time).
//!
//! Kinds:
//! * `human`: opens only through `bd gate resolve`.
//! * `timer`: opens once `timeout` has elapsed since arming.
//! * `issue`: opens when the `await_id` issue closes as done; a failed close escalates.
//! * `gh:run`, `gh:pr`: a GitHub Actions run succeeding, a pull request
//!   merging; probed by the CLI with `gh`. Failures escalate. A `gh:run`
//!   gate on a workflow can narrow the runs it considers with `branch` and
//!   `event`; with `branch` it follows the newest head of that branch or tag.
//!
//! A non-timer gate with a `timeout` escalates when it is still shut that long
//! after arming. Escalation records the reason on the gate, comments on it, and
//! appends a `gate_escalated` event; it never opens the gate.
//!
//! GitHub gates are probed with the credentials of whoever checks them (the
//! server's, under `bd serve`), so the repositories they may name in `repo`
//! are a workspace setting, [`GateRepos`] (config `gate.repos`), enforced when
//! a gate is written and again before it is probed. Under `bd serve`, human
//! gates open only for a person: see [`crate::policy`].

use std::fmt;

use rusqlite::{Connection, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use crate::config;
use crate::error::{Error, Result};
use crate::graph::{self, BlockChange};
use crate::issues::{self, CloseOptions, CloseOutcome};
use crate::model::{DepType, GATE_TYPE, Issue, IssueRef, NewIssue, Outcome, Status};
use crate::store::WriteCtx;
use crate::time::{Timestamp, format_duration_ms, parse_duration};

/// What a gate waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GateKind {
    Human,
    Timer,
    Issue,
    GhRun,
    GhPr,
}

impl GateKind {
    pub const NAMES: [&'static str; 5] = ["human", "timer", "issue", "gh:run", "gh:pr"];

    pub fn as_str(self) -> &'static str {
        match self {
            GateKind::Human => "human",
            GateKind::Timer => "timer",
            GateKind::Issue => "issue",
            GateKind::GhRun => "gh:run",
            GateKind::GhPr => "gh:pr",
        }
    }

    /// Parses a kind; `bead` is accepted for beads compatibility.
    pub fn parse(s: &str) -> Result<GateKind> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "human" => GateKind::Human,
            "timer" => GateKind::Timer,
            "issue" | "bead" => GateKind::Issue,
            "gh:run" => GateKind::GhRun,
            "gh:pr" => GateKind::GhPr,
            other => {
                return Err(Error::invalid(format!(
                    "unknown gate type {other:?} (valid: {})",
                    GateKind::NAMES.join(", ")
                )));
            }
        })
    }

    pub fn is_github(self) -> bool {
        matches!(self, GateKind::GhRun | GateKind::GhPr)
    }
}

impl fmt::Display for GateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for GateKind {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GateKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        GateKind::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The condition a gate waits for, stored as `metadata.gate`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSpec {
    #[serde(rename = "type")]
    pub kind: GateKind,
    /// `issue`: the issue id; `gh:pr`: the PR number; `gh:run`: a run id or a
    /// workflow name/file (the first run started after arming is used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub await_id: Option<String>,
    /// `timer`: how long to wait. Other kinds: escalate when still shut this
    /// long after arming.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    /// GitHub gates: `OWNER/REPO` or `HOST/OWNER/REPO` (default: the current repository).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// `gh:run` on a workflow: only runs for this branch or tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// `gh:run` on a workflow: only runs triggered by this event (`push`, `workflow_dispatch`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
}

impl GateSpec {
    pub fn new(kind: GateKind) -> GateSpec {
        GateSpec { kind, await_id: None, timeout: None, repo: None, branch: None, event: None }
    }

    /// For `gh:run`: the awaited run id when `await_id` is one, rather than a workflow.
    pub fn run_id(&self) -> Option<&str> {
        let target = self.await_id.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
        (self.kind == GateKind::GhRun && target.chars().all(|c| c.is_ascii_digit())).then_some(target)
    }

    pub fn validate(&self) -> Result<()> {
        let target = self.await_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
        match self.kind {
            GateKind::Timer if self.timeout.is_none() => {
                return Err(Error::invalid("a timer gate needs a duration (timeout = \"24h\")"));
            }
            GateKind::Issue | GateKind::GhRun | GateKind::GhPr if target.is_none() => {
                let what = match self.kind {
                    GateKind::Issue => "the issue id to wait for",
                    GateKind::GhPr => "the pull request number",
                    _ => "a workflow name or run id",
                };
                return Err(Error::invalid(format!("a {} gate needs await_id: {what}", self.kind)));
            }
            _ => {}
        }
        if self.kind == GateKind::GhPr {
            let n = target.unwrap_or_default().trim_start_matches('#');
            if n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()) {
                return Err(Error::invalid(format!(
                    "gh:pr await_id must be a pull request number, got {:?}",
                    target.unwrap_or_default()
                )));
            }
        }
        if let Some(t) = &self.timeout {
            if parse_duration(t)?.is_zero() {
                return Err(Error::invalid(format!("gate timeout {t:?} must be positive")));
            }
        }
        if let Some(repo) = &self.repo {
            if !self.kind.is_github() {
                return Err(Error::invalid(format!("repo only applies to gh:run and gh:pr gates, not {}", self.kind)));
            }
            validate_repo(repo)?;
        }
        if self.branch.is_some() || self.event.is_some() {
            if self.kind != GateKind::GhRun {
                return Err(Error::invalid(format!("branch and event only apply to gh:run gates, not {}", self.kind)));
            }
            if let Some(id) = self.run_id() {
                return Err(Error::invalid(format!(
                    "branch and event only apply when await_id is a workflow, not run {id}"
                )));
            }
        }
        if let Some(b) = &self.branch {
            if b.is_empty() || b.len() > 255 || b.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::invalid(format!("invalid branch {b:?}")));
            }
        }
        if let Some(e) = &self.event {
            if e.is_empty() || !e.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                return Err(Error::invalid(format!(
                    "invalid event {e:?} (a GitHub event name such as push or workflow_dispatch)"
                )));
            }
        }
        Ok(())
    }

    pub fn timeout_ms(&self) -> Option<i64> {
        self.timeout.as_deref().and_then(|t| parse_duration(t).ok()).map(|d| d.as_millis() as i64)
    }

    /// A readable title for a gate holding back `work` (a title).
    pub fn default_title(&self, work: Option<&str>) -> String {
        let target = self.await_id.clone().unwrap_or_default();
        let base = match self.kind {
            GateKind::Human => "Approval".to_string(),
            GateKind::Timer => format!("Wait {}", self.timeout.as_deref().unwrap_or("?")),
            GateKind::Issue => format!("Wait for {target}"),
            GateKind::GhRun => format!("Wait for GitHub run {target}"),
            GateKind::GhPr => format!("Wait for PR #{} to merge", target.trim_start_matches('#')),
        };
        match work {
            Some(w) => format!("{base}: {w}"),
            None => base,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("gate spec serializes")
    }
}

/// The repositories GitHub gates may name in `repo`, from the workspace's
/// `gate.repos` config: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*` (every
/// repository of an owner), `HOST/OWNER/*`, or `*` (any). A gate without
/// `repo` uses the repository of the workspace's directory, which is always
/// allowed. Case does not matter, but the host does: `OWNER/REPO` is on gh's
/// default host (`GH_HOST`, or the one gh is logged in to), so it never
/// matches `HOST/OWNER/REPO`, nor the other way round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateRepos {
    Any,
    Only(Vec<String>),
}

impl GateRepos {
    /// The workspace's allowlist. Unset, it allows any repository, except
    /// under `bd serve` (`served`), where gates may only use the workspace's
    /// own: a client must not point the server's credentials elsewhere.
    pub fn load(conn: &Connection, served: bool) -> Result<GateRepos> {
        let list = config::split_list(&config::get_or_default(conn, "gate.repos")?);
        Ok(if list.iter().any(|r| r == "*") || (list.is_empty() && !served) {
            GateRepos::Any
        } else {
            GateRepos::Only(list)
        })
    }

    pub fn allows(&self, repo: &str) -> bool {
        match self {
            GateRepos::Any => true,
            GateRepos::Only(list) => list.iter().any(|p| repo_matches(p, repo)),
        }
    }

    /// Refuse a GitHub gate whose `repo` is not allowed.
    pub fn check(&self, spec: &GateSpec) -> Result<()> {
        match &spec.repo {
            Some(repo) if spec.kind.is_github() => self.check_repo(spec.kind, repo),
            _ => Ok(()),
        }
    }

    fn check_repo(&self, kind: GateKind, repo: &str) -> Result<()> {
        if self.allows(repo) {
            return Ok(());
        }
        let list = match self {
            GateRepos::Only(list) => list.clone(),
            GateRepos::Any => Vec::new(),
        };
        Err(Error::Refused(if list.is_empty() {
            format!(
                "{kind} gate repo {repo} is not allowed: through bd serve, GitHub gates may only use the workspace's \
                 own repository unless gate.repos allows others (`bd config set gate.repos {repo}`, an admin access token)"
            )
        } else {
            format!(
                "{kind} gate repo {repo} is not in gate.repos ({}); allow it with `bd config set gate.repos {},{repo}`",
                list.join(", "),
                list.join(",")
            )
        }))
    }
}

fn normalize_repo(repo: &str) -> String {
    repo.trim().to_ascii_lowercase()
}

fn repo_matches(pattern: &str, repo: &str) -> bool {
    let (p, r) = (normalize_repo(pattern), normalize_repo(repo));
    if p == "*" {
        return true;
    }
    match p.strip_suffix("/*") {
        Some(owner) => r.rsplit_once('/').is_some_and(|(o, _)| o == owner),
        None => p == r,
    }
}

/// An entry of `gate.repos`: `*`, `OWNER/*`, `HOST/OWNER/*`, or a repository.
pub fn validate_repo_pattern(pattern: &str) -> Result<()> {
    let ok = pattern == "*"
        || match pattern.strip_suffix("/*") {
            Some(owner) => validate_repo(&format!("{owner}/x")).is_ok(),
            None => validate_repo(pattern).is_ok(),
        };
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid gate.repos entry {pattern:?} (OWNER/REPO, HOST/OWNER/REPO, OWNER/* or *)")))
    }
}

/// The kind and `repo` of a GitHub gate with a valid condition.
fn github_repo(issue_type: &str, metadata: &Value) -> Option<(GateKind, String)> {
    if issue_type != GATE_TYPE {
        return None;
    }
    let spec = spec_from_metadata(metadata).ok()?;
    if !spec.kind.is_github() {
        return None;
    }
    Some((spec.kind, spec.repo?))
}

/// `OWNER/REPO` or `HOST/OWNER/REPO`.
pub fn validate_repo(repo: &str) -> Result<()> {
    let parts: Vec<&str> = repo.split('/').collect();
    let ok = matches!(parts.len(), 2 | 3)
        && parts.iter().all(|p| {
            p.starts_with(|c: char| c.is_ascii_alphanumeric())
                && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        });
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid repo {repo:?} (expected OWNER/REPO or HOST/OWNER/REPO)")))
    }
}

/// Where a gate is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatePhase {
    /// The work it holds back still has open prerequisites.
    Waiting,
    /// Prerequisites are done; waiting for the condition.
    Armed,
    /// Armed, and the condition failed or the timeout passed.
    Escalated,
    /// Closed: the condition held or someone resolved it.
    Resolved,
}

impl GatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            GatePhase::Waiting => "waiting",
            GatePhase::Armed => "armed",
            GatePhase::Escalated => "escalated",
            GatePhase::Resolved => "resolved",
        }
    }
}

/// A gate as `bd gate` shows it.
#[derive(Clone, Debug, Serialize)]
pub struct GateView {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub phase: GatePhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<GateSpec>,
    /// Set when `metadata.gate` is missing or invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub created_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub armed_at: Option<Timestamp>,
    /// When a timer opens, or when any other gate escalates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalated_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation: Option<String>,
    /// GitHub run pinned by an earlier check (gh:run gates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    /// Issues this gate holds back.
    pub blocks: Vec<IssueRef>,
}

impl GateView {
    pub fn is_armed(&self) -> bool {
        matches!(self.phase, GatePhase::Armed | GatePhase::Escalated)
    }
}

fn gate_meta(issue: &Issue) -> Option<&Map<String, Value>> {
    issue.metadata.get("gate").and_then(Value::as_object)
}

fn meta_time(meta: Option<&Map<String, Value>>, key: &str) -> Option<Timestamp> {
    meta.and_then(|m| m.get(key)).and_then(Value::as_str).and_then(|s| Timestamp::parse_rfc3339(s).ok())
}

fn meta_str(meta: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    meta.and_then(|m| m.get(key)).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// The gate's condition, or why it has none.
pub fn spec_of(issue: &Issue) -> std::result::Result<GateSpec, String> {
    spec_from_metadata(&issue.metadata)
}

fn spec_from_metadata(metadata: &Value) -> std::result::Result<GateSpec, String> {
    let Some(meta) = metadata.get("gate").and_then(Value::as_object) else {
        return Err("no metadata.gate condition".into());
    };
    let mut fields = Map::new();
    for key in ["type", "await_id", "timeout", "repo", "branch", "event"] {
        if let Some(v) = meta.get(key).filter(|v| !v.is_null()) {
            fields.insert(key.into(), v.clone());
        }
    }
    let spec: GateSpec = serde_json::from_value(Value::Object(fields)).map_err(|e| e.to_string())?;
    spec.validate().map_err(|e| e.to_string())?;
    Ok(spec)
}

/// Gate view of `issue`; fails if it is not a gate.
pub fn view_of(conn: &Connection, issue: &Issue) -> Result<GateView> {
    if issue.issue_type != GATE_TYPE {
        return Err(Error::invalid(format!("{} is not a gate (type {})", issue.id, issue.issue_type)));
    }
    let meta = gate_meta(issue);
    let (spec, spec_error) = match spec_of(issue) {
        Ok(s) => (Some(s), None),
        Err(e) => (None, Some(e)),
    };
    let armed_at = (issue.status == Status::Open && !issue.is_blocked)
        .then(|| meta_time(meta, "armed_at").unwrap_or(issue.created_at));
    let escalated_at = meta_time(meta, "escalated_at");
    let escalation = meta_str(meta, "escalation");
    let deadline = match (&spec, armed_at) {
        (Some(s), Some(armed)) => s.timeout_ms().map(|ms| Timestamp(armed.millis().saturating_add(ms))),
        _ => None,
    };
    let phase = if issue.status.is_terminal() {
        GatePhase::Resolved
    } else if armed_at.is_none() {
        GatePhase::Waiting
    } else if escalation.is_some() {
        GatePhase::Escalated
    } else {
        GatePhase::Armed
    };
    let blocks = {
        let mut stmt = conn.prepare_cached(
            "SELECT o.id, o.title, o.status, o.priority, o.issue_type, o.assignee
             FROM dependencies d JOIN issues o ON o.id = d.issue_id
             WHERE d.depends_on_id = ?1 AND d.dep_type = 'blocks' ORDER BY o.id",
        )?;
        let rows = stmt.query_map([&issue.id], |r| {
            Ok(IssueRef {
                id: r.get(0)?,
                title: r.get(1)?,
                status: r.get(2)?,
                priority: r.get::<_, i64>(3)? as u8,
                issue_type: r.get(4)?,
                assignee: r.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(GateView {
        id: issue.id.clone(),
        title: issue.title.clone(),
        status: issue.status,
        phase,
        spec,
        spec_error,
        assignee: issue.assignee.clone(),
        created_at: issue.created_at,
        armed_at,
        deadline,
        escalated_at,
        escalation,
        run_id: meta_str(meta, "run_id"),
        closed_at: issue.closed_at,
        close_reason: issue.close_reason.clone(),
        blocks,
    })
}

pub fn view(conn: &Connection, id: &str) -> Result<GateView> {
    view_of(conn, &issues::require(conn, id)?)
}

/// Every gate (open ones only unless `include_closed`), oldest first.
pub fn list(conn: &Connection, include_closed: bool) -> Result<Vec<GateView>> {
    let sql = format!(
        "SELECT {} FROM issues i WHERE i.issue_type = 'gate' {} ORDER BY i.created_at, i.rowid",
        issues::ISSUE_COLUMNS,
        if include_closed { "" } else { "AND i.status NOT IN ('closed','pinned')" }
    );
    let gates: Vec<Issue> = {
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map([], issues::issue_from_row)?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    gates.iter().map(|g| view_of(conn, g)).collect()
}

/// The result of checking one gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", content = "detail", rename_all = "snake_case")]
pub enum Verdict {
    /// Still shut; nothing to do.
    Pending(String),
    /// The condition holds: close the gate.
    Resolve(String),
    /// The condition failed or the timeout passed: flag it for a human.
    Escalate(String),
}

impl Verdict {
    pub fn detail(&self) -> &str {
        match self {
            Verdict::Pending(d) | Verdict::Resolve(d) | Verdict::Escalate(d) => d,
        }
    }
}

/// Evaluate gates that need nothing outside the database (`human`, `timer`,
/// `issue`, and gates that are not armed or are malformed). Returns `None`
/// for armed GitHub gates, which the caller probes.
pub fn evaluate_local(conn: &Connection, gate: &GateView, now: Timestamp) -> Result<Option<Verdict>> {
    if gate.phase == GatePhase::Resolved {
        return Ok(Some(Verdict::Pending("already resolved".into())));
    }
    let Some(spec) = &gate.spec else {
        let why = gate.spec_error.clone().unwrap_or_default();
        return Ok(Some(Verdict::Escalate(format!("malformed gate: {why}"))));
    };
    if gate.armed_at.is_none() {
        return Ok(Some(Verdict::Pending("waiting for the work it holds back to become ready".into())));
    }
    Ok(match spec.kind {
        GateKind::Human => Some(Verdict::Pending(format!("waiting for a person: bd gate resolve {}", gate.id))),
        GateKind::Timer => {
            let deadline = gate.deadline.unwrap_or(now);
            if now >= deadline {
                Some(Verdict::Resolve(format!(
                    "timer elapsed ({} after arming at {})",
                    spec.timeout.as_deref().unwrap_or("?"),
                    gate.armed_at.unwrap_or(now)
                )))
            } else {
                Some(Verdict::Pending(format!("opens in {}", format_duration_ms(deadline.since(now)))))
            }
        }
        GateKind::Issue => {
            let raw = spec.await_id.as_deref().unwrap_or_default().trim();
            // beads' cross-rig form `<rig>:<id>`: the id is what matters here.
            let raw = raw.rsplit_once(':').map(|(_, id)| id).unwrap_or(raw);
            match issues::resolve_id(conn, raw) {
                Err(Error::NotFound { .. }) => Some(Verdict::Escalate(format!("awaited issue {raw} does not exist"))),
                Err(e) => return Err(e),
                Ok(id) => {
                    let target = issues::require(conn, &id)?;
                    match (target.status, target.close_outcome) {
                        (Status::Closed, Some(Outcome::Failed)) => Some(Verdict::Escalate(format!(
                            "{id} closed as failed{}",
                            target.close_reason.map(|r| format!(": {r}")).unwrap_or_default()
                        ))),
                        (Status::Closed, _) | (Status::Pinned, _) => Some(Verdict::Resolve(format!("{id} closed"))),
                        (st, _) => Some(Verdict::Pending(format!("{id} is {st}"))),
                    }
                }
            }
        }
        GateKind::GhRun | GateKind::GhPr => None,
    })
}

/// Escalation reason when a non-timer gate is still shut past its timeout.
/// The text depends only on the gate, so repeated checks escalate once.
pub fn overdue(gate: &GateView, now: Timestamp) -> Option<String> {
    let spec = gate.spec.as_ref()?;
    if spec.kind == GateKind::Timer || gate.phase == GatePhase::Resolved {
        return None;
    }
    let deadline = gate.deadline?;
    (now >= deadline).then(|| {
        format!(
            "still shut {} after arming at {}",
            spec.timeout.as_deref().unwrap_or("?"),
            gate.armed_at.map(|t| t.to_string()).unwrap_or_default()
        )
    })
}

/// Arming hook, called by [`graph::recompute`] for every net change of the
/// blocked flag: a gate that became unblocked arms now; one that became
/// blocked again disarms (and re-arms, restarting its clock, when unblocked).
pub(crate) fn note_block_changes(ctx: &mut WriteCtx<'_>, changes: &[BlockChange]) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let now = ctx.now().to_rfc3339();
    let conn = ctx.conn();
    let mut arm = conn.prepare_cached(
        "UPDATE issues SET metadata = json_set(metadata, '$.gate.armed_at', ?1)
         WHERE id = ?2 AND issue_type = 'gate' AND status NOT IN ('closed','pinned')
           AND json_type(metadata, '$.gate') = 'object'",
    )?;
    let mut disarm = conn.prepare_cached(
        "UPDATE issues SET metadata = json_remove(metadata, '$.gate.armed_at')
         WHERE id = ?1 AND issue_type = 'gate' AND json_type(metadata, '$.gate.armed_at') IS NOT NULL",
    )?;
    for c in changes {
        if c.blocked {
            disarm.execute([&c.id])?;
        } else {
            arm.execute(params![now, c.id])?;
        }
    }
    Ok(())
}

/// Input for an ad-hoc gate (`bd gate create`).
#[derive(Clone, Debug)]
pub struct NewGate {
    pub spec: GateSpec,
    /// Issues the gate holds back (at least one).
    pub blocks: Vec<String>,
    pub title: Option<String>,
    pub description: String,
    /// Who should act on it (e.g. the approver of a human gate).
    pub assignee: Option<String>,
    /// Default: the parent of the single issue it holds back.
    pub parent: Option<String>,
    pub priority: Option<u8>,
    pub ephemeral: bool,
}

impl WriteCtx<'_> {
    /// Refuse writing a GitHub gate (`issue_type` and `metadata` of a new or
    /// updated issue) whose `repo` the workspace does not allow, unless the
    /// issue already watched that repository before this update (`old`).
    pub(crate) fn check_gate_repo(&self, issue_type: &str, metadata: &Value, old: Option<&Issue>) -> Result<()> {
        let Some((kind, repo)) = github_repo(issue_type, metadata) else {
            return Ok(());
        };
        if old.and_then(|o| github_repo(&o.issue_type, &o.metadata)).is_some_and(|(_, r)| r == repo) {
            return Ok(());
        }
        GateRepos::load(self.conn(), self.policy().is_some())?.check_repo(kind, &repo)
    }

    /// Create a gate holding back `blocks`. The gate also takes on their
    /// prerequisites, so it arms only once that work could otherwise start.
    pub fn create_gate(&mut self, mut g: NewGate) -> Result<Issue> {
        g.spec.await_id =
            g.spec.await_id.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| {
                if g.spec.kind == GateKind::GhPr { s.trim_start_matches('#').to_string() } else { s.to_string() }
            });
        g.spec.validate()?;
        if g.blocks.is_empty() {
            return Err(Error::invalid("a gate must hold back at least one issue (--blocks <id>)"));
        }
        let mut held = Vec::new();
        for id in &g.blocks {
            let issue = issues::require(self.conn(), id)?;
            if issue.status.is_terminal() {
                return Err(Error::invalid(format!("{id} is already {}; nothing to hold back", issue.status)));
            }
            held.push(issue);
        }
        let parent = match g.parent {
            Some(p) => Some(p),
            None if held.len() == 1 => match graph::parent_of(self.conn(), &held[0].id)? {
                Some(p) if !issues::require(self.conn(), &p)?.status.is_terminal() => Some(p),
                _ => None,
            },
            None => None,
        };
        let work = (held.len() == 1).then(|| held[0].title.as_str());
        let title = g.title.clone().unwrap_or_else(|| g.spec.default_title(work));
        let gate = self.create_issue(NewIssue {
            title,
            description: g.description.clone(),
            issue_type: Some(GATE_TYPE.into()),
            priority: g.priority.or(Some(held.iter().map(|i| i.priority).min().unwrap_or(2))),
            assignee: g.assignee.clone(),
            parent,
            metadata: Some(json!({ "gate": g.spec.to_value() })),
            ephemeral: g.ephemeral,
            ..Default::default()
        })?;
        for issue in &held {
            self.add_dependency(&issue.id, &gate.id, DepType::Blocks, None)?;
        }
        for issue in &held {
            self.copy_prerequisites(&issue.id, &gate.id)?;
        }
        self.arm_gate_if_ready(&gate.id)?;
        issues::require(self.conn(), &gate.id)
    }

    /// Give `gate` the scheduling prerequisites of `work` (except itself).
    pub(crate) fn copy_prerequisites(&mut self, work: &str, gate: &str) -> Result<()> {
        let edges: Vec<(String, DepType, Value)> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT depends_on_id, dep_type, metadata FROM dependencies
                 WHERE issue_id = ?1 AND dep_type IN ('blocks','conditional-blocks','waits-for')
                 ORDER BY depends_on_id",
            )?;
            let rows = stmt.query_map([work], |r| {
                let meta: String = r.get(2)?;
                Ok((r.get::<_, String>(0)?, r.get::<_, DepType>(1)?, meta))
            })?;
            rows.map(|row| row.map(|(t, d, m)| (t, d, serde_json::from_str(&m).unwrap_or_else(|_| json!({})))))
                .collect::<rusqlite::Result<_>>()?
        };
        for (target, dep_type, meta) in edges {
            if target == gate || graph::load_edge(self.conn(), gate, &target)?.is_some() {
                continue;
            }
            self.add_dependency(gate, &target, dep_type, Some(meta))?;
        }
        Ok(())
    }

    /// Record `armed_at` for a gate that is open and unblocked but not yet armed
    /// (gates created unblocked never see a blocked -> unblocked change).
    pub(crate) fn arm_gate_if_ready(&mut self, id: &str) -> Result<()> {
        let now = self.now().to_rfc3339();
        self.conn()
            .prepare_cached(
                "UPDATE issues SET metadata = json_set(metadata, '$.gate.armed_at', ?1)
                 WHERE id = ?2 AND issue_type = 'gate' AND status = 'open' AND is_blocked = 0
                   AND json_type(metadata, '$.gate') = 'object'
                   AND json_type(metadata, '$.gate.armed_at') IS NULL",
            )?
            .execute(params![now, id])?;
        Ok(())
    }

    /// Open a gate by hand (any kind). `force` resolves it even while the
    /// work it holds back still has open prerequisites.
    pub fn resolve_gate(&mut self, id: &str, reason: Option<&str>, force: bool) -> Result<CloseOutcome> {
        let issue = issues::require(self.conn(), id)?;
        if issue.issue_type != GATE_TYPE {
            return Err(Error::invalid(format!("{id} is not a gate")));
        }
        if issue.is_blocked && !force && !issue.status.is_terminal() {
            return Err(Error::Refused(format!(
                "{id} is not armed yet (the work it holds back has open prerequisites); pass --force to resolve it early"
            )));
        }
        let reason = reason.map(str::trim).filter(|r| !r.is_empty()).map(String::from);
        let reason = reason.unwrap_or_else(|| format!("resolved by {}", self.actor()));
        self.close_issue(
            id,
            &CloseOptions { reason: Some(reason), outcome: Some(Outcome::Done), force: true, ..Default::default() },
        )
    }

    /// Flag a gate for attention. Idempotent per reason: returns false (and
    /// writes nothing) when the gate is already escalated for this reason.
    pub fn escalate_gate(&mut self, id: &str, reason: &str) -> Result<bool> {
        let issue = issues::require(self.conn(), id)?;
        if issue.issue_type != GATE_TYPE {
            return Err(Error::invalid(format!("{id} is not a gate")));
        }
        if issue.status.is_terminal() {
            return Ok(false);
        }
        if meta_str(gate_meta(&issue), "escalation").as_deref() == Some(reason) {
            return Ok(false);
        }
        let now = self.now();
        let mut metadata = issue.metadata.clone();
        let obj = metadata.as_object_mut().ok_or_else(|| Error::invalid(format!("{id} has non-object metadata")))?;
        let gate = obj.entry("gate").or_insert_with(|| json!({}));
        if !gate.is_object() {
            *gate = json!({});
        }
        gate["escalated_at"] = json!(now.to_rfc3339());
        gate["escalation"] = json!(reason);
        self.conn()
            .prepare_cached("UPDATE issues SET metadata = ?1, updated_at = ?2, revision = revision + 1 WHERE id = ?3")?
            .execute(params![metadata.to_string(), now, id])?;
        self.emit("gate_escalated", Some(id), json!({ "reason": reason }))?;
        self.add_comment(id, &format!("Gate escalated: {reason}"))?;
        Ok(true)
    }

    /// Remember which GitHub run a `gh:run` gate watches. Re-pinning to
    /// another run drops an escalation, which was about the previous run, and
    /// comments on the gate. Returns whether anything changed.
    pub fn pin_gate_run(&mut self, id: &str, run_id: &str, why: Option<&str>) -> Result<bool> {
        let issue = issues::require(self.conn(), id)?;
        if issue.issue_type != GATE_TYPE || gate_meta(&issue).is_none() {
            return Err(Error::invalid(format!("{id} is not a gate")));
        }
        let previous = meta_str(gate_meta(&issue), "run_id");
        if previous.as_deref() == Some(run_id) {
            return Ok(false);
        }
        if previous.is_some() {
            let now = self.now();
            self.conn()
                .prepare_cached(
                    "UPDATE issues SET metadata = json_remove(json_set(metadata, '$.gate.run_id', ?1),
                         '$.gate.escalation', '$.gate.escalated_at'), updated_at = ?2, revision = revision + 1
                     WHERE id = ?3",
                )?
                .execute(params![run_id, now, id])?;
        } else {
            self.conn()
                .prepare_cached("UPDATE issues SET metadata = json_set(metadata, '$.gate.run_id', ?1) WHERE id = ?2")?
                .execute(params![run_id, id])?;
        }
        self.emit("gate_updated", Some(id), json!({ "run_id": run_id, "previous_run_id": previous }))?;
        if let Some(prev) = &previous {
            let why = why.map(|w| format!(": {w}")).unwrap_or_default();
            self.add_comment(id, &format!("Now watching GitHub run {run_id} instead of {prev}{why}"))?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_validation() {
        let mut s = GateSpec::new(GateKind::Timer);
        assert!(s.validate().is_err(), "timer needs a duration");
        s.timeout = Some("1d".into());
        s.validate().unwrap();
        s.timeout = Some("1x".into());
        assert!(s.validate().is_err());

        let mut pr = GateSpec::new(GateKind::GhPr);
        pr.await_id = Some("main".into());
        assert!(pr.validate().is_err(), "PR numbers only");
        pr.await_id = Some("#42".into());
        pr.repo = Some("org/repo".into());
        pr.validate().unwrap();
        pr.repo = Some("not a repo".into());
        assert!(pr.validate().is_err());
        pr.repo = None;
        pr.branch = Some("main".into());
        assert!(pr.validate().is_err(), "branch is gh:run-only");

        let mut run = GateSpec::new(GateKind::GhRun);
        run.await_id = Some("release.yml".into());
        run.branch = Some("v1.2.3".into());
        run.event = Some("push".into());
        run.validate().unwrap();
        run.event = Some("Push now".into());
        assert!(run.validate().is_err());
        run.event = None;
        run.branch = Some("two words".into());
        assert!(run.validate().is_err());
        run.branch = Some("main".into());
        run.await_id = Some("12345".into());
        assert_eq!(run.run_id(), Some("12345"));
        assert!(run.validate().is_err(), "a run id pins one run; filters make no sense");

        let mut human = GateSpec::new(GateKind::Human);
        human.repo = Some("org/repo".into());
        assert!(human.validate().is_err(), "repo is GitHub-only");
        assert_eq!(GateKind::parse("bead").unwrap(), GateKind::Issue);
        assert!(GateKind::parse("mail").is_err());
    }
}
