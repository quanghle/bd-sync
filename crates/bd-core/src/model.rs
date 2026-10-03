//! Domain types shared by the engine and its clients.

use std::fmt;
use std::str::FromStr;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::time::Timestamp;

/// Issue lifecycle states.
///
/// `closed` and `pinned` are *terminal for blocking*: they release issues that
/// depend on them. Every other status keeps dependents blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    Open,
    InProgress,
    Blocked,
    Deferred,
    Closed,
    Pinned,
}

impl Status {
    pub const ALL: [Status; 6] =
        [Status::Open, Status::InProgress, Status::Blocked, Status::Deferred, Status::Closed, Status::Pinned];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::InProgress => "in_progress",
            Status::Blocked => "blocked",
            Status::Deferred => "deferred",
            Status::Closed => "closed",
            Status::Pinned => "pinned",
        }
    }

    pub fn parse(s: &str) -> Result<Status> {
        Ok(match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "open" => Status::Open,
            "in_progress" | "inprogress" | "wip" => Status::InProgress,
            "blocked" => Status::Blocked,
            "deferred" => Status::Deferred,
            "closed" | "done" => Status::Closed,
            "pinned" => Status::Pinned,
            other => {
                return Err(Error::invalid(format!(
                    "unknown status {other:?} (valid: open, in_progress, blocked, deferred, closed, pinned)"
                )));
            }
        })
    }

    /// Terminal statuses release dependents.
    pub fn is_terminal(self) -> bool {
        matches!(self, Status::Closed | Status::Pinned)
    }

    pub fn icon(self) -> &'static str {
        match self {
            Status::Open => "○",
            Status::InProgress => "◐",
            Status::Blocked => "●",
            Status::Deferred => "❄",
            Status::Closed => "✓",
            Status::Pinned => "📌",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Status {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Status::parse(s)
    }
}

/// Typed dependency edges. An edge `issue -> depends_on` reads
/// "issue depends on depends_on".
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DepType {
    /// Hard ordering: issue stays blocked until the target is closed/pinned.
    Blocks,
    /// Error path: issue runs only if the target closes with outcome `failed`.
    ConditionalBlocks,
    /// Hierarchy (child -> parent). A blocked parent blocks its whole subtree.
    ParentChild,
    /// Fan-in gate: issue waits on the target's children
    /// (metadata `gate`: `all-children` (default) | `any-children`).
    WaitsFor,
    Related,
    DiscoveredFrom,
    Tracks,
    CausedBy,
    Validates,
    Supersedes,
    Duplicates,
    RepliesTo,
    /// Any other lowercase name; informational, never blocks.
    Custom(String),
}

impl DepType {
    pub const BUILTIN: [&'static str; 12] = [
        "blocks",
        "conditional-blocks",
        "parent-child",
        "waits-for",
        "related",
        "discovered-from",
        "tracks",
        "caused-by",
        "validates",
        "supersedes",
        "duplicates",
        "replies-to",
    ];

    pub fn as_str(&self) -> &str {
        match self {
            DepType::Blocks => "blocks",
            DepType::ConditionalBlocks => "conditional-blocks",
            DepType::ParentChild => "parent-child",
            DepType::WaitsFor => "waits-for",
            DepType::Related => "related",
            DepType::DiscoveredFrom => "discovered-from",
            DepType::Tracks => "tracks",
            DepType::CausedBy => "caused-by",
            DepType::Validates => "validates",
            DepType::Supersedes => "supersedes",
            DepType::Duplicates => "duplicates",
            DepType::RepliesTo => "replies-to",
            DepType::Custom(s) => s,
        }
    }

    pub fn parse(s: &str) -> Result<DepType> {
        let norm = s.trim().to_ascii_lowercase().replace('_', "-");
        Ok(match norm.as_str() {
            "blocks" | "blocked-by" | "depends-on" => DepType::Blocks,
            "conditional-blocks" | "conditional" | "on-failure" => DepType::ConditionalBlocks,
            "parent-child" | "parent" | "child-of" => DepType::ParentChild,
            "waits-for" => DepType::WaitsFor,
            "related" | "relates-to" => DepType::Related,
            "discovered-from" => DepType::DiscoveredFrom,
            "tracks" => DepType::Tracks,
            "caused-by" => DepType::CausedBy,
            "validates" => DepType::Validates,
            "supersedes" => DepType::Supersedes,
            "duplicates" => DepType::Duplicates,
            "replies-to" => DepType::RepliesTo,
            other => {
                let valid = !other.is_empty()
                    && other.len() <= 32
                    && other.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && other.starts_with(|c: char| c.is_ascii_lowercase());
                if !valid {
                    return Err(Error::invalid(format!(
                        "invalid dependency type {s:?} (built-in: {}; custom types must match [a-z][a-z0-9-]{{0,31}})",
                        DepType::BUILTIN.join(", ")
                    )));
                }
                DepType::Custom(other.to_string())
            }
        })
    }

    /// Edge types that influence readiness.
    pub fn affects_ready(&self) -> bool {
        matches!(self, DepType::Blocks | DepType::ConditionalBlocks | DepType::ParentChild | DepType::WaitsFor)
    }

    /// Edge types checked for cycles (a cycle among them is a deadlock).
    pub fn is_scheduling(&self) -> bool {
        matches!(self, DepType::Blocks | DepType::ConditionalBlocks | DepType::ParentChild)
    }
}

impl fmt::Display for DepType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DepType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        DepType::parse(s)
    }
}

/// How a closed issue ended; drives `conditional-blocks` edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    Done,
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Done => "done",
            Outcome::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Outcome> {
        match s.trim().to_ascii_lowercase().as_str() {
            "done" | "success" | "succeeded" => Ok(Outcome::Done),
            "failed" | "failure" | "fail" => Ok(Outcome::Failed),
            other => Err(Error::invalid(format!("unknown outcome {other:?} (valid: done, failed)"))),
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! string_enum_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                <$t>::parse(&s).map_err(serde::de::Error::custom)
            }
        }
        impl ToSql for $t {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::from(self.as_str().to_string()))
            }
        }
        impl FromSql for $t {
            fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
                let s = v.as_str()?;
                <$t>::parse(s).map_err(|e| FromSqlError::Other(Box::new(e)))
            }
        }
    };
}

string_enum_serde!(Status);
string_enum_serde!(DepType);
string_enum_serde!(Outcome);

/// Built-in issue types. Extra types may be allowed with the
/// `types.custom` config key (comma separated). `gate` issues are wait
/// conditions (see [`crate::gates`]): never ready, never claimed.
pub const BUILTIN_TYPES: [&str; 10] =
    ["task", "bug", "feature", "epic", "chore", "decision", "spike", "story", "milestone", "gate"];

/// Issue type of gates.
pub const GATE_TYPE: &str = "gate";

/// Maximum title length (characters).
pub const MAX_TITLE_CHARS: usize = 500;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub design: String,
    #[serde(default, alias = "acceptance")]
    pub acceptance_criteria: String,
    #[serde(default)]
    pub notes: String,
    pub status: Status,
    pub priority: u8,
    #[serde(alias = "type")]
    pub issue_type: String,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub estimated_minutes: Option<i64>,
    #[serde(default = "empty_object")]
    pub metadata: Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    #[serde(default)]
    pub started_at: Option<Timestamp>,
    #[serde(default)]
    pub closed_at: Option<Timestamp>,
    #[serde(default)]
    pub close_reason: Option<String>,
    #[serde(default)]
    pub close_outcome: Option<Outcome>,
    #[serde(default)]
    pub due_at: Option<Timestamp>,
    #[serde(default)]
    pub defer_until: Option<Timestamp>,
    /// Scratch work: excluded from exports and deleted by `purge` once closed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ephemeral: bool,
    /// Materialized: true while a live blocking edge (or a blocked ancestor)
    /// holds this issue back.
    #[serde(default)]
    pub is_blocked: bool,
    /// Monotonic per-issue version for optimistic concurrency.
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub labels: Vec<String>,
}

pub(crate) fn empty_object() -> Value {
    Value::Object(Default::default())
}

pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

impl Issue {
    pub fn to_ref(&self) -> IssueRef {
        IssueRef {
            id: self.id.clone(),
            title: self.title.clone(),
            status: self.status,
            priority: self.priority,
            issue_type: self.issue_type.clone(),
            assignee: self.assignee.clone(),
        }
    }
}

/// A compact issue summary used in lists of related issues.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRef {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub priority: u8,
    pub issue_type: String,
    #[serde(default)]
    pub assignee: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Dependency {
    pub issue_id: String,
    pub depends_on_id: String,
    #[serde(rename = "type", alias = "dep_type")]
    pub dep_type: DepType,
    pub created_at: Timestamp,
    #[serde(default)]
    pub created_by: String,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

/// One side of an edge as seen from an issue (`show`, `dep list`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub priority: u8,
    #[serde(rename = "type")]
    pub dep_type: DepType,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub id: i64,
    pub issue_id: String,
    pub author: String,
    pub text: String,
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    pub key: String,
    pub content: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub created_by: String,
    pub updated_by: String,
    pub revision: i64,
}

/// A claim lease. `token` is a fencing token: it is the sequence number of
/// the event that granted the lease, so it is unique and strictly increasing
/// across all grants in the workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub issue_id: String,
    pub holder: String,
    pub token: i64,
    pub granted_at: Timestamp,
    pub expires_at: Timestamp,
    pub heartbeat_at: Timestamp,
    pub renewals: i64,
}

impl Lease {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at <= now
    }

    pub fn remaining_ms(&self, now: Timestamp) -> i64 {
        self.expires_at.since(now)
    }
}

/// One row of the transactional event history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Gapless, commit-ordered sequence number.
    pub seq: i64,
    /// Sequence number of the first event written by the same transaction.
    pub tx: i64,
    pub ts: Timestamp,
    pub actor: String,
    pub op: String,
    #[serde(default)]
    pub issue_id: Option<String>,
    #[serde(default = "empty_object")]
    pub data: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    /// `blocks` edge onto a live issue.
    Blocks,
    /// `conditional-blocks` edge whose target has not failed (yet).
    Conditional,
    /// `waits-for` gate that is still shut.
    WaitsFor,
    /// A blocked ancestor (inherited through `parent-child`).
    Parent,
}

/// Why an issue is not ready.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocker {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub kind: BlockerKind,
    pub detail: String,
}

/// Everything `show` displays about one issue.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssueDetails {
    #[serde(flatten)]
    pub issue: Issue,
    pub parent: Option<String>,
    pub children: Vec<IssueRef>,
    pub dependencies: Vec<Edge>,
    pub dependents: Vec<Edge>,
    pub blockers: Vec<Blocker>,
    pub lease: Option<Lease>,
    pub comments: Vec<Comment>,
    /// Set when the issue (or an ancestor) is deferred, so it is hidden from ready.
    pub deferred_by: Option<String>,
}

/// Input for creating an issue.
#[derive(Clone, Debug, Default)]
pub struct NewIssue {
    pub id: Option<String>,
    pub title: String,
    pub description: String,
    pub design: String,
    pub acceptance_criteria: String,
    pub notes: String,
    pub issue_type: Option<String>,
    pub priority: Option<u8>,
    pub status: Option<Status>,
    pub assignee: Option<String>,
    pub labels: Vec<String>,
    pub parent: Option<String>,
    /// Edges from the new issue: `(type, target)` = "new issue depends on target".
    pub deps: Vec<(DepType, String)>,
    pub external_ref: Option<String>,
    pub estimated_minutes: Option<i64>,
    pub due_at: Option<Timestamp>,
    pub defer_until: Option<Timestamp>,
    pub metadata: Option<Value>,
    /// Scratch work, excluded from exports and purged once closed.
    pub ephemeral: bool,
}

impl NewIssue {
    pub fn titled(title: impl Into<String>) -> Self {
        NewIssue { title: title.into(), ..Default::default() }
    }
}

/// A partial update. `None` leaves a field untouched; for nullable fields,
/// `Some(None)` clears the value.
#[derive(Clone, Debug, Default)]
pub struct IssuePatch {
    pub title: Option<String>,
    pub description: Option<String>,
    pub design: Option<String>,
    pub acceptance_criteria: Option<String>,
    pub notes: Option<String>,
    pub append_notes: Option<String>,
    pub status: Option<Status>,
    pub priority: Option<u8>,
    pub issue_type: Option<String>,
    pub assignee: Option<Option<String>>,
    pub external_ref: Option<Option<String>>,
    pub estimated_minutes: Option<Option<i64>>,
    pub due_at: Option<Option<Timestamp>>,
    pub defer_until: Option<Option<Timestamp>>,
    pub metadata: Option<Value>,
    pub set_metadata: Vec<(String, Value)>,
    pub unset_metadata: Vec<String>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
    pub set_labels: Option<Vec<String>>,
    /// Reparent: `Some(Some(p))` moves under `p`, `Some(None)` detaches.
    pub parent: Option<Option<String>>,
    pub ephemeral: Option<bool>,
}

impl IssuePatch {
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.description.is_none()
            && self.design.is_none()
            && self.acceptance_criteria.is_none()
            && self.notes.is_none()
            && self.append_notes.is_none()
            && self.status.is_none()
            && self.priority.is_none()
            && self.issue_type.is_none()
            && self.assignee.is_none()
            && self.external_ref.is_none()
            && self.estimated_minutes.is_none()
            && self.due_at.is_none()
            && self.defer_until.is_none()
            && self.metadata.is_none()
            && self.set_metadata.is_empty()
            && self.unset_metadata.is_empty()
            && self.add_labels.is_empty()
            && self.remove_labels.is_empty()
            && self.set_labels.is_none()
            && self.parent.is_none()
            && self.ephemeral.is_none()
    }
}

/// Optimistic-concurrency preconditions, checked inside the write
/// transaction. All present guards must hold or nothing is written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Guard {
    pub if_revision: Option<i64>,
    pub if_status: Option<Status>,
    /// `Some(None)` requires the issue to be unassigned.
    pub if_assignee: Option<Option<String>>,
}

impl Guard {
    pub fn is_empty(&self) -> bool {
        self.if_revision.is_none() && self.if_status.is_none() && self.if_assignee.is_none()
    }

    pub fn check(&self, issue: &Issue) -> Result<()> {
        if let Some(rev) = self.if_revision {
            if issue.revision != rev {
                return Err(Error::Conflict {
                    id: issue.id.clone(),
                    field: "revision",
                    expected: rev.to_string(),
                    actual: issue.revision.to_string(),
                });
            }
        }
        if let Some(status) = self.if_status {
            if issue.status != status {
                return Err(Error::Conflict {
                    id: issue.id.clone(),
                    field: "status",
                    expected: status.to_string(),
                    actual: issue.status.to_string(),
                });
            }
        }
        if let Some(expected) = &self.if_assignee {
            if issue.assignee.as_deref() != expected.as_deref() {
                let show = |a: Option<&str>| a.map(|s| format!("{s:?}")).unwrap_or_else(|| "unassigned".into());
                return Err(Error::Conflict {
                    id: issue.id.clone(),
                    field: "assignee",
                    expected: show(expected.as_deref()),
                    actual: show(issue.assignee.as_deref()),
                });
            }
        }
        Ok(())
    }
}

/// Ready-queue ordering. Every policy ends with `id` so results are total
/// and deterministic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortPolicy {
    /// priority, then oldest first.
    #[default]
    Priority,
    /// Issues created in the last 48h by priority, then older issues by age.
    Hybrid,
    /// Oldest first, ignoring priority.
    Oldest,
}

impl SortPolicy {
    pub fn parse(s: &str) -> Result<SortPolicy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "priority" => Ok(SortPolicy::Priority),
            "hybrid" => Ok(SortPolicy::Hybrid),
            "oldest" | "fifo" => Ok(SortPolicy::Oldest),
            other => Err(Error::invalid(format!("invalid sort policy {other:?} (valid: priority, hybrid, oldest)"))),
        }
    }
}

/// Filters shared by `ready`, `claim --next`, `list`, and `reclaim`.
#[derive(Clone, Debug, Default)]
pub struct WorkFilter {
    pub assignee: Option<String>,
    pub unassigned: bool,
    pub types: Vec<String>,
    pub exclude_types: Vec<String>,
    pub priority: Option<u8>,
    /// Upper bound (inclusive) on priority number, e.g. 1 = P0 and P1 only.
    pub max_priority: Option<u8>,
    pub labels_all: Vec<String>,
    pub labels_any: Vec<String>,
    pub exclude_labels: Vec<String>,
    /// Only issues below this one in the parent-child hierarchy.
    pub parent: Option<String>,
    pub ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ReadyQuery {
    pub filter: WorkFilter,
    pub sort: SortPolicy,
    /// `None` = unlimited.
    pub limit: Option<usize>,
    pub include_deferred: bool,
    /// Epics are containers, not work; they are excluded unless asked for
    /// (and like any issue with open children, one is not ready: see [`crate::ready`]).
    pub include_epics: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ListSort {
    #[default]
    Priority,
    Created,
    Updated,
    Id,
}

impl ListSort {
    pub fn parse(s: &str) -> Result<ListSort> {
        match s.trim().to_ascii_lowercase().as_str() {
            "priority" => Ok(ListSort::Priority),
            "created" => Ok(ListSort::Created),
            "updated" => Ok(ListSort::Updated),
            "id" => Ok(ListSort::Id),
            other => Err(Error::invalid(format!("invalid sort {other:?} (valid: priority, created, updated, id)"))),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ListQuery {
    pub filter: WorkFilter,
    /// Empty = every status except closed and pinned (unless `all`).
    pub statuses: Vec<Status>,
    pub all: bool,
    pub blocked_only: bool,
    /// Case-insensitive substring over id, title, description, notes.
    pub search: Option<String>,
    pub sort: ListSort,
    pub reverse: bool,
    pub limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parsing_and_terminality() {
        assert_eq!(Status::parse("in-progress").unwrap(), Status::InProgress);
        assert!(Status::Closed.is_terminal() && Status::Pinned.is_terminal());
        assert!(!Status::Deferred.is_terminal());
        assert!(Status::parse("tombstone").is_err());
    }

    #[test]
    fn dep_type_parsing() {
        assert_eq!(DepType::parse("blocked-by").unwrap(), DepType::Blocks);
        assert_eq!(DepType::parse("parent").unwrap(), DepType::ParentChild);
        assert_eq!(DepType::parse("mentions").unwrap(), DepType::Custom("mentions".into()));
        assert!(DepType::parse("Bad Type").is_err());
        assert!(DepType::WaitsFor.affects_ready() && !DepType::WaitsFor.is_scheduling());
        assert!(!DepType::Related.affects_ready());
    }

    #[test]
    fn guard_checks() {
        let issue = Issue {
            id: "x-1".into(),
            title: "t".into(),
            description: String::new(),
            design: String::new(),
            acceptance_criteria: String::new(),
            notes: String::new(),
            status: Status::Open,
            priority: 2,
            issue_type: "task".into(),
            assignee: None,
            created_by: "a".into(),
            external_ref: None,
            estimated_minutes: None,
            metadata: empty_object(),
            created_at: Timestamp(0),
            updated_at: Timestamp(0),
            started_at: None,
            closed_at: None,
            close_reason: None,
            close_outcome: None,
            due_at: None,
            defer_until: None,
            ephemeral: false,
            is_blocked: false,
            revision: 3,
            labels: vec![],
        };
        assert!(Guard { if_revision: Some(3), ..Default::default() }.check(&issue).is_ok());
        let err = Guard { if_revision: Some(2), ..Default::default() }.check(&issue).unwrap_err();
        assert_eq!(err.exit_code(), 13);
        assert!(Guard { if_assignee: Some(None), ..Default::default() }.check(&issue).is_ok());
        assert!(Guard { if_assignee: Some(Some("bob".into())), ..Default::default() }.check(&issue).is_err());
    }
}
