//! Issue lifecycle: init, create, show, list, update, close, reopen, defer, delete, ready, blocked, purge.

use clap::{Args, ValueEnum};

use super::*;

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// Issue id prefix (default: derived from the directory name)
    #[arg(long)]
    pub prefix: Option<String>,
    /// Id scheme
    #[arg(long, value_enum, default_value = "hash")]
    pub id_mode: IdModeArg,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum IdModeArg {
    Hash,
    Counter,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    /// Title (words are joined)
    #[arg(required = true, num_args = 1..)]
    pub title: Vec<String>,
    #[arg(short, long)]
    pub description: Option<String>,
    #[arg(long)]
    pub design: Option<String>,
    #[arg(long)]
    pub acceptance: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// task, bug, feature, epic, chore, decision, spike, story, milestone
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,
    /// 0 (critical) .. 4 (backlog); P0..P4 accepted
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    /// Reserve for an assignee (only they, or a pool, can claim it)
    #[arg(short, long)]
    pub assignee: Option<String>,
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Parent issue (creates a hierarchical child id)
    #[arg(long)]
    pub parent: Option<String>,
    /// Dependencies of the new issue: ID (blocks) or TYPE:ID, e.g. discovered-from:bd-12
    #[arg(long = "dep", value_delimiter = ',')]
    pub deps: Vec<String>,
    #[arg(long)]
    pub external_ref: Option<String>,
    /// Estimate in minutes
    #[arg(long)]
    pub estimate: Option<i64>,
    /// Due time (2026-01-15, +2d, RFC 3339)
    #[arg(long)]
    pub due: Option<String>,
    /// Hide from ready work until this time
    #[arg(long)]
    pub defer: Option<String>,
    /// Metadata JSON object
    #[arg(long)]
    pub metadata: Option<String>,
    /// Explicit id
    #[arg(long)]
    pub id: Option<String>,
    /// Create as pinned (persistent context, never ready, releases dependents)
    #[arg(long)]
    pub pinned: bool,
    /// Scratch work: left out of exports and deleted by `bd purge` once closed
    #[arg(long)]
    pub ephemeral: bool,
    /// Claim the new issue for yourself in the same transaction
    #[arg(long)]
    pub claim: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct FilterArgs {
    /// Only issues assigned to this actor
    #[arg(short, long)]
    pub assignee: Option<String>,
    /// Only unassigned issues
    #[arg(long)]
    pub unassigned: bool,
    #[arg(short = 't', long = "type", value_delimiter = ',')]
    pub types: Vec<String>,
    #[arg(long = "exclude-type", value_delimiter = ',')]
    pub exclude_types: Vec<String>,
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    /// Only priorities at or above this one (e.g. 1 = P0 and P1)
    #[arg(long, value_parser = parse_priority)]
    pub max_priority: Option<u8>,
    /// Must have ALL these labels
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Must have ANY of these labels
    #[arg(long = "label-any", value_delimiter = ',')]
    pub labels_any: Vec<String>,
    /// Must have NONE of these labels
    #[arg(long = "exclude-label", value_delimiter = ',')]
    pub exclude_labels: Vec<String>,
    /// Only issues below this one in the hierarchy (--run: the steps of a playbook run)
    #[arg(long, visible_alias = "run")]
    pub parent: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Status filter (repeatable or comma separated); default hides closed and pinned
    #[arg(short, long, value_delimiter = ',')]
    pub status: Vec<String>,
    /// Include closed and pinned issues
    #[arg(long)]
    pub all: bool,
    /// Only issues blocked by dependencies
    #[arg(long)]
    pub blocked: bool,
    /// Case-insensitive text search over id, title, description, notes
    #[arg(long)]
    pub search: Option<String>,
    /// priority | created | updated | id
    #[arg(long, default_value = "priority")]
    pub sort: String,
    #[arg(long)]
    pub reverse: bool,
    /// Maximum rows (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GuardArgs {
    /// Apply only if the issue is still at this revision
    #[arg(long, value_name = "N")]
    pub if_revision: Option<i64>,
    /// Apply only if the status still equals this
    #[arg(long, value_name = "STATUS")]
    pub if_status: Option<String>,
    /// Apply only if the assignee still equals this ('' = unassigned)
    #[arg(long, value_name = "ACTOR")]
    pub if_assignee: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    pub id: String,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(short, long)]
    pub description: Option<String>,
    #[arg(long)]
    pub design: Option<String>,
    #[arg(long)]
    pub acceptance: Option<String>,
    /// Replace notes
    #[arg(long)]
    pub notes: Option<String>,
    /// Append a line to notes
    #[arg(long)]
    pub append_notes: Option<String>,
    /// open | blocked | deferred | pinned | in_progress (needs an assignee)
    #[arg(short, long)]
    pub status: Option<String>,
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,
    /// New assignee ('' to unassign)
    #[arg(short, long)]
    pub assignee: Option<String>,
    /// '' clears
    #[arg(long)]
    pub external_ref: Option<String>,
    /// Minutes ('' clears)
    #[arg(long)]
    pub estimate: Option<String>,
    /// Due time ('' clears)
    #[arg(long)]
    pub due: Option<String>,
    /// Hide from ready until this time ('' clears)
    #[arg(long)]
    pub defer: Option<String>,
    /// Replace metadata with this JSON object
    #[arg(long)]
    pub metadata: Option<String>,
    /// Set metadata key=value (value parsed as JSON when valid)
    #[arg(long = "set-metadata", value_name = "K=V")]
    pub set_metadata: Vec<String>,
    #[arg(long = "unset-metadata", value_name = "KEY")]
    pub unset_metadata: Vec<String>,
    #[arg(long = "add-label", value_delimiter = ',')]
    pub add_labels: Vec<String>,
    #[arg(long = "remove-label", value_delimiter = ',')]
    pub remove_labels: Vec<String>,
    /// Replace all labels
    #[arg(long = "set-labels", value_delimiter = ',')]
    pub set_labels: Option<Vec<String>>,
    /// Move under a new parent ('' detaches)
    #[arg(long)]
    pub parent: Option<String>,
    /// Mark as scratch work (true) or keep it permanently (false)
    #[arg(long, value_name = "BOOL")]
    pub ephemeral: Option<bool>,
    #[command(flatten)]
    pub guard: GuardArgs,
    /// Take over or end another actor's live claim: reassign it, or move it out of in_progress (recorded in the
    /// event; through bd serve, an admin token unless the token's actor owns the claim)
    #[arg(long)]
    pub take_over: bool,
}

#[derive(Args, Debug, Clone)]
pub struct CloseArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(short, long, alias = "message")]
    pub reason: Option<String>,
    /// Record the outcome as failed (releases conditional-blocks dependents)
    #[arg(long)]
    pub failed: bool,
    /// Close despite open children or live blockers (never past another actor's claim: see --take-over)
    #[arg(long)]
    pub force: bool,
    /// Close another actor's live claim (recorded in the event; through bd serve, an admin token unless the token's
    /// actor owns the claim)
    #[arg(long)]
    pub take_over: bool,
    /// Fencing token from `claim`: close only while that lease is held
    #[arg(long)]
    pub token: Option<i64>,
    #[command(flatten)]
    pub guard: GuardArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ReopenArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(short, long)]
    pub reason: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DeferArgs {
    pub id: String,
    /// Until when (2026-01-15, +3d, RFC 3339); omit to defer indefinitely
    #[arg(long)]
    pub until: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Also delete everything that depends on them
    #[arg(long)]
    pub cascade: bool,
    /// Delete even if other issues depend on them (drops those edges; never past another actor's claim: see
    /// --take-over)
    #[arg(long)]
    pub force: bool,
    /// Delete issues other actors hold live claims on (recorded in the events; through bd serve, an admin token unless
    /// the token's actor owns the claims)
    #[arg(long)]
    pub take_over: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ReadyArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// priority | hybrid | oldest
    #[arg(long, default_value = "priority")]
    pub sort: String,
    /// Maximum rows (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 50)]
    pub limit: usize,
    /// Include issues deferred to a future time
    #[arg(long)]
    pub include_deferred: bool,
    /// Include epics (containers are excluded by default)
    #[arg(long)]
    pub include_epics: bool,
}

#[derive(Args, Debug, Clone)]
pub struct BlockedArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    #[arg(short = 'n', long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone)]
pub struct PurgeArgs {
    /// Only issues closed at least this long ago (e.g. 7d)
    #[arg(long)]
    pub older_than: Option<String>,
    /// List what would be deleted
    #[arg(long)]
    pub dry_run: bool,
}
