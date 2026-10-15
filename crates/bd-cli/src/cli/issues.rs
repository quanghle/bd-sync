//! Issue lifecycle: init, create, show, list, update, close, reopen, defer, delete, ready, blocked, purge.

use clap::{Args, ValueEnum};

use super::*;

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// Issue id prefix: letters, digits and '-', at most 32, lowercased (default: from the directory name)
    #[arg(long, value_name = "PREFIX")]
    pub prefix: Option<String>,
    /// How new issue ids are made
    #[arg(long, value_enum, default_value = "hash")]
    pub id_mode: IdModeArg,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum IdModeArg {
    /// Short hash ids, e.g. bd-a3f
    Hash,
    /// Sequential numbers, e.g. bd-1
    Counter,
}

pub const CREATE_LONG_ABOUT: &str = "\
Create an issue

A new issue starts open and joins the ready queue once nothing blocks or
defers it; --pinned creates it pinned instead, which is never ready. A --dep
of type blocks (the default), conditional-blocks or waits-for makes it wait on
an existing issue, and parent-child:ID (aliases parent:, child-of:) is the
same as --parent ID; other types, such as discovered-from, only record a
relation. --parent puts it below one. With --claim it is claimed for the
actor in the same transaction; if it cannot be claimed (not ready, or
pinned), nothing is created. The new id is printed (alone with --quiet).";

const CREATE_EXAMPLES: &str = "\
Examples:
  bd create \"Fix login\" -t bug -p 1 --dep discovered-from:bd-12
  bd create \"Write the migration\" --parent bd-7 --claim";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = CREATE_EXAMPLES)]
pub struct CreateArgs {
    /// Title, at most 500 characters (words are joined)
    #[arg(required = true, num_args = 1..)]
    pub title: Vec<String>,
    /// Description
    #[arg(short, long)]
    pub description: Option<String>,
    /// Design notes
    #[arg(long)]
    pub design: Option<String>,
    /// Acceptance criteria
    #[arg(long)]
    pub acceptance: Option<String>,
    /// Notes
    #[arg(long)]
    pub notes: Option<String>,
    /// Type: task, bug, feature, epic, chore, decision, spike, story, milestone, gate (see `bd gate create`), or one in
    /// config types.custom (default: task)
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,
    /// Priority 0 (critical) to 4 (backlog), P0-P4 also accepted (default: 2)
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    /// Reserve for ACTOR: only it may claim the issue, unless ACTOR is in config claim.pools (then any actor may)
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Labels (repeatable or comma separated)
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Parent issue (the new issue gets a child id below it)
    #[arg(long, value_name = "ID")]
    pub parent: Option<String>,
    /// Dependency of the new issue: ID (it blocks the new issue) or TYPE:ID, e.g. discovered-from:bd-12 (repeatable or
    /// comma separated; types: `bd dep add -h`)
    #[arg(long = "dep", value_delimiter = ',', value_name = "[TYPE:]ID")]
    pub deps: Vec<String>,
    /// Reference in another system, e.g. gh-123
    #[arg(long)]
    pub external_ref: Option<String>,
    /// Estimate in minutes, 0 or more
    #[arg(long, value_name = "MINUTES")]
    pub estimate: Option<i64>,
    /// Due time, e.g. 2026-01-15 or +2d
    #[arg(long, value_name = "TIME")]
    pub due: Option<String>,
    /// Hide from ready work until this time
    #[arg(long, value_name = "TIME")]
    pub defer: Option<String>,
    /// Metadata, a JSON object
    #[arg(long, value_name = "JSON")]
    pub metadata: Option<String>,
    /// Explicit id: letters, digits, '-', '_' or '.', starting with a letter or digit, at most 255 characters
    #[arg(long)]
    pub id: Option<String>,
    /// Create as pinned (persistent context, never ready, releases dependents)
    #[arg(long)]
    pub pinned: bool,
    /// Scratch work: left out of exports and deleted by `bd purge` once closed
    #[arg(long)]
    pub ephemeral: bool,
    /// Claim the new issue in the same transaction
    #[arg(long)]
    pub claim: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    /// Issue ids
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct FilterArgs {
    /// Only issues assigned to this actor
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Only unassigned issues
    #[arg(long)]
    pub unassigned: bool,
    /// Only these types (repeatable or comma separated)
    #[arg(short = 't', long = "type", value_delimiter = ',')]
    pub types: Vec<String>,
    /// Leave out these types (repeatable or comma separated)
    #[arg(long = "exclude-type", value_delimiter = ',')]
    pub exclude_types: Vec<String>,
    /// Only this priority, 0-4 or P0-P4
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    /// Only priorities at or above this one, e.g. 1 = P0 and P1
    #[arg(long, value_parser = parse_priority)]
    pub max_priority: Option<u8>,
    /// Only issues with all these labels (repeatable or comma separated)
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Only issues with any of these labels (repeatable or comma separated)
    #[arg(long = "label-any", value_delimiter = ',')]
    pub labels_any: Vec<String>,
    /// Leave out issues with any of these labels (repeatable or comma separated)
    #[arg(long = "exclude-label", value_delimiter = ',')]
    pub exclude_labels: Vec<String>,
    /// Only issues below this one in the hierarchy (--run: the steps of a playbook run)
    #[arg(long, visible_alias = "run", value_name = "ID")]
    pub parent: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Only these statuses: open, in_progress (or wip), blocked, deferred, closed (or done), pinned (repeatable or
    /// comma separated; default: all but closed and pinned)
    #[arg(short, long, value_delimiter = ',')]
    pub status: Vec<String>,
    /// Include closed and pinned issues (ignored with --status)
    #[arg(long)]
    pub all: bool,
    /// Only issues blocked by dependencies
    #[arg(long)]
    pub blocked: bool,
    /// Only issues whose id, title, description or notes contain this text (case-insensitive)
    #[arg(long, value_name = "TEXT")]
    pub search: Option<String>,
    /// Sort order: priority, created or updated (newest first), or id
    #[arg(long, default_value = "priority")]
    pub sort: String,
    /// Reverse the sort order
    #[arg(long)]
    pub reverse: bool,
    #[arg(short = 'n', long, default_value_t = 100, help = LIMIT_HELP)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GuardArgs {
    #[arg(long, value_name = "N", help = if_revision_help!())]
    pub if_revision: Option<i64>,
    /// Apply only if the status is still STATUS
    #[arg(long, value_name = "STATUS")]
    pub if_status: Option<String>,
    /// Apply only if the assignee is still ACTOR (empty string: unassigned)
    #[arg(long, value_name = "ACTOR")]
    pub if_assignee: Option<String>,
}

pub const UPDATE_LONG_ABOUT: &str = "\
Update fields of an issue

Only the fields given change. --if-revision, --if-status and --if-assignee make
the update conditional: if the issue changed meanwhile, nothing is written and
bd exits 13. Closing and reopening go through `bd close` and `bd reopen`;
claiming and releasing through `bd claim` and `bd release`.";

const UPDATE_EXAMPLES: &str = "\
Examples:
  bd update bd-12 --status open --if-revision 4
  bd update bd-12 -p 1 --add-label backend --estimate 90
  bd update bd-12 --assignee '' --due ''";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = UPDATE_EXAMPLES)]
pub struct UpdateArgs {
    /// Issue id
    pub id: String,
    /// New title, at most 500 characters
    #[arg(long)]
    pub title: Option<String>,
    /// New description
    #[arg(short, long)]
    pub description: Option<String>,
    /// New design notes
    #[arg(long)]
    pub design: Option<String>,
    /// New acceptance criteria
    #[arg(long)]
    pub acceptance: Option<String>,
    /// Replace notes
    #[arg(long)]
    pub notes: Option<String>,
    /// Append a line to notes
    #[arg(long)]
    pub append_notes: Option<String>,
    /// New status: open, in_progress (needs an assignee), blocked, deferred or pinned (closing and reopening: `bd
    /// close`, `bd reopen`)
    #[arg(short, long)]
    pub status: Option<String>,
    /// New priority, 0 (critical) to 4 (backlog) or P0-P4
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
    /// New type (types as in `bd create -h`)
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,
    /// Reserve for ACTOR: only it may claim the issue, unless ACTOR is in config claim.pools (then any actor may;
    /// empty string unassigns)
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Reference in another system (empty string clears)
    #[arg(long)]
    pub external_ref: Option<String>,
    /// Estimate in minutes, 0 or more (empty string clears)
    #[arg(long, value_name = "MINUTES")]
    pub estimate: Option<String>,
    /// Due time (empty string clears)
    #[arg(long, value_name = "TIME")]
    pub due: Option<String>,
    /// Hide from ready work until this time (empty string clears)
    #[arg(long, value_name = "TIME")]
    pub defer: Option<String>,
    /// Replace metadata with this JSON object
    #[arg(long, value_name = "JSON")]
    pub metadata: Option<String>,
    /// Set metadata key=value, the value parsed as JSON when valid (repeatable)
    #[arg(long = "set-metadata", value_name = "K=V")]
    pub set_metadata: Vec<String>,
    /// Remove this metadata key (repeatable)
    #[arg(long = "unset-metadata", value_name = "KEY")]
    pub unset_metadata: Vec<String>,
    /// Add labels (repeatable or comma separated)
    #[arg(long = "add-label", value_delimiter = ',')]
    pub add_labels: Vec<String>,
    /// Remove labels (repeatable or comma separated)
    #[arg(long = "remove-label", value_delimiter = ',')]
    pub remove_labels: Vec<String>,
    /// Replace all labels (repeatable or comma separated; empty string clears)
    #[arg(long = "set-labels", value_delimiter = ',')]
    pub set_labels: Option<Vec<String>>,
    /// Move under this parent (empty string detaches)
    #[arg(long, value_name = "ID")]
    pub parent: Option<String>,
    /// Mark as scratch work (true) or keep it permanently (false)
    #[arg(long, value_name = "BOOL")]
    pub ephemeral: Option<bool>,
    #[command(flatten)]
    pub guard: GuardArgs,
    #[arg(
        long,
        help = concat!(
            "Take over another actor's live claim: reassign it or move it out of in_progress",
            take_over_suffix!()
        )
    )]
    pub take_over: bool,
}

pub const CLOSE_LONG_ABOUT: &str = "\
Close issues, all or none

Closes every issue named, or none if one is refused. An issue with open
children or blockers is refused unless --force; another actor's live claim
needs --take-over. --token closes only while that claim's lease is held, and
the --if-* guards only if the issue is unchanged (exit 13 if not). Closing
releases what the issue blocked, and a playbook run closes with its last step.";

const CLOSE_EXAMPLES: &str = "\
Examples:
  bd close bd-12 --token 41 -r \"Done\"
  bd close bd-13 bd-14 --failed -r \"Upstream API removed\"";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = CLOSE_EXAMPLES)]
pub struct CloseArgs {
    /// Issue ids
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Reason recorded with the close
    #[arg(short, long, alias = "message")]
    pub reason: Option<String>,
    /// Record the outcome as failed (releases conditional-blocks dependents)
    #[arg(long)]
    pub failed: bool,
    #[arg(long, help = concat!("Close despite open children or blockers", force_claim_suffix!()))]
    pub force: bool,
    #[arg(long, help = concat!("Close another actor's live claim", take_over_suffix!()))]
    pub take_over: bool,
    #[arg(long, help = FENCING_TOKEN_HELP)]
    pub token: Option<i64>,
    #[command(flatten)]
    pub guard: GuardArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ReopenArgs {
    /// Issue ids
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Reason recorded with the reopen
    #[arg(short, long)]
    pub reason: Option<String>,
}

pub const DEFER_LONG_ABOUT: &str = "\
Hide an issue from ready work, until a time or indefinitely

With --until the issue keeps its status and comes back to the ready queue at
that time. Without it the status becomes deferred, which `bd claim` refuses
(even with --allow-blocked) until `bd undefer`. Either way the issue's children
are hidden too. Closed and in-progress issues cannot be deferred.";

const DEFER_EXAMPLES: &str = "\
Examples:
  bd defer bd-12 --until +3d
  bd defer bd-12          # until `bd undefer bd-12`";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = DEFER_EXAMPLES)]
pub struct DeferArgs {
    /// Issue id
    pub id: String,
    /// Hide until this time; without it the status becomes deferred, which `bd claim` refuses
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DeleteArgs {
    /// Issue ids
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Also delete the issues that depend on them, transitively (through blocks, conditional-blocks, parent-child and
    /// waits-for edges)
    #[arg(long)]
    pub cascade: bool,
    #[arg(
        long,
        help = concat!("Delete even if other issues depend on them, dropping those edges", force_claim_suffix!())
    )]
    pub force: bool,
    #[arg(long, help = concat!("Delete issues other actors hold live claims on", take_over_suffix!()))]
    pub take_over: bool,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

pub const READY_LONG_ABOUT: &str = "\
List ready work in queue order

Ready means open, not blocked, not deferred (neither the issue nor an
ancestor) and not waiting on open children; epics show only with
--include-epics or -t epic, gates only with -t gate. --sort orders the queue:
priority (then oldest first), hybrid (issues from the last 48 hours by
priority, then older ones oldest first) or oldest. `bd claim --next` takes the
head of the same queue, among the issues the actor may claim.";

const READY_EXAMPLES: &str = "\
Examples:
  bd ready -n 5 --parent bd-7
  bd ready --sort hybrid -l backend";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = READY_EXAMPLES)]
pub struct ReadyArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Queue order: priority, hybrid or oldest
    #[arg(long, default_value = "priority")]
    pub sort: String,
    #[arg(short = 'n', long, default_value_t = 50, help = LIMIT_HELP)]
    pub limit: usize,
    /// Include open issues hidden by a future defer time or a deferred ancestor
    #[arg(long)]
    pub include_deferred: bool,
    /// Include epics (left out unless -t epic)
    #[arg(long)]
    pub include_epics: bool,
}

#[derive(Args, Debug, Clone)]
pub struct BlockedArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    #[arg(short = 'n', long, default_value_t = 100, help = LIMIT_HELP)]
    pub limit: usize,
}

pub const PURGE_LONG_ABOUT: &str = "\
Delete closed ephemeral issues (finished ephemeral runs) for good

Deletes issues created with --ephemeral (such as the steps of ephemeral
playbook runs) once closed, with no undo. A run goes as a whole: none of it is
deleted while anything below it is still open, closed too recently or
persistent. Without --older-than every closed ephemeral issue qualifies.";

const PURGE_EXAMPLES: &str = "\
Examples:
  bd purge --older-than 7d --dry-run
  bd purge --older-than 7d";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PURGE_EXAMPLES)]
pub struct PurgeArgs {
    /// Only issues closed at least this long ago, e.g. 7d
    #[arg(long, value_name = "DURATION")]
    pub older_than: Option<String>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}
