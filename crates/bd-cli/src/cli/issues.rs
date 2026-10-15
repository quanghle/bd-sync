//! Issue lifecycle: init, create, show, list, update, close, reopen, defer, delete, ready, blocked, purge.

use clap::{ArgGroup, Args, ValueEnum};

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

pub const QUICK_LONG_ABOUT: &str = "\
Create an issue and print only its id

Quick capture: creates an issue as `bd create` does, with the flags below
(use `bd create` for the others), and prints just the new id, with or
without --quiet, so a script can use it. With --json the result is the same
as that of `bd create`.";

const QUICK_EXAMPLES: &str = "\
Examples:
  ID=$(bd q \"Fix login\" -p 1)
  bd q \"Write the migration\" --parent bd-7 -l db,ops";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = QUICK_EXAMPLES)]
pub struct QuickArgs {
    /// Title, at most 500 characters (words are joined)
    #[arg(required = true, num_args = 1..)]
    pub title: Vec<String>,
    /// Description
    #[arg(short, long)]
    pub description: Option<String>,
    /// Type: task, bug, feature, epic, chore, decision, spike, story, milestone, gate (see `bd gate create`), or one in
    /// config types.custom (default: task)
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,
    /// Priority 0 (critical) to 4 (backlog), P0-P4 also accepted (default: 2)
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
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
}

impl QuickArgs {
    /// The `bd create` arguments for the same issue: every flag `bd q` lacks is unset.
    pub fn to_create(&self) -> CreateArgs {
        CreateArgs {
            title: self.title.clone(),
            description: self.description.clone(),
            design: None,
            acceptance: None,
            notes: None,
            issue_type: self.issue_type.clone(),
            priority: self.priority,
            assignee: None,
            labels: self.labels.clone(),
            parent: self.parent.clone(),
            deps: self.deps.clone(),
            external_ref: None,
            estimate: None,
            due: None,
            defer: None,
            metadata: None,
            id: None,
            pinned: false,
            ephemeral: false,
            claim: false,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    /// Issue ids
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Show the issues as they were at TIME: an event seq (N or #N), a date or time, or -DURATION ago
    #[arg(long, value_name = "TIME", allow_hyphen_values = true, conflicts_with_all = ["brief", "comments_tail", "why"])]
    pub as_of: Option<String>,
    /// Only the fields needed to pick up the issue: no texts but a cut description, open blocker ids, the last comments
    #[arg(long)]
    pub brief: bool,
    /// Only the last N comments (default with --brief: 3)
    #[arg(long, value_name = "N")]
    pub comments_tail: Option<usize>,
    /// Say whether the issue is ready and, if not, why
    #[arg(long)]
    pub why: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct FilterArgs {
    /// Only issues assigned to this actor
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Only unassigned issues
    #[arg(long, visible_alias = "no-assignee")]
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

/// Time and title filters of `bd list` and `bd ready`.
#[derive(Args, Debug, Clone, Default)]
pub struct TimeFilterArgs {
    /// Only issues created at or after TIME (7d = 7 days ago)
    #[arg(long, value_name = "TIME")]
    pub created_after: Option<String>,
    /// Only issues created before TIME (7d = 7 days ago)
    #[arg(long, value_name = "TIME")]
    pub created_before: Option<String>,
    /// Only issues updated at or after TIME (7d = 7 days ago)
    #[arg(long, value_name = "TIME")]
    pub updated_after: Option<String>,
    /// Only issues updated before TIME (7d = 7 days ago)
    #[arg(long, value_name = "TIME")]
    pub updated_before: Option<String>,
    /// Only issues not closed whose due time has passed
    #[arg(long)]
    pub overdue: bool,
    /// Only open or in-progress issues not updated within DURATION, e.g. 14d
    #[arg(long, value_name = "DURATION")]
    pub stale: Option<String>,
    /// Only issues whose title contains TEXT (ASCII case-insensitive, % and _ taken literally)
    #[arg(long, value_name = "TEXT")]
    pub title_contains: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    #[command(flatten)]
    pub times: TimeFilterArgs,
    /// Only issues closed at or after TIME (7d = 7 days ago; implies --all without --status)
    #[arg(long, value_name = "TIME")]
    pub closed_after: Option<String>,
    /// Only issues closed before TIME (implies --all without --status)
    #[arg(long, value_name = "TIME")]
    pub closed_before: Option<String>,
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
    /// One line per issue with only its key fields: id, title, status, priority, type, assignee, parent, labels
    #[arg(long)]
    pub brief: bool,
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

pub const EDIT_LONG_ABOUT: &str = "\
Edit a field of an issue in an editor

Opens the field's text in $VISUAL, else $EDITOR, else vi (notepad on Windows),
on a private temporary file; the value may carry arguments, e.g. `code --wait`.
When the editor exits successfully with changed text, the issue is updated
conditionally on the revision read before editing: if the issue changed
meanwhile, nothing is written, bd exits 13, and the edited text stays in the
temporary file, whose path is printed. Unchanged text writes nothing, and a
title must stay one non-empty line. Runs only in a terminal on the machine
holding the workspace, never through `bd serve` (use `bd update` there, or in
scripts).";

const EDIT_EXAMPLES: &str = "\
Examples:
  bd edit bd-12
  bd edit bd-12 --field notes
  EDITOR='code --wait' bd edit bd-12 --field design";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = EDIT_EXAMPLES)]
pub struct EditArgs {
    /// Issue id
    pub id: String,
    /// Field to edit
    #[arg(long, value_enum, default_value = "description")]
    pub field: EditField,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum EditField {
    /// The title: one non-empty line
    Title,
    /// The description
    Description,
    /// Design notes
    Design,
    /// Acceptance criteria
    Acceptance,
    /// Notes
    Notes,
}

pub const UPDATE_LONG_ABOUT: &str = "\
Update fields of an issue

Only the fields given change. --if-revision, --if-status and --if-assignee make
the update conditional: if the issue changed meanwhile, nothing is written and
bd exits 13. Closing and reopening go through `bd close` and `bd reopen`.

Updating also claims and releases: --status in_progress (with an assignee)
grants the assignee a lease, a new --assignee moves it, and leaving in_progress
drops it. `bd claim` also checks that the issue is ready.";

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
releases what the issue blocked, and a playbook run closes with its last step.

--claim-next then claims the next ready issue in the same transaction: first
under the first issue's parent, then anywhere in the queue (only under --parent
when given). It claims nothing when every issue named was already closed, so a
retried close does not claim twice. --suggest-next names that issue without
claiming it. The filter flags and --sort apply only with one of the two.";

const CLOSE_EXAMPLES: &str = "\
Examples:
  bd close bd-12 --token 41 -r \"Done\"
  bd close bd-12 --token 41 -r \"Done\" --claim-next
  bd close bd-12 -r \"Done\" --suggest-next -l backend
  bd close bd-13 bd-14 --failed -r \"Upstream API removed\"";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = CLOSE_EXAMPLES)]
#[command(group(ArgGroup::new("next_mode").args(["claim_next", "suggest_next"]).multiple(false)))]
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
    /// Then claim the next ready issue: under the first issue's parent first, then the whole queue
    #[arg(long)]
    pub claim_next: bool,
    /// Then name the issue --claim-next would claim, without claiming it
    #[arg(long)]
    pub suggest_next: bool,
    #[command(flatten)]
    pub next: NextArgs,
}

/// Which issue `bd close --claim-next`/`--suggest-next` picks; each flag needs one of the two.
#[derive(Args, Debug, Clone, Default)]
pub struct NextArgs {
    /// Next issue only if assigned to this actor
    #[arg(short, long, value_name = "ACTOR", requires = "next_mode")]
    pub assignee: Option<String>,
    /// Next issue only if unassigned
    #[arg(long, requires = "next_mode")]
    pub unassigned: bool,
    /// Next issue only of these types (repeatable or comma separated)
    #[arg(short = 't', long = "type", value_delimiter = ',', requires = "next_mode")]
    pub types: Vec<String>,
    /// Next issue only with all these labels (repeatable or comma separated)
    #[arg(short, long = "label", value_delimiter = ',', requires = "next_mode")]
    pub labels: Vec<String>,
    /// Next issue only below this one in the hierarchy, with no fallback to the queue
    #[arg(long, value_name = "ID", requires = "next_mode")]
    pub parent: Option<String>,
    /// Queue order for the next issue: priority, hybrid or oldest (default: priority)
    #[arg(long, requires = "next_mode")]
    pub sort: Option<String>,
    // `requires` alone lets --suggest-next through: clap waives a requirement that conflicts with an argument given.
    #[arg(long, value_name = "DURATION", help = TTL_HELP, requires = "claim_next", conflicts_with = "suggest_next")]
    pub ttl: Option<String>,
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
head of the same queue, among the issues the actor may claim.

--explain adds each ready issue's order key and lists the open issues the
same filters match that are not ready (blocked, deferred or waiting on their
children), with the reasons; `bd show ID --why` explains a single issue.";

const READY_EXAMPLES: &str = "\
Examples:
  bd ready -n 5 --parent bd-7
  bd ready --sort hybrid -l backend
  bd ready --explain -n 5";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = READY_EXAMPLES)]
pub struct ReadyArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    #[command(flatten)]
    pub times: TimeFilterArgs,
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
    /// One line per issue with only its key fields: id, title, status, priority, type, assignee, parent, labels
    #[arg(long)]
    pub brief: bool,
    /// Also list open issues that are not ready, with the reasons, and each ready issue's order key; -n bounds each
    /// list
    #[arg(long)]
    pub explain: bool,
}

#[derive(Args, Debug, Clone)]
pub struct BlockedArgs {
    #[command(flatten)]
    pub filter: FilterArgs,
    #[arg(short = 'n', long, default_value_t = 100, help = LIMIT_HELP)]
    pub limit: usize,
}

pub const COMPACT_LONG_ABOUT: &str = "\
Summarise old closed issues' text: list candidates, apply a summary, count

Compaction keeps a workspace small and its old issues quick to read. An agent
runs the loop: `bd compact --analyze` lists closed issues (not ephemeral,
never compacted, with text) closed at least --older-than ago, with their text
and revision; the agent writes a shorter summary of each, and `bd compact
--apply ID --if-revision REV --summary -` puts it in place of the
description, design, acceptance criteria and notes, which only a closed issue
allows. Title, close reason, labels, dependencies and comments stay; the
issue's metadata.compaction records the level, time and original size. The
original text stays in the `compacted` event: `bd history ID --diff` and `bd
show ID --as-of` show it while retention keeps that event. A summary of
another revision than the current one exits 13. Unlike `bd playbook
compact`, which folds a playbook run's steps into the run issue, this changes
no issue but the one named.";

const COMPACT_EXAMPLES: &str = "\
Examples:
  bd compact --analyze --older-than 90d -n 5
  bd compact --apply t-12 --if-revision 7 --summary -
  bd compact --apply t-12 --if-revision 7 --summary @summary.md
  bd compact --stats";

#[derive(Args, Debug, Clone)]
#[command(
    after_long_help = COMPACT_EXAMPLES,
    group(clap::ArgGroup::new("mode").required(true).args(["analyze", "apply", "stats"]))
)]
pub struct IssueCompactArgs {
    /// List the closed issues to summarise, oldest closed first, with their text
    #[arg(long)]
    pub analyze: bool,
    /// Replace this closed issue's text with --summary
    #[arg(long, value_name = "ID", requires_all = ["summary", "if_revision"])]
    pub apply: Option<String>,
    /// Count closed and compacted issues and the bytes compaction saved
    #[arg(long)]
    pub stats: bool,
    /// The summary: the text itself, @FILE to read a file, or - to read stdin
    #[arg(long, value_name = "TEXT|@FILE|-", requires = "apply", allow_hyphen_values = true)]
    pub summary: Option<String>,
    /// Only issues closed at least this long ago, e.g. 90d (default 30d)
    #[arg(long, value_name = "DURATION", conflicts_with = "apply")]
    pub older_than: Option<String>,
    #[arg(short = 'n', long, default_value_t = 20, help = LIMIT_HELP, conflicts_with = "apply")]
    pub limit: usize,
    #[arg(long, value_name = "N", help = if_revision_help!())]
    pub if_revision: Option<i64>,
}

pub const FIND_DUPLICATES_LONG_ABOUT: &str = "\
List likely duplicate pairs among open issues

Compares every pair of unfinished issues (open, in progress, blocked or
deferred) and lists those whose score reaches --threshold, best first. The
score is the larger of two similarities, each from 0 to 1: the share of
character trigrams the two titles have in common (forgiving typos and
plurals), and the share of words the title and description texts have in
common (common words and single characters left out). Closed and pinned
issues, ephemeral issues, gates and playbook run issues are not compared.
In each pair the first issue is the older one, usually the one to keep.

The comparison is pairwise, so time grows with the square of the number of
open issues. Through bd serve at most 1000 pairs are returned (-n 0 means
1000 there).

Read-only: nothing is closed or linked. Close a duplicate with `bd duplicate`.";

const FIND_DUPLICATES_EXAMPLES: &str = "\
Examples:
  bd find-duplicates
  bd find-duplicates --threshold 0.6 -n 10
  bd find-duplicates --json";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = FIND_DUPLICATES_EXAMPLES)]
pub struct FindDuplicatesArgs {
    /// Lowest score to report, above 0 and at most 1
    #[arg(long, default_value_t = 0.8, value_parser = parse_threshold, value_name = "SCORE")]
    pub threshold: f64,
    #[arg(short = 'n', long, default_value_t = 50, help = LIMIT_HELP)]
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
