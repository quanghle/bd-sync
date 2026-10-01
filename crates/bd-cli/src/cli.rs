//! Command-line grammar.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "bd",
    version,
    about = "bd: a coordination engine for agents and humans: tasks, typed dependencies, deterministic ready work, leased claims, and an event log on SQLite WAL",
    after_help = "Agent loop:  bd ready  ->  bd claim --next  ->  bd heartbeat <id>  ->  bd close <id>\nRun `bd prime` for workflow context. Exit codes: 2 invalid, 3 not found, 4 claim conflict, 5 busy, 6 events truncated, 7 access denied, 8 server unreachable, 9 write's answer lost (may have taken effect), 13 stale guard."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[command(flatten)]
    pub global: Global,
}

#[derive(Args, Debug, Clone)]
pub struct Global {
    /// Database file (default: nearest .bd/bd.db walking up from the current directory)
    #[arg(long, global = true, env = "BD_DB", value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Workspace on a bd server, e.g. https://bd.example.com/w/proj (default: .bd/remote.toml); token: $BD_TOKEN or `bd remote login`
    #[arg(long, global = true, env = "BD_REMOTE", value_name = "URL")]
    pub remote: Option<String>,
    /// Run as if started in this directory
    #[arg(short = 'C', long = "directory", global = true, value_name = "DIR")]
    pub directory: Option<PathBuf>,
    /// Actor name (default: $BD_ACTOR, $BEADS_ACTOR, git user.name, $USER)
    #[arg(long, global = true, value_name = "NAME")]
    pub actor: Option<String>,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    pub json: bool,
    /// Minimal output (ids only)
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Log format for diagnostics on stderr (filter with BD_LOG, e.g. BD_LOG=bd=debug)
    #[arg(long, global = true, value_enum, env = "BD_LOG_FORMAT", default_value = "text")]
    pub log_format: LogFormat,
    /// Print per-command timing to stderr (also BD_TIMING=1)
    #[arg(long, global = true)]
    pub timing: bool,
    /// Warn about operations slower than this many milliseconds
    #[arg(long, global = true, env = "BD_SLOW_MS", default_value_t = 250, value_name = "MS")]
    pub slow_ms: u64,
    /// How long a writer waits for the database write lock
    #[arg(long, global = true, env = "BD_BUSY_TIMEOUT_MS", default_value_t = 10_000, value_name = "MS")]
    pub busy_timeout_ms: u64,
    /// Read playbooks only from this bundle (how a remote client sends the playbooks of its checkout)
    #[arg(long, global = true, hide = true, value_name = "FILE")]
    pub playbook_bundle: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a workspace (.bd/bd.db) in the current directory
    Init(InitArgs),
    /// Create an issue
    Create(CreateArgs),
    /// Show issue details
    Show(ShowArgs),
    /// List issues
    List(ListArgs),
    /// Update fields of an issue
    Update(UpdateArgs),
    /// Close issues (atomically, all or none)
    Close(CloseArgs),
    /// Reopen closed issues
    Reopen(ReopenArgs),
    /// Hide an issue from ready work, until a time or indefinitely
    Defer(DeferArgs),
    /// Undo a deferral
    Undefer(IdArg),
    /// Delete issues
    Delete(DeleteArgs),
    /// Ready work in queue order: open, unblocked, not deferred
    Ready(ReadyArgs),
    /// Blocked issues and what blocks them
    Blocked(BlockedArgs),
    /// Atomically claim an issue, or the next ready one, under a lease
    Claim(ClaimArgs),
    /// Renew the lease on an issue you hold
    #[command(alias = "hb")]
    Heartbeat(HeartbeatArgs),
    /// Give up a claim (or an assignment)
    #[command(alias = "unclaim")]
    Release(ReleaseArgs),
    /// Revert claims whose lease expired past the grace window (dead-worker recovery)
    Reclaim(ReclaimArgs),
    /// List live leases
    Leases(LeasesArgs),
    /// Manage dependencies
    #[command(subcommand)]
    Dep(DepCommand),
    /// Manage labels
    #[command(subcommand)]
    Label(LabelCommand),
    /// Add or list comments
    #[command(subcommand)]
    Comment(CommentCommand),
    /// List the comments on an issue
    Comments(IdArg),
    /// Durable workspace memory
    #[command(subcommand)]
    Memory(MemoryCommand),
    /// Store a memory (same as `memory add`)
    Remember(MemoryAddArgs),
    /// Print a memory (same as `memory get`)
    Recall(KeyArg),
    /// List or search memories (same as `memory list`)
    Memories(MemoryListArgs),
    /// Delete a memory (same as `memory rm`)
    Forget(KeyArg),
    /// Read the transactional event history
    Events(EventsArgs),
    /// Event history of one issue
    History(HistoryArgs),
    /// Agent context: workflow, your claims, ready work, memories
    Prime(PrimeArgs),
    /// Workspace statistics
    Stats,
    /// Operational metrics (Prometheus text or JSON)
    Metrics(MetricsArgs),
    /// Check database health and invariants; --fix repairs what it safely can
    Doctor(DoctorArgs),
    /// Read or change workspace configuration
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Export a consistent JSONL snapshot
    Export(ExportArgs),
    /// Import a JSONL snapshot (bd or beads format), all or nothing
    Import(ImportArgs),
    /// Run many write operations in one transaction
    Batch(BatchArgs),
    /// Repeatable multi-step work: list, preview, start and manage playbook runs
    #[command(subcommand)]
    Playbook(PlaybookCommand),
    /// Gates: wait conditions in front of steps (human, timer, issue, GitHub run/PR)
    #[command(subcommand)]
    Gate(GateCommand),
    /// Delete closed ephemeral issues (finished ephemeral runs) for good
    Purge(PurgeArgs),
    /// Benchmark concurrent claim throughput on a scratch database
    Bench(BenchArgs),
    #[command(hide = true)]
    BenchWorker(BenchWorkerArgs),
    /// Serve workspaces to remote bd clients over HTTPS; `bd serve token` manages access
    Serve(ServeArgs),
    /// Use a workspace on a bd server from this checkout: set, show (with a connection check), unset, login, logout
    #[command(subcommand)]
    Remote(RemoteCommand),
    /// Workspace information
    Info,
    /// Print the version
    Version,
}

#[derive(Args, Debug, Clone)]
pub struct IdArg {
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct KeyArg {
    pub key: String,
}

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
    /// Allow taking over another actor's live claim (through bd serve: an admin token)
    #[arg(long)]
    pub force: bool,
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
    /// Close despite open children or live blockers
    #[arg(long)]
    pub force: bool,
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
    /// Delete even if other issues depend on them (drops those edges)
    #[arg(long)]
    pub force: bool,
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
pub struct ClaimArgs {
    /// Issue to claim (omit with --next)
    #[arg(required_unless_present = "next", conflicts_with = "next")]
    pub id: Option<String>,
    /// Claim the head of the ready queue (filters apply)
    #[arg(long)]
    pub next: bool,
    #[command(flatten)]
    pub filter: FilterArgs,
    /// priority | hybrid | oldest (with --next)
    #[arg(long, default_value = "priority")]
    pub sort: String,
    /// Lease duration (default: lease.ttl)
    #[arg(long)]
    pub ttl: Option<String>,
    /// Claim even if blocked or deferred (by id only)
    #[arg(long)]
    pub allow_blocked: bool,
    #[arg(long, value_name = "N")]
    pub if_revision: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct HeartbeatArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Fencing token from `claim` (fails if the lease was re-granted)
    #[arg(long)]
    pub token: Option<i64>,
    #[arg(long)]
    pub ttl: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ReleaseArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(short, long)]
    pub reason: Option<String>,
    /// Release another actor's claim (through bd serve: an admin token)
    #[arg(long)]
    pub force: bool,
    /// Release only if still held by this actor (compare-and-swap)
    #[arg(long, value_name = "ACTOR")]
    pub if_assignee: Option<String>,
    #[arg(long)]
    pub token: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct ReclaimArgs {
    /// Only leases expired at least this long ago (default: lease.grace)
    #[arg(long)]
    pub grace: Option<String>,
    /// Only these holders
    #[arg(short, long)]
    pub assignee: Option<String>,
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    #[arg(long = "id", value_delimiter = ',')]
    pub ids: Vec<String>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct LeasesArgs {
    /// Only expired leases
    #[arg(long)]
    pub expired: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DepCommand {
    /// ISSUE depends on DEPENDS_ON
    Add(DepAddArgs),
    /// Remove the edge between ISSUE and DEPENDS_ON
    #[command(alias = "remove")]
    Rm(DepPairArgs),
    /// Edges of an issue
    List(DepListArgs),
    /// Dependency tree
    Tree(DepTreeArgs),
    /// Report cycles among scheduling edges
    Cycles,
}

#[derive(Args, Debug, Clone)]
pub struct DepAddArgs {
    pub issue: String,
    pub depends_on: String,
    /// blocks, conditional-blocks, parent-child, waits-for, related, discovered-from, ...
    #[arg(short = 't', long = "type", default_value = "blocks")]
    pub dep_type: String,
    /// waits-for gate: all-children | any-children
    #[arg(long)]
    pub gate: Option<String>,
    /// Edge metadata JSON object
    #[arg(long)]
    pub metadata: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepPairArgs {
    pub issue: String,
    pub depends_on: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum DirectionArg {
    /// What the issue depends on
    Down,
    /// What depends on the issue
    Up,
    Both,
}

#[derive(Args, Debug, Clone)]
pub struct DepListArgs {
    pub id: String,
    #[arg(long, value_enum, default_value = "both")]
    pub direction: DirectionArg,
    #[arg(short = 't', long = "type")]
    pub dep_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepTreeArgs {
    pub id: String,
    #[arg(long, value_enum, default_value = "down")]
    pub direction: DirectionArg,
    #[arg(long, default_value_t = 50)]
    pub max_depth: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LabelCommand {
    Add(LabelEditArgs),
    #[command(alias = "remove")]
    Rm(LabelEditArgs),
    /// Labels of an issue, or all labels with counts
    List(LabelListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct LabelEditArgs {
    pub id: String,
    #[arg(required = true, num_args = 1.., value_delimiter = ',')]
    pub labels: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct LabelListArgs {
    pub id: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CommentCommand {
    Add(CommentAddArgs),
    List(IdArg),
}

#[derive(Args, Debug, Clone)]
pub struct CommentAddArgs {
    pub id: String,
    /// Comment text (words are joined); or use --file / --stdin
    #[arg(num_args = 0..)]
    pub text: Vec<String>,
    #[arg(long, conflicts_with = "stdin")]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub stdin: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MemoryCommand {
    /// Store or update a memory
    Add(MemoryAddArgs),
    Get(KeyArg),
    /// List all, or search by substring
    List(MemoryListArgs),
    #[command(alias = "remove")]
    Rm(KeyArg),
}

#[derive(Args, Debug, Clone)]
pub struct MemoryAddArgs {
    /// Content (words are joined)
    #[arg(required = true, num_args = 1..)]
    pub content: Vec<String>,
    /// Explicit key (default: derived from content)
    #[arg(long)]
    pub key: Option<String>,
    /// Compare-and-set: write only at this revision (0 = create only)
    #[arg(long, value_name = "N")]
    pub if_revision: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct MemoryListArgs {
    pub query: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct EventsArgs {
    #[command(subcommand)]
    pub action: Option<EventsAction>,
    /// Strict cursor: events with seq > N (fails if pruned past it)
    #[arg(long)]
    pub since: Option<i64>,
    /// Maximum events (default 50 without --since, unlimited with it)
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,
    /// Keep polling for new events
    #[arg(short, long)]
    pub follow: bool,
    /// Poll interval for --follow
    #[arg(long, default_value_t = 500, value_name = "MS")]
    pub interval_ms: u64,
    #[arg(long)]
    pub issue: Option<String>,
    /// Only these ops (repeatable or comma separated)
    #[arg(long = "op", value_delimiter = ',')]
    pub ops: Vec<String>,
    #[arg(long = "by")]
    pub by_actor: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EventsAction {
    /// Delete old events (criteria combine conservatively)
    Prune(PruneArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PruneArgs {
    /// Delete events with seq below N
    #[arg(long)]
    pub before: Option<i64>,
    /// Delete events older than this (e.g. 30d)
    #[arg(long)]
    pub older_than: Option<String>,
    /// Keep the newest N events
    #[arg(long)]
    pub keep: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct PrimeArgs {
    /// Cap the number of memories shown (0 = all)
    #[arg(long, default_value_t = 0)]
    pub max_memories: usize,
    /// Number of ready items shown
    #[arg(long, default_value_t = 10)]
    pub ready: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum MetricsFormat {
    Prometheus,
    Json,
}

#[derive(Args, Debug, Clone)]
pub struct MetricsArgs {
    #[arg(long, value_enum, default_value = "prometheus")]
    pub format: MetricsFormat,
}

#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    #[arg(long)]
    pub fix: bool,
    /// Full integrity_check instead of quick_check
    #[arg(long)]
    pub full: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommand {
    Get(KeyArg),
    Set(ConfigSetArgs),
    Unset(KeyArg),
    List,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigSetArgs {
    pub key: String,
    pub value: String,
}

#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    /// Output file (default stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub no_memories: bool,
    /// Skip closed and pinned issues
    #[arg(long)]
    pub open_only: bool,
    /// Include ephemeral issues (scratch runs), which are left out by default
    #[arg(long)]
    pub include_ephemeral: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ImportArgs {
    /// JSONL file, or - for stdin
    pub file: String,
    /// Validate and report without writing
    #[arg(long)]
    pub dry_run: bool,
    /// Keep unknown issue types and map unknown statuses to open
    #[arg(long)]
    pub lenient: bool,
}

#[derive(Args, Debug, Clone)]
pub struct BatchArgs {
    /// Read operations from this file (default stdin)
    #[arg(short, long)]
    pub file: Option<PathBuf>,
    /// Run everything, report, then roll back
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PlaybookCommand {
    /// Playbooks in .bd/playbooks, $BD_PLAYBOOK_PATH, then the user config dir (bd/playbooks); remote: then the server's
    #[command(alias = "ls")]
    List,
    /// Validate a playbook and show its variables and steps
    Show(PlaybookRefArgs),
    /// Preview a run: the issues and edges it would create (nothing is written)
    Plan(RunArgs),
    /// Start a run: create its issues and edges in one transaction
    Run(RunArgs),
    /// Every step of a run with its state and what it waits on
    Status(IdArg),
    /// Runs, newest first
    Runs(RunsArgs),
    /// Fold a finished run's steps into a digest on the run issue
    Compact(CompactArgs),
    /// Delete a run and all of its issues
    Discard(DiscardArgs),
    /// Write a playbook from an existing epic and its children
    Extract(ExtractArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PlaybookRefArgs {
    /// Playbook name (looked up in the playbook path) or file path
    pub playbook: String,
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Playbook name (looked up in the playbook path) or file path
    pub playbook: String,
    /// Variable value (repeatable)
    #[arg(long = "var", value_name = "NAME=VALUE")]
    pub vars: Vec<String>,
    /// Make the run ephemeral: left out of exports, deleted by `bd purge` once closed
    #[arg(long, conflicts_with = "persistent")]
    pub ephemeral: bool,
    /// Keep the run for good even if the playbook says ephemeral
    #[arg(long)]
    pub persistent: bool,
    /// Assign the run and every step that has no assignee
    #[arg(short, long)]
    pub assignee: Option<String>,
    /// Title of the run issue (default: the playbook's title)
    #[arg(long)]
    pub title: Option<String>,
    /// Create the run under this issue (e.g. a spawner step that others wait on)
    #[arg(long)]
    pub parent: Option<String>,
    /// Start only after these issues close (repeatable or comma separated)
    #[arg(long, value_delimiter = ',')]
    pub after: Vec<String>,
    /// Check everything against the database, show the result, then roll back
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct RunsArgs {
    /// Include finished runs
    #[arg(long)]
    pub all: bool,
    /// Only runs of this playbook
    #[arg(long)]
    pub playbook: Option<String>,
    /// Maximum rows (0 = unlimited)
    #[arg(short = 'n', long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args, Debug, Clone)]
pub struct CompactArgs {
    pub id: String,
    /// Your summary, written above the generated digest
    #[arg(short, long)]
    pub summary: Option<String>,
    /// Compact even though the run is not finished
    #[arg(long)]
    pub force: bool,
    /// Print the digest without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DiscardArgs {
    pub id: String,
    /// Discard even with steps in progress
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ExtractArgs {
    /// The epic (or run) to turn into a playbook
    pub id: String,
    /// Playbook name (default: from the run, or the epic's title)
    #[arg(long)]
    pub name: Option<String>,
    /// Write to this file instead of stdout
    #[arg(short, long, conflicts_with = "save")]
    pub output: Option<PathBuf>,
    /// Write to .bd/playbooks/<name>.toml
    #[arg(long)]
    pub save: bool,
    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GateCommand {
    /// Open gates (--all: resolved ones too)
    #[command(alias = "ls")]
    List(GateListArgs),
    /// A gate's condition, phase, deadline and what it holds back
    Show(IdArg),
    /// Evaluate armed gates: open those whose condition holds; escalate failures and timeouts
    Check(GateCheckArgs),
    /// Open gates by hand (approvals; through bd serve, human gates need a human token)
    Resolve(GateResolveArgs),
    /// Put a gate in front of existing work
    Create(Box<GateCreateArgs>),
}

#[derive(Args, Debug, Clone)]
pub struct GateListArgs {
    #[arg(long)]
    pub all: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GateCheckArgs {
    /// Only these gates (default: every open gate)
    pub ids: Vec<String>,
    /// Only gates of this type (human, timer, issue, gh:run, gh:pr; gh for both GitHub types, local for all others)
    #[arg(short = 't', long = "type")]
    pub kind: Option<String>,
    /// Report what would happen without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GateResolveArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(short, long)]
    pub reason: Option<String>,
    /// Resolve before the gate is armed (its work still has open prerequisites)
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GateCreateArgs {
    /// human | timer | issue | gh:run | gh:pr
    #[arg(short = 't', long = "type")]
    pub kind: String,
    /// Issues the gate holds back (repeatable or comma separated)
    #[arg(long, required = true, value_delimiter = ',')]
    pub blocks: Vec<String>,
    /// issue: id to wait for; gh:pr: PR number; gh:run: run id or workflow name/file
    #[arg(long)]
    pub await_id: Option<String>,
    /// timer: how long to wait; other types: escalate when still shut this long after arming
    #[arg(long)]
    pub timeout: Option<String>,
    /// GitHub gates: OWNER/REPO or HOST/OWNER/REPO (default: this repository; gate.repos limits others)
    #[arg(long)]
    pub repo: Option<String>,
    /// gh:run on a workflow: only runs for this branch or tag; follows its newest head
    #[arg(long)]
    pub branch: Option<String>,
    /// gh:run on a workflow: only runs triggered by this event (push, workflow_dispatch, ...)
    #[arg(long)]
    pub event: Option<String>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(short, long)]
    pub description: Option<String>,
    /// Who should act on it (e.g. the approver)
    #[arg(short, long)]
    pub assignee: Option<String>,
    /// Parent issue (default: the parent of the single issue it holds back)
    #[arg(long)]
    pub parent: Option<String>,
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BenchMode {
    /// Worker threads in this process, one connection each (embedded library)
    Threads,
    /// One long-lived worker process each (cross-process locking)
    Processes,
    /// A fresh `bd` process per claim and close (what CLI agents experience)
    Cli,
    /// Like `cli`, but every command goes through a scratch `bd serve` (HTTP, access token, server)
    Remote,
}

#[derive(Args, Debug, Clone)]
pub struct BenchArgs {
    /// Concurrent workers
    #[arg(short, long, default_value_t = 8)]
    pub workers: usize,
    #[arg(long, value_enum, default_value = "threads")]
    pub mode: BenchMode,
    /// Issues to seed
    #[arg(short = 'n', long, default_value_t = 2000)]
    pub issues: usize,
    /// Average blocking dependencies per issue (random DAG)
    #[arg(long, default_value_t = 1.0)]
    pub deps: f64,
    /// Simulated work per claim
    #[arg(long, default_value_t = 0, value_name = "MS")]
    pub work_ms: u64,
    /// Heartbeat once per claim before closing
    #[arg(long)]
    pub heartbeat: bool,
    /// Durability (off | normal | full)
    #[arg(long, default_value = "normal")]
    pub durability: String,
    /// Keep the scratch database at this path instead of a temp dir (remote mode: <root>/<name>/.bd/bd.db)
    #[arg(long)]
    pub keep: Option<PathBuf>,
    /// RNG seed for the generated graph
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
}

#[derive(Args, Debug, Clone)]
pub struct BenchWorkerArgs {
    #[arg(long)]
    pub path: PathBuf,
    #[arg(long)]
    pub name: String,
    #[arg(long, default_value_t = 0)]
    pub work_ms: u64,
    #[arg(long)]
    pub heartbeat: bool,
    #[arg(long, default_value = "normal")]
    pub durability: String,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub action: Option<ServeAction>,
    /// Directory of workspaces: <root>/<name>/.bd/bd.db is served at /w/<name>; tokens in <root>/tokens.json
    #[arg(long, env = "BD_SERVE_ROOT", value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Address and port to listen on
    #[arg(long, default_value = "127.0.0.1:7420", value_name = "ADDR")]
    pub listen: String,
    /// TLS certificate chain (PEM): serve HTTPS
    #[arg(long, requires = "tls_key", value_name = "FILE")]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM)
    #[arg(long, requires = "tls_cert", value_name = "FILE")]
    pub tls_key: Option<PathBuf>,
    /// Allow plain HTTP on a non-loopback address (behind a TLS proxy, or on an encrypted private network)
    #[arg(long)]
    pub insecure_http: bool,
    /// Largest request accepted, in MiB (imports and batches travel in the request)
    #[arg(long, default_value_t = 64, value_name = "MIB")]
    pub max_body_mib: u64,
    /// Reclaim leases expired past lease.grace in every workspace this often (0 = off)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub reclaim_every: String,
    /// Check timer, issue and human gates in every workspace this often (0 = off)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub gate_check_every: String,
    /// Check GitHub gates with this host's gh this often (0 = off)
    #[arg(long, default_value = "5m", value_name = "DURATION")]
    pub gh_check_every: String,
    /// Back up every workspace into DIR/<name>/ (default: no backups)
    #[arg(long, value_name = "DIR")]
    pub backup_dir: Option<PathBuf>,
    /// Time between backups of a workspace
    #[arg(long, default_value = "1h", value_name = "DURATION", requires = "backup_dir")]
    pub backup_every: String,
    /// Backups kept per workspace; older ones are deleted (0 = keep all)
    #[arg(long, default_value_t = 24, value_name = "N", requires = "backup_dir")]
    pub backup_keep: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServeAction {
    /// Manage access tokens (run on the server host)
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    /// Create an access token and print its secret once
    Create(TokenCreateArgs),
    /// List access tokens (never their secrets)
    #[command(alias = "ls")]
    List(TokenRootArgs),
    /// Revoke an access token; it stops working at once
    Revoke(TokenRevokeArgs),
}

#[derive(Args, Debug, Clone)]
pub struct TokenRootArgs {
    /// Server root holding tokens.json
    #[arg(long, env = "BD_SERVE_ROOT", value_name = "DIR")]
    pub root: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct TokenCreateArgs {
    /// Unique token name, e.g. alice-laptop or ci
    pub name: String,
    /// The actor the token acts as; clients may also use <actor>/<agent> sub-actors
    #[arg(long = "as", value_name = "ACTOR")]
    pub act_as: String,
    #[arg(long, value_enum, default_value = "write")]
    pub role: crate::auth::Role,
    /// Who holds it: a person's token (human) may also resolve human gates
    #[arg(long, value_enum, default_value = "agent")]
    pub kind: crate::auth::Kind,
    /// Workspaces the token may use (repeatable or comma separated; default all)
    #[arg(long = "workspace", value_delimiter = ',', value_name = "NAME")]
    pub workspaces: Vec<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenRevokeArgs {
    pub name: String,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RemoteCommand {
    /// Point this checkout at a workspace on a bd server (writes .bd/remote.toml)
    Set(RemoteSetArgs),
    /// The remote workspace in use, and a check of the connection, certificate, token and actor
    Show,
    /// Stop using the remote workspace (removes .bd/remote.toml)
    #[command(alias = "rm")]
    Unset,
    /// Save an access token for a bd server in your user config directory, so BD_TOKEN is not needed
    ///
    /// The token is read from stdin when it is piped (`printf %s "$TOKEN" | bd remote login`), else from a
    /// prompt that does not echo it; never from the command line. It is checked against the server first.
    Login(RemoteLoginArgs),
    /// Forget access tokens saved by `bd remote login`
    Logout(RemoteLogoutArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RemoteLoginArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj (default: this checkout's remote workspace)
    pub url: Option<String>,
    /// Save the token for this workspace only, instead of for every workspace on its server
    #[arg(long)]
    pub workspace_only: bool,
    /// Save the token without checking it against the server
    #[arg(long)]
    pub no_verify: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct RemoteLogoutArgs {
    /// Workspace or server URL (default: this checkout's remote workspace); a server URL also forgets
    /// tokens saved for its workspaces
    pub url: Option<String>,
    /// Forget only the token saved for this workspace with `login --workspace-only`
    #[arg(long)]
    pub workspace_only: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct RemoteSetArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj
    pub url: String,
    /// CA certificate (PEM) that signed the server's certificate; copied to .bd/ca.pem
    #[arg(long, value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,
    /// Write it even though .bd/bd.db holds a local workspace, which remote.toml hides
    #[arg(long)]
    pub force: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}

pub fn parse_priority(s: &str) -> Result<u8, String> {
    let t = s.trim().trim_start_matches(['P', 'p']);
    match t.parse::<u8>() {
        Ok(p) if p <= 4 => Ok(p),
        _ => Err(format!("invalid priority {s:?} (0-4 or P0-P4)")),
    }
}
