//! Command-line grammar.

use std::path::PathBuf;
use std::time::Duration;

use bd_core::agents::Harness;
use clap::{Args, Parser, Subcommand, ValueEnum};

// Help wording shared by flags that mean the same thing. The suffixes are
// macros so `concat!` can append them to a command's own clause; each has a
// const of the same text.

/// The start of every `--take-over` suffix.
macro_rules! take_over_clause {
    () => {
        " (a live-claim override is recorded in its event; through bd serve"
    };
}

/// Ends `--take-over` help (bd-core `check_claim_override`).
macro_rules! take_over_suffix {
    () => {
        concat!(
            take_over_clause!(),
            " it needs an admin token unless the token's actor or one of its sub-actors holds the claim)"
        )
    };
}

/// Ends `bd import --take-over` help: remote import is admin-only.
macro_rules! import_take_over_suffix {
    () => {
        concat!(take_over_clause!(), ", import always needs an admin token)")
    };
}

/// Ends `--force` help on commands that also have `--take-over`.
macro_rules! force_claim_suffix {
    () => {
        " (never past another actor's live claim: see --take-over)"
    };
}

/// `--if-revision` help of the guards (`GuardArgs`), which `bd claim` extends.
macro_rules! if_revision_help {
    () => {
        "Apply only if the issue is still at revision N"
    };
}

/// Ends `bd claim --if-revision` help.
macro_rules! if_revision_by_id_suffix {
    () => {
        " (by id only; ignored with --next)"
    };
}

pub const DRY_RUN_HELP: &str = "Show what would happen without changing anything";
pub const FENCING_TOKEN_HELP: &str = "Fencing token from `bd claim`: act only while that lease is held";
pub const TTL_HELP: &str = "Lease duration, at least 1s, e.g. 30m (default: config lease.ttl)";
pub const LIMIT_HELP: &str = "Maximum rows (0 = unlimited)";
pub const IF_REVISION_BY_ID_SUFFIX: &str = if_revision_by_id_suffix!();
pub const FORCE_CLAIM_SUFFIX: &str = force_claim_suffix!();
pub const TAKE_OVER_CLAUSE: &str = take_over_clause!();
pub const TAKE_OVER_SUFFIX: &str = take_over_suffix!();
pub const IMPORT_TAKE_OVER_SUFFIX: &str = import_take_over_suffix!();

mod access;
mod agents;
mod bench;
mod claims;
mod hooks;
mod issues;
mod links;
mod playbooks;
mod remote;
mod serve;
#[cfg(test)]
mod tests;
mod workspace;

pub use access::*;
pub use agents::*;
pub use bench::*;
pub use claims::*;
pub use hooks::*;
pub use issues::*;
pub use links::*;
pub use playbooks::*;
pub use remote::*;
pub use serve::*;
pub use workspace::*;

#[derive(Parser, Debug)]
#[command(
    name = "bd",
    version,
    about = "Coordinate agents and humans: issues, dependencies, ready work, leased claims",
    after_help = ROOT_AFTER_HELP,
    after_long_help = ROOT_AFTER_LONG_HELP
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[command(flatten)]
    pub global: Global,
}

const ROOT_AFTER_HELP: &str = "\
Agent loop: bd ready -> bd claim --next -> bd heartbeat <id> -> bd close <id>
Run `bd prime` for workflow context.
Exit codes: 2 invalid, 3 not found, 4 claim conflict, 5 busy, 6 events
truncated, 7 access denied, 8 server unreachable, 9 write's answer lost (may
have taken effect), 13 stale guard.
See `bd --help` for actors, sessions, remote use, durations and times.";

const ROOT_AFTER_LONG_HELP: &str = "\
Agent loop:
  bd ready -> bd claim --next -> bd heartbeat <id> -> bd close <id>
  Run `bd prime` for workflow context.

Actors, local workspace:
  --actor, else $BD_ACTOR, else $BEADS_ACTOR names the actor outright.
  Otherwise the actor is the user (git user.name, else $USER, else $USERNAME),
  or `<user>/<session>` inside an agent session.

Sessions:
  A session label joins with '.' the short id of each agent harness found,
  then the --session or $BD_SESSION name:
    claude-<id>   from $CLAUDE_CODE_SESSION_ID
    copilot-<id>  from $COPILOT_AGENT_SESSION_ID
    codex-<id>    from $CODEX_THREAD_ID, else $CODEX_SESSION_ID
  <id> is the last 8 letters and digits of the harness's session id. Without
  a harness, a --session or $BD_SESSION name alone makes the actor
  `<user>/<NAME>`. An actor named outright gets no session suffix.
  --session takes the place of $BD_SESSION. It takes 1 to 64 ASCII letters,
  digits, '.', '_' or '-' (surrounding spaces ignored), not starting or ending
  with '.' or '-'; any other name is refused. $BD_SESSION is cleaned up
  instead: other characters become '-', it is cut to 64 characters, and
  leading and trailing '.' and '-' are dropped.

Actors, through bd serve:
  --actor, else $BD_ACTOR, else $BEADS_ACTOR; otherwise the access token's
  actor, or `<token actor>/<session>` inside an agent session. An actor named
  by --actor, $BD_ACTOR or $BEADS_ACTOR must be one the token allows: its
  actor or one of its sub-actors.

Remote workspaces:
  --remote, else $BD_REMOTE, else .bd/remote.toml names the workspace (not with
  --db). $BD_TOKEN is sent only to a server named by --remote or $BD_REMOTE;
  otherwise the token saved by `bd remote login` for that server is used.

JSON:
  --json prints results as JSON, and command errors on stderr as
  {\"error\": {\"code\", \"message\", \"exit_code\"}}. Argument errors that
  clap reports (unknown flags, missing or malformed values) stay plain text
  (exit 2).

Durations:
  250ms, 90s, 5m, 1h30m, 2d, 1w; a bare number is seconds.

Times:
  2026-01-15 (local midnight), 2026-01-15 09:00 or 2026-01-15T09:00:30 (local),
  RFC 3339 such as 2026-01-15T09:00:00Z, +2h or 3d (from now), now, tomorrow
  (local midnight).

Environment:
  BD_DB, BD_REMOTE, BD_TOKEN, BD_ACTOR, BEADS_ACTOR, BD_SESSION, BD_LOG,
  BD_LOG_FORMAT, BD_TIMING, BD_SLOW_MS, BD_BUSY_TIMEOUT_MS; the rest are
  listed in docs/commands.md.

Exit codes:
  0 ok, 1 other failure, 2 invalid, 3 not found, 4 claim conflict, 5 busy,
  6 events truncated, 7 access denied, 8 server unreachable, 9 write's answer
  lost (may have taken effect), 13 stale guard.";

#[derive(Args, Debug, Clone)]
pub struct Global {
    /// Database file (default: the nearest .bd/bd.db here or above)
    #[arg(long, global = true, env = "BD_DB", value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Workspace URL on a bd server (default: .bd/remote.toml)
    #[arg(long, global = true, env = "BD_REMOTE", value_name = "URL")]
    pub remote: Option<String>,
    /// Run as if started in DIR
    #[arg(short = 'C', long = "directory", global = true, value_name = "DIR")]
    pub directory: Option<PathBuf>,
    /// Act as this actor (default: the user or token's actor; see `bd --help`)
    #[arg(long, global = true, value_name = "NAME")]
    pub actor: Option<String>,
    /// Name this agent session, as $BD_SESSION does (rules: `bd --help`)
    #[arg(long, global = true, value_name = "NAME")]
    pub session: Option<String>,
    /// Print JSON; command errors go to stderr as JSON too
    #[arg(long, global = true)]
    pub json: bool,
    /// Print minimal output (ids only)
    #[arg(short, long, global = true)]
    pub quiet: bool,
    // A global flag's value help would put every command's --help in clap's long layout,
    // so its values are named here and clap's list is hidden.
    /// Format of diagnostics on stderr: text or json (filter with $BD_LOG)
    #[arg(long, global = true, value_enum, env = "BD_LOG_FORMAT", default_value = "text", hide_possible_values = true)]
    pub log_format: LogFormat,
    /// Print the command's timing on stderr (also $BD_TIMING=1)
    #[arg(long, global = true)]
    pub timing: bool,
    /// Warn about operations slower than this, in milliseconds
    #[arg(long, global = true, env = "BD_SLOW_MS", default_value_t = 250, value_name = "MS")]
    pub slow_ms: u64,
    /// How long to wait for a locked database or agent assets, in milliseconds
    #[arg(long, global = true, env = "BD_BUSY_TIMEOUT_MS", default_value_t = 10_000, value_name = "MS")]
    pub busy_timeout_ms: u64,
    /// Read playbooks only from this bundle (how a remote client sends the playbooks of its checkout)
    #[arg(long, global = true, hide = true, value_name = "FILE")]
    pub playbook_bundle: Option<PathBuf>,
    /// The checkout's and the user's playbooks for `bd prime` to list (how a remote client sends them)
    #[arg(long, global = true, hide = true, value_name = "FILE")]
    pub client_playbooks: Option<PathBuf>,
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
    #[command(long_about = CREATE_LONG_ABOUT)]
    Create(CreateArgs),
    /// Show issue details
    Show(ShowArgs),
    /// List issues
    List(ListArgs),
    /// Update fields of an issue
    #[command(long_about = UPDATE_LONG_ABOUT)]
    Update(UpdateArgs),
    /// Close issues, all or none
    #[command(long_about = CLOSE_LONG_ABOUT)]
    Close(CloseArgs),
    /// Reopen closed issues
    Reopen(ReopenArgs),
    /// Hide an issue from ready work, until a time or indefinitely
    #[command(long_about = DEFER_LONG_ABOUT)]
    Defer(DeferArgs),
    /// Undo a deferral
    Undefer(IdArg),
    /// Delete issues
    Delete(DeleteArgs),
    /// List ready work in queue order
    #[command(long_about = READY_LONG_ABOUT)]
    Ready(ReadyArgs),
    /// List blocked issues and what blocks them
    Blocked(BlockedArgs),
    /// Claim an issue, or the next ready one, under a lease
    #[command(long_about = CLAIM_LONG_ABOUT)]
    Claim(ClaimArgs),
    /// Renew the lease on claimed issues
    #[command(alias = "hb", long_about = HEARTBEAT_LONG_ABOUT)]
    Heartbeat(HeartbeatArgs),
    /// Give up a claim or an assignment
    #[command(alias = "unclaim", long_about = RELEASE_LONG_ABOUT)]
    Release(ReleaseArgs),
    /// Revert expired claims of dead workers (past the grace period)
    #[command(long_about = RECLAIM_LONG_ABOUT)]
    Reclaim(ReclaimArgs),
    /// List leases and their expiry
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
    /// Manage durable workspace memories
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
    /// Read the event history
    #[command(long_about = EVENTS_LONG_ABOUT)]
    Events(EventsArgs),
    /// Show the event history of one issue
    History(HistoryArgs),
    /// Print agent context: workflow, actor, claims, ready work, memories
    #[command(long_about = PRIME_LONG_ABOUT)]
    Prime(PrimeArgs),
    /// Run agent session hooks (called by an agent harness)
    #[command(subcommand)]
    Hook(HookCommand),
    /// Show workspace statistics
    Stats,
    /// Print operational metrics (Prometheus text or JSON)
    Metrics(MetricsArgs),
    /// Check database health and invariants, and repair with --fix
    #[command(long_about = DOCTOR_LONG_ABOUT)]
    Doctor(DoctorArgs),
    /// Read or change workspace configuration
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Rename issues to a new id prefix and make it the issue_prefix
    #[command(long_about = RENAME_PREFIX_LONG_ABOUT)]
    RenamePrefix(RenamePrefixArgs),
    /// Export a consistent JSONL snapshot
    #[command(long_about = EXPORT_LONG_ABOUT)]
    Export(ExportArgs),
    /// Import a JSONL snapshot (bd or beads format), all or nothing
    #[command(long_about = IMPORT_LONG_ABOUT)]
    Import(ImportArgs),
    /// Back up the local workspace database, keeping the newest copies
    #[command(long_about = BACKUP_LONG_ABOUT)]
    Backup(BackupArgs),
    /// Run many write operations in one transaction
    #[command(long_about = BATCH_LONG_ABOUT)]
    Batch(BatchArgs),
    /// List, preview, start and manage playbook runs
    #[command(subcommand)]
    Playbook(PlaybookCommand),
    /// Manage gates that hold work back (human, timer, issue, GitHub)
    #[command(subcommand)]
    Gate(GateCommand),
    /// Delete closed ephemeral issues (finished ephemeral runs) for good
    #[command(long_about = PURGE_LONG_ABOUT)]
    Purge(PurgeArgs),
    /// Sync agent skills and MCP definitions from the workspace's .bd/agents
    #[command(subcommand)]
    Agents(AgentsCommand),
    /// Benchmark concurrent claim throughput on a scratch database
    Bench(BenchArgs),
    #[command(hide = true)]
    BenchWorker(BenchWorkerArgs),
    /// Serve workspaces to bd and MCP clients over HTTP(S)
    #[command(long_about = SERVE_LONG_ABOUT)]
    Serve(ServeArgs),
    /// Serve this workspace to an AI assistant as MCP tools over stdio
    #[command(long_about = MCP_LONG_ABOUT)]
    Mcp(McpArgs),
    /// Use a workspace on a bd server from this checkout
    #[command(subcommand)]
    Remote(RemoteCommand),
    /// Show workspace information
    Info,
    /// Print the version
    Version,
}

#[derive(Args, Debug, Clone)]
pub struct IdArg {
    /// Issue id
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct KeyArg {
    /// Memory key
    pub key: String,
}

pub fn parse_wait(s: &str) -> Result<Duration, String> {
    bd_core::time::parse_duration(s).map_err(|e| e.to_string())
}

pub fn parse_priority(s: &str) -> Result<u8, String> {
    let t = s.trim().trim_start_matches(['P', 'p']);
    match t.parse::<u8>() {
        Ok(p) if p <= 4 => Ok(p),
        _ => Err(format!("invalid priority {s:?} (0-4 or P0-P4)")),
    }
}

fn harness_parser() -> impl clap::builder::TypedValueParser<Value = Harness> {
    use clap::builder::{PossibleValue, PossibleValuesParser, TypedValueParser};
    PossibleValuesParser::new(Harness::ALL.map(|harness| {
        PossibleValue::new(harness.name()).help(match harness {
            Harness::Claude => "Claude Code",
            Harness::Codex => "Codex",
            Harness::Copilot => "Copilot CLI",
        })
    }))
    .map(|name| name.parse::<Harness>().expect("one of the possible values"))
}
