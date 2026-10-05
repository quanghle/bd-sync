//! Command-line grammar.

use std::path::PathBuf;
use std::time::Duration;

use bd_core::agents::Harness;
use clap::{Args, Parser, Subcommand, ValueEnum};

mod agents;
mod bench;
mod claims;
mod hooks;
mod issues;
mod links;
mod playbooks;
mod remote;
mod serve;
mod workspace;

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
    /// Workspace on a bd server, e.g. https://bd.example.com/w/proj (default: .bd/remote.toml); token: $BD_TOKEN (with this or $BD_REMOTE only) or `bd remote login`
    #[arg(long, global = true, env = "BD_REMOTE", value_name = "URL")]
    pub remote: Option<String>,
    /// Run as if started in this directory
    #[arg(short = 'C', long = "directory", global = true, value_name = "DIR")]
    pub directory: Option<PathBuf>,
    /// Actor name (default: $BD_ACTOR, $BEADS_ACTOR, else git user.name or $USER, as `<user>/<session>` in an agent session: $CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID, $CODEX_THREAD_ID, $BD_SESSION)
    #[arg(long, global = true, value_name = "NAME")]
    pub actor: Option<String>,
    /// Name this session, as $BD_SESSION does (and instead of it): act as `<user>/<harness session>.<NAME>`, e.g. a Claude Code subagent's `--session agent-<id>`; no effect when the actor is named outright
    #[arg(long, global = true, value_name = "NAME")]
    pub session: Option<String>,
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
    /// How long a writer waits for the database write lock (and bd agents for a checkout's agent assets mutex)
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
    /// Agent context: workflow, your actor and claims, ready work, memories
    Prime(PrimeArgs),
    /// Agent session hooks, run by an agent harness (see `bd hook --help`)
    #[command(subcommand)]
    Hook(HookCommand),
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
    /// Back up the local workspace's database into DIR/<name>/, keeping the newest N copies
    Backup(BackupArgs),
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
    /// Agent skills and MCP server definitions the workspace serves per harness (claude, codex, copilot) from .bd/agents
    #[command(subcommand)]
    Agents(AgentsCommand),
    /// Benchmark concurrent claim throughput on a scratch database
    Bench(BenchArgs),
    #[command(hide = true)]
    BenchWorker(BenchWorkerArgs),
    /// Serve workspaces to remote bd clients over HTTPS; `bd serve token` manages access
    Serve(ServeArgs),
    /// Serve this workspace to an AI assistant as MCP tools over stdio (local or remote workspace)
    Mcp(McpArgs),
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
    use clap::builder::{PossibleValuesParser, TypedValueParser};
    PossibleValuesParser::new(Harness::ALL.map(Harness::name))
        .map(|name| name.parse::<Harness>().expect("one of the possible values"))
}
