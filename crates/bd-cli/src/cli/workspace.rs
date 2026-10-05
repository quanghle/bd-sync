//! Memories, events, history, prime, metrics, doctor, config, export, backup, import and batch.

use std::path::PathBuf;
use std::time::Duration;

use bd_core::agents::Harness;
use clap::{Args, Subcommand, ValueEnum};

use super::*;

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
    /// Keep printing new events as they are committed
    #[arg(short, long)]
    pub follow: bool,
    /// With --since: if no event matches yet, wait up to this long for one (e.g. 30s, 5m)
    #[arg(long, value_name = "DURATION", requires = "since", conflicts_with = "follow", value_parser = parse_wait)]
    pub wait: Option<Duration>,
    /// Poll interval for --follow and --wait; a remote follower asks at most this often
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
    /// Cap the number of playbooks listed (0 = all)
    #[arg(long, default_value_t = 10)]
    pub max_playbooks: usize,
    /// Run as a session hook of this agent harness: work in the session's directory (the cwd of the hook's JSON
    /// input on stdin), and print the context as the harness reads it: copilot gets one JSON object
    /// {"additionalContext": "..."}, as Copilot CLI drops plain text; claude and codex read plain text. Takes
    /// precedence over --json
    #[arg(long, value_name = "HARNESS", value_parser = harness_parser())]
    pub hook: Option<Harness>,
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
pub struct BackupArgs {
    /// Directory to back up into: the copy goes to DIR/<name>/<name>-<UTC time>.db
    #[arg(long, value_name = "DIR")]
    pub to: PathBuf,
    /// Backups kept in DIR/<name>/, the new one included; older ones are deleted (0 = keep all)
    #[arg(long, default_value_t = 24, value_name = "N")]
    pub keep: usize,
    /// Name of the backups (default: the workspace's issue prefix)
    #[arg(long)]
    pub name: Option<String>,
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
    /// Import over other actors' live claims too (moving them out of in_progress or to another assignee; recorded in
    /// the events)
    #[arg(long)]
    pub take_over: bool,
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
