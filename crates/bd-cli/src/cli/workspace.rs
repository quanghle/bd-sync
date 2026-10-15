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
    /// Print a memory
    Get(KeyArg),
    /// List memories, or search them by substring
    List(MemoryListArgs),
    /// Delete a memory
    #[command(alias = "remove")]
    Rm(KeyArg),
}

#[derive(Args, Debug, Clone)]
pub struct MemoryAddArgs {
    /// Content, up to 64 KiB (words are joined)
    #[arg(required = true, num_args = 1..)]
    pub content: Vec<String>,
    /// Key: letters, digits, '-', '_', '.', ':' or '/', at most 128 characters (default: the content's first 8 words,
    /// lowercased and joined with '-', at most 60 characters)
    #[arg(long, value_name = "KEY")]
    pub key: Option<String>,
    /// Write only if the memory is still at revision N (0 = create only)
    #[arg(long, value_name = "N")]
    pub if_revision: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct MemoryListArgs {
    /// Only memories whose key or content contains this text (case-insensitive)
    pub query: Option<String>,
}

pub const EVENTS_LONG_ABOUT: &str = "\
Read the event history

Every change is recorded as an event with a sequence number (seq). Without
--since, prints the latest events; with --since SEQ, every event after SEQ, so
a reader continues from the last seq it saw. --follow keeps printing new
events until interrupted, and --since SEQ --wait D waits up to D for the first
match. The filters (--issue, --op, --by) apply to all of these. With --json,
one JSON object per line. A cursor behind the oldest event kept fails with
exit 6 (see `bd events prune`).";

const EVENTS_EXAMPLES: &str = "\
Examples:
  bd events --since 120 --wait 30s
  bd events --follow --op closed,released
  bd events --issue bd-12 -n 10";

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true, after_long_help = EVENTS_EXAMPLES)]
pub struct EventsArgs {
    #[command(subcommand)]
    pub action: Option<EventsAction>,
    /// Only events after sequence number SEQ, a strict cursor (exit 6 if events after it were pruned)
    #[arg(long, value_name = "SEQ")]
    pub since: Option<i64>,
    /// Maximum events (default: the latest 50; with --since, unlimited)
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,
    /// Keep printing new events as they are committed, until interrupted
    #[arg(short, long)]
    pub follow: bool,
    /// With --since: if no event matches yet, wait up to this long for one, e.g. 30s
    #[arg(long, value_name = "DURATION", requires = "since", conflicts_with = "follow", value_parser = parse_wait)]
    pub wait: Option<Duration>,
    /// Poll interval for --follow and --wait, in milliseconds (at least 10; against a bd server, at least 200 between
    /// requests)
    #[arg(long, default_value_t = 500, value_name = "MS")]
    pub interval_ms: u64,
    /// Only events of this issue (a deleted one too)
    #[arg(long, value_name = "ID")]
    pub issue: Option<String>,
    /// Only these ops, e.g. created, claimed, closed (repeatable or comma separated)
    #[arg(long = "op", value_delimiter = ',', value_name = "OP")]
    pub ops: Vec<String>,
    /// Only events recorded by this actor (exact name, sub-actors not included)
    #[arg(long = "by", value_name = "ACTOR")]
    pub by_actor: Option<String>,
}

pub const EVENTS_PRUNE_LONG_ABOUT: &str = "\
Delete old events

Deletes the events that every criterion given marks as old: an event survives
if --before or --older-than keeps it, or if --keep N keeps it as one of the
newest N. --keep adds a bound only once the workspace holds at least N events;
with fewer, the other criteria decide alone, and --keep alone has nothing to
prune. At least one criterion is needed. Readers whose cursor falls behind the
oldest event kept then fail with exit 6. Config events.retain_days and
events.retain_rows prune automatically as events are written. Through bd
serve, events prune needs an admin token.";

const EVENTS_PRUNE_EXAMPLES: &str = "\
Examples:
  bd events prune --older-than 30d
  bd events prune --older-than 7d --keep 10000   # older than 7d, outside the newest 10000";

#[derive(Subcommand, Debug, Clone)]
pub enum EventsAction {
    /// Delete old events
    #[command(long_about = EVENTS_PRUNE_LONG_ABOUT)]
    Prune(PruneArgs),
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = EVENTS_PRUNE_EXAMPLES)]
pub struct PruneArgs {
    /// Delete events with a sequence number below SEQ
    #[arg(long, value_name = "SEQ")]
    pub before: Option<i64>,
    /// Delete events older than this, e.g. 30d
    #[arg(long, value_name = "DURATION")]
    pub older_than: Option<String>,
    /// Keep the newest N events (no bound while fewer than N exist)
    #[arg(long, value_name = "N")]
    pub keep: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    /// Issue id (a deleted issue keeps its history)
    pub id: String,
}

pub const PRIME_LONG_ABOUT: &str = "\
Print agent context: workflow, actor, claims, ready work, memories

Prints what an agent session needs to start: the bd workflow, the actor it
acts as, its claims and those of the user's other sessions, the head of the
ready queue, gates waiting on a person, playbooks and the workspace's
memories. Session-start hooks run it (with --hook); run it again after the
session's context was cleared.";

const PRIME_EXAMPLES: &str = "\
Examples:
  bd prime
  bd prime --hook copilot        # as a Copilot CLI session-start hook";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PRIME_EXAMPLES)]
pub struct PrimeArgs {
    /// Most memories shown (0 = all)
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub max_memories: usize,
    /// Ready issues shown, at least 1
    #[arg(long, default_value_t = 10, value_name = "N")]
    pub ready: usize,
    /// Most playbooks listed (0 = all)
    #[arg(long, default_value_t = 10, value_name = "N")]
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
    /// Prometheus text exposition format
    Prometheus,
    /// One JSON document
    Json,
}

#[derive(Args, Debug, Clone)]
pub struct MetricsArgs {
    /// Output format (--json prints JSON too)
    #[arg(long, value_enum, default_value = "prometheus")]
    pub format: MetricsFormat,
}

pub const DOCTOR_LONG_ABOUT: &str = "\
Check database health and invariants, and repair with --fix

Checks SQLite integrity, foreign keys, the journal mode and schema version,
status invariants, that claims and leases match, the materialized blocked
flags, dependency cycles, the event sequence and leases expired past their
grace. Exits 1 if an error remains; warnings do not count. --fix repairs
leases that do not match their claims and recomputes blocked flags, in one
transaction; other problems are only reported. Through bd serve, doctor needs
an admin token.";

const DOCTOR_EXAMPLES: &str = "\
Examples:
  bd doctor
  bd doctor --fix
  bd doctor --full --json";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = DOCTOR_EXAMPLES)]
pub struct DoctorArgs {
    /// Repair what can be repaired safely (leases out of step with claims, drifted blocked flags)
    #[arg(long)]
    pub fix: bool,
    /// Run SQLite's full integrity_check instead of quick_check (slower)
    #[arg(long)]
    pub full: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommand {
    /// Print a configuration value, or its default
    Get(ConfigKeyArg),
    /// Set a configuration value
    Set(ConfigSetArgs),
    /// Remove a configuration value, restoring its default
    Unset(ConfigKeyArg),
    /// List configuration values, marking defaults
    List,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigKeyArg {
    /// Configuration key (see `bd config list`)
    pub key: String,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigSetArgs {
    /// Configuration key: one `bd config list` shows, or custom.<name> for a value of one's own
    pub key: String,
    /// Value, checked against what the key accepts
    pub value: String,
}

pub const EXPORT_LONG_ABOUT: &str = "\
Export a consistent JSONL snapshot

Writes one snapshot, read in a single transaction: a header with the event
head at that moment, then the issues sorted by id with their labels,
dependencies and comments, then the memories. Leases are never exported, nor
ephemeral issues without --include-ephemeral. `bd import` reads it back, into
this workspace or another one, and a mirror can follow `bd events --since`
from the header's head.";

const EXPORT_EXAMPLES: &str = "\
Examples:
  bd export -o snapshot.jsonl
  bd export --open-only --no-memories -o open.jsonl";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = EXPORT_EXAMPLES)]
pub struct ExportArgs {
    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Leave memories out
    #[arg(long)]
    pub no_memories: bool,
    /// Leave closed and pinned issues out
    #[arg(long)]
    pub open_only: bool,
    /// Include ephemeral issues (scratch runs), which are left out by default
    #[arg(long)]
    pub include_ephemeral: bool,
}

pub const BACKUP_LONG_ABOUT: &str = "\
Back up the local workspace database, keeping the newest copies

Writes a checked copy of the database to DIR/<name>/<name>-<UTC time>.db while
the workspace stays in use, then deletes the oldest backups of that name
beyond --keep. Works on a local workspace only: a bd server backs up the
workspaces it serves itself (`bd serve --backup-dir`).";

const BACKUP_EXAMPLES: &str = "\
Examples:
  bd backup --to ../backups
  bd backup --to /var/backups/bd --keep 48 --name proj";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = BACKUP_EXAMPLES)]
pub struct BackupArgs {
    /// Directory to back up into: the copy goes to DIR/<name>/<name>-<UTC time>.db
    #[arg(long, value_name = "DIR")]
    pub to: PathBuf,
    /// Backups kept in DIR/<name>/, the new one included; older ones are deleted (0 = keep all)
    #[arg(long, default_value_t = 24, value_name = "N")]
    pub keep: usize,
    /// Backup name: ASCII letters, digits, '.', '_' or '-', starting with a letter or digit, at most 100 characters
    /// (default: the issue prefix)
    #[arg(long)]
    pub name: Option<String>,
}

pub const IMPORT_LONG_ABOUT: &str = "\
Import a JSONL snapshot (bd or beads format), all or nothing

Upserts issues by id, with their labels, dependencies and comments, and
memories by key, in one transaction: on any error nothing is imported. Reads
`bd export` output and the beads export format. An import that would end
another actor's live claim is refused without --take-over. Through bd serve,
import always needs an admin token.";

const IMPORT_EXAMPLES: &str = "\
Examples:
  bd import snapshot.jsonl --dry-run
  bd import snapshot.jsonl
  bd import - --lenient          # from stdin";

pub const RENAME_PREFIX_LONG_ABOUT: &str = "\
Rename issues to a new id prefix and make it the issue_prefix

Renames every issue whose id starts with OLD- (default: the current
issue_prefix) to NEW_PREFIX-, in one transaction. Ids move everywhere they are
stored: edges, labels, comments, claims with their lease tokens, child
counters and events. JSON references in metadata and event data, and
whole-token references in issue text, comments and memories, are rewritten
too. An id that would collide with an issue not being renamed refuses the
whole rename. Through bd serve, rename-prefix needs an admin token.";

const RENAME_PREFIX_EXAMPLES: &str = "\
Examples:
  bd rename-prefix acme --dry-run
  bd rename-prefix acme --from bd";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = RENAME_PREFIX_EXAMPLES)]
pub struct RenamePrefixArgs {
    /// New prefix: lowercase letters, digits and '-', at most 32 characters
    #[arg(value_name = "NEW_PREFIX")]
    pub prefix: String,
    /// Rename ids with this prefix instead of the current issue_prefix
    #[arg(long, value_name = "OLD")]
    pub from: Option<String>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = IMPORT_EXAMPLES)]
pub struct ImportArgs {
    /// JSONL file, or - for stdin
    pub file: String,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
    /// Keep unknown issue types and map unknown statuses to open
    #[arg(long)]
    pub lenient: bool,
    #[arg(
        long,
        help = concat!(
            "Import over other actors' live claims, moving them out of in_progress or to another assignee",
            import_take_over_suffix!()
        )
    )]
    pub take_over: bool,
}

pub const BATCH_LONG_ABOUT: &str = "\
Run many write operations in one transaction

Reads one operation per line: a bd subcommand without the leading `bd`, with
the same flags as on the command line. $N stands for the id that operation N
produced (counting operations from 1, not lines), $$ for a literal $, and
lines starting with # are comments. The operations: create, update, close,
reopen, defer, undefer, delete, dep, label, comment add, claim, release,
heartbeat, remember, forget, config set and config unset. If one fails, none
is applied.";

const BATCH_EXAMPLES: &str = "\
Example file:
  create \"Write the migration\" -p 1
  create \"Run the migration\" --dep $1
  # $2 waits on $1
  claim $1

Examples:
  bd batch -f ops.txt --dry-run
  bd batch -f ops.txt";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = BATCH_EXAMPLES)]
pub struct BatchArgs {
    /// Read operations from this file (default: stdin)
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}
