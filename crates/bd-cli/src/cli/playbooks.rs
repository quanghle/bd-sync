//! `bd playbook` and `bd gate`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::*;

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
    /// Compact even though the run is not finished, deleting its open steps (never past another actor's claim: see
    /// --take-over)
    #[arg(long)]
    pub force: bool,
    /// Delete steps other actors hold live claims on (recorded in the event; through bd serve, an admin token unless
    /// the token's actor owns the claims)
    #[arg(long)]
    pub take_over: bool,
    /// Print the digest without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DiscardArgs {
    pub id: String,
    /// Discard even with work in progress: your own claims, or dead ones (never past another actor's claim: see
    /// --take-over)
    #[arg(long)]
    pub force: bool,
    /// Discard although other actors hold live claims on the run or its steps (recorded in the events; through bd
    /// serve, an admin token unless the token's actor owns the claims)
    #[arg(long)]
    pub take_over: bool,
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
