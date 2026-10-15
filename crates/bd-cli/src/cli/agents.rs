//! `bd agents`.

use std::time::Duration;

use bd_core::agents::Harness;
use clap::{Args, Subcommand};

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum AgentsCommand {
    /// List the skills and MCP entries the workspace serves to each harness
    #[command(long_about = AGENTS_MANIFEST_LONG_ABOUT, after_long_help = AGENTS_MANIFEST_HELP)]
    Manifest(AgentsManifestArgs),
    /// One harness's skill files and MCP server entries, as JSON (what bd clients pull)
    #[command(hide = true)]
    Fetch(AgentsFetchArgs),
    /// Compare this checkout's agent skills and MCP entries with the workspace's
    #[command(long_about = AGENTS_STATUS_LONG_ABOUT, after_long_help = AGENTS_STATUS_HELP)]
    Status(AgentsStatusArgs),
    /// Bring this checkout's agent skills and MCP entries up to date
    #[command(long_about = AGENTS_PULL_LONG_ABOUT, after_long_help = AGENTS_PULL_HELP)]
    Pull(AgentsPullArgs),
    /// Review and approve new or changed skills and MCP definitions
    #[command(long_about = AGENTS_APPROVE_LONG_ABOUT, after_long_help = AGENTS_APPROVE_HELP)]
    Approve(AgentsApproveArgs),
    /// Keep pulling agent assets as the workspace's sets change
    #[command(long_about = AGENTS_WATCH_LONG_ABOUT, after_long_help = AGENTS_WATCH_HELP)]
    Watch(AgentsWatchArgs),
}

const AGENTS_MANIFEST_LONG_ABOUT: &str = "\
List the skills and MCP entries the workspace serves to each harness

Shows, for each harness, the skills (a SHA-256 per file), the MCP server
entries (a SHA-256 per entry) and a revision, checking .bd/agents/<harness>
strictly. Changes nothing.";

const AGENTS_MANIFEST_HELP: &str = "\
Examples:
  bd agents manifest
  bd agents manifest --harness claude --json";

const AGENTS_STATUS_LONG_ABOUT: &str = "\
Compare this checkout's agent skills and MCP entries with the workspace's

Compares with the workspace's sets (the server's in a remote workspace) and
reports what a pull would add, update or remove, skills and MCP changes
waiting for approval, local edits and conflicts. Changes nothing.";

const AGENTS_PULL_LONG_ABOUT: &str = "\
Bring this checkout's agent skills and MCP entries up to date

Updates the harness's skills (.claude/skills, .agents/skills, .github/skills)
and MCP entries from the workspace's sets, recorded in .bd/agents.lock: skill
files and MCP entries the server removed are removed, and those deleted here
restored as approved; new or changed skills and MCP definitions wait for `bd
agents approve`. Never overwrites or deletes what bd did not write, or local
edits (without --force). Also adds the harness's session-start hook (bd hook
session-start, then bd prime) where none is configured:
.claude/settings.local.json, .codex/hooks.json, .github/hooks/bd.json.";

macro_rules! agents_sync_help {
    () => {
        "\
Harnesses: --harness, else the running agent session's
($CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID, $CODEX_THREAD_ID), else
those .bd/agents.lock records.

Exit codes: 0 done (MCP changes waiting for approval, conflicts and local edits
are reported, not failures); 2 no harness, no checkout or an unusable
.bd/agents.lock; 3 no workspace; 5 another bd process is changing this
checkout's agent assets; 7 access denied; 8 server unreachable, or its answer
failed its checks (nothing was written)."
    };
}

const AGENTS_STATUS_HELP: &str = concat!(
    agents_sync_help!(),
    "

Examples:
  bd agents status
  bd agents status --harness claude,codex --json"
);

const AGENTS_PULL_HELP: &str = concat!(
    agents_sync_help!(),
    "

Examples:
  bd agents pull --harness claude
  bd agents pull --force --no-hook"
);

const AGENTS_APPROVE_LONG_ABOUT: &str = "\
Review and approve new or changed skills and MCP definitions

Shows each skill or MCP server definition waiting for approval (a skill's new
files whole and its changed ones as a diff; what a definition runs or connects
to, the environment variables it reads, what changed) and asks y/N, then
writes those approved into the harness's skills directory (.claude/skills,
.agents/skills, .github/skills) or MCP file (.mcp.json, .github/mcp.json,
.codex/config.toml) and .bd/agents.lock. Runs only in a terminal, outside
agent sessions.";

const AGENTS_APPROVE_HELP: &str = "\
Harnesses: --harness, else those .bd/agents.lock records. Refused inside an
agent session ($CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID,
$CODEX_THREAD_ID or $CODEX_SESSION_ID set), and when there is something to ask
about but stdin is not a terminal, with no way around either: run it in a
separate terminal. Files and entries bd did not write (conflicts) are never
replaced.

Exit codes: 0 done (declined skills and entries stay pending); 2 refused, no
harness, a name not served, no checkout or an unusable .bd/agents.lock; 3 no
workspace; 5 another bd process is changing this checkout's agent assets; 7
access denied; 8 server unreachable, or its answer failed its checks (nothing
was written).

Examples:
  bd agents approve
  bd agents approve review-skill --harness claude --full";

const AGENTS_WATCH_LONG_ABOUT: &str = "\
Keep pulling agent assets as the workspace's sets change

Pulls each change to the workspace's sets as `bd agents pull` would (removals
applied, new or changed skills and MCP definitions left for `bd agents
approve`) and reports it, until interrupted. A remote workspace's server says
when its sets change (bd serve --agents-every), and its sets are compared with
those pulled after each wait for that ends with no change; a local
workspace's .bd/agents is checked every --interval.";

const AGENTS_WATCH_HELP: &str = "\
Harnesses: --harness, else the running agent session's
($CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID, $CODEX_THREAD_ID), else
those .bd/agents.lock records.

Output: a report per pull, as `bd agents pull` prints it (one JSON object per
line with --json). Never approves anything. Failures (the server unreachable,
the checkout busy, an unusable set or lock file) are reported on stderr once,
when they start and when they end, and tried again: in a remote workspace
after growing pauses (30 s at most), in a local one every --interval. Ctrl-C
stops it, once a pull under way has finished; a second Ctrl-C stops it at
once (exit 130).

Exit codes: 0 stopped by Ctrl-C; 2 no harness or no checkout; 3 no workspace;
7 access denied (also once running).

Examples:
  bd agents watch --interval 30s
  bd agents watch --harness claude,copilot";

#[derive(Args, Debug, Clone)]
pub struct AgentsWatchArgs {
    /// Harnesses to keep up to date (repeatable or comma separated; default: the running agent session's, else those
    /// in .bd/agents.lock)
    #[arg(long = "harness", value_delimiter = ',', value_parser = harness_parser())]
    pub harnesses: Vec<Harness>,
    /// Local workspace: how often to check .bd/agents. Remote workspace: the least time between two requests to the
    /// server, which otherwise holds each one until a set changes (100ms to 1h)
    #[arg(long, default_value = "10s", value_name = "DURATION", value_parser = parse_watch_interval)]
    pub interval: Duration,
}

fn parse_watch_interval(s: &str) -> Result<Duration, String> {
    let d = bd_core::time::parse_duration(s).map_err(|e| e.to_string())?;
    if d < Duration::from_millis(100) || d > Duration::from_secs(3600) {
        return Err("use 100ms to 1h".into());
    }
    Ok(d)
}

#[derive(Args, Debug, Clone)]
pub struct AgentsApproveArgs {
    /// Only these skills and MCP servers (default: every one waiting for approval)
    pub names: Vec<String>,
    /// Harnesses to approve for (repeatable or comma separated; default: those in .bd/agents.lock)
    #[arg(long = "harness", value_delimiter = ',', value_parser = harness_parser())]
    pub harnesses: Vec<Harness>,
    /// Show long skill files, and long values, arrays and tables of the definitions, in full instead of cut short
    /// (the summary repeated before each prompt stays short)
    #[arg(long)]
    pub full: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AgentsManifestArgs {
    /// Only these harnesses (repeatable or comma separated; default: all)
    #[arg(long = "harness", value_delimiter = ',', value_parser = harness_parser())]
    pub harnesses: Vec<Harness>,
}

#[derive(Args, Debug, Clone)]
pub struct AgentsStatusArgs {
    /// Harnesses to check (repeatable or comma separated; default: the running agent session's, else those in
    /// .bd/agents.lock)
    #[arg(long = "harness", value_delimiter = ',', value_parser = harness_parser())]
    pub harnesses: Vec<Harness>,
    /// Leave the harness's session-start hook out of the check
    #[arg(long)]
    pub no_hook: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AgentsPullArgs {
    /// Harnesses to pull (repeatable or comma separated; default: the running agent session's, else those in
    /// .bd/agents.lock)
    #[arg(long = "harness", value_delimiter = ',', value_parser = harness_parser())]
    pub harnesses: Vec<Harness>,
    /// Also replace (with what was approved) or remove local edits of skill files and MCP entries bd wrote, and try
    /// again to set executable bits the file system did not keep. Never touches what bd did not write, and new or
    /// changed skills and MCP definitions still wait for approval
    #[arg(long)]
    pub force: bool,
    /// Do not add the harness's session-start hook (bd hook session-start, then bd prime) where none is configured
    #[arg(long)]
    pub no_hook: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AgentsFetchArgs {
    #[arg(long, value_parser = harness_parser())]
    pub harness: Harness,
}
