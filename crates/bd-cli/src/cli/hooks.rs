//! `bd hook`.

use bd_core::agents::Harness;
use clap::{Args, Subcommand};

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum HookCommand {
    /// SessionStart hook: check the checkout's agent skills and MCP definitions against the workspace's (applying
    /// removals, never writing new or changed skills or MCP definitions) and say what changed or waits; in Claude Code, also
    /// give the session its own actor by writing `export CLAUDE_CODE_SESSION_ID=<id>` (the session's own id, from
    /// the hook's JSON input on stdin) to $CLAUDE_ENV_FILE. Prints nothing when there is nothing to say
    #[command(after_help = HOOK_SESSION_START_HELP)]
    SessionStart(HookSessionStartArgs),
    /// Claude Code SubagentStart hook: tell the subagent (in its context) to pass `--session agent-<id>` to its bd commands, so that it acts as its own actor rather than as its parent session, whose session id its commands carry
    SubagentStart,
    /// Claude Code PreToolUse hook for Bash: in a subagent, refuse a command that runs bd without `--session`, $BD_SESSION or an actor of its own, giving the command to run instead; never approves anything
    PreToolUse,
}

const HOOK_SESSION_START_HELP: &str = "Hook entries: `bd hook session-start --harness claude` (.claude/settings.json), `--harness codex` (.codex/hooks.json), `--harness copilot` (a Copilot CLI plugin or .github/hooks), each followed by `bd prime` (`bd prime --hook copilot` for Copilot CLI).\nIt works in the session's directory, the cwd of the hook's JSON input on stdin (Copilot CLI runs a plugin's hooks in the plugin's own directory).\nOutput: plain text for claude and codex; one JSON object {\"additionalContext\": \"...\"} for copilot, which reads nothing else; nothing when there is nothing to say. Never fails the hook: it exits 0, gives up on the server within a few seconds, and reports problems in one line.";

#[derive(Args, Debug, Clone)]
pub struct HookSessionStartArgs {
    /// The agent harness running the hook: what it prints, and whose agent assets it checks (default: the agent
    /// session's, from $CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID or $CODEX_THREAD_ID, which Codex and
    /// Copilot CLI do not set for hooks; else those .bd/agents.lock records, with plain-text output)
    #[arg(long, value_parser = harness_parser())]
    pub harness: Option<Harness>,
}
