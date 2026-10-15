//! `bd hook`.

use bd_core::agents::Harness;
use clap::{Args, Subcommand};

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum HookCommand {
    /// Check agent assets and tell a new session what changed (SessionStart hook)
    #[command(long_about = HOOK_SESSION_START_LONG_ABOUT, after_long_help = HOOK_SESSION_START_HELP)]
    SessionStart(HookSessionStartArgs),
    /// Give a Claude Code subagent an actor of its own (SubagentStart hook)
    #[command(long_about = HOOK_SUBAGENT_START_LONG_ABOUT)]
    SubagentStart,
    /// Refuse bd commands that would act as a subagent's parent (PreToolUse hook)
    #[command(long_about = HOOK_PRE_TOOL_USE_LONG_ABOUT)]
    PreToolUse,
}

const HOOK_SESSION_START_LONG_ABOUT: &str = "\
Check agent assets and tell a new session what changed (SessionStart hook)

Checks the checkout's agent skills and MCP definitions against the
workspace's, applying removals but never writing new or changed skills or MCP
definitions, and says what changed or waits for `bd agents approve`. In Claude
Code it also gives the session its own actor, by writing `export
CLAUDE_CODE_SESSION_ID=<id>` (the session's own id, from the hook's JSON input
on stdin) to $CLAUDE_ENV_FILE. A --harness other than the one running the
hook makes it do and print nothing. Prints nothing when there is nothing to
say.";

const HOOK_SESSION_START_HELP: &str = "\
Hook entries, each followed by `bd prime` (`bd prime --hook copilot` for
Copilot CLI):
  --harness claude    in .claude/settings.json
  --harness codex     in .codex/hooks.json
  --harness copilot   in a Copilot CLI plugin or .github/hooks
It works in the session's directory, the cwd of the hook's JSON input on stdin
(Copilot CLI runs a plugin's hooks in the plugin's own directory).

Output: plain text for claude and codex; one JSON object
{\"additionalContext\": \"...\"} for copilot, which reads nothing else; nothing
when there is nothing to say. Never fails the hook: it exits 0, gives up on
the server within a few seconds, and reports problems in one line.

Examples:
  bd hook session-start --harness claude
  bd hook session-start --harness copilot";

const HOOK_SUBAGENT_START_LONG_ABOUT: &str = "\
Give a Claude Code subagent an actor of its own (SubagentStart hook)

A subagent's commands carry its parent session's id, so its bd commands would
act as the parent, able to end the parent's claims. This hook tells the
subagent, in its context, to pass `--session agent-<id>` to its bd commands,
so that it acts as its own actor. Never fails the hook.";

const HOOK_PRE_TOOL_USE_LONG_ABOUT: &str = "\
Refuse bd commands that would act as a subagent's parent (PreToolUse hook)

Run by Claude Code before a Bash command. In a subagent, a command that runs
bd without --session, $BD_SESSION or an actor of its own (--actor, $BD_ACTOR)
is refused, with the command to run instead. Never rewrites or approves a
command, so the permission rules apply as they are, and never fails the hook.";

#[derive(Args, Debug, Clone)]
pub struct HookSessionStartArgs {
    /// The agent harness running the hook: what it prints, and whose agent assets it checks (default: the agent
    /// session's, from $CLAUDE_CODE_SESSION_ID, $COPILOT_AGENT_SESSION_ID or $CODEX_THREAD_ID, which Codex and
    /// Copilot CLI do not set for hooks; else those .bd/agents.lock records, with plain-text output)
    #[arg(long, value_parser = harness_parser())]
    pub harness: Option<Harness>,
}
