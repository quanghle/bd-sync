//! `bd setup`.

use clap::{Args, ValueEnum};

use super::*;

/// An agent harness `bd setup` writes bd's integration for.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SetupTarget {
    /// Claude Code: hooks in .claude/settings.json
    Claude,
    /// Codex: hooks in .codex/hooks.json
    Codex,
    /// Copilot CLI: hooks in .github/hooks/bd.json
    Copilot,
    /// Cursor: instructions in .cursor/rules/bd.mdc
    Cursor,
    /// Gemini CLI: instructions in GEMINI.md
    Gemini,
    /// `opencode`: instructions in AGENTS.md
    Opencode,
}

impl SetupTarget {
    pub const ALL: [SetupTarget; 6] = [
        SetupTarget::Claude,
        SetupTarget::Codex,
        SetupTarget::Copilot,
        SetupTarget::Cursor,
        SetupTarget::Gemini,
        SetupTarget::Opencode,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SetupTarget::Claude => "claude",
            SetupTarget::Codex => "codex",
            SetupTarget::Copilot => "copilot",
            SetupTarget::Cursor => "cursor",
            SetupTarget::Gemini => "gemini",
            SetupTarget::Opencode => "opencode",
        }
    }
}

pub const SETUP_LONG_ABOUT: &str = "\
Write an agent harness's bd integration into this project

Writes what makes the harness's sessions in this project use bd. For Claude
Code, Codex and Copilot CLI: hooks that run `bd hook session-start` and `bd
prime` when a session starts (and, in Claude Code and Codex, again after the
conversation is compacted), plus Claude Code's subagent hooks. For Cursor,
Gemini CLI and opencode: a marked section of instructions telling agents to
run `bd prime`.

The project is the nearest directory, from the working directory (or -C) up,
holding a .bd directory or a .git (a directory, or a worktree's file),
whichever is closer: a git worktree is set up in itself. Setup merges into
existing files, keeping everything else in them, and skips a hook already
configured; running it again changes nothing. A file it cannot merge into is
reported and left as it is, and the command then exits 1. --remove takes out
only what setup writes.";

const SETUP_EXAMPLES: &str = "\
Examples:
  bd setup claude
  bd setup codex --dry-run
  bd setup opencode --remove
  bd setup --list";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SETUP_EXAMPLES)]
pub struct SetupArgs {
    /// The agent harness to set up
    #[arg(value_enum, required_unless_present = "list")]
    pub harness: Option<SetupTarget>,
    /// List every harness, what setup writes for it and whether it is set up here
    #[arg(long, conflicts_with_all = ["harness", "remove", "dry_run"])]
    pub list: bool,
    /// Remove what bd setup writes, leaving everything else
    #[arg(long)]
    pub remove: bool,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}
