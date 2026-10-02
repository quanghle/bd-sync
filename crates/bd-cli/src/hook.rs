//! What a session hook prints for the model's context, in the format of the
//! agent harness that runs it.
//!
//! - Claude Code and Codex add a SessionStart hook's plain-text stdout to the
//!   context. Other events take `{"hookSpecificOutput": {"hookEventName":
//!   "<event>", "additionalContext": "..."}}`, which both also read for
//!   SessionStart.
//! - Copilot CLI parses a hook's whole stdout with one `JSON.parse` and reads
//!   only `{"additionalContext": "..."}` from it (sessionStart,
//!   subagentStart): plain text, Claude Code's `hookSpecificOutput`, and two
//!   JSON documents in a row all count as no output. So everything a hook
//!   says goes into one object, printed once. Contexts of several hooks are
//!   joined with blank lines.
//!
//! Checked with Claude Code 2.1.287, Codex 0.155.1 and Copilot CLI 1.0.91.
//! A bare `{"additionalContext"}` is lost on Claude Code and fails the hook
//! on Codex, so the format follows the harness, never one for all.
//!
//! Each harness writes a JSON input on the hook's stdin, whose `cwd` is the
//! session's directory: `bd hook session-start` and `bd prime --hook` work
//! there ([`enter_session_dir`]), as Copilot CLI runs a plugin's hooks in
//! the plugin's own directory. Reading it takes [`INPUT_WAIT`] at most,
//! which counts against `bd hook session-start`'s time.
//!
//! Copilot CLI also runs the repository's `.claude/settings.json` hooks, so
//! a hook for Claude Code acts only when Claude Code runs it ([`runs_in`]).

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use bd_core::agents::Harness;
use serde_json::{Value, json};

use crate::app::App;
use crate::cli::Command;
use crate::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    SessionStart,
    SubagentStart,
}

impl Event {
    fn name(self) -> &'static str {
        match self {
            Event::SessionStart => "SessionStart",
            Event::SubagentStart => "SubagentStart",
        }
    }
}

/// `text` as `harness`'s `event` hook prints it (`None`: a harness that
/// reads plain text at session start, as Claude Code and Codex do); `None`
/// when there is nothing to say.
pub fn context(harness: Option<Harness>, event: Event, text: &str) -> Option<String> {
    let text = text.trim_end();
    if text.is_empty() {
        return None;
    }
    Some(match (harness, event) {
        (Some(Harness::Copilot), _) => json!({ "additionalContext": text }).to_string(),
        (_, Event::SessionStart) => text.to_string(),
        (_, event) => {
            json!({ "hookSpecificOutput": { "hookEventName": event.name(), "additionalContext": text } }).to_string()
        }
    })
}

/// Print [`context`] on stdout, if there is anything to say.
pub fn print_context(harness: Option<Harness>, event: Event, text: &str) {
    if let Some(out) = context(harness, event, text) {
        io::outln(out);
    }
}

/// How long a hook waits for its JSON input, which harnesses write on its
/// stdin at once, then close.
pub const INPUT_WAIT: Duration = Duration::from_secs(2);

static INPUT: OnceLock<String> = OnceLock::new();

/// The hook's JSON input: stdin, read once, unless it is a terminal; empty
/// when nothing arrives within [`INPUT_WAIT`] (a stdin left open).
pub fn input() -> &'static str {
    INPUT.get_or_init(|| {
        if std::io::stdin().is_terminal() {
            return String::new();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(io::read_stdin().unwrap_or_default());
        });
        rx.recv_timeout(INPUT_WAIT).unwrap_or_default()
    })
}

/// Whether a session hook for `harness` runs in that harness.
///
/// Copilot CLI runs the repository's `.claude/settings.json` hooks as well,
/// with input shaped like Claude Code's (`session_id`), so a `--harness
/// claude` hook acts only when Claude Code started it: `$CLAUDE_ENV_FILE`
/// (given to its SessionStart hooks) or `$CLAUDE_CODE_SESSION_ID` (2.1.132+)
/// is set, and Copilot CLI sets neither. A Copilot CLI session started from
/// a Claude Code shell inherits the latter, and is taken for Claude Code.
///
/// No harness runs Codex's or Copilot CLI's hook files, and neither marks
/// its hook processes with a documented variable (Codex 0.155.1 sets none;
/// Copilot CLI 1.0.91 sets `COPILOT_CLI` and `COPILOT_PROJECT_DIR`, which
/// its shells pass on too, undocumented), so `--harness codex` and
/// `--harness copilot` are taken as given.
pub fn runs_in(harness: Harness) -> bool {
    match harness {
        Harness::Claude => {
            ["CLAUDE_ENV_FILE", crate::actor::CLAUDE_SESSION_VAR].iter().any(|v| crate::actor::env(v).is_some())
        }
        Harness::Codex | Harness::Copilot => true,
    }
}

/// Whether `cmd` runs as a session hook that works on the session's
/// checkout: `bd hook session-start` (unless [`runs_in`] says it is not its
/// harness's), and `bd prime --hook`.
pub fn works_in_session_dir(cmd: &Command) -> bool {
    use crate::cli::HookCommand;
    match cmd {
        Command::Hook(HookCommand::SessionStart(a)) => a.harness.is_none_or(runs_in),
        Command::Prime(a) => a.hook.is_some(),
        _ => false,
    }
}

/// Work in the agent session's directory, the `cwd` of the hook's input,
/// unless `-C` names one: Copilot CLI runs a plugin's hooks in the
/// plugin's own directory, not in the session's.
pub fn enter_session_dir(app: &mut App) {
    if app.g.directory.is_some() {
        return;
    }
    let Ok(input) = serde_json::from_str::<Value>(input().trim()) else { return };
    let Some(dir) = input.get("cwd").and_then(Value::as_str).map(PathBuf::from) else { return };
    if dir.is_absolute() && dir.is_dir() {
        app.cwd = dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_harness_gets_the_format_it_reads() {
        let text = "bd: line one\nline \"two\"\n";
        for h in [None, Some(Harness::Claude), Some(Harness::Codex)] {
            assert_eq!(context(h, Event::SessionStart, text).as_deref(), Some("bd: line one\nline \"two\""));
        }
        let copilot = context(Some(Harness::Copilot), Event::SessionStart, text).unwrap();
        assert!(!copilot.contains('\n'), "{copilot}");
        let v: Value = serde_json::from_str(&copilot).unwrap();
        assert_eq!(v, json!({ "additionalContext": "bd: line one\nline \"two\"" }));
        let claude: Value = serde_json::from_str(&context(None, Event::SubagentStart, text).unwrap()).unwrap();
        assert_eq!(claude["hookSpecificOutput"]["hookEventName"], "SubagentStart");
        assert_eq!(claude["hookSpecificOutput"]["additionalContext"], "bd: line one\nline \"two\"");
        let copilot = context(Some(Harness::Copilot), Event::SubagentStart, "x").unwrap();
        assert_eq!(copilot, r#"{"additionalContext":"x"}"#);
        for h in [None, Some(Harness::Copilot)] {
            assert_eq!(context(h, Event::SessionStart, " \n"), None, "nothing at all, not an empty object");
        }
    }

    /// The hook commands of `file` (Claude Code's settings format), by event.
    fn hook_commands(file: &str) -> Vec<(String, String)> {
        let v: Value = serde_json::from_str(file).unwrap();
        let mut commands = Vec::new();
        for (event, groups) in v["hooks"].as_object().unwrap() {
            for group in groups.as_array().unwrap() {
                for hook in group["hooks"].as_array().unwrap() {
                    commands.push((event.clone(), hook["command"].as_str().unwrap().to_string()));
                }
            }
        }
        commands
    }

    #[test]
    fn the_repositorys_hook_configs_run_bd_commands_that_parse() {
        use clap::Parser;
        let claude = hook_commands(include_str!("../../../.claude/settings.json"));
        let copilot = hook_commands(include_str!("../../../.copilot-plugin/plugin.json"));
        let session_start = |commands: &[(String, String)]| -> Vec<String> {
            commands.iter().filter(|(e, _)| e == "SessionStart").map(|(_, c)| c.clone()).collect()
        };
        assert_eq!(session_start(&claude), ["bd hook session-start --harness claude", "bd prime"]);
        assert_eq!(session_start(&copilot), ["bd hook session-start --harness copilot", "bd prime --hook copilot"]);
        // Copilot CLI uses no PreCompact hook's output.
        assert!(copilot.iter().all(|(e, _)| e == "SessionStart"), "{copilot:?}");
        for (event, command) in claude.iter().chain(&copilot) {
            let words: Vec<&str> = command.trim_end_matches("|| true").split_whitespace().collect();
            assert_eq!(words.first(), Some(&"bd"), "{event}: {command}");
            if let Err(e) = crate::cli::Cli::try_parse_from(&words) {
                panic!("{event}: {command}: {e}");
            }
        }
    }
}
