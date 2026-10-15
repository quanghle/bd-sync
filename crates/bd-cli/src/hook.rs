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
//!
//! After compacting a conversation, Claude Code and Codex run SessionStart
//! hooks again with `"source": "compact"` in the input ([`compacted`]), and
//! add their output to the new context: that is how a session gets its bd
//! context back. PreCompact and PostCompact output never reaches the model,
//! and Copilot CLI has no event that runs after compaction.

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

/// Whether the hook runs because the conversation was compacted: its input's
/// `source` is `compact` (a SessionStart hook in Claude Code and Codex).
pub fn compacted() -> bool {
    compacted_in(input())
}

/// [`compacted`] of a hook's JSON `input`: an input naming another event
/// than SessionStart never counts.
fn compacted_in(input: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(input.trim()) else { return false };
    if v.get("hook_event_name").and_then(Value::as_str).is_some_and(|e| e != "SessionStart") {
        return false;
    }
    v.get("source").and_then(Value::as_str) == Some("compact")
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

/// Act as the session's commands do: the session id of the hook's input,
/// for a harness that keeps its session variable from hook processes
/// ([`crate::actor::set_hook_session`]), when the hook runs in that harness
/// ([`runs_in`]); `bd hook session-start --harness` and `bd prime --hook`.
pub fn take_session_id(cmd: &Command) {
    use crate::cli::HookCommand;
    let harness = match cmd {
        Command::Hook(HookCommand::SessionStart(a)) => a.harness,
        Command::Prime(a) => a.hook,
        _ => None,
    };
    if let Some(h) = harness.filter(|&h| runs_in(h)) {
        crate::actor::set_hook_session(h, input());
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
        let plugin = hook_commands(PLUGIN_HOOKS);
        let copilot = hook_commands(include_str!("../../../.copilot-plugin/plugin.json"));
        let session_start = |commands: &[(String, String)]| -> Vec<String> {
            commands.iter().filter(|(e, _)| e == "SessionStart").map(|(_, c)| c.clone()).collect()
        };
        assert_eq!(session_start(&claude), ["bd hook session-start --harness claude", "bd prime --hook claude"]);
        assert_eq!(session_start(&copilot), ["bd hook session-start --harness copilot", "bd prime --hook copilot"]);
        // Copilot CLI uses no PreCompact hook's output.
        assert!(copilot.iter().all(|(e, _)| e == "SessionStart"), "{copilot:?}");
        for (event, command) in claude.iter().chain(&copilot).chain(&plugin) {
            let words: Vec<&str> = command.trim_end_matches("|| true").split_whitespace().collect();
            assert_eq!(words.first(), Some(&"bd"), "{event}: {command}");
            if let Err(e) = crate::cli::Cli::try_parse_from(&words) {
                panic!("{event}: {command}: {e}");
            }
        }
    }

    #[test]
    fn the_repositorys_hook_configs_have_no_empty_matcher() {
        // Copilot CLI refuses a whole file with an empty `matcher`; an omitted one matches all for both harnesses.
        for file in [
            include_str!("../../../.claude/settings.json"),
            include_str!("../../../.copilot-plugin/plugin.json"),
            PLUGIN_HOOKS,
        ] {
            let v: Value = serde_json::from_str(file).unwrap();
            for (event, groups) in v["hooks"].as_object().unwrap() {
                for group in groups.as_array().unwrap() {
                    assert_ne!(group.get("matcher").and_then(Value::as_str), Some(""), "{event}");
                }
            }
        }
    }

    #[test]
    fn compaction_is_told_by_the_input_source() {
        assert!(compacted_in(r#"{"session_id": "s", "source": "compact"}"#));
        assert!(compacted_in(r#"{"hook_event_name": "SessionStart", "source": "compact"}"#));
        for input in [
            r#"{"source": "startup"}"#,
            r#"{"source": "resume"}"#,
            r#"{"session_id": "s"}"#,
            "not json",
            "",
            r#"{"hook_event_name": "PreCompact", "source": "compact"}"#,
        ] {
            assert!(!compacted_in(input), "{input}");
        }
    }

    /// The Claude Code plugin's hooks and skill: a missing file fails the build.
    const PLUGIN_HOOKS: &str = include_str!("../../../plugins/bd/hooks/hooks.json");
    const PLUGIN_SKILL: &str = include_str!("../../../plugins/bd/skills/bd/SKILL.md");

    #[test]
    fn bd_session_start_hooks_fire_after_compaction() {
        use crate::agents::session_hook::items;
        let mut configs: Vec<(String, Value)> = vec![
            (
                ".claude/settings.json".into(),
                serde_json::from_str(include_str!("../../../.claude/settings.json")).unwrap(),
            ),
            ("plugins/bd/hooks/hooks.json".into(), serde_json::from_str(PLUGIN_HOOKS).unwrap()),
        ];
        for h in [Harness::Claude, Harness::Codex] {
            configs.push((format!("pull's {h} items"), json!({ "hooks": { "SessionStart": items(h) } })));
        }
        let mut checked = 0;
        for (name, v) in &configs {
            for group in v["hooks"]["SessionStart"].as_array().unwrap() {
                let runs_bd = group["hooks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|h| h["command"].as_str().is_some_and(|c| c.starts_with("bd hook session-start")));
                if !runs_bd {
                    continue;
                }
                checked += 1;
                if let Some(matcher) = group.get("matcher").and_then(Value::as_str) {
                    assert!(matcher.split('|').any(|m| m == "compact"), "{name}: matcher {matcher:?}");
                }
            }
            for event in ["PreCompact", "PostCompact"] {
                assert!(v["hooks"].get(event).is_none(), "{name}: {event} output never reaches the model");
            }
        }
        assert!(checked >= 3, "{checked}");
    }

    #[test]
    fn the_claude_plugin_runs_the_same_hooks_as_the_repository() {
        let text = PLUGIN_HOOKS;
        let plugin: Value = serde_json::from_str(text).unwrap();
        let settings: Value = serde_json::from_str(include_str!("../../../.claude/settings.json")).unwrap();
        assert_eq!(plugin["hooks"], settings["hooks"]);
        let keys: Vec<&String> = plugin.as_object().unwrap().keys().collect();
        assert!(keys.iter().all(|k| *k == "hooks" || *k == "description"), "{keys:?}");
        // The commands parse, and no matcher is empty, as the repository's own configs are checked above.
        for (event, command) in hook_commands(text) {
            let words: Vec<&str> = command.trim_end_matches("|| true").split_whitespace().collect();
            if let Err(e) = <crate::cli::Cli as clap::Parser>::try_parse_from(&words) {
                panic!("{event}: {command}: {e}");
            }
        }
    }

    #[test]
    fn the_plugin_marketplace_has_the_documented_shape() {
        let market: Value = serde_json::from_str(include_str!("../../../.claude-plugin/marketplace.json")).unwrap();
        let plugin: Value =
            serde_json::from_str(include_str!("../../../plugins/bd/.claude-plugin/plugin.json")).unwrap();
        assert!(market["name"].as_str().is_some_and(|n| !n.is_empty()));
        assert!(market["owner"]["name"].as_str().is_some_and(|n| !n.is_empty()));
        let entry = &market["plugins"][0];
        assert_eq!(entry["name"], "bd");
        assert_eq!(plugin["name"], entry["name"]);
        let source = entry["source"].as_str().unwrap();
        assert!(source.starts_with("./") && !source.contains(".."), "{source}");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(source);
        assert!(dir.join(".claude-plugin/plugin.json").is_file(), "{}", dir.display());
        const MANIFEST_FIELDS: [&str; 18] = [
            "name",
            "displayName",
            "version",
            "description",
            "author",
            "homepage",
            "repository",
            "license",
            "keywords",
            "hooks",
            "skills",
            "commands",
            "agents",
            "mcpServers",
            "outputStyles",
            "lspServers",
            "userConfig",
            "dependencies",
        ];
        for key in plugin.as_object().unwrap().keys() {
            assert!(MANIFEST_FIELDS.contains(&key.as_str()), "plugin.json: {key} is not a manifest field");
        }
        assert!(plugin.get("version").is_none(), "installs track commits");
        // A Windows checkout may have CRLF line endings.
        let skill = PLUGIN_SKILL.replace("\r\n", "\n");
        let front = skill.strip_prefix("---\n").and_then(|s| s.split_once("\n---\n")).map(|(f, _)| f).unwrap();
        assert!(front.lines().any(|l| l == "name: bd"), "{front}");
        assert!(front.lines().any(|l| l.starts_with("description: ")), "{front}");
        assert!(skill.contains("bd prime") && skill.contains("compact"));
    }

    #[test]
    fn the_skills_say_to_prime_again_after_compaction() {
        for skill in [PLUGIN_SKILL, include_str!("../../../.agents/skills/bd/SKILL.md")] {
            assert!(
                skill.lines().any(|l| l.contains("compacted") && l.contains("bd prime") && l.contains("lease token")),
                "{skill}"
            );
        }
    }

    #[test]
    fn the_plugin_skill_does_not_forbid_the_take_overs_bd_directs() {
        // `bd prime` ("Held by other sessions of yours") and `bd hook subagent-start` tell a session to
        // take over a claim it continues; the skill must not tell agents never to.
        let lower = PLUGIN_SKILL.to_lowercase();
        assert!(lower.contains("held by other sessions of yours") && lower.contains("subagent hook"));
        for ban in ["never", "do not", "don't"] {
            for verb in ["pass", "use", "run"] {
                for flag in ["`--take-over`", "--take-over"] {
                    assert!(!lower.contains(&format!("{ban} {verb} {flag}")), "{ban} {verb} {flag}");
                }
            }
        }
    }
}
