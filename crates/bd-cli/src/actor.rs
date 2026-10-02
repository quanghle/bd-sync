//! Who a command acts as.
//!
//! `--actor`, then `$BD_ACTOR`, then `$BEADS_ACTOR` name the actor outright.
//! Otherwise it is the user (`git config user.name`, then `$USER`,
//! `$USERNAME`), and inside an agent session the sub-actor
//! `<user>/<session>`: every session gets its own actor, so concurrent
//! sessions of one user never share claims, while a terminal without a
//! session keeps the plain user. The session comes from `$BD_SESSION`, or
//! from the session id an agent harness gives every shell command it runs
//! ([`SESSION_VARS`]); it stays the same for every command of the session.

use std::io::IsTerminal;
use std::process::Command;

use bd_core::Result;
use serde::Serialize;
use serde_json::Value;

use crate::app::App;
use crate::io;

/// Names a session explicitly: bd acts as `<user>/<BD_SESSION>`.
pub const SESSION_VAR: &str = "BD_SESSION";

/// Session ids that agent harnesses set in the environment of the shell
/// commands they run, and the label prefix of each: the session is
/// `<prefix>-<last 8 letters and digits of the id>`.
pub const SESSION_VARS: &[(&str, &str)] = &[
    // Claude Code 2.1.132+: Bash tool and hook subprocesses; changes on /clear.
    ("CLAUDE_CODE_SESSION_ID", "claude"),
    // Copilot CLI 1.0.29+: shell commands and MCP servers.
    ("COPILOT_AGENT_SESSION_ID", "copilot"),
    // Codex: the thread (each subagent has its own), then the root session.
    ("CODEX_THREAD_ID", "codex"),
    ("CODEX_SESSION_ID", "codex"),
];

/// Longest session label.
pub const MAX_LABEL: usize = 64;

/// Where an actor came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// `--actor`.
    Flag,
    /// `$BD_ACTOR` or `$BEADS_ACTOR`.
    Env,
    /// The user's sub-actor for this agent session.
    Session,
    /// The plain user name (or a remote access token's actor): shared by
    /// every session of that user that has no session of its own.
    Default,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub actor: String,
    pub source: Source,
    /// What named it, for people: `--actor`, `$BD_ACTOR`, `git user.name`, ...
    pub from: String,
}

impl Resolved {
    pub fn new(actor: impl Into<String>, source: Source, from: impl Into<String>) -> Resolved {
        Resolved { actor: actor.into(), source, from: from.into() }
    }
}

/// An agent session's label, and the variable it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub label: String,
    pub var: &'static str,
}

/// Looks up an environment variable (non-empty, trimmed).
pub type Env<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// The user's name, and where it came from.
pub type UserName<'a> = dyn Fn(&Env<'_>) -> (String, &'static str) + 'a;

/// A non-empty, trimmed environment variable.
pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The actor of this process: [`resolve_with`] over the real environment.
/// Under `bd serve` a request's actor is set by the server, never derived
/// from the server's own environment.
pub fn resolve(flag: Option<&str>) -> Resolved {
    if io::in_server_process() {
        return resolve_with(flag, &|_| None, &user_name);
    }
    resolve_with(flag, &env, &user_name)
}

/// `--actor`, `$BD_ACTOR`, `$BEADS_ACTOR`, else the user (from `user`), as
/// `<user>/<session>` when `env` names an agent session.
pub fn resolve_with(flag: Option<&str>, env: &Env<'_>, user: &UserName<'_>) -> Resolved {
    if let Some(a) = flag.map(str::trim).filter(|a| !a.is_empty()) {
        return Resolved::new(a, Source::Flag, "--actor");
    }
    for var in ["BD_ACTOR", "BEADS_ACTOR"] {
        if let Some(a) = env(var) {
            return Resolved::new(a, Source::Env, format!("${var}"));
        }
    }
    let (name, from) = user(env);
    match session(env) {
        Some(s) => Resolved::new(format!("{name}/{}", s.label), Source::Session, format!("{from} + ${}", s.var)),
        None => Resolved::new(name, Source::Default, from),
    }
}

/// `git config user.name`, then `$USER`, `$USERNAME`.
fn user_name(env: &Env<'_>) -> (String, &'static str) {
    let git = Command::new("git")
        .args(["config", "user.name"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(n) = git {
        return (n, "git user.name");
    }
    if let Some(n) = env("USER") {
        return (n, "$USER");
    }
    if let Some(n) = env("USERNAME") {
        return (n, "$USERNAME");
    }
    ("unknown".into(), "no user name")
}

/// The agent session `env` names: `$BD_SESSION`, else the first of
/// [`SESSION_VARS`] that is set.
pub fn session(env: &Env<'_>) -> Option<Session> {
    if let Some(label) = env(SESSION_VAR).and_then(|v| sanitize_label(&v)) {
        return Some(Session { label, var: SESSION_VAR });
    }
    SESSION_VARS.iter().find_map(|&(var, prefix)| {
        let id = short_id(&env(var)?)?;
        Some(Session { label: format!("{prefix}-{id}"), var })
    })
}

/// The last 8 letters and digits of a session id, lowercased: the random
/// part of a UUID, whether v4 or time-ordered v7 (whose first digits are
/// the same for sessions started within a minute).
pub fn short_id(id: &str) -> Option<String> {
    let alnum: Vec<char> = id.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect();
    (!alnum.is_empty()).then(|| alnum[alnum.len().saturating_sub(8)..].iter().collect())
}

/// A session name usable in an actor: letters, digits, `.`, `_`, `-` (other
/// characters become `-`), not starting or ending with `.` or `-`, at most
/// [`MAX_LABEL`] characters.
pub fn sanitize_label(s: &str) -> Option<String> {
    let mapped: String = s
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_') { c } else { '-' })
        .take(MAX_LABEL)
        .collect();
    let label = mapped.trim_matches(|c| c == '-' || c == '.');
    (!label.is_empty()).then(|| label.to_string())
}

/// Whether `s` is already a session label as [`sanitize_label`] makes them.
pub fn is_label(s: &str) -> bool {
    sanitize_label(s).as_deref() == Some(s)
}

/// `bd hook session-start`: run by an agent harness when a session starts.
/// Claude Code gives SessionStart hooks `$CLAUDE_ENV_FILE`, a script its
/// later Bash commands source: this appends `export BD_SESSION=claude-<id>`
/// to it, from the hook's JSON input, so that every bd command of the
/// session acts as the same sub-actor even where Claude Code does not set
/// `$CLAUDE_CODE_SESSION_ID` (before 2.1.132). Never fails the hook: a
/// problem is a warning on stderr.
pub fn cmd_session_start(_app: &mut App) -> Result<i32> {
    io::require_local("bd hook session-start")?;
    let Some(file) = env("CLAUDE_ENV_FILE") else { return Ok(0) };
    // An actor or session named outright is the user's choice; keep it.
    if ["BD_ACTOR", "BEADS_ACTOR", SESSION_VAR].into_iter().any(|v| env(v).is_some()) {
        return Ok(0);
    }
    let input = if std::io::stdin().is_terminal() { String::new() } else { io::read_stdin().unwrap_or_default() };
    let id = hook_session_id(&input).or_else(|| env("CLAUDE_CODE_SESSION_ID"));
    let Some(label) = id.as_deref().and_then(short_id).map(|id| format!("claude-{id}")) else {
        io::errln("bd hook session-start: no session_id in the hook input; nothing written to $CLAUDE_ENV_FILE");
        return Ok(0);
    };
    match append_export(std::path::Path::new(&file), SESSION_VAR, &label) {
        Ok(()) => io::outln(format!(
            "bd: this session's bd commands act as their own actor, `<you>/{label}` ({SESSION_VAR}={label})."
        )),
        Err(e) => io::errln(format!("bd hook session-start: cannot write {file}: {e}")),
    }
    Ok(0)
}

/// `session_id` (Claude Code, and Copilot's VS Code compatible hooks) or
/// `sessionId` (Copilot's camelCase hooks) of a hook's JSON input.
pub fn hook_session_id(input: &str) -> Option<String> {
    let v: Value = serde_json::from_str(input.trim()).ok()?;
    ["session_id", "sessionId"]
        .iter()
        .find_map(|k| v.get(k).and_then(Value::as_str))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn append_export(path: &std::path::Path, var: &str, value: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    // Labels are letters, digits, `.`, `_` and `-`: nothing a shell interprets.
    writeln!(f, "export {var}='{value}'")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn with(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }

    fn git(_: &Env<'_>) -> (String, &'static str) {
        ("Quang Le".into(), "git user.name")
    }

    fn resolve(flag: Option<&str>, vars: &[(&str, &str)]) -> Resolved {
        resolve_with(flag, &with(vars), &git)
    }

    const COPILOT: (&str, &str) = ("COPILOT_AGENT_SESSION_ID", "286f56fd-c22e-458a-93ac-dfcfb9bb2788");
    const CLAUDE: (&str, &str) = ("CLAUDE_CODE_SESSION_ID", "8e7d0c1a-0b6f-4c55-9d3e-1f2a3b4c5d6e");

    #[test]
    fn explicit_actors_win_over_sessions() {
        let all = [("BD_ACTOR", "alice/w1"), ("BEADS_ACTOR", "bob"), ("BD_SESSION", "s"), COPILOT, CLAUDE];
        assert_eq!(resolve(Some(" carol "), &all), Resolved::new("carol", Source::Flag, "--actor"));
        assert_eq!(resolve(Some("  "), &all), Resolved::new("alice/w1", Source::Env, "$BD_ACTOR"));
        assert_eq!(resolve(None, &all[1..]), Resolved::new("bob", Source::Env, "$BEADS_ACTOR"));
        assert_eq!(resolve(None, &[("BD_ACTOR", " "), ("BEADS_ACTOR", "bob")]).actor, "bob", "blank is unset");
    }

    #[test]
    fn agent_sessions_get_sub_actors_of_the_user() {
        assert_eq!(
            resolve(None, &[COPILOT]),
            Resolved::new("Quang Le/copilot-b9bb2788", Source::Session, "git user.name + $COPILOT_AGENT_SESSION_ID")
        );
        assert_eq!(resolve(None, &[CLAUDE]).actor, "Quang Le/claude-3b4c5d6e");
        assert_eq!(resolve(None, &[("BD_SESSION", "w1"), COPILOT]).actor, "Quang Le/w1");
        assert!(bd_core::policy::is_actor_or_sub_actor("Quang Le", &resolve(None, &[CLAUDE]).actor));
    }

    #[test]
    fn session_precedence_and_determinism() {
        // BD_SESSION, then Claude, Copilot, Codex thread, Codex session.
        let all = [
            ("BD_SESSION", "worker 1"),
            CLAUDE,
            COPILOT,
            ("CODEX_THREAD_ID", "0199a213-81c0-7800-8aa1-bbab2a035a53"),
            ("CODEX_SESSION_ID", "0199a213-81c0-7800-8aa1-000000000001"),
        ];
        let labels: Vec<String> = (0..all.len()).map(|i| session(&with(&all[i..])).unwrap().label).collect();
        assert_eq!(labels, ["worker-1", "claude-3b4c5d6e", "copilot-b9bb2788", "codex-2a035a53", "codex-00000001"]);
        assert_eq!(session(&with(&all)), session(&with(&all)), "the same environment, the same session");
        assert_eq!(session(&with(&[("BD_SESSION", " / ")])), None, "nothing usable");
        assert_eq!(session(&with(&[])), None);
        assert_eq!(resolve(None, &[]), Resolved::new("Quang Le", Source::Default, "git user.name"), "a terminal");
    }

    #[test]
    fn time_ordered_ids_started_together_still_differ() {
        // UUIDv7s minted in the same minute share their first 8 digits.
        let a = short_id("0199a213-81c0-7800-8aa1-bbab2a035a53").unwrap();
        let b = short_id("0199a213-81c1-7f00-9bb2-0c1d2e3f4a5b").unwrap();
        assert_ne!(a, b);
        assert_eq!(short_id("ABC"), Some("abc".into()));
        assert_eq!(short_id("--"), None);
    }

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(sanitize_label("  agent/2\n"), Some("agent-2".into()));
        assert_eq!(sanitize_label(".-x-."), Some("x".into()));
        assert_eq!(sanitize_label(&"y".repeat(100)).unwrap().len(), MAX_LABEL);
        assert_eq!(sanitize_label("über"), Some("ber".into()));
        assert!(is_label("copilot-286f56fd") && is_label("w_1.x"));
        for bad in ["", "a/b", "-a", "a.", "a b", "a\nb", &"z".repeat(65)] {
            assert!(!is_label(bad), "{bad:?}");
        }
    }

    #[test]
    fn hook_input_names_the_session() {
        assert_eq!(hook_session_id(r#"{"session_id":"abc123","source":"startup"}"#), Some("abc123".into()));
        assert_eq!(hook_session_id(r#"{"sessionId":" s-1 "}"#), Some("s-1".into()));
        assert_eq!(hook_session_id(r#"{"session_id":""}"#), None);
        assert_eq!(hook_session_id("not json"), None);
    }
}
