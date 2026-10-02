//! Who a command acts as.
//!
//! `--actor`, then `$BD_ACTOR`, then `$BEADS_ACTOR` name the actor outright.
//! Otherwise it is the user (`git config user.name`, then `$USER`,
//! `$USERNAME`), and inside an agent session the sub-actor
//! `<user>/<session>`: every session gets its own actor, so concurrent
//! sessions of one user never share claims, while a terminal without a
//! session keeps the plain user. The session comes from the session id an
//! agent harness gives every shell command it runs ([`HARNESSES`]), and
//! `$BD_SESSION`; it stays the same for every command of the session.
//!
//! Environment variables are inherited: an agent started from another
//! agent's shell (a coordinator running `claude -p` workers, Codex run from
//! Claude Code) sees its parent's variables too. A harness sets its own
//! variable afresh for its commands, so a nested session of the same
//! harness has its own id; one of another harness keeps the outer id as
//! well. The label therefore joins every harness's id (`claude-<id>.codex-<id>`):
//! the nested session differs from its parent and from its siblings, without
//! guessing which harness is the innermost. `$BD_SESSION`, which any shell
//! may have exported, only ever adds to it.

use std::io::IsTerminal;
use std::process::Command;

use bd_core::Result;
use serde::Serialize;
use serde_json::Value;

use crate::app::App;
use crate::io;

/// Names a session explicitly, for scripts and harnesses bd does not know:
/// bd acts as `<user>/<BD_SESSION>` (inside a known agent session, as
/// `<user>/<harness session>.<BD_SESSION>`).
pub const SESSION_VAR: &str = "BD_SESSION";

/// Claude Code's session id variable, which `bd hook session-start` also
/// exports for Claude Code versions that do not set it.
pub const CLAUDE_SESSION_VAR: &str = "CLAUDE_CODE_SESSION_ID";

/// Agent harnesses, by label prefix, with the variables holding the session
/// id they set in the environment of the shell commands they run (the
/// first one set counts): the harness's part of the label is
/// `<prefix>-<last 8 letters and digits of the id>`.
pub const HARNESSES: &[(&str, &[&str])] = &[
    // Claude Code 2.1.132+: Bash tool and hook subprocesses; changes on /clear.
    ("claude", &[CLAUDE_SESSION_VAR]),
    // Copilot CLI 1.0.29+: shell commands and MCP servers.
    ("copilot", &["COPILOT_AGENT_SESSION_ID"]),
    // Codex: the thread (each subagent has its own), then the root session.
    ("codex", &["CODEX_THREAD_ID", "CODEX_SESSION_ID"]),
];

/// Longest `$BD_SESSION` part of a label.
pub const MAX_NAME: usize = 64;
/// Longest session label (harness ids and a `$BD_SESSION` name).
pub const MAX_LABEL: usize = 128;

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

/// An agent session's label, and the variables it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub label: String,
    pub vars: Vec<&'static str>,
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
        Some(s) => {
            let vars: Vec<String> = s.vars.iter().map(|v| format!("${v}")).collect();
            Resolved::new(format!("{name}/{}", s.label), Source::Session, format!("{from} + {}", vars.join(" + ")))
        }
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

/// The agent session `env` names: the id of every harness in
/// [`HARNESSES`] that set one, in that order, then `$BD_SESSION`, joined
/// with `.`; `None` without any.
pub fn session(env: &Env<'_>) -> Option<Session> {
    let mut parts = Vec::new();
    let mut vars = Vec::new();
    for &(prefix, names) in HARNESSES {
        if let Some((var, id)) = names.iter().find_map(|&v| Some((v, short_id(&env(v)?)?))) {
            parts.push(format!("{prefix}-{id}"));
            vars.push(var);
        }
    }
    if let Some(name) = env(SESSION_VAR).and_then(|v| sanitize_label(&v, MAX_NAME)) {
        parts.push(name);
        vars.push(SESSION_VAR);
    }
    (!parts.is_empty()).then(|| Session { label: parts.join("."), vars })
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
/// `max` characters.
pub fn sanitize_label(s: &str, max: usize) -> Option<String> {
    let mapped: String = s
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_') { c } else { '-' })
        .take(max)
        .collect();
    let label = mapped.trim_matches(|c| c == '-' || c == '.');
    (!label.is_empty()).then(|| label.to_string())
}

/// Whether `s` is a session label as [`session`] makes them.
pub fn is_label(s: &str) -> bool {
    sanitize_label(s, MAX_LABEL).as_deref() == Some(s)
}

/// The user an actor belongs to, whose sub-actors are that user's other
/// sessions: under `bd serve` the access token's actor, else the actor's
/// first `/` segment.
pub fn user_root(actor: &str) -> String {
    match io::policy() {
        Some(p) if bd_core::policy::is_actor_or_sub_actor(&p.actor, actor) => p.actor,
        _ => actor.split('/').next().unwrap_or(actor).to_string(),
    }
}

/// Whether `holder` is another session of the user `actor` belongs to.
pub fn other_session_of_user(actor: &str, holder: &str) -> bool {
    holder != actor && bd_core::policy::is_actor_or_sub_actor(&user_root(actor), holder)
}

/// `s` as one shell word.
pub fn shell_word(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command that takes `id`'s claim over for `actor`.
pub fn take_over_command(id: &str, actor: &str) -> String {
    format!("bd update {id} --assignee {} --take-over", shell_word(actor))
}

/// `bd hook session-start`: run by an agent harness when a session starts.
/// Claude Code gives SessionStart hooks `$CLAUDE_ENV_FILE`, a script its
/// later Bash commands source: this appends `export
/// CLAUDE_CODE_SESSION_ID=<id>` to it, with the id from the hook's JSON
/// input, so that every bd command of the session acts as the same
/// sub-actor even where Claude Code does not set that variable itself
/// (before 2.1.132). It always writes the session's own id, never one
/// inherited from the environment, so a session started from another
/// session's shell does not act as its parent. Never fails the hook: a
/// problem is a warning on stderr.
pub fn cmd_session_start(_app: &mut App) -> Result<i32> {
    io::require_local("bd hook session-start")?;
    let Some(file) = env("CLAUDE_ENV_FILE") else { return Ok(0) };
    let input = if std::io::stdin().is_terminal() { String::new() } else { io::read_stdin().unwrap_or_default() };
    let Some(id) = hook_session_id(&input).filter(|id| !id.chars().any(char::is_control)) else {
        io::errln("bd hook session-start: no session_id in the hook input; nothing written to $CLAUDE_ENV_FILE");
        return Ok(0);
    };
    if let Err(e) = append_export(std::path::Path::new(&file), CLAUDE_SESSION_VAR, &id) {
        io::errln(format!("bd hook session-start: cannot write {file}: {e}"));
        return Ok(0);
    }
    if env("BD_ACTOR").is_none() && env("BEADS_ACTOR").is_none() {
        let own = |v: &str| if v == CLAUDE_SESSION_VAR { Some(id.clone()) } else { env(v) };
        if let Some(s) = session(&own) {
            io::outln(format!("bd: this session's bd commands act as their own actor, `<you>/{}`.", s.label));
        }
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
    writeln!(f, "export {var}={}", shell_word(value))
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
        assert_eq!(resolve(None, &[("BD_SESSION", "w1")]).actor, "Quang Le/w1", "a harness bd does not know");
        assert_eq!(
            resolve(None, &[("BD_SESSION", "w1"), COPILOT]),
            Resolved::new(
                "Quang Le/copilot-b9bb2788.w1",
                Source::Session,
                "git user.name + $COPILOT_AGENT_SESSION_ID + $BD_SESSION"
            ),
            "BD_SESSION only adds to the harness's session"
        );
        assert!(bd_core::policy::is_actor_or_sub_actor("Quang Le", &resolve(None, &[CLAUDE]).actor));
    }

    #[test]
    fn sessions_join_every_harness_and_stay_deterministic() {
        let thread = ("CODEX_THREAD_ID", "0199a213-81c0-7800-8aa1-bbab2a035a53");
        let codex_session = ("CODEX_SESSION_ID", "0199a213-81c0-7800-8aa1-000000000001");
        let all = [CLAUDE, COPILOT, thread, codex_session, ("BD_SESSION", "worker 1")];
        let s = session(&with(&all)).unwrap();
        assert_eq!(s.label, "claude-3b4c5d6e.copilot-b9bb2788.codex-2a035a53.worker-1");
        assert_eq!(s.vars, ["CLAUDE_CODE_SESSION_ID", "COPILOT_AGENT_SESSION_ID", "CODEX_THREAD_ID", "BD_SESSION"]);
        assert!(is_label(&s.label), "a server accepts it");
        assert_eq!(session(&with(&[codex_session])).unwrap().label, "codex-00000001", "no thread: the session");
        assert_eq!(session(&with(&all)), session(&with(&all)), "the same environment, the same session");
        assert_eq!(session(&with(&[("BD_SESSION", " / ")])), None, "nothing usable");
        assert_eq!(session(&with(&[])), None);
        assert_eq!(resolve(None, &[]), Resolved::new("Quang Le", Source::Default, "git user.name"), "a terminal");
    }

    #[test]
    fn nested_sessions_never_act_as_their_parent() {
        // A `claude -p` worker started from a coordinator's shell that exported
        // BD_SESSION: the worker's own session id still tells them apart.
        let parent = resolve(None, &[("BD_SESSION", "claude-parent")]).actor;
        let child = resolve(None, &[("BD_SESSION", "claude-parent"), (CLAUDE.0, "child-0001")]).actor;
        assert_ne!(parent, child);
        assert_eq!(child, "Quang Le/claude-hild0001.claude-parent");
        // Codex (or Copilot) started from a Claude Code shell inherits Claude's id
        // and has its own: it differs from the Claude session and from its siblings.
        let claude = resolve(None, &[(CLAUDE.0, "aaaa-1111")]).actor;
        let codex = resolve(None, &[(CLAUDE.0, "aaaa-1111"), ("CODEX_THREAD_ID", "zzzz-9999")]).actor;
        let sibling = resolve(None, &[(CLAUDE.0, "aaaa-1111"), ("CODEX_THREAD_ID", "yyyy-8888")]).actor;
        assert_eq!(claude, "Quang Le/claude-aaaa1111");
        assert_eq!(codex, "Quang Le/claude-aaaa1111.codex-zzzz9999");
        assert!(claude != codex && codex != sibling && claude != sibling);
        // Claude Code inside Copilot CLI, and Copilot CLI inside Claude Code, too.
        let nested = resolve(None, &[COPILOT, CLAUDE]).actor;
        assert!(nested != resolve(None, &[COPILOT]).actor && nested != resolve(None, &[CLAUDE]).actor);
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
        assert_eq!(sanitize_label("  agent/2\n", MAX_NAME), Some("agent-2".into()));
        assert_eq!(sanitize_label(".-x-.", MAX_NAME), Some("x".into()));
        assert_eq!(sanitize_label(&"y".repeat(200), MAX_NAME).unwrap().len(), MAX_NAME);
        assert_eq!(sanitize_label("über", MAX_NAME), Some("ber".into()));
        assert!(is_label("copilot-286f56fd") && is_label("w_1.x") && is_label(&"z".repeat(MAX_LABEL)));
        for bad in ["", "a/b", "-a", "a.", "a b", "a\nb", &"z".repeat(MAX_LABEL + 1)] {
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

    #[test]
    fn takeover_commands_quote_the_actor() {
        assert_eq!(shell_word("alice/copilot-1"), "alice/copilot-1");
        assert_eq!(shell_word("Quang Le/x"), "'Quang Le/x'");
        assert_eq!(shell_word("O'Brien"), "'O'\\''Brien'");
        assert_eq!(take_over_command("t-1", "Quang Le/c"), "bd update t-1 --assignee 'Quang Le/c' --take-over");
    }

    #[test]
    fn other_sessions_share_the_users_root() {
        assert!(other_session_of_user("Quang Le/copilot-1", "Quang Le"));
        assert!(other_session_of_user("Quang Le/copilot-1", "Quang Le/claude-2"));
        assert!(other_session_of_user("Quang Le", "Quang Le/claude-2"));
        assert!(!other_session_of_user("Quang Le/copilot-1", "Quang Le/copilot-1"), "itself");
        assert!(!other_session_of_user("Quang Le/copilot-1", "Quang Lee/x"));
        assert!(!other_session_of_user("alice", "bob/alice"));
    }
}
