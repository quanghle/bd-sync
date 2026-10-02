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
//!
//! A Claude Code subagent runs its commands with its parent session's
//! environment, `$CLAUDE_CODE_SESSION_ID` included, and nothing in that
//! environment tells it apart: only hook inputs carry its `agent_id`. So
//! `bd hook subagent-start` tells the subagent to pass `--session
//! agent-<id>` (which stands in for `$BD_SESSION`), and `bd hook
//! pre-tool-use` refuses its bd commands that do not.

use std::io::IsTerminal;
use std::process::Command;
use std::sync::OnceLock;

use bd_core::{Error, Result};
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

/// Longest session id `bd hook session-start` writes to `$CLAUDE_ENV_FILE`, in bytes.
pub const MAX_SESSION_ID: usize = 256;

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

/// This process's `--session`, which stands in for `$BD_SESSION`.
static SESSION_FLAG: OnceLock<String> = OnceLock::new();

/// Set this process's `--session` (once, before any command runs; never
/// under `bd serve`, whose requests send their session with the request).
pub fn set_session_flag(name: &str) -> Result<()> {
    let label = sanitize_label(name, MAX_NAME).filter(|l| l == name.trim()).ok_or_else(|| {
        Error::invalid(format!(
            "invalid --session {name:?}: letters, digits, '.', '_' and '-', at most {MAX_NAME} characters"
        ))
    })?;
    let _ = SESSION_FLAG.set(label);
    Ok(())
}

/// A non-empty, trimmed environment variable; for `$BD_SESSION`, this
/// process's `--session` if it has one.
pub fn env(name: &str) -> Option<String> {
    if name == SESSION_VAR {
        if let Some(s) = SESSION_FLAG.get() {
            return Some(s.clone());
        }
    }
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The actor of this process: [`resolve_with`] over the real environment.
/// Under `bd serve` a request's actor is set by the server, never derived
/// from the server's own environment.
pub fn resolve(flag: Option<&str>) -> Resolved {
    if io::in_server_process() {
        return resolve_with(flag, &|_| None, &user_name);
    }
    let mut r = resolve_with(flag, &env, &user_name);
    if r.source == Source::Session && SESSION_FLAG.get().is_some() {
        r.from = r.from.replace(&format!("${SESSION_VAR}"), "--session");
    }
    r
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

/// The user whose sub-actors are the caller's other sessions, when bd
/// derived the caller's actor: the plain user (locally `git user.name` or
/// `$USER`, under `bd serve` the access token's actor), or the user part of
/// an agent session's `<user>/<session>`. `None` for an actor named
/// outright (`--actor`, `$BD_ACTOR`, `$BEADS_ACTOR`): its first segment may
/// name a pool of workers (`pool/w1`) rather than a user, and its siblings
/// are other agents, not sessions of the caller.
pub fn user_root(me: &Resolved) -> Option<&str> {
    match me.source {
        Source::Flag | Source::Env => None,
        Source::Default => Some(&me.actor),
        // A session label has no `/`: what precedes the last one is the user.
        Source::Session => Some(me.actor.rsplit_once('/').map_or(me.actor.as_str(), |(user, _)| user)),
    }
}

/// Whether `holder` is another session of the user the caller acts as (see [`user_root`]).
pub fn other_session_of_user(me: &Resolved, holder: &str) -> bool {
    holder != me.actor && user_root(me).is_some_and(|root| bd_core::policy::is_actor_or_sub_actor(root, holder))
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
    let usable = |id: &String| id.len() <= MAX_SESSION_ID && !id.chars().any(char::is_control);
    let Some(id) = hook_session_id(&input).filter(usable) else {
        io::errln("bd hook session-start: no usable session_id in the hook input; nothing written to $CLAUDE_ENV_FILE");
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

/// The `--session` of a Claude Code subagent: `agent-<last 8 letters and
/// digits of its agent_id>` (Claude Code 2.1.287's are 17 hex digits).
fn subagent_session(agent_id: &str) -> Option<String> {
    short_id(agent_id.strip_prefix("agent-").unwrap_or(agent_id)).map(|id| format!("agent-{id}"))
}

/// A Claude Code subagent, from a hook's JSON input (`agent_id` is present
/// only in hooks that fire inside a subagent).
struct Subagent {
    /// Its `--session`.
    name: String,
    agent_type: Option<String>,
    /// What its bd commands act as without `--session`: the parent session's actor.
    parent: String,
    /// What they act as with it.
    own: String,
}

/// The subagent a hook's input names, unless the hook ran outside one or
/// the actor is named outright (`$BD_ACTOR`, `$BEADS_ACTOR`): then every bd
/// command acts as that actor, which `--session` does not change.
fn subagent(input: &Value) -> Option<Subagent> {
    let field = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.len() <= MAX_SESSION_ID && !v.chars().any(char::is_control))
            .map(String::from)
    };
    let name = field("agent_id").as_deref().and_then(subagent_session)?;
    if env("BD_ACTOR").is_some() || env("BEADS_ACTOR").is_some() {
        return None;
    }
    // The parent's id comes with the input too, for Claude Code versions without it in the environment.
    let session_id = field("session_id");
    let base = |k: &str| if k == CLAUDE_SESSION_VAR { session_id.clone().or_else(|| env(k)) } else { env(k) };
    let user = user_name(&env);
    let user = |_: &Env<'_>| user.clone();
    let parent = resolve_with(None, &base, &user).actor;
    let own = resolve_with(None, &|k: &str| if k == SESSION_VAR { Some(name.clone()) } else { base(k) }, &user).actor;
    Some(Subagent { name, agent_type: field("agent_type"), parent, own })
}

fn hook_input() -> Value {
    let input = if std::io::stdin().is_terminal() { String::new() } else { io::read_stdin().unwrap_or_default() };
    serde_json::from_str(input.trim()).unwrap_or(Value::Null)
}

/// `bd hook subagent-start`: run by Claude Code when it starts (or resumes)
/// a subagent. The subagent's shell commands carry its parent session's
/// id, so its bd commands would act as the parent, able to end the parent's
/// claims by name. Its `agent_id` reaches hooks only, so this hook adds to
/// the subagent's context the `--session` that gives it an actor of its
/// own. Never fails the hook.
pub fn cmd_subagent_start(app: &mut App) -> Result<i32> {
    io::require_local("bd hook subagent-start")?;
    let Some(s) = subagent(&hook_input()) else { return Ok(0) };
    let own = remote_actor(app, &s.own);
    // A placeholder for the token's actor is for the agent to fill in, not a shell word.
    let assignee = if own.starts_with('<') { own.clone() } else { shell_word(&own) };
    let context = format!(
        "bd: you are a subagent{}. Your shell commands carry your parent session's id, so a plain `bd` command \
         acts as your parent, `{}`, and could end its claims. Pass `--session {name}` to every bd command you run \
         (`bd --session {name} claim --next`, `bd --session {name} close <id> --reason \"...\"`): you then act as \
         your own actor, `{own}`. If your parent handed you an issue it claimed, take that claim over once with \
         `bd --session {name} update <id> --assignee {} --take-over` and use the lease token it prints; leave its \
         other claims alone. Close or release what you claimed before you finish.",
        s.agent_type.map(|t| format!(" ({t})")).unwrap_or_default(),
        remote_actor(app, &s.parent),
        assignee,
        name = s.name,
    );
    io::outln(
        serde_json::json!({
            "hookSpecificOutput": { "hookEventName": "SubagentStart", "additionalContext": context }
        })
        .to_string(),
    );
    Ok(0)
}

/// `bd hook pre-tool-use`: run by Claude Code before a Bash command. In a
/// subagent, a command that runs bd without `--session`, `$BD_SESSION` or
/// an actor of its own (`--actor`, `$BD_ACTOR`) would act as the parent
/// session: this denies it, naming the command to run instead. It never
/// rewrites or approves a command, so the permission rules apply as they
/// are. Never fails the hook.
pub fn cmd_pre_tool_use(app: &mut App) -> Result<i32> {
    io::require_local("bd hook pre-tool-use")?;
    let input = hook_input();
    if input.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Ok(0);
    }
    let Some(command) = input.pointer("/tool_input/command").and_then(Value::as_str) else { return Ok(0) };
    let Some(s) = subagent(&input) else { return Ok(0) };
    let unnamed = bd_without_actor(command);
    if unnamed.is_empty() {
        return Ok(0);
    }
    let mut fixed = command.to_string();
    for &at in unnamed.iter().rev() {
        fixed.insert_str(at, &format!(" --session {}", s.name));
    }
    let instead = if fixed.len() <= 400 { format!(": `{fixed}`") } else { String::new() };
    let reason = format!(
        "bd: this subagent's commands carry its parent session's id, so this bd command would act as the parent, \
         `{}`, whose claims are not yours to end. Pass `--session {name}` to every bd command here, which makes you \
         your own actor `{}`{instead}",
        remote_actor(app, &s.parent),
        remote_actor(app, &s.own),
        name = s.name,
    );
    io::outln(
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
        .to_string(),
    );
    Ok(0)
}

/// `actor` as a remote workspace knows it: the access token's actor in place of the local user.
fn remote_actor(app: &App, actor: &str) -> String {
    match (crate::remote::configured(app).ok().flatten().is_some(), actor.rsplit_once('/')) {
        (true, Some((_, label))) => format!("<token actor>/{label}"),
        (true, None) => "<token actor>".into(),
        (false, _) => actor.to_string(),
    }
}

/// Where `command` (a shell command line) runs bd without naming a session
/// or an actor: the byte offset just past each such `bd` word. A rough
/// reading of the shell's grammar: quotes and escapes, command separators,
/// here-documents, leading assignments, and the wrappers in [`WRAPPERS`]
/// with their options. Where it is unsure (a wrapper option it does not
/// know to take a value, `env -S`, a bd run from a script or through
/// `xargs`) it finds nothing, so it never refuses a command that does not
/// run bd.
fn bd_without_actor(command: &str) -> Vec<usize> {
    let words = shell_words(command);
    let names = |w: &str| {
        ["BD_SESSION=", "BD_ACTOR=", "BEADS_ACTOR=", "--session=", "--actor="]
            .iter()
            .any(|p| w.strip_prefix(p).is_some_and(|v| !v.is_empty()))
    };
    // `export BD_SESSION=...` (or an actor) earlier in the line covers what follows.
    if words.iter().any(|w| matches!(w, Token::Word { text, .. } if names(text))) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for segment in words.split(|t| matches!(t, Token::Sep)) {
        let word = |i: usize| match segment.get(i) {
            Some(Token::Word { text, .. }) => Some(text.as_str()),
            _ => None,
        };
        let named =
            (0..segment.len()).any(|i| matches!(word(i), Some("--session" | "--actor")) && word(i + 1).is_some());
        let mut bd = None;
        let mut at_command = true;
        let mut i = 0;
        while i < segment.len() {
            let Token::Word { text, end } = &segment[i] else {
                at_command = true;
                i += 1;
                continue;
            };
            if !at_command {
                i += 1;
                continue;
            }
            match command_word(&word, i) {
                Step::Skip(n) => i += n,
                Step::Unsure => break,
                Step::Command => {
                    at_command = false;
                    let program = text.rsplit(['/', '\\']).next().unwrap_or(text);
                    if bd.is_none() && matches!(program, "bd" | "bd.exe") {
                        bd = Some(*end);
                    }
                    i += 1;
                }
            }
        }
        if let (Some(end), false) = (bd, named) {
            found.push(end);
        }
    }
    found
}

/// What a word in command position is.
enum Step {
    /// Not the command: an assignment, a keyword, or a wrapper with its
    /// options and arguments, this many words; the command comes after.
    Skip(usize),
    /// Not a command run, or a form not understood: nothing to check here.
    Unsure,
    /// The command.
    Command,
}

/// A command that runs the command after its options: its name, the short
/// and long options that take a value, the short and long options after
/// which it does not run one (or that are not understood), and how many
/// arguments come before the command.
struct Wrapper {
    name: &'static str,
    short_values: &'static str,
    long_values: &'static [&'static str],
    short_unsure: &'static str,
    long_unsure: &'static [&'static str],
    arguments: usize,
}

const fn wrapper(name: &'static str) -> Wrapper {
    Wrapper { name, short_values: "", long_values: &[], short_unsure: "", long_unsure: &[], arguments: 0 }
}

/// Wrappers Claude Code also looks through when it matches a rule like `Bash(bd *)`.
const WRAPPERS: &[Wrapper] = &[
    Wrapper { short_unsure: "vV", ..wrapper("command") },
    Wrapper {
        short_values: "uC",
        long_values: &["--unset", "--chdir"],
        short_unsure: "S",
        long_unsure: &["--split-string"],
        ..wrapper("env")
    },
    Wrapper {
        short_values: "ugCDRTpUrth",
        long_values: &[
            "--user",
            "--group",
            "--close-from",
            "--chdir",
            "--chroot",
            "--command-timeout",
            "--prompt",
            "--other-user",
            "--role",
            "--type",
            "--host",
        ],
        short_unsure: "lveVK",
        long_unsure: &["--list", "--validate", "--edit", "--version", "--remove-timestamp"],
        ..wrapper("sudo")
    },
    Wrapper { short_values: "n", long_values: &["--adjustment"], ..wrapper("nice") },
    Wrapper { short_values: "sk", long_values: &["--signal", "--kill-after"], arguments: 1, ..wrapper("timeout") },
    Wrapper { short_values: "ioe", long_values: &["--input", "--output", "--error"], ..wrapper("stdbuf") },
    Wrapper { short_values: "a", ..wrapper("exec") },
    wrapper("nohup"),
    wrapper("builtin"),
    wrapper("time"),
];

/// What the word `i` of a command (`word(i)`), in command position, is.
fn command_word<'a>(word: &dyn Fn(usize) -> Option<&'a str>, i: usize) -> Step {
    let Some(text) = word(i) else { return Step::Command };
    let assignment = text.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    });
    const KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"];
    if assignment || KEYWORDS.contains(&text) {
        return Step::Skip(1);
    }
    let Some(w) = WRAPPERS.iter().find(|w| w.name == text) else { return Step::Command };
    let mut n = 1;
    while let Some(arg) = word(i + n) {
        if arg == "--" {
            n += 1;
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            break;
        }
        n += 1;
        if let Some(long) = arg.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(long));
            if w.long_unsure.contains(&name.as_str()) {
                return Step::Unsure;
            }
            if w.long_values.contains(&name.as_str()) && !long.contains('=') {
                n += 1;
            }
            continue;
        }
        // Short options, combined (`-Eu root`) or with the value attached (`-n5`).
        for (k, c) in arg[1..].char_indices() {
            if w.short_unsure.contains(c) {
                return Step::Unsure;
            }
            if w.short_values.contains(c) {
                if k + c.len_utf8() == arg.len() - 1 {
                    n += 1;
                }
                break;
            }
        }
    }
    n += w.arguments;
    if word(i + n - 1).is_none() { Step::Unsure } else { Step::Skip(n) }
}

#[derive(Debug, PartialEq)]
enum Token {
    /// A word, unquoted, and the byte offset just past it.
    Word { text: String, end: usize },
    /// Where a new command starts within the same command list: `(`, `$(`, a backtick.
    Sub,
    /// Between command lists: `;`, `&`, `|`, a newline.
    Sep,
}

/// `command` split into words and separators, roughly as a POSIX shell
/// would; `#` comments and here-document bodies are dropped.
fn shell_words(command: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word: Option<String> = None;
    let mut quote: Option<char> = None;
    // Here-documents whose bodies start after this line: their terminator, and whether `<<-` strips tabs.
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut chars = command.char_indices().peekable();
    let finish = |word: &mut Option<String>, tokens: &mut Vec<Token>, end: usize| {
        if let Some(text) = word.take() {
            tokens.push(Token::Word { text, end });
        }
    };
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"'), '\\') => {
                if let Some((_, n)) = chars.next() {
                    word.get_or_insert_default().push(n);
                }
            }
            (Some(_), c) => word.get_or_insert_default().push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (None, '\\') => match chars.next() {
                Some((_, '\n')) => {}
                Some((_, n)) => word.get_or_insert_default().push(n),
                None => {}
            },
            (None, '#') if word.is_none() => while chars.next_if(|&(_, n)| n != '\n').is_some() {},
            (None, '\n') => {
                finish(&mut word, &mut tokens, i);
                tokens.push(Token::Sep);
                for (end, strip_tabs) in heredocs.drain(..) {
                    loop {
                        let mut line = String::new();
                        while let Some((_, n)) = chars.next_if(|&(_, n)| n != '\n') {
                            line.push(n);
                        }
                        let last = chars.next().is_none();
                        let line = if strip_tabs { line.trim_start_matches('\t') } else { &line };
                        if line == end || last {
                            break;
                        }
                    }
                }
            }
            (None, ';' | '&' | '|') => {
                finish(&mut word, &mut tokens, i);
                tokens.push(Token::Sep);
            }
            (None, '(' | ')' | '`') => {
                // `$(`: the `$` belongs to the substitution, not to a word.
                if word.as_deref() == Some("$") {
                    word = None;
                } else if let Some(w) = word.as_mut().filter(|w| w.ends_with('$') && c == '(') {
                    w.pop();
                }
                finish(&mut word, &mut tokens, i);
                tokens.push(Token::Sub);
            }
            (None, '<') if chars.peek().is_some_and(|&(_, n)| n == '<') => {
                finish(&mut word, &mut tokens, i);
                chars.next();
                // `<<<` is a here-string: its word is an argument.
                if chars.next_if(|&(_, n)| n == '<').is_none() {
                    let strip_tabs = chars.next_if(|&(_, n)| n == '-').is_some();
                    while chars.next_if(|&(_, n)| n == ' ' || n == '\t').is_some() {}
                    heredocs.push((heredoc_end(&mut chars), strip_tabs));
                }
            }
            (None, '<' | '>') => finish(&mut word, &mut tokens, i),
            (None, c) if c.is_whitespace() => finish(&mut word, &mut tokens, i),
            (None, c) => word.get_or_insert_default().push(c),
        }
    }
    finish(&mut word, &mut tokens, command.len());
    tokens
}

/// The terminator word of a here-document (`<<EOF`, `<<'EOF'`, `<<"E"OF`), quotes removed.
fn heredoc_end(chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>) -> String {
    let mut end = String::new();
    while let Some((_, c)) = chars.next_if(|&(_, c)| !c.is_whitespace() && !";&|<>()".contains(c)) {
        match c {
            '\'' | '"' => {
                while let Some((_, n)) = chars.next_if(|&(_, n)| n != c) {
                    end.push(n);
                }
                chars.next();
            }
            '\\' => {
                if let Some((_, n)) = chars.next() {
                    end.push(n);
                }
            }
            c => end.push(c),
        }
    }
    end
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
        let session = |a: &str| Resolved::new(a, Source::Session, "git user.name + $COPILOT_AGENT_SESSION_ID");
        let user = |a: &str| Resolved::new(a, Source::Default, "git user.name");
        assert!(other_session_of_user(&session("Quang Le/copilot-1"), "Quang Le"));
        assert!(other_session_of_user(&session("Quang Le/copilot-1"), "Quang Le/claude-2"));
        assert!(other_session_of_user(&user("Quang Le"), "Quang Le/claude-2"));
        assert!(!other_session_of_user(&session("Quang Le/copilot-1"), "Quang Le/copilot-1"), "itself");
        assert!(!other_session_of_user(&session("Quang Le/copilot-1"), "Quang Lee/x"));
        assert!(!other_session_of_user(&user("alice"), "bob/alice"));
        // A user name with a `/` keeps it: the session is only the last segment.
        assert!(other_session_of_user(&session("org/alice/claude-1"), "org/alice/claude-2"));
        assert!(!other_session_of_user(&session("org/alice/claude-1"), "org/bob"));
        assert!(!other_session_of_user(&user("org/alice"), "org/bob"));
    }

    #[test]
    fn actors_named_outright_have_no_other_sessions() {
        // `pool/w2` is another worker of the pool, not a session of `pool/w1`.
        for source in [Source::Flag, Source::Env] {
            let me = Resolved::new("pool/w1", source, "$BD_ACTOR");
            assert_eq!(user_root(&me), None);
            for holder in ["pool/w2", "pool", "pool/w1/x"] {
                assert!(!other_session_of_user(&me, holder), "{source:?} {holder}");
            }
        }
    }

    #[test]
    fn subagents_get_a_session_of_their_own() {
        assert_eq!(subagent_session("acfc95cf1792257ed").as_deref(), Some("agent-792257ed"));
        assert_eq!(subagent_session("agent-abc123").as_deref(), Some("agent-abc123"), "the docs' example");
        assert_eq!(subagent_session("--"), None);
        let child = resolve(None, &[CLAUDE, (SESSION_VAR, "agent-792257ed")]).actor;
        assert_eq!(child, "Quang Le/claude-3b4c5d6e.agent-792257ed");
        assert!(other_session_of_user(&resolve(None, &[CLAUDE]), &child), "its parent may take it over");
    }

    /// The commands [`bd_without_actor`] flags, with ` --session X` inserted where it would go.
    fn flagged(command: &str) -> String {
        let mut fixed = command.to_string();
        for at in bd_without_actor(command).into_iter().rev() {
            fixed.insert_str(at, " --session X");
        }
        fixed
    }

    #[test]
    fn bd_commands_without_a_session_are_found() {
        for (command, fixed) in [
            ("bd claim --next", "bd --session X claim --next"),
            ("bd", "bd --session X"),
            ("cd /w && bd close t-1 --reason 'done; ok'", "cd /w && bd --session X close t-1 --reason 'done; ok'"),
            ("FOO=1 ~/.cargo/bin/bd ready | head", "FOO=1 ~/.cargo/bin/bd --session X ready | head"),
            ("bd ready; bd show t-1 --session X", "bd --session X ready; bd show t-1 --session X"),
            ("echo $(bd ready -q)", "echo $(bd --session X ready -q)"),
            (
                "if true; then sudo -E bd list
fi",
                "if true; then sudo -E bd --session X list
fi",
            ),
            ("\"bd\" show t-1", "\"bd\" --session X show t-1"),
            ("bd.exe show t-1>out", "bd.exe --session X show t-1>out"),
        ] {
            assert_eq!(flagged(command), fixed, "{command}");
        }
        for command in [
            "bd --session agent-1 claim --next",
            "bd claim --next --session=agent-1",
            "BD_SESSION=agent-1 bd claim --next",
            "export BD_SESSION=agent-1; bd ready && bd claim t-1",
            "bd --actor me close t-1",
            "BD_ACTOR=me bd close t-1",
            "echo bd ready",
            "git commit -m 'bd close; bd claim'",
            "grep -r \"bd ready\" .",
            "ls bd/ # bd ready",
            "cargo build && ./target/release/bdx ready",
            "rg bd",
        ] {
            assert_eq!(bd_without_actor(command), Vec::<usize>::new(), "{command}");
        }
    }

    #[test]
    fn here_documents_are_text_not_commands() {
        let note = "bd --session agent-792257ed comment add t-1 --stdin <<'EOF'\nHandoff: tests pass.\nbd ready lists t-2 next.\nEOF";
        for command in [
            note,
            "cat > notes.md <<EOF\nbd close t-1\nEOF",
            "cat <<\"E\"OF\nbd close t-1\nEOF\necho done",
            "cat <<-EOF\n\tbd close t-1\n\tEOF",
            "cat <<A <<B\nbd x\nA\nbd y\nB",
            "cat <<EOF\nbd close t-1",
        ] {
            assert_eq!(bd_without_actor(command), Vec::<usize>::new(), "{command:?}");
        }
        // The command after a here-document, or on its line, still counts; `<<<` is a here-string.
        for (command, fixed) in [
            ("cat <<EOF\nbd x\nEOF\nbd close t-1", "cat <<EOF\nbd x\nEOF\nbd --session X close t-1"),
            ("bd comment add t-1 --stdin <<EOF\nbd x\nEOF", "bd --session X comment add t-1 --stdin <<EOF\nbd x\nEOF"),
            ("cat <<-EOF\n\tx\n\tEOF\nbd ready", "cat <<-EOF\n\tx\n\tEOF\nbd --session X ready"),
            ("bd batch <<< 'close t-1'", "bd --session X batch <<< 'close t-1'"),
        ] {
            assert_eq!(flagged(command), fixed, "{command:?}");
        }
    }

    #[test]
    fn wrappers_are_looked_through_with_their_options() {
        for (command, fixed) in [
            ("timeout 30 bd close t-1", "timeout 30 bd --session X close t-1"),
            ("timeout -s KILL -k 5 30s bd close t-1", "timeout -s KILL -k 5 30s bd --session X close t-1"),
            ("timeout --signal=TERM 1m bd ready", "timeout --signal=TERM 1m bd --session X ready"),
            ("nice -n 5 bd close t-1", "nice -n 5 bd --session X close t-1"),
            ("nice -n5 bd ready", "nice -n5 bd --session X ready"),
            ("nice --adjustment 5 bd ready", "nice --adjustment 5 bd --session X ready"),
            ("env -u FOO bd ready", "env -u FOO bd --session X ready"),
            ("env -i -C /w FOO=1 bd ready", "env -i -C /w FOO=1 bd --session X ready"),
            ("sudo -u root bd ready", "sudo -u root bd --session X ready"),
            ("sudo -Eu root -- bd ready", "sudo -Eu root -- bd --session X ready"),
            ("stdbuf -o L -eL bd ready", "stdbuf -o L -eL bd --session X ready"),
            ("nohup time -p bd ready", "nohup time -p bd --session X ready"),
            ("command bd close t-1", "command bd --session X close t-1"),
            ("exec -a name bd ready", "exec -a name bd --session X ready"),
        ] {
            assert_eq!(flagged(command), fixed, "{command}");
        }
        for command in [
            "command -v bd",
            "command -V bd",
            "if command -v bd >/dev/null; then echo ok; fi",
            "sudo -u bd whoami",
            "sudo -g bd id",
            "env -u bd printenv",
            "timeout 30 cargo test",
            "timeout -k bd 5 true",
            "nice -n 5 make",
            "stdbuf -o bd cat",
            "env -S 'bd ready'",
            "sudo -l bd",
            "sudo -u",
        ] {
            assert_eq!(bd_without_actor(command), Vec::<usize>::new(), "{command}");
        }
    }
}
