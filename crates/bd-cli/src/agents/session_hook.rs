//! The session-start hook a pull puts in a checkout, so that the harness's
//! sessions there run `bd hook session-start` and `bd prime`: without it, an
//! agent in a fresh checkout has no way to learn that bd tracks its work.
//! `bd setup` writes its hooks through the same functions ([`ensure_entries`],
//! [`remove_entries`]), Claude Code's SubagentStart and PreToolUse ones too.
//!
//! The hook is bd's own, the same for every checkout, and never comes from
//! the server: a server can no more add hooks this way than through its
//! sets. It goes where the harness reads project hooks, merged into what the
//! file holds (each harness runs the hooks of all its sources):
//!
//! | harness   | file                          | entries                                                  |
//! |-----------|-------------------------------|----------------------------------------------------------|
//! | `claude`  | `.claude/settings.local.json` | `bd hook session-start --harness claude`, `bd prime --hook claude` |
//! | `codex`   | `.codex/hooks.json`           | `bd hook session-start --harness codex`, `bd prime --hook codex` |
//! | `copilot` | `.github/hooks/bd.json`       | `bd hook session-start --harness copilot`, `bd prime --hook copilot` |
//!
//! Claude Code and Codex run these hooks again after compacting a
//! conversation (SessionStart with source `compact`: Claude Code's entry has
//! no matcher, Codex's names `compact`), which gives the session its bd
//! context back.
//!
//! Nothing is written when a bd session-start hook for the harness is
//! already configured, in the checkout or for the user ([`configured`]):
//! the plugin's (Copilot CLI's installed plugins, Claude Code's plugin
//! cache), say, or one written by hand. A target file bd cannot merge
//! into (not a JSON object, hooks not where the harness keeps them, a
//! symlink) is a conflict, reported and left alone.

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use bd_core::agents::{Harness, under};
use bd_core::{Error, Result};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::checkout::{Checkout, write_atomically};

/// What a pull did, or would do, about the harness's session-start hook.
#[derive(Debug, Serialize)]
pub struct HookReport {
    /// Where the hook is (a checkout-relative path, or an absolute one
    /// outside it), or goes.
    pub file: String,
    pub state: HookState,
    /// Why a conflict was left alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HookState {
    /// Already configured: nothing to do.
    Present,
    /// Written (pull), or to write (status).
    Added,
    /// The target file is in the way.
    Conflict,
    /// bd's text in the file replaced by the current one (`bd setup`).
    Updated,
    /// bd's entries taken out of the file (`bd setup --remove`).
    Removed,
    /// Nothing of bd's in the file to remove (`bd setup --remove`).
    Absent,
}

/// What [`ensure_entries`] or [`remove_entries`] did, or would do.
#[derive(Debug)]
pub struct Outcome {
    pub report: HookReport,
    /// The events whose hooks were added or removed.
    pub events: Vec<&'static str>,
}

/// The file bd writes the harness's hook to, relative to the checkout.
pub fn target(h: Harness) -> &'static str {
    match h {
        Harness::Claude => ".claude/settings.local.json",
        Harness::Codex => ".codex/hooks.json",
        Harness::Copilot => ".github/hooks/bd.json",
    }
}

/// The event key the harness's hooks go under in [`target`].
fn event(h: Harness) -> &'static str {
    match h {
        Harness::Claude | Harness::Codex => "SessionStart",
        Harness::Copilot => "sessionStart",
    }
}

/// The items bd appends to `hooks.<event>` in [`target`].
pub(crate) fn items(h: Harness) -> Vec<Value> {
    let cmd = |c: &str| json!({ "type": "command", "command": c });
    match h {
        Harness::Claude => {
            vec![json!({ "hooks": [cmd("bd hook session-start --harness claude"), cmd("bd prime --hook claude")] })]
        }
        Harness::Codex => {
            let timed = |c: &str| json!({ "type": "command", "command": c, "timeout": 30 });
            vec![json!({
                "matcher": "startup|resume|clear|compact",
                "hooks": [timed("bd hook session-start --harness codex"), timed("bd prime --hook codex")],
            })]
        }
        Harness::Copilot => vec![cmd("bd hook session-start --harness copilot"), cmd("bd prime --hook copilot")],
    }
}

/// One of bd's hook commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BdHook {
    /// `bd hook session-start` for the harness (one naming none counts too).
    SessionStart(Harness),
    /// `bd hook subagent-start` (Claude Code).
    SubagentStart,
    /// `bd hook pre-tool-use` (Claude Code).
    PreToolUse,
}

/// Hook items bd adds under one event of a hook file.
pub struct Entry {
    pub event: &'static str,
    /// The hook that tells whether the event is configured already.
    pub kind: BdHook,
    pub items: Vec<Value>,
}

/// The harness's session-start entry, as a pull adds it to [`target`].
pub fn session_entries(h: Harness) -> Vec<Entry> {
    vec![Entry { event: event(h), kind: BdHook::SessionStart(h), items: items(h) }]
}

/// The hooks of this repository's `.claude/settings.json`, which `bd setup
/// claude` writes there: session start (with `bd prime`), and the subagent
/// hooks giving subagents actors of their own.
pub fn claude_project_entries() -> Vec<Entry> {
    let mut entries = session_entries(Harness::Claude);
    entries.push(Entry {
        event: "SubagentStart",
        kind: BdHook::SubagentStart,
        items: vec![json!({ "hooks": [{ "type": "command", "command": "bd hook subagent-start || true" }] })],
    });
    entries.push(Entry {
        event: "PreToolUse",
        kind: BdHook::PreToolUse,
        items: vec![json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "if": "Bash(bd *)", "command": "bd hook pre-tool-use || true" }],
        })],
    });
    entries
}

/// Whether `command` runs bd's hook `kind`; a session-start one naming no
/// harness counts for every harness, as it takes the session's.
fn runs_bd_hook(command: &str, kind: BdHook) -> bool {
    let sub = match kind {
        BdHook::SessionStart(_) => "session-start",
        BdHook::SubagentStart => "subagent-start",
        BdHook::PreToolUse => "pre-tool-use",
    };
    let words: Vec<&str> = command.split_whitespace().collect();
    let Some(at) = words.windows(3).position(|w| is_bd(w[0]) && w[1] == "hook" && w[2] == sub) else {
        return false;
    };
    let BdHook::SessionStart(h) = kind else { return true };
    let rest = &words[at + 3..];
    match rest.iter().position(|w| *w == "--harness" || w.starts_with("--harness=")) {
        None => true,
        Some(i) => match rest[i].strip_prefix("--harness=") {
            Some(v) => v == h.name(),
            None => rest.get(i + 1) == Some(&h.name()),
        },
    }
}

/// Whether `command` runs bd's session-start hook for `h`.
#[cfg(test)]
fn runs_hook(command: &str, h: Harness) -> bool {
    runs_bd_hook(command, BdHook::SessionStart(h))
}

/// Whether `program` is bd, by name or path.
fn is_bd(program: &str) -> bool {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    name == "bd" || name.eq_ignore_ascii_case("bd.exe")
}

/// Whether any string in `v` is a command running bd's hook `kind`.
fn holds_bd_hook(v: &Value, kind: BdHook) -> bool {
    match v {
        Value::String(s) => runs_bd_hook(s, kind),
        Value::Array(a) => a.iter().any(|v| holds_bd_hook(v, kind)),
        Value::Object(m) => m.values().any(|v| holds_bd_hook(v, kind)),
        _ => false,
    }
}

/// Whether any string in `v` is a command running bd's hook for `h`.
#[cfg(test)]
fn holds_hook(v: &Value, h: Harness) -> bool {
    holds_bd_hook(v, BdHook::SessionStart(h))
}

/// The user's configuration directories of the harnesses, where their
/// user-level hooks are.
pub struct Homes {
    /// `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    pub claude: Option<PathBuf>,
    /// `$CODEX_HOME`, else `~/.codex`.
    pub codex: Option<PathBuf>,
    /// `$COPILOT_HOME`, else `~/.copilot`.
    pub copilot: Option<PathBuf>,
}

impl Homes {
    pub fn from_env() -> Homes {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        // As the harnesses find it: Node's os.homedir() and Codex ignore HOME on Windows.
        let home = if cfg!(windows) { var("USERPROFILE") } else { var("HOME") };
        let dir = |env: &str, name: &str| var(env).or_else(|| home.as_ref().map(|h| h.join(name)));
        Homes {
            claude: dir("CLAUDE_CONFIG_DIR", ".claude"),
            codex: dir("CODEX_HOME", ".codex"),
            copilot: dir("COPILOT_HOME", ".copilot"),
        }
    }
}

/// The `.json` files in `dir`, sorted.
fn json_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect())
        .unwrap_or_default();
    files.sort();
    files
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default();
    dirs.sort();
    dirs
}

/// Where [`configured_hook`] looks for a hook already configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sources {
    /// Every file the harness reads hooks from ([`hook_files`]).
    All,
    /// The target file itself and installed plugins only: for Claude Code's
    /// shared settings, as Claude Code runs a handler once across settings
    /// files but a plugin's copy separately.
    TargetAndPlugins,
}

/// The files the harness reads hooks from: the checkout's (`root`), then
/// the user's, then the manifests and hook files of installed plugins
/// ([`plugin_files`]).
fn hook_files(root: &Path, h: Harness, homes: &Homes) -> Vec<PathBuf> {
    let mut files = checkout_and_user_files(root, h, homes);
    files.extend(plugin_files(h, homes));
    files
}

/// The checkout's and the user's hook files of the harness.
fn checkout_and_user_files(root: &Path, h: Harness, homes: &Homes) -> Vec<PathBuf> {
    let mut files = Vec::new();
    match h {
        Harness::Claude => {
            files.push(under(root, ".claude/settings.json"));
            files.push(under(root, ".claude/settings.local.json"));
            files.extend(homes.claude.iter().map(|d| d.join("settings.json")));
        }
        Harness::Codex => {
            files.push(under(root, ".codex/hooks.json"));
            files.extend(homes.codex.iter().map(|d| d.join("hooks.json")));
        }
        Harness::Copilot => {
            files.extend(json_in(&under(root, ".github/hooks")));
            files.push(under(root, ".github/copilot/settings.json"));
            files.push(under(root, ".github/copilot/settings.local.json"));
            if let Some(dir) = &homes.copilot {
                files.extend(json_in(&dir.join("hooks")));
                files.push(dir.join("settings.json"));
            }
        }
    }
    files
}

/// The manifests and hook files of the harness's installed plugins: Copilot
/// CLI's (`<copilot home>/installed-plugins/<source>/<plugin>/`), and Claude
/// Code's plugin cache (`<claude home>/plugins/cache/<marketplace>/<plugin>/
/// <version>/`, leaving out versions marked `.orphaned_at`).
fn plugin_files(h: Harness, homes: &Homes) -> Vec<PathBuf> {
    let mut files = Vec::new();
    match h {
        Harness::Claude => {
            if let Some(dir) = &homes.claude {
                for marketplace in subdirs(&under(dir, "plugins/cache")) {
                    for plugin in subdirs(&marketplace) {
                        for version in subdirs(&plugin).into_iter().filter(|v| !v.join(".orphaned_at").exists()) {
                            files.push(under(&version, "hooks/hooks.json"));
                            files.push(under(&version, ".claude-plugin/plugin.json"));
                        }
                    }
                }
            }
        }
        Harness::Codex => {}
        Harness::Copilot => {
            if let Some(dir) = &homes.copilot {
                for source in subdirs(&dir.join("installed-plugins")) {
                    for plugin in subdirs(&source) {
                        for rel in [
                            "plugin.json",
                            ".plugin/plugin.json",
                            ".github/plugin/plugin.json",
                            ".claude-plugin/plugin.json",
                            "hooks.json",
                            "hooks/hooks.json",
                        ] {
                            files.push(under(&plugin, rel));
                        }
                    }
                }
            }
        }
    }
    files
}

/// The first file configuring bd's session-start hook for `h`, if any:
/// checkout-relative when inside `root`.
pub fn configured(root: &Path, h: Harness, homes: &Homes) -> Option<String> {
    configured_hook(root, target(h), h, BdHook::SessionStart(h), Sources::All, homes)
}

/// The first file of `sources` configuring bd's hook `kind` for the harness
/// `h`, if any: checkout-relative when inside `root`. `rel` is the target
/// file, the one [`Sources::TargetAndPlugins`] looks at.
pub fn configured_hook(
    root: &Path,
    rel: &str,
    h: Harness,
    kind: BdHook,
    sources: Sources,
    homes: &Homes,
) -> Option<String> {
    let files = match sources {
        Sources::All => hook_files(root, h, homes),
        Sources::TargetAndPlugins => {
            let mut files = vec![under(root, rel)];
            files.extend(plugin_files(h, homes));
            files
        }
    };
    files.into_iter().find(|f| read_json(f).is_some_and(|v| holds_bd_hook(&v, kind))).map(|f| shown(root, &f))
}

/// The JSON in `path` if it is a regular file (following symlinks) of at
/// most [`MAX_READ`] bytes: never a FIFO or a device a checkout links to.
fn read_json(path: &Path) -> Option<Value> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(MAX_READ + 1).read_to_string(&mut text).ok()?;
    if text.len() as u64 > MAX_READ {
        return None;
    }
    serde_json::from_str(&text).ok()
}

/// The largest hook or settings file bd reads when looking for its hook.
const MAX_READ: u64 = 4 << 20;

fn shown(root: &Path, path: &Path) -> String {
    // The root may be canonical while the path is not (macOS's /var is /private/var): compare them canonical too.
    let canonical = || {
        let (root, path) = (std::fs::canonicalize(root).ok()?, std::fs::canonicalize(path).ok()?);
        path.strip_prefix(root).ok().map(Path::to_path_buf)
    };
    match path.strip_prefix(root).ok().map(Path::to_path_buf).or_else(canonical) {
        Some(rel) => rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"),
        None => path.display().to_string(),
    }
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// The text of a file bd is to change: `Ok(None)` when there is none,
/// `Err(why)` when bd does not change it (a symlink, not a regular file,
/// not UTF-8).
pub(crate) fn read_target(path: &Path) -> Result<std::result::Result<Option<String>, String>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Ok(Err("a symlink, which bd does not write through".into())),
        Ok(m) if !m.is_file() => Ok(Err("not a regular file".into())),
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(text) => Ok(Ok(Some(text))),
            Err(e) if e.kind() == ErrorKind::InvalidData => Ok(Err("not UTF-8 text".into())),
            Err(e) => Err(path_error(path, e)),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Ok(None)),
        Err(e) => Err(path_error(path, e)),
    }
}

/// Write `text` to `path` at once, making its directory, and keeping the
/// permissions of the file it replaces.
pub(crate) fn write_target(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| path_error(dir, e))?;
    }
    let perms = std::fs::metadata(path).ok().map(|m| m.permissions());
    write_atomically(path, text.as_bytes(), true, |f| match perms {
        Some(p) => f.set_permissions(p),
        None => Ok(()),
    })
}

/// Delete `path`, which bd emptied.
pub(crate) fn delete_target(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(path_error(path, e)),
        _ => Ok(()),
    }
}

/// Make sure the checkout's harness `h` sessions run bd's session-start
/// hook: when none is configured, add it to [`target`] (`apply`) or report
/// that a pull would. The caller holds the checkout's mutex.
pub fn ensure(checkout: &Checkout, h: Harness, apply: bool, homes: &Homes) -> Result<HookReport> {
    ensure_entries(&checkout.root, target(h), h, &session_entries(h), Sources::All, apply, homes).map(|o| o.report)
}

/// Add to `rel` (under `root`) the `entries` whose hook `sources` does not
/// configure already (`apply`), or report what would be added. Present
/// when every one is configured, with the first file found.
pub fn ensure_entries(
    root: &Path,
    rel: &str,
    h: Harness,
    entries: &[Entry],
    sources: Sources,
    apply: bool,
    homes: &Homes,
) -> Result<Outcome> {
    let outcome = |file: String, state, reason: Option<String>, events| Outcome {
        report: HookReport { file, state, reason },
        events,
    };
    let mut found = None;
    let mut missing = Vec::new();
    for entry in entries {
        match configured_hook(root, rel, h, entry.kind, sources, homes) {
            Some(file) => {
                found.get_or_insert(file);
            }
            None => missing.push(entry),
        }
    }
    if missing.is_empty() {
        return Ok(outcome(found.unwrap_or_else(|| rel.to_string()), HookState::Present, None, Vec::new()));
    }
    let path = under(root, rel);
    let text = match read_target(&path)? {
        Ok(text) => text,
        Err(why) => return Ok(outcome(rel.to_string(), HookState::Conflict, Some(why), Vec::new())),
    };
    let merged = match merge_entries(text.as_deref(), h == Harness::Copilot && rel == target(h), &missing) {
        Ok(merged) => merged,
        Err(why) => return Ok(outcome(rel.to_string(), HookState::Conflict, Some(why), Vec::new())),
    };
    if apply {
        write_target(&path, &merged)?;
    }
    let events = missing.iter().map(|e| e.event).collect();
    Ok(outcome(rel.to_string(), HookState::Added, None, events))
}

/// The text of [`target`] with bd's hook items appended to its
/// `hooks.<event>` (`text`: what it holds, if it exists), or why bd cannot.
#[cfg(test)]
fn merge(h: Harness, text: Option<&str>) -> std::result::Result<String, String> {
    merge_entries(text, h == Harness::Copilot, &session_entries(h).iter().collect::<Vec<_>>())
}

/// `text` (what a hook file holds, if it exists) with the items of each of
/// `entries` appended to its `hooks.<event>`, or why bd cannot; a new file
/// starts with `"version": 1` when `init_version` (Copilot CLI's).
fn merge_entries(text: Option<&str>, init_version: bool, entries: &[&Entry]) -> std::result::Result<String, String> {
    let mut top = match text.map(str::trim) {
        None | Some("") => {
            let mut top = Map::new();
            if init_version {
                top.insert("version".into(), json!(1));
            }
            top
        }
        Some(text) => parse_object(text)?,
    };
    let Value::Object(hooks) = top.entry("hooks").or_insert_with(|| json!({})) else {
        return Err("its `hooks` is not an object".into());
    };
    for entry in entries {
        let Value::Array(list) = hooks.entry(entry.event).or_insert_with(|| json!([])) else {
            return Err(format!("its `hooks.{}` is not an array", entry.event));
        };
        list.extend(entry.items.iter().cloned());
    }
    pretty(top)
}

fn parse_object(text: &str) -> std::result::Result<Map<String, Value>, String> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(top)) => Ok(top),
        Ok(_) => Err("not a JSON object".into()),
        Err(e) => Err(format!("not valid JSON ({e})")),
    }
}

fn pretty(top: Map<String, Value>) -> std::result::Result<String, String> {
    serde_json::to_string_pretty(&Value::Object(top)).map(|s| s + "\n").map_err(|e| e.to_string())
}

/// Take bd's hook handlers out of `rel` (under `root`): those whose command
/// is, up to whitespace, one of `entries`' (`apply`), or report what would
/// go. A group, event or `hooks` object this empties goes too, and the file
/// when nothing else is left (but Copilot CLI's `version`).
pub fn remove_entries(root: &Path, rel: &str, entries: &[Entry], apply: bool) -> Result<Outcome> {
    let outcome = |state, reason: Option<String>, events| Outcome {
        report: HookReport { file: rel.to_string(), state, reason },
        events,
    };
    let path = under(root, rel);
    let text = match read_target(&path)? {
        Ok(Some(text)) if !text.trim().is_empty() => text,
        Ok(_) => return Ok(outcome(HookState::Absent, None, Vec::new())),
        Err(why) => return Ok(outcome(HookState::Conflict, Some(why), Vec::new())),
    };
    let mut top = match parse_object(text.trim()) {
        Ok(top) => top,
        Err(why) => return Ok(outcome(HookState::Conflict, Some(why), Vec::new())),
    };
    let ours: Vec<String> = entries.iter().flat_map(|e| &e.items).flat_map(item_commands).collect();
    let is_ours =
        |handler: &Value| handler.get("command").and_then(Value::as_str).is_some_and(|c| ours.contains(&normal(c)));
    let mut events = Vec::new();
    let Some(hooks) = top.get_mut("hooks") else { return Ok(outcome(HookState::Absent, None, Vec::new())) };
    let Value::Object(hooks) = hooks else {
        return Ok(outcome(HookState::Conflict, Some("its `hooks` is not an object".into()), Vec::new()));
    };
    for entry in entries {
        let Some(list) = hooks.get_mut(entry.event) else { continue };
        let Value::Array(list) = list else {
            let why = format!("its `hooks.{}` is not an array", entry.event);
            return Ok(outcome(HookState::Conflict, Some(why), Vec::new()));
        };
        let mut removed = false;
        list.retain_mut(|item| {
            if let Some(Value::Array(handlers)) = item.get_mut("hooks") {
                let before = handlers.len();
                handlers.retain(|h| !is_ours(h));
                removed |= handlers.len() < before;
                return !(handlers.is_empty() && before > 0);
            }
            let ours = is_ours(item);
            removed |= ours;
            !ours
        });
        if removed {
            if list.is_empty() {
                hooks.remove(entry.event);
            }
            if !events.contains(&entry.event) {
                events.push(entry.event);
            }
        }
    }
    if events.is_empty() {
        return Ok(outcome(HookState::Absent, None, Vec::new()));
    }
    if hooks.is_empty() {
        top.remove("hooks");
    }
    if apply {
        let only_version = rel == target(Harness::Copilot) && top.keys().all(|k| k == "version");
        if top.is_empty() || only_version {
            delete_target(&path)?;
        } else {
            let text = pretty(top).map_err(Error::invalid)?;
            write_target(&path, &text)?;
        }
    }
    Ok(outcome(HookState::Removed, None, events))
}

/// The commands of a hook item: a group's handlers' (Claude Code, Codex), or
/// the handler's own (Copilot CLI).
fn item_commands(item: &Value) -> Vec<String> {
    let handlers = match item.get("hooks").and_then(Value::as_array) {
        Some(handlers) => handlers.iter().collect(),
        None => vec![item],
    };
    handlers.into_iter().filter_map(|h| h.get("command").and_then(Value::as_str)).map(normal).collect()
}

/// `command` with its runs of whitespace as one space, trimmed.
fn normal(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_bd_hook_commands_for_the_harness() {
        let h = Harness::Copilot;
        assert!(runs_hook("bd hook session-start --harness copilot", h));
        assert!(runs_hook("/usr/local/bin/bd hook session-start --harness=copilot", h));
        assert!(runs_hook("bd hook session-start", h));
        assert!(!runs_hook("bd hook session-start --harness claude", h));
        assert!(!runs_hook("bd prime --hook copilot", h));
        assert!(!runs_hook("echo bd hook", h));
    }

    #[test]
    fn copilot_file_is_created_with_a_version() {
        let text = merge(Harness::Copilot, None).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["version"], 1);
        let cmds: Vec<&str> =
            v["hooks"]["sessionStart"].as_array().unwrap().iter().map(|i| i["command"].as_str().unwrap()).collect();
        assert_eq!(cmds, ["bd hook session-start --harness copilot", "bd prime --hook copilot"]);
        assert!(holds_hook(&v, Harness::Copilot));
    }

    #[test]
    fn merging_keeps_what_the_file_holds() {
        let before = r#"{"permissions": {"allow": ["Bash(ls)"]}, "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}], "Stop": []}}"#;
        let v: Value = serde_json::from_str(&merge(Harness::Claude, Some(before)).unwrap()).unwrap();
        assert_eq!(v["permissions"]["allow"][0], "Bash(ls)");
        assert_eq!(v["hooks"]["Stop"], json!([]));
        let starts = v["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0]["hooks"][0]["command"], "echo hi");
        assert_eq!(starts[1]["hooks"][1]["command"], "bd prime --hook claude");
        assert!(v.get("version").is_none());
    }

    #[test]
    fn files_it_cannot_merge_into_are_refused() {
        assert!(merge(Harness::Codex, Some("[]")).unwrap_err().contains("not a JSON object"));
        assert!(merge(Harness::Codex, Some("{")).unwrap_err().contains("not valid JSON"));
        assert!(merge(Harness::Codex, Some(r#"{"hooks": []}"#)).unwrap_err().contains("`hooks` is not an object"));
        assert!(
            merge(Harness::Codex, Some(r#"{"hooks": {"SessionStart": {}}}"#)).unwrap_err().contains("not an array")
        );
    }

    fn homes(dir: &Path) -> Homes {
        Homes { claude: Some(dir.join("claude")), codex: Some(dir.join("codex")), copilot: Some(dir.join("copilot")) }
    }

    #[test]
    fn ensure_adds_once_and_reports_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        let homes = homes(&dir.path().join("home"));
        let r = ensure(&checkout, Harness::Codex, false, &homes).unwrap();
        assert_eq!((r.state, r.file.as_str()), (HookState::Added, ".codex/hooks.json"));
        assert!(!dir.path().join(".codex").exists(), "status writes nothing");
        assert_eq!(ensure(&checkout, Harness::Codex, true, &homes).unwrap().state, HookState::Added);
        let r = ensure(&checkout, Harness::Codex, true, &homes).unwrap();
        assert_eq!((r.state, r.file.as_str()), (HookState::Present, ".codex/hooks.json"));
        let text = std::fs::read_to_string(dir.path().join(".codex/hooks.json")).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["hooks"]["SessionStart"].as_array().unwrap().len(), 1);
        assert_eq!(v["hooks"]["SessionStart"][0]["hooks"][1]["command"], "bd prime --hook codex");

        std::fs::create_dir_all(dir.path().join(".github/hooks")).unwrap();
        std::fs::write(dir.path().join(".github/hooks/bd.json"), "not json").unwrap();
        let r = ensure(&checkout, Harness::Copilot, true, &homes).unwrap();
        assert_eq!(r.state, HookState::Conflict);
        assert!(r.reason.unwrap().contains("not valid JSON"));
        assert_eq!(std::fs::read_to_string(dir.path().join(".github/hooks/bd.json")).unwrap(), "not json");
    }

    #[cfg(unix)]
    #[test]
    fn devices_and_fifos_are_never_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".bd")).unwrap();
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(".codex/hooks.json")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        let user = tempfile::tempdir().unwrap();
        let r = ensure(&checkout, Harness::Codex, true, &homes(user.path())).unwrap();
        assert_eq!(r.state, HookState::Conflict);
        assert!(r.reason.unwrap().contains("symlink"));
    }

    #[test]
    fn a_hook_configured_elsewhere_is_left_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        let user = tempfile::tempdir().unwrap();
        let home = user.path().to_path_buf();
        let homes = homes(&home);
        // An installed Copilot CLI plugin's hooks, as this repository's plugin has them.
        let plugin = under(&home, "copilot/installed-plugins/_direct/bd");
        std::fs::create_dir_all(&plugin).unwrap();
        let manifest = json!({"name": "bd", "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "bd hook session-start --harness copilot"}]}]}});
        std::fs::write(plugin.join("plugin.json"), manifest.to_string()).unwrap();
        let r = ensure(&checkout, Harness::Copilot, true, &homes).unwrap();
        assert_eq!(r.state, HookState::Present);
        assert_eq!(r.file, plugin.join("plugin.json").display().to_string());
        assert!(!dir.path().join(".github").exists());

        // A claude hook in the shared settings, while the copilot one names another harness.
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        let settings = json!({"hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "bd hook session-start --harness claude"}]}]}});
        std::fs::write(dir.path().join(".claude/settings.json"), settings.to_string()).unwrap();
        let r = ensure(&checkout, Harness::Claude, true, &homes).unwrap();
        assert_eq!((r.state, r.file.as_str()), (HookState::Present, ".claude/settings.json"));
        assert!(!dir.path().join(".claude/settings.local.json").exists());
    }

    fn all(entries: &[Entry]) -> Vec<&Entry> {
        entries.iter().collect()
    }

    fn write(path: &Path, v: &Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
    }

    fn read(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn claude_project_entries_match_the_repositorys_settings() {
        let text = merge_entries(None, false, &all(&claude_project_entries())).unwrap();
        let settings: Value = serde_json::from_str(include_str!("../../../../.claude/settings.json")).unwrap();
        // The repository's settings hold more than bd's hooks (its plugins, for one); the hooks are the same.
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), json!({ "hooks": settings["hooks"] }));
    }

    #[test]
    fn subagent_and_pre_tool_use_hooks_are_recognized() {
        assert!(runs_bd_hook("bd hook subagent-start || true", BdHook::SubagentStart));
        assert!(runs_bd_hook("/opt/bin/bd hook subagent-start", BdHook::SubagentStart));
        assert!(runs_bd_hook("bd hook pre-tool-use || true", BdHook::PreToolUse));
        assert!(runs_bd_hook("C:\\bin\\bd.exe hook pre-tool-use", BdHook::PreToolUse));
        assert!(!runs_bd_hook("bd hook pre-tool-use", BdHook::SubagentStart));
        assert!(!runs_bd_hook("bd hook subagent-start", BdHook::SessionStart(Harness::Claude)));
        assert!(!runs_bd_hook("echo hook pre-tool-use", BdHook::PreToolUse));
    }

    #[test]
    fn target_and_plugins_ignores_personal_settings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let homes = homes(&dir.path().join("home"));
        let every = merge_entries(None, false, &all(&claude_project_entries())).unwrap();
        let every: Value = serde_json::from_str(&every).unwrap();
        write(&root.join(".claude/settings.local.json"), &every);
        write(&homes.claude.as_ref().unwrap().join("settings.json"), &every);
        let rel = ".claude/settings.json";
        let o = ensure_entries(&root, rel, Harness::Claude, &claude_project_entries(), Sources::All, false, &homes)
            .unwrap();
        assert_eq!((o.report.state, o.report.file.as_str()), (HookState::Present, ".claude/settings.local.json"));
        let entries = claude_project_entries();
        let o = ensure_entries(&root, rel, Harness::Claude, &entries, Sources::TargetAndPlugins, true, &homes).unwrap();
        assert_eq!(o.report.state, HookState::Added);
        assert_eq!(o.events, ["SessionStart", "SubagentStart", "PreToolUse"]);
        assert_eq!(read(&root.join(rel)), every);
        let o = ensure_entries(&root, rel, Harness::Claude, &entries, Sources::TargetAndPlugins, true, &homes).unwrap();
        assert_eq!((o.report.state, o.report.file.as_str()), (HookState::Present, rel));
    }

    #[test]
    fn all_sources_skips_events_configured_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let homes = homes(&dir.path().join("home"));
        let subagent = json!({"hooks": {"SubagentStart": [{"hooks": [{"type": "command", "command": "bd hook subagent-start"}]}]}});
        write(&homes.claude.as_ref().unwrap().join("settings.json"), &subagent);
        let rel = ".claude/settings.json";
        let o =
            ensure_entries(&root, rel, Harness::Claude, &claude_project_entries(), Sources::All, true, &homes).unwrap();
        assert_eq!(o.events, ["SessionStart", "PreToolUse"]);
        let v = read(&root.join(rel));
        assert!(v["hooks"].get("SubagentStart").is_none() && v["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn an_installed_claude_plugin_counts_as_configured() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        let user = tempfile::tempdir().unwrap();
        let homes = homes(user.path());
        let cache = homes.claude.as_ref().unwrap().join("plugins/cache/bd/bd");
        let hooks = merge_entries(None, false, &all(&claude_project_entries())).unwrap();
        // An orphaned version does not count.
        std::fs::create_dir_all(cache.join("old/hooks")).unwrap();
        std::fs::write(cache.join("old/hooks/hooks.json"), &hooks).unwrap();
        std::fs::write(cache.join("old/.orphaned_at"), "1").unwrap();
        assert_eq!(ensure(&checkout, Harness::Claude, false, &homes).unwrap().state, HookState::Added);

        std::fs::create_dir_all(cache.join("abc123/hooks")).unwrap();
        std::fs::write(cache.join("abc123/hooks/hooks.json"), &hooks).unwrap();
        let r = ensure(&checkout, Harness::Claude, true, &homes).unwrap();
        assert_eq!(r.state, HookState::Present);
        // Compared as paths: on Windows the expected one mixes '/' and '\'.
        assert_eq!(Path::new(&r.file), cache.join("abc123/hooks/hooks.json"));
        let rel = ".claude/settings.json";
        let o = ensure_entries(
            dir.path(),
            rel,
            Harness::Claude,
            &claude_project_entries(),
            Sources::TargetAndPlugins,
            true,
            &homes,
        )
        .unwrap();
        assert_eq!(o.report.state, HookState::Present);
        assert!(!dir.path().join(".claude").exists());
    }

    #[test]
    fn ensure_reports_no_events() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        let r = ensure(&checkout, Harness::Codex, true, &homes(&dir.path().join("home"))).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), json!({"file": ".codex/hooks.json", "state": "added"}));
    }

    #[test]
    fn remove_entries_restores_what_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let homes = homes(&root.join("home"));
        let rel = ".claude/settings.json";
        let before = json!({"permissions": {"allow": ["Bash(ls)"]}, "hooks": {"SessionStart": [
            {"hooks": [{"type": "command", "command": "echo hi"}]},
            {"hooks": [{"type": "command", "command": "bd prime --hook claude --ready 5"}]}]}});
        write(&root.join(rel), &before);
        let entries = claude_project_entries();
        ensure_entries(root, rel, Harness::Claude, &entries, Sources::TargetAndPlugins, true, &homes).unwrap();
        assert_ne!(read(&root.join(rel)), before);
        // A dry run writes nothing.
        let o = remove_entries(root, rel, &entries, false).unwrap();
        assert_eq!(o.report.state, HookState::Removed);
        assert_ne!(read(&root.join(rel)), before);
        let o = remove_entries(root, rel, &entries, true).unwrap();
        assert_eq!((o.report.state, o.events.len()), (HookState::Removed, 3));
        assert_eq!(read(&root.join(rel)), before, "the hand-written variant stays");
        assert_eq!(remove_entries(root, rel, &entries, true).unwrap().report.state, HookState::Absent);

        // A file bd created goes, Copilot CLI's flat list and version included.
        let rel = target(Harness::Copilot);
        let entries = session_entries(Harness::Copilot);
        ensure_entries(root, rel, Harness::Copilot, &entries, Sources::All, true, &homes).unwrap();
        assert_eq!(read(&root.join(rel))["version"], 1);
        assert_eq!(remove_entries(root, rel, &entries, true).unwrap().report.state, HookState::Removed);
        assert!(!root.join(rel).exists());
        assert_eq!(remove_entries(root, rel, &entries, true).unwrap().report.state, HookState::Absent);
    }

    #[test]
    fn remove_refuses_files_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let entries = session_entries(Harness::Codex);
        let rel = target(Harness::Codex);
        for text in ["{", r#"{"hooks": []}"#, r#"{"hooks": {"SessionStart": {}}}"#] {
            std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
            std::fs::write(dir.path().join(rel), text).unwrap();
            let o = remove_entries(dir.path(), rel, &entries, true).unwrap();
            assert_eq!(o.report.state, HookState::Conflict, "{text}");
            assert_eq!(std::fs::read_to_string(dir.path().join(rel)).unwrap(), text);
        }
    }
}
