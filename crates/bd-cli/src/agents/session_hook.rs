//! The session-start hook a pull puts in a checkout, so that the harness's
//! sessions there run `bd hook session-start` and `bd prime`: without it, an
//! agent in a fresh checkout has no way to learn that bd tracks its work.
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
//! Nothing is written when a bd session-start hook for the harness is
//! already configured, in the checkout or for the user ([`configured`]):
//! the plugin's, say, or one written by hand. A target file bd cannot merge
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
fn items(h: Harness) -> Vec<Value> {
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

/// Whether `command` runs bd's session-start hook for `h`: one naming no
/// harness counts too, as it takes the session's.
fn runs_hook(command: &str, h: Harness) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    let Some(at) = words.windows(3).position(|w| is_bd(w[0]) && w[1] == "hook" && w[2] == "session-start") else {
        return false;
    };
    let rest = &words[at + 3..];
    match rest.iter().position(|w| *w == "--harness" || w.starts_with("--harness=")) {
        None => true,
        Some(i) => match rest[i].strip_prefix("--harness=") {
            Some(v) => v == h.name(),
            None => rest.get(i + 1) == Some(&h.name()),
        },
    }
}

/// Whether `program` is bd, by name or path.
fn is_bd(program: &str) -> bool {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    name == "bd" || name.eq_ignore_ascii_case("bd.exe")
}

/// Whether any string in `v` is a command running bd's hook for `h`.
fn holds_hook(v: &Value, h: Harness) -> bool {
    match v {
        Value::String(s) => runs_hook(s, h),
        Value::Array(a) => a.iter().any(|v| holds_hook(v, h)),
        Value::Object(m) => m.values().any(|v| holds_hook(v, h)),
        _ => false,
    }
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

/// The files the harness reads hooks from: the checkout's (`root`), then
/// the user's, then (Copilot CLI) the manifests and hook files of installed
/// plugins (`<copilot home>/installed-plugins/<source>/<plugin>/`).
fn hook_files(root: &Path, h: Harness, homes: &Homes) -> Vec<PathBuf> {
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
    hook_files(root, h, homes)
        .into_iter()
        .find(|f| read_json(f).is_some_and(|v| holds_hook(&v, h)))
        .map(|f| shown(root, &f))
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
    match path.strip_prefix(root) {
        Ok(rel) => rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"),
        Err(_) => path.display().to_string(),
    }
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// Make sure the checkout's harness `h` sessions run bd's session-start
/// hook: when none is configured, add it to [`target`] (`apply`) or report
/// that a pull would. The caller holds the checkout's mutex.
pub fn ensure(checkout: &Checkout, h: Harness, apply: bool, homes: &Homes) -> Result<HookReport> {
    let root = &checkout.root;
    let rel = target(h);
    let report = |state, reason: Option<String>| HookReport { file: rel.to_string(), state, reason };
    if let Some(file) = configured(root, h, homes) {
        return Ok(HookReport { file, state: HookState::Present, reason: None });
    }
    let path = under(root, rel);
    let text = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Ok(report(HookState::Conflict, Some("a symlink, which bd does not write through".into())));
        }
        Ok(m) if !m.is_file() => return Ok(report(HookState::Conflict, Some("not a regular file".into()))),
        Ok(_) => match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                return Ok(report(HookState::Conflict, Some("not UTF-8 text".into())));
            }
            Err(e) => return Err(path_error(&path, e)),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(path_error(&path, e)),
    };
    let merged = match merge(h, text.as_deref()) {
        Ok(merged) => merged,
        Err(why) => return Ok(report(HookState::Conflict, Some(why))),
    };
    if apply {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| path_error(dir, e))?;
        }
        let perms = std::fs::metadata(&path).ok().map(|m| m.permissions());
        write_atomically(&path, merged.as_bytes(), true, |f| match perms {
            Some(p) => f.set_permissions(p),
            None => Ok(()),
        })?;
    }
    Ok(report(HookState::Added, None))
}

/// The text of [`target`] with bd's hook items appended to its
/// `hooks.<event>` (`text`: what it holds, if it exists), or why bd cannot.
fn merge(h: Harness, text: Option<&str>) -> std::result::Result<String, String> {
    let mut top = match text.map(str::trim) {
        None | Some("") => {
            let mut top = Map::new();
            if h == Harness::Copilot {
                top.insert("version".into(), json!(1));
            }
            top
        }
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(top)) => top,
            Ok(_) => return Err("not a JSON object".into()),
            Err(e) => return Err(format!("not valid JSON ({e})")),
        },
    };
    let Value::Object(hooks) = top.entry("hooks").or_insert_with(|| json!({})) else {
        return Err("its `hooks` is not an object".into());
    };
    let Value::Array(list) = hooks.entry(event(h)).or_insert_with(|| json!([])) else {
        return Err(format!("its `hooks.{}` is not an array", event(h)));
    };
    list.extend(items(h));
    serde_json::to_string_pretty(&Value::Object(top)).map(|s| s + "\n").map_err(|e| e.to_string())
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
}
