//! Access tokens saved by `bd remote login`, so shells need no `$BD_TOKEN`.
//!
//! They live in `<user config dir>/bd/credentials.toml` (see
//! [`user_config_dir`]), one entry per bd server, or per workspace for a
//! token saved with `--workspace-only`:
//!
//! ```toml
//! [servers."https://bd.example.com"]
//! token = "bdt_..."
//! ca = "system"
//!
//! [workspaces."https://bd.example.com/w/other"]
//! token = "bdt_..."
//! ca = "sha256:..."
//! ```
//!
//! A server is its URL up to `/w/<workspace>`: scheme, host, port and any
//! path prefix (lowercase scheme and host, no default port), since one token
//! may cover every workspace of its server. A workspace entry takes precedence
//! over its server's, and `$BD_TOKEN` over both.
//!
//! `ca` is what the server's certificate was trusted against at login: the
//! system's certificate authorities, or the SHA-256 of a CA file's
//! certificates. A token is only sent under the same trust (see
//! `remote::token_for`), so a checkout whose `.bd/remote.toml` names another
//! CA for the same URL cannot redirect a saved token. Entries without `ca`
//! count as `system`.
//!
//! On Unix the file is replaced
//! atomically by one created with mode 0600, in a directory created 0700, and
//! a file other users can read is refused. On Windows it inherits the
//! per-user ACL of the profile's `%APPDATA%`. Secrets never appear in output
//! or errors.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use bd_core::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::auth::random_hex;
use crate::paths::user_config_dir;
use crate::protocol::valid_workspace_name;

const HEADER: &str = "# Access tokens saved by `bd remote login`. Keep this file private; never commit it.\n\n";

#[derive(Default, Serialize, Deserialize)]
struct File {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    servers: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    workspaces: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    token: String,
    #[serde(default = "system_ca")]
    ca: String,
}

/// The trust of a token checked against the system's certificate authorities.
pub const SYSTEM_CA: &str = "system";

fn system_ca() -> String {
    SYSTEM_CA.to_string()
}

/// Which entry a token is saved under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every workspace on the server.
    Server,
    /// One workspace.
    Workspace,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Server => "server",
            Scope::Workspace => "workspace",
        }
    }
}

/// The entries a URL's token may be saved under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    /// `scheme://host[:port][/prefix]`.
    pub server: String,
    /// `<server>/w/<workspace>`, for a workspace URL.
    pub workspace: Option<String>,
}

/// The saved token that applies to a workspace URL.
pub struct Saved {
    pub token: String,
    /// What the server's certificate was trusted against at login: [`SYSTEM_CA`] or `sha256:<hex>`.
    pub ca: String,
    pub path: PathBuf,
    /// The entry it is saved under.
    pub key: String,
    pub scope: Scope,
}

/// What [`save`] did.
#[derive(Debug)]
pub struct SaveReport {
    pub key: String,
    /// An earlier token for the same entry was replaced.
    pub replaced: bool,
    /// A workspace entry removed because it would have hidden the new server token.
    pub dropped: Option<String>,
    /// The file's earlier mode, when other users could read it.
    pub loose_mode: Option<u32>,
}

/// What [`remove`] did.
#[derive(Debug, Default)]
pub struct RemoveReport {
    pub removed: Vec<String>,
    /// Nothing was left, so the file was deleted.
    pub file_removed: bool,
}

/// The entries for a server URL (`https://host[:port][/prefix]`) or a
/// workspace URL (`<server>/w/<workspace>`).
pub fn keys(raw: &str) -> Result<Keys> {
    let url = raw.trim().trim_end_matches('/');
    let bad = || {
        Error::invalid(format!(
            "{raw:?} is not a bd server or workspace URL; expected https://host[:port][/prefix][/w/<workspace>]"
        ))
    };
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "https" | "http") || url.contains(['?', '#']) {
        return Err(bad());
    }
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let authority = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let authority = authority.strip_suffix(default_port).unwrap_or(&authority);
    let (prefix, workspace) = match path.rsplit_once("/w/") {
        Some((prefix, name)) if valid_workspace_name(name) => (prefix, Some(name)),
        _ => (path, None),
    };
    let server = format!("{scheme}://{authority}{prefix}");
    Ok(Keys { workspace: workspace.map(|name| format!("{server}/w/{name}")), server })
}

/// `<user config dir>/bd/credentials.toml`.
pub fn default_path() -> Result<PathBuf> {
    user_config_dir().map(|d| d.join("bd").join("credentials.toml")).ok_or_else(|| {
        Error::invalid(if cfg!(windows) {
            "no user config directory to keep access tokens in: set APPDATA or XDG_CONFIG_HOME"
        } else {
            "no user config directory to keep access tokens in: set HOME or XDG_CONFIG_HOME"
        })
    })
}

/// The saved token for a workspace URL, if any: its workspace entry, else its server's.
pub fn lookup(url: &str) -> Result<Option<Saved>> {
    match user_config_dir() {
        Some(_) => lookup_in(&default_path()?, url),
        None => Ok(None),
    }
}

fn lookup_in(path: &Path, url: &str) -> Result<Option<Saved>> {
    let Some((mut file, loose_mode)) = load(path)? else { return Ok(None) };
    if let Some(mode) = loose_mode {
        return Err(Error::Refused(format!(
            "{0} holds access tokens but other users may read it (mode {mode:03o}): run `chmod 600 {0}` and consider \
             revoking its tokens, or log in again",
            path.display()
        )));
    }
    let keys = keys(url)?;
    let workspace = keys.workspace.and_then(|k| file.workspaces.remove(&k).map(|e| (k, Scope::Workspace, e)));
    let found = workspace.or_else(|| file.servers.remove(&keys.server).map(|e| (keys.server, Scope::Server, e)));
    Ok(found.map(|(key, scope, entry)| Saved {
        token: entry.token,
        ca: entry.ca,
        path: path.to_path_buf(),
        key,
        scope,
    }))
}

/// Refuse what cannot be an access token, without quoting it.
pub fn check_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(Error::invalid("the access token is empty"));
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::invalid("the access token must be one word on one line (it contains whitespace)"));
    }
    Ok(())
}

/// Save `token` for `url`'s server, or for the workspace only, with the
/// trust it was checked under (`ca`: [`SYSTEM_CA`] or `sha256:<hex>`).
pub fn save(path: &Path, url: &str, token: &str, ca: &str, scope: Scope) -> Result<SaveReport> {
    check_token(token)?;
    let keys = keys(url)?;
    let (mut file, loose_mode) = load(path)?.unwrap_or_default();
    let entry = Entry { token: token.to_string(), ca: ca.to_string() };
    let report = match scope {
        Scope::Server => {
            let dropped = keys.workspace.filter(|k| file.workspaces.remove(k).is_some());
            let replaced = file.servers.insert(keys.server.clone(), entry).is_some();
            SaveReport { key: keys.server, replaced, dropped, loose_mode }
        }
        Scope::Workspace => {
            let key = keys.workspace.ok_or_else(|| Error::invalid(format!("{url}: not a workspace URL")))?;
            let replaced = file.workspaces.insert(key.clone(), entry).is_some();
            SaveReport { key, replaced, dropped: None, loose_mode }
        }
    };
    write(path, &file)?;
    Ok(report)
}

/// Forget the tokens saved for `url`. For a workspace URL: its own entry and,
/// unless `workspace_only`, its server's. For a server URL: the server's and
/// those of all its workspaces. The file is deleted once empty.
pub fn remove(path: &Path, url: &str, workspace_only: bool) -> Result<RemoveReport> {
    let keys = keys(url)?;
    if workspace_only && keys.workspace.is_none() {
        return Err(Error::invalid(format!("--workspace-only needs a workspace URL (…/w/<workspace>), not {url}")));
    }
    let Some((mut file, _)) = load(path)? else { return Ok(RemoveReport::default()) };
    let mut removed = Vec::new();
    if !workspace_only && file.servers.remove(&keys.server).is_some() {
        removed.push(keys.server.clone());
    }
    match &keys.workspace {
        Some(k) => removed.extend(file.workspaces.remove(k).map(|_| k.clone())),
        None => {
            let prefix = format!("{}/w/", keys.server);
            let under: Vec<String> = file
                .workspaces
                .keys()
                .filter(|k| k.strip_prefix(&prefix).is_some_and(valid_workspace_name))
                .cloned()
                .collect();
            for k in under {
                file.workspaces.remove(&k);
                removed.push(k);
            }
        }
    }
    if removed.is_empty() {
        return Ok(RemoveReport::default());
    }
    let file_removed = file.servers.is_empty() && file.workspaces.is_empty();
    if file_removed {
        std::fs::remove_file(path).map_err(|e| io_error(path, e))?;
    } else {
        write(path, &file)?;
    }
    Ok(RemoveReport { removed, file_removed })
}

fn io_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// The file, and its mode when other users may read it; `None` if it does not exist.
fn load(path: &Path) -> Result<Option<(File, Option<u32>)>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(path, e)),
    };
    let file = toml::from_str::<File>(&text).map_err(|e| {
        // The parser's message may quote the file, which holds secrets: name the line only.
        let line = e.span().map(|s| text.as_bytes()[..s.start.min(text.len())].iter().filter(|&&b| b == b'\n').count());
        Error::invalid(format!(
            "{}{}: not a valid credentials file; fix it, or delete it and log in again (`bd remote login`)",
            path.display(),
            line.map(|n| format!(" (line {})", n + 1)).unwrap_or_default()
        ))
    })?;
    Ok(Some((file, loose_mode(path)?)))
}

#[cfg(unix)]
fn loose_mode(path: &Path) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map_err(|e| io_error(path, e))?.permissions().mode() & 0o777;
    Ok((mode & 0o077 != 0).then_some(mode))
}

#[cfg(not(unix))]
fn loose_mode(_: &Path) -> Result<Option<u32>> {
    Ok(None)
}

/// Replace the file atomically with a fresh one only its owner can read.
fn write(path: &Path, file: &File) -> Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(|e| io_error(dir, e))?;
    let body = toml::to_string(file).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    let tmp = dir.join(format!(".credentials.{}.tmp", random_hex(8)?));
    let written = write_new(&tmp, format!("{HEADER}{body}").as_bytes()).and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_error(path, e));
    }
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(server: &str, workspace: Option<&str>) -> Keys {
        Keys { server: server.into(), workspace: workspace.map(String::from) }
    }

    #[test]
    fn urls_normalize_to_their_server_and_workspace() {
        let proj = k("https://bd.example.com", Some("https://bd.example.com/w/proj"));
        for url in
            ["https://bd.example.com/w/proj", "https://bd.example.com/w/proj/", " HTTPS://BD.Example.com:443/w/proj "]
        {
            assert_eq!(keys(url).unwrap(), proj, "{url}");
        }
        assert_eq!(keys("https://bd.example.com/").unwrap(), k("https://bd.example.com", None));
        assert_eq!(
            keys("https://example.com:8443/bd/w/proj").unwrap(),
            k("https://example.com:8443/bd", Some("https://example.com:8443/bd/w/proj")),
            "a path prefix belongs to the server"
        );
        assert_eq!(keys("https://example.com/bd").unwrap(), k("https://example.com/bd", None));
        assert_eq!(keys("http://127.0.0.1:80/w/a").unwrap().server, "http://127.0.0.1");
        assert_eq!(keys("http://[::1]:7420/w/a").unwrap().server, "http://[::1]:7420");
        assert_eq!(keys("https://h:4430/w/a").unwrap().server, "https://h:4430");
        assert_eq!(keys("https://h/w/x/w/a").unwrap().server, "https://h/w/x");
        for bad in ["bd.example.com/w/proj", "ftp://h/w/a", "https:///w/a", "https://u:p@h/w/a", "https://h/w/a?x"] {
            assert!(keys(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn save_lookup_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg").join("bd").join("credentials.toml");
        assert!(lookup_in(&path, "https://h/w/a").unwrap().is_none(), "a missing file is no token");
        assert!(remove(&path, "https://h/w/a", false).unwrap().removed.is_empty());

        let r = save(&path, "https://H:443/w/a", "bdt_server", SYSTEM_CA, Scope::Server).unwrap();
        assert_eq!((r.key.as_str(), r.replaced, r.dropped.is_none()), ("https://h", false, true));
        save(&path, "https://other/w/a", "bdt_other", SYSTEM_CA, Scope::Server).unwrap();
        save(&path, "https://h/w/b", "bdt_b", SYSTEM_CA, Scope::Workspace).unwrap();
        let found = |url: &str| lookup_in(&path, url).unwrap().map(|s| (s.token, s.key, s.scope));
        assert_eq!(found("https://h/w/a"), Some(("bdt_server".into(), "https://h".into(), Scope::Server)));
        assert_eq!(found("https://h/w/b"), Some(("bdt_b".into(), "https://h/w/b".into(), Scope::Workspace)));
        assert_eq!(found("https://h/prefix/w/a"), None, "another server behind the same host");

        // Logging in to b's server again replaces the server token and drops b's own, which would hide it.
        let r = save(&path, "https://h/w/b", "bdt_new", SYSTEM_CA, Scope::Server).unwrap();
        assert!(r.replaced);
        assert_eq!(r.dropped.as_deref(), Some("https://h/w/b"));
        assert_eq!(found("https://h/w/b").unwrap().0, "bdt_new");

        save(&path, "https://h/w/b", "bdt_b", SYSTEM_CA, Scope::Workspace).unwrap();
        save(&path, "https://h/w/c", "bdt_c", SYSTEM_CA, Scope::Workspace).unwrap();
        let r = remove(&path, "https://h/w/b", true).unwrap();
        assert_eq!(r.removed, vec!["https://h/w/b"]);
        assert_eq!(found("https://h/w/b").unwrap().0, "bdt_new", "back to the server token");
        assert!(remove(&path, "https://h", true).is_err(), "--workspace-only needs a workspace");

        let r = remove(&path, "https://h/", false).unwrap();
        assert_eq!(r.removed, vec!["https://h", "https://h/w/c"], "a server URL removes its workspaces too");
        assert!(!r.file_removed);
        assert_eq!(found("https://other/w/z").unwrap().0, "bdt_other");
        let r = remove(&path, "https://other/w/a", false).unwrap();
        assert_eq!((r.removed, r.file_removed), (vec!["https://other".to_string()], true));
        assert!(!path.exists(), "an empty file is deleted");
    }

    #[test]
    fn entries_keep_the_trust_they_were_checked_under() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        save(&path, "https://h/w/a", "bdt_x", "sha256:abc", Scope::Server).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("ca = \"sha256:abc\""));
        assert_eq!(lookup_in(&path, "https://h/w/a").unwrap().unwrap().ca, "sha256:abc");
        std::fs::write(&path, "[servers.\"https://h\"]\ntoken = \"bdt_x\"\n").unwrap();
        assert_eq!(lookup_in(&path, "https://h/w/a").unwrap().unwrap().ca, SYSTEM_CA, "entries without ca");
    }

    #[test]
    fn bad_tokens_and_files_are_reported_without_secrets() {
        assert!(check_token("bdt_ok").is_ok());
        for bad in ["", "bdt_a bdt_b", "bdt_a\nbdt_b"] {
            let e = check_token(bad).unwrap_err().to_string();
            assert!(bad.is_empty() || !e.contains("bdt_a"), "{e}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        assert!(save(&path, "https://h/w/a", "", SYSTEM_CA, Scope::Server).is_err());
        assert!(
            save(&path, "https://h", "bdt_x", SYSTEM_CA, Scope::Workspace).is_err(),
            "a workspace entry needs a workspace URL"
        );
        assert!(!path.exists(), "nothing is written for a refused save");

        std::fs::write(&path, "[servers.\"https://h\"]\ntoken = bdt_secret_value\n").unwrap();
        let e = lookup_in(&path, "https://h/w/a").err().unwrap();
        let msg = e.to_string();
        assert_eq!(e.exit_code(), 2);
        assert!(msg.contains(&path.display().to_string()) && msg.contains("line 2"), "{msg}");
        assert!(!msg.contains("bdt_secret"), "{msg}");
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg").join("bd").join("credentials.toml");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        save(&path, "https://h/w/a", "bdt_x", SYSTEM_CA, Scope::Server).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&dir.path().join("cfg")), 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(HEADER) && text.contains("[servers.\"https://h\"]"), "{text}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = lookup_in(&path, "https://h/w/a").err().unwrap();
        assert!(e.to_string().contains("chmod 600") && e.exit_code() == 2, "{e}");
        let r = save(&path, "https://h/w/a", "bdt_y", SYSTEM_CA, Scope::Server).unwrap();
        assert_eq!(r.loose_mode, Some(0o644));
        assert_eq!(mode(&path), 0o600, "saving again makes it private");
        assert_eq!(lookup_in(&path, "https://h/w/a").unwrap().unwrap().token, "bdt_y");
        let leftovers = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "no temp files are left behind");
    }
}
