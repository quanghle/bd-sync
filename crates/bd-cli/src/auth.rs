//! Access tokens for `bd serve`: who may call, as which actor, with which role.
//!
//! Tokens live in `<root>/tokens.json` (mode 0600 on Unix), which stores
//! only the SHA-256 of each secret. `bd serve token create` prints a secret
//! once. A token acts as one actor, or as `<actor>/<name>` sub-actors (one
//! per agent), so claims and leases keep meaning "this caller".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use bd_core::{Error, Result, Timestamp};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::{App, Out};
use crate::cli::{TokenCommand, TokenCreateArgs, TokenRootArgs};
use crate::protocol::valid_workspace_name;

/// What a token may do. Each role includes the ones before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only commands; the database connection is query-only.
    Read,
    /// Every command a local user runs, except admin ones.
    Write,
    /// Also `config set/unset`, `import`, `events prune`, `doctor`.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Write => "write",
            Role::Admin => "admin",
        }
    }
}

/// One entry of `tokens.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    /// Stable id, recorded with each request (the principal).
    pub id: String,
    pub name: String,
    pub actor: String,
    pub role: Role,
    /// Workspace names, or `*` for every workspace.
    pub workspaces: Vec<String>,
    /// Hex SHA-256 of the secret.
    pub sha256: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

impl Token {
    pub fn allows_workspace(&self, workspace: &str) -> bool {
        self.workspaces.iter().any(|w| w == "*" || w == workspace)
    }

    /// The token's actor, or a sub-actor `<actor>/<name>`.
    pub fn allows_actor(&self, actor: &str) -> bool {
        actor == self.actor
            || actor
                .strip_prefix(self.actor.as_str())
                .and_then(|r| r.strip_prefix('/'))
                .is_some_and(|r| !r.trim().is_empty())
    }

    fn view(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "name": self.name,
            "actor": self.actor,
            "role": self.role,
            "workspaces": self.workspaces,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
        })
    }

    fn describe(&self) -> String {
        let ws = if self.workspaces.iter().any(|w| w == "*") { "all".to_string() } else { self.workspaces.join(",") };
        format!("acts as {0} or {0}/<agent>, role {1}, workspaces {ws}", self.actor, self.role.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenFile {
    version: u32,
    tokens: Vec<Token>,
}

pub fn tokens_path(root: &Path) -> PathBuf {
    root.join("tokens.json")
}

fn load_file(path: &Path) -> Result<TokenFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TokenFile { version: 1, tokens: Vec::new() }),
        Err(e) => Err(Error::invalid(format!("{}: {e}", path.display()))),
    }
}

fn save_file(path: &Path, file: &TokenFile) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut text = serde_json::to_string_pretty(file)?;
    text.push('\n');
    // A leftover temp file would keep its permissions; start from a fresh one (mode 0600).
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    {
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex of `n` random bytes from the operating system.
pub fn random_hex(n: usize) -> Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(hex(&buf))
}

pub fn hash(secret: &str) -> String {
    hex(&Sha256::digest(secret.as_bytes()))
}

/// Checks bearer tokens, rereading `tokens.json` whenever it changes, so
/// new and revoked tokens take effect without a restart.
pub struct Verifier {
    path: PathBuf,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    loaded: bool,
    stamp: Option<(Option<SystemTime>, u64)>,
    by_hash: HashMap<String, Token>,
}

impl Verifier {
    pub fn new(root: &Path) -> Verifier {
        Verifier { path: tokens_path(root), cache: Mutex::new(Cache::default()) }
    }

    /// The live (not revoked) token with this secret.
    pub fn verify(&self, secret: &str) -> Result<Option<Token>> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let stamp = std::fs::metadata(&self.path).ok().map(|m| (m.modified().ok(), m.len()));
        if !cache.loaded || stamp != cache.stamp {
            let file = load_file(&self.path)?;
            cache.by_hash =
                file.tokens.into_iter().filter(|t| t.revoked_at.is_none()).map(|t| (t.sha256.clone(), t)).collect();
            cache.stamp = stamp;
            cache.loaded = true;
        }
        Ok(cache.by_hash.get(&hash(secret)).cloned())
    }
}

fn root_dir(a: &TokenRootArgs) -> Result<PathBuf> {
    if a.root.is_dir() {
        Ok(a.root.clone())
    } else {
        Err(Error::invalid(format!("--root {}: not a directory", a.root.display())))
    }
}

pub fn cmd_token(app: &mut App, cmd: &TokenCommand) -> Result<()> {
    match cmd {
        TokenCommand::Create(a) => create(app, a),
        TokenCommand::List(a) => list(app, a),
        TokenCommand::Revoke(a) => revoke(app, &a.root, &a.name),
    }
}

fn create(app: &mut App, a: &TokenCreateArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    let (token, secret) = issue_token(&root, &a.name, &a.act_as, a.role, &a.workspaces)?;
    let mut view = token.view();
    view["token"] = json!(secret);
    let out = Out::new(view)
        .line(format!("✓ Created access token {}: {}", token.name, token.describe()))
        .line(secret.clone())
        .line("Shown only once. On the client, save it with `bd remote login`, or set it as BD_TOKEN.")
        .id(secret);
    app.print(out);
    Ok(())
}

/// Add an access token to `<root>/tokens.json`. Returns it with its secret,
/// which is not stored anywhere.
pub fn issue_token(root: &Path, name: &str, actor: &str, role: Role, workspaces: &[String]) -> Result<(Token, String)> {
    let name = name.trim();
    let name_ok = name.len() <= 64
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !name_ok {
        return Err(Error::invalid(format!(
            "invalid token name {name:?}: a letter or digit, then letters, digits, '.', '_' or '-' (at most 64)"
        )));
    }
    let actor = actor.trim();
    bd_core::store::validate_actor(actor)?;
    if actor.starts_with('/') || actor.ends_with('/') || actor.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "invalid actor {actor:?}: no control characters, and no '/' at either end"
        )));
    }
    let mut workspaces: Vec<String> =
        workspaces.iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).collect();
    if workspaces.is_empty() {
        workspaces.push("*".into());
    }
    workspaces.sort();
    workspaces.dedup();
    if let Some(bad) = workspaces.iter().find(|w| *w != "*" && !valid_workspace_name(w)) {
        return Err(Error::invalid(format!("invalid workspace name {bad:?}")));
    }
    let path = tokens_path(root);
    let mut file = load_file(&path)?;
    if file.tokens.iter().any(|t| t.name == name && t.revoked_at.is_none()) {
        return Err(Error::Refused(format!("access token {name} already exists; revoke it first")));
    }
    let secret = format!("bdt_{}", random_hex(32)?);
    let token = Token {
        id: random_hex(8)?,
        name: name.to_string(),
        actor: actor.to_string(),
        role,
        workspaces,
        sha256: hash(&secret),
        created_at: Timestamp::now().to_rfc3339(),
        revoked_at: None,
    };
    file.tokens.push(token.clone());
    save_file(&path, &file)?;
    Ok((token, secret))
}

fn list(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = load_file(&tokens_path(&root_dir(a)?))?;
    let mut out = Out::new(file.tokens.iter().map(Token::view).collect::<Vec<_>>());
    if file.tokens.is_empty() {
        out = out.line("No access tokens. Create one with `bd serve token create <name> --as <actor>`.");
    }
    for t in &file.tokens {
        let state = match &t.revoked_at {
            Some(at) => format!("revoked {at}"),
            None => format!("created {}", t.created_at),
        };
        out = out.line(format!("{:<20} {}  ({state})", t.name, t.describe())).id(t.name.clone());
    }
    app.print(out);
    Ok(())
}

fn revoke(app: &mut App, root: &TokenRootArgs, name: &str) -> Result<()> {
    let path = tokens_path(&root_dir(root)?);
    let mut file = load_file(&path)?;
    let now = Timestamp::now().to_rfc3339();
    let mut revoked = 0;
    let mut known = false;
    for t in file.tokens.iter_mut().filter(|t| t.name == name) {
        known = true;
        if t.revoked_at.is_none() {
            t.revoked_at = Some(now.clone());
            revoked += 1;
        }
    }
    if !known {
        return Err(Error::not_found("access token", name));
    }
    if revoked > 0 {
        save_file(&path, &file)?;
    }
    let text =
        if revoked > 0 { format!("✓ Revoked access token {name}") } else { format!("= {name} was already revoked") };
    app.print(Out::new(json!({ "name": name, "revoked": revoked > 0 })).line(text).id(name.to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(actor: &str, workspaces: &[&str]) -> Token {
        Token {
            id: "id".into(),
            name: "n".into(),
            actor: actor.into(),
            role: Role::Write,
            workspaces: workspaces.iter().map(|s| s.to_string()).collect(),
            sha256: String::new(),
            created_at: String::new(),
            revoked_at: None,
        }
    }

    #[test]
    fn actors_are_the_token_actor_or_its_sub_actors() {
        let t = token("alice", &["*"]);
        for ok in ["alice", "alice/agent-1", "alice/ci/run-7"] {
            assert!(t.allows_actor(ok), "{ok}");
        }
        for bad in ["bob", "alice2", "alicex/agent", "alice/", "alice/ ", "", "ALICE"] {
            assert!(!t.allows_actor(bad), "{bad}");
        }
    }

    #[test]
    fn workspaces_are_scoped() {
        assert!(token("a", &["*"]).allows_workspace("anything"));
        let t = token("a", &["one", "two"]);
        assert!(t.allows_workspace("two") && !t.allows_workspace("three"));
    }

    #[test]
    fn verifier_rereads_the_file_and_ignores_revoked_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = tokens_path(dir.path());
        let v = Verifier::new(dir.path());
        assert!(v.verify("bdt_x").unwrap().is_none(), "no file yet");
        let mut t = token("alice", &["*"]);
        t.sha256 = hash("bdt_secret");
        save_file(&path, &TokenFile { version: 1, tokens: vec![t.clone()] }).unwrap();
        assert_eq!(v.verify("bdt_secret").unwrap().map(|t| t.actor), Some("alice".to_string()));
        assert!(v.verify("bdt_other").unwrap().is_none());
        t.revoked_at = Some("2026-01-01T00:00:00Z".into());
        save_file(&path, &TokenFile { version: 1, tokens: vec![t] }).unwrap();
        assert!(v.verify("bdt_secret").unwrap().is_none(), "revocation applies without a restart");
    }
}
