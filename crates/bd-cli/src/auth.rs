//! Access tokens for `bd serve`: who may call, as which actor, with which
//! role, and whether a person or an agent holds it.
//!
//! Tokens live in `<root>/tokens.json` (mode 0600 on Unix), which stores
//! only the SHA-256 of each secret. `bd serve token create` prints a secret
//! once; GitHub sign-in (`oauth.rs`) issues tokens that expire, recording
//! the GitHub account, and with a GitHub App a refresh secret
//! (`bdr_<family>_<random>`): each refresh replaces both secrets of the
//! sign-in's entry in place, and a refresh secret used twice revokes it. A token acts as one actor, or as `<actor>/<name>`
//! sub-actors (one per agent), so claims and leases keep meaning "this
//! caller". Its role and kind become the request's [`bd_core::Policy`]:
//! only admins end or take over other actors' claims, and only human tokens
//! open human gates. Whoever changes the file holds `<root>/tokens.lock`,
//! since the server issues tokens while an admin may create or revoke others.
//!
//! The file also binds each GitHub account that signed in to its actor, its
//! login at its first sign-in (`accounts`): the account keeps that actor
//! when its login changes, and no other principal gets it, even once the
//! account's tokens are gone, until an admin releases it (`revoke --github
//! <login> --forget`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use bd_core::{Error, Result, Timestamp};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::{App, Out};
use crate::cli::{TokenCommand, TokenCreateArgs, TokenRevokeArgs, TokenRootArgs};
use crate::protocol::valid_workspace_name;

/// Expired tokens from GitHub sign-in stay listed this long, then are
/// dropped from the file when a token is added.
const PRUNE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a change of `tokens.json` waits for another one to finish.
const LOCK_WAIT: Duration = Duration::from_secs(10);

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

/// Who holds a token, independent of its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A person: may also resolve human gates and move work past them.
    Human,
    /// A program (the default of `bd serve token create`).
    Agent,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Human => "human",
            Kind::Agent => "agent",
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
    pub kind: Kind,
    /// Workspace names, or `*` for every workspace.
    pub workspaces: Vec<String>,
    /// Hex SHA-256 of the secret.
    pub sha256: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// When the token stops working: set on tokens from GitHub sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The GitHub account that signed in for the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubUser>,
    /// The most issues its actor and sub-actors may hold, claimed or reserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<u32>,
    /// How a token from GitHub sign-in is refreshed, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Refresh>,
    /// The only MCP endpoint the token works at (its audience): the URL of
    /// `/w/<name>/mcp` as clients reach it. A bound token is refused
    /// everywhere else, CLI requests included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// The refresh state of a GitHub sign-in: one per token entry, whose
/// secrets each refresh replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    /// Names the sign-in in its refresh secrets (`bdr_<family>_<random>`):
    /// never shown or logged.
    pub family: String,
    /// Hex SHA-256 of the current refresh secret: any other secret of the
    /// family is a spent one.
    pub sha256: String,
    /// The workspace the account signed in for: refreshes apply the rules for it.
    pub workspace: String,
    pub refreshed_at: Timestamp,
    /// Until when it may be refreshed, as of its latest refresh.
    pub until: Timestamp,
    /// The latest refresh, which a client whose answer was lost may send
    /// again: hashes of the secret it spent and of its request id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<LastRefresh>,
}

/// What [`Refresh::last`] keeps of a refresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastRefresh {
    /// Hex SHA-256 of the refresh secret it spent.
    pub spent: String,
    /// Hex SHA-256 of its request id.
    pub request: String,
}

impl Refresh {
    /// Whether `secret` and `request_id` are those of the latest refresh: a
    /// retry whose answer was lost, not a spent secret used again.
    pub fn retries_last(&self, secret: &str, request_id: &str) -> bool {
        self.last.as_ref().is_some_and(|l| l.spent == hash(secret) && l.request == hash(request_id))
    }
}

/// A refresh secret's family: `bdr_<family>_<random>` -> `<family>`.
pub fn refresh_family(secret: &str) -> Option<&str> {
    let (family, random) = secret.strip_prefix("bdr_")?.split_once('_')?;
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    (hex(family, 32) && hex(random, 64)).then_some(family)
}

/// A new refresh secret of `family`.
fn refresh_secret(family: &str) -> Result<String> {
    Ok(format!("bdr_{family}_{}", random_hex(32)?))
}

/// A GitHub account, as GitHub names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubUser {
    /// The GitHub it signed in at (`github.url` of `auth.toml`, lowercase):
    /// user ids are only unique within one.
    pub url: String,
    pub login: String,
    /// GitHub's user id, which stays with the account when its login changes.
    pub id: u64,
}

/// A GitHub account that signed in, bound to the actor its tokens act as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// The GitHub it signed in at, as in [`GithubUser::url`].
    pub url: String,
    pub id: u64,
    /// The actor of its tokens: its login when it first signed in.
    pub actor: String,
    /// Its login at its latest sign-in.
    pub login: String,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

impl Account {
    /// Whether `user` is this account.
    fn is(&self, user: &GithubUser) -> bool {
        self.id == user.id && self.url == user.url
    }
}

/// Whether one of two actors is the other, or one of its sub-actors
/// (`<actor>/<name>`), whatever their case.
/// `bd serve`'s own actor ([`crate::jobs::ACTOR`]) or one of its sub-actors,
/// whatever the case: no token or request may act as it, so the history
/// tells the server's background writes from clients'.
pub fn is_reserved_actor(actor: &str) -> bool {
    related(crate::jobs::ACTOR, actor)
}

fn related(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    let covers = |a: &str, b: &str| a == b || b.strip_prefix(a).is_some_and(|rest| rest.starts_with('/'));
    covers(&a, &b) || covers(&b, &a)
}

/// What a token may do: its role, kind and workspaces, and how much work
/// its actor may hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub role: Role,
    pub kind: Kind,
    /// Workspace names, or `*` for every workspace.
    pub workspaces: Vec<String>,
    /// The most issues its actor and sub-actors may hold, claimed or reserved.
    pub max_claims: Option<u32>,
}

impl Grant {
    pub fn allows_workspace(&self, workspace: &str) -> bool {
        self.workspaces.iter().any(|w| w == "*" || w == workspace)
    }
}

/// `workspaces` trimmed, sorted and checked: `*` (every workspace) when empty.
pub fn workspace_list(workspaces: &[String]) -> Result<Vec<String>> {
    let mut list: Vec<String> = workspaces.iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).collect();
    if list.is_empty() {
        list.push("*".into());
    }
    list.sort();
    list.dedup();
    match list.iter().find(|w| *w != "*" && !valid_workspace_name(w)) {
        Some(bad) => Err(Error::invalid(format!("invalid workspace name {bad:?}"))),
        None => Ok(list),
    }
}

fn workspaces_text(workspaces: &[String]) -> String {
    if workspaces.iter().any(|w| w == "*") { "all".to_string() } else { workspaces.join(",") }
}

/// A token as one line, from its [`Token::summary`] (maybe a server's):
/// `role write, kind human, workspaces all; token <name>, expires <time>,
/// GitHub user <login>`.
pub fn access_line(summary: &serde_json::Value) -> String {
    let text = |k: &str| summary[k].as_str().unwrap_or("?").to_string();
    let workspaces: Vec<String> = summary["workspaces"]
        .as_array()
        .map(|list| list.iter().filter_map(|w| w.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut line = format!(
        "role {}, kind {}, workspaces {}; token {}",
        text("role"),
        text("kind"),
        workspaces_text(&workspaces),
        text("name")
    );
    if let Some(n) = summary["max_claims"].as_u64() {
        line.push_str(&format!(", at most {n} claims"));
    }
    if let Some(at) = summary["expires_at"].as_str() {
        line.push_str(&format!(", expires {at}"));
    }
    if let Some(at) = summary["refreshable_until"].as_str() {
        line.push_str(&format!(", refreshed until {at}"));
    }
    if let Some(login) = summary["github"]["login"].as_str() {
        line.push_str(&format!(", GitHub user {login}"));
    }
    line
}

impl Token {
    pub fn allows_workspace(&self, workspace: &str) -> bool {
        self.workspaces.iter().any(|w| w == "*" || w == workspace)
    }

    /// The token's actor, or a sub-actor `<actor>/<name>`.
    pub fn allows_actor(&self, actor: &str) -> bool {
        bd_core::policy::is_actor_or_sub_actor(&self.actor, actor)
    }

    /// What the token's requests may override.
    pub fn policy(&self) -> bd_core::Policy {
        bd_core::Policy {
            actor: self.actor.clone(),
            admin: self.role == Role::Admin,
            human: self.kind == Kind::Human,
            max_claims: self.max_claims,
        }
    }

    /// Whether the token no longer works at `now` because it expired.
    pub fn expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }

    /// Whether the token expired and can no longer be refreshed either at `now`.
    fn ended(&self, now: Timestamp) -> bool {
        self.expired(now) && self.refresh.as_ref().is_none_or(|r| r.until <= now)
    }

    /// Until when a refresh may renew it, if it is refreshed.
    fn refreshable_until(&self) -> Option<Timestamp> {
        self.refresh.as_ref().map(|r| r.until)
    }

    /// What `bd info` tells a client of the token it used: never its id or
    /// hash.
    pub fn summary(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "actor": self.actor,
            "role": self.role,
            "kind": self.kind,
            "workspaces": self.workspaces,
            "expires_at": self.expires_at,
            "refreshable_until": self.refreshable_until(),
            "github": self.github,
            "max_claims": self.max_claims,
        })
    }

    fn view(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "name": self.name,
            "actor": self.actor,
            "role": self.role,
            "kind": self.kind,
            "workspaces": self.workspaces,
            "created_at": self.created_at,
            "revoked_at": self.revoked_at,
            "expires_at": self.expires_at,
            "refreshable_until": self.refreshable_until(),
            "github": self.github,
            "max_claims": self.max_claims,
            "resource": self.resource,
        })
    }

    fn describe(&self) -> String {
        let mut text = format!(
            "acts as {0} or {0}/<agent>, role {1}, kind {2}, workspaces {3}",
            self.actor,
            self.role.as_str(),
            self.kind.as_str(),
            workspaces_text(&self.workspaces)
        );
        if let Some(n) = self.max_claims {
            text.push_str(&format!(", at most {n} claims"));
        }
        if let Some(resource) = &self.resource {
            text.push_str(&format!(", only at MCP endpoint {resource}"));
        }
        if let Some(user) = &self.github {
            text.push_str(&format!(", signed in as GitHub user {}", user.login));
        }
        text
    }

    /// Created, and when it expires or expired (and until when it is
    /// refreshed); or when it was revoked.
    fn state(&self, now: Timestamp) -> String {
        let refreshed = match self.refreshable_until() {
            Some(until) if until > now => format!(", refreshed until {until}"),
            _ => String::new(),
        };
        match (&self.revoked_at, self.expires_at) {
            (Some(at), _) => format!("revoked {at}"),
            (None, Some(at)) if at <= now => format!("expired {at}{refreshed}"),
            (None, Some(at)) => format!("created {}, expires {at}{refreshed}", self.created_at),
            (None, None) => format!("created {}", self.created_at),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenFile {
    version: u32,
    tokens: Vec<Token>,
    /// GitHub accounts that signed in: never dropped, so an actor never
    /// passes from one account to another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    accounts: Vec<Account>,
}

pub fn tokens_path(root: &Path) -> PathBuf {
    root.join("tokens.json")
}

/// A lock file, held: released when dropped, or when the process ends.
pub(crate) struct FileLock(std::fs::File);

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

/// Take `<root>/tokens.lock` before changing `tokens.json`, waiting up to [`LOCK_WAIT`].
fn lock_tokens(root: &Path) -> Result<FileLock> {
    lock_file(&root.join("tokens.lock"), "the access tokens")
}

/// Take the lock file `path` before changing the file it guards (`what`,
/// for the error), waiting up to [`LOCK_WAIT`].
pub(crate) fn lock_file(path: &Path, what: &str) -> Result<FileLock> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let io_error = |e: std::io::Error| Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    let file = opts.open(path).map_err(io_error)?;
    let deadline = Instant::now() + LOCK_WAIT;
    let mut delay = Duration::from_millis(5);
    loop {
        // Called through the trait: std's own File::try_lock (Rust 1.89) is newer than bd's MSRV.
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => return Ok(FileLock(file)),
            Err(fs4::TryLockError::WouldBlock) => {}
            Err(fs4::TryLockError::Error(e)) => return Err(io_error(e)),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Busy(format!(
                "another bd process is changing {what} ({} is locked); retry",
                path.display()
            )));
        }
        std::thread::sleep(delay.min(left));
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn load_file(path: &Path) -> Result<TokenFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(TokenFile { version: 1, tokens: Vec::new(), accounts: Vec::new() })
        }
        Err(e) => Err(Error::invalid(format!("{}: {e}", path.display()))),
    }
}

fn save_file(path: &Path, file: &TokenFile) -> Result<()> {
    save_json(path, file)
}

/// Replace the JSON file `path` (mode 0600) with `value`, all or nothing.
pub(crate) fn save_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut text = serde_json::to_string_pretty(value)?;
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
    crate::io::replace_file(&tmp, path)
        .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))))
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

/// What a bearer secret is to [`Verifier::verify`].
#[derive(Debug)]
pub enum Verified {
    /// A live token: neither revoked nor expired.
    Valid(Token),
    /// A token that has expired; it no longer works.
    Expired(Token),
    /// No token that is not revoked has this secret.
    Unknown,
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

    /// The token that is not revoked with this secret, and whether it expired.
    pub fn verify(&self, secret: &str) -> Result<Verified> {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let stamp = std::fs::metadata(&self.path).ok().map(|m| (m.modified().ok(), m.len()));
        if !cache.loaded || stamp != cache.stamp {
            let file = load_file(&self.path)?;
            cache.by_hash =
                file.tokens.into_iter().filter(|t| t.revoked_at.is_none()).map(|t| (t.sha256.clone(), t)).collect();
            cache.stamp = stamp;
            cache.loaded = true;
        }
        Ok(match cache.by_hash.get(&hash(secret)) {
            Some(t) if t.expired(Timestamp::now()) => Verified::Expired(t.clone()),
            Some(t) => Verified::Valid(t.clone()),
            None => Verified::Unknown,
        })
    }

    /// Reread the file at the next check: this process changed it, maybe
    /// too quickly for its modification time and size to tell.
    pub fn invalidate(&self) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).loaded = false;
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
        TokenCommand::Accounts(a) => accounts(app, a),
        TokenCommand::Revoke(a) => revoke(app, a),
    }
}

fn create(app: &mut App, a: &TokenCreateArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    let grant = Grant { role: a.role, kind: a.kind, workspaces: a.workspaces.clone(), max_claims: a.max_claims };
    let holder = Holder::Admin { name: a.name.trim(), actor: a.act_as.trim(), resource: a.resource.as_deref() };
    let (token, secret) = add_token(&root, holder, grant).map(|issued| (issued.token, issued.secret))?;
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
pub fn issue_token(
    root: &Path,
    name: &str,
    actor: &str,
    role: Role,
    kind: Kind,
    workspaces: &[String],
) -> Result<(Token, String)> {
    let grant = Grant { role, kind, workspaces: workspaces.to_vec(), max_claims: None };
    add_token(root, Holder::Admin { name: name.trim(), actor: actor.trim(), resource: None }, grant)
        .map(|issued| (issued.token, issued.secret))
}

/// A token just issued or refreshed, with its secrets, which are not
/// stored anywhere.
pub struct Issued {
    pub token: Token,
    pub secret: String,
    /// The refresh secret, for a token that is refreshed.
    pub refresh_secret: Option<String>,
}

/// How long a GitHub sign-in's tokens last.
#[derive(Clone, Copy, Debug)]
pub struct Lifetime {
    /// How long each access token works.
    pub ttl: Duration,
    /// Until when its refreshes may renew it, if it is refreshed: they ask
    /// GitHub again, by the workspace it signed in for.
    pub refresh: Option<(Timestamp, Duration)>,
}

/// Add an access token for a GitHub account that signed in for
/// `workspace`. It acts as the account's actor: the one bound to it at an
/// earlier sign-in, else its login, bound to it now. It is named
/// `github-<actor>-<random>` (the actor cut to 40 characters), and expires
/// after `life.ttl`; with `life.refresh`, `(limit, idle)`, it may be
/// refreshed until the earlier of `limit` and `idle` after each refresh.
pub fn issue_github_token(
    root: &Path,
    user: &GithubUser,
    grant: Grant,
    life: Lifetime,
    workspace: &str,
    by_login: bool,
) -> Result<Issued> {
    let now = Timestamp::now();
    let refresh = life.refresh.map(|(limit, idle)| (workspace, limit.min(now.plus(idle))));
    let expires_at = now.plus(life.ttl).min(refresh.map_or(Timestamp(i64::MAX), |(_, until)| until));
    add_token(root, Holder::Github { user, expires_at, by_login, refresh }, grant)
}

/// The sign-in whose refresh secret this is, unless revoked: its token, and
/// whether the secret is its current one (else it is spent, or forged).
pub fn find_refresh(root: &Path, secret: &str) -> Result<Option<(Token, bool)>> {
    let Some(family) = refresh_family(secret) else { return Ok(None) };
    let file = load_file(&tokens_path(root))?;
    let found = file
        .tokens
        .into_iter()
        .find(|t| t.revoked_at.is_none() && t.refresh.as_ref().is_some_and(|r| r.family.eq_ignore_ascii_case(family)));
    Ok(found.map(|t| {
        let current = t.refresh.as_ref().is_some_and(|r| r.sha256 == hash(secret));
        (t, current)
    }))
}

/// Refresh the sign-in `id`, whose current refresh secret hashes to
/// `current`, for the request `last` (the secret it presents, and its
/// request id): new secrets, the account as GitHub names it now, what the
/// rules grant it now, expiring at `expires_at` and refreshed until
/// `until`. `None` when `current` is no longer the sign-in's (another
/// refresh changed it meanwhile), or the sign-in was revoked.
#[allow(clippy::too_many_arguments)]
pub fn rotate(
    root: &Path,
    id: &str,
    current: &str,
    last: LastRefresh,
    user: &GithubUser,
    grant: Grant,
    by_login: bool,
    expires_at: Timestamp,
    until: Timestamp,
) -> Result<Option<Issued>> {
    let workspaces = workspace_list(&grant.workspaces)?;
    let path = tokens_path(root);
    let _lock = lock_tokens(root)?;
    let mut file = load_file(&path)?;
    let now = Timestamp::now();
    let live =
        |t: &Token| t.id == id && t.revoked_at.is_none() && t.refresh.as_ref().is_some_and(|r| r.sha256 == current);
    let Some(i) = file.tokens.iter().position(live) else { return Ok(None) };
    let actor = bind(&mut file.accounts, user, now, by_login)?;
    if actor != file.tokens[i].actor {
        return Err(Error::Unauthorized(format!(
            "GitHub user {} now acts as {actor}, not {}: sign in again (`bd remote login --github`)",
            user.login, file.tokens[i].actor
        )));
    }
    if by_login && !related(&actor, &user.login) {
        if let Some(other) = actor_conflict(&file.tokens, &user.login, Some(user), now) {
            return Err(conflict_error(&user.login, Some(user), other));
        }
    }
    if let Some(other) = actor_conflict(&file.tokens, &actor, Some(user), now) {
        return Err(conflict_error(&actor, Some(user), other));
    }
    let secret = format!("bdt_{}", random_hex(32)?);
    let t = &mut file.tokens[i];
    let refresh = t.refresh.as_mut().expect("found by its refresh state");
    let refresh_secret = refresh_secret(&refresh.family)?;
    refresh.sha256 = hash(&refresh_secret);
    refresh.refreshed_at = now;
    refresh.until = until;
    refresh.last = Some(last);
    t.sha256 = hash(&secret);
    t.expires_at = Some(expires_at.min(until));
    t.role = grant.role;
    t.kind = grant.kind;
    t.workspaces = workspaces;
    t.max_claims = grant.max_claims;
    t.github = Some(user.clone());
    let token = t.clone();
    save_file(&path, &file)?;
    Ok(Some(Issued { token, secret, refresh_secret: Some(refresh_secret) }))
}

/// Whom a new token is for.
enum Holder<'a> {
    /// An admin names it, its actor, and maybe the MCP endpoint it is bound to.
    Admin { name: &'a str, actor: &'a str, resource: Option<&'a str> },
    /// A GitHub account that signed in; `by_login` when a rule let it in by
    /// its login; `refresh`, the workspace it signed in for and until when
    /// it may be refreshed, if it may.
    Github { user: &'a GithubUser, expires_at: Timestamp, by_login: bool, refresh: Option<(&'a str, Timestamp)> },
}

fn check_name(name: &str) -> Result<()> {
    let ok = name.len() <= 64
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    match ok {
        true => Ok(()),
        false => Err(Error::invalid(format!(
            "invalid token name {name:?}: a letter or digit, then letters, digits, '.', '_' or '-' (at most 64)"
        ))),
    }
}

fn check_actor(actor: &str) -> Result<()> {
    bd_core::store::validate_actor(actor)?;
    if actor.starts_with('/') || actor.ends_with('/') || actor.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "invalid actor {actor:?}: no control characters, and no '/' at either end"
        )));
    }
    Ok(())
}

fn add_token(root: &Path, holder: Holder, grant: Grant) -> Result<Issued> {
    let mut workspaces = workspace_list(&grant.workspaces)?;
    let mut resource = None;
    if let Holder::Admin { resource: Some(url), .. } = &holder {
        let (url, workspace) =
            crate::mcp::http::resource_url(url).map_err(|e| Error::invalid(format!("--resource {e}")))?;
        if !workspaces.iter().any(|w| w == "*" || *w == workspace) {
            return Err(Error::invalid(format!(
                "--resource {url} is workspace {workspace}'s, which the token may not use"
            )));
        }
        // A bound token works at that workspace only.
        workspaces = vec![workspace];
        resource = Some(url);
    }
    if let Holder::Admin { name, actor, .. } = &holder {
        check_name(name)?;
        check_actor(actor)?;
        if is_reserved_actor(actor) {
            return Err(Error::invalid(format!(
                "actor {actor} is reserved for bd serve's background writes: pick another actor"
            )));
        }
    }
    let path = tokens_path(root);
    let _lock = lock_tokens(root)?;
    let mut file = load_file(&path)?;
    let now = Timestamp::now();
    // Tokens from GitHub sign-in stay listed for a while after they expire (and can no longer be refreshed), then go.
    file.tokens.retain(|t| t.github.is_none() || !t.ended(now.minus(PRUNE_AFTER)));
    let (name, actor, expires_at, github, refresh) = match holder {
        Holder::Admin { name, actor, .. } => {
            if let Some(account) = file.accounts.iter().find(|a| related(&a.actor, actor)) {
                return Err(Error::Refused(format!(
                    "actor {actor} would share actor {} with GitHub user {}, who signed in: pick another actor, or \
                     release that one first (`bd serve token revoke --github {} --forget`)",
                    account.actor, account.login, account.login
                )));
            }
            (name.to_string(), actor.to_string(), None, None, None)
        }
        Holder::Github { user, expires_at, by_login, refresh } => {
            let actor = bind(&mut file.accounts, user, now, by_login)?;
            if is_reserved_actor(&actor) {
                return Err(Error::Unauthorized(format!(
                    "GitHub user {} may not sign in to this bd server: its actor {actor} is bd serve's own",
                    user.login
                )));
            }
            // A renamed account let in by a login that names another principal's actor must not pass for it.
            if by_login && !related(&actor, &user.login) {
                if let Some(other) = actor_conflict(&file.tokens, &user.login, Some(user), now) {
                    return Err(conflict_error(&user.login, Some(user), other));
                }
            }
            let label: String = actor.chars().take(40).collect();
            let name = format!("github-{label}-{}", random_hex(4)?);
            check_name(&name)?;
            check_actor(&actor)?;
            (name, actor, Some(expires_at), Some(user.clone()), refresh)
        }
    };
    if file.tokens.iter().any(|t| t.name == name && t.revoked_at.is_none()) {
        return Err(Error::Refused(format!("access token {name} already exists; revoke it first")));
    }
    if let Some(other) = actor_conflict(&file.tokens, &actor, github.as_ref(), now) {
        return Err(conflict_error(&actor, github.as_ref(), other));
    }
    let secret = format!("bdt_{}", random_hex(32)?);
    let (refresh, refresh_secret) = match refresh {
        Some((workspace, until)) => {
            let family = random_hex(16)?;
            let secret = refresh_secret(&family)?;
            let state = Refresh {
                family,
                sha256: hash(&secret),
                workspace: workspace.to_string(),
                refreshed_at: now,
                until,
                last: None,
            };
            (Some(state), Some(secret))
        }
        None => (None, None),
    };
    let token = Token {
        id: random_hex(8)?,
        name,
        actor,
        role: grant.role,
        kind: grant.kind,
        workspaces,
        sha256: hash(&secret),
        created_at: now.to_rfc3339(),
        revoked_at: None,
        expires_at,
        github,
        max_claims: grant.max_claims,
        refresh,
        resource,
    };
    file.tokens.push(token.clone());
    save_file(&path, &file)?;
    Ok(Issued { token, secret, refresh_secret })
}

/// The actor of `user`'s tokens: the one bound to its account, else its
/// login, bound to it now. Refused while the login would bind another
/// account's actor; and, when a rule let the account in `by_login`, while
/// another account's actor or latest login is related to it, even for an
/// account bound before: one that took a login given up must not pass for
/// its previous holder, whom rules name by it.
fn bind(accounts: &mut Vec<Account>, user: &GithubUser, now: Timestamp, by_login: bool) -> Result<String> {
    let bound = accounts.iter().any(|a| a.is(user));
    let taken = |a: &Account| {
        let actor = related(&a.actor, &user.login) && (!bound || by_login);
        let login = by_login && related(&a.login, &user.login);
        !a.is(user) && (actor || login)
    };
    if let Some(other) = accounts.iter().find(|a| taken(a)) {
        tracing::info!(
            target: "bd::serve",
            login = %user.login,
            id = user.id,
            actor = %other.actor,
            bound_to = other.id,
            "GitHub sign-in refused: the login's actor belongs to another account"
        );
        let whose = match related(&other.actor, &user.login) {
            true => format!("actor {} belongs to another GitHub account, which had that login before", other.actor),
            false => format!("login {} was that of another GitHub account (actor {}) before", other.login, other.actor),
        };
        return Err(Error::Unauthorized(format!(
            "GitHub user {} may not sign in to this bd server: {whose}; the server's admin resolves that (`bd serve \
             token accounts`)",
            user.login
        )));
    }
    if let Some(account) = accounts.iter_mut().find(|a| a.is(user)) {
        account.login = user.login.clone();
        account.last_seen = now;
        return Ok(account.actor.clone());
    }
    accounts.push(Account {
        url: user.url.clone(),
        id: user.id,
        actor: user.login.clone(),
        login: user.login.clone(),
        first_seen: now,
        last_seen: now,
    });
    Ok(user.login.clone())
}

/// A live token of another principal whose actor a new token's would share,
/// or cover with sub-actors: a GitHub account's against an admin's or
/// another account's, and the other way round. Tokens an admin creates may
/// share actors among themselves.
fn actor_conflict<'a>(
    tokens: &'a [Token],
    actor: &str,
    github: Option<&GithubUser>,
    now: Timestamp,
) -> Option<&'a Token> {
    tokens.iter().filter(|t| t.revoked_at.is_none() && !t.expired(now)).find(|t| match (github, &t.github) {
        (None, None) => false,
        (Some(user), Some(other)) => related(actor, &t.actor) && !(other.id == user.id && other.url == user.url),
        _ => related(actor, &t.actor),
    })
}

fn conflict_error(actor: &str, github: Option<&GithubUser>, other: &Token) -> Error {
    match (github, &other.github) {
        (Some(user), _) => {
            tracing::info!(
                target: "bd::serve",
                login = %user.login,
                id = user.id,
                token = %other.name,
                actor = %other.actor,
                "GitHub sign-in refused: another token's actor"
            );
            Error::Unauthorized(format!(
                "GitHub user {} may not sign in to this bd server as actor {actor}: another access token acts as {}; \
                 the server's admin resolves that (`bd serve token list`)",
                user.login, other.actor
            ))
        }
        (None, Some(owner)) => Error::Refused(format!(
            "actor {actor} would share actor {} with GitHub user {}, who signed in: pick another actor, or release \
             that one first (`bd serve token revoke --github {} --forget`)",
            other.actor, owner.login, owner.login
        )),
        (None, None) => Error::Refused(format!("actor {actor} is taken by access token {}", other.name)),
    }
}

fn list(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = load_file(&tokens_path(&root_dir(a)?))?;
    let now = Timestamp::now();
    let mut out = Out::new(file.tokens.iter().map(Token::view).collect::<Vec<_>>());
    if file.tokens.is_empty() {
        out = out.line(
            "No access tokens. Create one with `bd serve token create <name> --as <actor>`, or let people sign in \
             with GitHub (auth.toml).",
        );
    }
    for t in &file.tokens {
        out = out.line(format!("{:<20} {}  ({})", t.name, t.describe(), t.state(now))).id(t.name.clone());
    }
    app.print(out);
    Ok(())
}

fn accounts(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = load_file(&tokens_path(&root_dir(a)?))?;
    let now = Timestamp::now();
    let live = |account: &Account| {
        let live = |t: &&Token| t.revoked_at.is_none() && !t.expired(now);
        file.tokens.iter().filter(live).filter(|t| t.github.as_ref().is_some_and(|g| account.is(g))).count()
    };
    let views: Vec<serde_json::Value> = file
        .accounts
        .iter()
        .map(|account| {
            let mut view = json!(account);
            view["live_tokens"] = json!(live(account));
            view
        })
        .collect();
    let mut out = Out::new(views);
    if file.accounts.is_empty() {
        out = out.line("No GitHub account is bound to an actor.");
    }
    for account in &file.accounts {
        let n = live(account);
        out = out
            .line(format!(
                "{:<20} GitHub user {} (id {} at {}), signed in first {}, last {}; {n} live token{}",
                account.actor,
                account.login,
                account.id,
                account.url,
                account.first_seen,
                account.last_seen,
                if n == 1 { "" } else { "s" }
            ))
            .id(account.actor.clone());
    }
    app.print(out);
    Ok(())
}

fn revoke(app: &mut App, a: &TokenRevokeArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    match (&a.name, a.github.as_deref().map(str::trim)) {
        (Some(name), None) => {
            let named = |tokens: &[Token]| (0..tokens.len()).filter(|&i| tokens[i].name == *name).collect();
            let (known, revoked) = revoke_where(&root, named)?;
            if known == 0 {
                return Err(Error::not_found("access token", name.as_str()));
            }
            let text = match revoked.is_empty() {
                true => format!("= {name} was already revoked"),
                false => format!("✓ Revoked access token {name}"),
            };
            app.print(Out::new(json!({ "name": name, "revoked": !revoked.is_empty() })).line(text).id(name.clone()));
        }
        (None, Some(login)) => {
            let done = revoke_github(&root, login, a.forget)?;
            let view =
                json!({ "github": login, "revoked": done.revoked, "accounts": done.accounts, "forgot": a.forget });
            let mut out = Out::new(view).line(match done.revoked.len() {
                0 => format!("= GitHub user {login} has no live access tokens"),
                1 => format!("✓ Revoked the access token of GitHub user {login}: {}", done.revoked[0]),
                n => format!("✓ Revoked {n} access tokens of GitHub user {login}: {}", done.revoked.join(", ")),
            });
            for account in &done.accounts {
                out = out.line(match a.forget {
                    true => format!(
                        "✓ Released actor {} of GitHub user {} (id {}): the next account to sign in as {} gets it",
                        account.actor, account.login, account.id, account.actor
                    ),
                    false => format!(
                        "  actor {} stays bound to GitHub user {} (id {}); --forget releases it",
                        account.actor, account.login, account.id
                    ),
                });
            }
            app.print(done.revoked.iter().fold(out, |out, name| out.id(name.clone())));
        }
        _ => return Err(Error::invalid("name the access token to revoke, or a GitHub user with --github")),
    }
    Ok(())
}

/// Revoke the token with this id (not its name, which a later token may
/// reuse): whether it was revoked now.
pub fn revoke_by_id(root: &Path, id: &str) -> Result<bool> {
    let (_, revoked) = revoke_where(root, |tokens| (0..tokens.len()).filter(|&i| tokens[i].id == id).collect())?;
    Ok(!revoked.is_empty())
}

/// Revoke the tokens `pick` selects (indexes): how many it selects, and the
/// names of those revoked now (the others already were).
fn revoke_where(root: &Path, pick: impl FnOnce(&[Token]) -> Vec<usize>) -> Result<(usize, Vec<String>)> {
    let path = tokens_path(root);
    let _lock = lock_tokens(root)?;
    let mut file = load_file(&path)?;
    let picked = pick(&file.tokens);
    let now = Timestamp::now().to_rfc3339();
    let mut revoked = Vec::new();
    for &i in &picked {
        let t = &mut file.tokens[i];
        if t.revoked_at.is_none() {
            t.revoked_at = Some(now.clone());
            revoked.push(t.name.clone());
        }
    }
    if !revoked.is_empty() {
        save_file(&path, &file)?;
    }
    Ok((picked.len(), revoked))
}

/// What `revoke --github` did.
#[derive(Debug)]
struct GithubRevoked {
    /// The accounts known by the login: their latest login, or their actor.
    accounts: Vec<Account>,
    /// Names of the tokens revoked now (the others already were).
    revoked: Vec<String>,
}

/// Revoke every token of the GitHub accounts known by `login` (their latest
/// login, or their actor), and any token that signed in as it, so that the
/// tokens from before a rename go too; with `forget`, also release those
/// accounts' actors.
fn revoke_github(root: &Path, login: &str, forget: bool) -> Result<GithubRevoked> {
    let path = tokens_path(root);
    let _lock = lock_tokens(root)?;
    let mut file = load_file(&path)?;
    let named = |s: &str| s.eq_ignore_ascii_case(login);
    let accounts: Vec<Account> = file.accounts.iter().filter(|a| named(&a.login) || named(&a.actor)).cloned().collect();
    let theirs = |t: &Token| t.github.as_ref().is_some_and(|g| named(&g.login) || accounts.iter().any(|a| a.is(g)));
    let picked: Vec<usize> = (0..file.tokens.len()).filter(|&i| theirs(&file.tokens[i])).collect();
    if accounts.is_empty() && picked.is_empty() {
        return Err(Error::not_found("GitHub user with access tokens", login));
    }
    let now = Timestamp::now().to_rfc3339();
    let mut revoked = Vec::new();
    for i in picked {
        let t = &mut file.tokens[i];
        if t.revoked_at.is_none() {
            t.revoked_at = Some(now.clone());
            revoked.push(t.name.clone());
        }
    }
    let forgotten = forget && !accounts.is_empty();
    if forgotten {
        file.accounts.retain(|a| !accounts.contains(a));
    }
    if !revoked.is_empty() || forgotten {
        save_file(&path, &file)?;
    }
    Ok(GithubRevoked { accounts, revoked })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sign-in token lasting `ttl`, not refreshed.
    fn github_token(
        root: &Path,
        user: &GithubUser,
        grant: Grant,
        ttl: Duration,
        by_login: bool,
    ) -> Result<(Token, String)> {
        let life = Lifetime { ttl, refresh: None };
        issue_github_token(root, user, grant, life, "proj", by_login).map(|i| (i.token, i.secret))
    }

    fn token(actor: &str, workspaces: &[&str]) -> Token {
        Token {
            id: "id".into(),
            name: "n".into(),
            actor: actor.into(),
            role: Role::Write,
            kind: Kind::Agent,
            workspaces: workspaces.iter().map(|s| s.to_string()).collect(),
            sha256: String::new(),
            created_at: String::new(),
            revoked_at: None,
            expires_at: None,
            github: None,
            max_claims: None,
            refresh: None,
            resource: None,
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
        let actor = |secret: &str| match v.verify(secret).unwrap() {
            Verified::Valid(t) => Some(t.actor),
            Verified::Expired(t) => panic!("{} expired", t.name),
            Verified::Unknown => None,
        };
        assert_eq!(actor("bdt_x"), None, "no file yet");
        let mut t = token("alice", &["*"]);
        t.sha256 = hash("bdt_secret");
        save_file(&path, &TokenFile { version: 1, tokens: vec![t.clone()], accounts: Vec::new() }).unwrap();
        assert_eq!(actor("bdt_secret"), Some("alice".to_string()));
        assert_eq!(actor("bdt_other"), None);
        t.revoked_at = Some("2026-01-01T00:00:00Z".into());
        save_file(&path, &TokenFile { version: 1, tokens: vec![t], accounts: Vec::new() }).unwrap();
        assert_eq!(actor("bdt_secret"), None, "revocation applies without a restart");
    }

    #[test]
    fn expired_tokens_are_told_apart_and_never_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = tokens_path(dir.path());
        let mut t = token("alice", &["*"]);
        t.sha256 = hash("bdt_secret");
        t.expires_at = Some(Timestamp::now().plus(Duration::from_secs(3600)));
        save_file(&path, &TokenFile { version: 1, tokens: vec![t.clone()], accounts: Vec::new() }).unwrap();
        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Valid(_)));
        t.expires_at = Some(Timestamp::now().minus(Duration::from_secs(1)));
        save_file(&path, &TokenFile { version: 1, tokens: vec![t.clone()], accounts: Vec::new() }).unwrap();
        v.invalidate();
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Expired(e) if e.name == "n"));
        let text = std::fs::read_to_string(&path).unwrap();
        let stamp = t.expires_at.unwrap().to_rfc3339();
        std::fs::write(&path, text.replace(&stamp, "soon")).unwrap();
        v.invalidate();
        assert!(v.verify("bdt_secret").is_err(), "an expiry that is not a time fails closed");
        t.revoked_at = Some(Timestamp::now().to_rfc3339());
        save_file(&path, &TokenFile { version: 1, tokens: vec![t], accounts: Vec::new() }).unwrap();
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Unknown), "revoked, whether expired or not");
    }

    const GITHUB: &str = "https://github.com";

    fn gh(login: &str, id: u64) -> GithubUser {
        GithubUser { url: GITHUB.into(), login: login.into(), id }
    }

    #[test]
    fn github_sign_ins_get_expiring_tokens_named_after_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let alice = gh("Alice-GH", 42);
        let grant = Grant {
            role: Role::Read,
            kind: Kind::Human,
            workspaces: vec!["proj".into(), " ".into()],
            max_claims: None,
        };
        let ttl = Duration::from_secs(30 * 24 * 3600);
        let before = Timestamp::now();
        let (t, secret) = github_token(dir.path(), &alice, grant.clone(), ttl, true).unwrap();
        assert!(secret.starts_with("bdt_") && t.sha256 == hash(&secret));
        assert!(t.name.starts_with("github-Alice-GH-") && t.name.len() == "github-Alice-GH-".len() + 8, "{}", t.name);
        assert_eq!((t.actor.as_str(), t.role, t.kind), ("Alice-GH", Role::Read, Kind::Human));
        assert_eq!(t.workspaces, ["proj"]);
        assert_eq!(t.github.as_ref(), Some(&alice));
        let expires = t.expires_at.unwrap();
        assert!(expires >= before.plus(ttl) && expires <= Timestamp::now().plus(ttl));
        assert!(t.describe().contains("signed in as GitHub user Alice-GH"), "{}", t.describe());
        assert!(t.state(Timestamp::now()).contains("expires"), "{}", t.state(Timestamp::now()));
        assert!(t.state(expires).starts_with("expired"));
        let (again, _) = github_token(dir.path(), &alice, grant.clone(), ttl, true).unwrap();
        assert_ne!(again.name, t.name, "each sign-in gets a token of its own");
        let long = gh(&"a".repeat(60), 7);
        let (t, _) = github_token(dir.path(), &long, grant, ttl, true).unwrap();
        assert_eq!((t.actor.len(), t.name.len()), (60, "github-".len() + 40 + 9), "the actor keeps the whole login");

        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify(&secret).unwrap(), Verified::Valid(v) if v.github == Some(alice.clone())));
    }

    #[test]
    fn long_expired_github_tokens_are_dropped_when_a_token_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = tokens_path(dir.path());
        let now = Timestamp::now();
        let entry = |name: &str, expired_ago: Option<Duration>, github: bool| {
            let mut t = token("alice", &["*"]);
            t.name = name.into();
            t.expires_at = expired_ago.map(|d| now.minus(d));
            t.github = github.then(|| gh("alice", 1));
            t
        };
        let day = Duration::from_secs(24 * 3600);
        let tokens = vec![
            entry("old-sign-in", Some(PRUNE_AFTER + day), true),
            entry("recent-sign-in", Some(day), true),
            entry("manual", None, false),
            entry("manual-expired", Some(PRUNE_AFTER + day), false),
        ];
        save_file(&path, &TokenFile { version: 1, tokens, accounts: Vec::new() }).unwrap();
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let names: Vec<String> = load_file(&path).unwrap().tokens.into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["recent-sign-in", "manual", "manual-expired", "ci"]);
    }

    #[test]
    fn refreshable_sign_ins_stay_listed_until_they_can_no_longer_be_refreshed() {
        let dir = tempfile::tempdir().unwrap();
        let path = tokens_path(dir.path());
        let now = Timestamp::now();
        let day = Duration::from_secs(24 * 3600);
        let entry = |name: &str, until: Timestamp| {
            let mut t = token("alice", &["*"]);
            t.name = name.into();
            t.expires_at = Some(now.minus(PRUNE_AFTER + day));
            t.github = Some(gh("alice", 1));
            let family = "0".repeat(32);
            t.refresh = Some(Refresh {
                family,
                sha256: String::new(),
                workspace: "proj".into(),
                refreshed_at: now,
                until,
                last: None,
            });
            t
        };
        let tokens = vec![entry("refreshable", now.plus(day)), entry("ended", now.minus(PRUNE_AFTER + day))];
        save_file(&path, &TokenFile { version: 1, tokens, accounts: Vec::new() }).unwrap();
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let names: Vec<String> = load_file(&path).unwrap().tokens.into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["refreshable", "ci"]);
    }

    #[test]
    fn sign_ins_rotate_their_secrets_and_spent_ones_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let alice = gh("alice", 1);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let now = Timestamp::now();
        let life = Lifetime { ttl: hour, refresh: Some((now.plus(week * 4), week)) };
        let issued = issue_github_token(dir.path(), &alice, grant.clone(), life, "proj", true).unwrap();
        let first = issued.refresh_secret.expect("refreshed");
        assert!(first.starts_with("bdr_") && refresh_family(&first).is_some(), "{}", first.len());
        let t = issued.token;
        let state = t.refresh.clone().unwrap();
        assert_eq!(state.workspace, "proj");
        assert!(state.until >= now.plus(week) && state.until <= Timestamp::now().plus(week), "idle, not the limit");
        assert!(t.expires_at.unwrap() <= Timestamp::now().plus(hour));
        assert!(t.summary()["refreshable_until"].is_string() && !t.summary().to_string().contains(&state.family));
        let (found, current) = find_refresh(dir.path(), &first).unwrap().unwrap();
        assert!(current && found.id == t.id);

        let verifier = Verifier::new(dir.path());
        assert!(matches!(verifier.verify(&issued.secret).unwrap(), Verified::Valid(_)));
        let read = Grant { role: Role::Read, ..grant.clone() };
        let renamed = gh("alice-new", 1);
        let (expires, until) = (now.plus(hour * 2), now.plus(week));
        let last = |secret: &str, id: &str| LastRefresh { spent: hash(secret), request: hash(id) };
        let rotated =
            rotate(dir.path(), &t.id, &hash(&first), last(&first, "r1"), &renamed, read, true, expires, until)
                .unwrap()
                .unwrap();
        let second = rotated.refresh_secret.unwrap();
        let r = rotated.token;
        assert_eq!((r.id.as_str(), r.name.as_str(), r.actor.as_str()), (t.id.as_str(), t.name.as_str(), "alice"));
        assert_eq!((r.role, r.github.as_ref().unwrap().login.as_str()), (Role::Read, "alice-new"), "the rules now");
        assert_eq!((r.expires_at, r.refresh.as_ref().unwrap().until), (Some(expires), until));
        assert_eq!(load_file(&tokens_path(dir.path())).unwrap().tokens.len(), 1, "replaced in place");
        verifier.invalidate();
        assert!(matches!(verifier.verify(&issued.secret).unwrap(), Verified::Unknown), "the old secret is gone");
        assert!(matches!(verifier.verify(&rotated.secret).unwrap(), Verified::Valid(_)));

        assert!(!find_refresh(dir.path(), &first).unwrap().unwrap().1, "spent");
        assert!(find_refresh(dir.path(), &second).unwrap().unwrap().1);
        let again =
            rotate(dir.path(), &t.id, &hash(&first), last(&first, "r2"), &renamed, grant.clone(), true, expires, until);
        assert!(again.unwrap().is_none(), "a spent secret rotates nothing");
        let state = find_refresh(dir.path(), &second).unwrap().unwrap().0.refresh.unwrap();
        assert!(state.retries_last(&first, "r1"), "the latest refresh, sent again");
        assert!(!state.retries_last(&first, "r2") && !state.retries_last(&second, "r1"));
        let forged = format!("{}_{}", &second[..36], "0".repeat(64));
        assert!(!find_refresh(dir.path(), &forged).unwrap().unwrap().1, "the family alone is not enough");
        for bad in ["bdt_x", "bdr_", "bdr_xyz_abc", &second[..second.len() - 1]] {
            assert!(find_refresh(dir.path(), bad).unwrap().is_none(), "{bad}");
        }
        assert!(revoke_by_id(dir.path(), &t.id).unwrap());
        assert!(find_refresh(dir.path(), &second).unwrap().is_none(), "revoked");

        let once = Lifetime { ttl: hour, refresh: None };
        let plain = issue_github_token(dir.path(), &alice, grant, once, "proj", true).unwrap();
        assert!(plain.refresh_secret.is_none() && plain.token.refresh.is_none());
    }

    #[test]
    fn github_accounts_keep_their_actor_through_renames_and_after_their_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = tokens_path(dir.path());
        let hour = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let sign_in = |user: &GithubUser| github_token(dir.path(), user, grant.clone(), hour, true);
        let accounts = || load_file(&path).unwrap().accounts;

        let (first, _) = sign_in(&gh("alice", 1)).unwrap();
        assert_eq!(first.actor, "alice");
        let bound = accounts();
        assert_eq!((bound.len(), bound[0].actor.as_str(), bound[0].first_seen), (1, "alice", bound[0].last_seen));

        // Renamed at GitHub: the same account, the same actor.
        let (renamed, _) = sign_in(&gh("alice-smith", 1)).unwrap();
        assert_eq!(renamed.actor, "alice");
        assert!(renamed.name.starts_with("github-alice-"), "{}", renamed.name);
        assert_eq!(renamed.github.as_ref().map(|g| g.login.as_str()), Some("alice-smith"));
        let bound = accounts();
        assert_eq!((bound.len(), bound[0].login.as_str()), (1, "alice-smith"), "the latest login");
        assert!(bound[0].last_seen >= bound[0].first_seen);

        // Another account that took the login is refused, even once the first account's tokens are gone.
        let e = sign_in(&gh("Alice", 2)).unwrap_err();
        assert!(e.exit_code() == 7 && e.to_string().contains("belongs to another GitHub account"), "{e}");
        revoke_github(dir.path(), "alice", false).unwrap();
        let mut file = load_file(&path).unwrap();
        for t in &mut file.tokens {
            t.expires_at = Some(Timestamp::now().minus(PRUNE_AFTER + hour));
        }
        save_file(&path, &file).unwrap();
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        assert_eq!(load_file(&path).unwrap().tokens.len(), 1, "alice's tokens were pruned");
        assert!(sign_in(&gh("alice", 2)).is_err(), "the binding outlives the tokens");
        let e = issue_token(dir.path(), "x", "alice/ci", Role::Write, Kind::Agent, &[]).unwrap_err();
        assert!(e.to_string().contains("bd serve token revoke --github alice-smith --forget"), "{e}");

        // An id at another GitHub is another account.
        let (other, _) =
            sign_in(&GithubUser { url: "https://ghe.example.com".into(), login: "bob".into(), id: 1 }).unwrap();
        assert_eq!(other.actor, "bob");
        assert_eq!(accounts().len(), 2);

        // Released, the actor goes to the next account signing in as it.
        let done = revoke_github(dir.path(), "alice-smith", true).unwrap();
        assert_eq!((done.accounts.len(), done.revoked.len()), (1, 0), "{done:?}");
        assert_eq!(accounts().len(), 1);
        assert_eq!(sign_in(&gh("alice", 2)).unwrap().0.actor, "alice");
    }

    #[test]
    fn revoking_by_github_user_takes_all_of_their_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let ttl = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (a1, _) = github_token(dir.path(), &gh("Alice", 1), grant.clone(), ttl, true).unwrap();
        let (a2, _) = github_token(dir.path(), &gh("alice-new", 1), grant.clone(), ttl, true).unwrap();
        let (b, _) = github_token(dir.path(), &gh("bob", 2), grant, ttl, true).unwrap();
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let mut done = revoke_github(dir.path(), "ALICE-NEW", false).unwrap();
        done.revoked.sort();
        let mut expected = vec![a1.name, a2.name];
        expected.sort();
        assert_eq!(done.revoked, expected, "by account: tokens from before a rename go too");
        assert_eq!(done.accounts.iter().map(|a| a.actor.as_str()).collect::<Vec<_>>(), ["Alice"]);
        let again = revoke_github(dir.path(), "alice", false).unwrap();
        assert!(again.revoked.is_empty() && again.accounts.len() == 1, "known by its actor too: {again:?}");
        assert_eq!(revoke_github(dir.path(), "nobody", false).unwrap_err().exit_code(), 3);
        let live: Vec<String> = load_file(&tokens_path(dir.path()))
            .unwrap()
            .tokens
            .into_iter()
            .filter(|t| t.revoked_at.is_none())
            .map(|t| t.name)
            .collect();
        assert_eq!(live, [b.name, "ci".to_string()]);
    }

    #[test]
    fn github_accounts_never_share_actors_with_other_principals() {
        let dir = tempfile::tempdir().unwrap();
        let ttl = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let manual = |name: &str, actor: &str| issue_token(dir.path(), name, actor, Role::Write, Kind::Agent, &[]);
        manual("ci", "ci-agents").unwrap();
        manual("carol-ci", "carol/ci").unwrap();
        for (login, id) in [("ci-agents", 1), ("CI-Agents", 1), ("carol", 2)] {
            let e = github_token(dir.path(), &gh(login, id), grant.clone(), ttl, true).unwrap_err();
            assert_eq!(e.exit_code(), 7, "{login}: {e}");
            assert!(e.to_string().contains("another access token acts as"), "{e}");
        }
        assert!(load_file(&tokens_path(dir.path())).unwrap().accounts.is_empty(), "a refused sign-in binds nothing");
        github_token(dir.path(), &gh("alice", 3), grant.clone(), ttl, true).unwrap();
        github_token(dir.path(), &gh("alice", 3), grant.clone(), ttl, true).unwrap();
        assert!(github_token(dir.path(), &gh("Alice", 4), grant.clone(), ttl, true).is_err(), "another account");
        for actor in ["alice", "ALICE/ci"] {
            let e = manual("x", actor).unwrap_err();
            assert!(e.to_string().contains("bd serve token revoke --github alice --forget"), "{e}");
        }
        manual("alice2", "alice2").unwrap();

        // Revoked, an account keeps its actor; released, the actor is free again. Admins' tokens may share theirs.
        revoke_github(dir.path(), "alice", false).unwrap();
        assert!(github_token(dir.path(), &gh("alice", 4), grant.clone(), ttl, true).is_err());
        assert!(manual("x", "alice").is_err());
        revoke_github(dir.path(), "alice", true).unwrap();
        github_token(dir.path(), &gh("alice", 4), grant, ttl, true).unwrap();
        manual("ci-2", "ci-agents").unwrap();
    }

    #[test]
    fn the_servers_own_actor_is_never_a_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let ttl = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        for actor in ["bd-serve", "BD-Serve", "bd-serve/jobs"] {
            let e = issue_token(dir.path(), "x", actor, Role::Admin, Kind::Agent, &[]).unwrap_err();
            assert!(e.exit_code() == 2 && e.to_string().contains("reserved"), "{actor}: {e}");
            let e = github_token(dir.path(), &gh(actor, 1), grant.clone(), ttl, true).unwrap_err();
            assert!(e.exit_code() == 7 && e.to_string().contains("bd serve's own"), "{actor}: {e}");
        }
        let file = load_file(&tokens_path(dir.path())).unwrap();
        assert!(file.tokens.is_empty() && file.accounts.is_empty(), "nothing issued, nothing bound");
        for (name, actor) in [("a", "bd-server"), ("b", "bd"), ("c", "alice/bd-serve")] {
            issue_token(dir.path(), name, actor, Role::Write, Kind::Agent, &[]).unwrap();
        }
    }

    #[test]
    fn writers_wait_for_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_tokens(dir.path()).unwrap();
        let root = dir.path().to_path_buf();
        let writer = std::thread::spawn(move || issue_token(&root, "ci", "ci", Role::Write, Kind::Agent, &[]));
        std::thread::sleep(Duration::from_millis(200));
        assert!(!tokens_path(dir.path()).exists(), "nothing is written while another holds the lock");
        drop(held);
        writer.join().unwrap().unwrap();
        assert_eq!(load_file(&tokens_path(dir.path())).unwrap().tokens.len(), 1);
    }

    #[test]
    fn clients_see_what_their_token_may_do_but_never_its_hash() {
        let mut t = token("alice", &["proj", "ops"]);
        t.kind = Kind::Human;
        t.sha256 = hash("bdt_secret");
        let summary = t.summary();
        let text = summary.to_string();
        assert!(!text.contains(&t.sha256) && summary.get("id").is_none(), "{text}");
        assert_eq!(access_line(&summary), "role write, kind human, workspaces proj,ops; token n");

        t.workspaces = vec!["*".into()];
        t.expires_at = Some(Timestamp::parse_rfc3339("2026-11-01T00:00:00Z").unwrap());
        t.github = Some(gh("alice", 1));
        assert_eq!(
            access_line(&t.summary()),
            "role write, kind human, workspaces all; token n, expires 2026-11-01T00:00:00.000Z, GitHub user alice"
        );
        assert_eq!(access_line(&json!({})), "role ?, kind ?, workspaces ; token ?", "whatever a server sends");
    }

    #[test]
    fn tokens_are_revoked_by_id_not_name() {
        let dir = tempfile::tempdir().unwrap();
        let (first, _) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        revoke_where(dir.path(), |tokens| (0..tokens.len()).collect()).unwrap();
        let (second, _) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        assert!(!revoke_by_id(dir.path(), &first.id).unwrap(), "already revoked");
        let live =
            || load_file(&tokens_path(dir.path())).unwrap().tokens.iter().filter(|t| t.revoked_at.is_none()).count();
        assert_eq!(live(), 1, "the later token of the same name is untouched");
        assert!(revoke_by_id(dir.path(), &second.id).unwrap());
        assert_eq!(live(), 0);
    }

    #[test]
    fn every_entry_names_its_kind() {
        let dir = tempfile::tempdir().unwrap();
        let (human, _) = issue_token(dir.path(), "alice-desk", "alice", Role::Write, Kind::Human, &[]).unwrap();
        assert!(human.policy().human && !human.policy().admin);
        let (agent, _) = issue_token(dir.path(), "ci", "alice", Role::Admin, Kind::Agent, &[]).unwrap();
        assert_eq!(
            agent.policy(),
            bd_core::Policy { actor: "alice".into(), admin: true, human: false, max_claims: None }
        );
        assert!(agent.describe().contains("kind agent"), "{}", agent.describe());
        let text = std::fs::read_to_string(tokens_path(dir.path())).unwrap();
        assert!(text.contains("\"kind\": \"agent\"") && text.contains("\"kind\": \"human\""), "{text}");
        assert!(!text.contains("expires_at") && !text.contains("github"), "only sign-ins have them: {text}");

        let without = json!({ "version": 1, "tokens": [{
            "id": "0123456789abcdef", "name": "n", "actor": "alice", "role": "admin", "workspaces": ["*"],
            "sha256": hash("bdt_x"), "created_at": "2026-01-01T00:00:00Z",
        }]});
        std::fs::write(tokens_path(dir.path()), without.to_string()).unwrap();
        let err = Verifier::new(dir.path()).verify("bdt_x").unwrap_err().to_string();
        assert!(err.contains("tokens.json") && err.contains("kind"), "{err}");
    }
}
