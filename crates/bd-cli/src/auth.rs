//! Access tokens for `bd serve`: who may call, as which actor, with which
//! role, and whether a person or an agent holds it.
//!
//! Tokens live in `<root>/server.db` (`server_db.rs`), which stores
//! only the SHA-256 of each secret. `bd serve token create` prints a secret
//! once; GitHub sign-in (`oauth.rs`) issues tokens that expire, recording
//! the GitHub account, and with a GitHub App a refresh secret
//! (`bdr_<family>_<random>`): each refresh replaces both secrets of the
//! sign-in's entry in place, and a refresh secret used twice revokes it. A token acts as one actor, or as `<actor>/<name>`
//! sub-actors (one per agent), so claims and leases keep meaning "this
//! caller". Its role and kind become the request's [`bd_core::Policy`]:
//! only admins end or take over other actors' claims, and only human tokens
//! open human gates. Each change is one write transaction ([`change`]),
//! since the server issues tokens while an admin may create or revoke others.
//!
//! The file also binds each account that signed in (by its provider's
//! issuer and subject) to its actor, its login at its first sign-in
//! (`accounts`): the account keeps that actor when its login changes, and
//! no other principal gets it, even once the account's tokens are gone,
//! until an admin releases it (`revoke --account <login> --forget`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::{App, Out};
use crate::cli::{TokenCommand, TokenCreateArgs, TokenRevokeArgs, TokenRootArgs};
use crate::protocol::valid_workspace_name;
use crate::server_db;

/// Tokens stay listed this long after they end (revoked, or a sign-in's
/// expired and no longer refreshed), then are deleted at the next write.
const PRUNE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

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

/// An access token, as `server.db` keeps it.
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
    /// The account that signed in for the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
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
    /// The OAuth client the token was issued to (its client ID), by the
    /// authorization server (`oauth_server/`): only that client refreshes
    /// or revokes it there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
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
    /// When the rules or the authorizer last decided about it (its sign-in,
    /// or a refresh they allowed): a refresh kept while the authorizer
    /// cannot answer does not move it.
    pub decided_at: Timestamp,
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

/// An account that signed in, as its provider names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The provider's name in `auth.toml`: `github`, or that of an
    /// `[oidc.<name>]` table.
    pub provider: String,
    /// Who vouches for the account: the GitHub it signed in at (lowercase),
    /// or an OIDC issuer. Subjects are unique within one issuer only.
    pub issuer: String,
    /// The account's id at its issuer, which stays when its login changes.
    pub subject: String,
    /// Its login, user name or verified email now, which may change and may
    /// once have been another account's.
    pub login: String,
}

impl Identity {
    /// Whether `other` is the same account.
    pub fn same(&self, other: &Identity) -> bool {
        self.issuer == other.issuer && self.subject == other.subject
    }

    /// How messages name it: `GitHub user alice`, `google account alice@acme.com`.
    pub fn who(&self) -> String {
        who(&self.provider, &self.login)
    }

    /// The actor an account takes at its first sign-in: its login under its
    /// provider's name (`github:alice`, `google:alice@acme.com`), so that no
    /// provider's users, who may choose their own names, can pass for
    /// another provider's or for an admin's actors. A `/` in it would name a
    /// sub-actor: it becomes `-`.
    pub fn actor(&self) -> String {
        format!("{}:{}", self.provider, self.login.replace('/', "-"))
    }
}

/// An account that signed in, bound to the actor its tokens act as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// As in [`Identity`].
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    /// The actor of its tokens: its login when it first signed in.
    pub actor: String,
    /// Its login at its latest sign-in.
    pub login: String,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

impl Account {
    /// Whether `user` is this account.
    fn is(&self, user: &Identity) -> bool {
        self.subject == user.subject && self.issuer == user.issuer
    }

    /// How messages name it.
    fn who(&self) -> String {
        who(&self.provider, &self.login)
    }
}

/// How messages name the account `login` of `provider`.
pub fn who(provider: &str, login: &str) -> String {
    match provider {
        "github" => format!("GitHub user {login}"),
        provider => format!("{provider} account {login}"),
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
    if let Some(login) = summary["account"]["login"].as_str() {
        line.push_str(&format!(", {}", who(summary["account"]["provider"].as_str().unwrap_or_default(), login)));
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
            "account": self.identity,
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
            "account": self.identity,
            "max_claims": self.max_claims,
            "resource": self.resource,
            "client": self.client,
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
        if let Some(client) = &self.client {
            text.push_str(&format!(", for OAuth client {client}"));
        }
        if let Some(user) = &self.identity {
            text.push_str(&format!(", signed in as {}", user.who()));
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

/// The accounts and tokens of `<root>/server.db`, in the order they were added.
#[derive(Clone, Debug, Default)]
struct TokenFile {
    tokens: Vec<Token>,
    /// Accounts that signed in: never dropped, so an actor never passes
    /// from one account to another.
    accounts: Vec<Account>,
}

/// The records of a table's `data` column, in the order they were added.
fn records<T: serde::de::DeserializeOwned>(conn: &rusqlite::Connection, sql: &str) -> Result<Vec<T>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let texts = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    texts.iter().map(|t| serde_json::from_str(t).map_err(|e| Error::invalid(format!("server.db: {e}")))).collect()
}

fn load(conn: &rusqlite::Connection) -> Result<TokenFile> {
    Ok(TokenFile {
        tokens: records(conn, "SELECT data FROM tokens ORDER BY seq")?,
        accounts: records(conn, "SELECT data FROM accounts ORDER BY seq")?,
    })
}

/// All the accounts and tokens, as they are now (none if there is no `server.db`).
fn read(root: &Path) -> Result<TokenFile> {
    read_scoped(root, None)
}

/// The accounts and tokens `scope` names (all of them for `None`), read at one moment.
fn read_scoped(root: &Path, scope: Option<&Scope>) -> Result<TokenFile> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(TokenFile::default()) };
    server_db::read(root, &mut conn, |tx| match scope {
        Some(scope) => load_scope(tx, scope),
        None => load(tx),
    })
}

/// Change all the accounts and tokens with `f`, in one transaction: the
/// rows it added, changed or dropped are written if it succeeds, nothing if
/// not. For an admin's changes; the server's go through [`change_scoped`].
fn change<T>(root: &Path, f: impl FnOnce(&mut TokenFile) -> Result<T>) -> Result<T> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        prune(tx)?;
        let before = load(tx)?;
        let mut file = before.clone();
        let out = f(&mut file)?;
        save(tx, &before, &file)?;
        Ok(out)
    })
}

/// [`change`], with only the rows `scope` names loaded: all that a sign-in,
/// a refresh or a revocation by id looks at, so that each costs what its
/// own rows do, however many others there are. `f` gets the transaction too.
fn change_scoped<T>(
    root: &Path,
    scope: &Scope,
    f: impl FnOnce(&rusqlite::Transaction, &mut TokenFile) -> Result<T>,
) -> Result<T> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        prune(tx)?;
        let before = load_scope(tx, scope)?;
        let mut file = before.clone();
        let out = f(tx, &mut file)?;
        save(tx, &before, &file)?;
        Ok(out)
    })
}

/// Delete the tokens that ended [`PRUNE_AFTER`] ago: revoked, or a
/// sign-in's that expired and could no longer be refreshed (`ended_at`).
fn prune(tx: &rusqlite::Transaction) -> Result<()> {
    tx.execute("DELETE FROM tokens WHERE ended_at <= ?1", [Timestamp::now().minus(PRUNE_AFTER).millis()])?;
    Ok(())
}

/// Which rows a change or a read looks at.
#[derive(Default)]
struct Scope<'a> {
    /// Tokens by id; their actors' tokens and accounts too.
    ids: &'a [&'a str],
    /// The tokens and accounts of actors related to these.
    actors: Vec<String>,
    /// The account of this identity, and every account and token that
    /// [`bind`] and [`actor_conflict`] would look at for it: those related
    /// to its actor, to the actor its account is bound to, and to its login.
    user: Option<&'a Identity>,
    /// The account with this issuer and subject, and the tokens of its actor.
    account: Option<(&'a str, &'a str)>,
}

/// The rows `scope` names, in the order they were added: a superset of
/// what the checks of a change for it look at, so they decide as they
/// would over every row.
fn load_scope(conn: &rusqlite::Connection, scope: &Scope) -> Result<TokenFile> {
    use std::collections::BTreeMap;
    let mut tokens: BTreeMap<i64, String> = BTreeMap::new();
    let mut accounts: BTreeMap<i64, String> = BTreeMap::new();
    let add = |into: &mut BTreeMap<i64, String>, sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<()> {
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(args, |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (seq, data) = row?;
            into.insert(seq, data);
        }
        Ok(())
    };
    // Every key related to `key` in `column`: itself, its ancestors, its descendants.
    let related = |into: &mut BTreeMap<i64, String>, table: &str, column: &str, key: &str| -> Result<()> {
        let (exact, (low, high)) = server_db::related_keys(key);
        for k in &exact {
            add(into, &format!("SELECT seq, data FROM {table} WHERE {column} = ?1"), &[k])?;
        }
        add(into, &format!("SELECT seq, data FROM {table} WHERE {column} > ?1 AND {column} < ?2"), &[&low, &high])
    };
    let actor_of = |data: &str| -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(data)?;
        Ok(v["actor"].as_str().unwrap_or_default().to_string())
    };
    let mut actors = scope.actors.clone();
    for id in scope.ids {
        add(&mut tokens, "SELECT seq, data FROM tokens WHERE id = ?1", &[id])?;
    }
    for data in tokens.values() {
        actors.push(actor_of(data)?);
    }
    if let Some((issuer, subject)) = scope.account {
        let sql = "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2";
        add(&mut accounts, sql, &[&issuer, &subject])?;
        for data in accounts.values() {
            actors.push(actor_of(data)?);
        }
    }
    if let Some(user) = scope.user {
        let sql = "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2";
        add(&mut accounts, sql, &[&user.issuer, &user.subject])?;
        for data in accounts.values() {
            actors.push(actor_of(data)?);
        }
        actors.push(user.actor());
        related(&mut accounts, "accounts", "login_key", &server_db::key(&user.login))?;
    }
    for actor in &actors {
        let key = server_db::key(actor);
        related(&mut accounts, "accounts", "actor_key", &key)?;
        related(&mut tokens, "tokens", "actor_key", &key)?;
    }
    fn parse<T: serde::de::DeserializeOwned>(what: &str, data: &str) -> Result<T> {
        serde_json::from_str(data).map_err(|e| Error::invalid(format!("server.db: {what}: {e}")))
    }
    Ok(TokenFile {
        tokens: tokens.values().map(|d| parse("a token", d)).collect::<Result<_>>()?,
        accounts: accounts.values().map(|d| parse("an account", d)).collect::<Result<_>>()?,
    })
}

/// Write the rows of `after` that are not as in `before`, and drop those it no longer has.
fn save(tx: &rusqlite::Transaction, before: &TokenFile, after: &TokenFile) -> Result<()> {
    let was: HashMap<&str, String> =
        before.tokens.iter().map(|t| Ok((t.id.as_str(), serde_json::to_string(t)?))).collect::<Result<_>>()?;
    let ids: std::collections::HashSet<&str> = after.tokens.iter().map(|t| t.id.as_str()).collect();
    for gone in was.keys().filter(|id| !ids.contains(*id)) {
        tx.execute("DELETE FROM tokens WHERE id = ?1", [gone])?;
    }
    for t in &after.tokens {
        let data = serde_json::to_string(t)?;
        if was.get(t.id.as_str()) != Some(&data) {
            let family = t.refresh.as_ref().map(|r| r.family.to_ascii_lowercase());
            let (actor_key, name, ended_at) = server_db::token_keys(&serde_json::to_value(t)?);
            tx.execute(
                "INSERT INTO tokens (id, sha256, family, actor_key, name, ended_at, data) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (id) DO UPDATE SET sha256 = excluded.sha256, \
                 family = excluded.family, actor_key = excluded.actor_key, name = excluded.name, \
                 ended_at = excluded.ended_at, data = excluded.data",
                rusqlite::params![t.id, t.sha256, family, actor_key, name, ended_at, data],
            )?;
        }
    }
    let key = |a: &Account| (a.issuer.clone(), a.subject.clone());
    let was: HashMap<(String, String), String> =
        before.accounts.iter().map(|a| Ok((key(a), serde_json::to_string(a)?))).collect::<Result<_>>()?;
    let keys: std::collections::HashSet<(String, String)> = after.accounts.iter().map(key).collect();
    for (issuer, subject) in was.keys().filter(|k| !keys.contains(*k)) {
        tx.execute("DELETE FROM accounts WHERE issuer = ?1 AND subject = ?2", [issuer, subject])?;
    }
    for a in &after.accounts {
        let data = serde_json::to_string(a)?;
        if was.get(&key(a)) != Some(&data) {
            let (actor_key, login_key) = server_db::account_keys(&serde_json::to_value(a)?);
            tx.execute(
                "INSERT INTO accounts (issuer, subject, actor_key, login_key, data) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (issuer, subject) DO UPDATE SET actor_key = excluded.actor_key, \
                 login_key = excluded.login_key, data = excluded.data",
                [&a.issuer, &a.subject, &actor_key, &login_key, &data],
            )?;
        }
    }
    Ok(())
}

/// The tokens that are not revoked whose `column` is `value`.
fn live_where(conn: &rusqlite::Connection, column: &str, value: &str) -> Result<Vec<Token>> {
    let sql = format!("SELECT data FROM tokens WHERE {column} = ?1 ORDER BY seq");
    let mut stmt = conn.prepare_cached(&sql)?;
    let texts = stmt.query_map([value], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    let tokens = texts
        .iter()
        .map(|t| serde_json::from_str::<Token>(t).map_err(|e| Error::invalid(format!("server.db: {e}"))))
        .collect::<Result<Vec<_>>>()?;
    Ok(tokens.into_iter().filter(|t| t.revoked_at.is_none()).collect())
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

/// Checks bearer tokens against `<root>/server.db`, which it asks each
/// time, so new and revoked tokens take effect at once, whoever changed them.
pub struct Verifier {
    root: PathBuf,
    /// Opened at the first check, and again after one that failed or once
    /// the file is another (removed and created again).
    conn: Mutex<Option<(rusqlite::Connection, Option<u64>)>>,
}

impl Verifier {
    pub fn new(root: &Path) -> Verifier {
        Verifier { root: root.to_path_buf(), conn: Mutex::new(None) }
    }

    /// The token that is not revoked with this secret, and whether it expired.
    pub fn verify(&self, secret: &str) -> Result<Verified> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let file = server_db::file_id(&self.root);
        if conn.as_ref().is_none_or(|(_, opened)| *opened != file) {
            *conn = None;
            // No database yet: no token.
            let Some(opened) = server_db::open_existing(&self.root)? else { return Ok(Verified::Unknown) };
            *conn = Some((opened, server_db::file_id(&self.root)));
        }
        let found = live_where(&conn.as_ref().expect("opened").0, "sha256", &hash(secret));
        let found = match found {
            Ok(found) => found,
            Err(e) => {
                *conn = None;
                return Err(e);
            }
        };
        Ok(match found.into_iter().next() {
            Some(t) if t.expired(Timestamp::now()) => Verified::Expired(t),
            Some(t) => Verified::Valid(t),
            None => Verified::Unknown,
        })
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

/// Add an access token to `<root>/server.db`. Returns it with its secret,
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
pub fn issue_sign_in_token(
    root: &Path,
    user: &Identity,
    grant: Grant,
    life: Lifetime,
    workspace: &str,
    by_login: bool,
) -> Result<Issued> {
    let now = Timestamp::now();
    let refresh = life.refresh.map(|(limit, idle)| (workspace, limit.min(now.plus(idle))));
    let expires_at = now.plus(life.ttl).min(refresh.map_or(Timestamp(i64::MAX), |(_, until)| until));
    add_token(root, Holder::SignIn { user, expires_at, by_login, refresh, client: None }, grant)
}

/// The OAuth client a token is issued to, and the MCP endpoint it is bound to.
#[derive(Clone, Copy, Debug)]
pub struct ForClient<'a> {
    pub id: &'a str,
    pub resource: &'a str,
}

/// [`issue_sign_in_token`] for an OAuth `client` an account authorized
/// (`oauth_server/token.rs`): bound to its MCP endpoint (and so to that
/// workspace only), and named `oauth-<client>-<actor>-<random>`.
pub fn issue_client_token(
    root: &Path,
    user: &Identity,
    grant: Grant,
    life: Lifetime,
    client: ForClient<'_>,
    by_login: bool,
) -> Result<Issued> {
    let (_, workspace) = crate::mcp::http::resource_url(client.resource).map_err(Error::invalid)?;
    let now = Timestamp::now();
    let refresh = life.refresh.map(|(limit, idle)| (workspace.as_str(), limit.min(now.plus(idle))));
    let expires_at = now.plus(life.ttl).min(refresh.map_or(Timestamp(i64::MAX), |(_, until)| until));
    add_token(root, Holder::SignIn { user, expires_at, by_login, refresh, client: Some(client) }, grant)
}

/// `text` as part of a token name: letters, digits, `.`, `_` and `-`
/// (anything else becomes `-`), at most `max` characters.
fn name_part(text: &str, max: usize) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    text.chars().map(|c| if plain(c) { c } else { '-' }).take(max).collect()
}

/// What names a client in its tokens' names: the host of its metadata
/// document, or its registered ID; letters, digits, `.`, `_` and `-` only.
fn client_label(id: &str) -> String {
    let id = id.strip_prefix("https://").map_or(id, |rest| rest.split(['/', ':', '?', '#']).next().unwrap_or_default());
    let label: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(20)
        .collect::<String>()
        .to_ascii_lowercase();
    if label.is_empty() { "client".into() } else { label }
}

/// The sign-in whose refresh secret this is, unless revoked: its token, and
/// whether the secret is its current one (else it is spent, or forged).
pub fn find_refresh(root: &Path, secret: &str) -> Result<Option<(Token, bool)>> {
    let Some(family) = refresh_family(secret) else { return Ok(None) };
    let Some(conn) = server_db::open_existing(root)? else { return Ok(None) };
    let found = live_where(&conn, "family", &family.to_ascii_lowercase())?.into_iter().next();
    Ok(found.map(|t| {
        let current = t.refresh.as_ref().is_some_and(|r| r.sha256 == hash(secret));
        (t, current)
    }))
}

/// The token that is not revoked with this secret, or with this refresh
/// secret (its current one, or one spent): what a revocation names.
pub fn find_by_secret(root: &Path, secret: &str) -> Result<Option<Token>> {
    if refresh_family(secret).is_some() {
        return Ok(find_refresh(root, secret)?.map(|(t, _)| t));
    }
    let sha = hash(secret);
    let Some(conn) = server_db::open_existing(root)? else { return Ok(None) };
    Ok(live_where(&conn, "sha256", &sha)?.into_iter().next())
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
    user: &Identity,
    grant: Grant,
    by_login: bool,
    decided: bool,
    expires_at: Timestamp,
    until: Timestamp,
) -> Result<Option<Issued>> {
    let workspaces = workspace_list(&grant.workspaces)?;
    let scope = Scope { ids: &[id], user: Some(user), ..Scope::default() };
    change_scoped(root, &scope, |_, file| {
        let now = Timestamp::now();
        let live =
            |t: &Token| t.id == id && t.revoked_at.is_none() && t.refresh.as_ref().is_some_and(|r| r.sha256 == current);
        let Some(i) = file.tokens.iter().position(live) else { return Ok(None) };
        // A token bound to an MCP endpoint keeps to its workspace, which the rules were just applied for.
        let workspaces = match (&file.tokens[i].resource, &file.tokens[i].refresh) {
            (Some(_), Some(r)) => vec![r.workspace.clone()],
            _ => workspaces,
        };
        let actor = bind(&mut file.accounts, user, now, by_login)?;
        if actor != file.tokens[i].actor {
            return Err(Error::Unauthorized(format!(
                "{} now acts as {actor}, not {}: sign in again (`bd remote login`)",
                user.who(),
                file.tokens[i].actor
            )));
        }
        if by_login && !related(&actor, &user.actor()) {
            if let Some(other) = actor_conflict(&file.tokens, &user.actor(), Some(user), now) {
                return Err(conflict_error(&user.actor(), Some(user), other));
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
        if decided {
            refresh.decided_at = now;
        }
        refresh.until = until;
        refresh.last = Some(last);
        t.sha256 = hash(&secret);
        t.expires_at = Some(expires_at.min(until));
        t.role = grant.role;
        t.kind = grant.kind;
        t.workspaces = workspaces;
        t.max_claims = grant.max_claims;
        t.identity = Some(user.clone());
        let token = t.clone();
        Ok(Some(Issued { token, secret, refresh_secret: Some(refresh_secret) }))
    })
}

/// Whom a new token is for.
enum Holder<'a> {
    /// An admin names it, its actor, and maybe the MCP endpoint it is bound to.
    Admin { name: &'a str, actor: &'a str, resource: Option<&'a str> },
    /// A GitHub account that signed in; `by_login` when a rule let it in by
    /// its login; `refresh`, the workspace it signed in for and until when
    /// it may be refreshed, if it may; `client`, the OAuth client it
    /// authorized, if it did.
    SignIn {
        user: &'a Identity,
        expires_at: Timestamp,
        by_login: bool,
        refresh: Option<(&'a str, Timestamp)>,
        client: Option<ForClient<'a>>,
    },
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
    let bound = match &holder {
        Holder::Admin { resource: Some(url), .. } => {
            Some(crate::mcp::http::resource_url(url).map_err(|e| Error::invalid(format!("--resource {e}")))?)
        }
        Holder::SignIn { client: Some(client), .. } => {
            Some(crate::mcp::http::resource_url(client.resource).map_err(Error::invalid)?)
        }
        _ => None,
    };
    if let Some((url, workspace)) = bound {
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
    let scope = match &holder {
        Holder::Admin { actor, .. } => Scope { actors: vec![actor.to_string()], ..Scope::default() },
        Holder::SignIn { user, .. } => Scope { user: Some(*user), ..Scope::default() },
    };
    change_scoped(root, &scope, |tx, file| {
        let now = Timestamp::now();
        let (name, actor, expires_at, identity, refresh, client) = match holder {
            Holder::Admin { name, actor, .. } => {
                if let Some(account) = file.accounts.iter().find(|a| related(&a.actor, actor)) {
                    return Err(Error::Refused(format!(
                        "actor {actor} would share actor {} with {}, who signed in: pick another actor, or release that \
                     one first (`bd serve token revoke --account {} --forget`)",
                        account.actor,
                        account.who(),
                        account.actor
                    )));
                }
                (name.to_string(), actor.to_string(), None, None, None, None)
            }
            Holder::SignIn { user, expires_at, by_login, refresh, client } => {
                let actor = account_actor(file, user, now, by_login)?;
                let name = match client {
                    Some(c) => format!("oauth-{}-{}-{}", client_label(c.id), name_part(&actor, 24), random_hex(4)?),
                    None => {
                        // `github-alice-…`, `google-alice-acme.com-…`: the provider once.
                        let named = match actor.contains(':') {
                            true => actor.clone(),
                            false => format!("{}:{actor}", user.provider),
                        };
                        format!("{}-{}", name_part(&named, 55), random_hex(4)?)
                    }
                };
                check_name(&name)?;
                check_actor(&actor)?;
                (name, actor, Some(expires_at), Some(user.clone()), refresh, client.map(|c| c.id.to_string()))
            }
        };
        if !live_where(tx, "name", &name)?.is_empty() {
            return Err(Error::Refused(format!("access token {name} already exists; revoke it first")));
        }
        if let Some(other) = actor_conflict(&file.tokens, &actor, identity.as_ref(), now) {
            return Err(conflict_error(&actor, identity.as_ref(), other));
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
                    decided_at: now,
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
            identity,
            max_claims: grant.max_claims,
            refresh,
            resource,
            client,
        };
        file.tokens.push(token.clone());
        Ok(Issued { token, secret, refresh_secret })
    })
}

/// The actor a sign-in of `user` gets, bound to its account in `file`, or
/// why it may not sign in for its actor's sake.
fn account_actor(file: &mut TokenFile, user: &Identity, now: Timestamp, by_login: bool) -> Result<String> {
    let actor = bind(&mut file.accounts, user, now, by_login)?;
    if is_reserved_actor(&actor) {
        return Err(Error::Unauthorized(format!(
            "{} may not sign in to this bd server: its actor {actor} is bd serve's own",
            user.who()
        )));
    }
    // A renamed account let in by a login that names another principal's actor must not pass for it.
    if by_login && !related(&actor, &user.actor()) {
        if let Some(other) = actor_conflict(&file.tokens, &user.actor(), Some(user), now) {
            return Err(conflict_error(&user.actor(), Some(user), other));
        }
    }
    if let Some(other) = actor_conflict(&file.tokens, &actor, Some(user), now) {
        return Err(conflict_error(&actor, Some(user), other));
    }
    Ok(actor)
}

/// The actor a sign-in of `user` would get now, binding nothing: what
/// [`issue_sign_in_token`] would refuse for its actor's sake is refused
/// before anyone is asked to approve a client (`oauth_server/authorize.rs`).
/// Issuing the token checks again.
pub fn preview_actor(root: &Path, user: &Identity, by_login: bool) -> Result<String> {
    let mut file = read_scoped(root, Some(&Scope { user: Some(user), ..Scope::default() }))?;
    let actor = account_actor(&mut file, user, Timestamp::now(), by_login)?;
    check_actor(&actor)?;
    Ok(actor)
}

/// The actor of `user`'s tokens: the one bound to its account, else its
/// login, bound to it now. Refused while the login would bind another
/// account's actor; and, when a rule let the account in `by_login`, while
/// another account's actor or latest login is related to it, even for an
/// account bound before: one that took a login given up must not pass for
/// its previous holder, whom rules name by it.
fn bind(accounts: &mut Vec<Account>, user: &Identity, now: Timestamp, by_login: bool) -> Result<String> {
    let bound = accounts.iter().any(|a| a.is(user));
    let wanted = user.actor();
    let taken = |a: &Account| {
        let actor = related(&a.actor, &wanted) && (!bound || by_login);
        // A login names an account at its own provider only.
        let login = by_login && a.provider == user.provider && related(&a.login, &user.login);
        !a.is(user) && (actor || login)
    };
    if let Some(other) = accounts.iter().find(|a| taken(a)) {
        tracing::info!(
            target: "bd::serve",
            login = %user.login,
            subject = %user.subject,
            actor = %other.actor,
            bound_to = %other.subject,
            "sign-in refused: the login's actor belongs to another account"
        );
        let whose = match related(&other.actor, &wanted) {
            true => format!("actor {} belongs to another account, which had that login before", other.actor),
            false => format!("login {} was that of another account (actor {}) before", other.login, other.actor),
        };
        return Err(Error::Unauthorized(format!(
            "{} may not sign in to this bd server: {whose}; the server's admin resolves that (`bd serve token \
             accounts`)",
            user.who()
        )));
    }
    if let Some(account) = accounts.iter_mut().find(|a| a.is(user)) {
        account.login = user.login.clone();
        account.last_seen = now;
        return Ok(account.actor.clone());
    }
    accounts.push(Account {
        provider: user.provider.clone(),
        issuer: user.issuer.clone(),
        subject: user.subject.clone(),
        actor: wanted.clone(),
        login: user.login.clone(),
        first_seen: now,
        last_seen: now,
    });
    Ok(wanted)
}

/// A live token of another principal whose actor a new token's would share,
/// or cover with sub-actors: a GitHub account's against an admin's or
/// another account's, and the other way round. Tokens an admin creates may
/// share actors among themselves.
fn actor_conflict<'a>(
    tokens: &'a [Token],
    actor: &str,
    identity: Option<&Identity>,
    now: Timestamp,
) -> Option<&'a Token> {
    tokens.iter().filter(|t| t.revoked_at.is_none() && !t.expired(now)).find(|t| match (identity, &t.identity) {
        (None, None) => false,
        (Some(user), Some(other)) => related(actor, &t.actor) && !(other.same(user)),
        _ => related(actor, &t.actor),
    })
}

fn conflict_error(actor: &str, identity: Option<&Identity>, other: &Token) -> Error {
    match (identity, &other.identity) {
        (Some(user), _) => {
            tracing::info!(
                target: "bd::serve",
                login = %user.login,
                subject = %user.subject,
                token = %other.name,
                actor = %other.actor,
                "sign-in refused: another token's actor"
            );
            Error::Unauthorized(format!(
                "{} may not sign in to this bd server as actor {actor}: another access token acts as {}; the \
                 server's admin resolves that (`bd serve token list`)",
                user.who(),
                other.actor
            ))
        }
        (None, Some(owner)) => Error::Refused(format!(
            "actor {actor} would share actor {} with {}, who signed in: pick another actor, or release that one \
             first (`bd serve token revoke --account {} --forget`)",
            other.actor,
            owner.who(),
            other.actor
        )),
        (None, None) => Error::Refused(format!("actor {actor} is taken by access token {}", other.name)),
    }
}

fn list(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = read(&root_dir(a)?)?;
    let now = Timestamp::now();
    let mut out = Out::new(file.tokens.iter().map(Token::view).collect::<Vec<_>>());
    if file.tokens.is_empty() {
        out = out.line(
            "No access tokens. Create one with `bd serve token create <name> --as <actor>`, or let people sign in \
             in (auth.toml).",
        );
    }
    for t in &file.tokens {
        out = out.line(format!("{:<20} {}  ({})", t.name, t.describe(), t.state(now))).id(t.name.clone());
    }
    app.print(out);
    Ok(())
}

fn accounts(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = read(&root_dir(a)?)?;
    let now = Timestamp::now();
    let live = |account: &Account| {
        let live = |t: &&Token| t.revoked_at.is_none() && !t.expired(now);
        file.tokens.iter().filter(live).filter(|t| t.identity.as_ref().is_some_and(|g| account.is(g))).count()
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
        out = out.line("No account is bound to an actor.");
    }
    for account in &file.accounts {
        let n = live(account);
        out = out
            .line(format!(
                "{:<20} {} (subject {} at {}), signed in first {}, last {}; {n} live token{}",
                account.actor,
                account.who(),
                account.subject,
                account.issuer,
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
    if let Some(client) = a.client.as_deref().map(str::trim) {
        let theirs =
            |tokens: &[Token]| (0..tokens.len()).filter(|&i| tokens[i].client.as_deref() == Some(client)).collect();
        let (known, revoked) = revoke_where(&root, theirs)?;
        if known == 0 {
            return Err(Error::not_found("OAuth client with access tokens", client));
        }
        let text = match revoked.len() {
            0 => format!("= OAuth client {client} has no live access tokens"),
            1 => format!("✓ Revoked the access token of OAuth client {client}: {}", revoked[0]),
            n => format!("✓ Revoked {n} access tokens of OAuth client {client}: {}", revoked.join(", ")),
        };
        let out = Out::new(json!({ "client": client, "revoked": revoked })).line(text);
        app.print(revoked.iter().fold(out, |out, name| out.id(name.clone())));
        return Ok(());
    }
    match (&a.name, a.account.as_deref().map(str::trim)) {
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
            let done = revoke_account(&root, login, a.forget)?;
            let view = json!({
                "account": login, "revoked": done.revoked, "accounts": done.accounts, "forgot": a.forget,
                "erased": done.erased,
            });
            let mut out = Out::new(view).line(match done.revoked.len() {
                0 => format!("= account {login} has no live access tokens"),
                1 => format!("✓ Revoked the access token of account {login}: {}", done.revoked[0]),
                n => format!("✓ Revoked {n} access tokens of account {login}: {}", done.revoked.join(", ")),
            });
            for account in &done.accounts {
                out = out.line(match a.forget {
                    true => format!(
                        "✓ Released actor {} of {} (subject {}) and deleted its records: the next account to sign in \
                         as {} gets it",
                        account.actor,
                        account.who(),
                        account.subject,
                        account.actor
                    ),
                    false => format!(
                        "  actor {} stays bound to {} (subject {}); --forget releases it",
                        account.actor,
                        account.who(),
                        account.subject
                    ),
                });
            }
            if done.erased == Some(false) {
                out = out.line(
                    "  The deleted records stay in server.db's write-ahead log until bd serve's next checkpoint, \
                     which overwrites them",
                );
            }
            app.print(done.revoked.iter().fold(out, |out, name| out.id(name.clone())));
        }
        _ => return Err(Error::invalid("name the access token to revoke, or an account with --account")),
    }
    Ok(())
}

/// Revoke the token with this id (not its name, which a later token may
/// reuse): whether it was revoked now.
pub fn revoke_by_id(root: &Path, id: &str) -> Result<bool> {
    change_scoped(root, &Scope { ids: &[id], ..Scope::default() }, |_, file| {
        let now = Timestamp::now().to_rfc3339();
        let token = file.tokens.iter_mut().find(|t| t.id == id && t.revoked_at.is_none());
        Ok(token.map(|t| t.revoked_at = Some(now)).is_some())
    })
}

/// Revoke the tokens `pick` selects (indexes): how many it selects, and the
/// names of those revoked now (the others already were).
fn revoke_where(root: &Path, pick: impl FnOnce(&[Token]) -> Vec<usize>) -> Result<(usize, Vec<String>)> {
    change(root, |file| {
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
        Ok((picked.len(), revoked))
    })
}

/// End the sign-ins of the account with this issuer and subject made
/// before `at`, as its provider says it revoked its consent then: the names
/// of the tokens revoked. One signed in since is the account's new consent.
pub fn end_sign_ins_before(root: &Path, issuer: &str, subject: &str, at: Timestamp) -> Result<Vec<String>> {
    change_scoped(root, &Scope { account: Some((issuer, subject)), ..Scope::default() }, |_, file| {
        let now = Timestamp::now().to_rfc3339();
        let mut revoked = Vec::new();
        for t in &mut file.tokens {
            let theirs = t.identity.as_ref().is_some_and(|g| g.issuer == issuer && g.subject == subject);
            let before = Timestamp::parse_rfc3339(&t.created_at).is_ok_and(|created| created < at);
            if theirs && before && t.revoked_at.is_none() {
                t.revoked_at = Some(now.clone());
                revoked.push(t.name.clone());
            }
        }
        Ok(revoked)
    })
}

/// Forget the account with this issuer and subject, as its provider says it
/// was deleted: the account and every token of it, erased as `revoke
/// --account --forget` does. Whether there was one.
pub fn forget_account(root: &Path, issuer: &str, subject: &str) -> Result<bool> {
    let found = change_scoped(root, &Scope { account: Some((issuer, subject)), ..Scope::default() }, |_, file| {
        let theirs = |g: &Identity| g.issuer == issuer && g.subject == subject;
        let before = (file.accounts.len(), file.tokens.len());
        file.accounts.retain(|a| !(a.issuer == issuer && a.subject == subject));
        file.tokens.retain(|t| !t.identity.as_ref().is_some_and(theirs));
        Ok(before != (file.accounts.len(), file.tokens.len()))
    })?;
    if found {
        server_db::scrub(root)?;
    }
    Ok(found)
}

/// What `revoke --account` did.
#[derive(Debug)]
struct AccountRevoked {
    /// The accounts known by the login: their latest login, or their actor.
    accounts: Vec<Account>,
    /// Names of the tokens revoked now (the others already were).
    revoked: Vec<String>,
    /// With `--forget`: whether what was deleted is gone from the
    /// database's files too, or stays in its write-ahead log until the
    /// server's next checkpoint.
    erased: Option<bool>,
}

/// Revoke every token of the accounts known by `login` (their latest
/// login, or their actor), and any token that signed in as it, so that the
/// tokens from before a rename go too; with `forget`, also release those
/// accounts' actors.
fn revoke_account(root: &Path, login: &str, forget: bool) -> Result<AccountRevoked> {
    change(root, |file| {
        let named = |s: &str| s.eq_ignore_ascii_case(login);
        // An actor names its account alone; else a login names the accounts it is (or, renamed, was) the login of,
        // at one provider: at several, their actors tell them apart.
        let by_actor: Vec<Account> = file.accounts.iter().filter(|a| named(&a.actor)).cloned().collect();
        let accounts = match by_actor.is_empty() {
            false => by_actor,
            true => file.accounts.iter().filter(|a| named(&a.login)).cloned().collect(),
        };
        let mut providers: Vec<&str> = accounts.iter().map(|a| a.provider.as_str()).collect();
        providers.sort_unstable();
        providers.dedup();
        if providers.len() > 1 {
            let actors: Vec<&str> = accounts.iter().map(|a| a.actor.as_str()).collect();
            return Err(Error::invalid(format!(
                "{login} is the login of accounts at {}: name the one to revoke by its actor ({})",
                providers.join(" and "),
                actors.join(", ")
            )));
        }
        // Their tokens, and tokens signed in as the login at the same provider (from before a rename).
        let theirs = |t: &Token| {
            t.identity.as_ref().is_some_and(|g| {
                accounts.iter().any(|a| a.is(g))
                    || (named(&g.login) && (accounts.is_empty() || providers.contains(&g.provider.as_str())))
            })
        };
        let picked: Vec<usize> = (0..file.tokens.len()).filter(|&i| theirs(&file.tokens[i])).collect();
        if accounts.is_empty() && picked.is_empty() {
            return Err(Error::not_found("account with access tokens", login));
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
        if forget {
            // Erased, not kept until pruned: the account and every record of its tokens.
            file.accounts.retain(|a| !accounts.contains(a));
            file.tokens.retain(|t| !theirs(t));
        }
        Ok(AccountRevoked { accounts, revoked, erased: None })
    })
    .and_then(|mut done| {
        if forget {
            done.erased = Some(server_db::scrub(root)?);
        }
        Ok(done)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly these accounts and tokens.
    fn put(root: &Path, file: TokenFile) {
        change(root, |all| {
            *all = file;
            Ok(())
        })
        .unwrap();
    }

    /// Every token's record, as stored.
    fn raw(root: &Path) -> String {
        let conn = server_db::open(root).unwrap();
        conn.query_row("SELECT group_concat(data, char(10)) FROM tokens", [], |r| r.get(0)).unwrap()
    }

    /// Replace `from` with `to` in the tokens' stored records.
    fn edit(root: &Path, from: &str, to: &str) {
        let conn = server_db::open(root).unwrap();
        conn.execute("UPDATE tokens SET data = replace(data, ?1, ?2)", [from, to]).unwrap();
    }

    /// A sign-in token lasting `ttl`, not refreshed.
    fn github_token(
        root: &Path,
        user: &Identity,
        grant: Grant,
        ttl: Duration,
        by_login: bool,
    ) -> Result<(Token, String)> {
        let life = Lifetime { ttl, refresh: None };
        issue_sign_in_token(root, user, grant, life, "proj", by_login).map(|i| (i.token, i.secret))
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
            identity: None,
            max_claims: None,
            refresh: None,
            resource: None,
            client: None,
        }
    }

    #[test]
    fn other_providers_accounts_act_under_their_name() {
        let dir = tempfile::tempdir().unwrap();
        let grant =
            || Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec!["proj".into()], max_claims: None };
        let id = |provider: &str, subject: &str, login: &str| Identity {
            provider: provider.into(),
            issuer: format!("https://{provider}.example"),
            subject: subject.into(),
            login: login.into(),
        };
        let sign_in = |user: &Identity| github_token(dir.path(), user, grant(), Duration::from_secs(3600), true);
        // An email login: an actor under the provider's name, and a token name of plain characters.
        let (t, _) = sign_in(&id("google", "1", "alice@acme.example")).unwrap();
        assert_eq!(t.actor, "google:alice@acme.example");
        assert!(t.name.starts_with("google-alice-acme.example-") && t.name.len() <= 64, "{}", t.name);
        // The same login at GitHub and at another provider: two accounts, two actors.
        let github = Identity {
            provider: "github".into(),
            issuer: "https://github.com".into(),
            subject: "7".into(),
            login: "alice".into(),
        };
        let okta = id("okta", "00u1", "alice");
        assert_eq!(sign_in(&github).unwrap().0.actor, "github:alice");
        assert_eq!(sign_in(&okta).unwrap().0.actor, "okta:alice");
        // No sub-actors from a login, and long names stay names.
        assert_eq!(sign_in(&id("keycloak", "k1", "bob/x")).unwrap().0.actor, "keycloak:bob-x");
        let (t, _) = sign_in(&id("corporate-single-sign-on", "c1", &"l".repeat(60))).unwrap();
        assert!(t.name.len() <= 64, "{}", t.name);
        // An actor names its account alone; a login of accounts at two providers names neither.
        let done = revoke_account(dir.path(), "github:alice", false).unwrap();
        assert_eq!((done.accounts.len(), done.accounts[0].provider.as_str()), (1, "github"));
        assert_eq!(done.revoked.len(), 1, "not okta:alice's: {:?}", done.revoked);
        assert_eq!(revoke_account(dir.path(), "okta:alice", false).unwrap().accounts.len(), 1);
        sign_in(&id("okta", "00u2", "carol")).unwrap();
        sign_in(&id("keycloak", "k2", "carol")).unwrap();
        let e = revoke_account(dir.path(), "carol", false).unwrap_err().to_string();
        assert!(e.contains("keycloak and okta") && e.contains("okta:carol"), "{e}");
        assert!(preview_actor(dir.path(), &id("google", "2", "eve@acme.example"), true).is_ok());
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
        let v = Verifier::new(dir.path());
        let actor = |secret: &str| match v.verify(secret).unwrap() {
            Verified::Valid(t) => Some(t.actor),
            Verified::Expired(t) => panic!("{} expired", t.name),
            Verified::Unknown => None,
        };
        assert_eq!(actor("bdt_x"), None, "no file yet");
        let mut t = token("alice", &["*"]);
        t.sha256 = hash("bdt_secret");
        put(dir.path(), TokenFile { tokens: vec![t.clone()], accounts: Vec::new() });
        assert_eq!(actor("bdt_secret"), Some("alice".to_string()));
        assert_eq!(actor("bdt_other"), None);
        t.revoked_at = Some("2026-01-01T00:00:00Z".into());
        put(dir.path(), TokenFile { tokens: vec![t], accounts: Vec::new() });
        assert_eq!(actor("bdt_secret"), None, "revocation applies without a restart");
    }

    #[cfg(unix)]
    #[test]
    fn the_verifier_follows_a_database_made_anew() {
        let dir = tempfile::tempdir().unwrap();
        let (_, old) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify(&old).unwrap(), Verified::Valid(_)));
        for file in ["server.db", "server.db-wal", "server.db-shm"] {
            let _ = std::fs::remove_file(dir.path().join(file));
        }
        let (_, new) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        assert!(matches!(v.verify(&new).unwrap(), Verified::Valid(_)), "the new database's token");
        assert!(matches!(v.verify(&old).unwrap(), Verified::Unknown), "not the removed one's");
    }

    #[test]
    fn expired_tokens_are_told_apart_and_never_valid() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = token("alice", &["*"]);
        t.sha256 = hash("bdt_secret");
        t.expires_at = Some(Timestamp::now().plus(Duration::from_secs(3600)));
        put(dir.path(), TokenFile { tokens: vec![t.clone()], accounts: Vec::new() });
        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Valid(_)));
        t.expires_at = Some(Timestamp::now().minus(Duration::from_secs(1)));
        put(dir.path(), TokenFile { tokens: vec![t.clone()], accounts: Vec::new() });
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Expired(e) if e.name == "n"));
        let stamp = t.expires_at.unwrap().to_rfc3339();
        edit(dir.path(), &stamp, "soon");
        assert!(v.verify("bdt_secret").is_err(), "an expiry that is not a time fails closed");
        edit(dir.path(), "soon", &stamp);
        t.revoked_at = Some(Timestamp::now().to_rfc3339());
        put(dir.path(), TokenFile { tokens: vec![t], accounts: Vec::new() });
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Unknown), "revoked, whether expired or not");
    }

    const GITHUB: &str = "https://github.com";

    fn gh(login: &str, id: u64) -> Identity {
        Identity { provider: "github".into(), issuer: GITHUB.into(), subject: id.to_string(), login: login.into() }
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
        assert_eq!((t.actor.as_str(), t.role, t.kind), ("github:Alice-GH", Role::Read, Kind::Human));
        assert_eq!(t.workspaces, ["proj"]);
        assert_eq!(t.identity.as_ref(), Some(&alice));
        let expires = t.expires_at.unwrap();
        assert!(expires >= before.plus(ttl) && expires <= Timestamp::now().plus(ttl));
        assert!(t.describe().contains("signed in as GitHub user Alice-GH"), "{}", t.describe());
        assert!(t.state(Timestamp::now()).contains("expires"), "{}", t.state(Timestamp::now()));
        assert!(t.state(expires).starts_with("expired"));
        let (again, _) = github_token(dir.path(), &alice, grant.clone(), ttl, true).unwrap();
        assert_ne!(again.name, t.name, "each sign-in gets a token of its own");
        let long = gh(&"a".repeat(60), 7);
        let (t, _) = github_token(dir.path(), &long, grant, ttl, true).unwrap();
        assert_eq!((t.actor.len(), t.name.len()), (67, 64), "the actor keeps the whole login");

        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify(&secret).unwrap(), Verified::Valid(v) if v.identity == Some(alice.clone())));
    }

    #[test]
    fn tokens_are_deleted_a_week_after_they_end_at_the_next_write() {
        let dir = tempfile::tempdir().unwrap();
        let now = Timestamp::now();
        let entry = |name: &str, expired_ago: Option<Duration>, github: bool| {
            let mut t = token("alice", &["*"]);
            (t.id, t.name) = (name.into(), name.into());
            t.expires_at = expired_ago.map(|d| now.minus(d));
            t.identity = github.then(|| gh("alice", 1));
            t
        };
        let day = Duration::from_secs(24 * 3600);
        let tokens = vec![
            entry("old-sign-in", Some(PRUNE_AFTER + day), true),
            entry("recent-sign-in", Some(day), true),
            entry("manual", None, false),
            entry("manual-expired", Some(PRUNE_AFTER + day), false),
        ];
        let revoked = |name: &str, ago: Duration, github: bool| {
            let mut t = entry(name, None, github);
            t.revoked_at = Some(now.minus(ago).to_rfc3339());
            t
        };
        let tokens = [
            tokens,
            vec![
                revoked("revoked-long-ago", PRUNE_AFTER + day, false),
                revoked("revoked-sign-in-long-ago", PRUNE_AFTER + day, true),
                revoked("revoked-recently", day, true),
            ],
        ]
        .concat();
        put(dir.path(), TokenFile { tokens, accounts: Vec::new() });
        // Any write: here, revoking another token.
        let (other, _) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let names: Vec<String> = read(dir.path()).unwrap().tokens.into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["recent-sign-in", "manual", "manual-expired", "revoked-recently", "ci"]);
        let old = Timestamp::now().minus(PRUNE_AFTER + day).to_rfc3339();
        edit(dir.path(), "\"name\":\"manual\"", &format!("\"name\":\"manual\",\"revoked_at\":\"{old}\""));
        let conn = server_db::open(dir.path()).unwrap();
        conn.execute("UPDATE tokens SET ended_at = 0 WHERE name = 'manual'", []).unwrap();
        assert!(revoke_by_id(dir.path(), &other.id).unwrap());
        let names: Vec<String> = read(dir.path()).unwrap().tokens.into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["recent-sign-in", "manual-expired", "revoked-recently", "ci"], "pruned by a revocation");
    }

    #[test]
    fn refreshable_sign_ins_stay_listed_until_they_can_no_longer_be_refreshed() {
        let dir = tempfile::tempdir().unwrap();
        let now = Timestamp::now();
        let day = Duration::from_secs(24 * 3600);
        let entry = |name: &str, until: Timestamp| {
            let mut t = token("alice", &["*"]);
            (t.id, t.name) = (name.into(), name.into());
            t.expires_at = Some(now.minus(PRUNE_AFTER + day));
            t.identity = Some(gh("alice", 1));
            let family = "0".repeat(32);
            t.refresh = Some(Refresh {
                family,
                sha256: String::new(),
                workspace: "proj".into(),
                refreshed_at: now,
                decided_at: now,
                until,
                last: None,
            });
            t
        };
        let tokens = vec![entry("refreshable", now.plus(day)), entry("ended", now.minus(PRUNE_AFTER + day))];
        put(dir.path(), TokenFile { tokens, accounts: Vec::new() });
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let names: Vec<String> = read(dir.path()).unwrap().tokens.into_iter().map(|t| t.name).collect();
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
        let issued = issue_sign_in_token(dir.path(), &alice, grant.clone(), life, "proj", true).unwrap();
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
        let reader = Grant { role: Role::Read, ..grant.clone() };
        let renamed = gh("alice-new", 1);
        let (expires, until) = (now.plus(hour * 2), now.plus(week));
        let last = |secret: &str, id: &str| LastRefresh { spent: hash(secret), request: hash(id) };
        let rotated =
            rotate(dir.path(), &t.id, &hash(&first), last(&first, "r1"), &renamed, reader, true, true, expires, until)
                .unwrap()
                .unwrap();
        let second = rotated.refresh_secret.unwrap();
        let r = rotated.token;
        assert_eq!(
            (r.id.as_str(), r.name.as_str(), r.actor.as_str()),
            (t.id.as_str(), t.name.as_str(), "github:alice")
        );
        assert_eq!((r.role, r.identity.as_ref().unwrap().login.as_str()), (Role::Read, "alice-new"), "the rules now");
        assert_eq!((r.expires_at, r.refresh.as_ref().unwrap().until), (Some(expires), until));
        assert_eq!(read(dir.path()).unwrap().tokens.len(), 1, "replaced in place");
        assert!(matches!(verifier.verify(&issued.secret).unwrap(), Verified::Unknown), "the old secret is gone");
        assert!(matches!(verifier.verify(&rotated.secret).unwrap(), Verified::Valid(_)));

        assert!(!find_refresh(dir.path(), &first).unwrap().unwrap().1, "spent");
        assert!(find_refresh(dir.path(), &second).unwrap().unwrap().1);
        let again = rotate(
            dir.path(),
            &t.id,
            &hash(&first),
            last(&first, "r2"),
            &renamed,
            grant.clone(),
            true,
            true,
            expires,
            until,
        );
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
        let plain = issue_sign_in_token(dir.path(), &alice, grant, once, "proj", true).unwrap();
        assert!(plain.refresh_secret.is_none() && plain.token.refresh.is_none());
    }

    #[test]
    fn github_accounts_keep_their_actor_through_renames_and_after_their_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let hour = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let sign_in = |user: &Identity| github_token(dir.path(), user, grant.clone(), hour, true);
        let accounts = || read(dir.path()).unwrap().accounts;

        let (first, _) = sign_in(&gh("alice", 1)).unwrap();
        assert_eq!(first.actor, "github:alice");
        let bound = accounts();
        assert_eq!(
            (bound.len(), bound[0].actor.as_str(), bound[0].first_seen),
            (1, "github:alice", bound[0].last_seen)
        );

        // Renamed at GitHub: the same account, the same actor.
        let (renamed, _) = sign_in(&gh("alice-smith", 1)).unwrap();
        assert_eq!(renamed.actor, "github:alice");
        assert!(renamed.name.starts_with("github-alice-"), "{}", renamed.name);
        assert_eq!(renamed.identity.as_ref().map(|g| g.login.as_str()), Some("alice-smith"));
        let bound = accounts();
        assert_eq!((bound.len(), bound[0].login.as_str()), (1, "alice-smith"), "the latest login");
        assert!(bound[0].last_seen >= bound[0].first_seen);

        // Another account that took the login is refused, even once the first account's tokens are gone.
        let e = sign_in(&gh("Alice", 2)).unwrap_err();
        assert!(e.exit_code() == 7 && e.to_string().contains("belongs to another account"), "{e}");
        revoke_account(dir.path(), "github:alice", false).unwrap();
        let mut file = read(dir.path()).unwrap();
        for t in &mut file.tokens {
            t.expires_at = Some(Timestamp::now().minus(PRUNE_AFTER + hour));
        }
        put(dir.path(), file);
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        assert_eq!(read(dir.path()).unwrap().tokens.len(), 1, "alice's tokens were pruned");
        assert!(sign_in(&gh("alice", 2)).is_err(), "the binding outlives the tokens");
        let e = issue_token(dir.path(), "x", "github:alice/ci", Role::Write, Kind::Agent, &[]).unwrap_err();
        assert!(e.to_string().contains("bd serve token revoke --account github:alice --forget"), "{e}");

        // An id at another GitHub is another account.
        let (other, _) = sign_in(&Identity {
            provider: "github".into(),
            issuer: "https://ghe.example.com".into(),
            subject: "1".into(),
            login: "bob".into(),
        })
        .unwrap();
        assert_eq!(other.actor, "github:bob");
        assert_eq!(accounts().len(), 2);

        // Released, the actor goes to the next account signing in as it.
        let done = revoke_account(dir.path(), "alice-smith", true).unwrap();
        assert_eq!((done.accounts.len(), done.revoked.len()), (1, 0), "{done:?}");
        assert_eq!(accounts().len(), 1);
        assert_eq!(sign_in(&gh("alice", 2)).unwrap().0.actor, "github:alice");
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
        let mut done = revoke_account(dir.path(), "ALICE-NEW", false).unwrap();
        done.revoked.sort();
        let mut expected = vec![a1.name, a2.name];
        expected.sort();
        assert_eq!(done.revoked, expected, "by account: tokens from before a rename go too");
        assert_eq!(done.accounts.iter().map(|a| a.actor.as_str()).collect::<Vec<_>>(), ["github:Alice"]);
        let again = revoke_account(dir.path(), "github:alice", false).unwrap();
        assert!(again.revoked.is_empty() && again.accounts.len() == 1, "known by its actor too: {again:?}");
        assert_eq!(revoke_account(dir.path(), "nobody", false).unwrap_err().exit_code(), 3);
        let live: Vec<String> =
            read(dir.path()).unwrap().tokens.into_iter().filter(|t| t.revoked_at.is_none()).map(|t| t.name).collect();
        assert_eq!(live, [b.name, "ci".to_string()]);
    }

    #[test]
    fn github_accounts_never_share_actors_with_other_principals() {
        let dir = tempfile::tempdir().unwrap();
        let ttl = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let manual = |name: &str, actor: &str| issue_token(dir.path(), name, actor, Role::Write, Kind::Agent, &[]);
        manual("ci", "github:ci-agents").unwrap();
        manual("carol-ci", "github:carol/ci").unwrap();
        for (login, id) in [("ci-agents", 1), ("CI-Agents", 1), ("carol", 2)] {
            let e = github_token(dir.path(), &gh(login, id), grant.clone(), ttl, true).unwrap_err();
            assert_eq!(e.exit_code(), 7, "{login}: {e}");
            assert!(e.to_string().contains("another access token acts as"), "{e}");
        }
        assert!(read(dir.path()).unwrap().accounts.is_empty(), "a refused sign-in binds nothing");
        github_token(dir.path(), &gh("alice", 3), grant.clone(), ttl, true).unwrap();
        github_token(dir.path(), &gh("alice", 3), grant.clone(), ttl, true).unwrap();
        assert!(github_token(dir.path(), &gh("Alice", 4), grant.clone(), ttl, true).is_err(), "another account");
        for actor in ["github:alice", "GitHub:ALICE/ci"] {
            let e = manual("x", actor).unwrap_err();
            assert!(e.to_string().contains("bd serve token revoke --account github:alice --forget"), "{e}");
        }
        manual("alice2", "github:alice2").unwrap();
        manual("bare", "alice").unwrap();

        // Revoked, an account keeps its actor; released, the actor is free again. Admins' tokens may share theirs.
        revoke_account(dir.path(), "alice", false).unwrap();
        assert!(github_token(dir.path(), &gh("alice", 4), grant.clone(), ttl, true).is_err());
        assert!(manual("x", "github:alice").is_err());
        revoke_account(dir.path(), "alice", true).unwrap();
        github_token(dir.path(), &gh("alice", 4), grant, ttl, true).unwrap();
        manual("ci-2", "github:ci-agents").unwrap();
    }

    #[test]
    fn the_servers_own_actor_is_never_a_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let ttl = Duration::from_secs(3600);
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        for actor in ["bd-serve", "BD-Serve", "bd-serve/jobs"] {
            let e = issue_token(dir.path(), "x", actor, Role::Admin, Kind::Agent, &[]).unwrap_err();
            assert!(e.exit_code() == 2 && e.to_string().contains("reserved"), "{actor}: {e}");
        }
        assert!(read(dir.path()).unwrap().tokens.is_empty(), "nothing issued");
        // Sign-ins act under their provider's name, so a login never takes the server's actor.
        let (t, _) = github_token(dir.path(), &gh("bd-serve", 1), grant, ttl, true).unwrap();
        assert_eq!(t.actor, "github:bd-serve");
        for (name, actor) in [("a", "bd-server"), ("b", "bd"), ("c", "alice/bd-serve")] {
            issue_token(dir.path(), name, actor, Role::Write, Kind::Agent, &[]).unwrap();
        }
    }

    #[test]
    fn sign_ins_load_the_rows_their_checks_look_at_and_no_others() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let hour = Duration::from_secs(3600);
        for actor in ["GitHub:Alice/ci", "github:alice/ci/run-1", "github:alicex", "github:al", "bob"] {
            issue_token(
                dir.path(),
                &format!("t-{}", actor.replace([':', '/'], "-")),
                actor,
                Role::Write,
                Kind::Agent,
                &[],
            )
            .unwrap();
        }
        github_token(dir.path(), &gh("carol", 7), grant.clone(), hour, true).unwrap();
        // Renamed: carol's account is now alice-at-work, bound to github:carol.
        let renamed = gh("alice-at-work", 7);
        let names = |file: &TokenFile| {
            let mut tokens: Vec<String> = file.tokens.iter().map(|t| t.actor.clone()).collect();
            tokens.sort();
            let accounts: Vec<String> = file.accounts.iter().map(|a| a.actor.clone()).collect();
            (tokens, accounts)
        };
        let scope = |user: &Identity| read_scoped(dir.path(), Some(&Scope { user: Some(user), ..Scope::default() }));
        // alice: the tokens of github:alice, its ancestors and descendants, regardless of case; not alicex's or al's.
        let (tokens, accounts) = names(&scope(&gh("alice", 1)).unwrap());
        assert_eq!(tokens, ["GitHub:Alice/ci", "github:alice/ci/run-1"]);
        assert!(accounts.is_empty(), "{accounts:?}");
        // The renamed account: its own, by issuer and subject, and the actor it is bound to.
        let (tokens, accounts) = names(&scope(&renamed).unwrap());
        assert_eq!((tokens, accounts), (vec!["github:carol".to_string()], vec!["github:carol".to_string()]));
        // Another account taking the login carol's account has now: found by that login alone, as bind looks
        // at it (its own actor, github:alice-at-work, is unrelated to github:carol).
        github_token(dir.path(), &renamed, grant, hour, true).unwrap();
        let (_, accounts) = names(&scope(&gh("Alice-At-Work", 9)).unwrap());
        assert_eq!(accounts, ["github:carol"]);
        // An admin's actor: the tokens related to it.
        let file = read_scoped(dir.path(), Some(&Scope { actors: vec!["github:alice".into()], ..Scope::default() }));
        assert_eq!(names(&file.unwrap()).0.len(), 2);
        // A token by id brings its actor's.
        let all = read(dir.path()).unwrap();
        let ci = all.tokens.iter().find(|t| t.actor == "GitHub:Alice/ci").unwrap();
        let file = read_scoped(dir.path(), Some(&Scope { ids: &[ci.id.as_str()], ..Scope::default() })).unwrap();
        assert_eq!(names(&file).0, ["GitHub:Alice/ci", "github:alice/ci/run-1"]);
    }

    #[test]
    fn forgetting_an_account_leaves_nothing_of_it_in_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let hour = Duration::from_secs(3600);
        let files = || {
            ["server.db", "server.db-wal"]
                .iter()
                .flat_map(|f| std::fs::read(dir.path().join(f)).unwrap_or_default())
                .collect::<Vec<u8>>()
        };
        let has = |bytes: &[u8], what: &str| bytes.windows(what.len()).any(|w| w == what.as_bytes());
        github_token(dir.path(), &gh("forgettable-login", 41), grant.clone(), hour, true).unwrap();
        github_token(dir.path(), &gh("forgettable-login", 41), grant.clone(), hour, true).unwrap();
        github_token(dir.path(), &gh("keeper", 42), grant, hour, true).unwrap();
        assert!(has(&files(), "forgettable-login"));

        let done = revoke_account(dir.path(), "forgettable-login", false).unwrap();
        assert_eq!((done.revoked.len(), done.erased), (2, None));
        assert_eq!(read(dir.path()).unwrap().tokens.len(), 3, "revoked, still listed");
        let done = revoke_account(dir.path(), "github:forgettable-login", true).unwrap();
        assert_eq!(done.erased, Some(true));
        let file = read(dir.path()).unwrap();
        assert_eq!((file.tokens.len(), file.accounts.len()), (1, 1), "only keeper's");
        let bytes = files();
        assert!(!has(&bytes, "forgettable-login") && has(&bytes, "keeper"), "erased from the files themselves");
    }

    #[test]
    fn writers_wait_for_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let held = server_db::open(dir.path()).unwrap();
        held.execute_batch("BEGIN IMMEDIATE").unwrap();
        let root = dir.path().to_path_buf();
        let writer = std::thread::spawn(move || issue_token(&root, "ci", "ci", Role::Write, Kind::Agent, &[]));
        std::thread::sleep(Duration::from_millis(200));
        assert!(read(dir.path()).unwrap().tokens.is_empty(), "nothing is written while another writes");
        held.execute_batch("COMMIT").unwrap();
        writer.join().unwrap().unwrap();
        assert_eq!(read(dir.path()).unwrap().tokens.len(), 1);
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
        t.identity = Some(gh("alice", 1));
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
        let live = || read(dir.path()).unwrap().tokens.iter().filter(|t| t.revoked_at.is_none()).count();
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
        let text = raw(dir.path());
        assert!(text.contains("\"kind\":\"agent\"") && text.contains("\"kind\":\"human\""), "{text}");
        assert!(!text.contains("expires_at") && !text.contains("github"), "only sign-ins have them: {text}");

        let without = json!({
            "id": "0123456789abcdef", "name": "n", "actor": "alice", "role": "admin", "workspaces": ["*"],
            "sha256": hash("bdt_x"), "created_at": "2026-01-01T00:00:00Z",
        });
        let conn = server_db::open(dir.path()).unwrap();
        let sql =
            "INSERT INTO tokens (id, sha256, actor_key, name, data) VALUES ('0123456789abcdef', ?1, 'alice', 'n', ?2)";
        conn.execute(sql, [hash("bdt_x"), without.to_string()]).unwrap();
        let err = Verifier::new(dir.path()).verify("bdt_x").unwrap_err().to_string();
        assert!(err.contains("server.db") && err.contains("kind"), "{err}");
    }
}
