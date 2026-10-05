//! Access tokens for `bd serve`: who may call, as which actor, with which
//! role, and whether a person or an agent holds it.
//!
//! Tokens live in `<root>/server.db` (`server_db.rs`), which stores
//! only the SHA-256 of each secret. `bd serve token create` prints a secret
//! once; sign-in (`oauth/`) issues tokens that expire, recording the
//! account (its provider's issuer and subject), and, where access is decided
//! again at refreshes, a refresh secret (`bdr_<family>_<random>`): each
//! refresh replaces both secrets of the sign-in's entry in place, and a
//! refresh secret used twice revokes it. A token acts as one actor, or as
//! `<actor>/<name>` sub-actors (one per agent), so claims and leases keep meaning "this
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
//!
//! Here: tokens, accounts, grants and the request-time `Verifier`. Beside
//! it: `store` (`server.db` transactions, scoped loads, pruning), `issue`
//! (issuing, finding and refreshing tokens), `binding` (accounts' actors:
//! binding, conflicts, links, names, revocation, forgetting) and `admin`
//! (`bd serve token …`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::{App, Out};
use crate::cli::{
    TokenCommand, TokenCreateArgs, TokenEventsArgs, TokenLinkArgs, TokenNameArgs, TokenRevokeArgs, TokenRootArgs,
};
use crate::protocol::valid_workspace_name;
use crate::server_db::{self, AuthEvent};

mod admin;
mod binding;
mod issue;
mod store;

pub use admin::*;
pub use binding::*;
pub use issue::*;
use store::*;

/// Tokens stay listed this long after they end (revoked, or a sign-in's
/// expired and no longer refreshed), then are deleted at the next write.
/// The live sign-ins an account keeps at one client (or at none, for
/// `bd remote login`): signing in again past it revokes the oldest, so
/// that clients authorizing anew each time do not pile up live tokens.
const MAX_SIGN_INS: usize = 20;

/// How long a token check waits while `server.db` is busy (a reader rarely
/// is, as when its write-ahead log is reset), before the request is told to
/// retry (503).
const VERIFY_WAIT: Duration = Duration::from_millis(250);

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
    /// When the token stops working: set on tokens from sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The account that signed in for the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// The most issues its actor and sub-actors may hold, claimed or reserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<u32>,
    /// How a token from sign-in is refreshed, if it is.
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

/// The refresh state of a sign-in: one per token entry, whose secrets each
/// refresh replaces.
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
    /// The fingerprint of the `[[oidc.<name>.allow]]` rule that last let it
    /// in: one that decides by the ID token's claims keeps it while it is there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
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

    /// How messages name it: `GitHub user alice`, `google account u-3f9a2c1e7b04`.
    pub fn who(&self) -> String {
        who(&self.provider, &self.login)
    }

    /// The actor an account takes at its first sign-in: its login under its
    /// provider's name (`github:alice`, `google:u-3f9a2c1e7b04`), so that no
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
    /// What an admin calls the account (`bd serve token name`), as its actor
    /// may be a pseudonym: the admin's, never the provider's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Account {
    /// Whether `user` is this account.
    fn is(&self, user: &Identity) -> bool {
        self.subject == user.subject && self.issuer == user.issuer
    }

    /// Whether `other` is this account (another record of it).
    fn is_same(&self, other: &Account) -> bool {
        self.subject == other.subject && self.issuer == other.issuer
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

/// `bd serve`'s own actor ([`crate::jobs::ACTOR`]) or one of its sub-actors,
/// whatever the case: no token or request may act as it, so the history
/// tells the server's background writes from clients'.
pub fn is_reserved_actor(actor: &str) -> bool {
    related(crate::jobs::ACTOR, actor)
}

/// Whether one of two actors is the other, or one of its sub-actors
/// (`<actor>/<name>`), whatever their case.
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

    /// Whether the token was revoked, or expired with no refresh left at `now`.
    fn ended(&self, now: Timestamp) -> bool {
        self.revoked_at.is_some() || (self.expired(now) && self.refresh.as_ref().is_none_or(|r| r.until <= now))
    }

    /// An event of this token, for the audit trail.
    fn event(&self, kind: &'static str, detail: Option<&str>) -> AuthEvent {
        let id = self.identity.as_ref();
        AuthEvent {
            kind,
            actor: Some(self.actor.clone()),
            provider: id.map(|g| g.provider.clone()),
            issuer: id.map(|g| g.issuer.clone()),
            subject: id.map(|g| g.subject.clone()),
            token: Some(self.name.clone()),
            client: self.client.clone(),
            detail: detail.map(str::to_string),
        }
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

#[cfg(test)]
thread_local! {
    /// Load every row where a scope would do: the test that scoped loads
    /// decide as whole ones runs each change both ways.
    static WHOLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
        let found = self.live_where("sha256", &hash(secret))?;
        Ok(match found.into_iter().next() {
            Some(t) if t.expired(Timestamp::now()) => Verified::Expired(t),
            Some(t) => Verified::Valid(t),
            None => Verified::Unknown,
        })
    }

    /// Whether this refresh secret is of a sign-in that is not revoked (its
    /// current secret or one spent): asked before a refresh takes a slot,
    /// on the connection kept for checking tokens.
    pub fn knows_refresh(&self, secret: &str) -> Result<bool> {
        let Some(family) = refresh_family(secret) else { return Ok(false) };
        Ok(!self.live_where("family", &family.to_ascii_lowercase())?.is_empty())
    }

    /// The tokens that are not revoked whose `column` is `value`, on the
    /// connection kept (opened again if it failed, or the file was replaced);
    /// none without a database.
    fn live_where(&self, column: &str, value: &str) -> Result<Vec<Token>> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let file = server_db::file_id(&self.root);
        if conn.as_ref().is_none_or(|(_, opened)| *opened != file) {
            *conn = None;
            let Some(opened) = server_db::open_existing(&self.root)? else { return Ok(Vec::new()) };
            // Checked on the server's async threads, under this lock: never a long wait for a writer.
            opened.busy_timeout(VERIFY_WAIT)?;
            *conn = Some((opened, server_db::file_id(&self.root)));
        }
        let found = live_where(&conn.as_ref().expect("opened").0, column, value);
        if found.is_err() {
            *conn = None;
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`rotate`], its [`Rotation`] spelled out in order.
    #[allow(clippy::too_many_arguments)]
    fn rotate_with(
        root: &Path,
        id: &str,
        current: &str,
        last: LastRefresh,
        user: &Identity,
        fresh: bool,
        grant: Grant,
        by_login: bool,
        decided: bool,
        rule: Option<String>,
        expires_at: Timestamp,
        until: Timestamp,
    ) -> Result<Option<Issued>> {
        let rotation = Rotation { last, user, fresh, grant, by_login, decided, rule, expires_at, until };
        rotate(root, id, current, rotation)
    }

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
        let life = Lifetime { ttl, refresh: None, rule: None };
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
        put(dir.path(), TokenFile { tokens: vec![t.clone()], ..TokenFile::default() });
        assert_eq!(actor("bdt_secret"), Some("alice".to_string()));
        assert_eq!(actor("bdt_other"), None);
        t.revoked_at = Some("2026-01-01T00:00:00Z".into());
        put(dir.path(), TokenFile { tokens: vec![t], ..TokenFile::default() });
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
        put(dir.path(), TokenFile { tokens: vec![t.clone()], ..TokenFile::default() });
        let v = Verifier::new(dir.path());
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Valid(_)));
        t.expires_at = Some(Timestamp::now().minus(Duration::from_secs(1)));
        put(dir.path(), TokenFile { tokens: vec![t.clone()], ..TokenFile::default() });
        assert!(matches!(v.verify("bdt_secret").unwrap(), Verified::Expired(e) if e.name == "n"));
        let stamp = t.expires_at.unwrap().to_rfc3339();
        edit(dir.path(), &stamp, "soon");
        assert!(v.verify("bdt_secret").is_err(), "an expiry that is not a time fails closed");
        edit(dir.path(), "soon", &stamp);
        t.revoked_at = Some(Timestamp::now().to_rfc3339());
        put(dir.path(), TokenFile { tokens: vec![t], ..TokenFile::default() });
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
        put(dir.path(), TokenFile { tokens, ..TokenFile::default() });
        // Any write: here, revoking another token.
        let (other, _) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let names: Vec<String> = read(dir.path()).unwrap().tokens.into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["recent-sign-in", "manual", "manual-expired", "revoked-recently", "ci"]);
        let old = Timestamp::now().minus(PRUNE_AFTER + day).to_rfc3339();
        edit(dir.path(), "\"name\":\"manual\"", &format!("\"name\":\"manual\",\"revoked_at\":\"{old}\""));
        let conn = server_db::open(dir.path()).unwrap();
        conn.execute("UPDATE tokens SET ended_at = 0 WHERE name = 'manual'", []).unwrap();
        assert!(revoke_by_id(dir.path(), &other.id, "test").unwrap());
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
                rule: None,
            });
            t
        };
        let tokens = vec![entry("refreshable", now.plus(day)), entry("ended", now.minus(PRUNE_AFTER + day))];
        put(dir.path(), TokenFile { tokens, ..TokenFile::default() });
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
        let life = Lifetime { ttl: hour, refresh: Some((now.plus(week * 4), week)), rule: None };
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
        let rotated = rotate_with(
            dir.path(),
            &t.id,
            &hash(&first),
            last(&first, "r1"),
            &renamed,
            true,
            reader,
            true,
            true,
            None,
            expires,
            until,
        )
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
        let again = rotate_with(
            dir.path(),
            &t.id,
            &hash(&first),
            last(&first, "r2"),
            &renamed,
            true,
            grant.clone(),
            true,
            true,
            None,
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
        assert!(revoke_by_id(dir.path(), &t.id, "test").unwrap());
        assert!(find_refresh(dir.path(), &second).unwrap().is_none(), "revoked");

        let once = Lifetime { ttl: hour, refresh: None, rule: None };
        let plain = issue_sign_in_token(dir.path(), &alice, grant, once, "proj", true).unwrap();
        assert!(plain.refresh_secret.is_none() && plain.token.refresh.is_none());
    }

    #[test]
    fn a_refresh_replaying_a_kept_login_does_not_rename_the_account_back() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = || Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let old = issue_sign_in_token(dir.path(), &gh("alice", 1), grant.clone(), life(), "proj", true).unwrap();
        issue_sign_in_token(dir.path(), &gh("alice.smith", 1), grant.clone(), life(), "proj", true).unwrap();
        // The old sign-in refreshes with the identity it kept (no provider asked again).
        let secret = old.refresh_secret.unwrap();
        let last = LastRefresh { spent: hash(&secret), request: hash("r1") };
        let (now, kept) = (Timestamp::now(), old.token.identity.clone().unwrap());
        let until = now.plus(week);
        rotate_with(
            dir.path(),
            &old.token.id,
            &hash(&secret),
            last,
            &kept,
            false,
            grant,
            true,
            true,
            None,
            now.plus(hour),
            until,
        )
        .unwrap()
        .unwrap();
        assert_eq!(read(dir.path()).unwrap().accounts[0].login, "alice.smith", "still its latest login");
        let done = revoke_account(dir.path(), "alice.smith", false).unwrap();
        assert_eq!(done.revoked.len(), 2, "both sign-ins, by its latest login: {done:?}");
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
        assert!(e.to_string().contains("names a provider's account"), "{e}");

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
        // An admin may not name a provider's account's actor at all...
        for actor in ["github:ci-agents", "GitHub:Carol/ci", "okta:x"] {
            let e = manual("ci", actor).unwrap_err();
            assert!(e.to_string().contains("names a provider's account"), "{actor}: {e}");
        }
        // ...and were such tokens there (written another way), sign-ins would still not share their actors.
        let admins: Vec<Token> = [("ci", "github:ci-agents"), ("carol-ci", "github:carol/ci")]
            .iter()
            .map(|(name, actor)| {
                let mut t = token(actor, &["*"]);
                (t.id, t.name) = (name.to_string(), name.to_string());
                t
            })
            .collect();
        put(dir.path(), TokenFile { tokens: admins, ..TokenFile::default() });
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
            assert!(manual("x", actor).is_err(), "{actor}");
        }
        manual("alice2", "alice2").unwrap();
        manual("bare", "alice").unwrap();

        // Revoked, an account keeps its actor; released, the actor is free again. Admins' tokens may share theirs.
        revoke_account(dir.path(), "alice", false).unwrap();
        assert!(github_token(dir.path(), &gh("alice", 4), grant.clone(), ttl, true).is_err());
        revoke_account(dir.path(), "alice", true).unwrap();
        github_token(dir.path(), &gh("alice", 4), grant, ttl, true).unwrap();
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
        // Tokens of actors related in every way to github:alice, written as rows (an admin may not create them).
        let rows: Vec<Token> = ["GitHub:Alice/ci", "github:alice/ci/run-1", "github:alicex", "github:al", "bob"]
            .iter()
            .map(|actor| {
                let mut t = token(actor, &["*"]);
                let name = format!("t-{}", actor.replace([':', '/'], "-"));
                (t.id, t.name) = (name.clone(), name);
                t
            })
            .collect();
        put(dir.path(), TokenFile { tokens: rows, ..TokenFile::default() });
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
    fn the_audit_trail_records_each_change_and_forgets_with_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let alice = issue_sign_in_token(dir.path(), &gh("alice", 1), grant.clone(), life, "proj", true).unwrap();
        issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let secret = alice.refresh_secret.unwrap();
        let last = LastRefresh { spent: hash(&secret), request: hash("r1") };
        let (now, user) = (Timestamp::now(), gh("alice", 1));
        rotate_with(
            dir.path(),
            &alice.token.id,
            &hash(&secret),
            last,
            &user,
            true,
            grant,
            true,
            true,
            None,
            now.plus(hour),
            now.plus(week),
        )
        .unwrap()
        .unwrap();
        assert!(revoke_by_id(dir.path(), &alice.token.id, "its holder logged out").unwrap());
        let all = |actor: Option<&str>| server_db::events(dir.path(), 0, actor, &[], 100).unwrap();
        let kinds: Vec<&str> = all(None).iter().map(|e| e.event.kind).collect();
        assert_eq!(kinds, ["signed_in", "token_created", "refreshed", "revoked"]);
        let revoked = &all(None)[3].event;
        assert_eq!(
            (revoked.actor.as_deref(), revoked.subject.as_deref(), revoked.detail.as_deref()),
            (Some("github:alice"), Some("1"), Some("its holder logged out"))
        );
        assert_eq!(all(Some("GitHub:Alice")).len(), 3, "an actor's, whatever its case");
        assert_eq!(server_db::events(dir.path(), 0, None, &[], 2).unwrap()[0].event.kind, "refreshed", "the latest");

        // Forgotten: nothing of the account stays, but that it was.
        revoke_account(dir.path(), "github:alice", true).unwrap();
        let after = all(None);
        assert!(after.iter().all(|e| e.event.subject.is_none() && e.event.actor.as_deref() != Some("github:alice")));
        let kinds: Vec<&str> = after.iter().map(|e| e.event.kind).collect();
        assert_eq!(kinds, ["token_created", "forgotten"]);
        assert_eq!(after[1].event.provider.as_deref(), Some("github"));

        // Kept 90 days: older ones go at the next write.
        let conn = server_db::open(dir.path()).unwrap();
        let old = Timestamp::now().millis() - i64::try_from(server_db::EVENTS_KEPT.as_millis()).unwrap() - 1;
        conn.execute("UPDATE auth_events SET at = ?1 WHERE kind = 'token_created'", [old]).unwrap();
        issue_token(dir.path(), "ci-2", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        let kinds: Vec<&str> = all(None).iter().map(|e| e.event.kind).collect();
        assert_eq!(kinds, ["forgotten", "token_created"]);
    }

    #[test]
    fn an_admin_links_one_persons_accounts_at_several_providers_to_one_actor() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let hour = Duration::from_secs(3600);
        let apple = Identity {
            provider: "apple".into(),
            issuer: "https://appleid.apple.com".into(),
            subject: "001.abc.9".into(),
            login: "u-0123456789ab".into(),
        };
        let sign_in = |user: &Identity| github_token(dir.path(), user, grant.clone(), hour, true);
        let (gh_token, gh_secret) = sign_in(&gh("alice", 1)).unwrap();
        let (apple_token, _) = sign_in(&apple).unwrap();
        assert_eq!(apple_token.actor, "apple:u-0123456789ab");

        // Refused: an actor no account has, or its own.
        assert_eq!(link(dir.path(), "apple:u-0123456789ab", "github:nobody").unwrap_err().exit_code(), 3);
        assert!(link(dir.path(), "github:alice", "github:alice").is_err(), "no other account has it");

        let done = link(dir.path(), "u-0123456789ab", "GitHub:Alice").unwrap();
        assert_eq!((done.was.as_str(), done.account.actor.as_str()), ("apple:u-0123456789ab", "github:alice"));
        assert_eq!(done.revoked, std::slice::from_ref(&apple_token.name), "its tokens acted as its former actor");
        // Both sign in as the one actor, neither refused for the other's tokens.
        let (again, _) = sign_in(&apple).unwrap();
        assert_eq!(again.actor, "github:alice");
        assert_eq!(sign_in(&gh("alice", 1)).unwrap().0.actor, "github:alice");
        assert!(matches!(Verifier::new(dir.path()).verify(&gh_secret).unwrap(), Verified::Valid(_)), "untouched");
        // Nobody else gets it, nor its old one back by accident: a new Apple account is its own.
        let other = Identity { subject: "002.def.1".into(), login: "u-ffffffffffff".into(), ..apple.clone() };
        assert_eq!(sign_in(&other).unwrap().0.actor, "apple:u-ffffffffffff");
        assert!(issue_token(dir.path(), "x", "github:alice/ci", Role::Write, Kind::Agent, &[]).is_err());
        let kinds: Vec<&str> = server_db::events(dir.path(), 0, Some("github:alice"), &[], 100)
            .unwrap()
            .iter()
            .map(|e| e.event.kind)
            .collect();
        assert!(kinds.contains(&"linked"), "{kinds:?}");

        // Its actor names both accounts: revoked, or forgotten, together.
        let done = revoke_account(dir.path(), "github:alice", true).unwrap();
        assert_eq!(done.accounts.len(), 2);
        assert!(read(dir.path()).unwrap().accounts.iter().all(|a| a.actor != "github:alice"));
        assert!(!read(dir.path()).unwrap().tokens.iter().any(|t| t.id == gh_token.id));
    }

    #[test]
    fn admins_name_accounts_and_the_name_goes_with_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let apple = Identity {
            provider: "apple".into(),
            issuer: "https://appleid.apple.com".into(),
            subject: "001.abc.9".into(),
            login: "u-0123456789ab".into(),
        };
        github_token(dir.path(), &apple, grant.clone(), Duration::from_secs(3600), true).unwrap();
        let named = set_name(dir.path(), "apple:u-0123456789ab", Some("Quang (Apple)")).unwrap();
        assert_eq!(named.name.as_deref(), Some("Quang (Apple)"));
        assert_eq!(read(dir.path()).unwrap().accounts[0].name.as_deref(), Some("Quang (Apple)"));
        // A sign-in keeps it.
        github_token(dir.path(), &apple, grant, Duration::from_secs(3600), true).unwrap();
        assert_eq!(read(dir.path()).unwrap().accounts[0].name.as_deref(), Some("Quang (Apple)"));
        for bad in ["", "a\u{202e}b", &"x".repeat(65)] {
            assert!(set_name(dir.path(), "apple:u-0123456789ab", Some(bad)).is_err(), "{bad:?}");
        }
        assert_eq!(set_name(dir.path(), "nobody", Some("x")).unwrap_err().exit_code(), 3);
        assert_eq!(set_name(dir.path(), "u-0123456789ab", None).unwrap().name, None, "by login, cleared");
        set_name(dir.path(), "apple:u-0123456789ab", Some("Quang")).unwrap();
        // Forgotten, with every trace of it.
        revoke_account(dir.path(), "apple:u-0123456789ab", true).unwrap();
        assert!(server_db::events(dir.path(), 0, None, &[], 100).unwrap().iter().all(|e| e.event.kind == "forgotten"));
    }

    /// What a database holds, without what differs between two runs of the
    /// same changes (ids, secrets, times): to compare them.
    fn state(root: &Path) -> Vec<String> {
        let file = read(root).unwrap();
        let mut rows: Vec<String> = file
            .tokens
            .iter()
            .map(|t| {
                let who = t.identity.as_ref().map(|g| format!("{}/{}/{}", g.issuer, g.subject, g.login));
                format!("token {} {:?} {} {}", t.actor, who, t.revoked_at.is_some(), t.client.is_some())
            })
            .chain(file.accounts.iter().map(|a| format!("account {} {} {} {}", a.issuer, a.subject, a.actor, a.login)))
            .collect();
        rows.sort();
        rows
    }

    #[test]
    fn scoped_loads_decide_as_loading_every_row_would() {
        // Logins and actors that relate to each other in every way the checks look at: case, sub-actors,
        // prefixes that are not sub-actors, '/' in logins, the same login at two providers, renames.
        const LOGINS: &[&str] = &["alice", "Alice", "ALICE", "al", "alice-smith", "alice/x", "alicex", "bob", "Bob"];
        const ADMIN: &[&str] =
            &["github:alice", "GitHub:Alice/ci", "github:al", "github:alice-x", "okta:bob", "okta:BOB/w", "carol"];
        let user = |n: u64, login: &str| {
            let (provider, issuer) =
                if n.is_multiple_of(3) { ("okta", "https://okta.example") } else { ("github", GITHUB) };
            Identity {
                provider: provider.into(),
                issuer: issuer.into(),
                subject: (n % 7).to_string(),
                login: login.into(),
            }
        };
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        // Seeds run on threads of their own (`WHOLE` is per thread).
        let seed_run = |seed: u64| {
            let mut seen = std::collections::BTreeSet::new();
            let (scoped_dir, whole_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut next = |n: u64| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng % n
            };
            for step in 0..200 {
                let (op, a, b, c) = (next(8), next(100), next(LOGINS.len() as u64), next(2) == 0);
                let login = LOGINS[b as usize];
                let id = user(a, login);
                // The same change on both: scoped, then loading every row.
                let run = |root: &Path, whole: bool| -> String {
                    WHOLE.set(whole);
                    let life =
                        Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
                    let out = match op {
                        0 | 1 => issue_sign_in_token(root, &id, grant.clone(), life, "proj", c)
                            .map(|i| format!("signed in as {}", i.token.actor)),
                        2 => issue_token(
                            root,
                            &format!("t{step}"),
                            ADMIN[(a % 7) as usize],
                            Role::Write,
                            Kind::Agent,
                            &[],
                        )
                        .map(|(t, _)| format!("admin token {}", t.actor)),
                        3 => preview_actor(root, &id, c),
                        4 => {
                            let target = ADMIN[(a % 7) as usize];
                            link(root, &id.actor(), target).map(|l| format!("linked {} to {}", l.was, l.account.actor))
                        }
                        5 => revoke_account(root, login, c)
                            .map(|d| format!("revoked {} of {}", d.revoked.len(), d.accounts.len())),
                        _ => {
                            // A live sign-in of this account in this database: refreshed as `id` names it now.
                            let file = read(root).unwrap();
                            let theirs =
                                |t: &&Token| t.revoked_at.is_none() && t.identity.as_ref().is_some_and(|g| g.same(&id));
                            match file.tokens.iter().find(theirs).and_then(|t| Some((t.id.clone(), t.refresh.clone()?)))
                            {
                                Some((token, state)) => {
                                    let last =
                                        LastRefresh { spent: state.sha256.clone(), request: hash(&step.to_string()) };
                                    let (now, g) = (Timestamp::now(), grant.clone());
                                    rotate_with(
                                        root,
                                        &token,
                                        &state.sha256,
                                        last,
                                        &id,
                                        c,
                                        g,
                                        true,
                                        true,
                                        None,
                                        now.plus(hour),
                                        now.plus(week),
                                    )
                                    .map(|r| format!("rotated {:?}", r.map(|i| i.token.actor)))
                                }
                                None => Ok("nothing to refresh".into()),
                            }
                        }
                    };
                    WHOLE.set(false);
                    match out {
                        Ok(s) => s,
                        Err(e) => format!("error {}", e.exit_code()),
                    }
                };
                // Refreshes need each database's own token ids and secrets: find them by account in each.
                let scoped_out = run(scoped_dir.path(), false);
                let whole_out = run(whole_dir.path(), true);
                assert_eq!(scoped_out, whole_out, "seed {seed} step {step}: op {op} {id:?} {c}");
                assert_eq!(state(scoped_dir.path()), state(whole_dir.path()), "seed {seed} step {step}");
                seen.insert(scoped_out.split(' ').take(2).collect::<Vec<_>>().join(" "));
            }
            seen
        };
        let seen: std::collections::BTreeSet<String> = std::thread::scope(|scope| {
            let runs: Vec<_> = (1..=4u64).map(|seed| scope.spawn(move || seed_run(seed))).collect();
            runs.into_iter().flat_map(|run| run.join().unwrap()).collect()
        });
        // The run reached the checks it is about: refusals for another's actor, links, refreshes both ways.
        for outcome in ["error 7", "admin token", "linked ", "rotated Some(", "revoked 2", "signed in"] {
            assert!(seen.iter().any(|s| s.starts_with(outcome)), "never {outcome}: {seen:?}");
        }
    }

    #[test]
    fn the_verifier_knows_refresh_secrets_of_live_sign_ins_only() {
        let dir = tempfile::tempdir().unwrap();
        let v = Verifier::new(dir.path());
        assert!(!v.knows_refresh("bdr_00_00").unwrap(), "no database yet");
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let issued = issue_sign_in_token(dir.path(), &gh("alice", 1), grant, life, "proj", true).unwrap();
        let secret = issued.refresh_secret.unwrap();
        assert!(v.knows_refresh(&secret).unwrap());
        let forged = format!("bdr_{}_{}", "1".repeat(32), "0".repeat(64));
        assert!(!v.knows_refresh(&forged).unwrap() && !v.knows_refresh("bdt_x").unwrap());
        assert!(revoke_by_id(dir.path(), &issued.token.id, "test").unwrap());
        assert!(!v.knows_refresh(&secret).unwrap(), "revoked");
    }

    #[test]
    fn accounts_keep_their_newest_sign_ins_at_each_client() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let sign_in =
            |user: &Identity| issue_sign_in_token(dir.path(), user, grant.clone(), life.clone(), "proj", true);
        let first: Vec<String> = (0..MAX_SIGN_INS + 2).map(|_| sign_in(&gh("alice", 1)).unwrap().token.id).collect();
        sign_in(&gh("bob", 2)).unwrap();
        let file = read(dir.path()).unwrap();
        let live = |id: &str| file.tokens.iter().any(|t| t.id == id && t.revoked_at.is_none());
        assert!(!live(&first[0]) && !live(&first[1]), "the oldest two are revoked");
        assert!(first[2..].iter().all(|id| live(id)), "the newest {MAX_SIGN_INS} are kept");
        assert_eq!(file.tokens.iter().filter(|t| t.revoked_at.is_none()).count(), MAX_SIGN_INS + 1, "bob's too");
    }

    #[test]
    fn events_filter_by_actor_sub_actors_and_kind() {
        let dir = tempfile::tempdir().unwrap();
        for (name, actor) in [("a", "ops"), ("b", "Ops/CI"), ("c", "ops-x"), ("d", "opsy/ci")] {
            issue_token(dir.path(), name, actor, Role::Write, Kind::Agent, &[]).unwrap();
        }
        assert!(revoke_by_id(dir.path(), &read(dir.path()).unwrap().tokens[1].id, "test").unwrap());
        let events = |actor: Option<&str>, kinds: &[&str], limit: usize| -> Vec<(String, &'static str)> {
            let kinds: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
            let found = server_db::events(dir.path(), 0, actor, &kinds, limit).unwrap();
            found.into_iter().map(|e| (e.event.token.unwrap(), e.event.kind)).collect()
        };
        let named = |pairs: &[(&str, &'static str)]| -> Vec<(String, &'static str)> {
            pairs.iter().map(|(n, k)| (n.to_string(), *k)).collect()
        };
        assert_eq!(
            events(Some("OPS"), &[], 100),
            named(&[("a", "token_created"), ("b", "token_created"), ("b", "revoked")]),
            "itself and its sub-actors, whatever their case; not ops-x nor opsy/ci"
        );
        assert_eq!(events(Some("ops"), &["revoked"], 100), named(&[("b", "revoked")]));
        assert_eq!(events(None, &["token_created"], 2), named(&[("c", "token_created"), ("d", "token_created")]));
        assert_eq!(events(Some("ops/ci"), &[], 1), named(&[("b", "revoked")]), "the latest");
    }

    #[test]
    fn forgetting_a_linked_account_erases_the_tokens_of_its_former_actor() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let life = Lifetime { ttl: Duration::from_secs(3600), refresh: None, rule: None };
        let apple = Identity {
            provider: "apple".into(),
            issuer: "https://appleid.apple.com".into(),
            subject: "001.abc.1".into(),
            login: "u-0123456789ab".into(),
        };
        issue_sign_in_token(dir.path(), &gh("alice", 1), grant.clone(), life.clone(), "proj", true).unwrap();
        issue_sign_in_token(dir.path(), &apple, grant, life, "proj", true).unwrap();
        link(dir.path(), "apple:u-0123456789ab", "github:alice").unwrap();
        assert!(forget_account(dir.path(), &apple.issuer, &apple.subject).unwrap());
        let tokens = read(dir.path()).unwrap().tokens;
        assert!(tokens.iter().all(|t| t.identity.as_ref().is_none_or(|g| !g.same(&apple))), "{tokens:?}");
        assert_eq!(tokens.len(), 1, "github:alice's stays");
    }

    #[test]
    fn the_sign_in_cap_counts_each_client_apart() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let alice = gh("alice", 1);
        let resource = "https://bd.example.com/w/proj/mcp";
        let at = |client: &'static str| ForClient { id: client, resource };
        let cli = issue_sign_in_token(dir.path(), &alice, grant.clone(), life.clone(), "proj", true).unwrap();
        let other =
            issue_client_token(dir.path(), &alice, grant.clone(), life.clone(), at("https://b.example/c"), true);
        let first: Vec<String> = (0..MAX_SIGN_INS + 1)
            .map(|_| {
                let issued = issue_client_token(
                    dir.path(),
                    &alice,
                    grant.clone(),
                    life.clone(),
                    at("https://a.example/c"),
                    true,
                );
                issued.unwrap().token.id
            })
            .collect();
        let file = read(dir.path()).unwrap();
        let live = |id: &str| file.tokens.iter().any(|t| t.id == id && t.revoked_at.is_none());
        assert!(!live(&first[0]) && first[1..].iter().all(|id| live(id)), "the client's oldest goes");
        assert!(live(&cli.token.id) && live(&other.unwrap().token.id), "the CLI's and another client's stay");
    }

    /// Replace `from` with `to` in the accounts' stored records and lookup columns.
    fn edit_accounts(root: &Path, from: &str, to: &str) {
        let conn = server_db::open(root).unwrap();
        let sql = "UPDATE accounts SET data = replace(data, ?1, ?2), actor_key = replace(actor_key, ?1, ?2)";
        conn.execute(sql, [from, to]).unwrap();
    }

    #[test]
    fn a_refresh_is_refused_once_the_account_acts_as_another_actor() {
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let (hour, week) = (Duration::from_secs(3600), Duration::from_secs(7 * 24 * 3600));
        let life = Lifetime { ttl: hour, refresh: Some((Timestamp::now().plus(week * 4), week)), rule: None };
        let alice = gh("alice", 1);
        let issued = issue_sign_in_token(dir.path(), &alice, grant.clone(), life, "proj", false).unwrap();
        let state = issued.token.refresh.clone().unwrap();
        // Bound to another actor since (as a link does, its tokens otherwise revoked with it).
        edit_accounts(dir.path(), "github:alice", "github:carol");
        let last = LastRefresh { spent: state.sha256.clone(), request: hash("r") };
        let now = Timestamp::now();
        let e = rotate_with(
            dir.path(),
            &issued.token.id,
            &state.sha256,
            last,
            &alice,
            true,
            grant,
            false,
            true,
            None,
            now.plus(hour),
            now.plus(week),
        );
        let Err(e) = e else { panic!("rotated") };
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("now acts as github:carol"), "{e}");
    }

    #[test]
    fn no_account_signs_in_as_the_servers_own_actor() {
        // Accounts' actors carry their provider's name, so none takes `bd-serve`; were one bound to it, it is refused.
        let dir = tempfile::tempdir().unwrap();
        let grant = Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec![], max_claims: None };
        let life = Lifetime { ttl: Duration::from_secs(3600), refresh: None, rule: None };
        let mallory = gh("mallory", 9);
        issue_sign_in_token(dir.path(), &mallory, grant.clone(), life.clone(), "proj", false).unwrap();
        edit_accounts(dir.path(), "github:mallory", crate::jobs::ACTOR);
        let Err(e) = issue_sign_in_token(dir.path(), &mallory, grant, life, "proj", false) else { panic!("issued") };
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("is bd serve's own"), "{e}");
        assert!(preview_actor(dir.path(), &mallory, false).is_err());
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
        revoke_where(dir.path(), "test", |_| true).unwrap();
        let (second, _) = issue_token(dir.path(), "ci", "ci", Role::Write, Kind::Agent, &[]).unwrap();
        assert!(!revoke_by_id(dir.path(), &first.id, "test").unwrap(), "already revoked");
        let live = || read(dir.path()).unwrap().tokens.iter().filter(|t| t.revoked_at.is_none()).count();
        assert_eq!(live(), 1, "the later token of the same name is untouched");
        assert!(revoke_by_id(dir.path(), &second.id, "test").unwrap());
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
