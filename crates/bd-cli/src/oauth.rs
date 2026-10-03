//! GitHub sign-in: people get a `bd serve` access token by signing in with
//! GitHub (`bd remote login --github`), instead of an admin creating one.
//!
//! `<root>/auth.toml` turns it on and decides who may sign in, and what
//! their token may do:
//!
//! ```toml
//! [github]
//! client_id = "Ov23li0123456789abcd"  # a GitHub OAuth app or GitHub App, with device flow enabled
//! private_key = "github-app.pem"     # the GitHub App's private key (relative to the root): refreshes tokens
//! token_ttl = "1h"                    # access tokens expire (default 1h)
//! refresh_limit = "30d"               # refreshed for at most this long after the sign-in (default 30d)
//! refresh_idle = "7d"                 # and not after this long without a refresh (default 7d)
//! deny = [12345]                      # GitHub user ids that may never sign in
//!
//! [[github.allow]]                    # the first rule that lets the account into the workspace decides
//! users = ["alice"]
//! role = "admin"
//! kind = "human"
//!
//! [[github.allow]]
//! orgs = ["acme"]                     # active members of any of these organizations
//! teams = ["acme/bd-maintainers"]     # or of any of these teams
//! workspaces = ["proj"]
//!
//! [[github.allow]]
//! anyone = true                       # any GitHub account (an open project): last, read (default) or write
//! workspaces = ["oss"]
//! min_account_age = "30d"             # GitHub accounts younger than this are not let in by the rule
//! max_claims = 3                      # its tokens' actors may hold at most 3 issues, claimed or reserved
//!
//! [oauth]                             # MCP clients sign people in with OAuth (oauth_server.rs)
//! redirect_hosts = ["chatgpt.com", "claude.ai"]  # https redirect URIs on these hosts, without a port
//! loopback_redirects = true           # and http://127.0.0.1, [::1] or localhost on any port (desktop clients)
//! ```
//!
//! The server runs GitHub's device flow for the client, so the GitHub token
//! never leaves it: `POST <server>/v2/auth/github/device` asks GitHub for a
//! one-time code, which the person enters at GitHub, and the client polls
//! `POST <server>/v2/auth/github/token` until they did. Then the server reads
//! the account and the memberships the rules name with the GitHub token it
//! got, and issues an access token (`auth.rs`) with the permissions of the
//! first rule that matches. The GitHub token serves for this only: it is
//! never stored, logged or sent on. GitHub gives a code's token once, so
//! `bd serve` keeps the answer that issued a bd token for a few minutes, for
//! a client whose answer was lost (serve.rs). `auth.toml` is read for every
//! request, so a change applies from the next sign-in or refresh; tokens
//! already issued keep their permissions until they expire, are refreshed,
//! or are revoked.
//!
//! With `private_key` (a GitHub App's, with read access to organization
//! members, installed on every organization the rules name, or anywhere for
//! rules without any), each sign-in also gets a refresh secret, which the
//! client sends to `POST <server>/v2/auth/refresh` as its access token nears
//! its end. The server applies the rules again, asking GitHub with an
//! installation token of the App (never the account's own token, which it
//! does not keep): the account as GitHub names it now (by its user id), and
//! its memberships. If they still let the account into the workspace it
//! signed in for, the sign-in gets new secrets with what the first matching
//! rule grants now; if not, it is revoked. A refresh secret works once: one
//! used again revokes the sign-in, as someone else may hold a copy.
//!
//! `[oauth]` makes `bd serve` an OAuth authorization server for MCP
//! clients, such as ChatGPT, that sign people in with OAuth rather than
//! send a token they were given: people sign in with GitHub under the same
//! rules, and their tokens last and are refreshed as `[github]` says, so it
//! needs `private_key`. The server's `--public-url` is its issuer.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use bd_core::{Error, Result, Timestamp};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{self, GithubUser, Grant, Kind, Role};
use crate::io;
use crate::protocol::{Issued, SignInAnswer, SignInCode, SignInPoll, SignInStart};
use crate::remote::Remote;

/// `<root>/auth.toml`.
pub const FILE: &str = "auth.toml";
/// How long issued tokens work, unless `token_ttl` says otherwise.
const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// The range of `token_ttl`, `refresh_limit` and `refresh_idle`.
const TTL_RANGE: (Duration, Duration) = (Duration::from_secs(5 * 60), Duration::from_secs(366 * 24 * 3600));
/// How long after its sign-in a token may be refreshed, unless `refresh_limit` says otherwise.
const DEFAULT_REFRESH_LIMIT: Duration = Duration::from_secs(30 * 24 * 3600);
/// How long a sign-in may go without a refresh, unless `refresh_idle` says otherwise.
const DEFAULT_REFRESH_IDLE: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long an installation token is used: GitHub's last an hour.
const INSTALLATION_TOKEN_LIFE: Duration = Duration::from_secs(50 * 60);
/// Each request to GitHub ends within this.
const GITHUB_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest GitHub answer read.
const MAX_ANSWER: u64 = 1 << 20;
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Characters of a GitHub error message passed on.
const MAX_MESSAGE: usize = 200;
/// The longest a one-time code is waited for, and the longest wait between
/// polls, in seconds (GitHub's codes last 15 minutes).
const MAX_CODE_LIFE: u64 = 3600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    #[serde(default)]
    github: Option<GithubDoc>,
    #[serde(default)]
    oauth: Option<OauthDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthDoc {
    #[serde(default)]
    redirect_hosts: Vec<String>,
    #[serde(default)]
    loopback_redirects: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubDoc {
    client_id: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    api_url: Option<String>,
    #[serde(default)]
    private_key: Option<PathBuf>,
    #[serde(default)]
    token_ttl: Option<String>,
    #[serde(default)]
    refresh_limit: Option<String>,
    #[serde(default)]
    refresh_idle: Option<String>,
    #[serde(default)]
    deny: Vec<u64>,
    #[serde(default)]
    allow: Vec<RuleDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDoc {
    #[serde(default)]
    anyone: bool,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    orgs: Vec<String>,
    #[serde(default)]
    teams: Vec<String>,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default = "agent_kind")]
    kind: Kind,
    #[serde(default)]
    workspaces: Vec<String>,
    #[serde(default)]
    min_account_age: Option<String>,
    #[serde(default)]
    max_claims: Option<u32>,
}

fn agent_kind() -> Kind {
    Kind::Agent
}

/// GitHub sign-in, as `auth.toml` configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Github {
    pub client_id: String,
    /// Where people sign in, with the device flow's endpoints:
    /// `https://github.com`, or a GitHub Enterprise Server.
    pub url: String,
    /// GitHub's REST API.
    pub api_url: String,
    /// How long issued tokens work.
    pub token_ttl: Duration,
    /// The GitHub App's private key file, as written (relative to the root).
    pub private_key: Option<PathBuf>,
    /// The key itself, read by [`load`]: tokens are refreshed only with it.
    pub app: Option<AppKey>,
    /// How long after its sign-in a token may be refreshed.
    pub refresh_limit: Duration,
    /// How long a sign-in may go without a refresh.
    pub refresh_idle: Duration,
    /// GitHub user ids that may never sign in, whatever the rules say.
    pub deny: Vec<u64>,
    pub rules: Vec<Rule>,
    /// The authorization server for MCP clients, if `[oauth]` turns it on.
    pub oauth: Option<OauthConfig>,
}

/// `[oauth]`: where the authorization server may send people back to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OauthConfig {
    /// Hosts of https redirect URIs, lowercased.
    pub redirect_hosts: Vec<String>,
    /// Whether http redirect URIs to this machine are allowed (desktop clients).
    pub loopback_redirects: bool,
}

impl OauthConfig {
    /// Whether a client may be sent back to `uri`: https on one of
    /// `redirect_hosts` without a port, or, with `loopback_redirects`, http to
    /// 127.0.0.1, [::1] or localhost on any port (RFC 8252). Never with user
    /// info or a fragment.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        let Some((scheme, rest)) = uri.split_once("://") else { return false };
        if uri.contains('#') || uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return false;
        }
        let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
        if !authority.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
            return false;
        }
        let (host, port) = match authority.rfind(':') {
            Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(&authority[i + 1..])),
            _ => (authority, None),
        };
        let host = host.to_ascii_lowercase();
        match scheme {
            "https" => port.is_none() && self.redirect_hosts.contains(&host),
            "http" => {
                self.loopback_redirects
                    && matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost")
                    && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
            }
            _ => false,
        }
    }
}

/// A host name as `redirect_hosts` takes it: a DNS name of two labels or
/// more, lowercased; no IP address, port or wildcard.
pub(crate) fn dns_name(raw: &str) -> Option<String> {
    let host = raw.trim().to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let label = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let numeric = labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    (host.len() <= 253 && labels.len() >= 2 && labels.iter().all(label) && !numeric).then_some(host)
}

fn oauth_config(o: OauthDoc) -> std::result::Result<OauthConfig, String> {
    let mut redirect_hosts = Vec::new();
    for raw in &o.redirect_hosts {
        let Some(host) = dns_name(raw) else {
            return Err(format!(
                "oauth.redirect_hosts {raw:?} is not a host name such as chatgpt.com (loopback_redirects = true \
                 allows this machine)"
            ));
        };
        if !redirect_hosts.contains(&host) {
            redirect_hosts.push(host);
        }
    }
    if redirect_hosts.is_empty() && !o.loopback_redirects {
        return Err("[oauth] allows no redirect URIs, so no client may sign anyone in: name redirect_hosts, or set \
                    loopback_redirects = true"
            .into());
    }
    Ok(OauthConfig { redirect_hosts, loopback_redirects: o.loopback_redirects })
}

/// One `[[github.allow]]` rule: whom it lets in, and what their token may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Any GitHub account: the rule names nobody, and is the last.
    pub anyone: bool,
    /// Logins, matched whatever their case.
    pub users: Vec<String>,
    pub orgs: Vec<String>,
    /// `(organization, team slug)`.
    pub teams: Vec<(String, String)>,
    /// Accounts GitHub created less than this long ago are not let in by the rule.
    pub min_account_age: Option<Duration>,
    pub grant: Grant,
}

impl Github {
    /// Whether a rule names organizations or teams, whose memberships an
    /// OAuth app reads with the `read:org` scope.
    fn reads_orgs(&self) -> bool {
        self.rules.iter().any(|r| !r.orgs.is_empty() || !r.teams.is_empty())
    }

    /// How long the tokens of a sign-in at `now` last: refreshed only with
    /// the GitHub App's key.
    fn lifetime(&self, now: Timestamp) -> auth::Lifetime {
        let refresh = self.app.as_ref().map(|_| (now.plus(self.refresh_limit), self.refresh_idle));
        auth::Lifetime { ttl: self.token_ttl, refresh }
    }
}

/// A GitHub App's private key (`github.private_key`), which signs the JWTs
/// that get installation tokens.
#[derive(Clone)]
pub struct AppKey {
    path: PathBuf,
    pair: Arc<ring::signature::RsaKeyPair>,
}

impl std::fmt::Debug for AppKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("AppKey").field("path", &self.path).finish()
    }
}

impl PartialEq for AppKey {
    fn eq(&self, other: &AppKey) -> bool {
        self.path == other.path
    }
}

impl Eq for AppKey {}

impl AppKey {
    /// The RSA key of a PEM file (PKCS#1, as GitHub gives them, or PKCS#8).
    fn load(path: &Path) -> std::result::Result<AppKey, String> {
        use ureq::tls::PemItem;
        let at = format!("github.private_key {}", path.display());
        let pem = std::fs::read(path).map_err(|e| format!("{at}: {e}"))?;
        let key = ureq::tls::parse_pem(&pem)
            .find_map(|item| match item {
                Ok(PemItem::PrivateKey(k)) => Some(k),
                _ => None,
            })
            .ok_or_else(|| format!("{at}: no private key in the file"))?;
        let pair = ring::signature::RsaKeyPair::from_der(key.der())
            .or_else(|_| ring::signature::RsaKeyPair::from_pkcs8(key.der()))
            .map_err(|e| format!("{at}: not a usable RSA key, as GitHub Apps' are ({e})"))?;
        Ok(AppKey { path: path.to_path_buf(), pair: Arc::new(pair) })
    }

    /// A JWT for the GitHub App `client_id`: valid for 9 minutes (GitHub
    /// takes at most 10), dated a minute back for clocks that differ.
    fn jwt(&self, client_id: &str) -> Result<String> {
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let now = Timestamp::now().millis() / 1000;
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({ "iat": now - 60, "exp": now + 540, "iss": client_id });
        let signed = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let mut signature = vec![0; self.pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        self.pair
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, signed.as_bytes(), &mut signature)
            .map_err(|_| Error::Io(std::io::Error::other("signing a GitHub App JWT failed")))?;
        Ok(format!("{signed}.{}", b64(&signature)))
    }
}

/// Installation tokens of GitHub Apps, by `<api_url> <client_id> <org or *>`,
/// with when to stop using them: shared by every refresh.
static INSTALLATION_TOKENS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> = LazyLock::new(Default::default);

/// GitHub sign-in as `<root>/auth.toml` configures it: `None` without the
/// file, or without its `[github]` table.
pub fn load(root: &Path) -> Result<Option<Github>> {
    let path = root.join(FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::invalid(format!("{}: {e}", path.display()))),
    };
    let Some(mut github) = parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))? else {
        return Ok(None);
    };
    if let Some(key) = &github.private_key {
        let key = if key.is_relative() { root.join(key) } else { key.clone() };
        github.app = Some(AppKey::load(&key).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?);
    }
    Ok(Some(github))
}

/// The authorization server's settings in `<root>/auth.toml` (`[oauth]`),
/// if it is on: `[github]` checked too, but not its private key, which
/// sign-ins and refreshes read.
pub fn load_oauth(root: &Path) -> Result<Option<OauthConfig>> {
    let path = root.join(FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::invalid(format!("{}: {e}", path.display()))),
    };
    let github = parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    Ok(github.and_then(|g| g.oauth))
}

fn parse(text: &str) -> std::result::Result<Option<Github>, String> {
    let doc: Doc = toml::from_str(text).map_err(|e| {
        // The parser's own text quotes the file, which may hold what should not be shown: name the line only.
        let line = e.span().map(|s| text.as_bytes()[..s.start.min(text.len())].iter().filter(|&&b| b == b'\n').count());
        format!("{}{}", line.map(|n| format!("line {}: ", n + 1)).unwrap_or_default(), e.message().trim_end())
    })?;
    let Some(g) = doc.github else {
        return match doc.oauth {
            Some(_) => Err("[oauth] signs people in with GitHub, so it needs [github]".into()),
            None => Ok(None),
        };
    };
    let client_id = g.client_id.trim().to_string();
    if client_id.is_empty() || client_id.len() > 100 || !client_id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "github.client_id {:?} is not the client ID of a GitHub OAuth app or GitHub App",
            g.client_id
        ));
    }
    let url = base_url("url", g.url.as_deref().unwrap_or("https://github.com"))?;
    let api_url = match &g.api_url {
        Some(raw) => base_url("api_url", raw)?,
        None if url.eq_ignore_ascii_case("https://github.com") => "https://api.github.com".to_string(),
        None => format!("{url}/api/v3"),
    };
    let duration = |field: &str, raw: &Option<String>, default: Duration| {
        let Some(raw) = raw else { return Ok(default) };
        let d = bd_core::time::parse_duration(raw).map_err(|e| format!("github.{field}: {e}"))?;
        match (TTL_RANGE.0..=TTL_RANGE.1).contains(&d) {
            true => Ok(d),
            false => Err(format!("github.{field} {raw:?}: use 5m to 366d")),
        }
    };
    let token_ttl = duration("token_ttl", &g.token_ttl, DEFAULT_TTL)?;
    let refresh_limit = duration("refresh_limit", &g.refresh_limit, DEFAULT_REFRESH_LIMIT)?;
    let refresh_idle = duration("refresh_idle", &g.refresh_idle, DEFAULT_REFRESH_IDLE)?;
    if g.private_key.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        return Err("github.private_key is empty: name the GitHub App's private key file, or leave it out".into());
    }
    let private_key = g.private_key;
    if private_key.is_none() && (g.refresh_limit.is_some() || g.refresh_idle.is_some()) {
        return Err("github.refresh_limit and refresh_idle need github.private_key: only a GitHub App refreshes \
                    tokens"
            .into());
    }
    if private_key.is_some() && !(token_ttl <= refresh_idle && refresh_idle <= refresh_limit) {
        return Err("github.token_ttl, refresh_idle and refresh_limit must each be at most the next (by default \
                    1h, 7d and 30d)"
            .into());
    }
    if g.allow.is_empty() {
        return Err("[github] has no [[github.allow]] rules, so no GitHub account may sign in: add rules, or remove \
                    [github]"
            .into());
    }
    let rules: Vec<Rule> =
        g.allow.into_iter().enumerate().map(|(i, r)| rule(i + 1, r)).collect::<std::result::Result<_, _>>()?;
    if let Some(i) = rules.iter().position(|r| r.anyone) {
        if i + 1 < rules.len() {
            return Err(format!(
                "[[github.allow]] rule {} lets anyone in, so the rules after it never match: make it the last",
                i + 1
            ));
        }
        // An account an earlier rule lets into a workspace gets that rule's token there, never the anyone rule's.
        let anyone = &rules[i].grant;
        if let Some(n) = rules[..i].iter().position(|r| r.grant.role < anyone.role && overlap(&r.grant, anyone)) {
            return Err(format!(
                "[[github.allow]] rule {} gives its accounts role {} where rule {} gives anyone role {}: raise its \
                 role, or keep their workspaces apart",
                n + 1,
                rules[n].grant.role.as_str(),
                i + 1,
                anyone.role.as_str()
            ));
        }
        // Read tokens hold nothing, so only a writing `anyone` rule sets a floor.
        let fewer = |r: &Rule| {
            anyone.role != Role::Read && r.grant.max_claims.is_some_and(|n| anyone.max_claims.is_none_or(|a| n < a))
        };
        if let Some(n) = rules[..i].iter().position(|r| fewer(r) && overlap(&r.grant, anyone)) {
            return Err(format!(
                "[[github.allow]] rule {} lets its accounts hold fewer claims than rule {} lets anyone hold: raise its \
                 max_claims, or keep their workspaces apart",
                n + 1,
                i + 1
            ));
        }
    }
    let oauth = doc.oauth.map(oauth_config).transpose()?;
    if oauth.is_some() && private_key.is_none() {
        return Err("[oauth] needs github.private_key: MCP clients' tokens are refreshed through the GitHub App, or \
                    people would sign in again each token_ttl"
            .into());
    }
    Ok(Some(Github {
        client_id,
        url,
        api_url,
        token_ttl,
        private_key,
        app: None,
        refresh_limit,
        refresh_idle,
        deny: g.deny,
        rules,
        oauth,
    }))
}

/// Whether two grants share a workspace.
fn overlap(a: &Grant, b: &Grant) -> bool {
    let all = |g: &Grant| g.workspaces.iter().any(|w| w == "*");
    all(a) || all(b) || a.workspaces.iter().any(|w| b.workspaces.contains(w))
}

/// `https://host[:port][/path]`, without a trailing slash; `http` only to
/// this machine (a stand-in for GitHub).
fn base_url(field: &str, raw: &str) -> std::result::Result<String, String> {
    let url = raw.trim().trim_end_matches('/');
    // A URL with credentials in it is not repeated.
    let shown = if raw.contains('@') { String::new() } else { format!(" {raw:?}") };
    let bad = |why: &str| format!("github.{field}{shown} {why}");
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad("has no scheme"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || url.contains(['?', '#'])
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(bad("needs a host, and no credentials, query or fragment"));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(url.to_string()),
        "http" if crate::remote::is_loopback(authority) => Ok(url.to_string()),
        _ => Err(bad("must use https")),
    }
}

/// A login, organization or team slug, as it may stand in a URL path:
/// letters, digits, `-`, `_` and `.`, from a letter or digit on.
fn github_name(s: &str) -> bool {
    s.len() <= 100
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn rule(n: usize, r: RuleDoc) -> std::result::Result<Rule, String> {
    let at = format!("[[github.allow]] rule {n}");
    let names = |field: &str, list: Vec<String>| {
        list.into_iter()
            .map(|s| {
                let name = s.trim();
                match github_name(name) {
                    true => Ok(name.to_string()),
                    false => Err(format!("{at}: {field} {s:?} is not a GitHub name")),
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    let users = names("users", r.users)?;
    let orgs = names("orgs", r.orgs)?;
    let teams = r
        .teams
        .into_iter()
        .map(|t| match t.trim().split_once('/') {
            Some((org, team)) if github_name(org) && github_name(team) => Ok((org.to_string(), team.to_string())),
            _ => Err(format!("{at}: teams {t:?} is not <organization>/<team slug>")),
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let names_someone = !(users.is_empty() && orgs.is_empty() && teams.is_empty());
    if r.anyone {
        if names_someone {
            return Err(format!("{at} lets anyone in: drop its users, orgs and teams, or anyone"));
        }
        // Any GitHub account, and its throwaway accounts: never an admin, nor a person who may open human gates.
        if r.role == Some(Role::Admin) {
            return Err(format!("{at} lets anyone in, so its role may be read or write, not admin"));
        }
        if r.kind == Kind::Human {
            return Err(format!("{at} lets anyone in, so its kind may be agent only: human tokens open human gates"));
        }
    } else if !names_someone {
        return Err(format!("{at} names no users, orgs or teams, so it lets nobody in (anyone = true lets everyone)"));
    }
    let role = r.role.unwrap_or(if r.anyone { Role::Read } else { Role::Write });
    let workspaces = auth::workspace_list(&r.workspaces).map_err(|e| format!("{at}: {e}"))?;
    let min_account_age = match &r.min_account_age {
        None => None,
        Some(raw) => Some(bd_core::time::parse_duration(raw).map_err(|e| format!("{at}: min_account_age: {e}"))?),
    };
    if r.max_claims == Some(0) {
        return Err(format!("{at}: max_claims must be at least 1 (role read lets its accounts claim nothing)"));
    }
    let grant = Grant { role, kind: r.kind, workspaces, max_claims: r.max_claims };
    Ok(Rule { anyone: r.anyone, users, orgs, teams, min_account_age, grant })
}

/// Whether a GitHub account belongs to an organization or a team.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Member {
    Yes,
    No,
    /// GitHub would not tell, and why: the account counts as no member.
    Unknown(String),
}

/// The memberships of the account signing in, asked of GitHub as rules need them.
pub trait Memberships {
    fn org(&mut self, org: &str) -> Result<Member>;
    fn team(&mut self, org: &str, team: &str) -> Result<Member>;
}

/// What the rules make of an account signing in to a workspace.
#[derive(Debug)]
pub enum Decision {
    /// What the first rule that lets the account into the workspace grants
    /// it, what matched (`GitHub user alice`, `member of acme`), and whether
    /// that was its login in the rule's `users`.
    In { grant: Grant, via: String, by_login: bool },
    /// Rules let the account in, but only into these other workspaces.
    Elsewhere(Vec<String>),
    /// A rule would let the account into the workspace, were its GitHub
    /// account this old (the least such `min_account_age`).
    TooNew(Duration),
    /// No rule lets the account in.
    Out,
}

/// The first rule that lets `login` into `workspace`: a rule that lets the
/// account in elsewhere only leaves it to the rules after it, and then the
/// grant covers `workspace` alone, never one where an earlier rule decides.
/// A rule whose `min_account_age` the account's `age` falls short of (or
/// whose age GitHub did not tell) does not let it in. Memberships GitHub
/// would not tell are noted in `unknown`.
pub fn decide(
    github: &Github,
    login: &str,
    age: Option<Duration>,
    workspace: &str,
    m: &mut dyn Memberships,
    unknown: &mut Vec<String>,
) -> Result<Decision> {
    let mut elsewhere: Vec<String> = Vec::new();
    let mut too_new: Option<Duration> = None;
    for rule in &github.rules {
        let Some((via, by_login)) = lets_in(rule, login, m, unknown)? else { continue };
        if let Some(min) = rule.min_account_age.filter(|min| age.is_none_or(|age| age < *min)) {
            if rule.grant.allows_workspace(workspace) {
                too_new = Some(too_new.map_or(min, |t| t.min(min)));
            }
            continue;
        }
        if rule.grant.allows_workspace(workspace) {
            let mut grant = rule.grant.clone();
            if !elsewhere.is_empty() {
                grant.workspaces = vec![workspace.to_string()];
            }
            return Ok(Decision::In { grant, via, by_login });
        }
        for w in &rule.grant.workspaces {
            if !elsewhere.contains(w) {
                elsewhere.push(w.clone());
            }
        }
    }
    Ok(match too_new {
        Some(min) => Decision::TooNew(min),
        None if elsewhere.is_empty() => Decision::Out,
        None => Decision::Elsewhere(elsewhere),
    })
}

/// What lets `login` in by `rule`, if anything, and whether it is the login.
fn lets_in(
    rule: &Rule,
    login: &str,
    m: &mut dyn Memberships,
    unknown: &mut Vec<String>,
) -> Result<Option<(String, bool)>> {
    let mut note = |what: String| {
        if !unknown.contains(&what) {
            unknown.push(what);
        }
    };
    if rule.anyone {
        return Ok(Some((format!("GitHub user {login}, as anyone"), false)));
    }
    if rule.users.iter().any(|u| u.eq_ignore_ascii_case(login)) {
        return Ok(Some((format!("GitHub user {login}"), true)));
    }
    for org in &rule.orgs {
        match m.org(org)? {
            Member::Yes => return Ok(Some((format!("member of {org}"), false))),
            Member::No => {}
            Member::Unknown(why) => note(format!("{org}: {why}")),
        }
    }
    for (org, team) in &rule.teams {
        match m.team(org, team)? {
            Member::Yes => return Ok(Some((format!("member of team {org}/{team}"), false))),
            Member::No => {}
            Member::Unknown(why) => note(format!("team {org}/{team}: {why}")),
        }
    }
    Ok(None)
}

/// The GitHub endpoints sign-in uses.
struct Api {
    url: String,
    api_url: String,
    agent: ureq::Agent,
}

impl Api {
    fn new(github: &Github) -> Api {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(GITHUB_TIMEOUT))
            .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
            .build();
        Api { url: github.url.clone(), api_url: github.api_url.clone(), agent: config.into() }
    }

    /// POST a form to a device flow endpoint (`/login/...`): GitHub's answer.
    fn form(&self, path: &str, form: &[(&str, &str)]) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.url);
        let sent = self.agent.post(&url).header("accept", "application/json").send_form(form.iter().copied());
        answer(&url, sent)
    }

    /// GET an API endpoint as the account that signed in: GitHub's answer.
    fn get(&self, token: &str, path: &str) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.api_url);
        let sent = self
            .agent
            .get(&url)
            .header("accept", "application/vnd.github+json")
            .header("authorization", &format!("Bearer {token}"))
            .call();
        answer(&url, sent)
    }
}

impl Api {
    /// POST to an API endpoint, without a body, with `token`: GitHub's answer.
    fn post(&self, token: &str, path: &str) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.api_url);
        let sent = self
            .agent
            .post(&url)
            .header("accept", "application/vnd.github+json")
            .header("authorization", &format!("Bearer {token}"))
            .send_empty();
        answer(&url, sent)
    }
}

/// A GitHub answer's status, and its JSON body (`null` when it has none).
fn answer(url: &str, sent: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<(u16, Value)> {
    let mut response = sent.map_err(|e| Error::Remote(format!("GitHub ({url}) did not answer: {e}")))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
        .map_err(|e| Error::Remote(format!("GitHub ({url}): reading the answer: {e}")))?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

/// ` (GitHub's message)`, if its answer has one.
fn message(body: &Value) -> String {
    let text = body["message"].as_str().or(body["error_description"].as_str()).unwrap_or_default();
    match text.char_indices().nth(MAX_MESSAGE) {
        _ if text.is_empty() => String::new(),
        Some((i, _)) => format!(" ({}…)", crate::agents::show::printable(&text[..i])),
        None => format!(" ({})", crate::agents::show::printable(text)),
    }
}

/// GitHub as the GitHub App of `auth.toml` sees it: what refreshes ask,
/// with installation tokens, never an account's own.
struct AppApi<'a> {
    api: &'a Api,
    github: &'a Github,
    key: &'a AppKey,
}

impl AppApi<'_> {
    fn cache_key(&self, org: Option<&str>) -> String {
        let org = org.map_or_else(|| "*".to_string(), str::to_ascii_lowercase);
        format!("{} {} {org}", self.github.api_url, self.github.client_id)
    }

    /// An installation token of the App: of its installation on `org`, or of
    /// any for `None`. `None` when it is not installed there.
    fn token(&self, org: Option<&str>) -> Result<Option<String>> {
        let key = self.cache_key(org);
        {
            let mut cache = INSTALLATION_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            cache.retain(|_, (_, until)| now < *until);
            if let Some((token, _)) = cache.get(&key) {
                return Ok(Some(token.clone()));
            }
        }
        let jwt = self.key.jwt(&self.github.client_id)?;
        let installation = match org {
            Some(org) => {
                let (status, body) = self.api.get(&jwt, &format!("/orgs/{org}/installation"))?;
                match status {
                    200 => body["id"].as_u64(),
                    404 => return Ok(None),
                    _ => return Err(self.failed(&format!("find its installation on {org}"), status, &body)),
                }
            }
            None => {
                // Any installation that is not suspended: the first that gives a token.
                let (status, body) = self.api.get(&jwt, "/app/installations?per_page=100")?;
                let Some(all) = body.as_array().filter(|_| status == 200) else {
                    return Err(self.failed("list its installations", status, &body));
                };
                let mut failure = None;
                for id in all.iter().filter(|i| i["suspended_at"].is_null()).filter_map(|i| i["id"].as_u64()) {
                    match self.mint(&jwt, id, key.clone()) {
                        Ok(token) => return Ok(Some(token)),
                        Err(e) => failure = Some(e),
                    }
                }
                return failure.map_or(Ok(None), Err);
            }
        };
        let Some(installation) = installation else {
            return Err(Error::Remote("GitHub answered an installation without its id".into()));
        };
        self.mint(&jwt, installation, key).map(Some)
    }

    /// An installation token of `installation`, cached under `key`.
    fn mint(&self, jwt: &str, installation: u64, key: String) -> Result<String> {
        let (status, body) = self.api.post(jwt, &format!("/app/installations/{installation}/access_tokens"))?;
        let Some(token) = body["token"].as_str().filter(|t| status == 201 && !t.is_empty()) else {
            return Err(self.failed("get an installation token", status, &body));
        };
        let mut cache = INSTALLATION_TOKENS.lock().unwrap_or_else(|p| p.into_inner());
        cache.insert(key, (token.to_string(), Instant::now() + INSTALLATION_TOKEN_LIFE));
        Ok(token.to_string())
    }

    /// GET `path` with an installation token (`org`'s, or any): `None` when
    /// the App is not installed there. A token GitHub refuses is not used again.
    fn get(&self, org: Option<&str>, path: &str) -> Result<Option<(u16, Value)>> {
        let Some(token) = self.token(org)? else { return Ok(None) };
        let (status, body) = self.api.get(&token, path)?;
        if status == 401 {
            INSTALLATION_TOKENS.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.cache_key(org));
        }
        Ok(Some((status, body)))
    }

    /// The account with this user id as GitHub names it now, and when
    /// GitHub created it; `None` when it no longer exists.
    fn user(&self, id: u64) -> Result<Option<(GithubUser, Option<Timestamp>)>> {
        let Some((status, body)) = self.get(None, &format!("/user/{id}"))? else {
            tracing::warn!(target: "bd::serve", github = %self.github.url, client_id = %self.github.client_id, "GitHub sign-ins cannot be refreshed: the GitHub App is not installed anywhere, or only suspended");
            return Err(Error::Remote(
                "this bd server's GitHub App is not installed anywhere, or only where it is suspended, so sign-ins \
                 cannot be refreshed: its admin installs it"
                    .into(),
            ));
        };
        let login = body["login"].as_str().filter(|l| github_name(l));
        match (status, login, body["id"].as_u64()) {
            (200, Some(login), Some(got)) if got == id => {
                let created = body["created_at"].as_str().and_then(|at| Timestamp::parse_rfc3339(at).ok());
                let user = GithubUser { url: self.github.url.to_ascii_lowercase(), login: login.to_string(), id };
                Ok(Some((user, created)))
            }
            (404, _, _) => Ok(None),
            _ => Err(self.failed(&format!("read GitHub user {id}"), status, &body)),
        }
    }

    fn failed(&self, doing: &str, status: u16, body: &Value) -> Error {
        let detail = message(body);
        tracing::warn!(target: "bd::serve", github = %self.github.url, client_id = %self.github.client_id, status, %detail, "the GitHub App could not {doing}");
        Error::Remote(format!("this bd server's GitHub App could not {doing} (HTTP {status}{detail}); try again later"))
    }
}

/// Memberships asked of GitHub with the App's installation tokens, each at
/// most once. An organization without the App, or one it may not read the
/// members of, does not tell.
struct Installed<'a> {
    app: &'a AppApi<'a>,
    login: &'a str,
    seen: HashMap<String, Member>,
}

impl Installed<'_> {
    fn ask(&mut self, org: &str, key: String, path: String) -> Result<Member> {
        if let Some(m) = self.seen.get(&key) {
            return Ok(m.clone());
        }
        let member = match self.app.get(Some(org), &path)? {
            None => {
                tracing::warn!(target: "bd::serve", %org, "GitHub App not installed on an organization the rules name: its members' sign-ins are not refreshed");
                Member::Unknown(format!("the GitHub App is not installed on {org}"))
            }
            Some((200, body)) if body["state"] == "active" => Member::Yes,
            Some((200 | 404, _)) => Member::No,
            Some((status @ (401 | 403), body)) => {
                let detail = message(&body);
                tracing::warn!(target: "bd::serve", %org, status, %detail, "the GitHub App may not read the members of an organization the rules name");
                Member::Unknown(format!("GitHub answered {status}{detail}"))
            }
            Some((status, body)) => {
                return Err(self.app.failed(&format!("check a membership of {key}"), status, &body));
            }
        };
        self.seen.insert(key, member.clone());
        Ok(member)
    }
}

impl Memberships for Installed<'_> {
    fn org(&mut self, org: &str) -> Result<Member> {
        self.ask(org, org.to_ascii_lowercase(), format!("/orgs/{org}/memberships/{}", self.login))
    }

    fn team(&mut self, org: &str, team: &str) -> Result<Member> {
        let path = format!("/orgs/{org}/teams/{team}/memberships/{}", self.login);
        self.ask(org, format!("{org}/{team}").to_ascii_lowercase(), path)
    }
}

/// GitHub sign-in as `auth.toml` sets it up now, for a sign-in request. A
/// mistake in the file is the admin's to see, in the log: the client gets
/// no detail of it.
fn enabled(root: &Path) -> Result<Github> {
    match load(root) {
        Ok(Some(github)) => Ok(github),
        Ok(None) => Err(Error::Unauthorized(
            "GitHub sign-in is not enabled on this bd server: its admin turns it on in auth.toml, or creates access \
             tokens (`bd serve token create`)"
                .into(),
        )),
        Err(e) => {
            tracing::warn!(target: "bd::serve", error = %e, "GitHub sign-in refused: auth.toml cannot be used");
            Err(Error::Remote(
                "GitHub sign-in is not working on this bd server: its admin finds why in the server log".into(),
            ))
        }
    }
}

/// GitHub refused a step of the device flow: for a reason of the server's
/// own settings (device flow disabled, an unknown client ID), logged for
/// its admin, or because it is unwell. Passed on either way.
fn refused(github: &Github, doing: &str, status: u16, body: &Value) -> Error {
    let detail = message(body);
    let Some(error) = body["error"].as_str().map(crate::agents::show::printable) else {
        if status >= 500 || status == 429 {
            tracing::warn!(target: "bd::serve", github = %github.url, status, %detail, "GitHub could not {doing}");
            return Error::Remote(format!("GitHub could not {doing} (HTTP {status}{detail}); try again later"));
        }
        tracing::warn!(target: "bd::serve", github = %github.url, client_id = %github.client_id, status, %detail, "GitHub refused to {doing}");
        return Error::Remote(format!(
            "GitHub refused to {doing}: HTTP {status}{detail}; the GitHub settings of this bd server need attention"
        ));
    };
    tracing::warn!(target: "bd::serve", github = %github.url, client_id = %github.client_id, %error, %detail, "GitHub refused to {doing}");
    Error::Remote(format!(
        "GitHub refused to {doing}: {error}{detail}; the GitHub settings of this bd server need attention"
    ))
}

/// Start a sign-in: the one-time code GitHub gives for it.
pub fn start(root: &Path) -> Result<SignInCode> {
    let github = enabled(root)?;
    let api = Api::new(&github);
    let mut form = vec![("client_id", github.client_id.as_str())];
    if github.reads_orgs() {
        form.push(("scope", "read:org"));
    }
    let (status, body) = api.form("/login/device/code", &form)?;
    let text = |k: &str| body[k].as_str().map(str::to_string);
    match (status, text("device_code"), text("user_code"), text("verification_uri")) {
        (200, Some(device_code), Some(user_code), Some(verification_uri)) if body.get("error").is_none() => {
            Ok(SignInCode {
                device_code,
                user_code,
                verification_uri,
                expires_in: body["expires_in"].as_u64().unwrap_or(900),
                interval: body["interval"].as_u64().unwrap_or(5),
            })
        }
        _ => Err(refused(&github, "start a sign-in", status, &body)),
    }
}

/// What became of a sign-in: still waiting for its code, or the access
/// token issued to the account that signed in.
pub fn poll(root: &Path, poll: &SignInPoll) -> Result<SignInAnswer> {
    let code = poll.device_code.as_str();
    if code.is_empty() || code.len() > 256 || !code.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::invalid("not a sign-in's device code"));
    }
    if !crate::protocol::valid_workspace_name(&poll.workspace) {
        return Err(Error::invalid(format!("invalid workspace name {:?}", poll.workspace)));
    }
    let github = enabled(root)?;
    let api = Api::new(&github);
    let form = [("client_id", github.client_id.as_str()), ("device_code", code), ("grant_type", DEVICE_GRANT)];
    let (status, body) = api.form("/login/oauth/access_token", &form)?;
    match body["error"].as_str() {
        Some("authorization_pending") => return Ok(SignInAnswer::Pending),
        Some("slow_down") => return Ok(SignInAnswer::SlowDown { interval: body["interval"].as_u64().unwrap_or(0) }),
        Some("expired_token" | "token_expired") => {
            return Err(Error::Unauthorized(
                "the one-time code expired before it was entered at GitHub: sign in again".into(),
            ));
        }
        Some("access_denied") => return Err(Error::Unauthorized("the sign-in was cancelled at GitHub".into())),
        Some("incorrect_device_code") => {
            return Err(Error::invalid(
                "GitHub does not know this sign-in (it ended, or never started): sign in again",
            ));
        }
        Some(_) => return Err(refused(&github, "finish a sign-in", status, &body)),
        None => {}
    }
    let Some(access) = body["access_token"].as_str().filter(|t| !t.is_empty()) else {
        return Err(refused(&github, "finish a sign-in", status, &body));
    };
    let (user, created) = account(&api, access)?;
    let age = created.map(|at| Duration::from_millis(Timestamp::now().since(at).max(0) as u64));
    if github.deny.contains(&user.id) {
        tracing::info!(target: "bd::serve", login = %user.login, id = user.id, "GitHub sign-in refused: the account is denied");
        return Err(Error::Unauthorized(format!("GitHub user {} may not sign in to this bd server", user.login)));
    }
    let mut asked = Asked { api: &api, token: access, login: &user.login, seen: HashMap::new() };
    let mut unknown = Vec::new();
    let (grant, via, by_login) = match decide(&github, &user.login, age, &poll.workspace, &mut asked, &mut unknown)? {
        Decision::In { grant, via, by_login } => (grant, via, by_login),
        Decision::TooNew(min) => {
            tracing::info!(target: "bd::serve", login = %user.login, id = user.id, workspace = %poll.workspace, ?age, "GitHub sign-in refused: the account is too new");
            return Err(Error::Unauthorized(format!(
                "GitHub user {} may not sign in to this bd server yet: its GitHub account must be at least {} old",
                user.login,
                bd_core::time::format_duration_ms(i64::try_from(min.as_millis()).unwrap_or(i64::MAX))
            )));
        }
        Decision::Elsewhere(workspaces) => {
            tracing::info!(target: "bd::serve", login = %user.login, id = user.id, workspace = %poll.workspace, ?unknown, "GitHub sign-in refused: workspace not allowed");
            return Err(Error::Unauthorized(format!(
                "GitHub user {} may sign in to this bd server, but not use workspace {} (only {})",
                user.login,
                poll.workspace,
                workspaces.join(", ")
            )));
        }
        Decision::Out => {
            tracing::info!(target: "bd::serve", login = %user.login, id = user.id, ?unknown, "GitHub sign-in refused: no rule lets the account in");
            return Err(Error::Unauthorized(format!(
                "GitHub user {} may not sign in to this bd server: no rule of its auth.toml lets the account in",
                user.login
            )));
        }
    };
    let life = github.lifetime(Timestamp::now());
    let issued = auth::issue_github_token(root, &user, grant, life, &poll.workspace, by_login)?;
    let token = &issued.token;
    tracing::info!(
        target: "bd::serve",
        login = %user.login,
        id = user.id,
        actor = %token.actor,
        token = %token.name,
        role = token.role.as_str(),
        kind = token.kind.as_str(),
        refreshed = token.refresh.is_some(),
        %via,
        ?unknown,
        "GitHub sign-in issued an access token"
    );
    Ok(SignInAnswer::Issued(Box::new(answer_of(issued, user.login, via))))
}

/// What the client gets of a token issued or refreshed.
fn answer_of(issued: auth::Issued, login: String, via: String) -> Issued {
    let t = issued.token;
    let expires_in = t.expires_at.map_or(0, |at| u64::try_from(at.since(Timestamp::now()) / 1000).unwrap_or(0));
    Issued {
        token: issued.secret,
        refresh_token: issued.refresh_secret,
        name: t.name,
        actor: t.actor,
        role: t.role.as_str().to_string(),
        kind: t.kind.as_str().to_string(),
        workspaces: t.workspaces,
        max_claims: t.max_claims,
        expires_at: t.expires_at.map(|at| at.to_rfc3339()).unwrap_or_default(),
        expires_in,
        refreshable_until: t.refresh.map(|r| r.until.to_rfc3339()),
        login,
        via,
    }
}

/// Refresh the sign-in whose refresh secret this is (`POST
/// /v2/auth/refresh`, request `request_id`): new secrets, with what the
/// rules grant its account now, asked of GitHub as the App. The secret
/// spent by the latest refresh, sent again with its request id (a client
/// whose answer was lost), refreshes again. A refusal is
/// `Error::Unauthorized`, and revokes the sign-in when the rules no longer
/// let the account in, or the secret was spent already; GitHub's failures,
/// and memberships it would not tell, are `Error::Remote`, and change nothing.
pub fn refresh(root: &Path, secret: &str, request_id: &str) -> Result<Issued> {
    let refused = |why: String| Error::Unauthorized(format!("{why}; sign in again: `bd remote login --github`"));
    let github = enabled(root)?;
    let Some((token, current)) = auth::find_refresh(root, secret)? else {
        return Err(refused("this bd server does not know the sign-in (it was revoked, or has ended)".into()));
    };
    let (Some(user), Some(state)) = (token.github.clone(), token.refresh.clone()) else {
        return Err(refused("not a sign-in's refresh token".into()));
    };
    let revoke = |why: &str| -> Result<()> {
        auth::revoke_by_id(root, &token.id)?;
        tracing::warn!(target: "bd::serve", login = %user.login, id = user.id, token = %token.name, "GitHub sign-in revoked at refresh: {why}");
        Ok(())
    };
    if !current && !state.retries_last(secret, request_id) {
        revoke("its refresh token was used twice")?;
        return Err(refused(
            "this refresh token was used already, so the sign-in was revoked: someone else may hold a copy of it"
                .into(),
        ));
    }
    let Some(key) = &github.app else {
        return Err(refused(
            "this bd server no longer refreshes tokens (its auth.toml has no github.private_key)".into(),
        ));
    };
    let now = Timestamp::now();
    let signed_in = Timestamp::parse_rfc3339(&token.created_at)?;
    let limit = signed_in.plus(github.refresh_limit);
    if now >= limit.min(state.refreshed_at.plus(github.refresh_idle)) {
        let why = match now >= limit {
            true => format!("the sign-in of {signed_in} is older than the server lets it be refreshed"),
            false => format!("the sign-in was last refreshed at {}, too long ago", state.refreshed_at),
        };
        return Err(refused(why));
    }
    if github.deny.contains(&user.id) {
        revoke("the account is denied")?;
        return Err(refused(format!("GitHub user {} may not use this bd server", user.login)));
    }
    let api = Api::new(&github);
    let app = AppApi { api: &api, github: &github, key };
    let Some((now_user, created)) = app.user(user.id)? else {
        revoke("the GitHub account no longer exists")?;
        return Err(refused(format!("GitHub has no account {} any more", user.login)));
    };
    if now_user.url != user.url {
        return Err(refused(format!("GitHub user {} signed in at another GitHub than the server's now", user.login)));
    }
    let age = created.map(|at| Duration::from_millis(now.since(at).max(0) as u64));
    let mut asked = Installed { app: &app, login: &now_user.login, seen: HashMap::new() };
    let mut unknown = Vec::new();
    let decision = decide(&github, &now_user.login, age, &state.workspace, &mut asked, &mut unknown)?;
    let (grant, via, by_login) = match decision {
        Decision::In { grant, via, by_login } => (grant, via, by_login),
        out => {
            let why = match out {
                Decision::TooNew(_) => "its GitHub account is too new for the rules".to_string(),
                Decision::Elsewhere(_) => format!("the rules no longer let it into workspace {}", state.workspace),
                _ => "no rule of the server's auth.toml lets the account in any more".to_string(),
            };
            // Memberships GitHub would not tell may come back: the sign-in stays, and only this refresh fails.
            if !unknown.is_empty() {
                tracing::warn!(target: "bd::serve", login = %now_user.login, ?unknown, "GitHub sign-in not refreshed: memberships unknown");
                return Err(Error::Remote(format!(
                    "GitHub would not tell this bd server the memberships of GitHub user {} ({}); try again later",
                    now_user.login,
                    unknown.join("; ")
                )));
            }
            revoke(&why)?;
            return Err(refused(format!("GitHub user {}: {why}", now_user.login)));
        }
    };
    let until = limit.min(now.plus(github.refresh_idle));
    let expires_at = now.plus(github.token_ttl);
    let last = auth::LastRefresh { spent: auth::hash(secret), request: auth::hash(request_id) };
    let rotated = auth::rotate(root, &token.id, &state.sha256, last, &now_user, grant, by_login, expires_at, until)?;
    let Some(issued) = rotated else {
        revoke("its refresh token was used twice")?;
        return Err(refused(
            "this refresh token was used already, so the sign-in was revoked: someone else may hold a copy of it"
                .into(),
        ));
    };
    tracing::info!(
        target: "bd::serve",
        login = %now_user.login,
        id = now_user.id,
        actor = %issued.token.actor,
        token = %issued.token.name,
        role = issued.token.role.as_str(),
        kind = issued.token.kind.as_str(),
        %via,
        ?unknown,
        "GitHub sign-in refreshed"
    );
    Ok(answer_of(issued, now_user.login, via))
}

/// The account a GitHub token belongs to, at the GitHub `api` talks to,
/// and when GitHub created it (if it says).
fn account(api: &Api, token: &str) -> Result<(GithubUser, Option<Timestamp>)> {
    let (status, body) = api.get(token, "/user")?;
    let login = body["login"].as_str().filter(|l| github_name(l));
    match (status, login, body["id"].as_u64()) {
        (200, Some(login), Some(id)) => {
            let created = body["created_at"].as_str().and_then(|at| Timestamp::parse_rfc3339(at).ok());
            Ok((GithubUser { url: api.url.to_ascii_lowercase(), login: login.to_string(), id }, created))
        }
        _ => Err(Error::Remote(format!("GitHub answered {status}{} for the account that signed in", message(&body)))),
    }
}

/// Memberships asked of GitHub with the token of the account signing in,
/// each at most once.
struct Asked<'a> {
    api: &'a Api,
    token: &'a str,
    login: &'a str,
    seen: HashMap<String, Member>,
}

impl Asked<'_> {
    fn ask(&mut self, key: String, path: String) -> Result<Member> {
        if let Some(m) = self.seen.get(&key) {
            return Ok(m.clone());
        }
        let (status, body) = self.api.get(self.token, &path)?;
        let member = match status {
            // A pending invitation is no membership yet.
            200 if body["state"] == "active" => Member::Yes,
            200 | 404 => Member::No,
            // An organization may keep OAuth apps out until an owner approves them; a GitHub App must be installed there.
            401 | 403 => Member::Unknown(format!("GitHub answered {status}{}", message(&body))),
            _ => {
                return Err(Error::Remote(format!(
                    "GitHub answered {status}{} to a membership check of {key}",
                    message(&body)
                )));
            }
        };
        self.seen.insert(key, member.clone());
        Ok(member)
    }
}

impl Memberships for Asked<'_> {
    fn org(&mut self, org: &str) -> Result<Member> {
        self.ask(org.to_ascii_lowercase(), format!("/user/memberships/orgs/{org}"))
    }

    fn team(&mut self, org: &str, team: &str) -> Result<Member> {
        let path = format!("/orgs/{org}/teams/{team}/memberships/{}", self.login);
        self.ask(format!("{org}/{team}").to_ascii_lowercase(), path)
    }
}

// ------------------------------------------------------------ client

/// A one-time code as GitHub writes them (`WDJB-MJHT`).
fn plain_code(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// An `https://` address of printable characters, nothing else.
fn plain_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && s.len() <= 300
        && s.bytes().all(|b| b.is_ascii_graphic())
}

/// `bd remote login --github`: sign in at GitHub through `remote`'s server
/// (`server`, its URL), for `workspace`. Shows the one-time code on stderr
/// and waits until it was entered, or expired; the token issued.
pub fn sign_in(remote: &Remote, workspace: &str, server: &str) -> Result<Issued> {
    let start = SignInStart { workspace: workspace.to_string() };
    let code: SignInCode = remote.auth_request("github/device", &start, Duration::ZERO)?;
    if !plain_code(&code.user_code) || !plain_url(&code.verification_uri) || code.device_code.is_empty() {
        return Err(Error::Remote(format!("{server}: unexpected sign-in answer: not a GitHub code and address")));
    }
    let lasts = Duration::from_secs(code.expires_in.clamp(1, MAX_CODE_LIFE));
    io::errln(format!("! One-time code: {}", code.user_code));
    io::errln(format!(
        "  Enter it at {} within {} minutes to sign in to {server} with GitHub",
        code.verification_uri,
        lasts.as_secs().div_ceil(60)
    ));
    io::errln("  Waiting for GitHub (Ctrl-C cancels)...");
    let deadline = Instant::now() + lasts;
    // GitHub's least time between polls, which only grows; past the deadline, the code is gone anyway.
    let mut interval = Duration::from_secs(code.interval.clamp(1, MAX_CODE_LIFE));
    let poll = SignInPoll { device_code: code.device_code, workspace: workspace.to_string() };
    loop {
        if Instant::now() + interval > deadline {
            return Err(Error::Unauthorized(
                "the one-time code expired before it was entered at GitHub: run `bd remote login --github` again"
                    .into(),
            ));
        }
        std::thread::sleep(interval);
        match remote.auth_request("github/token", &poll, interval)? {
            SignInAnswer::Pending => {}
            SignInAnswer::SlowDown { interval: asked } => {
                let asked = Duration::from_secs(asked.min(MAX_CODE_LIFE));
                interval = (interval + Duration::from_secs(5)).max(asked);
            }
            SignInAnswer::Issued(issued) => return Ok(*issued),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github(text: &str) -> Github {
        parse(text).unwrap().unwrap()
    }

    fn error(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn auth_toml_turns_sign_in_on_with_defaults() {
        assert_eq!(parse("").unwrap(), None, "no [github]: off");
        let g = github("[github]\nclient_id = \" Ov23liX \"\n[[github.allow]]\nusers = [\"alice\"]\n");
        assert_eq!(g.client_id, "Ov23liX");
        assert_eq!((g.url.as_str(), g.api_url.as_str()), ("https://github.com", "https://api.github.com"));
        assert_eq!(g.token_ttl, DEFAULT_TTL);
        let rule = &g.rules[0];
        assert_eq!(
            rule.grant,
            Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec!["*".into()], max_claims: None }
        );
        assert!(!g.reads_orgs(), "users alone need no scope");

        let g = github(
            "[github]\nclient_id = \"x\"\nurl = \"https://ghe.example.com/\"\ntoken_ttl = \"12h\"\n\
             [[github.allow]]\nteams = [\"acme/bd-admins\"]\nrole = \"admin\"\nkind = \"human\"\n\
             workspaces = [\"proj\", \"other\"]\n[[github.allow]]\norgs = [\"acme\"]\nrole = \"read\"\n",
        );
        assert_eq!(g.api_url, "https://ghe.example.com/api/v3", "GitHub Enterprise Server's API");
        assert_eq!(g.token_ttl, Duration::from_secs(12 * 3600));
        assert_eq!(g.rules[0].teams, [("acme".to_string(), "bd-admins".to_string())]);
        assert_eq!(g.rules[0].grant.workspaces, ["other", "proj"]);
        assert_eq!((g.rules[0].grant.role, g.rules[0].grant.kind), (Role::Admin, Kind::Human));
        assert_eq!(g.rules[1].grant.role, Role::Read);
        assert!(g.reads_orgs());
        let g = github(
            "[github]\nclient_id = \"x\"\nurl = \"http://127.0.0.1:9\"\napi_url = \"http://[::1]:9/api\"\n\
             [[github.allow]]\nusers = [\"a\"]\n",
        );
        assert_eq!((g.url.as_str(), g.api_url.as_str()), ("http://127.0.0.1:9", "http://[::1]:9/api"));

        let g = github(
            "[github]\nclient_id = \"x\"\n[[github.allow]]\nusers = [\"a\"]\n\
             [[github.allow]]\nanyone = true\nworkspaces = [\"oss\"]\n",
        );
        assert!(g.rules[1].anyone && !g.reads_orgs());
        let read = Grant { role: Role::Read, kind: Kind::Agent, workspaces: vec!["oss".into()], max_claims: None };
        assert_eq!(g.rules[1].grant, read, "anyone reads unless the rule says write");
        let g = github("[github]\nclient_id = \"x\"\n[[github.allow]]\nanyone = true\nrole = \"write\"\n");
        assert_eq!(g.rules[0].grant.role, Role::Write);
        let g = github(
            "[github]\nclient_id = \"x\"\n[[github.allow]]\norgs = [\"acme\"]\nmax_claims = 2\n[[github.allow]]\nanyone = true\n",
        );
        assert_eq!(g.rules[0].grant.max_claims, Some(2), "strangers who only read hold nothing to compare with");
    }

    #[test]
    fn auth_toml_turns_the_authorization_server_on() {
        let github = "[github]\nclient_id = \"Iv1.x\"\nprivate_key = \"app.pem\"\n[[github.allow]]\nusers = [\"a\"]\n";
        assert_eq!(parse(github).unwrap().unwrap().oauth, None, "off without [oauth]");
        let g =
            parse(&format!("{github}[oauth]\nredirect_hosts = [\" ChatGPT.com \", \"claude.ai\", \"chatgpt.com\"]\n"))
                .unwrap()
                .unwrap();
        let o = g.oauth.unwrap();
        assert_eq!(o.redirect_hosts, ["chatgpt.com", "claude.ai"], "lowercased, once each");
        assert!(!o.loopback_redirects);
        let o = parse(&format!("{github}[oauth]\nloopback_redirects = true\n")).unwrap().unwrap().oauth.unwrap();
        assert!(o.redirect_hosts.is_empty() && o.loopback_redirects);

        assert!(error("[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n").contains("needs [github]"));
        let no_key = "[github]\nclient_id = \"x\"\n[[github.allow]]\nusers = [\"a\"]\n";
        assert!(error(&format!("{no_key}[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n")).contains("private_key"));
        assert!(error(&format!("{github}[oauth]\n")).contains("allows no redirect URIs"));
        for bad in
            ["localhost", "127.0.0.1", "*.example.com", "chatgpt.com:443", "-a.com", "a..com", "https://a.com", ""]
        {
            let e = error(&format!("{github}[oauth]\nredirect_hosts = [\"{bad}\"]\n"));
            assert!(e.contains("is not a host name"), "{bad}: {e}");
        }
        assert!(error(&format!("{github}[oauth]\nissuer = \"https://x\"\n")).contains("unknown field"));
    }

    #[test]
    fn redirects_go_to_the_allowed_hosts_and_maybe_this_machine() {
        let hosts = OauthConfig { redirect_hosts: vec!["chatgpt.com".into()], loopback_redirects: false };
        for ok in [
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://ChatGPT.com/connector/oauth/abc?x=1",
            "https://chatgpt.com",
        ] {
            assert!(hosts.allows_redirect(ok), "{ok}");
        }
        for bad in [
            "http://chatgpt.com/cb",
            "HTTPS://chatgpt.com/cb",
            "https://chatgpt.com:8443/cb",
            "https://chatgpt.com.evil.example/cb",
            "https://evil.example/https://chatgpt.com/",
            "https://user@chatgpt.com/cb",
            "https://evil.example\\@chatgpt.com/cb",
            "https://chatgpt.com/cb#frag",
            "https://chatgpt.com/c b",
            "http://127.0.0.1:3000/callback",
            "chatgpt.com/cb",
            "javascript://chatgpt.com/%0aalert(1)",
        ] {
            assert!(!hosts.allows_redirect(bad), "{bad}");
        }
        let loopback = OauthConfig { redirect_hosts: vec![], loopback_redirects: true };
        for ok in
            ["http://127.0.0.1:3000/callback", "http://localhost:33418/cb", "http://[::1]:9/cb", "http://127.0.0.1/cb"]
        {
            assert!(loopback.allows_redirect(ok), "{ok}");
        }
        for bad in [
            "https://127.0.0.1:3000/callback",
            "http://127.0.0.2/cb",
            "http://localhost.evil.example/cb",
            "http://localhost:99999x/cb",
            "http://localhost:/cb",
            "https://chatgpt.com/cb",
        ] {
            assert!(!loopback.allows_redirect(bad), "{bad}");
        }
    }

    const TEST_KEY: &str = include_str!("../tests/fixtures/github-app.pem");

    #[test]
    fn auth_toml_sets_up_refreshes_with_a_github_app() {
        let base = "[github]\nclient_id = \"Iv1.x\"\n";
        let rule = "\n[[github.allow]]\nusers = [\"a\"]\n";
        let g = github(&format!("{base}{rule}"));
        assert_eq!((g.token_ttl, g.private_key.as_ref(), g.app.as_ref()), (DEFAULT_TTL, None, None));
        assert!(g.lifetime(Timestamp::now()).refresh.is_none(), "no App, no refresh");
        let g =
            github(&format!("{base}private_key = \"app.pem\"\nrefresh_limit = \"14d\"\nrefresh_idle = \"1d\"{rule}"));
        assert_eq!(g.private_key.as_deref(), Some(Path::new("app.pem")));
        assert_eq!((g.refresh_limit, g.refresh_idle), (Duration::from_secs(14 * 86400), Duration::from_secs(86400)));
        for (settings, says) in [
            ("refresh_limit = \"14d\"", "need github.private_key"),
            ("private_key = \"\"", "private_key is empty"),
            ("private_key = \"k\"\ntoken_ttl = \"10d\"", "at most the next"),
            ("private_key = \"k\"\nrefresh_idle = \"60d\"", "at most the next"),
            ("private_key = \"k\"\nrefresh_limit = \"400d\"", "use 5m to 366d"),
        ] {
            let e = error(&format!("{base}{settings}{rule}"));
            assert!(e.contains(says), "{settings}: {e}");
        }

        // load() reads the key, relative to the root.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), format!("{base}private_key = \"app.pem\"{rule}")).unwrap();
        let e = load(dir.path()).unwrap_err().to_string();
        assert!(e.contains("app.pem") && e.contains(FILE), "{e}");
        std::fs::write(dir.path().join("app.pem"), "not a key").unwrap();
        assert!(load(dir.path()).unwrap_err().to_string().contains("no private key in the file"));
        std::fs::write(dir.path().join("app.pem"), TEST_KEY).unwrap();
        let g = load(dir.path()).unwrap().unwrap();
        let key = g.app.as_ref().expect("loaded");
        assert!(!format!("{key:?}").contains("BEGIN"), "never the key");
        let now = Timestamp::now();
        let life = g.lifetime(now).refresh.unwrap();
        assert_eq!(life, (now.plus(DEFAULT_REFRESH_LIMIT), DEFAULT_REFRESH_IDLE));
    }

    #[test]
    fn github_app_keys_sign_jwts_for_their_app() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.pem");
        std::fs::write(&path, TEST_KEY).unwrap();
        let key = AppKey::load(&path).unwrap();
        let jwt = key.jwt("Iv1.test").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "{jwt}");
        let decode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
        let header: Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        let claims: Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(header, serde_json::json!({ "alg": "RS256", "typ": "JWT" }));
        assert_eq!(claims["iss"], "Iv1.test");
        let (iat, exp) = (claims["iat"].as_i64().unwrap(), claims["exp"].as_i64().unwrap());
        let now = Timestamp::now().millis() / 1000;
        assert!(iat <= now - 59 && exp - iat == 600, "{claims}");
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.pair.public().as_ref().to_vec(),
        );
        let signed = format!("{}.{}", parts[0], parts[1]);
        public.verify(signed.as_bytes(), &decode(parts[2])).expect("a valid RS256 signature");
    }

    #[test]
    fn auth_toml_mistakes_are_refused() {
        let with =
            |github: &str, rule: &str| format!("[github]\nclient_id = \"x\"\n{github}\n[[github.allow]]\n{rule}\n");
        for (text, says) in [
            ("[github]\nclient_id = \"x\"\n".to_string(), "no [[github.allow]] rules"),
            ("[github]\n[[github.allow]]\nusers = [\"a\"]\n".to_string(), "client_id"),
            (with("", "users = [\"a\"]\nrole = \"owner\""), "owner"),
            (with("", "users = [\"a\"]\nkind = \"robot\""), "robot"),
            (with("", "user = [\"a\"]"), "unknown field"),
            (with("secret = \"s\"", "users = [\"a\"]"), "unknown field"),
            (with("", "role = \"read\""), "lets nobody in"),
            (with("", "anyone = false"), "lets nobody in"),
            (with("", "anyone = true\nusers = [\"a\"]"), "drop its users, orgs and teams"),
            (with("", "anyone = true\norgs = [\"acme\"]"), "drop its users, orgs and teams"),
            (with("", "anyone = true\nrole = \"admin\""), "not admin"),
            (with("", "anyone = true\nkind = \"human\""), "agent only"),
            (
                with("", "anyone = true\n[[github.allow]]\nusers = [\"a\"]"),
                "rule 1 lets anyone in, so the rules after it",
            ),
            (
                with("", "orgs = [\"o\"]\nrole = \"read\"\n[[github.allow]]\nanyone = true\nrole = \"write\""),
                "rule 1 gives",
            ),
            (
                with(
                    "",
                    "users = [\"a\"]\nrole = \"read\"\nworkspaces = [\"p\"]\n[[github.allow]]\nanyone = true\nrole = \"write\"\nworkspaces = [\"p\", \"q\"]",
                ),
                "raise its role, or keep their workspaces apart",
            ),
            (with("deny = [\"alice\"]", "users = [\"a\"]"), "line 3: invalid type"),
            (with("", "users = [\"../admin\"]"), "not a GitHub name"),
            (with("", "orgs = [\"acme/x\"]"), "not a GitHub name"),
            (with("", "teams = [\"acme\"]"), "not <organization>/<team slug>"),
            (with("", "teams = [\"acme/x/y\"]"), "not <organization>/<team slug>"),
            (with("", "users = [\"a\"]\nworkspaces = [\"../x\"]"), "invalid workspace name"),
            (with("url = \"http://github.com\"", "users = [\"a\"]"), "must use https"),
            (with("api_url = \"https://u:p@h\"", "users = [\"a\"]"), "no credentials"),
            (with("url = \"github.com\"", "users = [\"a\"]"), "no scheme"),
            (with("token_ttl = \"1m\"", "users = [\"a\"]"), "use 5m to 366d"),
            (with("token_ttl = \"400d\"", "users = [\"a\"]"), "use 5m to 366d"),
            (with("token_ttl = \"soon\"", "users = [\"a\"]"), "token_ttl"),
            (with("", "anyone = true\nmin_account_age = \"a while\""), "rule 1: min_account_age"),
            (with("", "anyone = true\nmax_claims = 0"), "max_claims must be at least 1"),
            (with("", "anyone = true\nmax_claims = -1"), "line 6: invalid value"),
            (
                with(
                    "",
                    "orgs = [\"acme\"]\nmax_claims = 2\n[[github.allow]]\nanyone = true\nrole = \"write\"\nmax_claims = 5",
                ),
                "rule 1 lets its accounts hold fewer claims than rule 2",
            ),
            (
                with(
                    "",
                    "orgs = [\"acme\"]\nmax_claims = 2\nworkspaces = [\"p\"]\n[[github.allow]]\nanyone = true\nrole = \"write\"",
                ),
                "raise its max_claims, or keep their workspaces apart",
            ),
            ("[github]\nclient_id = \"has space\"\n[[github.allow]]\nusers = [\"a\"]\n".to_string(), "client_id"),
        ] {
            let e = error(&text);
            assert!(e.contains(says), "{text:?}: {e}");
        }
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), None, "no file: off");
        std::fs::write(dir.path().join(FILE), "[github]\nclient_id = 1\n").unwrap();
        let e = load(dir.path()).unwrap_err();
        assert!(e.to_string().contains(FILE) && e.exit_code() == 2, "{e}");
    }

    /// Memberships from a list (`acme`, `acme/team`); `blocked` organizations
    /// will not tell. Records each question.
    struct Known {
        member_of: Vec<&'static str>,
        blocked: Vec<&'static str>,
        asked: Vec<String>,
    }

    impl Memberships for Known {
        fn org(&mut self, org: &str) -> Result<Member> {
            self.asked.push(org.to_string());
            Ok(match (self.blocked.contains(&org), self.member_of.contains(&org)) {
                (true, _) => Member::Unknown("GitHub answered 403".into()),
                (_, true) => Member::Yes,
                _ => Member::No,
            })
        }

        fn team(&mut self, org: &str, team: &str) -> Result<Member> {
            let name = format!("{org}/{team}");
            self.asked.push(name.clone());
            Ok(if self.member_of.contains(&name.as_str()) { Member::Yes } else { Member::No })
        }
    }

    #[test]
    fn the_first_rule_that_lets_an_account_in_decides() {
        let g = github(
            "[github]\nclient_id = \"x\"\n\
             [[github.allow]]\nusers = [\"Alice\"]\nrole = \"admin\"\n\
             [[github.allow]]\nteams = [\"acme/bd\"]\norgs = [\"partner\"]\nkind = \"human\"\n\
             [[github.allow]]\norgs = [\"acme\"]\nrole = \"read\"\n",
        );
        let decide_for = |login: &str, member_of: Vec<&'static str>, blocked: Vec<&'static str>| {
            let mut known = Known { member_of, blocked, asked: Vec::new() };
            let mut unknown = Vec::new();
            let decided = role_via(decide(&g, login, None, "proj", &mut known, &mut unknown).unwrap());
            (decided, known.asked, unknown)
        };
        let (decided, asked, _) = decide_for("alice", vec!["acme"], vec![]);
        assert_eq!(decided, Some((Role::Admin, "GitHub user alice".into())), "logins match whatever their case");
        assert!(asked.is_empty(), "no membership is asked once a login matches");

        let (decided, asked, _) = decide_for("bob", vec!["acme", "acme/bd"], vec![]);
        assert_eq!(decided, Some((Role::Write, "member of team acme/bd".into())), "the team's rule comes first");
        assert_eq!(asked, ["partner", "acme/bd"], "organizations, then teams, of each rule in order");

        let (decided, asked, _) = decide_for("carol", vec!["acme"], vec![]);
        assert_eq!(decided, Some((Role::Read, "member of acme".into())));
        assert_eq!(asked, ["partner", "acme/bd", "acme"]);

        let (decided, _, unknown) = decide_for("mallory", vec!["acme/other"], vec!["partner", "acme"]);
        assert_eq!(decided, None);
        assert_eq!(unknown, ["partner: GitHub answered 403", "acme: GitHub answered 403"]);
    }

    fn role_via(d: Decision) -> Option<(Role, String)> {
        match d {
            Decision::In { grant, via, .. } => Some((grant.role, via)),
            _ => None,
        }
    }

    #[test]
    fn a_rule_for_other_workspaces_leaves_the_account_to_the_rules_after_it() {
        let g = github(
            "[github]\nclient_id = \"x\"\n\
             [[github.allow]]\norgs = [\"acme\"]\nrole = \"admin\"\nworkspaces = [\"internal\"]\n\
             [[github.allow]]\nusers = [\"bob\"]\nworkspaces = [\"docs\", \"internal\"]\n\
             [[github.allow]]\nanyone = true\nworkspaces = [\"oss\"]\n",
        );
        let decide_for = |login: &str, workspace: &str| {
            let mut known = Known { member_of: vec!["acme"], blocked: vec![], asked: Vec::new() };
            decide(&g, login, None, workspace, &mut known, &mut Vec::new()).unwrap()
        };
        assert_eq!(role_via(decide_for("bob", "internal")), Some((Role::Admin, "member of acme".into())));
        assert_eq!(role_via(decide_for("bob", "docs")), Some((Role::Write, "GitHub user bob".into())));
        assert_eq!(role_via(decide_for("bob", "oss")), Some((Role::Read, "GitHub user bob, as anyone".into())));
        let Decision::In { grant, .. } = decide_for("bob", "docs") else { panic!() };
        assert_eq!(grant.workspaces, ["docs"], "never internal, where the first rule decides");

        let g = github(
            "[github]\nclient_id = \"x\"\n[[github.allow]]\nusers = [\"bob\"]\nworkspaces = [\"docs\", \"internal\"]\n",
        );
        let mut known = Known { member_of: vec![], blocked: vec![], asked: Vec::new() };
        let Decision::In { grant, .. } = decide(&g, "bob", None, "docs", &mut known, &mut Vec::new()).unwrap() else {
            panic!()
        };
        assert_eq!(grant.workspaces, ["docs", "internal"], "the first rule that lets bob in decides: all of it");
        match decide_for("bob", "secret") {
            Decision::Elsewhere(w) => assert_eq!(w, ["internal", "docs", "oss"]),
            other => panic!("{other:?}"),
        }

        let g = github("[github]\nclient_id = \"x\"\n[[github.allow]]\nusers = [\"a\"]\nworkspaces = [\"p\"]\n");
        let mut known = Known { member_of: vec![], blocked: vec![], asked: Vec::new() };
        assert!(matches!(decide(&g, "z", None, "p", &mut known, &mut Vec::new()).unwrap(), Decision::Out));
    }

    #[test]
    fn an_anyone_rule_lets_in_whom_the_rules_before_it_do_not() {
        let g = github(
            "[github]\nclient_id = \"x\"\ndeny = [7]\n\
             [[github.allow]]\norgs = [\"acme\"]\nrole = \"write\"\n\
             [[github.allow]]\nanyone = true\n",
        );
        assert_eq!(g.deny, [7]);
        let mut known = Known { member_of: vec!["acme"], blocked: vec![], asked: Vec::new() };
        let decided = role_via(decide(&g, "bob", None, "proj", &mut known, &mut Vec::new()).unwrap());
        assert_eq!(decided, Some((Role::Write, "member of acme".into())));
        let mut known = Known { member_of: vec![], blocked: vec![], asked: Vec::new() };
        let decided = role_via(decide(&g, "Mallory", None, "proj", &mut known, &mut Vec::new()).unwrap());
        assert_eq!(decided, Some((Role::Read, "GitHub user Mallory, as anyone".into())));
        assert_eq!(known.asked, ["acme"], "the anyone rule asks GitHub nothing");
    }

    #[test]
    fn young_accounts_are_left_to_the_rules_without_a_min_account_age() {
        let g = github(
            "[github]\nclient_id = \"x\"\n\
             [[github.allow]]\norgs = [\"acme\"]\nworkspaces = [\"proj\"]\nmin_account_age = \"7d\"\n\
             [[github.allow]]\nanyone = true\nworkspaces = [\"proj\", \"oss\"]\nmin_account_age = \"30d\"\nmax_claims = 2\n",
        );
        assert_eq!(g.rules[1].min_account_age, Some(Duration::from_secs(30 * 86400)));
        assert_eq!(g.rules[1].grant.max_claims, Some(2));
        assert_eq!(g.rules[0].grant.max_claims, None);
        let days = |n: u64| Some(Duration::from_secs(n * 86400));
        let decide_for = |login: &str, age: Option<Duration>, workspace: &str| {
            let mut known = Known { member_of: vec!["acme"], blocked: vec![], asked: Vec::new() };
            decide(&g, login, age, workspace, &mut known, &mut Vec::new()).unwrap()
        };
        assert_eq!(role_via(decide_for("bob", days(8), "proj")), Some((Role::Write, "member of acme".into())));
        let Decision::In { grant, .. } = decide_for("eve", days(31), "oss") else { panic!() };
        assert_eq!((grant.role, grant.max_claims), (Role::Read, Some(2)));
        // Too new for every rule that would let it in: the least age it needs.
        assert!(matches!(decide_for("bob", days(6), "proj"), Decision::TooNew(d) if d == days(7).unwrap()));
        assert!(matches!(decide_for("bob", days(6), "oss"), Decision::TooNew(d) if d == days(30).unwrap()));
        assert!(matches!(decide_for("bob", None, "proj"), Decision::TooNew(_)), "no age from GitHub: too new");
        // Too new for a rule elsewhere only: the rules for this workspace decide.
        let mut known = Known { member_of: vec![], blocked: vec![], asked: Vec::new() };
        assert!(matches!(decide(&g, "eve", days(1), "secret", &mut known, &mut Vec::new()).unwrap(), Decision::Out));
    }

    #[test]
    fn the_client_shows_only_plain_codes_and_addresses() {
        assert!(plain_code("WDJB-MJHT") && !plain_code("") && !plain_code("WDJB MJHT") && !plain_code("\x1b[2J"));
        assert!(plain_url("https://github.com/login/device"));
        for bad in ["javascript:alert(1)", "https://github.com/login device", "https://evil\u{202e}moc", "ftp://x"] {
            assert!(!plain_url(bad), "{bad}");
        }
    }
}
