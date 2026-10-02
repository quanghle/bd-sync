//! GitHub sign-in: people get a `bd serve` access token by signing in with
//! GitHub (`bd remote login --github`), instead of an admin creating one.
//!
//! `<root>/auth.toml` turns it on and decides who may sign in, and what
//! their token may do:
//!
//! ```toml
//! [github]
//! client_id = "Ov23li0123456789abcd"  # a GitHub OAuth app or GitHub App, with device flow enabled
//! token_ttl = "30d"                   # issued tokens expire (default 30d)
//!
//! [[github.allow]]                    # the first rule that matches decides; no match, no token
//! users = ["alice"]
//! role = "admin"
//! kind = "human"
//!
//! [[github.allow]]
//! orgs = ["acme"]                     # active members of any of these organizations
//! teams = ["acme/bd-maintainers"]     # or of any of these teams
//! workspaces = ["proj"]
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
//! request, so a change applies from the next sign-in; tokens already issued
//! keep their permissions until they expire or are revoked.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use bd_core::{Error, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{self, GithubUser, Grant, Kind, Role};
use crate::io;
use crate::protocol::{Issued, SignInAnswer, SignInCode, SignInPoll, SignInStart};
use crate::remote::Remote;

/// `<root>/auth.toml`.
pub const FILE: &str = "auth.toml";
/// How long issued tokens work, unless `token_ttl` says otherwise.
const DEFAULT_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// The range of `token_ttl`.
const TTL_RANGE: (Duration, Duration) = (Duration::from_secs(3600), Duration::from_secs(366 * 24 * 3600));
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
    token_ttl: Option<String>,
    #[serde(default)]
    allow: Vec<RuleDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDoc {
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    orgs: Vec<String>,
    #[serde(default)]
    teams: Vec<String>,
    #[serde(default = "write_role")]
    role: Role,
    #[serde(default = "agent_kind")]
    kind: Kind,
    #[serde(default)]
    workspaces: Vec<String>,
}

fn write_role() -> Role {
    Role::Write
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
    pub rules: Vec<Rule>,
}

/// One `[[github.allow]]` rule: whom it lets in, and what their token may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Logins, matched whatever their case.
    pub users: Vec<String>,
    pub orgs: Vec<String>,
    /// `(organization, team slug)`.
    pub teams: Vec<(String, String)>,
    pub grant: Grant,
}

impl Github {
    /// Whether a rule names organizations or teams, whose memberships an
    /// OAuth app reads with the `read:org` scope.
    fn reads_orgs(&self) -> bool {
        self.rules.iter().any(|r| !r.orgs.is_empty() || !r.teams.is_empty())
    }
}

/// GitHub sign-in as `<root>/auth.toml` configures it: `None` without the
/// file, or without its `[github]` table.
pub fn load(root: &Path) -> Result<Option<Github>> {
    let path = root.join(FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::invalid(format!("{}: {e}", path.display()))),
    };
    parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
}

fn parse(text: &str) -> std::result::Result<Option<Github>, String> {
    let doc: Doc = toml::from_str(text).map_err(|e| {
        // The parser's own text quotes the file, which may hold what should not be shown: name the line only.
        let line = e.span().map(|s| text.as_bytes()[..s.start.min(text.len())].iter().filter(|&&b| b == b'\n').count());
        format!("{}{}", line.map(|n| format!("line {}: ", n + 1)).unwrap_or_default(), e.message().trim_end())
    })?;
    let Some(g) = doc.github else { return Ok(None) };
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
    let token_ttl = match &g.token_ttl {
        None => DEFAULT_TTL,
        Some(raw) => bd_core::time::parse_duration(raw).map_err(|e| format!("github.token_ttl: {e}"))?,
    };
    if token_ttl < TTL_RANGE.0 || token_ttl > TTL_RANGE.1 {
        return Err(format!("github.token_ttl {:?}: use 1h to 366d", g.token_ttl.unwrap_or_default()));
    }
    if g.allow.is_empty() {
        return Err("[github] has no [[github.allow]] rules, so no GitHub account may sign in: add rules, or remove \
                    [github]"
            .into());
    }
    let rules = g.allow.into_iter().enumerate().map(|(i, r)| rule(i + 1, r)).collect::<std::result::Result<_, _>>()?;
    Ok(Some(Github { client_id, url, api_url, token_ttl, rules }))
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
    if users.is_empty() && orgs.is_empty() && teams.is_empty() {
        return Err(format!("{at} names no users, orgs or teams, so it lets nobody in"));
    }
    let workspaces = auth::workspace_list(&r.workspaces).map_err(|e| format!("{at}: {e}"))?;
    Ok(Rule { users, orgs, teams, grant: Grant { role: r.role, kind: r.kind, workspaces } })
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

/// The first rule that lets `login` in, and what matched (`GitHub user
/// alice`, `member of acme`); `None` when no rule does. Memberships GitHub
/// would not tell are noted in `unknown`.
pub fn decide<'a>(
    github: &'a Github,
    login: &str,
    m: &mut dyn Memberships,
    unknown: &mut Vec<String>,
) -> Result<Option<(&'a Rule, String)>> {
    let mut note = |what: String| {
        if !unknown.contains(&what) {
            unknown.push(what);
        }
    };
    for rule in &github.rules {
        if rule.users.iter().any(|u| u.eq_ignore_ascii_case(login)) {
            return Ok(Some((rule, format!("GitHub user {login}"))));
        }
        for org in &rule.orgs {
            match m.org(org)? {
                Member::Yes => return Ok(Some((rule, format!("member of {org}")))),
                Member::No => {}
                Member::Unknown(why) => note(format!("{org}: {why}")),
            }
        }
        for (org, team) in &rule.teams {
            match m.team(org, team)? {
                Member::Yes => return Ok(Some((rule, format!("member of team {org}/{team}")))),
                Member::No => {}
                Member::Unknown(why) => note(format!("team {org}/{team}: {why}")),
            }
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
    let user = account(&api, access)?;
    let mut asked = Asked { api: &api, token: access, login: &user.login, seen: HashMap::new() };
    let mut unknown = Vec::new();
    let decided = decide(&github, &user.login, &mut asked, &mut unknown)?;
    let Some((rule, via)) = decided else {
        tracing::info!(target: "bd::serve", login = %user.login, id = user.id, ?unknown, "GitHub sign-in refused: no rule lets the account in");
        return Err(Error::Unauthorized(format!(
            "GitHub user {} may not sign in to this bd server: no rule of its auth.toml lets the account in",
            user.login
        )));
    };
    if !rule.grant.allows_workspace(&poll.workspace) {
        tracing::info!(target: "bd::serve", login = %user.login, id = user.id, workspace = %poll.workspace, %via, "GitHub sign-in refused: workspace not allowed");
        return Err(Error::Unauthorized(format!(
            "GitHub user {} may sign in to this bd server, but not use workspace {} (only {})",
            user.login,
            poll.workspace,
            rule.grant.workspaces.join(", ")
        )));
    }
    let (token, secret) = auth::issue_github_token(root, &user, rule.grant.clone(), github.token_ttl)?;
    tracing::info!(
        target: "bd::serve",
        login = %user.login,
        id = user.id,
        actor = %token.actor,
        token = %token.name,
        role = token.role.as_str(),
        kind = token.kind.as_str(),
        %via,
        "GitHub sign-in issued an access token"
    );
    Ok(SignInAnswer::Issued(Box::new(Issued {
        token: secret,
        name: token.name,
        actor: token.actor,
        role: token.role.as_str().to_string(),
        kind: token.kind.as_str().to_string(),
        workspaces: token.workspaces,
        expires_at: token.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
        login: user.login,
        via,
    })))
}

/// The account a GitHub token belongs to, at the GitHub `api` talks to.
fn account(api: &Api, token: &str) -> Result<GithubUser> {
    let (status, body) = api.get(token, "/user")?;
    let login = body["login"].as_str().filter(|l| github_name(l));
    match (status, login, body["id"].as_u64()) {
        (200, Some(login), Some(id)) => {
            Ok(GithubUser { url: api.url.to_ascii_lowercase(), login: login.to_string(), id })
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
        assert_eq!(rule.grant, Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec!["*".into()] });
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
            (with("", "users = [\"../admin\"]"), "not a GitHub name"),
            (with("", "orgs = [\"acme/x\"]"), "not a GitHub name"),
            (with("", "teams = [\"acme\"]"), "not <organization>/<team slug>"),
            (with("", "teams = [\"acme/x/y\"]"), "not <organization>/<team slug>"),
            (with("", "users = [\"a\"]\nworkspaces = [\"../x\"]"), "invalid workspace name"),
            (with("url = \"http://github.com\"", "users = [\"a\"]"), "must use https"),
            (with("api_url = \"https://u:p@h\"", "users = [\"a\"]"), "no credentials"),
            (with("url = \"github.com\"", "users = [\"a\"]"), "no scheme"),
            (with("token_ttl = \"10m\"", "users = [\"a\"]"), "use 1h to 366d"),
            (with("token_ttl = \"400d\"", "users = [\"a\"]"), "use 1h to 366d"),
            (with("token_ttl = \"soon\"", "users = [\"a\"]"), "token_ttl"),
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
            let decided = decide(&g, login, &mut known, &mut unknown).unwrap().map(|(r, via)| (r.grant.role, via));
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

    #[test]
    fn the_client_shows_only_plain_codes_and_addresses() {
        assert!(plain_code("WDJB-MJHT") && !plain_code("") && !plain_code("WDJB MJHT") && !plain_code("\x1b[2J"));
        assert!(plain_url("https://github.com/login/device"));
        for bad in ["javascript:alert(1)", "https://github.com/login device", "https://evil\u{202e}moc", "ftp://x"] {
            assert!(!plain_url(bad), "{bad}");
        }
    }
}
