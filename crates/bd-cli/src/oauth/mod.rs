//! Sign-in: people get a `bd serve` access token by signing in with a
//! provider (GitHub, or an OpenID Connect provider: `oidc.rs`), from the
//! command line (`bd remote login --provider <name>`, the device flow) or in
//! a browser through an MCP client (`oauth_server/`), instead of an admin
//! creating one. `<root>/auth.toml` turns it on and decides who may sign in
//! and what their token may do; docs/remote.md describes it.
//!
//! - `config`: `auth.toml` as written and checked (`parse`), loaded here
//!   with its secret files and cached until one of them changes (`load`).
//! - `rules`: `[[github.allow]]` rules (`decide`); OIDC providers' rules are
//!   in `oidc.rs`. `[authorizer]` (`authorizer.rs`) replaces the rules: the
//!   admin's own code decides, within caps; the account is still proved and
//!   bound here.
//! - `github`: GitHub's API as the App and as the person, the App's key and
//!   client secret, memberships, its web sign-in.
//! - `admit`: the device flow at the server, admitting an account
//!   (`admit`, `admit_oidc`), providers' account notifications.
//! - `refresh`: refreshing a sign-in: deciding again, then rotating its
//!   secrets (`auth::rotate`); a refresh secret used twice revokes it.
//! - `client`: `bd remote login --provider` on the client.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use bd_core::{Error, Result, Timestamp};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{self, Grant, Identity, Kind, Role};
use crate::io;
use crate::protocol::{Issued, SignInAnswer, SignInCode, SignInPoll, SignInStart};
use crate::remote::Remote;

mod admit;
mod client;
mod config;
mod github;
mod refresh;
mod rules;

pub use admit::*;
pub use client::*;
pub use config::*;
pub use github::*;
pub use refresh::*;
pub use rules::*;

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

/// Sign-in, as `auth.toml` configures it: the providers people sign in
/// with, how long their tokens last, who decides, and the authorization
/// server for MCP clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignIn {
    /// `[github]`, if people sign in with GitHub.
    pub github: Option<Github>,
    /// `[oidc.<name>]`: OpenID Connect providers (`oidc.rs`), by name.
    pub oidc: Vec<crate::oidc::Oidc>,
    /// How long issued tokens work (`[sign_in]`).
    pub token_ttl: Duration,
    /// How long after its sign-in a token may be refreshed.
    pub refresh_limit: Duration,
    /// How long a sign-in may go without a refresh.
    pub refresh_idle: Duration,
    /// The admin's own code deciding who may sign in (`[authorizer]`,
    /// `authorizer.rs`), instead of `[[github.allow]]` rules.
    pub authorizer: Option<crate::authorizer::Authorizer>,
    /// The authorization server for MCP clients, if `[oauth]` turns it on.
    pub oauth: Option<OauthConfig>,
}

impl SignIn {
    /// Whether sign-ins with `provider` get refresh tokens: only when
    /// someone decides again at each refresh, the authorizer, or GitHub's
    /// rules through the GitHub App.
    pub fn refreshes(&self, provider: &str) -> bool {
        self.authorizer.is_some()
            || (provider == "github" && self.github.as_ref().is_some_and(|g| g.private_key.is_some()))
            || self.oidc(provider).is_some_and(|o| !o.allow.is_empty())
    }

    /// The files holding secrets of sign-in, as written (relative to `root`
    /// unless absolute): the GitHub App's key and client secret, OIDC
    /// client secrets or the keys signing them, and the authorizer's token.
    pub fn secret_files(&self, root: &Path) -> Vec<PathBuf> {
        let mut files: Vec<&PathBuf> = Vec::new();
        if let Some(g) = &self.github {
            files.extend(g.private_key.iter().chain(&g.client_secret_file));
        }
        files.extend(self.oidc.iter().flat_map(|o| o.secret_files()));
        if let Some(crate::authorizer::How::Https { token_file: Some(f), .. }) =
            self.authorizer.as_ref().map(|a| &a.how)
        {
            files.push(f);
        }
        files.into_iter().map(|f| if f.is_relative() { root.join(f) } else { f.clone() }).collect()
    }

    /// What the server offers, for a message: `it offers github and okta
    /// (bd remote login --provider <name>)`.
    pub fn offered(&self) -> String {
        let names: Vec<&str> =
            self.github.iter().map(|_| "github").chain(self.oidc.iter().map(|o| o.name.as_str())).collect();
        format!("it offers {} (`bd remote login --provider <name>`)", names.join(", "))
    }

    /// Whether `user` signed in with a provider this configuration still
    /// has, at the same issuer: a provider removed, or pointed elsewhere,
    /// vouches for its sign-ins no more.
    pub fn provides(&self, user: &Identity) -> bool {
        match user.provider.as_str() {
            "github" => self.github.as_ref().is_some_and(|g| g.url.to_ascii_lowercase() == user.issuer),
            name => self.oidc(name).is_some_and(|o| o.issuer == user.issuer),
        }
    }

    /// The OIDC provider named `name`, if there is one.
    pub fn oidc(&self, name: &str) -> Option<&crate::oidc::Oidc> {
        self.oidc.iter().find(|o| o.name == name)
    }

    /// The providers people may sign in with in a browser, as the sign-in
    /// page offers them: name and label. GitHub only with its client secret.
    pub fn browser_providers(&self) -> Vec<(&str, &str)> {
        let github = self.github.as_ref().filter(|g| g.client_secret_file.is_some()).map(|_| ("github", "GitHub"));
        github.into_iter().chain(self.oidc.iter().map(|o| (o.name.as_str(), o.label.as_str()))).collect()
    }

    /// How long the tokens of a sign-in with `provider` at `now` last.
    pub fn lifetime(&self, now: Timestamp, provider: &str) -> auth::Lifetime {
        let refresh = self.refreshes(provider).then(|| (now.plus(self.refresh_limit), self.refresh_idle));
        auth::Lifetime { ttl: self.token_ttl, refresh, rule: None }
    }
}

/// Sign-in as `<root>/auth.toml` configures it (`None` without the file):
/// as last read, unless it or a secret file it names changed since.
pub fn load(root: &Path) -> Result<Option<SignIn>> {
    let fresh = |(file, seen): &(PathBuf, Option<Stamp>)| stamp(file) == *seen;
    if let Some((sign_in, files, at)) = loaded().get(root) {
        if at.elapsed() < RELOAD_AT_LEAST && files.iter().all(fresh) {
            return Ok(sign_in.clone());
        }
    }
    // Stamped before reading: a change made while reading is seen at the next load.
    let path = root.join(FILE);
    let before = stamp(&path);
    let sign_in = load_files(root)?;
    let mut files = vec![(path, before)];
    if let Some(s) = &sign_in {
        files.extend(s.secret_files(root).into_iter().map(|f| (f.clone(), stamp(&f))));
    }
    loaded().insert(root.to_path_buf(), (sign_in.clone(), files, Instant::now()));
    Ok(sign_in)
}

/// What tells a file's content changed: its modification time, size and
/// (on Unix) inode, which an editor replacing it changes.
type Stamp = (Option<std::time::SystemTime>, u64, u64);

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some((meta.modified().ok(), meta.len(), inode))
}

/// Each root's settings as last read, from which files (stamped), and when:
/// read again once any of them changed, and at least every
/// [`RELOAD_AT_LEAST`] (a change a coarse clock would not show).
type Loaded = HashMap<PathBuf, (Option<SignIn>, Vec<(PathBuf, Option<Stamp>)>, Instant)>;
static LOADED: LazyLock<Mutex<Loaded>> = LazyLock::new(Default::default);
const RELOAD_AT_LEAST: Duration = Duration::from_secs(30);

fn loaded() -> std::sync::MutexGuard<'static, Loaded> {
    LOADED.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `<root>/auth.toml` and the secret files it names, read now.
fn load_files(root: &Path) -> Result<Option<SignIn>> {
    let path = root.join(FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::invalid(format!("{}: {e}", path.display()))),
    };
    let Some(mut sign_in) = parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))? else {
        return Ok(None);
    };
    if let Some(github) = &mut sign_in.github {
        if let Some(key) = &github.private_key {
            let key = if key.is_relative() { root.join(key) } else { key.clone() };
            github.app = Some(AppKey::load(&key).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?);
        }
        if let Some(file) = &github.client_secret_file {
            let file = if file.is_relative() { root.join(file) } else { file.clone() };
            let secret = ClientSecret::load(&file).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
            github.client_secret = Some(secret);
        }
    }
    for oidc in &mut sign_in.oidc {
        oidc.load_secret(root).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    }
    if let Some(authorizer) = &mut sign_in.authorizer {
        authorizer.load_token(root).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    }
    Ok(Some(sign_in))
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
    let sign_in = parse(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    Ok(sign_in.and_then(|g| g.oauth))
}

/// GitHub sign-in as `auth.toml` sets it up now, for a sign-in request. A
/// mistake in the file is the admin's to see, in the log: the client gets
/// no detail of it.
fn enabled(root: &Path) -> Result<SignIn> {
    match load(root) {
        Ok(Some(sign_in)) => Ok(sign_in),
        Ok(None) => Err(not_enabled()),
        Err(e) => {
            tracing::warn!(target: "bd::serve", error = %e, "sign-in refused: auth.toml cannot be used");
            Err(Error::Remote("sign-in is not working on this bd server: its admin finds why in the server log".into()))
        }
    }
}

fn not_enabled() -> Error {
    Error::Unauthorized(
        "sign-in is not enabled on this bd server: its admin turns it on in auth.toml, or creates access tokens \
         (`bd serve token create`)"
            .into(),
    )
}

/// `[github]` of `sign_in`, or why people cannot sign in with GitHub.
fn github_of(sign_in: &SignIn) -> Result<&Github> {
    sign_in.github.as_ref().ok_or_else(|| {
        Error::invalid(format!("GitHub sign-in is not enabled on this bd server; {}", sign_in.offered()))
    })
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

/// The OIDC provider `name` of `sign_in`, or why people cannot sign in with it.
fn oidc_of<'s>(sign_in: &'s SignIn, name: &str) -> Result<&'s crate::oidc::Oidc> {
    sign_in
        .oidc(name)
        .ok_or_else(|| Error::invalid(format!("this bd server has no sign-in provider {name}; {}", sign_in.offered())))
}

/// An account the rules let into a workspace, and what they grant it there.
#[derive(Clone, Debug)]
pub struct Admitted {
    pub user: Identity,
    pub grant: Grant,
    /// What let it in (`GitHub user alice`, `member of acme`).
    pub via: String,
    /// Whether that was its login in a rule's `users`.
    pub by_login: bool,
    /// Memberships GitHub would not tell, for the log.
    pub unknown: Vec<String>,
    /// Its email, if its OIDC provider verified it: shown on the consent
    /// page, never kept.
    pub email: Option<String>,
    /// The fingerprint of the `[[oidc.<name>.allow]]` rule that let it in,
    /// kept with its sign-in: its refreshes go on while that rule is there.
    pub rule: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_in(text: &str) -> SignIn {
        parse(text).unwrap().unwrap()
    }

    fn github(text: &str) -> Github {
        sign_in(text).github.unwrap()
    }

    fn error(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn settings_are_read_again_only_when_a_file_they_come_from_changed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(FILE);
        let secret = dir.path().join("secret");
        let config = |label: &str| {
            format!(
                "[oidc.acme]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\nclient_secret_file = \"secret\"\n\
                 label = \"{label}\"\n[authorizer]\ncommand = [\"a\"]\n"
            )
        };
        let label = || load(dir.path()).unwrap().map(|s| s.oidc[0].label.clone());
        let secret_of = || load(dir.path()).unwrap().unwrap().oidc[0].client_secret.clone().unwrap();
        assert_eq!(label(), None, "no file");
        std::fs::write(&secret, "s3cret-1").unwrap();
        // A mistake is not kept: the fixed file is read.
        std::fs::write(&file, config("")).unwrap();
        assert!(load(dir.path()).is_err());
        std::fs::write(&file, config("Alice SSO")).unwrap();
        assert_eq!(label().as_deref(), Some("Alice SSO"));
        // Unchanged as far as its stamp tells: what was read is kept, not read again each time.
        let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
        let mut opened = std::fs::OpenOptions::new().write(true).open(&file).unwrap();
        std::io::Write::write_all(&mut opened, config("Bobby SSO").as_bytes()).unwrap();
        opened.set_modified(modified).unwrap();
        assert_eq!(label().as_deref(), Some("Alice SSO"), "kept");
        // Changed: read again; a secret file's change too.
        opened.set_modified(modified + Duration::from_secs(1)).unwrap();
        assert_eq!(label().as_deref(), Some("Bobby SSO"));
        assert!(format!("{:?}", secret_of()).contains("Secret"));
        let before = secret_of();
        std::fs::write(&secret, "s3cret-22").unwrap();
        assert_ne!(secret_of(), before, "the secret file was read again");
        std::fs::remove_file(&file).unwrap();
        assert_eq!(label(), None, "gone");
    }

    #[test]
    fn oidc_providers_have_rules_or_an_authorizer() {
        let corp = "[oidc.corp]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n";
        let rules = "[[oidc.corp.allow]]\nemail_domains = [\"acme.example\"]\n";
        let authorizer = "[authorizer]\ncommand = [\"a\"]\n";
        let ok = sign_in(&format!("{corp}{rules}"));
        assert!(ok.refreshes("corp"), "rules decide again at refreshes");
        assert!(error(corp).contains("lets nobody in: add [[oidc.corp.allow]] rules, or an [authorizer]"));
        assert!(error(&format!("{corp}{rules}{authorizer}")).contains("instead of [[oidc.corp.allow]] rules"));
        assert!(sign_in(&format!("{corp}{authorizer}")).refreshes("corp"));
        let anyone_first = format!("{corp}[[oidc.corp.allow]]\nanyone = true\n{rules}");
        assert!(error(&anyone_first).contains("[[oidc.corp.allow]] rule 1 lets anyone in"));
        let lower = format!(
            "{corp}[[oidc.corp.allow]]\nsubjects = [\"s\"]\nrole = \"read\"\n[[oidc.corp.allow]]\nanyone = true\nrole = \"write\"\n"
        );
        assert!(error(&lower).contains("gives its accounts role read where rule 2 gives anyone role write"));
    }

    #[test]
    fn one_issuer_is_one_provider() {
        let table = |name: &str, client: &str| {
            format!("[oidc.{name}]\nissuer = \"https://idp.example\"\nclient_id = \"{client}\"\n")
        };
        let text = format!("{}{}[authorizer]\ncommand = [\"x\"]\n", table("corp", "cli"), table("corp-web", "web"));
        let e = error(&text);
        assert!(e.contains("[oidc.corp] and [oidc.corp-web] name the same issuer"), "{e}");
    }

    #[test]
    fn auth_toml_turns_sign_in_on_with_defaults() {
        assert_eq!(parse("").unwrap(), None, "no [github]: off");
        let g = github("[github]\nclient_id = \" Ov23liX \"\n[[github.allow]]\nusers = [\"alice\"]\n");
        assert_eq!(g.client_id, "Ov23liX");
        assert_eq!((g.url.as_str(), g.api_url.as_str()), ("https://github.com", "https://api.github.com"));
        let rule = &g.rules[0];
        assert_eq!(
            rule.grant,
            Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec!["*".into()], max_claims: None }
        );
        assert!(!g.reads_orgs(), "users alone need no scope");

        let all = sign_in(
            "[sign_in]\ntoken_ttl = \"12h\"\n[github]\nclient_id = \"x\"\nurl = \"https://ghe.example.com/\"\n\
             [[github.allow]]\nteams = [\"acme/bd-admins\"]\nrole = \"admin\"\nkind = \"human\"\n\
             workspaces = [\"proj\", \"other\"]\n[[github.allow]]\norgs = [\"acme\"]\nrole = \"read\"\n",
        );
        assert_eq!(all.token_ttl, Duration::from_secs(12 * 3600));
        let g = all.github.unwrap();
        assert_eq!(g.api_url, "https://ghe.example.com/api/v3", "GitHub Enterprise Server's API");
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
        let no_secret =
            "[github]\nclient_id = \"Iv1.x\"\nprivate_key = \"app.pem\"\n[[github.allow]]\nusers = [\"a\"]\n";
        assert_eq!(parse(no_secret).unwrap().unwrap().oauth, None, "off without [oauth]");
        let github = &no_secret.replace("private_key", "client_secret_file = \"secret\"\nprivate_key");
        let g =
            parse(&format!("{github}[oauth]\nredirect_hosts = [\" ChatGPT.com \", \"claude.ai\", \"chatgpt.com\"]\n"))
                .unwrap()
                .unwrap();
        let o = g.oauth.unwrap();
        assert_eq!(o.redirect_hosts, ["chatgpt.com", "claude.ai"], "lowercased, once each");
        assert!(!o.loopback_redirects);
        let o = parse(&format!("{github}[oauth]\nloopback_redirects = true\n")).unwrap().unwrap().oauth.unwrap();
        assert!(o.redirect_hosts.is_empty() && o.loopback_redirects);

        assert!(error("[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n").contains("need a provider"));
        let no_key = "[github]\nclient_id = \"x\"\nclient_secret_file = \"s\"\n[[github.allow]]\nusers = [\"a\"]\n";
        let e = error(&format!("{no_key}[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n"));
        assert!(e.contains("needs refreshed tokens") && e.contains("private_key"), "{e}");
        assert!(error(&format!("{github}[oauth]\n")).contains("allows no redirect URIs"));
        for bad in
            ["localhost", "127.0.0.1", "*.example.com", "chatgpt.com:443", "-a.com", "a..com", "https://a.com", ""]
        {
            let e = error(&format!("{github}[oauth]\nredirect_hosts = [\"{bad}\"]\n"));
            assert!(e.contains("is not a host name"), "{bad}: {e}");
        }
        assert!(error(&format!("{github}[oauth]\nissuer = \"https://x\"\n")).contains("unknown field"));
        let hosts = "[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n";
        assert!(error(&format!("{no_secret}{hosts}")).contains("github.client_secret_file"));
        assert!(error(github).contains("serves [oauth]'s web sign-in only"));
        let empty = no_secret.replace("private_key", "client_secret_file = \"\"\nprivate_key");
        assert!(error(&format!("{empty}{hosts}")).contains("client_secret_file is empty"));
        assert_eq!(sign_in(&format!("{github}{hosts}")).github.unwrap().client_secret_file, Some("secret".into()));
    }

    #[test]
    fn exact_redirect_uris_allow_those_alone_and_registration_can_be_off() {
        let o = sign_in(
            "[github]\nclient_id = \"x\"\nclient_secret_file = \"s\"\nprivate_key = \"k\"\n[[github.allow]]\nusers = [\"a\"]\n\
             [oauth]\nredirect_uris = [\"https://chatgpt.com/connector_platform_oauth_redirect\"]\nregistration = false\n",
        )
        .oauth
        .unwrap();
        assert!(!o.registration);
        assert!(o.allows_redirect("https://chatgpt.com/connector_platform_oauth_redirect"));
        for other in [
            "https://chatgpt.com/other",
            "https://chatgpt.com/connector_platform_oauth_redirect/x",
            "https://chatgpt.com/connector_platform_oauth_redirect?x=1",
            "https://CHATGPT.com/connector_platform_oauth_redirect",
        ] {
            assert!(!o.allows_redirect(other), "{other}");
        }
        for bad in [
            "http://chatgpt.com/cb",
            "https://chatgpt.com:8443/cb",
            "https://u@chatgpt.com/cb",
            "https://chatgpt.com/cb#f",
        ] {
            let text = format!(
                "[github]\nclient_id = \"x\"\n[[github.allow]]\nusers = [\"a\"]\n[oauth]\nredirect_uris = [\"{bad}\"]\n"
            );
            assert!(error(&text).contains("oauth.redirect_uris"), "{bad}");
        }
    }

    #[test]
    fn redirects_go_to_the_allowed_hosts_and_maybe_this_machine() {
        let hosts = OauthConfig {
            redirect_hosts: vec!["chatgpt.com".into()],
            redirect_uris: vec![],
            loopback_redirects: false,
            registration: true,
        };
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
        let loopback =
            OauthConfig { redirect_hosts: vec![], redirect_uris: vec![], loopback_redirects: true, registration: true };
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

    const TEST_KEY: &str = include_str!("../../tests/fixtures/github-app.pem");

    #[test]
    fn auth_toml_hands_decisions_to_an_authorizer() {
        let base = "[github]\nclient_id = \"Iv1.x\"\n";
        let authorizer = "\n[authorizer]\ncommand = [\"bin/authorize\"]\n";
        let all = sign_in(&format!("{base}{authorizer}"));
        assert!(all.github.as_ref().unwrap().rules.is_empty());
        assert!(all.refreshes("github"), "the authorizer decides again at refreshes: no GitHub App needed");
        let a = all.authorizer.expect("an authorizer");
        assert_eq!(a.caps.max_role, Role::Write);
        assert_eq!(
            sign_in(&format!("{base}{authorizer}refresh_grace = \"4h\"\n")).authorizer.unwrap().refresh_grace,
            Some(Duration::from_secs(4 * 3600))
        );
        for (text, says) in [
            (format!("{base}{authorizer}\n[[github.allow]]\nusers = [\"a\"]\n"), "keep one of them"),
            (authorizer.to_string(), "need a provider"),
            (format!("{base}{authorizer}refresh_grace = \"10m\"\n"), "at least sign_in.token_ttl"),
            (format!("{base}{authorizer}refresh_grace = \"8d\"\n"), "at most sign_in.refresh_idle"),
            (format!("{base}\n[authorizer]\nurl = \"http://authz.example\"\n"), "not an https URL"),
        ] {
            let e = error(&text);
            assert!(e.contains(says), "{text}: {e}");
        }

        // load() reads an HTTPS authorizer's token, relative to the root, and never shows it.
        let dir = tempfile::tempdir().unwrap();
        let https = "\n[authorizer]\nurl = \"https://authz.example/bd\"\ntoken_file = \"authz-token\"\n";
        std::fs::write(dir.path().join(FILE), format!("{base}{https}")).unwrap();
        let e = load(dir.path()).unwrap_err().to_string();
        assert!(e.contains("authz-token"), "{e}");
        std::fs::write(dir.path().join("authz-token"), "s3cret\n").unwrap();
        let all = load(dir.path()).unwrap().unwrap();
        let debug = format!("{:?}", all.authorizer.unwrap());
        assert!(!debug.contains("s3cret"), "{debug}");
    }

    #[test]
    fn auth_toml_sets_up_refreshes_with_a_github_app() {
        let base = "[github]\nclient_id = \"Iv1.x\"\n";
        let rule = "\n[[github.allow]]\nusers = [\"a\"]\n";
        let all = sign_in(&format!("{base}{rule}"));
        let g = all.github.as_ref().unwrap();
        assert_eq!((all.token_ttl, g.private_key.as_ref(), g.app.as_ref()), (DEFAULT_TTL, None, None));
        assert!(all.lifetime(Timestamp::now(), "github").refresh.is_none(), "rules without the App: no refresh");
        let all = sign_in(&format!(
            "[sign_in]\nrefresh_limit = \"14d\"\nrefresh_idle = \"1d\"\n{base}private_key = \"app.pem\"{rule}"
        ));
        assert_eq!(all.github.as_ref().unwrap().private_key.as_deref(), Some(Path::new("app.pem")));
        assert_eq!(
            (all.refresh_limit, all.refresh_idle),
            (Duration::from_secs(14 * 86400), Duration::from_secs(86400))
        );
        assert!(all.refreshes("github") && !all.refreshes("google"), "the App applies GitHub's rules only");
        for (settings, says) in [
            ("[sign_in]\ntoken_ttl = \"10d\"\n", "at most the next"),
            ("[sign_in]\nrefresh_idle = \"60d\"\n", "at most the next"),
            ("[sign_in]\nrefresh_limit = \"400d\"\n", "use 5m to 366d"),
            ("[sign_in]\nttl = \"1h\"\n", "unknown field"),
        ] {
            let e = error(&format!("{settings}{base}{rule}"));
            assert!(e.contains(says), "{settings}: {e}");
        }
        assert!(error(&format!("{base}private_key = \"\"{rule}")).contains("private_key is empty"));
        let e = error(&format!("{base}token_ttl = \"1h\"{rule}"));
        assert!(e.contains("unknown field") && e.contains("are in [sign_in] now"), "{e}");
        assert!(error("[sign_in]\ntoken_ttl = \"1h\"\n").contains("need a provider"));

        // load() reads the key, relative to the root.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), format!("{base}private_key = \"app.pem\"{rule}")).unwrap();
        let e = load(dir.path()).unwrap_err().to_string();
        assert!(e.contains("app.pem") && e.contains(FILE), "{e}");
        std::fs::write(dir.path().join("app.pem"), "not a key").unwrap();
        assert!(load(dir.path()).unwrap_err().to_string().contains("no private key in the file"));
        std::fs::write(dir.path().join("app.pem"), TEST_KEY).unwrap();
        let all = load(dir.path()).unwrap().unwrap();
        let key = all.github.as_ref().unwrap().app.as_ref().expect("loaded");
        assert!(!format!("{key:?}").contains("BEGIN"), "never the key");
        let now = Timestamp::now();
        let life = all.lifetime(now, "github").refresh.unwrap();
        assert_eq!(life, (now.plus(DEFAULT_REFRESH_LIMIT), DEFAULT_REFRESH_IDLE));

        // ... and the client secret.
        let keys = "private_key = \"app.pem\"\nclient_secret_file = \"secret\"";
        let oauth = format!("{base}{keys}{rule}[oauth]\nredirect_hosts = [\"chatgpt.com\"]\n");
        std::fs::write(dir.path().join(FILE), oauth).unwrap();
        assert!(load(dir.path()).unwrap_err().to_string().contains("github.client_secret_file"));
        std::fs::write(dir.path().join("secret"), "two words\n").unwrap();
        assert!(load(dir.path()).unwrap_err().to_string().contains("not a client secret"));
        std::fs::write(dir.path().join("secret"), " s3cret \n").unwrap();
        let all = load(dir.path()).unwrap().unwrap();
        assert_eq!(all.github.as_ref().unwrap().client_secret.as_ref().map(|s| s.0.as_str()), Some("s3cret"));
        assert!(!format!("{all:?}").contains("s3cret"), "never the secret");
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
            (format!("[sign_in]\ntoken_ttl = \"1m\"\n{}", with("", "users = [\"a\"]")), "use 5m to 366d"),
            (format!("[sign_in]\ntoken_ttl = \"400d\"\n{}", with("", "users = [\"a\"]")), "use 5m to 366d"),
            (format!("[sign_in]\ntoken_ttl = \"soon\"\n{}", with("", "users = [\"a\"]")), "token_ttl"),
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
        assert_eq!(unknown, ["partner: GitHub answered 403"], "stopped at the rule it could not decide");
    }

    #[test]
    fn a_rule_github_will_not_decide_stops_the_rules_after_it() {
        // Eve is in both; GitHub will not say for vendor. Were that "no", acme's rule would make her an admin.
        let g = github(
            "[github]\nclient_id = \"x\"\n\
             [[github.allow]]\norgs = [\"vendor\"]\nrole = \"read\"\n\
             [[github.allow]]\norgs = [\"acme\"]\nrole = \"admin\"\n\
             [[github.allow]]\norgs = [\"vendor\"]\nworkspaces = [\"other\"]\n",
        );
        let mut known = Known { member_of: vec!["vendor", "acme"], blocked: vec!["vendor"], asked: Vec::new() };
        let mut unknown = Vec::new();
        let decided = decide(&g, "eve", None, "proj", &mut known, &mut unknown).unwrap();
        assert!(matches!(decided, Decision::Unknown), "not admin by the next rule");
        assert_eq!(known.asked, ["vendor"]);
        // A rule for other workspaces does not stop it, known or not.
        let g = github(
            "[github]\nclient_id = \"x\"\n\
             [[github.allow]]\norgs = [\"vendor\"]\nworkspaces = [\"other\"]\n\
             [[github.allow]]\norgs = [\"acme\"]\n",
        );
        let mut known = Known { member_of: vec!["acme"], blocked: vec!["vendor"], asked: Vec::new() };
        let decided = decide(&g, "eve", None, "proj", &mut known, &mut Vec::new()).unwrap();
        assert_eq!(role_via(decided), Some((Role::Write, "member of acme".into())));
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
