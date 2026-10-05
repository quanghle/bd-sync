//! The authorizer: whether an account that signed in may use a workspace of
//! `bd serve`, and with what access, decided by the admin's own code instead
//! of `auth.toml`'s rules. bd still proves who signed in (the provider's
//! sign-in, and the account bound to its actor); the authorizer only says whether
//! that account gets in, at every sign-in and every refresh:
//!
//! ```toml
//! [authorizer]
//! command = ["bin/authorize", "--org", "acme"]   # run as is, no shell (relative to the root if it has a /)
//! # url = "https://authz.internal/bd"           # or POST to this (http only to this machine)
//! # token_file = "authz-token"                  # sent as a bearer token to url (relative to the root)
//! timeout = "5s"                                # an answer within this, or the sign-in fails (1s to 60s)
//! env = ["GOOGLE_APPLICATION_CREDENTIALS"]      # passed to the command, with PATH, HOME and LANG; nothing else
//! refresh_grace = "4h"                          # while it cannot answer, a refresh keeps the last decision this long
//! max_role = "write"                            # the most it may grant (read, write, admin); default write
//! human = false                                 # whether it may grant kind human (opens human gates)
//! max_claims = 10                               # the most claims its tokens may hold (it may grant fewer)
//! workspaces = ["proj"]                         # the only workspaces it may let anyone into (default all)
//! ```
//!
//! It is asked with one JSON object ([`Request`]: on the command's stdin,
//! or as the POST body) and answers with one ([`Answer`]: on stdout, or as
//! a 200 response). Anything else (a timeout, a failed exit or status, an
//! answer that is not one strict object) fails the sign-in, never admits.
//! A grant beyond the caps denies, and is logged: a broken or compromised
//! authorizer cannot hand out more than `auth.toml` allows.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bd_core::{Error, Timestamp};
use serde::{Deserialize, Serialize};

use crate::auth::{Grant, Kind, Role};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// The largest answer read.
const MAX_ANSWER: u64 = 64 << 10;
/// What of the command's stderr goes to the log.
const MAX_STDERR: usize = 2 << 10;
/// Authorizers asked at once; more are told the server is busy.
const MAX_RUNNING: usize = 8;
/// The longest `via` shown on the consent page.
const MAX_VIA: usize = 100;
/// The longest `reason` logged.
const MAX_REASON: usize = 500;
/// Variables every command gets, from the server's environment, besides `env`.
const PASSED: &[&str] = &["PATH", "HOME", "LANG", "SystemRoot", "windir", "PATHEXT", "TEMP", "TMP", "USERPROFILE"];
/// The version of [`Request`] sent.
const VERSION: u32 = 1;

static RUNNING: AtomicUsize = AtomicUsize::new(0);

/// `[authorizer]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizerDoc {
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    refresh_grace: Option<String>,
    #[serde(default)]
    max_role: Option<Role>,
    #[serde(default)]
    human: bool,
    #[serde(default)]
    max_claims: Option<u32>,
    #[serde(default)]
    workspaces: Vec<String>,
}

/// The admin's authorizer, as `auth.toml` configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorizer {
    pub how: How,
    pub timeout: Duration,
    /// While the authorizer cannot answer, a refresh keeps the access its
    /// sign-in had if that was last decided at most this long ago.
    pub refresh_grace: Option<Duration>,
    pub caps: Caps,
}

/// How the authorizer is asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum How {
    /// Run this, as is: the program and its arguments, and the variables
    /// of the server's environment it gets besides [`PASSED`].
    Command { argv: Vec<String>, env: Vec<String> },
    /// POST to this URL, with the bearer token in `token_file` (read by
    /// [`Authorizer::load_token`]).
    Https { url: String, token_file: Option<PathBuf>, token: Option<Bearer> },
}

/// A bearer token, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Bearer(String);

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bearer(..)")
    }
}

/// The most an authorizer may grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caps {
    pub max_role: Role,
    /// Whether it may grant kind human.
    pub human: bool,
    /// The most claims its tokens may hold; a grant naming none gets this.
    pub max_claims: Option<u32>,
    /// Workspace names, or `*` for every workspace.
    pub workspaces: Vec<String>,
}

/// What the authorizer is asked about: an account that signed in, the
/// workspace it wants, and, at a refresh, what it has now.
#[derive(Debug, Serialize)]
pub struct Request<'a> {
    pub version: u32,
    /// `sign_in` or `refresh`.
    pub event: &'static str,
    pub workspace: &'a str,
    /// The provider the account signed in with: `github`, or an
    /// `[oidc.<name>]` table's name.
    pub provider: &'a str,
    /// Who vouches for the account: the GitHub's URL, or the OIDC issuer.
    pub issuer: &'a str,
    /// The account's id at the provider, which never changes.
    pub subject: String,
    /// Its login now, which may change, and may have been another account's.
    pub login: &'a str,
    /// When the provider created the account, if it says (GitHub).
    pub account_created: Option<String>,
    /// Its email, only if the provider verified it (OIDC, at a sign-in).
    pub email: Option<&'a str>,
    /// All the ID token's claims (OIDC, at a sign-in): groups, tenant and
    /// whatever else the provider puts in.
    pub claims: Option<&'a serde_json::Value>,
    /// The OAuth client signing the account in, if any (an MCP client).
    pub client: Option<&'a str>,
    /// At a refresh: the access the sign-in has now.
    pub current: Option<Current>,
}

/// The access a sign-in has, as [`Request::current`] tells it.
#[derive(Debug, Serialize)]
pub struct Current {
    pub role: Role,
    pub kind: Kind,
    pub max_claims: Option<u32>,
    pub signed_in_at: String,
}

/// What the authorizer answers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    allow: bool,
    /// Default read.
    #[serde(default)]
    role: Option<Role>,
    /// Default agent.
    #[serde(default)]
    kind: Option<Kind>,
    #[serde(default)]
    max_claims: Option<u32>,
    /// What let the account in, shown on the consent page.
    #[serde(default)]
    via: Option<String>,
    /// Why, for the server log only.
    #[serde(default)]
    reason: Option<String>,
}

/// What came of asking.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// In, with this access to the workspace asked about, and what let it in.
    Allow { grant: Grant, via: String },
    /// Out, and why (for the log only).
    Deny { reason: String },
    /// No decision: the sign-in fails, and why goes to the log.
    Unavailable { why: String },
}

/// `[authorizer]` from what `auth.toml` says.
pub(crate) fn parse(doc: AuthorizerDoc) -> std::result::Result<Authorizer, String> {
    let how = match (doc.command, doc.url) {
        (Some(_), Some(_)) => return Err("[authorizer] names both command and url: choose one".into()),
        (None, None) => return Err("[authorizer] needs command or url".into()),
        (Some(argv), None) => {
            if argv.is_empty() || argv[0].trim().is_empty() {
                return Err("authorizer.command is empty: name the program, then its arguments".into());
            }
            if argv.iter().any(|a| a.contains('\0')) {
                return Err("authorizer.command holds a NUL character".into());
            }
            if doc.token_file.is_some() {
                return Err("authorizer.token_file goes with url only: a command reads what it needs itself".into());
            }
            for name in &doc.env {
                let ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !ok {
                    return Err(format!("authorizer.env {name:?} is not a variable name"));
                }
            }
            How::Command { argv, env: doc.env }
        }
        (None, Some(url)) => {
            let url = url.trim().to_string();
            if !(url.starts_with("https://") || loopback_http(&url)) {
                return Err(format!(
                    "authorizer.url {url:?} is not an https URL (http only to 127.0.0.1, [::1] or localhost)"
                ));
            }
            let authority =
                url.split_once("://").map_or("", |(_, rest)| rest.split(['/', '?']).next().unwrap_or_default());
            if url.contains(['#', ' ']) || url.chars().any(char::is_control) || authority.contains('@') {
                return Err(format!("authorizer.url {url:?} is not a plain URL"));
            }
            if !doc.env.is_empty() {
                return Err("authorizer.env goes with command only".into());
            }
            if doc.token_file.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
                return Err("authorizer.token_file is empty: name the file, or leave it out".into());
            }
            How::Https { url, token_file: doc.token_file, token: None }
        }
    };
    let duration =
        |field: &str, raw: &str| bd_core::time::parse_duration(raw).map_err(|e| format!("authorizer.{field}: {e}"));
    let timeout = match &doc.timeout {
        None => DEFAULT_TIMEOUT,
        Some(raw) => {
            let t = duration("timeout", raw)?;
            if !(TIMEOUT_RANGE.0..=TIMEOUT_RANGE.1).contains(&t) {
                return Err(format!("authorizer.timeout {raw:?}: use 1s to 60s"));
            }
            t
        }
    };
    let refresh_grace = doc.refresh_grace.as_deref().map(|raw| duration("refresh_grace", raw)).transpose()?;
    if doc.max_claims == Some(0) {
        return Err("authorizer.max_claims must be at least 1".into());
    }
    let workspaces = crate::auth::workspace_list(&doc.workspaces).map_err(|e| format!("authorizer.workspaces: {e}"))?;
    let caps = Caps {
        max_role: doc.max_role.unwrap_or(Role::Write),
        human: doc.human,
        max_claims: doc.max_claims,
        workspaces,
    };
    Ok(Authorizer { how, timeout, refresh_grace, caps })
}

/// Whether `url` is http to this machine.
fn loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    // `http://127.0.0.1:80@example.com/` is example.com's.
    if authority.contains('@') {
        return false;
    }
    let host = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => &authority[..i],
        _ => authority,
    };
    matches!(host.to_ascii_lowercase().as_str(), "127.0.0.1" | "[::1]" | "localhost")
}

impl Authorizer {
    /// Read the bearer token of an HTTPS authorizer (relative to `root`).
    pub(crate) fn load_token(&mut self, root: &Path) -> std::result::Result<(), String> {
        let How::Https { token_file: Some(file), token, .. } = &mut self.how else { return Ok(()) };
        let path = if file.is_relative() { root.join(file) } else { file.clone() };
        let at = format!("authorizer.token_file {}", path.display());
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{at}: {e}"))?;
        let secret = text.trim();
        if secret.is_empty() || secret.len() > 4096 || !secret.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("{at}: not a token (one line of printable characters)"));
        }
        *token = Some(Bearer(secret.to_string()));
        Ok(())
    }

    /// Ask whether the account in `request` may use its workspace, and with
    /// what access, within the caps. `root` is where a command runs.
    pub fn ask(&self, root: &Path, request: &Request<'_>) -> Outcome {
        if !self.caps.workspaces.iter().any(|w| w == "*" || w == request.workspace) {
            return Outcome::Deny { reason: format!("authorizer.workspaces does not include {}", request.workspace) };
        }
        let Some(_slot) = Slot::take() else {
            return Outcome::Unavailable { why: "too many authorizations under way".into() };
        };
        let body = serde_json::to_vec(request).unwrap_or_default();
        let answered = match &self.how {
            How::Command { argv, env } => run(root, argv, env, &body, self.timeout),
            How::Https { url, token, .. } => post(url, token.as_ref(), &body, self.timeout),
        };
        match answered {
            Ok(bytes) => self.decide(request.workspace, &bytes),
            Err(why) => Outcome::Unavailable { why },
        }
    }

    /// What an answer means, within the caps.
    fn decide(&self, workspace: &str, bytes: &[u8]) -> Outcome {
        let answer: Answer = match serde_json::from_slice(bytes) {
            Ok(a) => a,
            Err(e) => return Outcome::Unavailable { why: format!("its answer is not one valid JSON object: {e}") },
        };
        if !answer.allow {
            let reason = answer.reason.as_deref().map_or("no reason given".into(), |r| clip(r, MAX_REASON));
            return Outcome::Deny { reason };
        }
        let role = answer.role.unwrap_or(Role::Read);
        let kind = answer.kind.unwrap_or(Kind::Agent);
        if answer.max_claims == Some(0) {
            return Outcome::Unavailable { why: "its answer grants max_claims 0".into() };
        }
        let via = match answer.via.filter(|v| !v.trim().is_empty()) {
            None => "the server's authorizer".to_string(),
            Some(via) if crate::oauth_server::clients::shows_plainly(&via, MAX_VIA) => via.trim().to_string(),
            Some(_) => {
                return Outcome::Unavailable {
                    why: format!("its via is longer than {MAX_VIA} characters, empty, or not plain text"),
                };
            }
        };
        if role > self.caps.max_role {
            return Outcome::Deny {
                reason: format!(
                    "it granted role {}, beyond authorizer.max_role {}",
                    role.as_str(),
                    self.caps.max_role.as_str()
                ),
            };
        }
        if kind == Kind::Human && !self.caps.human {
            return Outcome::Deny { reason: "it granted kind human, which authorizer.human does not allow".into() };
        }
        let max_claims = match (answer.max_claims, self.caps.max_claims) {
            (Some(n), Some(cap)) if n > cap => {
                return Outcome::Deny {
                    reason: format!("it granted max_claims {n}, beyond authorizer.max_claims {cap}"),
                };
            }
            (Some(n), _) => Some(n),
            (None, cap) => cap,
        };
        let grant = Grant { role, kind, workspaces: vec![workspace.to_string()], max_claims };
        Outcome::Allow { grant, via }
    }
}

/// `s` cut to `max` characters, for the log, its emails left out: the
/// authorizer is sent the account's email, and its reasons and stderr may
/// repeat it, while the log keeps none.
fn clip(s: &str, max: usize) -> String {
    let s: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let s = without_emails(&s);
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

/// `s` with each word shaped like an email (`<local>@<domain>.<tld>`, words
/// split at spaces, quotes, brackets and punctuation that addresses do not
/// hold) replaced by `<email>`.
fn without_emails(s: &str) -> String {
    let apart = |c: char| c.is_whitespace() || "\"'`<>()[]{},;:=|\\".contains(c);
    let email = |w: &str| {
        let w = w.trim_end_matches(['.', '!', '?']);
        w.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.contains('@') && domain.split('.').filter(|p| !p.is_empty()).count() >= 2
        })
    };
    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if email(word) {
            // Keep the sentence's own end.
            let end = &word[word.trim_end_matches(['.', '!', '?']).len()..];
            out.push_str("<email>");
            out.push_str(end);
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in s.chars() {
        if apart(c) {
            flush(&mut word, &mut out);
            out.push(c);
        } else {
            word.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Run the command with `body` on its stdin: its stdout, if it exits 0
/// within `timeout` with at most [`MAX_ANSWER`] bytes. It runs in a process
/// group of its own (on Unix), which is killed once it has answered or ran
/// out of time, so nothing it started outlives it or keeps bd waiting on
/// its output past the deadline.
fn run(
    root: &Path,
    argv: &[String],
    env: &[String],
    body: &[u8],
    timeout: Duration,
) -> std::result::Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let program = Path::new(&argv[0]);
    let program = match program.is_relative() && program.components().count() > 1 {
        true => root.join(program),
        false => program.to_path_buf(),
    };
    let mut command = Command::new(&program);
    command.args(&argv[1..]).current_dir(root).env_clear();
    for name in PASSED.iter().copied().chain(env.iter().map(String::as_str)) {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().map_err(|e| format!("{} could not be run: {e}", program.display()))?;
    let group = Group(child.id());
    let mut stdin = child.stdin.take().expect("piped");
    let body = body.to_vec();
    // Written and read on threads, so that a command which reads or writes little cannot stall the others; read
    // through channels, so that output a process it started keeps open never holds bd past the deadline.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let mut stdout = child.stdout.take().expect("piped");
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = (&mut stdout).take(MAX_ANSWER + 1).read_to_end(&mut out);
        let _ = out_tx.send(read.map(|_| out));
    });
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    let mut stderr = child.stderr.take().expect("piped");
    std::thread::spawn(move || {
        let mut err = Vec::new();
        let _ = (&mut stderr).take(MAX_STDERR as u64).read_to_end(&mut err);
        let _ = err_tx.send(err);
    });
    let late = || format!("it did not answer within {}", fmt_duration(timeout));
    // Its answer is all there once nothing holds its output open any more (or never, by the deadline).
    let out = out_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    // Whatever it left running goes, answered or not: the group is killed before the command is reaped, so its
    // id still names it, never another process's.
    let status = group.end(&mut child);
    let exited = status.as_ref().is_some_and(|s| s.code().is_some());
    let out = match out {
        Ok(read) => read.map_err(|e| format!("reading its answer: {e}"))?,
        Err(_) if exited => {
            return Err(format!("{}: it exited, but a process it started kept its output open", late()));
        }
        Err(_) => return Err(late()),
    };
    let Some(status) = status else { return Err("waiting for it failed".into()) };
    let err = err_rx.recv_timeout(Duration::from_millis(100)).unwrap_or_default();
    // First: past the limit, it was left writing to a closed pipe, which may be why it failed.
    if out.len() as u64 > MAX_ANSWER {
        return Err(format!("its answer is larger than {} KiB", MAX_ANSWER >> 10));
    }
    if !status.success() {
        let err = String::from_utf8_lossy(&err);
        return Err(format!("it exited with {status}: {}", clip(err.trim(), MAX_STDERR)));
    }
    Ok(out)
}

/// The process group of an authorizer command: its id, the command's own
/// (Unix only: elsewhere the command alone is killed).
struct Group(#[cfg_attr(not(unix), allow(dead_code))] u32);

impl Group {
    /// Kill the command, if it still runs, and on Unix every process left in
    /// its group; then reap the command: how it ended (killed, if it still
    /// ran), if that can be told.
    fn end(&self, child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        #[cfg(unix)]
        if let Ok(id) = i32::try_from(self.0) {
            // SAFETY: kill(2) with a negative pid signals the process group the command leads; it touches no
            // memory of this process.
            unsafe {
                libc::kill(-id, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        child.wait().ok()
    }
}

/// One of the [`MAX_RUNNING`] authorizations under way, given back when
/// dropped, however the asking ends.
struct Slot;

impl Slot {
    fn take() -> Option<Slot> {
        match RUNNING.fetch_add(1, Ordering::SeqCst) < MAX_RUNNING {
            true => Some(Slot),
            false => {
                RUNNING.fetch_sub(1, Ordering::SeqCst);
                None
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// POST `body` to `url`: the answer's body, if it is a 200 within `timeout`
/// of at most [`MAX_ANSWER`] bytes.
fn post(url: &str, token: Option<&Bearer>, body: &[u8], timeout: Duration) -> std::result::Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .https_only(!loopback_http(url))
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(timeout))
        .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut request = agent.post(url).header("content-type", "application/json").header("accept", "application/json");
    if let Some(Bearer(token)) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let mut response = request.send(body).map_err(|e| format!("no answer: {e}"))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!("it answered HTTP {status}"));
    }
    match response.body_mut().with_config().limit(MAX_ANSWER).read_to_vec() {
        Ok(bytes) => Ok(bytes),
        Err(ureq::Error::BodyExceedsLimit(_)) => Err(format!("its answer is larger than {} KiB", MAX_ANSWER >> 10)),
        Err(e) => Err(format!("reading its answer: {e}")),
    }
}

fn fmt_duration(d: Duration) -> String {
    bd_core::time::format_duration_ms(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The access a sign-in has had: what a refresh within `refresh_grace`
/// keeps while the authorizer cannot answer.
impl Authorizer {
    /// The access a sign-in has had, held to the caps as they are now: what
    /// a refresh within `refresh_grace` keeps while the authorizer cannot
    /// answer. A lowered `max_role`, `human` turned off or a smaller
    /// `max_claims` apply to it too.
    pub fn kept(&self, token: &crate::auth::Token) -> Grant {
        let kind = if token.kind == Kind::Human && !self.caps.human { Kind::Agent } else { token.kind };
        let max_claims = match (token.max_claims, self.caps.max_claims) {
            (Some(n), Some(cap)) => Some(n.min(cap)),
            (None, cap) => cap,
            (n, None) => n,
        };
        Grant { role: token.role.min(self.caps.max_role), kind, workspaces: token.workspaces.clone(), max_claims }
    }
}

/// The request about `user` signing in to, or refreshing, `workspace`.
pub fn request<'a>(
    event: &'static str,
    workspace: &'a str,
    user: &'a crate::auth::Identity,
    created: Option<Timestamp>,
    client: Option<&'a str>,
    current: Option<Current>,
    oidc: Option<&'a crate::oidc::Claims>,
) -> Request<'a> {
    Request {
        version: VERSION,
        event,
        workspace,
        provider: &user.provider,
        issuer: &user.issuer,
        subject: user.subject.clone(),
        login: &user.login,
        account_created: created.map(|t| t.to_string()),
        email: oidc.and_then(|c| c.email.as_deref()),
        claims: oidc.map(|c| &c.all),
        client,
        current,
    }
}

/// Why an account (`who`, as messages name it) was not let in, for the
/// person: what the authorizer says stays in the log.
pub fn refused(who: &str, workspace: &str) -> Error {
    Error::Unauthorized(format!("{who} may not use workspace {workspace} on this bd server"))
}

/// Why the authorizer could not say, for the person: busy, for a page
/// that can be loaded again.
pub fn unavailable() -> Error {
    Error::Busy("this bd server could not check the account's access just now; sign in again in a moment".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(toml_text: &str) -> std::result::Result<Authorizer, String> {
        parse(toml::from_str::<AuthorizerDoc>(toml_text).map_err(|e| e.to_string())?)
    }

    fn command(argv: &[&str]) -> Authorizer {
        let mut a = doc(r#"command = ["x"]"#).unwrap();
        a.how = How::Command { argv: argv.iter().map(|s| s.to_string()).collect(), env: vec![] };
        a
    }

    fn user() -> crate::auth::Identity {
        crate::auth::Identity {
            provider: "github".into(),
            issuer: "https://github.com".into(),
            subject: "7".into(),
            login: "alice".into(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn nothing_a_command_starts_outlives_it_or_holds_bd_past_its_time() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("authorize");
        let mut a = command(&["./authorize"]);
        a.timeout = Duration::from_secs(1);
        let user = user();
        let request = request("sign_in", "proj", &user, None, None, None, None);
        let alive = |dir: &Path| {
            let pid = std::fs::read_to_string(dir.join("bg.pid")).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            Command::new("kill").args(["-0", pid.trim()]).stderr(Stdio::null()).status().unwrap().success()
        };
        // A process it started keeps its output open: no answer, by the deadline, and that process is killed.
        let held = "#!/bin/sh\ncat >/dev/null\nsleep 30 &\necho $! > bg.pid\nprintf '{\"allow\":true}'\n";
        std::fs::write(&script, held).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let at = Instant::now();
        let Outcome::Unavailable { why } = a.ask(dir.path(), &request) else { panic!("decided") };
        assert!(at.elapsed() < Duration::from_secs(3), "{:?}", at.elapsed());
        assert!(why.contains("kept its output open"), "{why}");
        assert!(!alive(dir.path()), "killed with its group");
        // One that lets go of the output: the answer counts, and what it left running is killed.
        let detached =
            "#!/bin/sh\ncat >/dev/null\nsleep 30 >/dev/null 2>&1 &\necho $! > bg.pid\nprintf '{\"allow\":true}'\n";
        std::fs::write(&script, detached).unwrap();
        assert!(matches!(a.ask(dir.path(), &request), Outcome::Allow { .. }));
        assert!(!alive(dir.path()), "killed with its group");
    }

    #[test]
    fn access_kept_through_an_outage_is_held_to_the_caps_now() {
        let mut a = command(&["x"]);
        a.caps.max_claims = Some(3);
        let mut token = crate::auth::Token {
            id: "i".into(),
            name: "n".into(),
            actor: "alice".into(),
            role: Role::Admin,
            kind: Kind::Human,
            workspaces: vec!["proj".into()],
            sha256: String::new(),
            created_at: String::new(),
            revoked_at: None,
            expires_at: None,
            identity: None,
            max_claims: Some(10),
            refresh: None,
            resource: None,
            client: None,
        };
        assert_eq!(
            a.kept(&token),
            Grant { role: Role::Write, kind: Kind::Agent, workspaces: vec!["proj".into()], max_claims: Some(3) }
        );
        (token.role, token.kind, token.max_claims) = (Role::Read, Kind::Agent, None);
        assert_eq!(a.kept(&token).max_claims, Some(3), "the cap applies to a grant naming none");
    }

    #[test]
    fn the_table_is_checked() {
        let a = doc(r#"command = ["bin/authorize", "--org", "acme"]"#).unwrap();
        assert_eq!(a.timeout, DEFAULT_TIMEOUT);
        assert_eq!(
            a.caps,
            Caps { max_role: Role::Write, human: false, max_claims: None, workspaces: vec!["*".into()] }
        );
        let a =
            doc("url = \"https://authz.example/bd\"\ntoken_file = \"t\"\nmax_role = \"admin\"\nhuman = true").unwrap();
        assert!(matches!(a.how, How::Https { .. }));
        assert_eq!((a.caps.max_role, a.caps.human), (Role::Admin, true));
        assert!(doc(r#"url = "http://127.0.0.1:8080/authz""#).is_ok());
        for (bad, says) in [
            ("command = [\"x\"]\nurl = \"https://a.example\"", "choose one"),
            ("timeout = \"5s\"", "needs command or url"),
            ("command = []", "empty"),
            ("url = \"http://authz.example\"", "not an https URL"),
            ("url = \"http://127.0.0.1:80@authz.example/x\"", "not an https URL"),
            ("url = \"https://u:p@authz.example/x\"", "not a plain URL"),
            ("command = [\"x\"]\ntoken_file = \"t\"", "url only"),
            ("url = \"https://a.example\"\nenv = [\"X\"]", "command only"),
            ("command = [\"x\"]\nenv = [\"A=B\"]", "not a variable name"),
            ("command = [\"x\"]\ntimeout = \"2m\"", "1s to 60s"),
            ("command = [\"x\"]\nmax_claims = 0", "at least 1"),
            ("command = [\"x\"]\nworkspaces = [\"a b\"]", "authorizer.workspaces"),
            ("command = [\"x\"]\nshell = true", "unknown field"),
        ] {
            let e = doc(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    #[test]
    fn logged_text_leaves_emails_out() {
        assert_eq!(
            clip("denied alice@example.com (\"bob.smith+bd@mail.example.org\"); see admin@x.io.", 500),
            "denied <email> (\"<email>\"); see <email>."
        );
        assert_eq!(clip("user@localhost and @handle and a@b", 500), "user@localhost and @handle and a@b");
        assert_eq!(clip("email=carol@example.com\nnext", 500), "email=<email> next");
        assert_eq!(clip("aaaa x@y.zz", 6), "aaaa <…");
    }

    #[test]
    fn answers_are_held_to_the_caps() {
        let mut a = command(&["x"]);
        a.caps.max_claims = Some(5);
        let decide = |a: &Authorizer, json: &str| a.decide("proj", json.as_bytes());
        let grant = |role, kind, max_claims| Grant { role, kind, workspaces: vec!["proj".into()], max_claims };
        assert_eq!(
            decide(&a, r#"{"allow":true}"#),
            Outcome::Allow { grant: grant(Role::Read, Kind::Agent, Some(5)), via: "the server's authorizer".into() }
        );
        assert_eq!(
            decide(&a, r#"{"allow":true,"role":"write","max_claims":2,"via":"member of bd-users"}"#),
            Outcome::Allow { grant: grant(Role::Write, Kind::Agent, Some(2)), via: "member of bd-users".into() }
        );
        assert_eq!(
            decide(&a, r#"{"allow":false,"reason":"not in bd-users"}"#),
            Outcome::Deny { reason: "not in bd-users".into() }
        );
        for beyond in
            [r#"{"allow":true,"role":"admin"}"#, r#"{"allow":true,"kind":"human"}"#, r#"{"allow":true,"max_claims":6}"#]
        {
            assert!(matches!(decide(&a, beyond), Outcome::Deny { .. }), "{beyond}");
        }
        for bad in [
            "",
            "{}",
            r#"{"allow":"yes"}"#,
            r#"{"allow":true,"role":"owner"}"#,
            r#"{"allow":true,"workspaces":["*"]}"#,
            r#"{"allow":true} {"allow":true}"#,
            r#"{"allow":true,"max_claims":0}"#,
            "{\"allow\":true,\"via\":\"Chat\\u202eTPG\"}",
        ] {
            assert!(matches!(decide(&a, bad), Outcome::Unavailable { .. }), "{bad}");
        }
        a.caps.workspaces = vec!["other".into()];
        let user = user();
        let request = request("sign_in", "proj", &user, None, None, None, None);
        assert!(matches!(a.ask(Path::new("."), &request), Outcome::Deny { .. }), "not asked beyond its workspaces");
    }

    #[cfg(unix)]
    #[test]
    fn a_command_is_asked_on_stdin_and_answers_on_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("authorize");
        // Keep the request for the test to read, and answer with a variable of the environment as `via`.
        std::fs::write(
            &script,
            "#!/bin/sh\ncat > request.json\nprintf '{\"allow\":true,\"role\":\"write\",\"via\":\"%s\"}' \"${CARGO_PKG_NAME}\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut a = command(&["./authorize"]);
        let user = user();
        let request =
            request("sign_in", "proj", &user, None, Some("https://chatgpt.com/oauth/client.json"), None, None);
        // Variables of the server's environment not named in env never reach it (cargo sets this one for tests).
        let Outcome::Allow { via, .. } = a.ask(dir.path(), &request) else { panic!("not allowed") };
        assert_eq!(via, "the server's authorizer", "not passed, so empty: an empty via is no via");
        let sent: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("request.json")).unwrap()).unwrap();
        assert_eq!(sent["event"], "sign_in");
        assert_eq!(sent["subject"], "7");
        assert_eq!(sent["login"], "alice");
        assert_eq!(sent["client"], "https://chatgpt.com/oauth/client.json");
        if let (How::Command { env, .. }, Some(name)) = (&mut a.how, std::env::var("CARGO_PKG_NAME").ok()) {
            env.push("CARGO_PKG_NAME".into());
            let Outcome::Allow { via, .. } = a.ask(dir.path(), &request) else { panic!("not allowed") };
            assert_eq!(via, name, "passed when named");
        }

        for (body, says) in [
            ("exit 3", "exited with"),
            ("sleep 5", "did not answer within"),
            ("echo not json", "not one valid JSON object"),
            ("head -c 70000 /dev/zero", "larger than"),
        ] {
            std::fs::write(&script, format!("#!/bin/sh\ncat >/dev/null\n{body}\n")).unwrap();
            let mut quick = command(&["./authorize"]);
            quick.timeout = Duration::from_millis(500);
            let Outcome::Unavailable { why } = quick.ask(dir.path(), &request) else { panic!("{body}: decided") };
            assert!(why.contains(says), "{body}: {why}");
        }
        let missing = command(&["./nowhere"]);
        assert!(matches!(missing.ask(dir.path(), &request), Outcome::Unavailable { .. }));
    }

    #[test]
    fn an_https_authorizer_is_posted_to() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/authz", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for answer in [
                ("200 OK", r#"{"allow":true,"role":"write","via":"member of bd-users"}"#),
                ("200 OK", r#"{"allow":false}"#),
                ("500 Internal Server Error", ""),
                ("302 Found", ""),
            ] {
                let (mut conn, _) = listener.accept().unwrap();
                // The headers, then as much body as they say.
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = conn.read(&mut buf).unwrap();
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
                    let Some(end) = text.find("\r\n\r\n") else { continue };
                    let length = text
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if n == 0 || got.len() >= end + 4 + length {
                        break;
                    }
                }
                seen.push(String::from_utf8_lossy(&got).to_string());
                let response = format!(
                    "HTTP/1.1 {}\r\ncontent-length: {}\r\nlocation: http://127.0.0.1:9/\r\nconnection: close\r\n\r\n{}",
                    answer.0,
                    answer.1.len(),
                    answer.1
                );
                conn.write_all(response.as_bytes()).unwrap();
            }
            seen
        });
        let mut a = doc(&format!("url = {url:?}")).unwrap();
        if let How::Https { token, .. } = &mut a.how {
            *token = Some(Bearer("s3cret".into()));
        }
        let user = user();
        let request = request("refresh", "proj", &user, None, None, None, None);
        assert!(matches!(a.ask(Path::new("."), &request), Outcome::Allow { .. }));
        assert!(matches!(a.ask(Path::new("."), &request), Outcome::Deny { .. }));
        assert!(matches!(a.ask(Path::new("."), &request), Outcome::Unavailable { .. }), "a 500");
        assert!(matches!(a.ask(Path::new("."), &request), Outcome::Unavailable { .. }), "a redirect is not followed");
        let seen = server.join().unwrap();
        let first = seen[0].to_ascii_lowercase();
        assert!(first.starts_with("post /authz "), "{first}");
        assert!(first.contains("authorization: bearer s3cret"), "{first}");
        assert!(first.contains("\"event\":\"refresh\""), "{first}");
    }
}
