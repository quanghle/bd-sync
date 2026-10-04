//! The authorization endpoint (OAuth 2.1 authorization code with PKCE),
//! where people let an MCP client use a workspace for them, signing in with
//! GitHub's web flow:
//!
//! 1. `GET <issuer>/oauth/authorize` ([`begin`]): the client and its
//!    redirect URI are checked first, and refused on a page, never by a
//!    redirect (RFC 6749 section 4.1.2.1); then the other parameters, whose
//!    errors go back to the client with `iss` (RFC 9207). The browser goes
//!    on to GitHub with a PKCE challenge of this server's own.
//! 2. `GET <issuer>/oauth/github/callback` ([`callback`]): GitHub's code is
//!    exchanged for the account, and the rules of `auth.toml` decide what it
//!    may do in the workspace the client asked for (`oauth/`). A consent
//!    page shows what the client would get.
//! 3. `POST <issuer>/oauth/consent` ([`decide`]): approved, the client gets
//!    an authorization code, redeemed at the token endpoint with its PKCE
//!    verifier; denied, an `access_denied` error.
//!
//! Each step is bound to the browser that started it by a cookie, and kept
//! in memory for minutes ([`Flows`]): a restart ends authorizations under way.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::Error;
use sha2::{Digest, Sha256};

use super::cimd::Documents;
use super::clients::{self, Client};
use super::pages::{self, Page};
use super::{CHOOSE, CONSENT, form};
use crate::auth;
use crate::mcp::http as mcp_http;
use crate::oauth::{self, Admitted, OauthConfig};

/// The cookie binding an authorization's steps to one browser.
pub const COOKIE: &str = "bd_oauth";
/// The cookie's name on an `https` issuer: browsers keep a `__Secure-`
/// cookie only if a secure page set it with `Secure`, so a page of a sibling
/// host on plain http cannot plant one.
const SECURE_COOKIE: &str = "__Secure-bd_oauth";
/// How long people have to sign in at GitHub, and then to decide.
const STEP_TTL: Duration = Duration::from_secs(10 * 60);
/// How long an authorization code may wait to be redeemed.
const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Authorizations kept at the steps the server keeps (consents, codes),
/// which only people the rules let in reach: past it, the oldest go. The
/// steps before (choosing a provider, signing in there), which anyone may
/// start, keep nothing on the server ([`Pending`]).
const MAX_FLOWS: usize = 1024;
/// The longest sealed flow a cookie carries (browsers keep 4096 bytes).
const MAX_SEALED: usize = 3800;
/// The longest `state` a client may send, which comes back in redirects.
const MAX_STATE: usize = 1024;

/// What an authorization step needs of the server.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub issuer: &'a str,
    pub documents: &'a Documents,
    pub flows: &'a Mutex<Flows>,
    /// Whether the server has this workspace: told only to accounts the
    /// rules let in, as the resource metadata tells no one.
    pub workspace_exists: &'a dyn Fn(&str) -> bool,
}

/// Where a step sends the browser.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// On to this URL (302 after a GET, 303 after a POST).
    Redirect(String),
    /// A page, which ends the step.
    Page(Page),
}

/// An authorization request, checked.
#[derive(Clone, Debug)]
pub struct Authorization {
    pub client: Client,
    pub redirect_uri: String,
    pub state: Option<String>,
    /// The client's PKCE challenge (S256).
    pub challenge: String,
    /// The MCP endpoint the client asked for (RFC 8707), and its workspace.
    pub resource: String,
    pub workspace: String,
}

impl Authorization {
    /// The client's redirect URI with an error.
    fn error_url(&self, issuer: &str, error: &str, description: &str) -> String {
        answer_url(
            &self.redirect_uri,
            self.state.as_deref(),
            issuer,
            &[("error", error), ("error_description", description)],
        )
    }
}

/// An authorization code, issued when someone approved a client.
#[derive(Clone, Debug)]
pub struct Code {
    pub client_id: String,
    pub redirect_uri: String,
    /// The PKCE challenge the code is redeemed with the verifier of.
    pub challenge: String,
    /// The MCP endpoint it is for: its tokens work there only.
    pub resource: String,
    /// The account, and what the rules let it do in the workspace.
    pub admitted: Admitted,
    /// The actor its tokens would get, as the consent page showed.
    pub actor: String,
}

/// An authorization before anyone signed in: choosing a provider, then
/// signing in there. Anyone may start one, so the server keeps none: it is
/// sealed ([`Sealer`]) into what the browser brings back, the link it
/// follows to choose, then a cookie of its own while at the provider, and
/// the client's request is checked again at each step.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Pending {
    /// The client's authorization request, as it sent it.
    query: String,
    /// The hash of the browser's cookie.
    browser: String,
    /// Until when it may go on (milliseconds since the epoch).
    until: i64,
    /// At a provider: its name (`github`, or an `[oidc.<name>]`), the
    /// `state` it was sent, and this server's PKCE verifier and nonce there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<AtProvider>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct AtProvider {
    provider: String,
    state: String,
    verifier: String,
    nonce: String,
}

/// Seals what the browser carries between steps (ChaCha20-Poly1305, a key
/// of this process's): what it brings back is what this server gave it,
/// unread and unchanged, for the step it was given for.
pub struct Sealer(ring::aead::LessSafeKey);

impl Sealer {
    fn new() -> Sealer {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("the system's random number generator");
        let key = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).expect("a 32-byte key");
        Sealer(ring::aead::LessSafeKey::new(key))
    }

    /// `value`, sealed for `step`: base64url of a random nonce and the ciphertext.
    fn seal(&self, step: &str, value: &Pending) -> Result<String, Error> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let mut data = serde_json::to_vec(value)?;
        let aad = ring::aead::Aad::from(step.as_bytes());
        self.0
            .seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce), aad, &mut data)
            .map_err(|_| Error::Io(std::io::Error::other("sealing a flow failed")))?;
        Ok(URL_SAFE_NO_PAD.encode([&nonce[..], &data].concat()))
    }

    /// What [`Sealer::seal`] sealed for `step`, if `sealed` is that.
    fn open(&self, step: &str, sealed: &str) -> Option<Pending> {
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let (nonce, data) = bytes.split_at_checked(12)?;
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut data = data.to_vec();
        let plain = self.0.open_in_place(nonce, ring::aead::Aad::from(step.as_bytes()), &mut data).ok()?;
        serde_json::from_slice(plain).ok()
    }
}

/// The steps a [`Pending`] is sealed for.
const CHOOSING: &str = "choose";
const AT_PROVIDER: &str = "provider";

fn now_millis() -> i64 {
    bd_core::Timestamp::now().millis()
}

/// Waiting for a decision on the consent page.
struct Consent {
    request: Authorization,
    admitted: Admitted,
    actor: String,
    /// The hash of the value of its own cookie ([`consent_cookie`]).
    browser: String,
    /// What names its cookie.
    cookie: String,
}

/// Authorizations under way, by the hash of their secret at each step
/// (`state` at GitHub, the consent id, the code); each taken once.
pub struct Flows {
    sealer: Sealer,
    consents: Kept<Consent>,
    codes: Kept<Code>,
    /// Codes redeemed, for [`CODE_TTL`] after: one sent again revokes the
    /// token it issued (RFC 6749 section 4.1.2).
    spent: Kept<Spent>,
}

/// A code redeemed.
struct Spent {
    /// Its client and PKCE challenge: only a client proving them by sending
    /// it again has its token revoked.
    client_id: String,
    challenge: String,
    /// The id of the token it issued, once issued.
    token: Option<String>,
    /// Whether it was sent again.
    again: bool,
    /// When the code would have expired, had it not been redeemed.
    until: Instant,
}

/// What a code sent to the token endpoint is.
#[derive(Debug)]
pub enum Redeemed {
    /// Not redeemed before: what it stands for.
    Fresh(Box<Code>),
    /// Redeemed already, and the id of the token it issued, if it did yet.
    Again(Option<String>),
    /// Unknown, or expired.
    Unknown,
}

impl Default for Flows {
    fn default() -> Flows {
        Flows {
            sealer: Sealer::new(),
            consents: Kept::new(STEP_TTL),
            codes: Kept::new(CODE_TTL),
            spent: Kept::new(CODE_TTL),
        }
    }
}

impl Flows {
    /// Redeem `code`: what it stands for the first time, if it has not
    /// expired; after that, the token it issued.
    pub fn redeem(&mut self, code: &str, client_id: &str, verifier: &str) -> Redeemed {
        let key = auth::hash(code);
        if let Some((until, found)) = self.codes.take_entry(&key) {
            let (client_id, challenge) = (found.client_id.clone(), found.challenge.clone());
            self.spent.put(key, Spent { client_id, challenge, token: None, again: false, until });
            return Redeemed::Fresh(Box::new(found));
        }
        match self.spent.get_mut(&key) {
            // Its own client sending it again (RFC 6749 section 4.1.2): whoever redeemed it first is not to be trusted.
            Some(spent) if spent.client_id == client_id && s256(verifier) == spent.challenge => {
                spent.again = true;
                Redeemed::Again(spent.token.clone())
            }
            // Anyone else who saw the code may not end the session it started.
            Some(_) => Redeemed::Again(None),
            None => Redeemed::Unknown,
        }
    }

    /// Undo [`Flows::redeem`] of `code`, which stands for `found`, when
    /// it issued no token: it can be redeemed again until it expires, unless
    /// it was sent again meanwhile.
    pub fn unredeem(&mut self, code: &str, found: Code) {
        let key = auth::hash(code);
        let Some(spent) = self.spent.get_mut(&key) else { return };
        if spent.again || spent.token.is_some() {
            return;
        }
        let until = spent.until;
        self.spent.map.remove(&key);
        if until > Instant::now() {
            self.codes.put_until(key, until, found);
        }
    }

    /// Record that `code` issued the token `id`: whether the code was sent
    /// again meanwhile, so that the token must go.
    pub fn issued(&mut self, code: &str, id: &str) -> bool {
        match self.spent.get_mut(&auth::hash(code)) {
            Some(spent) => {
                spent.token = Some(id.to_string());
                spent.again
            }
            None => false,
        }
    }
}

/// Values that expire, at most [`MAX_FLOWS`] of them.
struct Kept<T> {
    ttl: Duration,
    map: HashMap<String, (Instant, T)>,
}

impl<T> Kept<T> {
    fn new(ttl: Duration) -> Kept<T> {
        Kept { ttl, map: HashMap::new() }
    }

    fn put(&mut self, key: String, value: T) {
        self.put_until(key, Instant::now() + self.ttl, value);
    }

    /// [`Kept::put`], expiring at `until`.
    fn put_until(&mut self, key: String, until: Instant, value: T) {
        let now = Instant::now();
        if self.map.len() >= MAX_FLOWS {
            self.map.retain(|_, (until, _)| *until > now);
        }
        if self.map.len() >= MAX_FLOWS {
            let oldest = self.map.iter().min_by_key(|(_, (until, _))| *until).map(|(k, _)| k.clone());
            self.map.remove(&oldest.unwrap_or_default());
        }
        self.map.insert(key, (until, value));
    }

    fn take(&mut self, key: &str) -> Option<T> {
        self.take_entry(key).map(|(_, value)| value)
    }

    /// [`Kept::take`], with when it would have expired.
    fn take_entry(&mut self, key: &str) -> Option<(Instant, T)> {
        let (until, value) = self.map.remove(key)?;
        (until > Instant::now()).then_some((until, value))
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        let now = Instant::now();
        self.map.get_mut(key).filter(|(until, _)| *until > now).map(|(_, value)| value)
    }
}

pub fn lock(flows: &Mutex<Flows>) -> std::sync::MutexGuard<'_, Flows> {
    flows.lock().unwrap_or_else(|e| e.into_inner())
}

/// The S256 PKCE challenge of `verifier` (RFC 7636 section 4.2).
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The cookie's name for `issuer`: prefixed where it can be `Secure`.
fn cookie_name(issuer: &str) -> &'static str {
    if issuer.starts_with("https://") { SECURE_COOKIE } else { COOKIE }
}

/// The browser's cookie for `issuer` in a `Cookie` header, if well-formed;
/// on an `https` issuer, only the prefixed one.
pub fn cookie<'h>(issuer: &str, header: &'h str) -> Option<&'h str> {
    let wanted = cookie_name(issuer);
    header
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value giving the browser `value`, sent back to the
/// authorization server's endpoints only, and with top-level navigations
/// from GitHub. It lasts both steps: signing in at GitHub, then deciding.
/// The name of the cookie that binds one consent to the browser that signed
/// in for it: its own, so that sign-ins under way in other tabs keep theirs.
fn consent_cookie_name(issuer: &str, suffix: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_consent_{suffix}")
}

/// The value of consent cookie `suffix` in the browser's `Cookie` headers
/// (joined with `;`), if well-formed.
pub fn consent_cookie<'h>(issuer: &str, headers: &'h str, suffix: &str) -> Option<&'h str> {
    let wanted = consent_cookie_name(issuer, suffix);
    headers
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value binding a consent to this browser: sent back to
/// the consent endpoint only, and for as long as the consent waits.
fn set_consent_cookie(issuer: &str, suffix: &str, value: &str) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}{CONSENT}", path_of(issuer));
    let name = consent_cookie_name(issuer, suffix);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", STEP_TTL.as_secs())
}

pub fn set_cookie(issuer: &str, value: &str) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    let name = cookie_name(issuer);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", 2 * STEP_TTL.as_secs())
}

/// `d` in words for a person: whole days, hours or minutes.
fn in_words(d: Duration) -> String {
    let secs = d.as_secs();
    let (n, unit) = if secs >= 86_400 && secs % 86_400 == 0 {
        (secs / 86_400, "day")
    } else if secs >= 3_600 && secs % 3_600 == 0 {
        (secs / 3_600, "hour")
    } else {
        (secs.div_ceil(60).max(1), "minute")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// `scheme://authority` of a URL.
pub fn origin(url: &str) -> &str {
    let start = url.find("://").map_or(0, |i| i + 3);
    let end = url[start..].find(['/', '?', '#']).map_or(url.len(), |i| start + i);
    &url[..end]
}

fn path_of(url: &str) -> &str {
    &url[origin(url).len()..]
}

fn host_of(url: &str) -> &str {
    let o = origin(url);
    o.find("://").map_or(o, |i| &o[i + 3..])
}

/// `redirect_uri` with `pairs`, `state` and `iss` added to its query.
fn answer_url(redirect_uri: &str, state: Option<&str>, issuer: &str, pairs: &[(&str, &str)]) -> String {
    let mut all = pairs.to_vec();
    if let Some(state) = state {
        all.push(("state", state));
    }
    all.push(("iss", issuer));
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{sep}{}", form::encode(&all))
}

/// A page for something that went wrong here: the details go to the log.
fn internal(e: &Error, doing: &str) -> Answer {
    tracing::error!(target: "bd::serve", error = %e, "{doing}");
    let why = "The server ran into a problem. Try again later.";
    Answer::Page(pages::refusal(500, "Something went wrong", why, None))
}

/// Why a refusal page shows when the server takes no applications.
const NO_APPS: &str = "This server doesn't accept connections from applications.";

/// Why a refusal page shows for a request the application got wrong. Pages
/// never name parameters, limits or the server's setup: what went wrong in
/// detail is for the log.
const MALFORMED: &str = "The application sent a request this server can't use. Start again from the application.";

fn refused(status: u16, why: &str) -> Answer {
    Answer::Page(pages::refusal(status, "Couldn't connect the application", why, None))
}

/// The parameters of an authorization request, before its client is known.
#[derive(Debug, PartialEq, Eq)]
struct Params {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    /// The others, by name; the first given more than once, if any.
    rest: HashMap<String, String>,
    repeated: Option<String>,
}

/// The parameters of `query`; refused on a page when the client cannot be
/// told (no client or redirect URI, or an unusable `state`).
fn parse(query: &str) -> Result<Params, Answer> {
    let Some(pairs) = form::decode(query) else {
        return Err(refused(400, MALFORMED));
    };
    let mut rest = HashMap::new();
    let mut repeated = None;
    let seen = |name: &str| pairs.iter().filter(|(k, _)| k == name).count();
    for name in ["client_id", "redirect_uri", "state"] {
        if seen(name) > 1 {
            return Err(refused(400, MALFORMED));
        }
    }
    let one = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let (Some(client_id), Some(redirect_uri)) = (one("client_id"), one("redirect_uri")) else {
        return Err(refused(400, MALFORMED));
    };
    let state = one("state");
    if state.as_ref().is_some_and(|s| s.len() > MAX_STATE) {
        return Err(refused(400, MALFORMED));
    }
    for (k, v) in &pairs {
        if matches!(k.as_str(), "client_id" | "redirect_uri" | "state") {
            continue;
        }
        if rest.insert(k.clone(), v.clone()).is_some() && repeated.is_none() {
            repeated = Some(k.clone());
        }
    }
    Ok(Params { client_id, redirect_uri, state, rest, repeated })
}

/// The authorization `params` ask for, from `client`: refused on a page if
/// it may not be sent back to the redirect URI, else with an error at it.
fn check(params: Params, client: Client, oauth: &OauthConfig, issuer: &str) -> Result<Authorization, Answer> {
    if !client.redirects_to(&params.redirect_uri, oauth) {
        let why = "The application asked to send you somewhere it isn't allowed to.";
        return Err(refused(400, why));
    }
    let error = |error: &str, description: &str| {
        let pairs = [("error", error), ("error_description", description)];
        Err(Answer::Redirect(answer_url(&params.redirect_uri, params.state.as_deref(), issuer, &pairs)))
    };
    if let Some(name) = &params.repeated {
        return error("invalid_request", &format!("{name} given more than once"));
    }
    let get = |name: &str| params.rest.get(name).map(String::as_str);
    match get("response_type") {
        Some("code") => {}
        None => return error("invalid_request", "response_type is missing"),
        Some(_) => return error("unsupported_response_type", "only the code response type is supported"),
    }
    if get("code_challenge_method") != Some("S256") {
        return error("invalid_request", "PKCE with code_challenge_method S256 is required");
    }
    let Some(challenge) = get("code_challenge").filter(|c| valid_challenge(c)) else {
        return error("invalid_request", "code_challenge must be an S256 challenge (43 base64url characters)");
    };
    let Some(resource) = get("resource") else {
        return error("invalid_request", "resource is required: the URL of the MCP endpoint (RFC 8707)");
    };
    let workspace = match mcp_http::resource_url(resource) {
        Ok((url, name)) if url == mcp_http::resource(issuer, &name) => name,
        _ => return error("invalid_target", "resource is not an MCP endpoint of this bd server"),
    };
    Ok(Authorization {
        challenge: challenge.to_string(),
        resource: mcp_http::resource(issuer, &workspace),
        workspace,
        redirect_uri: params.redirect_uri,
        state: params.state,
        client,
    })
}

fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The authorization request `query`, checked: its client found, its
/// redirect URI and parameters as `[oauth]` allows. At each step before a
/// sign-in, as no step keeps it.
fn request_of(cx: &Ctx<'_>, oauth_config: &OauthConfig, query: &str) -> Result<Authorization, Answer> {
    let params = parse(query)?;
    let client = match clients::lookup(cx.root, cx.documents, &params.client_id) {
        Ok(c) => c,
        Err(Error::Invalid(why) | Error::Remote(why)) => {
            tracing::info!(target: "bd::serve", client = %params.client_id, error = %why, "OAuth client refused");
            return Err(refused(400, "This application isn't set up to connect to this server."));
        }
        Err(Error::Busy(_)) => return Err(refused(503, "The server is busy. Try again in a moment.")),
        Err(e) => return Err(internal(&e, "looking up an OAuth client")),
    };
    check(params, client, oauth_config, cx.issuer)
}

/// Sign-in settings with `[oauth]`, or the page to answer with.
fn oauth_settings(cx: &Ctx<'_>) -> Result<(oauth::SignIn, OauthConfig), Answer> {
    match oauth::load(cx.root) {
        Ok(Some(g)) => match g.oauth.clone() {
            Some(o) => Ok((g, o)),
            None => Err(refused(404, NO_APPS)),
        },
        Ok(None) => Err(refused(404, NO_APPS)),
        Err(e) => Err(internal(&e, "reading auth.toml for an authorization")),
    }
}

/// `GET <issuer>/oauth/authorize?<query>`: check the request, and send the
/// browser to the provider to sign in, or to a page choosing one. `browser`
/// is its cookie, if it has one; the `Set-Cookie` values to answer with
/// come back with the answer.
pub fn begin(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> (Answer, Vec<String>) {
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let request = match request_of(cx, &oauth_config, query) {
        Ok(r) => r,
        Err(answer) => return (answer, Vec::new()),
    };
    let browser = match browser {
        Some(b) => b.to_string(),
        None => match auth::random_hex(32) {
            Ok(b) => b,
            Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
        },
    };
    let providers = sign_in.browser_providers();
    match providers.as_slice() {
        [] => (refused(404, NO_APPS), Vec::new()),
        [(provider, _)] => start(cx, &sign_in, request, query, provider, &browser),
        several => {
            let pending = Pending { query: query.to_string(), browser: auth::hash(&browser), until: until(), at: None };
            let flow = match lock(cx.flows).sealer.seal(CHOOSING, &pending) {
                Ok(f) => f,
                Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
            };
            let client = client_name(&request.client);
            let options: Vec<(String, String)> = several
                .iter()
                .map(|(name, label)| {
                    let query = form::encode(&[("flow", flow.as_str()), ("provider", name)]);
                    (label.to_string(), format!("{}{CHOOSE}?{query}", cx.issuer))
                })
                .collect();
            (Answer::Page(pages::choose(&client, &options)), vec![set_cookie(cx.issuer, &browser)])
        }
    }
}

/// When a step started now must be done by.
fn until() -> i64 {
    now_millis() + i64::try_from(STEP_TTL.as_millis()).unwrap_or(i64::MAX)
}

/// `GET <issuer>/oauth/choose?flow=<sealed>&provider=<name>`: the person
/// chose a provider on the page [`begin`] showed; on to it.
pub fn choose(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> (Answer, Vec<String>) {
    let pairs = form::decode(query).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let pending = get("flow").and_then(|flow| lock(cx.flows).sealer.open(CHOOSING, flow));
    let Some(pending) = pending.filter(|p| p.until > now_millis()) else {
        return (refused(400, "This sign-in has expired. Start again from the application."), Vec::new());
    };
    let Some(browser) = browser.filter(|b| auth::hash(b) == pending.browser) else {
        return (
            refused(400, "This sign-in started in a different browser. Start again from the application."),
            Vec::new(),
        );
    };
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let offered = sign_in.browser_providers();
    let Some((provider, _)) = offered.iter().find(|(name, _)| Some(*name) == get("provider")) else {
        return (refused(400, MALFORMED), Vec::new());
    };
    let request = match request_of(cx, &oauth_config, &pending.query) {
        Ok(r) => r,
        Err(answer) => return (answer, Vec::new()),
    };
    start(cx, &sign_in, request, &pending.query, provider, browser)
}

/// Send the browser to `provider` to sign in for `request` (`query`, as the
/// client sent it), binding the sign-in to `browser` (the cookie's value):
/// what it comes back for is sealed into a cookie of the flow's own.
fn start(
    cx: &Ctx<'_>,
    sign_in: &oauth::SignIn,
    request: Authorization,
    query: &str,
    provider: &str,
    browser: &str,
) -> (Answer, Vec<String>) {
    let secrets = (|| Ok::<_, Error>((auth::random_hex(16)?, auth::random_hex(32)?, auth::random_hex(16)?)))();
    let (state, verifier, nonce) = match secrets {
        Ok(s) => s,
        Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
    };
    let callback = format!("{}{}", cx.issuer, super::callback(provider));
    let url = match (provider, &sign_in.github, sign_in.oidc(provider)) {
        ("github", Some(github), _) => oauth::web_sign_in_url(github, &callback, &state, &s256(&verifier)),
        (_, _, Some(oidc)) => match oidc.metadata() {
            Ok(md) => oidc.authorization_url(&md, &callback, &state, &nonce, &s256(&verifier)),
            Err(e) => {
                tracing::warn!(target: "bd::serve", %provider, error = %e, "OAuth sign-in could not start");
                let link = request.error_url(cx.issuer, "temporarily_unavailable", "the provider could not be reached");
                let why = "It didn't respond as expected. Try again in a moment.";
                let title = format!("Couldn't reach {}", oidc.label);
                return (Answer::Page(pages::refusal(502, &title, why, Some(&link))), Vec::new());
            }
        },
        _ => return (refused(404, NO_APPS), Vec::new()),
    };
    let at = AtProvider { provider: provider.to_string(), state: state.clone(), verifier, nonce };
    let pending = Pending { query: query.to_string(), browser: auth::hash(browser), until: until(), at: Some(at) };
    let sealed = match lock(cx.flows).sealer.seal(AT_PROVIDER, &pending) {
        Ok(s) => s,
        Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
    };
    if sealed.len() > MAX_SEALED {
        tracing::info!(target: "bd::serve", client = %request.client.id, "OAuth sign-in refused: its request is too long to carry");
        return (refused(400, MALFORMED), Vec::new());
    }
    let cookies = vec![set_cookie(cx.issuer, browser), set_flow_cookie(cx.issuer, &state, &sealed, STEP_TTL)];
    (Answer::Redirect(url), cookies)
}

/// The name of the cookie carrying the flow sent to a provider with `state`.
fn flow_cookie_name(issuer: &str, state: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_flow_{}", &auth::hash(state)[..16])
}

/// The `Set-Cookie` value giving the browser the flow `sealed`, sent back to
/// the provider callbacks for as long as `lasts` (zero: removed).
fn set_flow_cookie(issuer: &str, state: &str, sealed: &str, lasts: Duration) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    let name = flow_cookie_name(issuer, state);
    format!("{name}={sealed}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", lasts.as_secs())
}

/// The flow the browser carries for `state` in its `Cookie` headers (joined with `;`).
fn flow_cookie<'h>(issuer: &str, headers: &'h str, state: &str) -> Option<&'h str> {
    let wanted = flow_cookie_name(issuer, state);
    headers.split(';').filter_map(|c| c.trim().split_once('=')).find(|(name, _)| *name == wanted).map(|(_, v)| v)
}

/// What the pages call a client: its name, else its document's host.
fn client_name(client: &Client) -> String {
    match (&client.name, client.document) {
        (Some(name), _) => name.clone(),
        (None, true) => host_of(&client.id).to_string(),
        (None, false) => "Unnamed application".into(),
    }
}

/// `POST <issuer>/oauth/<provider>/callback`: the provider's answer as a
/// form the browser posted (`response_mode=form_post`). Another site's POST
/// carries no `SameSite=Lax` cookie, so the step cannot tell the browser
/// here: the answer goes on to [`callback`] as the GET it would otherwise
/// have been, a top-level navigation the cookie goes with. Only what the
/// callback reads goes on (not an ID token or the user's name). Only a
/// provider configured to post its answers is relayed.
pub fn relay(cx: &Ctx<'_>, provider: &str, body: &str) -> Answer {
    let posts = match oauth::load(cx.root) {
        Ok(Some(s)) => s.oauth.is_some() && s.oidc(provider).is_some_and(|o| o.form_post),
        Ok(None) => false,
        Err(e) => return internal(&e, "reading auth.toml for a posted sign-in answer"),
    };
    if !posts {
        return refused(400, "This sign-in came back in a way it shouldn't. Start again from the application.");
    }
    let Some(pairs) = form::decode(body) else {
        return refused(400, "The sign-in came back unreadable. Start again from the application.");
    };
    let kept: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(k, _)| matches!(k.as_str(), "state" | "code" | "error" | "iss"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if !kept.iter().any(|(k, _)| *k == "state") {
        return refused(400, "This sign-in has expired. Start again from the application.");
    }
    Answer::Redirect(format!("{}{}?{}", cx.issuer, super::callback(provider), form::encode(&kept)))
}

/// `GET <issuer>/oauth/<provider>/callback?<query>`: the provider sent the
/// browser back. Find out who signed in and what the rules or the
/// authorizer let the account do in the workspace, and ask whether the
/// client may.
pub fn callback(
    cx: &Ctx<'_>,
    provider: &str,
    query: &str,
    browser: Option<&str>,
    cookies: &str,
) -> (Answer, Vec<String>) {
    let mut fresh = None;
    let answer = signed_in(cx, provider, query, browser, cookies, &mut fresh);
    // The flow's cookie has served: gone, whatever came of it.
    let state = form::decode(query).unwrap_or_default().into_iter().find(|(k, _)| k == "state").map(|(_, v)| v);
    let gone = state.map(|state| set_flow_cookie(cx.issuer, &state, "", Duration::ZERO));
    (answer, fresh.into_iter().chain(gone).collect())
}

/// [`callback`]'s answer. Once the person signed in, the browser gets a
/// cookie of the consent's own (`fresh`, its `Set-Cookie`), which the
/// consent is bound to: a cookie known or planted before the sign-in is good
/// for nothing after it, and other sign-ins under way in the same browser
/// keep theirs.
fn signed_in(
    cx: &Ctx<'_>,
    provider: &str,
    query: &str,
    browser: Option<&str>,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Answer {
    let pairs = form::decode(query).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    // The flow the browser carries for the state the provider sent back; a provider's code is used once, so a
    // flow brought back twice gets no second account.
    let state = get("state").unwrap_or_default();
    let pending =
        flow_cookie(cx.issuer, cookies, state).and_then(|sealed| lock(cx.flows).sealer.open(AT_PROVIDER, sealed));
    let pending = pending.filter(|p| p.until > now_millis() && p.at.as_ref().is_some_and(|at| at.state == state));
    let Some(Pending { query: requested, browser: started_in, at: Some(at), .. }) = pending else {
        return refused(400, "This sign-in has expired. Start again from the application.");
    };
    let AtProvider { provider: started_with, verifier, nonce, .. } = at;
    if browser.map(auth::hash).as_deref() != Some(started_in.as_str()) {
        return refused(400, "This sign-in started in a different browser. Start again from the application.");
    }
    if started_with != provider {
        return refused(400, "This sign-in came back from another provider. Start again from the application.");
    }
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return answer,
    };
    let request = match request_of(cx, &oauth_config, &requested) {
        Ok(r) => r,
        Err(answer) => return answer,
    };
    let label = match (provider, sign_in.oidc(provider)) {
        ("github", _) => "GitHub".to_string(),
        (_, Some(oidc)) => oidc.label.clone(),
        _ => return refused(404, NO_APPS),
    };
    // Mix-up: an OIDC provider's answer names it (RFC 9207), where it says it does, and never another one.
    if let Some(oidc) = sign_in.oidc(provider) {
        let required = oidc.metadata().is_ok_and(|md| md.iss_parameter);
        let ok = match get("iss") {
            Some(iss) => iss == oidc.issuer,
            None => !required,
        };
        if !ok {
            tracing::warn!(target: "bd::serve", %provider, iss = ?get("iss"), "a sign-in came back naming another issuer");
            return refused(400, "This sign-in came back from another provider. Start again from the application.");
        }
    }
    let back = |error: &str, description: &str| request.error_url(cx.issuer, error, description);
    if let Some(error) = get("error") {
        let (error, description) = match error {
            // Apple says `user_cancelled_authorize`.
            "access_denied" | "user_cancelled_authorize" => {
                ("access_denied", "the sign-in was cancelled at the provider")
            }
            _ => ("server_error", "the provider did not complete the sign-in"),
        };
        return Answer::Redirect(back(error, description));
    }
    let Some(code) = get("code").filter(|c| !c.is_empty()) else {
        let why = format!("{label} didn't return a sign-in code. Start again from the application.");
        return refused(400, &why);
    };
    let callback_url = format!("{}{}", cx.issuer, super::callback(provider));
    let workspace = &request.workspace;
    let client = &request.client.id;
    let admitted = match sign_in.oidc(provider) {
        None => oauth::web_sign_in(cx.root, &sign_in, code, &callback_url, &verifier, workspace, client),
        Some(oidc) => oidc
            .metadata()
            .and_then(|md| oidc.sign_in(&md, code, &callback_url, &verifier, &nonce))
            .and_then(|claims| oauth::admit_oidc(cx.root, &sign_in, oidc, &claims, workspace, Some(client))),
    };
    let found = admitted.and_then(|a| Ok((auth::preview_actor(cx.root, &a.user, a.by_login)?, a)));
    let (actor, admitted) = match found {
        Ok(found) => found,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "web sign-in refused");
            let link = back("access_denied", "the account may not use this workspace");
            let why = format!(
                "Your {label} account doesn't have access to this workspace. Ask the server's admin for access."
            );
            return Answer::Page(pages::refusal(403, "Access denied", &why, Some(&link)));
        }
        Err(Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "web sign-in did not complete");
            let link = back("access_denied", "the sign-in did not complete");
            let why = format!("{label} didn't finish signing you in. Start again from the application.");
            return Answer::Page(pages::refusal(400, "Sign-in didn't finish", &why, Some(&link)));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "web sign-in failed");
            let link = back("temporarily_unavailable", "the provider could not be reached");
            let why = format!("{label} didn't respond as expected. Try again in a moment.");
            return Answer::Page(pages::refusal(502, &format!("Couldn't reach {label}"), &why, Some(&link)));
        }
        Err(Error::Busy(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "web sign-in could not be decided");
            let link = back("temporarily_unavailable", "the server could not check access");
            let why = "The server couldn't check your access just now. Try again in a moment.";
            return Answer::Page(pages::refusal(503, "Couldn't check your access", why, Some(&link)));
        }
        Err(e) => return internal(&e, "finishing a web sign-in"),
    };
    if !(cx.workspace_exists)(&request.workspace) {
        return Answer::Redirect(back("invalid_target", "resource is not an MCP endpoint of this bd server"));
    }
    let id = match auth::random_hex(32) {
        Ok(id) => id,
        Err(e) => return internal(&e, "asking for consent"),
    };
    let client = &request.client;
    let name = client_name(client);
    let identity = if client.document {
        pages::Identity::Document { url: &client.id, host: host_of(&client.id) }
    } else {
        pages::Identity::Registered { client_id: &client.id }
    };
    let loopback = clients::is_loopback(&request.redirect_uri);
    let returns_to = host_of(&request.redirect_uri);
    let elsewhere = (client.document && !loopback && returns_to != host_of(&client.id)).then_some(returns_to);
    let lasts = match sign_in.refreshes(&admitted.user.provider) {
        true => format!(
            "at most {}, and ends after {} unused or when revoked",
            in_words(sign_in.refresh_limit),
            in_words(sign_in.refresh_idle)
        ),
        false => format!("{}, or until revoked", in_words(sign_in.token_ttl)),
    };
    let action = format!("{}{CONSENT}", cx.issuer);
    let page = pages::consent(&pages::Consent {
        client: &name,
        identity,
        logo: client.logo.as_deref().filter(|_| client.document),
        redirect_uri: &request.redirect_uri,
        loopback,
        elsewhere,
        lasts: &lasts,
        workspace: &request.workspace,
        provider: &label,
        // The email the person knows the account by, where the provider gave one: on this page only.
        login: admitted.email.as_deref().unwrap_or(&admitted.user.login),
        actor: &actor,
        access: match admitted.grant.role {
            auth::Role::Read => "Read only",
            auth::Role::Write => "Read and write",
            auth::Role::Admin => "Full, including administration",
        },
        via: &admitted.via,
        id: &id,
        action: &action,
        form_origins: &form_origins(&request.redirect_uri),
    });
    let (value, suffix) = match (auth::random_hex(32), auth::random_hex(4)) {
        (Ok(v), Ok(s)) => (v, s),
        (Err(e), _) | (_, Err(e)) => return internal(&e, "asking for consent"),
    };
    *fresh = Some(set_consent_cookie(cx.issuer, &suffix, &value));
    let consent = Consent { request, admitted, actor, browser: auth::hash(&value), cookie: suffix };
    lock(cx.flows).consents.put(auth::hash(&id), consent);
    Answer::Page(page)
}

/// `POST <issuer>/oauth/consent` with `consent=<id>&decision=approve|deny`:
/// send the browser back to the client with a code, or `access_denied`.
pub fn decide(cx: &Ctx<'_>, body: &str, cookies: &str) -> Answer {
    let pairs = form::decode(body).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    // Taken only by the browser it is bound to: another one that learned its id must not end it.
    let key = get("consent").map(auth::hash);
    let consent = {
        let mut flows = lock(cx.flows);
        let bound = |c: &Consent| {
            consent_cookie(cx.issuer, cookies, &c.cookie).map(auth::hash).as_deref() == Some(c.browser.as_str())
        };
        match key.as_ref().and_then(|k| flows.consents.get_mut(k).map(|c| bound(c))) {
            None => None,
            Some(false) => {
                return refused(400, "This request started in a different browser. Start again from the application.");
            }
            Some(true) => key.as_ref().and_then(|k| flows.consents.take(k)),
        }
    };
    let Some(Consent { request, admitted, actor, .. }) = consent else {
        return refused(400, "This request has expired. Start again from the application.");
    };
    // `[oauth]` may have changed since the request was checked: the browser
    // goes back only where it allows now (RFC 9700 section 4.11).
    match oauth::load(cx.root) {
        Ok(Some(g)) => match g.oauth {
            Some(o) if o.allows_redirect(&request.redirect_uri) => {}
            Some(_) => {
                tracing::info!(target: "bd::serve", redirect_uri = %request.redirect_uri, "OAuth redirect no longer allowed");
                let why = "The application asked to send you somewhere this server no longer allows.";
                return refused(400, why);
            }
            None => return refused(404, NO_APPS),
        },
        Ok(None) => return refused(404, NO_APPS),
        Err(e) => return internal(&e, "reading auth.toml for a consent"),
    }
    let log = |decision: &str| {
        tracing::info!(
            target: "bd::serve",
            client = %request.client.id,
            login = %admitted.user.login,
            subject = %admitted.user.subject,
            %actor,
            workspace = %request.workspace,
            "OAuth authorization {decision}"
        );
    };
    match get("decision") {
        Some("approve") => {}
        Some("deny") => {
            log("denied");
            return back_to(request.error_url(cx.issuer, "access_denied", "the authorization was denied"));
        }
        _ => return refused(400, "The form arrived incomplete. Start again from the application."),
    }
    let code = match auth::random_hex(32) {
        Ok(c) => c,
        Err(e) => return internal(&e, "issuing an authorization code"),
    };
    log("approved");
    if request.client.document {
        cx.documents.keep(&request.client);
    }
    let url = answer_url(&request.redirect_uri, request.state.as_deref(), cx.issuer, &[("code", &code)]);
    let issued = Code {
        client_id: request.client.id,
        redirect_uri: request.redirect_uri,
        challenge: request.challenge,
        resource: request.resource,
        admitted,
        actor,
    };
    lock(cx.flows).codes.put(auth::hash(&code), issued);
    back_to(url)
}

/// Whether `url`'s host is an IPv6 address (`http://[::1]:8080/cb`).
fn ipv6_host(url: &str) -> bool {
    host_of(url).starts_with('[')
}

/// Where the consent form may post, and be redirected after: the page's
/// own origin (`'self'`, which unlike a source naming it matches an IPv6
/// host), and the client's redirect URI, which a policy can name unless its
/// host is an IPv6 address ([`back_to`]).
fn form_origins(redirect_uri: &str) -> Vec<&str> {
    let mut origins = vec!["'self'"];
    if !ipv6_host(redirect_uri) {
        origins.push(origin(redirect_uri));
    }
    origins
}

/// Send the browser back to the client after the consent form, at `url`:
/// redirected, or by a page where the form's policy cannot allow it.
fn back_to(url: String) -> Answer {
    if ipv6_host(&url) { Answer::Page(pages::onward(&url)) } else { Answer::Redirect(url) }
}

/// A code for `bdc_1`, as tests issue them.
#[cfg(test)]
pub fn sample_code() -> Code {
    Code {
        client_id: "bdc_1".into(),
        redirect_uri: "https://app.example/cb".into(),
        challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into(),
        resource: "https://bd.example.com/bd/w/proj/mcp".into(),
        admitted: Admitted {
            user: auth::Identity {
                provider: "github".into(),
                issuer: "https://github.com".into(),
                subject: "1".into(),
                login: "alice".into(),
            },
            grant: auth::Grant {
                role: auth::Role::Write,
                kind: auth::Kind::Agent,
                workspaces: vec!["proj".into()],
                max_claims: None,
            },
            via: "GitHub user alice".into(),
            by_login: true,
            unknown: vec![],
            email: None,
            rule: None,
        },
        actor: "alice".into(),
    }
}

#[cfg(test)]
impl Flows {
    /// Issue `code` for `found`, as an approval does.
    pub fn put_code(&mut self, code: &str, found: Code) {
        self.codes.put(auth::hash(code), found);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://bd.example.com/bd";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    /// The verifier of [`CHALLENGE`] (RFC 7636 appendix B).
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn client() -> Client {
        Client {
            id: "bdc_1".into(),
            name: Some("App".into()),
            redirect_uris: vec!["https://app.example/cb?x=1".into()],
            document: false,
            logo: None,
            cacheable: true,
        }
    }

    fn oauth() -> OauthConfig {
        OauthConfig {
            redirect_hosts: vec!["app.example".into()],
            redirect_uris: vec![],
            loopback_redirects: false,
            registration: true,
        }
    }

    fn query(extra: &[(&str, &str)]) -> String {
        let mut q = vec![
            ("client_id", "bdc_1"),
            ("redirect_uri", "https://app.example/cb?x=1"),
            ("state", "s 1"),
            ("response_type", "code"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("resource", "https://bd.example.com/bd/w/proj/mcp"),
        ];
        for (k, v) in extra {
            match q.iter_mut().find(|(name, _)| name == k) {
                Some(pair) if v.is_empty() => pair.0 = "dropped",
                Some(pair) => pair.1 = v,
                None => q.push((k, v)),
            }
        }
        form::encode(&q)
    }

    fn checked(q: &str) -> Result<Authorization, Answer> {
        check(parse(q)?, client(), &oauth(), ISSUER)
    }

    fn page_status(answer: Answer) -> u16 {
        match answer {
            Answer::Page(p) => p.status,
            a => panic!("not a page: {a:?}"),
        }
    }

    fn redirect(answer: Answer) -> Vec<(String, String)> {
        let Answer::Redirect(url) = answer else { panic!("not a redirect: {answer:?}") };
        let rest = url.strip_prefix("https://app.example/cb?x=1&").unwrap_or_else(|| panic!("{url}"));
        form::decode(rest).unwrap()
    }

    #[test]
    fn a_valid_request_is_checked() {
        let a = checked(&query(&[("scope", "anything")])).unwrap();
        assert_eq!(a.redirect_uri, "https://app.example/cb?x=1");
        assert_eq!(a.state.as_deref(), Some("s 1"));
        assert_eq!(a.challenge, CHALLENGE);
        assert_eq!(a.workspace, "proj");
        assert_eq!(a.resource, "https://bd.example.com/bd/w/proj/mcp");
        assert_eq!(
            checked(&query(&[("resource", "https://BD.example.com/bd/w/proj/mcp/")])).unwrap().workspace,
            "proj"
        );
        assert!(checked(&query(&[("state", "")])).unwrap().state.is_none());
    }

    #[test]
    fn requests_the_client_cannot_be_told_about_are_refused_on_a_page() {
        for q in [
            query(&[("client_id", "")]),
            query(&[("redirect_uri", "")]),
            format!("{}&client_id=bdc_2", query(&[])),
            format!("{}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1", query(&[])),
            format!("{}&state=again", query(&[])),
            query(&[("state", &"s".repeat(MAX_STATE + 1))]),
            query(&[("redirect_uri", "https://app.example/cb?x=2")]),
            query(&[("redirect_uri", "https://evil.example/cb?x=1")]),
            "client_id=%zz".to_string(),
        ] {
            assert_eq!(page_status(checked(&q).unwrap_err()), 400, "{q}");
        }
        let allowed = OauthConfig {
            redirect_hosts: vec![],
            redirect_uris: vec![],
            loopback_redirects: false,
            registration: true,
        };
        let answer = check(parse(&query(&[])).unwrap(), client(), &allowed, ISSUER).unwrap_err();
        assert_eq!(page_status(answer), 400, "registered, but no longer allowed");
    }

    #[test]
    fn other_errors_go_back_to_the_client() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[("response_type", "")], "invalid_request"),
            (&[("response_type", "token")], "unsupported_response_type"),
            (&[("code_challenge_method", "")], "invalid_request"),
            (&[("code_challenge_method", "plain")], "invalid_request"),
            (&[("code_challenge", "")], "invalid_request"),
            (&[("code_challenge", "short")], "invalid_request"),
            (&[("code_challenge", &CHALLENGE.replace('-', "+"))], "invalid_request"),
            (&[("resource", "")], "invalid_request"),
            (&[("resource", "https://elsewhere.example/bd/w/proj/mcp")], "invalid_target"),
            (&[("resource", "https://bd.example.com/w/proj/mcp")], "invalid_target"),
            (&[("resource", "https://bd.example.com/bd/w/proj")], "invalid_target"),
        ];
        for (extra, error) in cases {
            let pairs = redirect(checked(&query(extra)).unwrap_err());
            assert_eq!(pairs[0], ("error".into(), error.to_string()), "{extra:?}");
            assert_eq!(pairs[1].0, "error_description");
            assert_eq!(pairs[2], ("state".into(), "s 1".into()));
            assert_eq!(pairs[3], ("iss".into(), ISSUER.into()));
        }
        let pairs = redirect(checked(&format!("{}&scope=a&scope=b", query(&[]))).unwrap_err());
        assert_eq!(pairs[0].1, "invalid_request");
        assert!(pairs[1].1.contains("scope"));
        let pairs = redirect(checked(&query(&[("state", ""), ("response_type", "token")])).unwrap_err());
        assert_eq!(pairs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["error", "error_description", "iss"]);
    }

    #[test]
    fn flows_are_taken_once_and_expire() {
        let mut kept = Kept::new(Duration::from_secs(60));
        kept.put("a".into(), 1);
        assert_eq!(kept.take("a"), Some(1));
        assert_eq!(kept.take("a"), None);
        let mut expired = Kept::new(Duration::ZERO);
        expired.put("a".into(), 1);
        assert_eq!(expired.take("a"), None);
        for i in 0..MAX_FLOWS + 10 {
            kept.put(i.to_string(), i);
        }
        assert_eq!(kept.map.len(), MAX_FLOWS);
        assert_eq!(kept.take("0"), None, "the oldest went first");
        assert_eq!(kept.take(&(MAX_FLOWS + 9).to_string()), Some(MAX_FLOWS + 9));
    }

    #[test]
    fn flows_before_a_sign_in_are_sealed_for_their_step() {
        let sealer = Sealer::new();
        let at = AtProvider { provider: "github".into(), state: "s".into(), verifier: "v".into(), nonce: "n".into() };
        let pending = Pending { query: "client_id=x".into(), browser: "b".into(), until: 1, at: Some(at) };
        let sealed = sealer.seal(AT_PROVIDER, &pending).unwrap();
        assert!(!sealed.contains("client_id") && !sealed.contains("github"), "unread: {sealed}");
        assert_eq!(sealer.open(AT_PROVIDER, &sealed), Some(pending));
        assert_eq!(sealer.open(CHOOSING, &sealed), None, "for its own step only");
        assert_eq!(Sealer::new().open(AT_PROVIDER, &sealed), None, "this process's key only");
        let mut changed = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(sealer.open(AT_PROVIDER, &URL_SAFE_NO_PAD.encode(changed)), None, "unchanged");
        assert_eq!(sealer.open(AT_PROVIDER, "AAAA"), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(in_words(Duration::from_secs(30 * 86_400)), "30 days");
        assert_eq!(in_words(Duration::from_secs(86_400)), "1 day");
        assert_eq!(in_words(Duration::from_secs(36 * 3_600)), "36 hours");
        assert_eq!(in_words(Duration::from_secs(90)), "2 minutes");
        assert_eq!(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), CHALLENGE, "RFC 7636 appendix B");
        let c = "a".repeat(64);
        let http = "http://127.0.0.1:7420";
        assert_eq!(cookie(http, &format!("x=1; {COOKIE}={c}; y=2")), Some(c.as_str()));
        assert_eq!(cookie(http, &format!("{COOKIE}={}", "A".repeat(64))), None);
        assert_eq!(cookie(http, &format!("{COOKIE}=abc")), None);
        assert_eq!(cookie(ISSUER, &format!("x=1; {SECURE_COOKIE}={c}")), Some(c.as_str()));
        assert_eq!(cookie(ISSUER, &format!("{COOKIE}={c}")), None, "unprefixed, on https: planted, maybe");
        assert_eq!(cookie(http, &format!("{SECURE_COOKIE}={c}")), None);
        assert_eq!(cookie(http, "x=1"), None);
        assert_eq!(
            set_cookie(ISSUER, &c),
            format!("{SECURE_COOKIE}={c}; Path=/bd/oauth; Max-Age=1200; HttpOnly; SameSite=Lax; Secure")
        );
        assert_eq!(
            set_cookie("http://127.0.0.1:7420", &c),
            format!("{COOKIE}={c}; Path=/oauth; Max-Age=1200; HttpOnly; SameSite=Lax")
        );
        assert_eq!(origin("https://a.example:8443/x?y#z"), "https://a.example:8443");
        assert_eq!(origin("http://127.0.0.1?x"), "http://127.0.0.1");
        assert_eq!(host_of("https://app.example/cb"), "app.example");
        let iss = "iss=https%3A%2F%2Fbd.example.com%2Fbd";
        assert_eq!(
            answer_url("https://a/cb", Some("s"), ISSUER, &[("code", "c")]),
            format!("https://a/cb?code=c&state=s&{iss}")
        );
        assert_eq!(answer_url("https://a/cb?x", None, ISSUER, &[]), format!("https://a/cb?x&{iss}"));
    }

    #[test]
    fn the_browser_returns_by_a_page_to_an_ipv6_address() {
        assert_eq!(form_origins("https://app.example/cb"), ["'self'", "https://app.example"]);
        assert_eq!(form_origins("http://127.0.0.1:8080/cb"), ["'self'", "http://127.0.0.1:8080"]);
        assert_eq!(form_origins("http://[::1]:8080/cb"), ["'self'"]);
        assert_eq!(
            back_to("http://127.0.0.1:8080/cb?code=c".into()),
            Answer::Redirect("http://127.0.0.1:8080/cb?code=c".into())
        );
        let Answer::Page(page) = back_to("http://[::1]:8080/cb?code=c".into()) else { panic!("not a page") };
        assert!(page.html.contains("href=\"http://[::1]:8080/cb?code=c\""), "{}", page.html);
    }

    #[test]
    fn codes_are_redeemed_once_and_a_code_sent_again_names_its_token() {
        let code = sample_code();
        let mut flows = Flows::default();
        let redeem = |flows: &mut Flows, c: &str| flows.redeem(c, "bdc_1", VERIFIER);
        flows.codes.put(auth::hash("c1"), code.clone());
        assert!(matches!(redeem(&mut flows, "c1"), Redeemed::Fresh(_)));
        assert!(!flows.issued("c1", "t1"));
        assert!(matches!(redeem(&mut flows, "c1"), Redeemed::Again(Some(t)) if t == "t1"));
        assert!(matches!(redeem(&mut flows, "c2"), Redeemed::Unknown));
        // Sent again while its token was being issued: that token must go.
        flows.codes.put(auth::hash("c3"), code.clone());
        assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Fresh(_)));
        assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Again(None)));
        assert!(flows.issued("c3", "t3"));
        // Undone, as no token was issued: good again, until it would have expired.
        flows.codes.put(auth::hash("c4"), code.clone());
        let until = flows.codes.map[&auth::hash("c4")].0;
        assert!(matches!(redeem(&mut flows, "c4"), Redeemed::Fresh(_)));
        flows.unredeem("c4", code.clone());
        assert_eq!(flows.codes.map[&auth::hash("c4")].0, until);
        assert!(matches!(redeem(&mut flows, "c4"), Redeemed::Fresh(_)));
        // Not once sent again, nor once it issued a token.
        flows.unredeem("c3", code.clone());
        assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Again(Some(t)) if t == "t3"));
        flows.codes.put(auth::hash("c5"), code.clone());
        assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Fresh(_)));
        assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Again(None)));
        flows.unredeem("c5", code.clone());
        assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Again(None)));
        // Sent again by someone who saw it, without its client's verifier: its token stays.
        flows.codes.put(auth::hash("c6"), code);
        assert!(matches!(redeem(&mut flows, "c6"), Redeemed::Fresh(_)));
        assert!(!flows.issued("c6", "t6"));
        let other_verifier = "x".repeat(43);
        assert!(matches!(flows.redeem("c6", "bdc_1", &other_verifier), Redeemed::Again(None)));
        assert!(matches!(flows.redeem("c6", "bdc_other", VERIFIER), Redeemed::Again(None)));
        assert!(matches!(redeem(&mut flows, "c6"), Redeemed::Again(Some(t)) if t == "t6"), "its own client: revoked");
    }
}
