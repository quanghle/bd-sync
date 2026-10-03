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
//!    may do in the workspace the client asked for (`oauth.rs`). A consent
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
use super::{CALLBACK, CONSENT, form};
use crate::auth;
use crate::mcp::http as mcp_http;
use crate::oauth::{self, Admitted, OauthConfig};

/// The cookie binding an authorization's steps to one browser.
pub const COOKIE: &str = "bd_oauth";
/// How long people have to sign in at GitHub, and then to decide.
const STEP_TTL: Duration = Duration::from_secs(10 * 60);
/// How long an authorization code may wait to be redeemed.
const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Authorizations kept at each step; past it, the oldest go first.
const MAX_FLOWS: usize = 1024;
/// The longest `state` a client may send, which comes back in redirects.
const MAX_STATE: usize = 1024;

/// What an authorization step needs of the server.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub issuer: &'a str,
    pub documents: &'a Documents,
    pub flows: &'a Mutex<Flows>,
    /// Whether the server has this workspace.
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
#[expect(dead_code, reason = "the token endpoint redeems codes")]
pub struct Code {
    pub client_id: String,
    pub redirect_uri: String,
    /// The PKCE challenge the code is redeemed with the verifier of.
    pub challenge: String,
    pub resource: String,
    pub workspace: String,
    /// The account, and what the rules let it do in the workspace.
    pub admitted: Admitted,
    /// The actor its tokens would get, as the consent page showed.
    pub actor: String,
}

/// Signing in at GitHub.
struct Started {
    request: Authorization,
    /// The PKCE verifier of this server's code from GitHub.
    verifier: String,
    /// The hash of the browser's cookie.
    browser: String,
}

/// Waiting for a decision on the consent page.
struct Consent {
    request: Authorization,
    admitted: Admitted,
    actor: String,
    browser: String,
}

/// Authorizations under way, by the hash of their secret at each step
/// (`state` at GitHub, the consent id, the code); each taken once.
pub struct Flows {
    started: Kept<Started>,
    consents: Kept<Consent>,
    codes: Kept<Code>,
}

impl Default for Flows {
    fn default() -> Flows {
        Flows { started: Kept::new(STEP_TTL), consents: Kept::new(STEP_TTL), codes: Kept::new(CODE_TTL) }
    }
}

impl Flows {
    /// The code `code` stands for, once, if it has not expired.
    #[expect(dead_code, reason = "the token endpoint redeems codes")]
    pub fn take_code(&mut self, code: &str) -> Option<Code> {
        self.codes.take(&auth::hash(code))
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
        let now = Instant::now();
        if self.map.len() >= MAX_FLOWS {
            self.map.retain(|_, (until, _)| *until > now);
        }
        if self.map.len() >= MAX_FLOWS {
            let oldest = self.map.iter().min_by_key(|(_, (until, _))| *until).map(|(k, _)| k.clone());
            self.map.remove(&oldest.unwrap_or_default());
        }
        self.map.insert(key, (now + self.ttl, value));
    }

    fn take(&mut self, key: &str) -> Option<T> {
        let (until, value) = self.map.remove(key)?;
        (until > Instant::now()).then_some(value)
    }
}

fn lock(flows: &Mutex<Flows>) -> std::sync::MutexGuard<'_, Flows> {
    flows.lock().unwrap_or_else(|e| e.into_inner())
}

/// The S256 PKCE challenge of `verifier` (RFC 7636 section 4.2).
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The browser's [`COOKIE`] in a `Cookie` header, if well-formed.
pub fn cookie(header: &str) -> Option<&str> {
    header
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value giving the browser `value`, sent back to the
/// authorization server's endpoints only, and with top-level navigations
/// from GitHub. It lasts both steps: signing in at GitHub, then deciding.
pub fn set_cookie(issuer: &str, value: &str) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    format!("{COOKIE}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", 2 * STEP_TTL.as_secs())
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
    let why = "The bd server could not go on; the details are in its log.";
    Answer::Page(pages::refusal(500, "Something went wrong", why, None))
}

fn refused(status: u16, why: &str) -> Answer {
    Answer::Page(pages::refusal(status, "This authorization cannot go on", why, None))
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
        return Err(refused(400, "The authorization request is not a valid query string."));
    };
    let mut rest = HashMap::new();
    let mut repeated = None;
    let seen = |name: &str| pairs.iter().filter(|(k, _)| k == name).count();
    for name in ["client_id", "redirect_uri", "state"] {
        if seen(name) > 1 {
            return Err(refused(400, &format!("The authorization request gives {name} more than once.")));
        }
    }
    let one = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let (Some(client_id), Some(redirect_uri)) = (one("client_id"), one("redirect_uri")) else {
        return Err(refused(400, "The authorization request needs a client_id and a redirect_uri."));
    };
    let state = one("state");
    if state.as_ref().is_some_and(|s| s.len() > MAX_STATE) {
        return Err(refused(400, &format!("The authorization request's state is longer than {MAX_STATE} bytes.")));
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
fn check(
    params: Params,
    client: Client,
    oauth: &OauthConfig,
    issuer: &str,
    workspace_exists: &dyn Fn(&str) -> bool,
) -> Result<Authorization, Answer> {
    if !client.redirects_to(&params.redirect_uri, oauth) {
        let why = "The redirect_uri is not one the client registered, or not one this bd server sends people back to.";
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
        Ok((url, name)) if url == mcp_http::resource(issuer, &name) && workspace_exists(&name) => name,
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

/// `GET <issuer>/oauth/authorize?<query>`: check the request, and send the
/// browser to GitHub to sign in. `browser` is its cookie, if it has one;
/// the `Set-Cookie` value to answer with comes back with the answer.
pub fn begin(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> (Answer, Option<String>) {
    let (github, oauth_config) = match oauth::load(cx.root) {
        Ok(Some(g)) => match g.oauth.clone() {
            Some(o) => (g, o),
            None => return (refused(404, "This bd server does not authorize applications."), None),
        },
        Ok(None) => return (refused(404, "This bd server does not authorize applications."), None),
        Err(e) => return (internal(&e, "reading auth.toml for an authorization"), None),
    };
    let params = match parse(query) {
        Ok(p) => p,
        Err(answer) => return (answer, None),
    };
    let client = match clients::lookup(cx.root, cx.documents, &params.client_id) {
        Ok(c) => c,
        Err(Error::Invalid(why) | Error::Remote(why)) => return (refused(400, &why), None),
        Err(Error::Busy(_)) => return (refused(503, "The bd server is busy; try again in a moment."), None),
        Err(e) => return (internal(&e, "looking up an OAuth client"), None),
    };
    let request = match check(params, client, &oauth_config, cx.issuer, cx.workspace_exists) {
        Ok(r) => r,
        Err(answer) => return (answer, None),
    };
    let secrets = (|| Ok::<_, Error>((auth::random_hex(32)?, auth::random_hex(32)?, auth::random_hex(32)?)))();
    let (state, verifier, new_cookie) = match secrets {
        Ok(s) => s,
        Err(e) => return (internal(&e, "starting an authorization"), None),
    };
    let browser = browser.map_or(new_cookie, str::to_string);
    let url = oauth::web_sign_in_url(&github, &format!("{}{CALLBACK}", cx.issuer), &state, &s256(&verifier));
    let started = Started { request, verifier, browser: auth::hash(&browser) };
    lock(cx.flows).started.put(auth::hash(&state), started);
    (Answer::Redirect(url), Some(set_cookie(cx.issuer, &browser)))
}

/// `GET <issuer>/oauth/github/callback?<query>`: GitHub sent the browser
/// back. Find out who signed in and what the rules let the account do in
/// the workspace, and ask whether the client may.
pub fn callback(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> Answer {
    let pairs = form::decode(query).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let started = get("state").and_then(|state| lock(cx.flows).started.take(&auth::hash(state)));
    let Some(Started { request, verifier, browser: started_in }) = started else {
        return refused(400, "This sign-in is unknown or expired: start again from the application.");
    };
    if browser.map(auth::hash).as_deref() != Some(started_in.as_str()) {
        return refused(400, "This sign-in started in another browser: start again from the application.");
    }
    let back = |error: &str, description: &str| request.error_url(cx.issuer, error, description);
    if let Some(error) = get("error") {
        let (error, description) = match error {
            "access_denied" => ("access_denied", "the sign-in was cancelled at GitHub"),
            _ => ("server_error", "GitHub did not complete the sign-in"),
        };
        return Answer::Redirect(back(error, description));
    }
    let Some(code) = get("code").filter(|c| !c.is_empty()) else {
        return refused(400, "GitHub sent no sign-in code: start again from the application.");
    };
    let github = match oauth::load(cx.root) {
        Ok(Some(g)) if g.oauth.is_some() => g,
        Ok(_) => return refused(404, "This bd server does not authorize applications."),
        Err(e) => return internal(&e, "reading auth.toml for an authorization"),
    };
    let callback_url = format!("{}{CALLBACK}", cx.issuer);
    let found = oauth::web_sign_in(&github, code, &callback_url, &verifier, &request.workspace)
        .and_then(|admitted| Ok((auth::preview_actor(cx.root, &admitted.user, admitted.by_login)?, admitted)));
    let (actor, admitted) = match found {
        Ok(found) => found,
        Err(Error::Unauthorized(why)) => {
            let link = back("access_denied", "the account may not use this workspace");
            return Answer::Page(pages::refusal(403, "Access refused", &why, Some(&link)));
        }
        Err(Error::Invalid(why)) => {
            let link = back("access_denied", "the sign-in did not complete");
            return Answer::Page(pages::refusal(400, "The sign-in did not complete", &why, Some(&link)));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", error = %why, "GitHub web sign-in failed");
            let link = back("temporarily_unavailable", "GitHub could not be reached");
            let why = "GitHub did not answer as expected; the details are in the bd server's log.";
            return Answer::Page(pages::refusal(502, "GitHub could not be reached", why, Some(&link)));
        }
        Err(e) => return internal(&e, "finishing a GitHub web sign-in"),
    };
    let id = match auth::random_hex(32) {
        Ok(id) => id,
        Err(e) => return internal(&e, "asking for consent"),
    };
    let client = &request.client;
    let (name, note) = match (&client.name, client.document) {
        (Some(name), true) => (name.clone(), format!("named by {}", host_of(&client.id))),
        (None, true) => (host_of(&client.id).to_string(), "identified by its address".into()),
        (Some(name), false) => (name.clone(), "a name the application gave itself, not verified".into()),
        (None, false) => ("An unnamed application".into(), format!("client {}", client.id)),
    };
    let action = format!("{}{CONSENT}", cx.issuer);
    let page = pages::consent(&pages::Consent {
        client: &name,
        client_note: &note,
        returns_to: host_of(&request.redirect_uri),
        workspace: &request.workspace,
        login: &admitted.user.login,
        actor: &actor,
        role: admitted.grant.role.as_str(),
        kind: admitted.grant.kind.as_str(),
        via: &admitted.via,
        id: &id,
        action: &action,
        form_origins: &[origin(cx.issuer), origin(&request.redirect_uri)],
    });
    let consent = Consent { request, admitted, actor, browser: started_in };
    lock(cx.flows).consents.put(auth::hash(&id), consent);
    Answer::Page(page)
}

/// `POST <issuer>/oauth/consent` with `consent=<id>&decision=approve|deny`:
/// send the browser back to the client with a code, or `access_denied`.
pub fn decide(cx: &Ctx<'_>, body: &str, browser: Option<&str>) -> Answer {
    let pairs = form::decode(body).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let consent = get("consent").and_then(|id| lock(cx.flows).consents.take(&auth::hash(id)));
    let Some(Consent { request, admitted, actor, browser: started_in }) = consent else {
        return refused(400, "This authorization is unknown or expired: start again from the application.");
    };
    if browser.map(auth::hash).as_deref() != Some(started_in.as_str()) {
        return refused(400, "This authorization started in another browser: start again from the application.");
    }
    let log = |decision: &str| {
        tracing::info!(
            target: "bd::serve",
            client = %request.client.id,
            login = %admitted.user.login,
            id = admitted.user.id,
            %actor,
            workspace = %request.workspace,
            "OAuth authorization {decision}"
        );
    };
    match get("decision") {
        Some("approve") => {}
        Some("deny") => {
            log("denied");
            return Answer::Redirect(request.error_url(cx.issuer, "access_denied", "the authorization was denied"));
        }
        _ => return refused(400, "The consent form was not filled in: start again from the application."),
    }
    let code = match auth::random_hex(32) {
        Ok(c) => c,
        Err(e) => return internal(&e, "issuing an authorization code"),
    };
    log("approved");
    let url = answer_url(&request.redirect_uri, request.state.as_deref(), cx.issuer, &[("code", &code)]);
    let issued = Code {
        client_id: request.client.id,
        redirect_uri: request.redirect_uri,
        challenge: request.challenge,
        resource: request.resource,
        workspace: request.workspace,
        admitted,
        actor,
    };
    lock(cx.flows).codes.put(auth::hash(&code), issued);
    Answer::Redirect(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://bd.example.com/bd";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn client() -> Client {
        Client {
            id: "bdc_1".into(),
            name: Some("App".into()),
            redirect_uris: vec!["https://app.example/cb?x=1".into()],
            document: false,
        }
    }

    fn oauth() -> OauthConfig {
        OauthConfig { redirect_hosts: vec!["app.example".into()], loopback_redirects: false }
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
        check(parse(q)?, client(), &oauth(), ISSUER, &|name| name == "proj")
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
        let allowed = OauthConfig { redirect_hosts: vec![], loopback_redirects: false };
        let answer = check(parse(&query(&[])).unwrap(), client(), &allowed, ISSUER, &|_| true).unwrap_err();
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
            (&[("resource", "https://bd.example.com/bd/w/other/mcp")], "invalid_target"),
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
    fn helpers() {
        assert_eq!(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), CHALLENGE, "RFC 7636 appendix B");
        let c = "a".repeat(64);
        assert_eq!(cookie(&format!("x=1; {COOKIE}={c}; y=2")), Some(c.as_str()));
        assert_eq!(cookie(&format!("{COOKIE}={}", "A".repeat(64))), None);
        assert_eq!(cookie(&format!("{COOKIE}=abc")), None);
        assert_eq!(cookie("x=1"), None);
        assert_eq!(
            set_cookie(ISSUER, &c),
            format!("{COOKIE}={c}; Path=/bd/oauth; Max-Age=1200; HttpOnly; SameSite=Lax; Secure")
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
}
