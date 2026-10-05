//! The authorization endpoint (OAuth 2.1 authorization code with PKCE),
//! where people let an MCP client use a workspace for them, signing in with
//! a provider (GitHub's web flow, or an OIDC provider):
//!
//! 1. `GET <issuer>/oauth/authorize` ([`begin`]): the client and its
//!    redirect URI are checked first, and refused on a page, never by a
//!    redirect (RFC 6749 section 4.1.2.1); then the other parameters, whose
//!    errors go back to the client with `iss` (RFC 9207). With several
//!    providers, a page chooses one (`/oauth/choose`); the browser goes on
//!    to it with a PKCE challenge (and, for OIDC, a nonce) of this server's own.
//! 2. `GET <issuer>/oauth/<provider>/callback` ([`callback`]): the
//!    provider's code is exchanged for the account (a provider that posts
//!    its answer, `form_post`, is relayed there first: [`relay`]), and the
//!    rules of `auth.toml` or the authorizer decide what it may do in the
//!    workspace the client asked for (`oauth::judge`). A consent page shows
//!    what the client would get.
//! 3. `POST <issuer>/oauth/consent` ([`decide`]): approved, the client gets
//!    an authorization code, redeemed at the token endpoint with its PKCE
//!    verifier; denied, an `access_denied` error.
//!
//! Each step is bound to the browser that started it by a cookie. The steps
//! before a sign-in keep nothing on the server: the request is sealed into
//! the chooser link ([`Pending`]) and a per-flow cookie (`Sealer`). Consents
//! and codes are kept in memory for minutes ([`Flows`]): a restart ends
//! authorizations under way.

mod begin;
mod callback;
mod consent;
mod cookies;
mod flows;
mod request;
#[cfg(test)]
mod tests;

pub use begin::*;
pub use callback::*;
pub use consent::*;
pub use cookies::*;
pub use flows::*;
use request::*;

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use bd_core::Error;

use super::cimd::Documents;
use super::clients::Client;
use super::form;
use super::pages::{self, Page};
#[cfg(test)]
use crate::auth;
use crate::oauth::Admitted;

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

/// `d` in words for a person: whole days, hours or minutes.
fn in_words(d: Duration) -> String {
    let secs = d.as_secs();
    let (n, unit) = if secs >= 86_400 && secs.is_multiple_of(86_400) {
        (secs / 86_400, "day")
    } else if secs >= 3_600 && secs.is_multiple_of(3_600) {
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

/// When a step started now must be done by.
fn until() -> i64 {
    now_millis() + i64::try_from(STEP_TTL.as_millis()).unwrap_or(i64::MAX)
}

/// What the pages call a client: its name, else its document's host.
fn client_name(client: &Client) -> String {
    match (&client.name, client.document) {
        (Some(name), _) => name.clone(),
        (None, true) => host_of(&client.id).to_string(),
        (None, false) => "Unnamed application".into(),
    }
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
