//! OpenID Connect providers: people sign in to `bd serve` with any OIDC
//! provider (Google, Microsoft Entra, GitLab, Okta, Keycloak, or a broker
//! such as Dex in front of others), as `auth.toml` names them:
//!
//! ```toml
//! [oidc.google]
//! issuer = "https://accounts.google.com"     # its discovery document is at <issuer>/.well-known/openid-configuration
//! client_id = "1234.apps.googleusercontent.com"
//! client_secret_file = "google-secret"       # relative to the root; leave out for a public client
//! label = "Google"                           # shown on the sign-in page (default: the table's name)
//! scopes = ["email", "profile"]              # asked for besides openid (this is the default)
//! ```
//!
//! A provider that sends its answers to the browser as a form it posts
//! (`response_mode = "form_post"`, which Apple requires when scopes are
//! asked for) is relayed to the callback by `serve/`. A provider whose
//! client secret is a JWT signed with a key of the client's (Apple's) gets
//! one bd signs for each request, from `[oidc.<name>.signed_secret]`. With
//! `account_events`, the provider's notifications of accounts that revoked
//! their consent or were deleted (Apple's server-to-server notifications)
//! are taken at `<issuer>/oauth/<name>/events` ([`Oidc::account_event`]).
//!
//! bd proves who signed in here; `[[oidc.<name>.allow]]` rules
//! (`oauth/rules.rs`), or an `[authorizer]` (`authorizer.rs`), decide who
//! gets in. The account is its issuer and its `sub`
//! claim, which never changes. Its login, which its actor is made of, is
//! never an email: its `preferred_username` unless that is one (Entra's is
//! the user principal name), else a pseudonym of the account ([`pseudonym`]),
//! as actors stay in workspaces' histories for good. Its email, if the
//! provider verified it, goes to the authorizer and the consent page only:
//! bd keeps it nowhere.
//!
//! ID tokens are checked strictly: signed with RS256 or ES256 by a key of
//! the provider's JWKS (fetched over https, cached, fetched again at most
//! once a minute for a key it does not have), from the issuer, for this
//! client alone (`aud` exactly the client ID; `azp`, when present, too), not
//! expired, and carrying the nonce of the sign-in.

mod config;
mod discovery;
mod events;
mod flow;
mod id_token;
#[cfg(test)]
pub(crate) mod tests;

pub use config::*;
pub use discovery::*;
pub use events::*;
pub use id_token::*;

use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde_json::Value;

/// How long a provider whose discovery failed is not asked again: sign-ins
/// fail at once meanwhile, rather than each wait for it.
const FAILED_FOR: Duration = Duration::from_secs(30);
/// How long discovery documents and key sets are kept.
const KEEP: Duration = Duration::from_secs(3600);
/// A key set is fetched again for a key it lacks at most this often.
const REFETCH: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest discovery document, key set or token answer read.
const MAX_ANSWER: u64 = 256 << 10;
/// Clocks may differ this much.
const SKEW: i64 = 120;
/// The longest `sub` taken.
const MAX_SUBJECT: usize = 255;
/// The longest login shown.
const MAX_LOGIN: usize = 100;

/// An OIDC provider, as `auth.toml` configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oidc {
    /// The table's name: how tokens, accounts and the sign-in page name it.
    pub name: String,
    /// What the sign-in page shows.
    pub label: String,
    /// Exactly as its ID tokens' `iss` says it.
    pub issuer: String,
    pub client_id: String,
    /// As written (relative to the root).
    pub client_secret_file: Option<PathBuf>,
    /// Read by [`Oidc::load_secret`].
    pub client_secret: Option<Secret>,
    /// Asked for, `openid` first.
    pub scopes: Vec<String>,
    /// Whether its answers come back as a form posted to the callback.
    pub form_post: bool,
    /// Its client secret signed for each request, instead of a file's.
    pub signed_secret: Option<SignedSecret>,
    /// The audiences of the account notifications it sends that bd takes
    /// (Apple names the app by its primary App ID, or the client ID); none:
    /// it takes none.
    pub account_events: Vec<String>,
    /// `[[oidc.<name>.allow]]`: who of its accounts get in, without an authorizer.
    pub allow: Vec<crate::oauth::Rule>,
    /// The ID token claim listing an account's groups, for rules' `groups`.
    pub groups_claim: String,
    /// Subjects (`sub`) of accounts that may never sign in, whatever the
    /// rules or the authorizer say.
    pub deny: Vec<String>,
}

/// A client secret, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What an ID token says of the account, once verified.
#[derive(Clone, Debug, PartialEq)]
pub struct Claims {
    pub subject: String,
    pub login: String,
    /// Its email, only if the provider verified it.
    pub email: Option<String>,
    /// All of them, for the authorizer (groups, tenant, ...).
    pub all: Value,
}

/// A provider's `error` code, if it is one (RFC 6749 section 5.2: printable
/// ASCII but `"` and `\\`), for messages and the log; else what stands in.
pub fn error_code(code: &str) -> &str {
    let plain = |b: u8| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\';
    match !code.is_empty() && code.len() <= 64 && code.bytes().all(plain) {
        true => code,
        false => "an error",
    }
}

/// The one HTTP client of every provider's requests: its connections (and
/// their TLS sessions) serve the next request to the same host.
fn agent() -> ureq::Agent {
    static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(TIMEOUT))
            .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .into()
    });
    AGENT.clone()
}

/// `s` as `application/x-www-form-urlencoded`, as a Basic header's parts are (RFC 6749 section 2.3.1).
fn form_encode(s: &str) -> String {
    crate::oauth_server::form::encode(&[("", s)]).trim_start_matches('=').to_string()
}
