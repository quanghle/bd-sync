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
//! bd proves who signed in, and only that: an `[authorizer]` decides who
//! gets in (`authorizer.rs`). The account is its issuer and its `sub`
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bd_core::{Error, Result, Timestamp};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::Identity;

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

/// `[oidc.<name>]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcDoc {
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_secret_file: Option<PathBuf>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    response_mode: Option<String>,
    #[serde(default)]
    signed_secret: Option<SignedSecretDoc>,
    #[serde(default)]
    account_events: Option<Vec<String>>,
    #[serde(default)]
    allow: Vec<RuleDoc>,
    #[serde(default)]
    groups_claim: Option<String>,
}

/// `[[oidc.<name>.allow]]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDoc {
    #[serde(default)]
    anyone: bool,
    #[serde(default)]
    subjects: Vec<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    email_domains: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    role: Option<crate::auth::Role>,
    #[serde(default = "agent_kind")]
    kind: crate::auth::Kind,
    #[serde(default)]
    workspaces: Vec<String>,
    #[serde(default)]
    max_claims: Option<u32>,
}

fn agent_kind() -> crate::auth::Kind {
    crate::auth::Kind::Agent
}

/// One `[[oidc.<name>.allow]]` rule: whom of the provider's accounts it lets
/// in, and what their token may do. By `subjects` (the accounts' ids, which
/// bd keeps) or `anyone`, it is decided again at each refresh; by `emails`,
/// `email_domains` (the verified email) or `groups` (a claim of the ID
/// token), which bd does not keep, at sign-in only: a refresh keeps a
/// sign-in while the rule that let it in is still there, unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub anyone: bool,
    pub subjects: Vec<String>,
    /// Lowercased.
    pub emails: Vec<String>,
    /// Lowercased, without `@`.
    pub email_domains: Vec<String>,
    pub groups: Vec<String>,
    pub grant: crate::auth::Grant,
}

impl Rule {
    /// Whether it needs the ID token's claims, which a refresh does not have.
    fn needs_claims(&self) -> bool {
        !(self.emails.is_empty() && self.email_domains.is_empty() && self.groups.is_empty())
    }

    /// What tells this rule from any other, or from itself changed: kept
    /// with a sign-in it let in.
    pub fn fingerprint(&self) -> String {
        crate::auth::hash(&format!("{self:?}"))[..16].to_string()
    }

    /// What lets the account `subject` in by this rule, if anything: from
    /// `claims` at sign-in; at a refresh (no claims), a rule that needs them
    /// only if it is the one `kept` (its fingerprint) let the sign-in in.
    fn lets_in(
        &self,
        subject: &str,
        claims: Option<&Claims>,
        groups_claim: &str,
        kept: Option<&str>,
    ) -> Option<String> {
        if self.anyone {
            return Some("anyone".into());
        }
        if self.subjects.iter().any(|s| s == subject) {
            return Some("a listed account".into());
        }
        if !self.needs_claims() {
            return None;
        }
        let Some(claims) = claims else {
            return (kept == Some(self.fingerprint().as_str())).then(|| "as at sign-in".into());
        };
        if let Some(email) = claims.email.as_deref().map(str::to_lowercase) {
            if self.emails.contains(&email) {
                return Some("a listed email".into());
            }
            let domain = email.rsplit_once('@').map(|(_, d)| d.to_string()).unwrap_or_default();
            if self.email_domains.contains(&domain) {
                return Some(format!("an email at {domain}"));
            }
        }
        let groups: Vec<&str> = match &claims.all[groups_claim] {
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            Value::String(one) => vec![one.as_str()],
            _ => Vec::new(),
        };
        self.groups.iter().find(|g| groups.contains(&g.as_str())).map(|g| format!("member of {g}"))
    }
}

/// What the first of `rules` that lets the account in decides for
/// `workspace`, as GitHub's rules do (`oauth::decide`), and the fingerprint
/// of that rule.
pub fn decide(
    rules: &[Rule],
    subject: &str,
    claims: Option<&Claims>,
    groups_claim: &str,
    kept: Option<&str>,
    workspace: &str,
) -> (crate::oauth::Decision, Option<String>) {
    let mut elsewhere: Vec<String> = Vec::new();
    for rule in rules {
        let Some(via) = rule.lets_in(subject, claims, groups_claim, kept) else { continue };
        if rule.grant.allows_workspace(workspace) {
            let mut grant = rule.grant.clone();
            if !elsewhere.is_empty() {
                grant.workspaces = vec![workspace.to_string()];
            }
            return (crate::oauth::Decision::In { grant, via, by_login: true }, Some(rule.fingerprint()));
        }
        for w in &rule.grant.workspaces {
            if !elsewhere.contains(w) {
                elsewhere.push(w.clone());
            }
        }
    }
    match elsewhere.is_empty() {
        true => (crate::oauth::Decision::Out, None),
        false => (crate::oauth::Decision::Elsewhere(elsewhere), None),
    }
}

/// `[[oidc.<name>.allow]]` rule `n`, checked.
fn rule(at: &str, n: usize, r: RuleDoc) -> std::result::Result<Rule, String> {
    use crate::auth::{Grant, Kind, Role};
    let at = format!("[[{at}.allow]] rule {n}");
    let plain = |field: &str, list: Vec<String>, lower: bool| {
        list.into_iter()
            .map(|s| {
                let v = s.trim();
                let v = if lower { v.to_lowercase() } else { v.to_string() };
                match !v.is_empty() && v.len() <= 255 && v.chars().all(|c| !c.is_control() && !c.is_whitespace()) {
                    true => Ok(v),
                    false => Err(format!("{at}: {field} {s:?} is not one")),
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    let subjects = plain("subjects", r.subjects, false)?;
    let emails = plain("emails", r.emails, true)?;
    let email_domains: Vec<String> =
        plain("email_domains", r.email_domains, true)?.into_iter().map(|d| d.trim_start_matches('@').into()).collect();
    if let Some(e) = emails.iter().find(|e| !e.contains('@')) {
        return Err(format!("{at}: emails {e:?} is not an email"));
    }
    let groups = plain("groups", r.groups, false)?;
    let names_someone = !(subjects.is_empty() && emails.is_empty() && email_domains.is_empty() && groups.is_empty());
    if r.anyone {
        if names_someone {
            return Err(format!("{at} lets anyone in: drop its subjects, emails, email_domains and groups, or anyone"));
        }
        if r.role == Some(Role::Admin) || r.kind == Kind::Human {
            return Err(format!("{at} lets anyone in, so its role may be read or write and its kind agent only"));
        }
    } else if !names_someone {
        return Err(format!(
            "{at} names no subjects, emails, email_domains or groups, so it lets nobody in (anyone = true lets everyone)"
        ));
    }
    let role = r.role.unwrap_or(if r.anyone { Role::Read } else { Role::Write });
    let workspaces = crate::auth::workspace_list(&r.workspaces).map_err(|e| format!("{at}: {e}"))?;
    if r.max_claims == Some(0) {
        return Err(format!("{at}: max_claims must be at least 1"));
    }
    let grant = Grant { role, kind: r.kind, workspaces, max_claims: r.max_claims };
    Ok(Rule { anyone: r.anyone, subjects, emails, email_domains, groups, grant })
}

/// `[oidc.<name>.signed_secret]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedSecretDoc {
    key_file: PathBuf,
    key_id: String,
    team_id: String,
}

/// A client secret that is a JWT signed with the client's key, as Apple
/// takes them: ES256, `kid` the key's ID, `iss` the team's, `sub` the client
/// ID, `aud` the issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSecret {
    /// As written (relative to the root).
    pub key_file: PathBuf,
    pub key_id: String,
    pub team_id: String,
    /// Read by [`Oidc::load_secret`].
    key: Option<SigningKey>,
}

/// A P-256 private key, never shown.
#[derive(Clone)]
struct SigningKey(std::sync::Arc<ring::signature::EcdsaKeyPair>);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        use ring::signature::KeyPair;
        self.0.public_key().as_ref() == other.0.public_key().as_ref()
    }
}

impl Eq for SigningKey {}

/// How long a signed client secret is good for: one request's.
const SIGNED_FOR: i64 = 300;

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
    pub allow: Vec<Rule>,
    /// The ID token claim listing an account's groups, for rules' `groups`.
    pub groups_claim: String,
}

/// A client secret, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// `[oidc.<name>]` from what `auth.toml` says.
pub(crate) fn parse(name: &str, doc: OidcDoc) -> std::result::Result<Oidc, String> {
    let at = format!("oidc.{name}");
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if name.is_empty() || name.len() > 32 || !name.chars().all(plain) || name.starts_with('-') {
        return Err(format!("[{at}]: a provider's name is 1 to 32 lowercase letters, digits and dashes"));
    }
    if name == "github" {
        return Err("[oidc.github]: github names the [github] provider: choose another name".into());
    }
    let issuer = doc.issuer.trim().to_string();
    if !endpoint_ok(&issuer, &issuer) || issuer.contains(['?', '#', ' ']) {
        return Err(format!("{at}.issuer {issuer:?} is not an https URL without a query or fragment"));
    }
    let client_id = doc.client_id.trim().to_string();
    if client_id.is_empty() || client_id.len() > 255 || !client_id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{at}.client_id is not a client ID"));
    }
    if doc.client_secret_file.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        return Err(format!("{at}.client_secret_file is empty: name the file, or leave it out"));
    }
    let form_post = match doc.response_mode.as_deref() {
        None | Some("query") => false,
        Some("form_post") => true,
        Some(other) => return Err(format!("{at}.response_mode {other:?} is neither \"query\" nor \"form_post\"")),
    };
    let signed_secret = match doc.signed_secret {
        None => None,
        Some(_) if doc.client_secret_file.is_some() => {
            return Err(format!("{at}: client_secret_file or signed_secret, not both"));
        }
        Some(d) => {
            let plain = |id: &str| !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric());
            if d.key_file.as_os_str().is_empty() {
                return Err(format!("{at}.signed_secret.key_file is empty: name the file holding the key"));
            }
            if !plain(d.key_id.trim()) || !plain(d.team_id.trim()) {
                return Err(format!("{at}.signed_secret: key_id and team_id are IDs of letters and digits"));
            }
            Some(SignedSecret {
                key_file: d.key_file,
                key_id: d.key_id.trim().to_string(),
                team_id: d.team_id.trim().to_string(),
                key: None,
            })
        }
    };
    let account_events: Vec<String> =
        doc.account_events.unwrap_or_default().iter().map(|a| a.trim().to_string()).collect();
    if account_events.iter().any(|a| a.is_empty() || a.len() > 255 || !a.bytes().all(|b| b.is_ascii_graphic())) {
        return Err(format!("{at}.account_events lists the IDs the provider names the app by: not empty, plain"));
    }
    let label = doc.label.map(|l| l.trim().to_string()).unwrap_or_else(|| name.to_string());
    if !crate::oauth_server::clients::shows_plainly(&label, 40) {
        return Err(format!("{at}.label is empty, longer than 40 characters, or not plain text"));
    }
    let mut scopes = vec!["openid".to_string()];
    for scope in doc.scopes.unwrap_or_else(|| vec!["email".into(), "profile".into()]) {
        if scope.is_empty() || !scope.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\') {
            return Err(format!("{at}.scopes {scope:?} is not a scope"));
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(Oidc {
        name: name.to_string(),
        label,
        issuer,
        client_id,
        client_secret_file: doc.client_secret_file,
        client_secret: None,
        scopes,
        form_post,
        signed_secret,
        account_events,
        allow: doc
            .allow
            .into_iter()
            .enumerate()
            .map(|(i, r)| rule(&at, i + 1, r))
            .collect::<std::result::Result<_, _>>()?,
        groups_claim: doc.groups_claim.map(|g| g.trim().to_string()).unwrap_or_else(|| "groups".into()),
    })
}

/// The P-256 key of a PEM file (PKCS#8 with its public key, as Apple's
/// `.p8` keys are).
fn signing_key(path: &Path) -> std::result::Result<SigningKey, String> {
    use ureq::tls::PemItem;
    let pem = std::fs::read(path).map_err(|e| e.to_string())?;
    let key = ureq::tls::parse_pem(&pem)
        .find_map(|item| match item {
            Ok(PemItem::PrivateKey(k)) => Some(k),
            _ => None,
        })
        .ok_or("no private key in the file")?;
    let rng = ring::rand::SystemRandom::new();
    let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, key.der(), &rng)
        .map_err(|e| format!("not a P-256 key in PKCS#8 with its public key, as Apple's .p8 keys are ({e})"))?;
    Ok(SigningKey(std::sync::Arc::new(pair)))
}

/// Whether `url` is http to this machine (a stand-in provider, in tests).
fn loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // `http://127.0.0.1:80@example.com/` is example.com's.
    !authority.contains('@') && crate::remote::is_loopback(authority)
}

/// Whether `url` is one bd sends anything of a provider at `issuer` to:
/// https with no user info, or http to this machine for an issuer that is
/// itself http to this machine (a stand-in provider, in tests).
fn endpoint_ok(url: &str, issuer: &str) -> bool {
    match url.strip_prefix("https://") {
        Some(rest) => !rest.split(['/', '?', '#']).next().unwrap_or_default().contains('@'),
        None => loopback_http(issuer) && loopback_http(url),
    }
}

/// What a provider's discovery document says, of what bd uses.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// For `bd remote login` (RFC 8628), if it offers it.
    pub device_authorization_endpoint: Option<String>,
    /// Whether it takes the client secret in a Basic header (the default),
    /// rather than in the form.
    pub basic_auth: bool,
    /// Whether it names itself in each authorization response (`iss`,
    /// RFC 9207), which then must be there.
    pub iss_parameter: bool,
}

/// A key of a provider's JWKS.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Jwk {
    Rsa {
        kid: Option<String>,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// P-256: the uncompressed point.
    Ec {
        kid: Option<String>,
        point: Vec<u8>,
    },
}

impl Jwk {
    fn kid(&self) -> Option<&str> {
        match self {
            Jwk::Rsa { kid, .. } | Jwk::Ec { kid, .. } => kid.as_deref(),
        }
    }
}

/// Things fetched, by URL, with when they were fetched.
type Fetched<T> = Mutex<HashMap<String, (T, Instant)>>;

/// Discovery documents by issuer.
static DISCOVERED: LazyLock<Fetched<Metadata>> = LazyLock::new(Default::default);
/// Issuers whose discovery failed, with when.
static FAILED: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);
/// Key sets by JWKS URL.
static KEYS: LazyLock<Fetched<Vec<Jwk>>> = LazyLock::new(Default::default);
/// Key sets whose fetch failed, with when: not fetched again for [`FAILED_FOR`].
static KEYS_FAILED: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);
/// Held while a key set is fetched: one fetch at a time, the others then
/// finding it kept (or its failure), however many requests want keys.
static FETCHING_KEYS: Mutex<()> = Mutex::new(());

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

impl Oidc {
    /// Read the client secret, or the key that signs it (relative to `root`).
    pub(crate) fn load_secret(&mut self, root: &Path) -> std::result::Result<(), String> {
        if let Some(signed) = &mut self.signed_secret {
            let file = &signed.key_file;
            let path = if file.is_relative() { root.join(file) } else { file.clone() };
            let at = format!("oidc.{}.signed_secret.key_file {}", self.name, path.display());
            signed.key = Some(signing_key(&path).map_err(|e| format!("{at}: {e}"))?);
            return Ok(());
        }
        let Some(file) = &self.client_secret_file else { return Ok(()) };
        let path = if file.is_relative() { root.join(file) } else { file.clone() };
        let at = format!("oidc.{}.client_secret_file {}", self.name, path.display());
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{at}: {e}"))?;
        let secret = text.trim();
        if secret.is_empty() || secret.len() > 1024 || !secret.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("{at}: not a client secret (one line of printable characters)"));
        }
        self.client_secret = Some(Secret(secret.to_string()));
        Ok(())
    }

    /// The files holding its secrets (relative to the root, as written).
    pub fn secret_files(&self) -> impl Iterator<Item = &PathBuf> {
        self.client_secret_file.iter().chain(self.signed_secret.iter().map(|s| &s.key_file))
    }

    /// The client secret sent with a request now: the file's, or one
    /// signed for it.
    fn secret(&self) -> Result<Option<Secret>> {
        let Some(signed) = &self.signed_secret else { return Ok(self.client_secret.clone()) };
        let Some(SigningKey(pair)) = &signed.key else {
            return Err(Error::Io(std::io::Error::other("the signing key of a client secret was not read")));
        };
        let now = Timestamp::now().millis() / 1000;
        let header = serde_json::json!({ "alg": "ES256", "kid": signed.key_id });
        let claims = serde_json::json!({
            "iss": signed.team_id, "iat": now - 60, "exp": now + SIGNED_FOR, "aud": self.issuer, "sub": self.client_id,
        });
        let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
        let signed_part = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let rng = ring::rand::SystemRandom::new();
        let signature = pair
            .sign(&rng, signed_part.as_bytes())
            .map_err(|_| Error::Io(std::io::Error::other("signing a client secret failed")))?;
        Ok(Some(Secret(format!("{signed_part}.{}", b64(signature.as_ref())))))
    }

    /// The account an ID token's verified claims name.
    pub fn identity(&self, claims: &Claims) -> Identity {
        Identity {
            provider: self.name.clone(),
            issuer: self.issuer.clone(),
            subject: claims.subject.clone(),
            login: claims.login.clone(),
        }
    }

    /// The provider's discovery document, fetched or kept; failures are
    /// kept [`FAILED_FOR`].
    pub fn metadata(&self) -> Result<Metadata> {
        if lock(&FAILED).get(&self.issuer).is_some_and(|at| at.elapsed() < FAILED_FOR) {
            return Err(Error::Remote(format!("{} could not be reached; try again later", self.label)));
        }
        let fetched = self.discover();
        let mut failed = lock(&FAILED);
        match &fetched {
            Ok(_) => failed.remove(&self.issuer),
            Err(_) => failed.insert(self.issuer.clone(), Instant::now()),
        };
        fetched
    }

    fn discover(&self) -> Result<Metadata> {
        if let Some((md, at)) = lock(&DISCOVERED).get(&self.issuer) {
            if at.elapsed() < KEEP {
                return Ok(md.clone());
            }
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer.trim_end_matches('/'));
        let doc = self.get_json(&url, "its discovery document")?;
        let endpoint = |field: &str| {
            let value = doc[field].as_str().map(str::to_string);
            value
                .filter(|u| endpoint_ok(u, &self.issuer))
                .ok_or_else(|| self.unwell(format!("its discovery document has no https {field}")))
        };
        if doc["issuer"].as_str() != Some(self.issuer.as_str()) {
            return Err(self.unwell(format!(
                "its discovery document names issuer {:?}, not {:?}",
                doc["issuer"].as_str().unwrap_or_default(),
                self.issuer
            )));
        }
        let methods: Vec<&str> = doc["token_endpoint_auth_methods_supported"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let md = Metadata {
            authorization_endpoint: endpoint("authorization_endpoint")?,
            token_endpoint: endpoint("token_endpoint")?,
            jwks_uri: endpoint("jwks_uri")?,
            device_authorization_endpoint: doc["device_authorization_endpoint"]
                .as_str()
                .filter(|u| endpoint_ok(u, &self.issuer))
                .map(str::to_string),
            basic_auth: methods.is_empty()
                || methods.contains(&"client_secret_basic")
                || !methods.contains(&"client_secret_post"),
            iss_parameter: doc["authorization_response_iss_parameter_supported"] == true,
        };
        lock(&DISCOVERED).insert(self.issuer.clone(), (md.clone(), Instant::now()));
        Ok(md)
    }

    /// Where the browser signs in: the code comes back to `redirect_uri`
    /// with `state`, its ID token carries `nonce`, and its token is given
    /// only with the PKCE verifier whose S256 challenge is `challenge`.
    pub fn authorization_url(
        &self,
        md: &Metadata,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> String {
        let scope = self.scopes.join(" ");
        let query = [
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("scope", scope.as_str()),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ];
        let mode = [("response_mode", "form_post")];
        let query: Vec<(&str, &str)> = query.iter().chain(mode.iter().filter(|_| self.form_post)).copied().collect();
        let sep = if md.authorization_endpoint.contains('?') { '&' } else { '?' };
        format!("{}{sep}{}", md.authorization_endpoint, crate::oauth_server::form::encode(&query))
    }

    /// The ID token's verified claims for `code`, which came back to
    /// `redirect_uri` (`verifier` is its PKCE verifier, `nonce` the one the
    /// sign-in sent).
    pub fn sign_in(
        &self,
        md: &Metadata,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<Claims> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        let answer = self.token(md, &form)?;
        if let Some(error) = answer["error"].as_str() {
            return Err(Error::invalid(format!("{} refused the sign-in's code ({})", self.label, error_code(error))));
        }
        let Some(id_token) = answer["id_token"].as_str() else {
            return Err(self.unwell("its token endpoint gave no ID token".into()));
        };
        self.verify(md, id_token, Some(nonce))
    }

    /// POST `form` to the token endpoint, as this client: its JSON answer,
    /// or `{"error": ...}` when it refused.
    pub fn token(&self, md: &Metadata, form: &[(&str, &str)]) -> Result<Value> {
        self.post(md, &md.token_endpoint, form)
    }

    /// Start a sign-in from the command line (RFC 8628): the provider's
    /// answer (`device_code`, `user_code`, `verification_uri`, ...), or
    /// `Invalid` if it has no device flow.
    pub fn device(&self, md: &Metadata) -> Result<Value> {
        let Some(endpoint) = &md.device_authorization_endpoint else {
            return Err(Error::invalid(format!(
                "{} does not offer sign-in from the command line (the device flow); sign in from an MCP client in a \
                 browser instead",
                self.label
            )));
        };
        let scope = self.scopes.join(" ");
        let answer = self.post(md, endpoint, &[("scope", &scope)])?;
        if let Some(error) = answer["error"].as_str() {
            return Err(self.unwell(format!("its device endpoint refused: {}", error_code(error))));
        }
        Ok(answer)
    }

    /// POST `form` to `url` as this client (its ID, and its secret as the
    /// provider takes it): the JSON answer, or `{"error": ...}`.
    fn post(&self, md: &Metadata, url: &str, form: &[(&str, &str)]) -> Result<Value> {
        let mut form: Vec<(&str, &str)> = form.to_vec();
        form.push(("client_id", &self.client_id));
        let mut request = agent().post(url).header("accept", "application/json");
        let secret = self.secret()?;
        match (&secret, md.basic_auth) {
            (Some(Secret(secret)), true) => {
                let pair = format!("{}:{}", form_encode(&self.client_id), form_encode(secret));
                request = request.header("authorization", format!("Basic {}", STANDARD.encode(pair)));
            }
            (Some(Secret(secret)), false) => form.push(("client_secret", secret)),
            (None, _) => {}
        }
        let sent = request.send_form(form.iter().copied());
        let mut response = sent.map_err(|e| self.unreachable(url, e))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_string()
            .map_err(|e| self.unreachable(url, e))?;
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(error) = body["error"].as_str() {
            return Ok(serde_json::json!({ "error": error }));
        }
        if status != 200 {
            return Err(self.unwell(format!("{url} answered HTTP {status}")));
        }
        Ok(body)
    }

    /// The claims of `id_token`, if it is valid for this client now (and
    /// carries `nonce`, when one was sent).
    pub fn verify(&self, md: &Metadata, id_token: &str, nonce: Option<&str>) -> Result<Claims> {
        let now = Timestamp::now().millis() / 1000;
        let kid = header(id_token).ok().and_then(|h| h["kid"].as_str().map(str::to_string));
        let keys = self.keys(md, false)?;
        let known = kid.as_deref().is_none_or(|kid| keys.iter().any(|k| k.kid() == Some(kid)));
        let keys = if known { keys } else { self.keys(md, true)? };
        verify(id_token, &keys, &self.issuer, &self.client_id, nonce, now).map_err(|why| {
            tracing::warn!(target: "bd::serve", provider = %self.name, %why, "an ID token was refused");
            Error::Remote(format!("{} gave an ID token this bd server cannot accept; sign in again", self.label))
        })
    }

    /// The account notification posted as `body` (`{"payload": "<JWT>"}`),
    /// if the provider signed it, for one of `account_events`' audiences;
    /// `Invalid` with why not (logged, never shown).
    pub fn account_event(&self, md: &Metadata, body: &[u8]) -> Result<AccountEvent> {
        let refused = |why: String| {
            tracing::warn!(target: "bd::serve", provider = %self.name, %why, "an account notification was refused");
            Error::invalid(format!("not a notification of {}", self.label))
        };
        let body: Value = serde_json::from_slice(body).map_err(|_| refused("its body is not JSON".into()))?;
        let token = body["payload"].as_str().ok_or_else(|| refused("it has no payload".into()))?;
        let kid = header(token).ok().and_then(|h| h["kid"].as_str().map(str::to_string));
        let keys = self.keys(md, false)?;
        let known = kid.as_deref().is_none_or(|kid| keys.iter().any(|k| k.kid() == Some(kid)));
        let keys = if known { keys } else { self.keys(md, true)? };
        let now = Timestamp::now().millis() / 1000;
        account_event(token, &keys, &self.issuer, &self.account_events, now).map_err(refused)
    }

    /// The provider's signing keys: kept, or fetched again (`fresh`, for a
    /// key not kept, at most once a [`REFETCH`]).
    fn keys(&self, md: &Metadata, fresh: bool) -> Result<Vec<Jwk>> {
        let kept = || -> Option<Vec<Jwk>> {
            let keys = lock(&KEYS);
            let (keys, at) = keys.get(&md.jwks_uri)?;
            let age = at.elapsed();
            (age < KEEP && (!fresh || age < REFETCH)).then(|| keys.clone())
        };
        let failed = || lock(&KEYS_FAILED).get(&md.jwks_uri).is_some_and(|at| at.elapsed() < FAILED_FOR);
        if let Some(keys) = kept() {
            return Ok(keys);
        }
        let _fetching = lock(&FETCHING_KEYS);
        // Another request may have fetched them, or failed to, while this one waited.
        if let Some(keys) = kept() {
            return Ok(keys);
        }
        if failed() {
            return Err(self.unwell("its signing keys could not be had a moment ago".into()));
        }
        let fetched = self.get_json(&md.jwks_uri, "its signing keys").and_then(|doc| {
            let keys = jwks(&doc);
            match keys.is_empty() {
                true => Err(self.unwell("its JWKS has no RS256 or ES256 signing key".into())),
                false => Ok(keys),
            }
        });
        match &fetched {
            Ok(keys) => drop(lock(&KEYS).insert(md.jwks_uri.clone(), (keys.clone(), Instant::now()))),
            Err(_) => drop(lock(&KEYS_FAILED).insert(md.jwks_uri.clone(), Instant::now())),
        }
        fetched
    }

    fn get_json(&self, url: &str, what: &str) -> Result<Value> {
        let mut response =
            agent().get(url).header("accept", "application/json").call().map_err(|e| self.unreachable(url, e))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(self.unwell(format!("{what} answered HTTP {status}")));
        }
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_string()
            .map_err(|e| self.unreachable(url, e))?;
        serde_json::from_str(&text).map_err(|_| self.unwell(format!("{what} is not JSON")))
    }

    fn unreachable(&self, url: &str, e: ureq::Error) -> Error {
        tracing::warn!(target: "bd::serve", provider = %self.name, url, error = %e, "the OIDC provider did not answer");
        Error::Remote(format!("{} could not be reached; try again later", self.label))
    }

    fn unwell(&self, why: String) -> Error {
        tracing::warn!(target: "bd::serve", provider = %self.name, %why, "the OIDC provider's answer cannot be used");
        Error::Remote(format!("{} did not answer as expected; the server's admin finds why in its log", self.label))
    }
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

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(TIMEOUT))
        .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// `s` as `application/x-www-form-urlencoded`, as a Basic header's parts are (RFC 6749 section 2.3.1).
fn form_encode(s: &str) -> String {
    crate::oauth_server::form::encode(&[("", s)]).trim_start_matches('=').to_string()
}

/// The keys of a JWKS bd can verify with: RSA, and EC on P-256, for signing.
fn jwks(doc: &Value) -> Vec<Jwk> {
    let b64 = |v: &Value| v.as_str().and_then(|s| URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok());
    let mut keys = Vec::new();
    for key in doc["keys"].as_array().into_iter().flatten() {
        if key.get("use").is_some_and(|u| u != "sig") {
            continue;
        }
        let kid = key["kid"].as_str().map(str::to_string);
        let alg = key["alg"].as_str();
        match key["kty"].as_str() {
            Some("RSA") if alg.is_none_or(|a| a == "RS256") => {
                if let (Some(n), Some(e)) = (b64(&key["n"]), b64(&key["e"])) {
                    keys.push(Jwk::Rsa { kid, n, e });
                }
            }
            Some("EC") if key["crv"] == "P-256" && alg.is_none_or(|a| a == "ES256") => {
                if let (Some(x), Some(y)) = (b64(&key["x"]), b64(&key["y"])) {
                    if x.len() == 32 && y.len() == 32 {
                        keys.push(Jwk::Ec { kid, point: [&[4u8][..], &x, &y].concat() });
                    }
                }
            }
            _ => {}
        }
    }
    keys
}

fn header(token: &str) -> std::result::Result<Value, String> {
    let part = token.split('.').next().unwrap_or_default();
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| "its header is not base64url".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "its header is not JSON".to_string())
}

/// The claims of `token` if a key of `keys` signed it, for `client_id`
/// from `issuer`, valid at `now` (seconds), with `nonce` when given; else why not.
fn verify(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
    now: i64,
) -> std::result::Result<Claims, String> {
    let claims = signed_claims(token, keys)?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err(format!("its issuer is {:?}", claims["iss"]));
    }
    id_token_claims(claims, issuer, client_id, nonce, now)
}

/// The claims of `token` if a key of `keys` signed it (RS256 or ES256).
fn signed_claims(token: &str, keys: &[Jwk]) -> std::result::Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, signature] = parts[..] else { return Err("not three parts".into()) };
    let header = header(token)?;
    let alg = header["alg"].as_str().unwrap_or_default();
    let kid = header["kid"].as_str();
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| "its signature is not base64url")?;
    let signed = format!("{head}.{body}");
    let candidates = keys.iter().filter(|k| kid.is_none_or(|kid| k.kid() == Some(kid)));
    let good = candidates.into_iter().any(|key| match (alg, key) {
        ("RS256", Jwk::Rsa { n, e, .. }) => ring::signature::RsaPublicKeyComponents { n, e }
            .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &signature)
            .is_ok(),
        ("ES256", Jwk::Ec { point, .. }) => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(signed.as_bytes(), &signature)
                .is_ok()
        }
        _ => false,
    });
    if !matches!(alg, "RS256" | "ES256") {
        return Err(format!("it is signed with {alg:?}, not RS256 or ES256"));
    }
    if !good {
        return Err("no key of the provider's JWKS signed it".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| "its claims are not base64url")?;
    serde_json::from_slice(&bytes).map_err(|_| "its claims are not JSON".to_string())
}

/// What an account notification says happened to the account `subject`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountEvent {
    pub kind: AccountChange,
    pub subject: String,
    /// When it happened.
    pub at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountChange {
    /// It no longer lets this app sign it in: its sign-ins end.
    ConsentRevoked,
    /// It was deleted at the provider: bd forgets it.
    Deleted,
    /// Anything else (email forwarding turned on or off), named: bd keeps
    /// no email, so nothing to do.
    Other(String),
}

/// How old an account notification may be: the provider retries one it
/// could not deliver for a while; an older one is a replay.
const MAX_EVENT_AGE: i64 = 7 * 24 * 3600;

/// The event of the account notification `token` (Apple's server-to-server
/// notifications), if a key of `keys` signed it, from `issuer`, for one of
/// `audiences`, issued within [`MAX_EVENT_AGE`] of `now` (seconds).
fn account_event(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    audiences: &[String],
    now: i64,
) -> std::result::Result<AccountEvent, String> {
    let claims = signed_claims(token, keys)?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err(format!("its issuer is {:?}", claims["iss"]));
    }
    if !claims["aud"].as_str().is_some_and(|aud| audiences.iter().any(|a| a == aud)) {
        return Err(format!("its audience {:?} is not in account_events", claims["aud"]));
    }
    let iat = claims["iat"].as_i64().ok_or("it has no iat")?;
    if iat > now + SKEW || iat < now - MAX_EVENT_AGE {
        return Err(format!("it was issued at {iat}, too far from now"));
    }
    // A JSON object, or (as Apple sends it) a string of one.
    let events = match &claims["events"] {
        Value::String(text) => serde_json::from_str(text).map_err(|_| "its events are not JSON")?,
        other => other.clone(),
    };
    let subject = events["sub"].as_str().unwrap_or_default();
    if subject.is_empty() || subject.len() > MAX_SUBJECT || !subject.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("its subject is missing or not plain".into());
    }
    // Seconds, as Apple documents them; milliseconds read as such.
    let time = events["event_time"].as_i64().ok_or("it has no event_time")?;
    let millis = if time > 100_000_000_000 { time } else { time.saturating_mul(1000) };
    let kind = match events["type"].as_str().ok_or("it has no type")? {
        "consent-revoked" => AccountChange::ConsentRevoked,
        "account-deleted" | "account-delete" => AccountChange::Deleted,
        other => AccountChange::Other(error_code(other).to_string()),
    };
    Ok(AccountEvent { kind, subject: subject.to_string(), at: Timestamp::from_millis(millis) })
}

/// An ID token's `claims`, signed and from its issuer, if they are for
/// `client_id`, valid at `now` (seconds), with `nonce` when given.
fn id_token_claims(
    claims: Value,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
    now: i64,
) -> std::result::Result<Claims, String> {
    // For this client only: bd trusts no other audience (OIDC Core 3.1.3.7, step 3).
    let audiences: Vec<&Value> = match &claims["aud"] {
        Value::Array(a) => a.iter().collect(),
        one => vec![one],
    };
    if audiences.len() != 1 || audiences[0].as_str() != Some(client_id) {
        return Err("it is not for this client alone (aud)".into());
    }
    if claims["azp"].as_str().is_some_and(|a| a != client_id) {
        return Err("it was given to another client (azp)".into());
    }
    let exp = claims["exp"].as_i64().ok_or("it has no expiry")?;
    if now > exp + SKEW {
        return Err("it has expired".into());
    }
    if claims["iat"].as_i64().is_some_and(|iat| iat > now + SKEW) {
        return Err("it was issued in the future".into());
    }
    if let Some(nonce) = nonce {
        if claims["nonce"].as_str() != Some(nonce) {
            return Err("its nonce is not the sign-in's".into());
        }
    }
    let subject = claims["sub"].as_str().unwrap_or_default();
    if subject.is_empty() || subject.len() > MAX_SUBJECT || !subject.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("its subject is missing or not plain".into());
    }
    let verified = matches!(&claims["email_verified"], Value::Bool(true)) || claims["email_verified"] == "true";
    let email = claims["email"]
        .as_str()
        .filter(|_| verified)
        .filter(|e| crate::oauth_server::clients::shows_plainly(e, MAX_LOGIN));
    let username = claims["preferred_username"]
        .as_str()
        .map(str::trim)
        .filter(|u| !u.contains('@') && !looks_like_pseudonym(u))
        .filter(|u| crate::oauth_server::clients::shows_plainly(u, MAX_LOGIN));
    let login = username.map_or_else(|| pseudonym(issuer, subject), str::to_string);
    Ok(Claims { subject: subject.to_string(), login, email: email.map(str::to_string), all: claims })
}

/// Whether `name` has the form of a [`pseudonym`], whatever its case: a user
/// name chosen to be another account's pseudonym is no login.
fn looks_like_pseudonym(name: &str) -> bool {
    name.len() == 14 && name[..2].eq_ignore_ascii_case("u-") && name[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// The login of an account whose provider gives no user name: `u-` and 12
/// hex digits of the SHA-256 of its issuer and subject, which tell nothing
/// of the person and stay the same at each sign-in.
pub fn pseudonym(issuer: &str, subject: &str) -> String {
    format!("u-{}", &crate::auth::hash(&format!("{issuer}\n{subject}"))[..12])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const TEST_KEY: &str = include_str!("../tests/fixtures/github-app.pem");

    /// The RSA key pair of the test fixture.
    pub(crate) fn rsa() -> ring::signature::RsaKeyPair {
        use ureq::tls::PemItem;
        let key = ureq::tls::parse_pem(TEST_KEY.as_bytes())
            .find_map(|item| match item {
                Ok(PemItem::PrivateKey(k)) => Some(k),
                _ => None,
            })
            .unwrap();
        ring::signature::RsaKeyPair::from_der(key.der())
            .or_else(|_| ring::signature::RsaKeyPair::from_pkcs8(key.der()))
            .unwrap()
    }

    /// The JWKS of the test key, as `kid`.
    pub(crate) fn rsa_jwks(kid: &str) -> Value {
        let pair = rsa();
        let public = pair.public();
        let components: ring::rsa::PublicKeyComponents<Vec<u8>> = public.into();
        serde_json::json!({ "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(&components.n), "e": URL_SAFE_NO_PAD.encode(&components.e),
        }]})
    }

    /// `claims` as an ID token signed with the test key, as `kid`.
    pub(crate) fn rs256(kid: &str, claims: &Value) -> String {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
        let signed =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let pair = rsa();
        let mut signature = vec![0; pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        pair.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, signed.as_bytes(), &mut signature).unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(now: i64) -> Value {
        serde_json::json!({
            "iss": "https://idp.example", "aud": "bd-client", "sub": "248289761001", "exp": now + 300, "iat": now,
            "nonce": "n-1", "email": "alice@acme.example", "email_verified": true, "name": "Alice",
        })
    }

    #[test]
    fn providers_error_codes_are_shown_only_when_plain() {
        assert_eq!(error_code("invalid_grant"), "invalid_grant");
        for odd in ["", "bad\nline", "\u{1b}[31mred", "quote\"", &"x".repeat(65)] {
            assert_eq!(error_code(odd), "an error", "{odd:?}");
        }
    }

    #[test]
    fn providers_are_checked() {
        let doc =
            |text: &str| toml::from_str::<OidcDoc>(text).map_err(|e| e.to_string()).and_then(|d| parse("google", d));
        let o = doc("issuer = \"https://accounts.google.com\"\nclient_id = \"c\"").unwrap();
        assert_eq!((o.label.as_str(), o.scopes.join(" ")), ("google", "openid email profile".to_string()));
        let o = doc("issuer = \"https://idp.example\"\nclient_id = \"c\"\nlabel = \"Acme SSO\"\nscopes = [\"groups\", \"openid\"]")
            .unwrap();
        assert_eq!((o.label.as_str(), o.scopes.join(" ")), ("Acme SSO", "openid groups".to_string()));
        for (bad, says) in [
            ("issuer = \"http://idp.example\"\nclient_id = \"c\"", "not an https URL"),
            ("issuer = \"https://idp.example?x\"\nclient_id = \"c\"", "not an https URL"),
            ("issuer = \"https://idp.example\"\nclient_id = \"\"", "not a client ID"),
            ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nlabel = \"\"", "label"),
            ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nscopes = [\"a b\"]", "not a scope"),
            ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nsecret = \"s\"", "unknown field"),
        ] {
            let e = doc(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
        assert!(
            doc("issuer = \"https://u:p@idp.example\"\nclient_id = \"c\"").unwrap_err().contains("not an https URL")
        );
        assert!(doc("issuer = \"http://127.0.0.1:80@evil.example\"\nclient_id = \"c\"").is_err(), "not this machine");
        let issuer = "https://idp.example";
        assert!(endpoint_ok("https://idp.example/token", issuer));
        assert!(!endpoint_ok("https://u@idp.example/token", issuer));
        assert!(!endpoint_ok("http://127.0.0.1:9/token", issuer), "no plain http from an https issuer");
        assert!(endpoint_ok("http://127.0.0.1:9/token", "http://127.0.0.1:9"));
        assert!(!endpoint_ok("http://localhost:1@evil.example/token", "http://127.0.0.1:9"));
        let ok = || toml::from_str::<OidcDoc>("issuer = \"https://idp.example\"\nclient_id = \"c\"").unwrap();
        assert!(parse("github", ok()).unwrap_err().contains("choose another name"));
        assert!(parse("Google", ok()).unwrap_err().contains("lowercase"));
    }

    #[test]
    fn rules_let_accounts_in_by_subject_email_domain_or_group_and_refreshes_keep_to_them() {
        use crate::oauth::Decision;
        let doc = |text: &str| {
            let text = format!("issuer = \"https://idp.example\"\nclient_id = \"c\"\ngroups_claim = \"roles\"\n{text}");
            toml::from_str::<OidcDoc>(&text).map_err(|e| e.to_string()).and_then(|d| parse("corp", d))
        };
        let o = doc("[[allow]]\nsubjects = [\"s-admin\"]\nrole = \"admin\"\nkind = \"human\"\n\
             [[allow]]\nemails = [\"Bob@Acme.example\"]\n\
             [[allow]]\nemail_domains = [\"@acme.example\"]\nrole = \"read\"\n\
             [[allow]]\ngroups = [\"eng\"]\nworkspaces = [\"proj\"]\n")
        .unwrap();
        assert_eq!((o.allow.len(), o.groups_claim.as_str()), (4, "roles"));
        let claims = |email: Option<&str>, roles: Value| Claims {
            subject: "s1".into(),
            login: "u-x".into(),
            email: email.map(str::to_string),
            all: serde_json::json!({ "roles": roles }),
        };
        let at_sign_in =
            |subject: &str, c: &Claims, ws: &str| decide(&o.allow, subject, Some(c), &o.groups_claim, None, ws);
        let role = |d: &(Decision, Option<String>)| match &d.0 {
            Decision::In { grant, via, .. } => Some((grant.role, via.clone())),
            _ => None,
        };
        let none = claims(None, Value::Null);
        assert_eq!(
            role(&at_sign_in("s-admin", &none, "proj")),
            Some((crate::auth::Role::Admin, "a listed account".into()))
        );
        assert_eq!(
            role(&at_sign_in("s1", &claims(Some("bob@acme.example"), Value::Null), "x")).unwrap().1,
            "a listed email"
        );
        let domain = at_sign_in("s1", &claims(Some("carol@ACME.example"), Value::Null), "x");
        assert_eq!(role(&domain), Some((crate::auth::Role::Read, "an email at acme.example".into())));
        let group = at_sign_in("s1", &claims(None, serde_json::json!(["ops", "eng"])), "proj");
        assert_eq!(role(&group).unwrap().1, "member of eng");
        assert!(matches!(at_sign_in("s1", &claims(None, serde_json::json!("eng")), "other").0, Decision::Elsewhere(_)));
        assert!(matches!(at_sign_in("s1", &claims(Some("eve@evil.example"), Value::Null), "proj").0, Decision::Out));

        // A refresh has no claims: a subject decides again; a claims rule only as the one that let it in, unchanged.
        let refresh =
            |subject: &str, kept: Option<&str>| decide(&o.allow, subject, None, &o.groups_claim, kept, "proj");
        assert!(role(&refresh("s-admin", None)).is_some());
        let kept = domain.1.clone().unwrap();
        assert_eq!(role(&refresh("s1", Some(&kept))), Some((crate::auth::Role::Read, "as at sign-in".into())));
        assert!(matches!(refresh("s1", None).0, Decision::Out), "no claims, no rule kept");
        let changed = doc("[[allow]]\nsubjects = [\"s-admin\"]\nrole = \"admin\"\nkind = \"human\"\n\
             [[allow]]\nemail_domains = [\"acme.example\"]\nrole = \"write\"\n")
        .unwrap();
        let again = decide(&changed.allow, "s1", None, &changed.groups_claim, Some(&kept), "proj");
        assert!(matches!(again.0, Decision::Out), "the rule changed: the sign-in is not kept");

        for (bad, says) in [
            ("[[allow]]\nrole = \"read\"", "lets nobody in"),
            ("[[allow]]\nanyone = true\nsubjects = [\"x\"]", "drop its"),
            ("[[allow]]\nanyone = true\nrole = \"admin\"", "anyone in"),
            ("[[allow]]\nemails = [\"not-an-email\"]", "not an email"),
            ("[[allow]]\ngroups = [\"a b\"]", "not one"),
            ("[[allow]]\nsubjects = [\"x\"]\nsecret = 1", "unknown field"),
        ] {
            let e = doc(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }
    }

    #[test]
    fn account_notifications_are_verified_and_read() {
        let now = 1_800_000_000;
        let keys = jwks(&rsa_jwks("k1"));
        let apps = vec!["net.example.app".to_string(), "net.example.app.signin".to_string()];
        let check = |token: &str| account_event(token, &keys, "https://idp.example", &apps, now);
        let notice = |events: Value| {
            serde_json::json!({ "iss": "https://idp.example", "aud": "net.example.app", "iat": now - 60,
                "jti": "j1", "events": events })
        };
        let event = |kind: &str| serde_json::json!({ "type": kind, "sub": "001.abc.9", "event_time": now - 30 });
        // As Apple sends it: the events a string of JSON.
        let revoked = check(&rs256("k1", &notice(event("consent-revoked").to_string().into()))).unwrap();
        assert_eq!(
            revoked,
            AccountEvent {
                kind: AccountChange::ConsentRevoked,
                subject: "001.abc.9".into(),
                at: Timestamp::from_millis((now - 30) * 1000),
            }
        );
        assert_eq!(check(&rs256("k1", &notice(event("account-deleted")))).unwrap().kind, AccountChange::Deleted);
        let email = check(&rs256("k1", &notice(event("email-disabled")))).unwrap();
        assert_eq!(email.kind, AccountChange::Other("email-disabled".into()));
        let mut ms = event("consent-revoked");
        ms["event_time"] = ((now - 30) * 1000).into();
        assert_eq!(check(&rs256("k1", &notice(ms))).unwrap().at, revoked.at, "milliseconds read as such");

        let refused = |c: Value| check(&rs256("k1", &c)).unwrap_err();
        let mut c = notice(event("account-deleted"));
        c["aud"] = "net.other.app".into();
        assert!(refused(c).contains("audience"));
        let mut c = notice(event("account-deleted"));
        c["iss"] = "https://evil.example".into();
        assert!(refused(c).contains("issuer"));
        let mut c = notice(event("account-deleted"));
        c["iat"] = (now - MAX_EVENT_AGE - 1).into();
        assert!(refused(c).contains("too far"), "a replay");
        let mut c = notice(event("account-deleted"));
        c["events"]["sub"] = "".into();
        assert!(refused(c).contains("subject"));
        assert!(check(&rs256("k2", &notice(event("account-deleted")))).is_err(), "another key");
        let unsigned = rs256("k1", &notice(event("account-deleted")));
        let forged = format!("{}.{}", &unsigned[..unsigned.rfind('.').unwrap()], "AAAA");
        assert!(check(&forged).is_err(), "a forged signature");
    }

    #[test]
    fn id_tokens_are_verified_strictly() {
        let now = 1_800_000_000;
        let keys = jwks(&rsa_jwks("k1"));
        assert_eq!(keys.len(), 1);
        let check = |token: &str| verify(token, &keys, "https://idp.example", "bd-client", Some("n-1"), now);
        let good = check(&rs256("k1", &claims(now))).unwrap();
        assert_eq!(
            (good.subject.as_str(), good.login.as_str(), good.email.as_deref()),
            ("248289761001", "u-1978d011ddff", Some("alice@acme.example"))
        );
        assert_eq!(good.all["name"], "Alice");
        let with = |field: &str, value: Value| {
            let mut c = claims(now);
            c[field] = value;
            rs256("k1", &c)
        };
        let login = |token: &str| check(token).unwrap().login;
        assert_eq!(login(&with("preferred_username", "alice".into())), "alice", "a user name first");
        let anonymous = pseudonym("https://idp.example", "248289761001");
        assert!(anonymous.starts_with("u-") && anonymous.len() == 14, "{anonymous}");
        assert_eq!(login(&rs256("k1", &claims(now))), anonymous, "never the email, though verified");
        assert_eq!(check(&rs256("k1", &claims(now))).unwrap().email.as_deref(), Some("alice@acme.example"));
        assert_eq!(check(&with("email_verified", false.into())).unwrap().email, None);
        assert_eq!(login(&with("preferred_username", "alice@contoso.example".into())), anonymous, "Entra's UPN");
        assert_eq!(login(&with("preferred_username", "al\u{202e}ice".into())), anonymous);
        assert_ne!(pseudonym("https://other.example", "248289761001"), anonymous, "per issuer");
        // A user name chosen to be another account's pseudonym is not taken: the account gets its own.
        let squatter = pseudonym("https://idp.example", "someone-else").to_uppercase().replacen("U-", "u-", 1);
        assert_eq!(login(&with("preferred_username", squatter.into())), anonymous);
        assert_eq!(login(&with("preferred_username", "u-abc".into())), "u-abc", "not that form");
        let aud = |aud: Value, azp: Option<&str>| {
            let mut c = claims(now);
            c["aud"] = aud;
            if let Some(azp) = azp {
                c["azp"] = azp.into();
            }
            check(&rs256("k1", &c))
        };
        assert!(aud(serde_json::json!(["bd-client"]), None).is_ok(), "a list of one");
        assert!(
            aud(serde_json::json!(["bd-client", "other"]), Some("bd-client")).unwrap_err().contains("aud"),
            "another audience"
        );
        for (token, says) in [
            (with("iss", "https://evil.example".into()), "issuer"),
            (with("aud", "other".into()), "aud"),
            (with("exp", (now - 600).into()), "expired"),
            (with("iat", (now + 600).into()), "future"),
            (with("nonce", "n-2".into()), "nonce"),
            (with("sub", "".into()), "subject"),
            (rs256("k2", &claims(now)), "no key"),
        ] {
            let e = check(&token).unwrap_err();
            assert!(e.contains(says), "{says}: {e}");
        }
        assert!(aud(serde_json::json!(["bd-client", "other"]), None).unwrap_err().contains("aud"));
        assert!(aud("bd-client".into(), Some("other")).unwrap_err().contains("azp"));
        assert!(
            verify(&rs256("k1", &claims(now)), &keys, "https://idp.example", "bd-client", None, now).is_ok(),
            "no nonce to check"
        );
        // Tampered with, or signed with nothing or a shared secret.
        let token = rs256("k1", &claims(now));
        let parts: Vec<&str> = token.split('.').collect();
        let mut forged = claims(now);
        forged["sub"] = "admin".into();
        let tampered = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(forged.to_string()), parts[2]);
        assert!(check(&tampered).unwrap_err().contains("no key"));
        for alg in ["none", "HS256"] {
            let head = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": alg, "kid": "k1" }).to_string());
            let token = format!("{head}.{}.{}", parts[1], parts[2]);
            assert!(check(&token).unwrap_err().contains("not RS256 or ES256"), "{alg}");
        }
        assert!(check("a.b").is_err());
    }

    #[test]
    fn providers_like_apple_post_their_answers_and_take_signed_secrets() {
        use ring::signature::{ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let doc = |text: &str| {
            let text = format!("issuer = \"https://appleid.apple.com\"\nclient_id = \"com.example.bd\"\n{text}");
            toml::from_str::<OidcDoc>(&text).map_err(|e| e.to_string()).and_then(|d| parse("apple", d))
        };
        let signed = "[signed_secret]\nkey_file = \"AuthKey.p8\"\nkey_id = \"KEY123\"\nteam_id = \"TEAM123\"\n";
        let mut o = doc(&format!("response_mode = \"form_post\"\n{signed}")).unwrap();
        assert!(o.form_post && doc("").unwrap().signed_secret.is_none() && !doc("").unwrap().form_post);
        assert_eq!(o.secret_files().collect::<Vec<_>>(), [&PathBuf::from("AuthKey.p8")]);
        for (bad, says) in [
            ("response_mode = \"fragment\"", "neither"),
            (&format!("client_secret_file = \"s\"\n{signed}"), "not both"),
            ("[signed_secret]\nkey_file = \"k\"\nkey_id = \"K 1\"\nteam_id = \"T\"", "letters and digits"),
            ("[signed_secret]\nkey_file = \"\"\nkey_id = \"K\"\nteam_id = \"T\"", "key_file is empty"),
            ("[signed_secret]\nkey_file = \"k\"\nkey_id = \"K\"", "team_id"),
        ] {
            let e = doc(bad).unwrap_err();
            assert!(e.contains(says), "{bad}: {e}");
        }

        // The key: a .p8 file, as Apple gives them; another kind of key is refused.
        let dir = tempfile::tempdir().unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let pem =
            format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(pkcs8.as_ref()));
        std::fs::write(dir.path().join("AuthKey.p8"), pem).unwrap();
        assert!(o.secret().is_err(), "not read yet");
        o.load_secret(dir.path()).unwrap();
        assert!(!format!("{o:?}").contains(&STANDARD.encode(pkcs8.as_ref())[..20]), "never the key");
        let mut rsa_key = o.clone();
        std::fs::write(dir.path().join("rsa.pem"), include_str!("../tests/fixtures/github-app.pem")).unwrap();
        rsa_key.signed_secret.as_mut().unwrap().key_file = "rsa.pem".into();
        assert!(rsa_key.load_secret(dir.path()).unwrap_err().contains("not a P-256 key"));

        // Each secret: signed for the client, for a few minutes.
        let Secret(jwt) = o.secret().unwrap().unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let part = |i: usize| serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[i]).unwrap()).unwrap();
        assert_eq!(part(0), serde_json::json!({ "alg": "ES256", "kid": "KEY123" }));
        let claims = part(1);
        assert_eq!((&claims["iss"], &claims["sub"]), (&"TEAM123".into(), &"com.example.bd".into()));
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        let now = Timestamp::now().millis() / 1000;
        assert!(claims["exp"].as_i64().unwrap() <= now + SIGNED_FOR && claims["iat"].as_i64().unwrap() <= now);
        let public = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref());
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature).unwrap();

        let md = Metadata {
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            device_authorization_endpoint: None,
            basic_auth: false,
            iss_parameter: false,
        };
        let url = |o: &Oidc| o.authorization_url(&md, "https://bd.example/oauth/apple/callback", "s", "n", "c");
        assert!(url(&o).contains("&response_mode=form_post"), "{}", url(&o));
        assert!(!url(&doc("").unwrap()).contains("response_mode"));
    }

    #[test]
    fn es256_tokens_are_verified_too() {
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let point = pair.public_key().as_ref();
        let doc = serde_json::json!({ "keys": [
            { "kty": "EC", "crv": "P-256", "kid": "e1", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..]) },
            { "kty": "oct", "kid": "s1", "k": "c2VjcmV0" },
            { "kty": "RSA", "use": "enc", "kid": "x", "n": "AQAB", "e": "AQAB" },
        ]});
        let keys = jwks(&doc);
        assert_eq!(keys.len(), 1, "only signing keys bd can use");
        let now = 1_800_000_000;
        let head = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": "ES256", "kid": "e1" }).to_string());
        let signed = format!("{head}.{}", URL_SAFE_NO_PAD.encode(claims(now).to_string()));
        let signature = pair.sign(&rng, signed.as_bytes()).unwrap();
        let token = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
        assert!(verify(&token, &keys, "https://idp.example", "bd-client", Some("n-1"), now).is_ok());
    }
}
