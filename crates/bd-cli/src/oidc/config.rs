//! Providers as `auth.toml` configures them: `[oidc.<name>]`, client secrets and the keys that sign them.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::{Error, Result, Timestamp};
use serde::Deserialize;

use super::*;

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
    allow: Vec<crate::oauth::RuleDoc>,
    #[serde(default)]
    groups_claim: Option<String>,
    #[serde(default)]
    deny: Vec<String>,
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
pub(super) const SIGNED_FOR: i64 = 300;

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
    let deny = crate::oauth::deny_list(&at, doc.deny, crate::oauth::Proves::Oidc)?;
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
        allow: crate::oauth::rules(&at, doc.allow, crate::oauth::Proves::Oidc)?,
        groups_claim: doc.groups_claim.map(|g| g.trim().to_string()).unwrap_or_else(|| "groups".into()),
        deny,
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
pub(super) fn endpoint_ok(url: &str, issuer: &str) -> bool {
    match url.strip_prefix("https://") {
        Some(rest) => !rest.split(['/', '?', '#']).next().unwrap_or_default().contains('@'),
        None => loopback_http(issuer) && loopback_http(url),
    }
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
    pub(super) fn secret(&self) -> Result<Option<Secret>> {
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
}
