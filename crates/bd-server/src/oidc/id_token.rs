//! ID tokens, checked strictly, and the account they name.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::{Error, Result, Timestamp};
use serde_json::Value;

use crate::auth::Identity;

use super::*;

pub(super) fn header(token: &str) -> std::result::Result<Value, String> {
    let part = token.split('.').next().unwrap_or_default();
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| "its header is not base64url".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "its header is not JSON".to_string())
}

/// The claims of `token` if a key of `keys` signed it, for `client_id`
/// from `issuer`, valid at `now` (seconds), with `nonce` when given; else why not.
pub(super) fn verify(
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
pub(super) fn signed_claims(token: &str, keys: &[Jwk]) -> std::result::Result<Value, String> {
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
    if let Some(nonce) = nonce
        && claims["nonce"].as_str() != Some(nonce)
    {
        return Err("its nonce is not the sign-in's".into());
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

impl Oidc {
    /// The account an ID token's verified claims name.
    /// What an ID token's `claims` prove of the account `user`, for the rules.
    pub fn facts<'a>(&self, user: &'a Identity, claims: &Claims) -> crate::oauth::Listed<'a> {
        let groups = match &claims.all[&self.groups_claim] {
            Value::Array(list) => list.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            Value::String(one) => vec![one.clone()],
            _ => Vec::new(),
        };
        crate::oauth::Listed { user, email: claims.email.clone(), groups, fresh: true }
    }

    pub fn identity(&self, claims: &Claims) -> Identity {
        Identity {
            provider: self.name.clone(),
            issuer: self.issuer.clone(),
            subject: claims.subject.clone(),
            login: claims.login.clone(),
        }
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
}
