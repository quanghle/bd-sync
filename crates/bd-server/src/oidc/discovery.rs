//! Discovery documents and key sets: fetched, cached, and fetched again at most so often.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::{Error, Result};
use serde_json::Value;

use super::*;

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
pub(super) enum Jwk {
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
    pub(super) fn kid(&self) -> Option<&str> {
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

/// Held while a key set is fetched, one per JWKS URL: one fetch of each at
/// a time, the others then finding it kept (or its failure), however many
/// requests want keys; a slow provider holds up no other's.
static FETCHING_KEYS: LazyLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = LazyLock::new(Default::default);

/// The keys of a JWKS bd can verify with: RSA, and EC on P-256, for signing.
pub(super) fn jwks(doc: &Value) -> Vec<Jwk> {
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
                if let (Some(x), Some(y)) = (b64(&key["x"]), b64(&key["y"]))
                    && x.len() == 32
                    && y.len() == 32
                {
                    keys.push(Jwk::Ec { kid, point: [&[4u8][..], &x, &y].concat() });
                }
            }
            _ => {}
        }
    }
    keys
}

impl Oidc {
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
        if let Some((md, at)) = lock(&DISCOVERED).get(&self.issuer)
            && at.elapsed() < KEEP
        {
            return Ok(md.clone());
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

    /// The provider's signing keys: kept, or fetched again (`fresh`, for a
    /// key not kept, at most once a [`REFETCH`]).
    pub(super) fn keys(&self, md: &Metadata, fresh: bool) -> Result<Vec<Jwk>> {
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
        let fetching = lock(&FETCHING_KEYS).entry(md.jwks_uri.clone()).or_default().clone();
        let _fetching = lock(&fetching);
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

    pub(super) fn unreachable(&self, url: &str, e: ureq::Error) -> Error {
        tracing::warn!(target: "bd::serve", provider = %self.name, url, error = %e, "the OIDC provider did not answer");
        Error::Remote(format!("{} could not be reached; try again later", self.label))
    }

    pub(super) fn unwell(&self, why: String) -> Error {
        tracing::warn!(target: "bd::serve", provider = %self.name, %why, "the OIDC provider's answer cannot be used");
        Error::Remote(format!("{} did not answer as expected; the server's admin finds why in its log", self.label))
    }
}
