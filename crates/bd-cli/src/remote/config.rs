//! Which remote workspace an invocation uses: `--remote`, `$BD_REMOTE` or
//! `.bd/remote.toml`, the CA certificates its server is trusted through, and
//! the access token sent to it.

use std::path::{Path, PathBuf};

use bd_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Configured, Remote, Source, env};
use crate::app::App;
use crate::credentials;
use crate::protocol::valid_workspace_name;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemoteFile {
    pub(super) url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ca_cert: Option<PathBuf>,
}

pub(super) fn missing_token(url: &str, ca: Option<&Path>) -> Error {
    Error::Unauthorized(format!(
        "no access token for {url}: sign in with `bd remote login --provider <name>` (where the \
         server offers sign-in), save a token from the server's admin with `bd remote login`, or set BD_TOKEN with {}",
        env_setup(url, ca)
    ))
}

fn env_token_refused(url: &str, file: &Path, ca: Option<&Path>) -> Error {
    Error::Unauthorized(format!(
        "$BD_TOKEN is not sent to {url}, named by {}: it goes only to the server named by --remote or $BD_REMOTE, \
         since a checkout's remote.toml may name any server. If the token is for {url}, set {}; or save a token \
         for it with `bd remote login`",
        file.display(),
        env_setup(url, ca)
    ))
}

/// The variables that send `$BD_TOKEN` to `url`: under `$BD_REMOTE` a
/// checkout's `ca_cert` is not read, so a private CA must be named again.
fn env_setup(url: &str, ca: Option<&Path>) -> String {
    match ca {
        Some(ca) => format!("BD_REMOTE={url} and BD_CA_CERT={}", ca.display()),
        None => format!("BD_REMOTE={url}"),
    }
}

/// The remote workspace configured for this invocation, if any.
pub fn configured(app: &App) -> Result<Option<Configured>> {
    let g = &app.g;
    let (url, source, ca_cert) = match g.remote.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(_) if g.db.is_some() => {
            return Err(Error::invalid("both --remote ($BD_REMOTE) and --db ($BD_DB) are set; use one"));
        }
        Some(url) => (url.to_string(), Source::Flag, None),
        None if g.db.is_some() => return Ok(None),
        None => match remote_file(&app.cwd) {
            Some(path) => {
                let file = read_remote_file(&path)?;
                let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
                let ca = file.ca_cert.map(|c| if c.is_relative() { dir.join(c) } else { c });
                (file.url, Source::File(path), ca)
            }
            None => return Ok(None),
        },
    };
    let url = check_url(&url)?;
    let ca_cert = env("BD_CA_CERT").map(PathBuf::from).or(ca_cert);
    Ok(Some(Configured { url, source, ca_cert }))
}

/// An access token, and where it came from.
pub(super) enum Token {
    Env(String),
    Saved(credentials::Saved),
}

impl Token {
    pub(super) fn secret(self) -> String {
        match self {
            Token::Env(t) => t,
            Token::Saved(s) => s.token,
        }
    }

    /// A remote sending this token, renewing it if it is a saved sign-in's.
    pub(super) fn remote(self, c: Configured, trust: Trust) -> Remote {
        match self {
            Token::Env(t) => Remote::new(c, trust, t),
            Token::Saved(s) => Remote::new(c, trust, s.token.clone()).renewing(&s),
        }
    }
}

/// What a remote's server certificate is checked against, read once per
/// process: the saved-token check and every request use this same snapshot,
/// so a CA file changed meanwhile (a `git checkout`) cannot slip in.
#[derive(Clone)]
pub struct Trust {
    /// The CA file, or `None` for the system's certificate authorities.
    pub(super) path: Option<PathBuf>,
    pub(super) certs: Option<Vec<ureq::tls::Certificate<'static>>>,
    /// [`credentials::SYSTEM_CA`], or the SHA-256 of the certificates (DER, so
    /// line endings do not matter): what a saved token is bound to.
    pub(super) anchor: String,
}

impl Trust {
    pub fn load(ca_cert: Option<&Path>) -> Result<Trust> {
        let Some(path) = ca_cert else {
            return Ok(Trust { path: None, certs: None, anchor: credentials::SYSTEM_CA.to_string() });
        };
        let certs = read_ca(path)?;
        let mut hash = Sha256::new();
        for cert in &certs {
            hash.update(cert.der());
        }
        let anchor = format!("sha256:{}", hash.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
        Ok(Trust { path: Some(path.to_path_buf()), certs: Some(certs), anchor })
    }
}

/// The access token for a workspace URL reached under `trust`: `$BD_TOKEN`
/// when the user's own `--remote` or `$BD_REMOTE` names the URL, else one
/// saved by `bd remote login` for it.
pub(super) fn token_for(url: &str, trust: &Trust, source: &Source) -> Result<Option<Token>> {
    let env_token = env("BD_TOKEN");
    if let (Some(t), Source::Flag) = (&env_token, source) {
        return Ok(Some(Token::Env(t.clone())));
    }
    // A checkout's remote.toml may name any server and CA: $BD_TOKEN, bound to
    // no URL, never goes there, or a cloned repository could collect it.
    let Some(saved) = credentials::lookup(url)? else {
        return match (env_token, source) {
            (Some(_), Source::File(path)) => Err(env_token_refused(url, path, trust.path.as_deref())),
            _ => Ok(None),
        };
    };
    // A CA named by a checkout's remote.toml must be the one the token was
    // saved under, or a cloned repository could send it to a man in the
    // middle. $BD_CA_CERT is the user's own setting.
    if env("BD_CA_CERT").is_none() && trust.anchor != saved.ca {
        let ca_cert = trust.path.as_deref();
        let then = match (saved.ca.as_str(), ca_cert) {
            (credentials::SYSTEM_CA, _) => "the system's certificate authorities",
            (_, Some(_)) => "another CA certificate",
            (_, None) => "a CA certificate",
        };
        let now = ca_cert.map_or_else(
            || "the system's certificate authorities".to_string(),
            |p| format!("the CA certificate {}", p.display()),
        );
        return Err(Error::Unauthorized(format!(
            "the access token saved for {} is not sent to {url}: it was saved trusting {then}, and {url} is now \
             set up to trust {now}. If that CA is trusted, log in again here (`bd remote login`); or set BD_TOKEN with \
             {}",
            saved.key,
            env_setup(url, ca_cert)
        )));
    }
    Ok(Some(Token::Saved(saved)))
}

/// The certificates of a PEM CA file.
fn read_ca(path: &Path) -> Result<Vec<ureq::tls::Certificate<'static>>> {
    ca_certificates(path).map_err(|e| Error::invalid(format!("CA certificate {e}")))
}

/// The certificates of a PEM CA file; the error starts with its path, for
/// the caller to say which setting named it.
pub fn ca_certificates(path: &Path) -> std::result::Result<Vec<ureq::tls::Certificate<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(format!("{}: no certificate in the file", path.display()));
    }
    Ok(certs)
}

/// The remote workspace this invocation uses, or `None` for a local one.
pub fn detect(app: &App) -> Result<Option<Remote>> {
    let Some(c) = configured(app)? else { return Ok(None) };
    let trust = Trust::load(c.ca_cert.as_deref())?;
    let token = token_for(&c.url, &trust, &c.source)?.ok_or_else(|| missing_token(&c.url, trust.path.as_deref()))?;
    Ok(Some(token.remote(c, trust)))
}

/// The nearest `.bd/remote.toml`, unless a nearer `.bd/bd.db` comes first.
pub(super) fn remote_file(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let bd = dir.join(".bd");
        let path = bd.join("remote.toml");
        if path.is_file() {
            return Some(path);
        }
        if bd.join("bd.db").is_file() {
            return None;
        }
    }
    None
}

fn read_remote_file(path: &Path) -> Result<RemoteFile> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
}

/// `http(s)://host[:port][/prefix]/w/<workspace>`, without a trailing slash.
pub(super) fn check_url(raw: &str) -> Result<String> {
    let url = raw.trim().trim_end_matches('/');
    let bad =
        |why: &str| Error::invalid(format!("remote URL {raw:?} {why}; expected https://host[:port]/w/<workspace>"));
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad("has no scheme"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, String::new()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad("needs a host and no embedded credentials"));
    }
    if url.contains(['?', '#']) {
        return Err(bad("must not have a query or fragment"));
    }
    if !path.rsplit_once("/w/").is_some_and(|(_, name)| valid_workspace_name(name)) {
        return Err(bad("does not end in /w/<workspace>"));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(url.to_string()),
        "http" if is_loopback(authority) || env("BD_INSECURE_HTTP").as_deref() == Some("1") => Ok(url.to_string()),
        "http" => Err(Error::invalid(format!(
            "refusing plain HTTP to {authority}: the access token would cross the network unencrypted. Use https, \
             or set BD_INSECURE_HTTP=1 on an encrypted private network"
        ))),
        _ => Err(bad("must use https or http")),
    }
}

pub fn is_loopback(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_urls() {
        assert_eq!(check_url("https://bd.example.com/w/proj/").unwrap(), "https://bd.example.com/w/proj");
        assert!(check_url("https://example.com/bd/w/proj").is_ok(), "behind a path prefix");
        assert!(check_url("http://127.0.0.1:7420/w/proj").is_ok(), "loopback may use http");
        assert!(check_url("http://[::1]:7420/w/proj").is_ok());
        assert!(check_url("http://localhost/w/proj").is_ok());
        for bad in [
            "bd.example.com/w/proj",
            "https://bd.example.com",
            "https://bd.example.com/w/",
            "https://bd.example.com/w/a/b",
            "https://user:pw@bd.example.com/w/proj",
            "https://bd.example.com/w/proj?x=1",
            "ftp://bd.example.com/w/proj",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_http_only_to_loopback() {
        if env("BD_INSECURE_HTTP").is_none() {
            let e = check_url("http://bd.example.com/w/proj").unwrap_err();
            assert!(e.to_string().contains("unencrypted"), "{e}");
        }
        assert!(is_loopback("127.0.0.1:1") && is_loopback("[::1]:1") && is_loopback("LOCALHOST"));
        assert!(!is_loopback("10.0.0.1:7420") && !is_loopback("bd.example.com"));
    }
}
