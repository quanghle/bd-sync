//! Client ID metadata documents (draft-ietf-oauth-client-id-metadata-document):
//! a client whose `client_id` is an https URL publishes its metadata at it,
//! as ChatGPT does at `https://chatgpt.com/oauth/client.json`.
//!
//! Anyone can make `bd serve` fetch such a URL, by naming it at the
//! authorization endpoint, so fetches are guarded: https only, to public
//! addresses only (checked by the resolver ureq connects with, so a name
//! cannot resolve once to a public address and again to a private one), no
//! redirects or proxies, a few at a time and one per host, small and quick.
//! Documents are cached for as long as their `Cache-Control: max-age` says,
//! within [`MAX_TTL`]. One expired is still used, for up to [`MAX_STALE`],
//! only while it cannot be fetched because every fetch, or another from its
//! host, is under way, so that slow hosts holding them cannot keep known
//! clients out; a host that does not answer, or answers with an error,
//! fails the authorization (draft section 5.1). Documents
//! of clients someone approved ([`Documents::keep`]) go last when the cache
//! is full, so that anyone naming many documents cannot push them out.
//!
//! A document's logo is fetched with it, the same way, and kept with it
//! (draft section 8.8): the consent page shows it from here, so the browser
//! asks no other site for it, and it cannot change between fetches.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bd_core::{Error, Result};
use serde_json::Value;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use super::clients::{self, Client};

/// The longest client ID URL taken.
const MAX_URL: usize = 1024;
/// The largest document read (the draft suggests 5 KB; ChatGPT's is 0.5).
const MAX_DOCUMENT: u64 = 8 << 10;
/// The largest logo read; a larger one is not shown.
const MAX_LOGO: u64 = 64 << 10;
/// How long fetching a document, and its logo after it, may take in all.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of that a logo may take: holding a fetch slot for a picture
/// is worth less than for the document.
const LOGO_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a document is kept without `max-age`, and at most.
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const MAX_TTL: Duration = Duration::from_secs(3600);
/// How long past its time a document is used while it cannot be fetched.
const MAX_STALE: Duration = Duration::from_secs(3600);
const MAX_CACHED: usize = 256;
/// Fetches at once, one per host; more wait for none and are refused.
const MAX_FETCHES: usize = 4;

/// Whether a client ID names its metadata document, rather than a client
/// registered here.
pub fn is_document_url(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

/// Fetches client metadata documents, and keeps them for a while.
pub struct Documents {
    agent: ureq::Agent,
    /// Off only in tests, to fetch from this machine over http.
    strict: bool,
    cache: Mutex<HashMap<String, Cached>>,
    /// The hosts fetched from now.
    fetching: Mutex<Vec<String>>,
}

/// A document kept.
struct Cached {
    /// When it is to be fetched again.
    until: Instant,
    client: Client,
    /// Whether someone approved its client.
    kept: bool,
}

/// Why a document could not be had.
enum Failed {
    /// Not fetched: every fetch, or another from its host, is under way.
    /// An expired copy may do meanwhile.
    Busy(Error),
    /// Its host did not answer, or not yet: no copy does, but one is kept.
    Transient(Error),
    /// Its host answered, with no good document.
    Final(Error),
}

impl Default for Documents {
    fn default() -> Documents {
        Documents::new()
    }
}

impl Documents {
    pub fn new() -> Documents {
        Documents::with(true)
    }

    fn with(strict: bool) -> Documents {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(strict)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(FETCH_TIMEOUT))
            .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
            .build();
        let resolver = Guarded { public_only: strict, inner: DefaultResolver::default() };
        Documents {
            agent: ureq::Agent::with_parts(config, DefaultConnector::new(), resolver),
            strict,
            cache: Mutex::new(HashMap::new()),
            fetching: Mutex::new(Vec::new()),
        }
    }

    /// The client whose ID is the URL `url`, from the cache or fetched.
    pub fn client(&self, url: &str) -> Result<Client> {
        let now = Instant::now();
        let mut stale = None;
        if let Some(cached) = lock(&self.cache).get(url) {
            if now < cached.until {
                return Ok(cached.client.clone());
            }
            if now < cached.until + MAX_STALE {
                stale = Some(cached.client.clone());
            }
        }
        check_url(url, self.strict).map_err(|e| Error::invalid(format!("client_id {url:?}: {e}")))?;
        let fetched = match Fetch::start(&self.fetching, host(url)) {
            Ok(_fetch) => self.fetch(url),
            Err(e) => Err(Failed::Busy(e)),
        };
        let (client, ttl) = match fetched {
            Ok(fetched) => fetched,
            Err(Failed::Busy(e)) => match stale {
                Some(client) => {
                    tracing::warn!(target: "bd::serve", url, error = %e, "using an expired client metadata document");
                    return Ok(client);
                }
                None => return Err(e),
            },
            Err(Failed::Transient(e)) => return Err(e),
            Err(Failed::Final(e)) => {
                lock(&self.cache).remove(url);
                return Err(e);
            }
        };
        let mut cache = lock(&self.cache);
        let kept = cache.remove(url).is_some_and(|c| c.kept);
        // Not to be kept: nor is the copy it replaces.
        if !ttl.is_zero() {
            insert(&mut cache, url, Cached { until: now + ttl, client: client.clone(), kept });
        }
        Ok(client)
    }

    /// Keep the document of `client` past others when the cache is full:
    /// someone approved it. One expired, or pushed out while the person
    /// signed in, counts as expired now, so that it is fetched again when
    /// next used, and meanwhile does for [`MAX_STALE`] while it cannot be
    /// fetched for other fetches. One its host said not to cache is not
    /// kept: approving it changes nothing.
    pub fn keep(&self, client: &Client) {
        if !client.cacheable {
            return;
        }
        let mut cache = lock(&self.cache);
        match cache.get_mut(&client.id) {
            Some(cached) => {
                cached.kept = true;
                cached.until = cached.until.max(Instant::now());
            }
            None => {
                let cached = Cached { until: Instant::now(), client: client.clone(), kept: true };
                insert(&mut cache, &client.id, cached);
            }
        }
    }

    /// Fetch the document at `url`. What its host answered (a status, a
    /// document) is told; why no host answered is only logged, as it would
    /// tell what names resolve to inside the server's network.
    fn fetch(&self, url: &str) -> std::result::Result<(Client, Duration), Failed> {
        let started = Instant::now();
        let error = |e: String| Error::Remote(format!("fetching the client metadata document {url:?}: {e}"));
        let failed = |e: String| Failed::Final(error(e));
        let unreachable = |e: ureq::Error| {
            tracing::warn!(target: "bd::serve", url, error = %e, "fetching a client metadata document");
            Failed::Transient(error("no answer from its host (details in the server log)".into()))
        };
        let mut response = self.agent.get(url).header("accept", "application/json").call().map_err(unreachable)?;
        let status = response.status().as_u16();
        if status == 429 || status >= 500 {
            return Err(Failed::Transient(error(format!("HTTP {status}"))));
        }
        if status != 200 {
            return Err(failed(format!("HTTP {status}")));
        }
        let ttl = ttl(response.headers().get("cache-control").and_then(|v| v.to_str().ok()));
        let text = match response.body_mut().with_config().limit(MAX_DOCUMENT).read_to_string() {
            Ok(text) => text,
            Err(ureq::Error::BodyExceedsLimit(_)) => {
                return Err(failed(format!("larger than {} KiB", MAX_DOCUMENT >> 10)));
            }
            Err(e) => return Err(unreachable(e)),
        };
        let doc: Value = serde_json::from_str(&text).map_err(|e| failed(format!("not JSON: {e}")))?;
        let mut client = document(url, &doc)
            .map_err(|e| Failed::Final(Error::invalid(format!("client metadata document {url:?}: {e}"))))?;
        let left = FETCH_TIMEOUT.saturating_sub(started.elapsed()).min(LOGO_TIMEOUT);
        let logo = logo_uri(doc.get("logo_uri"), self.strict);
        client.logo = logo.and_then(|logo| self.logo(&logo, left)).map(Into::into);
        client.cacheable = !ttl.is_zero();
        Ok((client, ttl))
    }

    /// The image at `url` as a `data:` URL, if it is a small PNG, JPEG, GIF
    /// or WebP image (by its bytes, whatever its type says): not SVG, which
    /// can hold more than a picture), within `time`. A logo that cannot be
    /// had is left out, not refused: the client is shown by its initial.
    fn logo(&self, url: &str, time: Duration) -> Option<String> {
        if time.is_zero() {
            return None;
        }
        let request = self.agent.get(url).config().timeout_global(Some(time)).build();
        let mut response = match request.header("accept", "image/*").call() {
            Ok(r) if r.status() == 200 => r,
            Ok(r) => {
                tracing::info!(target: "bd::serve", url, status = r.status().as_u16(), "client logo not shown");
                return None;
            }
            Err(e) => {
                tracing::info!(target: "bd::serve", url, error = %e, "client logo not shown");
                return None;
            }
        };
        let bytes = response.body_mut().with_config().limit(MAX_LOGO).read_to_vec().ok()?;
        let Some(kind) = image_kind(&bytes) else {
            tracing::info!(target: "bd::serve", url, "client logo not shown: not a PNG, JPEG, GIF or WebP image");
            return None;
        };
        Some(format!("data:{kind};base64,{}", STANDARD.encode(&bytes)))
    }
}

/// Cache `cached` as the document at `url`, making room: first by
/// dropping documents too old to use (but not whether they are kept),
/// then the one not kept to be fetched again soonest.
fn insert(cache: &mut HashMap<String, Cached>, url: &str, cached: Cached) {
    let now = Instant::now();
    cache.retain(|_, c| c.kept || now < c.until + MAX_STALE);
    if cache.len() >= MAX_CACHED {
        let first = cache.iter().min_by_key(|(_, c)| (c.kept, c.until)).map(|(k, _)| k.clone());
        cache.remove(&first.unwrap_or_default());
    }
    cache.insert(url.to_string(), cached);
}

/// The host of a client ID URL, without its port.
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    authority.rsplit_once(':').map_or(authority, |(host, _)| host)
}

/// One fetch of at most [`MAX_FETCHES`], from a host no other fetch is
/// from, until dropped.
struct Fetch<'a> {
    fetching: &'a Mutex<Vec<String>>,
    host: String,
}

impl<'a> Fetch<'a> {
    fn start(fetching: &'a Mutex<Vec<String>>, host: &str) -> Result<Fetch<'a>> {
        let mut hosts = lock(fetching);
        if hosts.iter().any(|h| h == host) {
            return Err(Error::Busy(format!("fetching another client metadata document from {host}; retry")));
        }
        if hosts.len() >= MAX_FETCHES {
            return Err(Error::Busy("fetching other client metadata documents; retry".into()));
        }
        hosts.push(host.to_string());
        Ok(Fetch { fetching, host: host.to_string() })
    }
}

impl Drop for Fetch<'_> {
    fn drop(&mut self) {
        let mut hosts = lock(self.fetching);
        if let Some(i) = hosts.iter().position(|h| *h == self.host) {
            hosts.swap_remove(i);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether `url` can be a client ID URL: https, a lowercase DNS name (one
/// document, one ID) with an optional port, and a path with no dot
/// segments; no user info, query or fragment.
fn check_url(url: &str, strict: bool) -> std::result::Result<(), &'static str> {
    if url.len() > MAX_URL {
        return Err("too long");
    }
    let rest = match url.strip_prefix("https://") {
        Some(rest) => rest,
        None if !strict => url.strip_prefix("http://").ok_or("not an https URL")?,
        None => return Err("not an https URL"),
    };
    let Some(slash) = rest.find('/') else { return Err("has no path") };
    let (authority, path) = rest.split_at(slash);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = crate::oauth::dns_name(host).is_some_and(|h| h == host) || !strict && host == "127.0.0.1";
    if !host_ok {
        return Err("its host is not a DNS name");
    }
    if port.is_some_and(|p| !(1..=5).contains(&p.len()) || p.parse::<u16>().map_or(true, |p| p == 0)) {
        return Err("its port is not valid");
    }
    if path == "/" {
        return Err("has no path");
    }
    let allowed = |b: u8| b.is_ascii_alphanumeric() || b"-._~/%!$&'()*+,;=:@".contains(&b);
    if !path.bytes().all(allowed) {
        return Err("its path has characters other than a URL path's (or a query or fragment)");
    }
    let mut bytes = path.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%'
            && !(bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                && bytes.next().is_some_and(|b| b.is_ascii_hexdigit()))
        {
            return Err("its path has a bad percent-encoding");
        }
    }
    let dots = |s: &str| matches!(s.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | "..");
    if path.split('/').any(dots) {
        return Err("its path has dot segments");
    }
    Ok(())
}

/// The client a metadata document fetched from `url` describes.
fn document(url: &str, doc: &Value) -> std::result::Result<Client, String> {
    let Some(doc) = doc.as_object() else { return Err("not a JSON object".into()) };
    if doc.get("client_id").and_then(Value::as_str) != Some(url) {
        return Err("its client_id is not the URL it is served at".into());
    }
    if doc.contains_key("client_secret") || doc.contains_key("client_secret_expires_at") {
        return Err("has a client secret, which a public document must not".into());
    }
    // A public client: `none`, or (as ChatGPT says) a list of methods with it.
    let method = doc.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("none");
    let also_none = doc
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .is_some_and(|methods| methods.iter().any(|m| m == "none"));
    if method != "none" && !also_none {
        return Err(format!("its token_endpoint_auth_method is {method:?}: bd serve takes public clients only (none)"));
    }
    clients::check_types(doc, true).map_err(|(_, e)| e)?;
    let redirect_uris = clients::string_list(doc.get("redirect_uris"), "redirect_uris", clients::MAX_REDIRECTS * 4)
        .map_err(|(_, e)| e)?;
    // A name that cannot be shown is left out, not the client: the page
    // shows the document's host instead.
    let name = clients::client_name(doc.get("client_name")).unwrap_or(None);
    Ok(Client { id: url.to_string(), name, redirect_uris, document: true, logo: None, cacheable: true })
}

/// The media type of an image, by its first bytes, if it is one shown.
fn image_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// The longest `logo_uri` shown.
const MAX_LOGO_URI: usize = 1024;

/// A document's `logo_uri`, if it is fetched: an `https` URL with a host
/// and no credentials, of plain characters (no `;`, `,`, quotes, spaces,
/// `*` or fragment). Any other is left out rather than refused: the client
/// still works, shown by its initial. Off `strict` (in tests only), http
/// too.
fn logo_uri(value: Option<&Value>, strict: bool) -> Option<String> {
    let uri = value?.as_str()?;
    let rest = uri.strip_prefix("https://").or_else(|| uri.strip_prefix("http://").filter(|_| !strict))?;
    let host = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
    let plain = |c: char| c.is_ascii_alphanumeric() || "-._~/:%?=&+".contains(c);
    let shown = uri.len() <= MAX_LOGO_URI && !host.is_empty() && !host.starts_with(':') && uri.chars().all(plain);
    shown.then(|| uri.to_string())
}

/// How long a document may be kept, from its `Cache-Control`.
fn ttl(cache_control: Option<&str>) -> Duration {
    let Some(cc) = cache_control else { return DEFAULT_TTL };
    let mut ttl = DEFAULT_TTL;
    for directive in cc.split(',').map(|d| d.trim().to_ascii_lowercase()) {
        if directive == "no-store" || directive == "no-cache" {
            return Duration::ZERO;
        }
        if let Some(secs) = directive.strip_prefix("max-age=") {
            ttl = secs.trim_matches('"').parse().map_or(Duration::ZERO, Duration::from_secs);
        }
    }
    ttl.min(MAX_TTL)
}

/// ureq's resolver, refusing names that resolve to any address that is not
/// public.
#[derive(Debug)]
struct Guarded {
    public_only: bool,
    inner: DefaultResolver,
}

impl Resolver for Guarded {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> std::result::Result<ResolvedSocketAddrs, ureq::Error> {
        let addrs = self.inner.resolve(uri, config, timeout)?;
        match addrs.iter().find(|a| self.public_only && !is_public(a.ip())) {
            Some(a) => Err(ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} resolves to {}, which is not a public address", uri.host().unwrap_or_default(), a.ip()),
            ))),
            None => Ok(addrs),
        }
    }
}

/// Whether `ip` is a public unicast address: not this machine, a private
/// or shared network, link-local, multicast, reserved or documentation,
/// nor an IPv6 address that maps or tunnels to IPv4 ones.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Global unicast (2000::/3), less IETF protocol assignments and Teredo
    // (2001::/23), documentation (2001:db8::/32, 3fff::/20) and 6to4 (2002::/16).
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] < 0x200)
        && !(s[0] == 0x2001 && s[1] == 0xdb8)
        && s[0] != 0x2002
        && (s[0] & 0xfff0) != 0x3ff0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn client_id_urls_are_https_urls_with_a_path() {
        for ok in [
            "https://chatgpt.com/oauth/client.json",
            "https://claude.ai/oauth/mcp-oauth-client-metadata",
            "https://example.com:8443/a/b%20c",
        ] {
            assert_eq!(check_url(ok, true), Ok(()), "{ok}");
        }
        for bad in [
            "http://chatgpt.com/oauth/client.json",
            "https://chatgpt.com",
            "https://chatgpt.com/",
            "https://user@chatgpt.com/c",
            "https://chatgpt.com/c?x=1",
            "https://chatgpt.com/c#x",
            "https://chatgpt.com/a/../c",
            "https://chatgpt.com/a/%2E%2e/c",
            "https://chatgpt.com/./c",
            "https://chatgpt.com/a%zz",
            "https://chatgpt.com/a\\b",
            "https://ChatGPT.com/c",
            "https://127.0.0.1/c",
            "https://[::1]/c",
            "https://localhost/c",
            "https://chatgpt.com:0/c",
            "https://chatgpt.com:99999/c",
            "https://chatgpt.com:/c",
            "https://chat gpt.com/c",
            "https://chatgpt.com/c d",
        ] {
            assert!(check_url(bad, true).is_err(), "{bad}");
        }
        assert!(check_url(&format!("https://a.com/{}", "x".repeat(MAX_URL)), true).is_err());
        assert_eq!(check_url("http://127.0.0.1:1/c", false), Ok(()));
        assert!(is_document_url("https://chatgpt.com/oauth/client.json"));
        assert!(!is_document_url("bdc_0123"));
    }

    #[test]
    fn only_plain_https_logos_are_shown() {
        let logo = |v: serde_json::Value| logo_uri(Some(&v), true);
        let shown = "https://cdn.example:8443/brand/logo-1.png?v=2&s=64";
        assert_eq!(logo(serde_json::json!(shown)).as_deref(), Some(shown));
        for not_shown in [
            "http://cdn.example/logo.png",
            "https://",
            "https:///logo.png",
            "https://:443/logo.png",
            "https://user:pw@cdn.example/logo.png",
            "https://cdn.example/a;script-src *",
            "https://cdn.example/a,b.png",
            "https://cdn.example/a b.png",
            "https://cdn.example/a'b.png",
            "https://cdn.example/*.png",
            "https://cdn.example/l.png#x",
            "data:image/png;base64,AAAA",
        ] {
            assert_eq!(logo(serde_json::json!(not_shown)), None, "{not_shown}");
        }
        assert_eq!(logo(serde_json::json!(format!("https://cdn.example/{}", "a".repeat(MAX_LOGO_URI)))), None);
        assert_eq!(logo(serde_json::json!(7)), None);
        assert_eq!(logo_uri(None, true), None);
    }

    #[test]
    fn documents_describe_public_clients_at_their_own_url() {
        let url = "https://chatgpt.com/oauth/client.json";
        // ChatGPT's own, as served.
        let chatgpt = serde_json::json!({
            "client_id": url, "client_uri": "https://chatgpt.com/",
            "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
            "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "client_name": "ChatGPT",
            "logo_uri": "https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
            "token_endpoint_auth_signing_alg": "RS256", "jwks_uri": "https://chatgpt.com/oauth/jwks.json"
        });
        let client = document(url, &chatgpt).unwrap();
        assert_eq!(client.name.as_deref(), Some("ChatGPT"));
        assert_eq!(client.redirect_uris, ["https://chatgpt.com/connector_platform_oauth_redirect"]);
        assert!(client.document);
        let logo = logo_uri(chatgpt.get("logo_uri"), true);
        assert_eq!(logo.as_deref(), Some("https://persistent.oaistatic.com/sonic/misc/openai-logo.png"));
        assert_eq!(client.logo, None, "fetched with the document, not read from it");
        // The Claude apps', as served: with a grant bd does not offer, left aside.
        let claude_url = "https://claude.ai/oauth/mcp-oauth-client-metadata";
        let claude = serde_json::json!({
            "client_id": claude_url, "client_name": "Claude", "client_uri": "https://claude.ai",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "response_types": ["code"], "token_endpoint_auth_method": "none"
        });
        let client = document(claude_url, &claude).unwrap();
        assert_eq!(client.name.as_deref(), Some("Claude"));
        assert_eq!(client.redirect_uris, ["https://claude.ai/api/mcp/auth_callback"]);
        assert_eq!(logo_uri(claude.get("logo_uri"), true), None);
        let minimal = serde_json::json!({ "client_id": url, "redirect_uris": ["https://a.com/cb"] });
        assert_eq!(document(url, &minimal).unwrap().name, None);

        let with = |field: &str, value: Value| {
            let mut doc = minimal.clone();
            doc[field] = value;
            document(url, &doc).unwrap_err()
        };
        assert!(with("client_id", "https://evil.example/c".into()).contains("not the URL"));
        assert!(with("client_secret", "s".into()).contains("secret"));
        assert!(with("token_endpoint_auth_method", "private_key_jwt".into()).contains("public clients only"));
        assert!(with("token_endpoint_auth_method", "client_secret_basic".into()).contains("public clients only"));
        assert!(with("redirect_uris", serde_json::json!([])).contains("redirect_uris"));
        assert!(with("redirect_uris", serde_json::json!("https://a.com/cb")).contains("redirect_uris"));
        assert!(with("grant_types", serde_json::json!(["client_credentials"])).contains("grant_types"));
        assert!(with("grant_types", serde_json::json!(["refresh_token"])).contains("authorization_code"));
        assert!(with("response_types", serde_json::json!(["token"])).contains("response_types"));
        assert!(
            document(url, &{
                let mut doc = minimal.clone();
                doc["response_types"] = serde_json::json!(["code", "token"]);
                doc
            })
            .is_ok()
        );
        let unnamed = |name: serde_json::Value| {
            let mut doc = minimal.clone();
            doc["client_name"] = name;
            document(url, &doc).unwrap().name
        };
        assert_eq!(unnamed(serde_json::json!(7)), None, "a name that cannot be shown is left out");
        assert_eq!(unnamed(serde_json::json!("Chat\u{202E}TPG")), None);
        assert!(document(url, &serde_json::json!([])).unwrap_err().contains("object"));
    }

    #[test]
    fn documents_are_kept_as_long_as_they_say_within_bounds() {
        assert_eq!(ttl(None), DEFAULT_TTL);
        assert_eq!(ttl(Some("public, max-age=300")), Duration::from_secs(300));
        assert_eq!(ttl(Some("max-age=86400")), MAX_TTL);
        assert_eq!(ttl(Some("max-age=60, no-store")), Duration::ZERO);
        assert_eq!(ttl(Some("no-cache")), Duration::ZERO);
        assert_eq!(ttl(Some("max-age=x")), Duration::ZERO);
        assert_eq!(ttl(Some("private")), DEFAULT_TTL);
    }

    #[test]
    fn only_public_addresses_are_fetched_from() {
        for public in ["8.8.8.8", "104.18.32.47", "2606:4700::6812:202f", "2001:4860:4860::8888", "::ffff:8.8.8.8"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "3fff::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        assert!(is_public("172.32.0.1".parse().unwrap()) && is_public("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn strict_fetches_refuse_private_addresses_before_connecting() {
        let resolver = Guarded { public_only: true, inner: DefaultResolver::default() };
        let uri: Uri = "https://127.0.0.1:1/c".parse().unwrap();
        let config = ureq::Agent::config_builder().build();
        let timeout = NextTimeout {
            after: ureq::unversioned::transport::time::Duration::NotHappening,
            reason: ureq::Timeout::Global,
        };
        let e = resolver.resolve(&uri, &config, timeout).unwrap_err().to_string();
        assert!(e.contains("not a public address"), "{e}");
    }

    /// A server on this machine for `/client.json`: answers each connection
    /// with what `answers` makes of the document's URL, in turn; the number of
    /// connections it served, once done.
    fn serve<A: AsRef<[u8]> + Send + 'static>(
        answers: impl FnOnce(&str) -> Vec<A>,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/client.json", listener.local_addr().unwrap());
        let answers = answers(&url);
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut served = 0;
            for answer in answers {
                let mut conn = loop {
                    match listener.accept() {
                        Ok((conn, _)) => break conn,
                        Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                        Err(_) => return served,
                    }
                };
                conn.set_nonblocking(false).unwrap();
                let mut buf = [0u8; 4096];
                let _ = conn.read(&mut buf);
                conn.write_all(answer.as_ref()).unwrap();
                served += 1;
            }
            served
        });
        (url, handle)
    }

    fn answer(status: &str, headers: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}", body.len())
    }

    fn doc(url: &str) -> String {
        serde_json::json!({ "client_id": url, "redirect_uris": ["http://127.0.0.1:9/cb"], "client_name": "T" })
            .to_string()
    }

    #[test]
    fn documents_are_fetched_once_while_fresh() {
        let docs = Documents::with(false);
        let (url, server) = serve(|url| vec![answer("200 OK", "cache-control: max-age=60\r\n", &doc(url))]);
        for _ in 0..3 {
            let client = docs.client(&url).unwrap();
            assert_eq!((client.id.as_str(), client.name.as_deref()), (url.as_str(), Some("T")));
        }
        assert_eq!(server.join().unwrap(), 1);

        let (url, server) = serve(|url| vec![answer("200 OK", "cache-control: no-store\r\n", &doc(url)); 2]);
        let client = docs.client(&url).unwrap();
        assert!(!client.cacheable);
        docs.keep(&client);
        assert!(!lock(&docs.cache).contains_key(&url), "approving it does not keep it");
        docs.client(&url).unwrap();
        assert_eq!(server.join().unwrap(), 2, "not kept");
    }

    #[test]
    fn fetches_take_one_small_document_and_follow_nothing() {
        let docs = Documents::with(false);
        type Make = fn(&str) -> String;
        let cases: [(&str, Make); 5] = [
            ("HTTP 302", |_| answer("302 Found", "location: http://127.0.0.1:9/c\r\n", "")),
            ("HTTP 404", |_| answer("404 Not Found", "", "")),
            ("larger than 8 KiB", |_| answer("200 OK", "", &" ".repeat(9 << 10))),
            ("not JSON", |_| answer("200 OK", "", "<html>")),
            ("not the URL", |_| answer("200 OK", "", &doc("http://127.0.0.1:9/client.json"))),
        ];
        for (expected, make) in cases {
            let (url, server) = serve(|url| vec![make(url)]);
            let e = docs.client(&url).unwrap_err().to_string();
            assert!(e.contains(expected), "{expected}: {e}");
            server.join().unwrap();
        }
        let e = Documents::new().client("http://127.0.0.1:9/client.json").unwrap_err().to_string();
        assert!(e.contains("not an https URL"), "{e}");
        // Nothing listens there: why is not told.
        let e = docs.client("http://127.0.0.1:9/client.json").unwrap_err().to_string();
        assert!(e.contains("no answer from its host (details in the server log)") && !e.contains("refused"), "{e}");
    }

    #[test]
    fn logos_are_fetched_small_and_only_as_pictures() {
        let docs = Documents::with(false);
        let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[0; 24]].concat();
        let image = |body: &[u8]| {
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
            [head.as_bytes(), body].concat()
        };
        let (url, server) = serve(|_| vec![image(&png)]);
        assert_eq!(docs.logo(&url, LOGO_TIMEOUT), Some(format!("data:image/png;base64,{}", STANDARD.encode(&png))));
        server.join().unwrap();

        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
        let large = [png.as_slice(), &vec![0; MAX_LOGO as usize]].concat();
        for not_shown in [image(svg), image(b"<html>"), image(&large), answer("404 Not Found", "", "").into_bytes()] {
            let (url, server) = serve(|_| vec![not_shown]);
            assert_eq!(docs.logo(&url, LOGO_TIMEOUT), None);
            server.join().unwrap();
        }
        // A logo host that does not answer in time holds the fetch no longer.
        let (url, server) = serve(|_| vec![image(&png)]);
        assert_eq!(docs.logo(&url, Duration::ZERO), None);
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = Instant::now();
        assert_eq!(
            docs.logo(&format!("http://{}/l.png", silent.local_addr().unwrap()), Duration::from_millis(200)),
            None
        );
        assert!(at.elapsed() < Duration::from_secs(2), "{:?}", at.elapsed());
        drop(server);
        assert_eq!(image_kind(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(image_kind(b"GIF89a..."), Some("image/gif"));
        assert_eq!(image_kind(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_kind(b"RIFF\0\0\0\0WAVE"), None);
    }

    #[test]
    fn a_document_comes_with_its_logo_inside() {
        let docs = Documents::with(false);
        let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[7; 16]].concat();
        let (url, server) = serve(|url| {
            let doc = serde_json::json!({
                "client_id": url, "redirect_uris": ["http://127.0.0.1:9/cb"], "client_name": "T",
                "logo_uri": url.replace("client.json", "logo.png"),
            })
            .to_string();
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", png.len());
            vec![answer("200 OK", "cache-control: max-age=60\r\n", &doc).into_bytes(), [head.as_bytes(), &png].concat()]
        });
        let client = docs.client(&url).unwrap();
        assert_eq!(client.logo.as_deref(), Some(format!("data:image/png;base64,{}", STANDARD.encode(&png)).as_str()));
        assert!(client.cacheable);
        assert_eq!(server.join().unwrap(), 2, "the document, then its logo");
        // Kept with the document: shared, not fetched again.
        let again = docs.client(&url).unwrap();
        assert!(std::sync::Arc::ptr_eq(client.logo.as_ref().unwrap(), again.logo.as_ref().unwrap()));
    }

    #[test]
    fn only_a_few_fetches_run_at_once_one_per_host() {
        let fetching = Mutex::new(Vec::new());
        let hosts: Vec<String> = (0..=MAX_FETCHES).map(|i| format!("h{i}.example")).collect();
        let held: Vec<_> = hosts[..MAX_FETCHES].iter().map(|h| Fetch::start(&fetching, h).unwrap()).collect();
        assert!(matches!(Fetch::start(&fetching, &hosts[MAX_FETCHES]), Err(Error::Busy(_))));
        drop(held);
        assert!(lock(&fetching).is_empty());
        let one = Fetch::start(&fetching, "h0.example").unwrap();
        let e = Fetch::start(&fetching, "h0.example").err().unwrap().to_string();
        assert!(e.contains("from h0.example"), "{e}");
        assert!(Fetch::start(&fetching, "h1.example").is_ok());
        drop(one);
        assert!(Fetch::start(&fetching, "h0.example").is_ok());
        assert_eq!(host("https://a.example:8443/c.json"), "a.example");
        assert_eq!(host("https://a.example/c.json"), "a.example");
    }

    #[test]
    fn approved_clients_documents_go_last_and_unkept_answers_replace_nothing() {
        let docs = Documents::with(false);
        let (url, server) = serve(|url| vec![answer("200 OK", "", &doc(url)); 2]);
        let client = docs.client(&url).unwrap();
        docs.keep(&client);
        lock(&docs.cache).get_mut(&url).unwrap().until = Instant::now();
        docs.client(&url).unwrap();
        assert!(lock(&docs.cache)[&url].kept, "still kept, fetched again");
        server.join().unwrap();
        // Anyone naming documents fills the cache: approved ones stay, expired or not.
        lock(&docs.cache).get_mut(&url).unwrap().until = Instant::now();
        for i in 1..MAX_CACHED {
            let until = Instant::now() + MAX_TTL;
            lock(&docs.cache)
                .insert(format!("https://x{i}.example/c"), Cached { until, client: client.clone(), kept: false });
        }
        let (other, server) = serve(|url| vec![answer("200 OK", "", &doc(url))]);
        docs.client(&other).unwrap();
        server.join().unwrap();
        let cache = lock(&docs.cache);
        assert!(cache.contains_key(&url) && cache.contains_key(&other));
        assert_eq!(cache.len(), MAX_CACHED);
        drop(cache);
        // Pushed out while the person signed in: approved, it comes back, to be fetched again.
        let pushed = lock(&docs.cache).remove(&other).unwrap().client;
        docs.keep(&pushed);
        let cache = lock(&docs.cache);
        assert!(cache[&other].kept && cache[&other].until <= Instant::now());
        assert_eq!(cache.len(), MAX_CACHED);
        drop(cache);
        // Too old to use, it is still kept, and approved again it does for another day.
        if let Some(old) = Instant::now().checked_sub(MAX_STALE + Duration::from_secs(1)) {
            lock(&docs.cache).get_mut(&other).unwrap().until = old;
            docs.keep(&Client { id: "https://new.example/client".into(), ..pushed.clone() });
            assert!(lock(&docs.cache)[&other].kept && lock(&docs.cache).len() == MAX_CACHED);
            let before = Instant::now();
            docs.keep(&pushed);
            assert!(lock(&docs.cache)[&other].until >= before);
        }
        // A document not to be kept takes the one before with it.
        let (url, server) = serve(|url| {
            vec![answer("200 OK", "", &doc(url)), answer("200 OK", "cache-control: no-store\r\n", &doc(url))]
        });
        docs.client(&url).unwrap();
        lock(&docs.cache).get_mut(&url).unwrap().until = Instant::now();
        docs.client(&url).unwrap();
        assert!(!lock(&docs.cache).contains_key(&url));
        server.join().unwrap();
    }

    #[test]
    fn an_expired_document_does_only_while_every_fetch_is_taken() {
        let docs = Documents::with(false);
        let expire = |url: &str| {
            let mut cache = lock(&docs.cache);
            let at = Instant::now();
            cache.get_mut(url).unwrap().until = at;
        };
        let (url, server) = serve(|url| {
            vec![
                answer("200 OK", "", &doc(url)),
                answer("503 Service Unavailable", "", ""),
                answer("200 OK", "", &doc(url)),
            ]
        });
        docs.client(&url).unwrap();
        expire(&url);
        // Its host failing: the authorization fails (draft section 5.1), but the copy is kept...
        assert!(docs.client(&url).unwrap_err().to_string().contains("HTTP 503"));
        assert!(lock(&docs.cache).contains_key(&url));
        // ...for while every fetch, or another from its host, is under way.
        let held = Fetch::start(&docs.fetching, "127.0.0.1").unwrap();
        assert_eq!(docs.client(&url).unwrap().name.as_deref(), Some("T"));
        drop(held);
        docs.client(&url).unwrap();
        assert_eq!(server.join().unwrap(), 3);
        // Its host saying it is gone: gone.
        let (gone, server) = serve(|url| vec![answer("200 OK", "", &doc(url)), answer("404 Not Found", "", "")]);
        docs.client(&gone).unwrap();
        expire(&gone);
        assert!(docs.client(&gone).unwrap_err().to_string().contains("HTTP 404"));
        assert!(!lock(&docs.cache).contains_key(&gone));
        server.join().unwrap();
        // Not one too old (on a machine up long enough to tell).
        if let Some(old) = Instant::now().checked_sub(MAX_STALE + Duration::from_secs(1)) {
            lock(&docs.cache).get_mut(&url).unwrap().until = old;
            let held = Fetch::start(&docs.fetching, "127.0.0.1").unwrap();
            assert!(matches!(docs.client(&url), Err(Error::Busy(_))));
            drop(held);
        }
    }
}
