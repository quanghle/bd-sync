//! Client ID metadata documents (draft-ietf-oauth-client-id-metadata-document):
//! a client whose `client_id` is an https URL publishes its metadata at it,
//! as ChatGPT does at `https://chatgpt.com/oauth/client.json`.
//!
//! Anyone can make `bd serve` fetch such a URL, by naming it at the
//! authorization endpoint, so fetches are guarded: https only, to public
//! addresses only (checked by the resolver ureq connects with, so a name
//! cannot resolve once to a public address and again to a private one), no
//! redirects or proxies, a few at a time, small and quick. Documents are
//! cached for as long as their `Cache-Control: max-age` says, within
//! [`MAX_TTL`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a document is kept without `max-age`, and at most.
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const MAX_TTL: Duration = Duration::from_secs(3600);
const MAX_CACHED: usize = 256;
/// Fetches at once; more wait for none and are refused.
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
    cache: Mutex<HashMap<String, (Instant, Client)>>,
    fetching: AtomicUsize,
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
            fetching: AtomicUsize::new(0),
        }
    }

    /// The client whose ID is the URL `url`, from the cache or fetched.
    pub fn client(&self, url: &str) -> Result<Client> {
        let now = Instant::now();
        if let Some((until, client)) = lock(&self.cache).get(url) {
            if now < *until {
                return Ok(client.clone());
            }
        }
        check_url(url, self.strict).map_err(|e| Error::invalid(format!("client_id {url:?}: {e}")))?;
        let _fetch = Fetch::start(&self.fetching)?;
        let (client, ttl) = self.fetch(url)?;
        if !ttl.is_zero() {
            let mut cache = lock(&self.cache);
            cache.retain(|_, (until, _)| now < *until);
            if cache.len() >= MAX_CACHED {
                let soonest = cache.iter().min_by_key(|(_, (until, _))| *until).map(|(k, _)| k.clone());
                cache.remove(&soonest.unwrap_or_default());
            }
            cache.insert(url.to_string(), (now + ttl, client.clone()));
        }
        Ok(client)
    }

    /// Fetch the document at `url`. What its host answered (a status, a
    /// document) is told; why no host answered is only logged, as it would
    /// tell what names resolve to inside the server's network.
    fn fetch(&self, url: &str) -> Result<(Client, Duration)> {
        let failed = |e: String| Error::Remote(format!("fetching the client metadata document {url:?}: {e}"));
        let unreachable = |e: ureq::Error| {
            tracing::warn!(target: "bd::serve", url, error = %e, "fetching a client metadata document");
            failed("no answer from its host (details in the server log)".into())
        };
        let mut response = self.agent.get(url).header("accept", "application/json").call().map_err(unreachable)?;
        let status = response.status().as_u16();
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
        let client =
            document(url, &doc).map_err(|e| Error::invalid(format!("client metadata document {url:?}: {e}")))?;
        Ok((client, ttl))
    }
}

/// One fetch of at most [`MAX_FETCHES`], until dropped.
struct Fetch<'a>(&'a AtomicUsize);

impl<'a> Fetch<'a> {
    fn start(fetching: &'a AtomicUsize) -> Result<Fetch<'a>> {
        if fetching.fetch_add(1, Ordering::SeqCst) >= MAX_FETCHES {
            fetching.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::Busy("fetching other client metadata documents; retry".into()));
        }
        Ok(Fetch(fetching))
    }
}

impl Drop for Fetch<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
    clients::check_types(doc).map_err(|(_, e)| e)?;
    let redirect_uris = clients::string_list(doc.get("redirect_uris"), "redirect_uris", clients::MAX_REDIRECTS * 4)
        .map_err(|(_, e)| e)?;
    let name = clients::client_name(doc.get("client_name")).map_err(|(_, e)| e)?;
    Ok(Client { id: url.to_string(), name, redirect_uris, document: true })
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
        assert!(with("response_types", serde_json::json!(["token"])).contains("response_types"));
        assert!(with("client_name", serde_json::json!(7)).contains("client_name"));
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
    fn serve(answers: impl FnOnce(&str) -> Vec<String>) -> (String, std::thread::JoinHandle<usize>) {
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
                conn.write_all(answer.as_bytes()).unwrap();
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
        docs.client(&url).unwrap();
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
    fn only_a_few_fetches_run_at_once() {
        let fetching = AtomicUsize::new(0);
        let held: Vec<_> = (0..MAX_FETCHES).map(|_| Fetch::start(&fetching).unwrap()).collect();
        assert!(matches!(Fetch::start(&fetching), Err(Error::Busy(_))));
        drop(held);
        assert_eq!(fetching.load(Ordering::SeqCst), 0);
        assert!(Fetch::start(&fetching).is_ok());
    }
}
