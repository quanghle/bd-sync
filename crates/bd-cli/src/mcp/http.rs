//! Streamable HTTP, as `bd serve` serves each workspace at `/w/<name>/mcp`:
//! one JSON-RPC message per POST, answered with one JSON object (never an
//! SSE stream), with no session ids. This module checks what HTTP adds to a
//! message (its headers) and picks each answer's status; `serve/`
//! authenticates the request and runs its tool calls.
//!
//! - A `MODERN` request mirrors its version, method and tool name in the
//!   `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers; one
//!   missing or not matching the body is refused with `HeaderMismatch`.
//! - A `LEGACY` client names its session's version in `MCP-Protocol-Version`
//!   after `initialize`; each request stands alone, and one without the
//!   header is served as `LEGACY`.
//!
//! Each endpoint is an OAuth protected resource (RFC 9728): its URL (the
//! resource) is `--public-url` or the request's own origin and path prefix,
//! followed by `/w/<name>/mcp`; its metadata is served at the resource's
//! prefix followed by `/.well-known/oauth-protected-resource/w/<name>/mcp`
//! (the RFC's own form, with the prefix after the well-known part, too), and
//! a refused request's `WWW-Authenticate` challenge points there.

use hyper::StatusCode;
use hyper::header::{self, HeaderMap};
use serde_json::{Map, Value, json};

use crate::protocol::valid_workspace_name;

use super::{
    Failure, INVALID_REQUEST, LEGACY, METHOD_NOT_FOUND, MODERN, PARSE_ERROR, Runner, Server, UNSUPPORTED_VERSION,
    VERSION_KEY, error, names_version, supported,
};

type Outcome<T> = std::result::Result<T, Failure>;

const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const METHOD_HEADER: &str = "mcp-method";
const NAME_HEADER: &str = "mcp-name";
/// The HTTP headers do not match the message, or one is missing or malformed.
const HEADER_MISMATCH: i64 = -32020;

/// The answer to one POST.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// A notification or a response was taken: 202, no body.
    Accepted,
    /// A JSON-RPC message: the answer to a request, or an error.
    Message(StatusCode, Value),
}

/// A request from a web page is refused (403): browsers send `Origin` with
/// every POST, and other clients none. `bd serve` serves no pages, so no
/// origin is its own; comparing one with `Host` would not stop DNS
/// rebinding, where the page's origin and the request's host are the same
/// name.
pub fn check_origin(headers: &HeaderMap) -> Result<(), Answer> {
    if !headers.contains_key(header::ORIGIN) {
        return Ok(());
    }
    Err(Answer::Message(
        StatusCode::FORBIDDEN,
        error(Value::Null, INVALID_REQUEST, "requests from web pages (with an Origin header) are not accepted", None),
    ))
}

/// The body must be JSON, so a page cannot send it as a form without the
/// browser asking the server first.
pub fn check_content_type(headers: &HeaderMap) -> Result<(), Answer> {
    let media = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).and_then(|v| v.split(';').next());
    if media.is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json")) {
        return Ok(());
    }
    Err(Answer::Message(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        error(Value::Null, INVALID_REQUEST, "Content-Type must be application/json", None),
    ))
}

/// Answer the message POSTed as `body` with `headers`.
pub fn answer<R: Runner>(server: &mut Server<R>, headers: &HeaderMap, body: &[u8]) -> Answer {
    let message: Value = match serde_json::from_slice(body) {
        Ok(m) => m,
        Err(e) => {
            let e = error(Value::Null, PARSE_ERROR, &format!("invalid JSON: {e}"), None);
            return Answer::Message(StatusCode::BAD_REQUEST, e);
        }
    };
    let modern = message.get("params").and_then(Value::as_object).is_some_and(names_version);
    if let Err((code, text, data)) = check_headers(&message, headers, modern) {
        let id = message.get("id").filter(|id| id.is_string() || id.is_number()).cloned().unwrap_or(Value::Null);
        return Answer::Message(StatusCode::BAD_REQUEST, error(id, code, &text, data));
    }
    match server.handle(&message) {
        None => Answer::Accepted,
        Some(answer) => {
            let status = match answer["error"]["code"].as_i64() {
                Some(PARSE_ERROR | INVALID_REQUEST | HEADER_MISMATCH | UNSUPPORTED_VERSION) => StatusCode::BAD_REQUEST,
                Some(METHOD_NOT_FOUND) if modern => StatusCode::NOT_FOUND,
                _ => StatusCode::OK,
            };
            Answer::Message(status, answer)
        }
    }
}

/// The headers a request needs, matching its body. Malformed messages and
/// notifications are left to [`Server::handle`].
fn check_headers(message: &Value, headers: &HeaderMap, modern: bool) -> Outcome<()> {
    let (Some(method), Some(_)) = (message.get("method").and_then(Value::as_str), message.get("id")) else {
        return Ok(());
    };
    let empty = Map::new();
    let params = message.get("params").and_then(Value::as_object).unwrap_or(&empty);
    let version = header_value(headers, PROTOCOL_VERSION_HEADER)?;
    if !modern {
        return match version.as_deref() {
            _ if method == "initialize" => Ok(()),
            None | Some(LEGACY) => Ok(()),
            Some(MODERN) => Err(mismatch(&format!(
                "the MCP-Protocol-Version header names {MODERN}, but the request has no _meta[{VERSION_KEY:?}]"
            ))),
            Some(other) => Err((
                UNSUPPORTED_VERSION,
                "Unsupported protocol version".into(),
                Some(json!({ "supported": supported(), "requested": other })),
            )),
        };
    }
    let in_body = params.get("_meta").and_then(|m| m.get(VERSION_KEY)).and_then(Value::as_str).unwrap_or_default();
    expect(version, "MCP-Protocol-Version", in_body)?;
    expect(header_value(headers, METHOD_HEADER)?, "Mcp-Method", method)?;
    if let (true, Some(name)) = (method == "tools/call", params.get("name").and_then(Value::as_str)) {
        let header = header_value(headers, NAME_HEADER)?;
        let decoded = match header.as_deref().map(decode) {
            Some(None) => return Err(mismatch("the Mcp-Name header is not valid base64-encoded UTF-8")),
            Some(Some(d)) => Some(d),
            None => None,
        };
        expect(decoded, "Mcp-Name", name)?;
    }
    Ok(())
}

/// `header`'s value, if the request has it.
fn header_value(headers: &HeaderMap, header: &str) -> Outcome<Option<String>> {
    match headers.get(header).map(|v| v.to_str()) {
        None => Ok(None),
        Some(Ok(v)) => Ok(Some(v.to_string())),
        Some(Err(_)) => Err(mismatch(&format!("the {header} header has characters a header may not carry"))),
    }
}

fn expect(header: Option<String>, name: &str, in_body: &str) -> Outcome<()> {
    match header {
        None => Err(mismatch(&format!("the {name} header is required"))),
        Some(h) if h == in_body => Ok(()),
        Some(h) => Err(mismatch(&format!("the {name} header names {h:?}, the request {in_body:?}"))),
    }
}

fn mismatch(message: &str) -> Failure {
    (HEADER_MISMATCH, format!("Header mismatch: {message}"), None)
}

/// A header value as sent, or decoded from its `=?base64?…?=` form.
fn decode(value: &str) -> Option<String> {
    match value.strip_prefix("=?base64?").and_then(|v| v.strip_suffix("?=")) {
        Some(encoded) => String::from_utf8(base64(encoded)?).ok(),
        None => Some(value.to_string()),
    }
}

/// Standard base64, padding optional.
fn base64(text: &str) -> Option<Vec<u8>> {
    let text = text.strip_suffix("==").or_else(|| text.strip_suffix('=')).unwrap_or(text);
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Where a resource's metadata lives, under its prefix.
pub const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// `url` as a server's public URL: http or https, a host, no user info,
/// query or fragment; scheme and host lowercased, a default port and
/// trailing slashes dropped.
pub fn public_url(url: &str) -> std::result::Result<String, String> {
    let bad = |why: &str| Err(format!("{url}: {why}"));
    let Some((scheme, rest)) = url.split_once("://") else {
        return bad("not an http:// or https:// URL");
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return bad("not an http:// or https:// URL");
    }
    if rest.contains(['?', '#']) {
        return bad("a query or fragment is not allowed");
    }
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if host.contains('@') {
        return bad("user info is not allowed");
    }
    let Some(host) = authority(host, scheme == "https") else {
        return bad("not a valid host[:port]");
    };
    let path = path.trim_end_matches('/');
    if !valid_prefix(path) {
        return bad("not a valid path");
    }
    Ok(format!("{scheme}://{host}{path}"))
}

/// `url` as an MCP endpoint's resource URL (`<public url>/w/<name>/mcp`):
/// its normalized form and its workspace.
pub fn resource_url(url: &str) -> std::result::Result<(String, String), String> {
    let url = public_url(url)?;
    let start = url.find("://").map_or(0, |i| i + 3);
    let path = url[start..].find('/').map_or("", |i| &url[start + i..]);
    let name = path
        .strip_suffix("/mcp")
        .and_then(|p| p.rsplit_once("/w/"))
        .map(|(_, name)| name)
        .filter(|name| valid_workspace_name(name));
    match name {
        Some(name) => Ok((url.clone(), name.to_string())),
        None => Err(format!("{url}: not an MCP endpoint URL (<server URL>/w/<name>/mcp)")),
    }
}

/// The server's URL as a request reached it, when no public URL is set:
/// its scheme, its `Host` (never `X-Forwarded-*`, which anyone can send)
/// and the path prefix before `/w/`. `None` if the host is not valid.
pub fn request_base(https: bool, host: Option<&str>, prefix: &str) -> Option<String> {
    let host = authority(host?, https)?;
    let scheme = if https { "https" } else { "http" };
    valid_prefix(prefix).then(|| format!("{scheme}://{host}{prefix}"))
}

/// `host[:port]`, lowercased, without the scheme's default port.
fn authority(raw: &str, https: bool) -> Option<String> {
    let a = raw.to_ascii_lowercase();
    if !a.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
        return None;
    }
    let (host, port) = match a.rfind(':') {
        Some(i) if !a[i..].contains(']') => (&a[..i], Some(&a[i + 1..])),
        _ => (a.as_str(), None),
    };
    if host.is_empty() {
        return None;
    }
    match port {
        None => Some(host.to_string()),
        Some(p) if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) => None,
        Some(p) if p == if https { "443" } else { "80" } => Some(host.to_string()),
        Some(p) => Some(format!("{host}:{p}")),
    }
}

/// A path prefix fit for a URL in a quoted header parameter: empty, or
/// `/`-separated segments of printable characters, with no `.` or `..`.
fn valid_prefix(path: &str) -> bool {
    path.is_empty()
        || path.starts_with('/')
            && path.bytes().all(|b| b.is_ascii_graphic() && !b"\"\\<>^`{|}".contains(&b))
            && path.split('/').skip(1).all(|s| !s.is_empty() && s != "." && s != "..")
}

/// `[<prefix A>]/.well-known/oauth-protected-resource[<prefix B>]/w/<name>/mcp`
/// -> the resource's prefix (A then B) and its workspace.
pub fn metadata_path(path: &str) -> Option<(String, &str)> {
    let (a, rest) = path.split_once(WELL_KNOWN)?;
    let (b, name) = rest.strip_suffix("/mcp")?.rsplit_once("/w/")?;
    ((b.is_empty() || b.starts_with('/')) && valid_workspace_name(name)).then(|| (format!("{a}{b}"), name))
}

/// The endpoint of workspace `name` on the server at `base`.
pub fn resource(base: &str, name: &str) -> String {
    format!("{base}/w/{name}/mcp")
}

/// Where the metadata of workspace `name`'s endpoint is served.
pub fn metadata_url(base: &str, name: &str) -> String {
    format!("{base}{WELL_KNOWN}/w/{name}/mcp")
}

/// The protected resource metadata (RFC 9728) of workspace `name`'s
/// endpoint, naming the server's authorization server if it runs one
/// (`oauth_server.rs`); without it, tokens come from the server's admin
/// (`bd serve token create`) or GitHub sign-in.
pub fn metadata(base: &str, name: &str, issuer: Option<&str>) -> Value {
    let mut m = json!({
        "resource": resource(base, name),
        "bearer_methods_supported": ["header"],
        "resource_name": format!("bd workspace {name}"),
    });
    if let Some(issuer) = issuer {
        m["authorization_servers"] = json!([issuer]);
    }
    m
}

/// A `WWW-Authenticate` challenge (RFC 6750) pointing at the metadata, if
/// its URL is known, with an error code and description, if any: a request
/// that sent no token gets none.
pub fn challenge(metadata: Option<&str>, error: Option<(&str, &str)>) -> String {
    let mut params = Vec::new();
    if let Some((code, description)) = error {
        params.push(format!("error=\"{code}\""));
        let description: String =
            description.chars().map(|c| if c == '"' || c == '\\' || c.is_control() { '\'' } else { c }).collect();
        params.push(format!("error_description=\"{description}\""));
    }
    if let Some(url) = metadata {
        params.push(format!("resource_metadata=\"{url}\""));
    }
    if params.is_empty() { "Bearer".into() } else { format!("Bearer {}", params.join(", ")) }
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;
    use crate::mcp::{CAPABILITIES_KEY, Ran};

    struct Nothing;

    impl Runner for Nothing {
        fn run(&mut self, _: &[String], _: bool) -> bd_core::Result<Ran> {
            Ok(Ran { stdout: "[]".into(), ..Ran::default() })
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn post(pairs: &[(&'static str, &str)], message: Value) -> Answer {
        answer(&mut Server::for_request(Nothing, false), &headers(pairs), message.to_string().as_bytes())
    }

    fn status_and_code(a: Answer) -> (StatusCode, Option<i64>) {
        match a {
            Answer::Message(s, v) => (s, v["error"]["code"].as_i64()),
            Answer::Accepted => (StatusCode::ACCEPTED, None),
        }
    }

    fn modern(method: &str, params: Value) -> Value {
        let mut params = params;
        params["_meta"] = json!({ VERSION_KEY: MODERN, CAPABILITIES_KEY: {} });
        json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params })
    }

    const CALL: [(&str, &str); 3] =
        [("mcp-protocol-version", MODERN), ("mcp-method", "tools/call"), ("mcp-name", "ready")];

    #[test]
    fn modern_requests_mirror_their_body_in_headers() {
        let call = modern("tools/call", json!({ "name": "ready" }));
        assert_eq!(status_and_code(post(&CALL, call.clone())), (StatusCode::OK, None));
        let encoded = [CALL[0], CALL[1], ("mcp-name", "=?base64?cmVhZHk=?=")];
        assert_eq!(status_and_code(post(&encoded, call.clone())), (StatusCode::OK, None));

        for (pairs, what) in [
            (&CALL[1..], "no version header"),
            (&[CALL[0], CALL[2]][..], "no method header"),
            (&CALL[..2], "no name header"),
            (&[CALL[0], CALL[1], ("mcp-name", "list")][..], "another tool"),
            (&[CALL[0], ("mcp-method", "tools/list"), CALL[2]][..], "another method"),
            (&[(CALL[0].0, LEGACY), CALL[1], CALL[2]][..], "another version"),
            (&[CALL[0], CALL[1], ("mcp-name", "=?base64?!!?=")][..], "bad base64"),
        ] {
            let a = post(pairs, call.clone());
            assert_eq!(status_and_code(a), (StatusCode::BAD_REQUEST, Some(HEADER_MISMATCH)), "{what}");
        }
        let Answer::Message(_, e) = post(&CALL[1..], call) else { panic!() };
        assert_eq!(e["id"], 7, "the error answers the request");

        let list = [CALL[0], ("mcp-method", "resources/list")];
        let r = post(&list, modern("resources/list", json!({})));
        assert_eq!(status_and_code(r), (StatusCode::NOT_FOUND, Some(METHOD_NOT_FOUND)));
        let mut future = modern("tools/list", json!({}));
        future["params"]["_meta"][VERSION_KEY] = json!("2099-01-01");
        let r = post(&[(CALL[0].0, "2099-01-01"), ("mcp-method", "tools/list")], future);
        assert_eq!(status_and_code(r), (StatusCode::BAD_REQUEST, Some(UNSUPPORTED_VERSION)));
    }

    #[test]
    fn legacy_requests_stand_alone() {
        let init =
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": LEGACY } });
        let Answer::Message(StatusCode::OK, r) = post(&[], init) else { panic!() };
        assert_eq!(r["result"]["protocolVersion"], LEGACY);
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert_eq!(post(&[(CALL[0].0, LEGACY)], note), Answer::Accepted);

        // No initialize in this server: the header names the session's version.
        let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        for pairs in [&[(CALL[0].0, LEGACY)][..], &[]] {
            let Answer::Message(StatusCode::OK, r) = post(pairs, list.clone()) else { panic!() };
            assert!(r["result"]["tools"].is_array(), "{r}");
        }
        let r = post(&[(CALL[0].0, "2025-06-18")], list.clone());
        assert_eq!(status_and_code(r), (StatusCode::BAD_REQUEST, Some(UNSUPPORTED_VERSION)));
        let r = post(&[(CALL[0].0, MODERN)], list);
        assert_eq!(status_and_code(r), (StatusCode::BAD_REQUEST, Some(HEADER_MISMATCH)));
        let r = post(&[(CALL[0].0, LEGACY)], json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }));
        assert_eq!(status_and_code(r), (StatusCode::OK, Some(METHOD_NOT_FOUND)));
    }

    #[test]
    fn malformed_bodies() {
        let mut server = Server::for_request(Nothing, false);
        assert_eq!(
            status_and_code(answer(&mut server, &HeaderMap::new(), b"{")),
            (StatusCode::BAD_REQUEST, Some(PARSE_ERROR))
        );
        let batch = json!([modern("ping", json!({}))]).to_string();
        let r = answer(&mut server, &HeaderMap::new(), batch.as_bytes());
        assert_eq!(status_and_code(r), (StatusCode::BAD_REQUEST, Some(INVALID_REQUEST)));
        let response = json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string();
        assert_eq!(answer(&mut server, &HeaderMap::new(), response.as_bytes()), Answer::Accepted);
    }

    #[test]
    fn origins_and_content_types() {
        assert!(check_origin(&headers(&[("host", "bd.example:8443")])).is_ok());
        // The same name as the host included: a page rebinding its own name to the server.
        for origin in ["https://evil.example", "null", "https://bd.example:8443"] {
            let h = headers(&[("host", "bd.example:8443"), ("origin", origin)]);
            assert!(matches!(check_origin(&h), Err(Answer::Message(StatusCode::FORBIDDEN, _))), "{origin}");
        }
        assert!(check_content_type(&headers(&[("content-type", "application/json; charset=utf-8")])).is_ok());
        for bad in [&[("content-type", "text/plain")][..], &[]] {
            let r = check_content_type(&headers(bad));
            assert!(matches!(r, Err(Answer::Message(StatusCode::UNSUPPORTED_MEDIA_TYPE, _))));
        }
    }

    #[test]
    fn base64_values() {
        assert_eq!(decode("ready").as_deref(), Some("ready"));
        assert_eq!(decode("=?base64?SGVsbG8sIOS4lueVjA==?=").as_deref(), Some("Hello, 世界"));
        assert_eq!(decode("=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=").as_deref(), Some("=?base64?literal?="));
        assert_eq!(decode("=?base64?A?="), None);
        assert_eq!(base64("").unwrap(), b"");
        assert_eq!(base64("Zm9vYg").unwrap(), b"foob");
    }

    #[test]
    fn public_urls_are_checked_and_normalized() {
        assert_eq!(public_url("https://bd.example.com").unwrap(), "https://bd.example.com");
        assert_eq!(public_url("HTTPS://BD.Example.com:443/bd/").unwrap(), "https://bd.example.com/bd");
        assert_eq!(public_url("http://127.0.0.1:80").unwrap(), "http://127.0.0.1");
        assert_eq!(public_url("http://127.0.0.1:8080/a/b").unwrap(), "http://127.0.0.1:8080/a/b");
        assert_eq!(public_url("https://[::1]:8443").unwrap(), "https://[::1]:8443");
        for bad in [
            "bd.example.com",
            "ftp://bd.example.com",
            "https://",
            "https://user@bd.example.com",
            "https://bd.example.com/?x=1",
            "https://bd.example.com/#x",
            "https://bd.example.com:http",
            "https://bd example.com",
            "https://bd.example.com/a//b",
            "https://bd.example.com/a/../b",
            "https://bd.example.com/a\"b",
        ] {
            assert!(public_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resource_urls_name_a_workspace() {
        let (url, name) = resource_url("https://Bd.example.com:443/bd/w/proj/mcp").unwrap();
        assert_eq!((url.as_str(), name.as_str()), ("https://bd.example.com/bd/w/proj/mcp", "proj"));
        let (_, name) = resource_url("https://w/w/x/mcp").unwrap();
        assert_eq!(name, "x");
        for bad in
            ["https://h/w/proj", "https://h/w/proj/mcp/x", "https://h/w/-x/mcp", "https://w/x/mcp", "https://h/mcp"]
        {
            assert!(resource_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_bases_trust_only_the_host() {
        assert_eq!(request_base(false, Some("127.0.0.1:8080"), "").as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(request_base(true, Some("BD.example.com:443"), "/bd").as_deref(), Some("https://bd.example.com/bd"));
        assert_eq!(request_base(true, None, ""), None);
        for host in ["evil.com/x", "a@b", "a b", "a\"b", ""] {
            assert_eq!(request_base(true, Some(host), ""), None, "{host}");
        }
        assert_eq!(request_base(true, Some("h"), "/a\"b"), None);
    }

    #[test]
    fn metadata_paths_put_the_prefix_on_either_side() {
        let at = |p| metadata_path(p).map(|(prefix, name)| (prefix, name.to_string()));
        assert_eq!(at("/.well-known/oauth-protected-resource/w/proj/mcp"), Some(("".into(), "proj".into())));
        assert_eq!(at("/.well-known/oauth-protected-resource/bd/w/proj/mcp"), Some(("/bd".into(), "proj".into())));
        assert_eq!(at("/bd/.well-known/oauth-protected-resource/w/proj/mcp"), Some(("/bd".into(), "proj".into())));
        for bad in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resourcex/w/proj/mcp",
            "/.well-known/oauth-protected-resource/w/proj",
            "/.well-known/oauth-protected-resource/w/a/b/mcp",
            "/w/proj/mcp",
        ] {
            assert_eq!(metadata_path(bad), None, "{bad}");
        }
        let base = "https://h/bd";
        assert_eq!(metadata_url(base, "p"), "https://h/bd/.well-known/oauth-protected-resource/w/p/mcp");
        assert_eq!(
            metadata(base, "p", None),
            json!({"resource": "https://h/bd/w/p/mcp", "bearer_methods_supported": ["header"], "resource_name": "bd workspace p"})
        );
        assert_eq!(metadata(base, "p", Some("https://h/bd"))["authorization_servers"], json!(["https://h/bd"]));
    }

    #[test]
    fn challenges_name_the_metadata_and_the_error() {
        assert_eq!(challenge(None, None), "Bearer");
        assert_eq!(challenge(Some("https://h/m"), None), "Bearer resource_metadata=\"https://h/m\"");
        assert_eq!(
            challenge(Some("https://h/m"), Some(("invalid_token", "token \"x\" expired\n"))),
            "Bearer error=\"invalid_token\", error_description=\"token 'x' expired'\", resource_metadata=\"https://h/m\""
        );
    }
}
