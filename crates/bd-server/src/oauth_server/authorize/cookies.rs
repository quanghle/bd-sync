//! The cookies binding an authorization's steps to one browser: the authorization's, each consent's, each flow at a
//! provider's, each gate approval's and each operation approval's; and those carrying an operation's link through
//! its sign-in.

use std::time::Duration;

use super::super::CONSENT;
use crate::auth;

use super::*;

/// The cookie's name for `issuer`: prefixed where it can be `Secure`.
fn cookie_name(issuer: &str) -> &'static str {
    if issuer.starts_with("https://") { SECURE_COOKIE } else { COOKIE }
}

/// The browser's cookie for `issuer` in a `Cookie` header, if well-formed;
/// on an `https` issuer, only the prefixed one.
pub fn cookie<'h>(issuer: &str, header: &'h str) -> Option<&'h str> {
    let wanted = cookie_name(issuer);
    header
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The name of the cookie that binds one consent to the browser that signed
/// in for it: its own, so that sign-ins under way in other tabs keep theirs.
fn consent_cookie_name(issuer: &str, suffix: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_consent_{suffix}")
}

/// The value of consent cookie `suffix` in the browser's `Cookie` headers
/// (joined with `;`), if well-formed.
pub fn consent_cookie<'h>(issuer: &str, headers: &'h str, suffix: &str) -> Option<&'h str> {
    let wanted = consent_cookie_name(issuer, suffix);
    headers
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value binding a consent to this browser: sent back to
/// the consent endpoint only, and for as long as the consent waits.
pub(super) fn set_consent_cookie(issuer: &str, suffix: &str, value: &str) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}{CONSENT}", path_of(issuer));
    let name = consent_cookie_name(issuer, suffix);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", STEP_TTL.as_secs())
}

/// The `Set-Cookie` value giving the browser `value`, sent back to the
/// authorization server's endpoints only, and with top-level navigations
/// from GitHub. It lasts both steps: signing in at GitHub, then deciding.
pub fn set_cookie(issuer: &str, value: &str) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    let name = cookie_name(issuer);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", 2 * STEP_TTL.as_secs())
}

/// The name of the cookie carrying the flow sent to a provider with `state`.
fn flow_cookie_name(issuer: &str, state: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_flow_{}", &auth::hash(state)[..16])
}

/// The `Set-Cookie` value giving the browser the flow `sealed`, sent back to
/// the provider callbacks for as long as `lasts` (zero: removed).
pub(super) fn set_flow_cookie(issuer: &str, state: &str, sealed: &str, lasts: Duration) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    let name = flow_cookie_name(issuer, state);
    format!("{name}={sealed}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", lasts.as_secs())
}

/// The flow the browser carries for `state` in its `Cookie` headers (joined with `;`).
pub(super) fn flow_cookie<'h>(issuer: &str, headers: &'h str, state: &str) -> Option<&'h str> {
    let wanted = flow_cookie_name(issuer, state);
    headers.split(';').filter_map(|c| c.trim().split_once('=')).find(|(name, _)| *name == wanted).map(|(_, v)| v)
}

/// The name of the cookie that binds one gate approval to the browser that
/// signed in for it: its own, as for a consent.
fn gate_cookie_name(issuer: &str, suffix: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_gate_{suffix}")
}

/// The value of gate approval cookie `suffix` in the browser's `Cookie`
/// headers (joined with `;`), if well-formed.
pub fn gate_cookie<'h>(issuer: &str, headers: &'h str, suffix: &str) -> Option<&'h str> {
    let wanted = gate_cookie_name(issuer, suffix);
    headers
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value binding a gate approval to this browser: sent
/// back to that gate's page only, never with another site's request
/// (`SameSite=Strict`: the approval is posted from this server's own page),
/// for as long as `lasts` (zero: removed).
pub(super) fn set_gate_cookie(
    issuer: &str,
    workspace: &str,
    gate: &str,
    suffix: &str,
    value: &str,
    lasts: Duration,
) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/w/{workspace}/gates/{gate}", path_of(issuer));
    let name = gate_cookie_name(issuer, suffix);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Strict{secure}", lasts.as_secs())
}

/// The most characters of an operation's link token one request cookie
/// carries: browsers keep 4096 bytes a cookie, name and attributes included.
pub const REQUEST_PART: usize = 3000;

/// The most request cookies an operation's link token rides in: enough for
/// the longest a link carries (`approval_link::MAX_TOKEN`).
pub const MAX_REQUEST_PARTS: u8 = 2;

/// How many request cookies carry a link token of `len` characters (at
/// least one), if it fits in [`MAX_REQUEST_PARTS`].
pub fn request_parts(len: usize) -> Option<u8> {
    u8::try_from(len.div_ceil(REQUEST_PART).max(1)).ok().filter(|n| *n <= MAX_REQUEST_PARTS)
}

/// The name of request cookie `n` (from 1) of the operation whose link
/// token hashes to `digest`.
fn request_cookie_name(issuer: &str, digest: &str, n: u8) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_opreq_{}_{n}", digest.get(..16).unwrap_or(digest))
}

/// The `Set-Cookie` values carrying an operation's link `token` through the
/// sign-in, cut into cookies of at most [`REQUEST_PART`] characters: sent
/// back to the authorization server's endpoints only, with top-level
/// navigations from the provider (`SameSite=Lax`), for as long as `lasts`.
pub fn set_request_cookies(issuer: &str, digest: &str, token: &str, lasts: Duration) -> Vec<String> {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    let chunks: Vec<&str> = if token.is_empty() {
        vec![""]
    } else {
        // A token is base64url: ASCII, so any byte offset is a character's.
        token.as_bytes().chunks(REQUEST_PART).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect()
    };
    (1u8..)
        .zip(chunks)
        .map(|(n, chunk)| {
            let name = request_cookie_name(issuer, digest, n);
            format!("{name}={chunk}; Path={path}; Max-Age={}; HttpOnly; SameSite=Lax{secure}", lasts.as_secs())
        })
        .collect()
}

/// The `Set-Cookie` values removing the `parts` request cookies of the
/// operation whose link token hashes to `digest`.
pub fn clear_request_cookies(issuer: &str, digest: &str, parts: u8) -> Vec<String> {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/oauth", path_of(issuer));
    (1..=parts.min(MAX_REQUEST_PARTS))
        .map(|n| {
            let name = request_cookie_name(issuer, digest, n);
            format!("{name}=; Path={path}; Max-Age=0; HttpOnly; SameSite=Lax{secure}")
        })
        .collect()
}

/// The link token the browser's `Cookie` headers (joined with `;`) carry in
/// the `parts` request cookies of the operation whose token hashes to
/// `digest`, joined in order: None unless every part is there, and holds
/// only base64url characters.
pub fn request_cookies(issuer: &str, headers: &str, digest: &str, parts: u8) -> Option<String> {
    if parts == 0 || parts > MAX_REQUEST_PARTS {
        return None;
    }
    let mut token = String::new();
    for n in 1..=parts {
        let wanted = request_cookie_name(issuer, digest, n);
        let value = headers
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(name, _)| *name == wanted)
            .map(|(_, value)| value)?;
        if value.len() > REQUEST_PART || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
            return None;
        }
        token.push_str(value);
    }
    Some(token)
}

/// The name of the cookie that binds one operation approval to the browser
/// that signed in for it: its own, as for a gate's.
fn op_cookie_name(issuer: &str, suffix: &str) -> String {
    let prefix = if issuer.starts_with("https://") { "__Secure-" } else { "" };
    format!("{prefix}bd_op_{suffix}")
}

/// The value of operation approval cookie `suffix` in the browser's
/// `Cookie` headers (joined with `;`), if well-formed.
pub fn op_cookie<'h>(issuer: &str, headers: &'h str, suffix: &str) -> Option<&'h str> {
    let wanted = op_cookie_name(issuer, suffix);
    headers
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(name, _)| *name == wanted)
        .map(|(_, value)| value)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The `Set-Cookie` value binding an operation approval to this browser:
/// sent back to that operation's page only, never with another site's
/// request (`SameSite=Strict`), for as long as `lasts` (zero: removed).
pub fn set_op_cookie(
    issuer: &str,
    workspace: &str,
    op: &str,
    issue: &str,
    suffix: &str,
    value: &str,
    lasts: Duration,
) -> String {
    let secure = if issuer.starts_with("https://") { "; Secure" } else { "" };
    let path = format!("{}/w/{workspace}/{op}/{issue}", path_of(issuer));
    let name = op_cookie_name(issuer, suffix);
    format!("{name}={value}; Path={path}; Max-Age={}; HttpOnly; SameSite=Strict{secure}", lasts.as_secs())
}
