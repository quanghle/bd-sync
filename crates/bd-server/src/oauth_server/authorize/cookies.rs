//! The cookies binding an authorization's steps to one browser: the authorization's, each consent's and each flow at a provider's.

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
