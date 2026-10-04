//! The token endpoint (`POST <issuer>/oauth/token`, RFC 6749 section 3.2)
//! and the revocation endpoint (`POST <issuer>/oauth/revoke`, RFC 7009) of
//! `bd serve`'s authorization server, for public clients: no client
//! authentication; PKCE protects codes, and rotation refresh tokens.
//!
//! A code is redeemed once, by the client it was issued to, with the PKCE
//! verifier of its authorization (and its redirect URI, if the client sends
//! it: OAuth 2.1 clients need not), for an access
//! token bound to the MCP endpoint the account approved
//! ([`auth::issue_client_token`]) and a refresh token. A code sent again
//! revokes the token it issued; one that issued nothing because the server
//! was busy or failed is kept for a retry. Refreshes go through [`oauth::refresh`],
//! which applies `auth.toml`'s rules again, and revokes the token when a
//! spent refresh token comes back: OAuth clients send no request id, so
//! even a retry whose answer was lost does.
//!
//! Error descriptions are fixed strings, for whoever reads them; the
//! details go to the server log.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

use bd_core::{Error, Timestamp};
use serde_json::{Value, json};

use super::authorize::{self, Flows, Redeemed};
use super::{clients, form};
use crate::auth::{self, ForClient};
use crate::mcp::http as mcp_http;
use crate::oauth;

/// Why a request was refused: its HTTP status, its OAuth error and why.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
}

fn refusal(status: u16, error: &'static str, description: &'static str) -> Refusal {
    Refusal { status, error, description }
}

fn invalid_request(description: &'static str) -> Refusal {
    refusal(400, "invalid_request", description)
}

fn invalid_grant(description: &'static str) -> Refusal {
    refusal(400, "invalid_grant", description)
}

/// The answer to a refresh token no sign-in has: given before anything is
/// spent on it.
pub fn unknown_refresh() -> Refusal {
    invalid_grant("the refresh token is unknown, or its sign-in ended")
}

fn server_error(e: &Error, doing: &str) -> Refusal {
    tracing::error!(target: "bd::serve", error = %e, "{doing}");
    refusal(500, "server_error", "the server could not answer; see its log")
}

/// A token request, checked for form.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// `grant_type=authorization_code`.
    Code { code: String, verifier: String, client_id: String, redirect_uri: Option<String>, resource: Option<String> },
    /// `grant_type=refresh_token`.
    Refresh { secret: String, client_id: Option<String>, resource: Option<String> },
}

/// The pairs of a form body, each name at most once (RFC 6749 section 3.2).
fn pairs(body: &str) -> Result<Vec<(String, String)>, Refusal> {
    let pairs = form::decode(body).ok_or_else(|| invalid_request("the request is not a valid form"))?;
    let mut seen = HashSet::with_capacity(pairs.len());
    for (name, _) in &pairs {
        if !seen.insert(name.as_str()) {
            return Err(match name.as_str() {
                "resource" => refusal(400, "invalid_target", "only one resource may be asked for"),
                _ => invalid_request("a parameter is repeated"),
            });
        }
    }
    Ok(pairs)
}

fn get(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs.iter().find(|(k, v)| k == name && !v.is_empty()).map(|(_, v)| v.clone())
}

/// A PKCE code verifier (RFC 7636 section 4.1).
fn is_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// The token request in the form `body`. Client credentials and
/// parameters bd does not use (`scope`) are ignored.
pub fn parse(body: &str) -> Result<Request, Refusal> {
    let pairs = pairs(body)?;
    let get = |name: &str| get(&pairs, name);
    match get("grant_type").as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (get("code"), get("code_verifier")) else {
                return Err(invalid_request("code and code_verifier are required"));
            };
            let Some(client_id) = get("client_id") else { return Err(invalid_request("client_id is required")) };
            if !is_verifier(&verifier) {
                return Err(invalid_request("code_verifier is not a PKCE code verifier"));
            }
            Ok(Request::Code {
                code,
                verifier,
                client_id,
                redirect_uri: get("redirect_uri"),
                resource: get("resource"),
            })
        }
        Some("refresh_token") => {
            let Some(secret) = get("refresh_token") else { return Err(invalid_request("refresh_token is required")) };
            Ok(Request::Refresh { secret, client_id: get("client_id"), resource: get("resource") })
        }
        Some(_) => Err(refusal(400, "unsupported_grant_type", "only authorization_code and refresh_token")),
        None => Err(invalid_request("grant_type is required")),
    }
}

/// What a token request gets: a bearer token for the MCP endpoint, and the
/// refresh token that renews it.
fn answer(access: &str, refresh: Option<&str>, expires_in: u64) -> Value {
    let mut answer = json!({ "access_token": access, "token_type": "Bearer", "expires_in": expires_in });
    if let Some(refresh) = refresh {
        answer["refresh_token"] = json!(refresh);
    }
    answer
}

/// Whether the `resource` a token request names, if any, is `bound`: the
/// MCP endpoint of the authorization (RFC 8707 section 2.2).
fn same_resource(resource: Option<&str>, bound: Option<&str>) -> Result<(), Refusal> {
    let Some(asked) = resource else { return Ok(()) };
    match mcp_http::resource_url(asked) {
        Ok((url, _)) if Some(url.as_str()) == bound => Ok(()),
        _ => Err(refusal(400, "invalid_target", "resource is not the MCP endpoint that was authorized")),
    }
}

/// Revoke the token `id` as `why` says, logging a failure.
fn revoke(root: &Path, id: &str, why: &str) {
    match auth::revoke_by_id(root, id, why) {
        Ok(_) => tracing::warn!(target: "bd::serve", token = id, "OAuth token revoked: {why}"),
        Err(e) => tracing::error!(target: "bd::serve", token = id, error = %e, "revoking an OAuth token ({why})"),
    }
}

/// Mark the registered client `id` used, so that it is kept.
fn touch(root: &Path, id: &str) {
    if let Err(e) = clients::touch(root, id) {
        tracing::warn!(target: "bd::serve", client = id, error = %e, "marking an OAuth client used");
    }
}

/// Redeem a code (a [`Request::Code`]): the answer with tokens, or why not.
/// Any request naming a code ends it, refused or not, unless the server
/// could not issue its token: then the code is kept for a retry.
pub fn redeem(root: &Path, flows: &Mutex<Flows>, request: Request) -> Result<Value, Refusal> {
    let Request::Code { code: secret, verifier, client_id, redirect_uri, resource } = request else {
        return Err(invalid_request("not an authorization code request"));
    };
    let redeemed = authorize::lock(flows).redeem(&secret, &client_id, &verifier);
    let code = match redeemed {
        Redeemed::Fresh(code) => code,
        Redeemed::Again(token) => {
            if let Some(id) = token {
                revoke(root, &id, "its authorization code was sent again");
            }
            return Err(invalid_grant("the code was redeemed already"));
        }
        Redeemed::Unknown => return Err(invalid_grant("the code is unknown or expired")),
    };
    if client_id != code.client_id {
        return Err(invalid_grant("the code was issued to another client"));
    }
    if redirect_uri.is_some_and(|uri| uri != code.redirect_uri) {
        return Err(invalid_grant("redirect_uri is not that of the authorization"));
    }
    if authorize::s256(&verifier) != code.challenge {
        return Err(invalid_grant("code_verifier does not match the code challenge"));
    }
    same_resource(resource.as_deref(), Some(&code.resource))?;
    // Nothing issued yet: the code stays good for a retry.
    let keep = |code: &authorize::Code, refused: Refusal| {
        authorize::lock(flows).unredeem(&secret, code.clone());
        Err(refused)
    };
    let sign_in = match oauth::load(root) {
        Ok(Some(sign_in)) => sign_in,
        Ok(None) => return Err(invalid_grant("this server no longer signs people in")),
        Err(e) => return keep(&code, server_error(&e, "redeeming an authorization code: auth.toml")),
    };
    let admitted = &code.admitted;
    if !sign_in.provides(&admitted.user) {
        return Err(invalid_grant("this server no longer signs people in with that provider"));
    }
    let client = ForClient { id: &code.client_id, resource: &code.resource };
    let life =
        auth::Lifetime { rule: admitted.rule.clone(), ..sign_in.lifetime(Timestamp::now(), &admitted.user.provider) };
    let issued = match auth::issue_client_token(
        root,
        &admitted.user,
        admitted.grant.clone(),
        life,
        client,
        admitted.by_login,
    ) {
        Ok(issued) => issued,
        Err(Error::Unauthorized(why) | Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", login = %admitted.user.login, client = %code.client_id, "OAuth token refused: {why}");
            return Err(invalid_grant("the account may not get a token now"));
        }
        Err(Error::Busy(why)) => {
            tracing::warn!(target: "bd::serve", "OAuth token not issued: {why}");
            return keep(&code, refusal(503, "temporarily_unavailable", "the server is busy; retry"));
        }
        Err(e) => return keep(&code, server_error(&e, "issuing an OAuth token")),
    };
    let t = &issued.token;
    if t.actor != code.actor {
        revoke(root, &t.id, "its account's actor is not the one it consented as");
        return Err(invalid_grant("the account's actor changed since it consented"));
    }
    if authorize::lock(flows).issued(&secret, &t.id) {
        revoke(root, &t.id, "its authorization code was sent again");
        return Err(invalid_grant("the code was redeemed already"));
    }
    touch(root, &code.client_id);
    tracing::info!(
        target: "bd::serve",
        client = %code.client_id,
        login = %admitted.user.login,
        actor = %t.actor,
        token = %t.name,
        resource = %code.resource,
        role = t.role.as_str(),
        kind = t.kind.as_str(),
        "OAuth token issued"
    );
    let expires_in = t.expires_at.map_or(0, |at| u64::try_from(at.since(Timestamp::now()) / 1000).unwrap_or(0));
    Ok(answer(&issued.secret, issued.refresh_secret.as_deref(), expires_in))
}

/// Refresh (a [`Request::Refresh`]): new tokens, with what the rules grant
/// the account now, or why not. A spent refresh token revokes its tokens.
pub fn refresh(root: &Path, request: Request) -> Result<Value, Refusal> {
    let Request::Refresh { secret, client_id, resource } = request else {
        return Err(invalid_request("not a refresh request"));
    };
    let unknown = || invalid_grant("the refresh token is not valid");
    let token = match auth::find_refresh(root, &secret) {
        Ok(Some((token, _))) => token,
        Ok(None) => return Err(unknown()),
        Err(e) => return Err(server_error(&e, "refreshing an OAuth token")),
    };
    // Only the client it was issued to: whether it names itself or not.
    let Some(client) = token.client.clone() else { return Err(unknown()) };
    if client_id.as_ref().is_some_and(|id| *id != client) {
        return Err(invalid_grant("the refresh token was issued to another client"));
    }
    same_resource(resource.as_deref(), token.resource.as_deref())?;
    let request_id = match auth::random_hex(16) {
        Ok(id) => id,
        Err(e) => return Err(server_error(&e, "refreshing an OAuth token")),
    };
    match oauth::refresh(root, &secret, &request_id, Some(&client)) {
        Ok(issued) => {
            touch(root, &client);
            Ok(answer(&issued.token, issued.refresh_token.as_deref(), issued.expires_in))
        }
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %client, token = %token.name, "OAuth token not refreshed: {why}");
            Err(invalid_grant("the refresh token is not valid any more: authorize again"))
        }
        Err(Error::Remote(why) | Error::Busy(why)) => {
            tracing::warn!(target: "bd::serve", %client, token = %token.name, "OAuth token not refreshed: {why}");
            Err(refusal(503, "temporarily_unavailable", "the server could not refresh the token now; retry later"))
        }
        Err(e) => Err(server_error(&e, "refreshing an OAuth token")),
    }
}

/// Revoke what the form `body` names (RFC 7009 section 2.1): an access or
/// refresh token issued to an OAuth client, which goes with the other. A
/// token unknown, issued to no client, or to another client than
/// `client_id` names, is left as it is, and answered the same.
pub fn revoke_named(root: &Path, body: &str) -> Result<(), Refusal> {
    let pairs = pairs(body)?;
    let Some(secret) = get(&pairs, "token") else { return Err(invalid_request("token is required")) };
    let client_id = get(&pairs, "client_id");
    let token = match auth::find_by_secret(root, &secret) {
        Ok(token) => token,
        Err(e) => return Err(server_error(&e, "revoking an OAuth token")),
    };
    let Some(token) = token else { return Ok(()) };
    let Some(client) = &token.client else { return Ok(()) };
    if client_id.as_ref().is_some_and(|id| id != client) {
        return Ok(());
    }
    match auth::revoke_by_id(root, &token.id, "its OAuth client revoked it") {
        Ok(_) => {
            tracing::info!(target: "bd::serve", %client, token = %token.name, actor = %token.actor, "OAuth token revoked by its client");
            Ok(())
        }
        Err(Error::Busy(why)) => {
            tracing::warn!(target: "bd::serve", "OAuth token not revoked: {why}");
            Err(refusal(503, "temporarily_unavailable", "the server is busy; retry"))
        }
        Err(e) => Err(server_error(&e, "revoking an OAuth token")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[test]
    fn token_requests_are_checked_for_form() {
        let code = format!(
            "grant_type=authorization_code&code=c1&code_verifier={VERIFIER}&client_id=bdc_1&\
             redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=x&client_secret=ignored"
        );
        assert_eq!(
            parse(&code).unwrap(),
            Request::Code {
                code: "c1".into(),
                verifier: VERIFIER.into(),
                client_id: "bdc_1".into(),
                redirect_uri: Some("https://app.example/cb".into()),
                resource: None,
            }
        );
        // OAuth 2.1 clients send no redirect_uri: PKCE binds the code.
        let without = code.replace("&redirect_uri=https%3A%2F%2Fapp.example%2Fcb", "");
        assert!(matches!(parse(&without).unwrap(), Request::Code { redirect_uri: None, .. }));
        assert_eq!(
            parse("grant_type=refresh_token&refresh_token=r&resource=x").unwrap(),
            Request::Refresh { secret: "r".into(), client_id: None, resource: Some("x".into()) }
        );
        let error = |body: &str| parse(body).unwrap_err().error;
        assert_eq!(error(""), "invalid_request");
        assert_eq!(error("grant_type=password"), "unsupported_grant_type");
        assert_eq!(error("grant_type=refresh_token"), "invalid_request");
        assert_eq!(error("grant_type=refresh_token&refresh_token=a&refresh_token=b"), "invalid_request");
        assert_eq!(error("grant_type=refresh_token&refresh_token=a&resource=x&resource=y"), "invalid_target");
        assert_eq!(error("grant_type=refresh_token&refresh_token=%zz"), "invalid_request");
        assert_eq!(error(&code.replace("&client_id=bdc_1", "")), "invalid_request");
        assert_eq!(error(&code.replace(VERIFIER, "short")), "invalid_request");
        assert_eq!(error(&code.replace(VERIFIER, &format!("{VERIFIER}!"))), "invalid_request");
    }

    #[test]
    fn a_resource_named_must_be_the_one_authorized() {
        let bound = "https://bd.example.com/w/proj/mcp";
        assert_eq!(same_resource(None, Some(bound)), Ok(()));
        assert_eq!(same_resource(Some("https://BD.example.com/w/proj/mcp"), Some(bound)), Ok(()));
        for other in ["https://bd.example.com/w/other/mcp", "nonsense"] {
            assert_eq!(same_resource(Some(other), Some(bound)).unwrap_err().error, "invalid_target");
        }
        assert_eq!(same_resource(Some(bound), None).unwrap_err().error, "invalid_target");
    }

    #[test]
    fn unknown_codes_and_other_requests_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let flows = Mutex::new(Flows::default());
        let request = |code: &str| Request::Code {
            code: code.into(),
            verifier: VERIFIER.into(),
            client_id: "bdc_1".into(),
            redirect_uri: Some("https://app.example/cb".into()),
            resource: None,
        };
        assert_eq!(
            redeem(dir.path(), &flows, request("nope")).unwrap_err().description,
            "the code is unknown or expired"
        );
        assert!(
            redeem(dir.path(), &flows, Request::Refresh { secret: "r".into(), client_id: None, resource: None })
                .is_err()
        );
    }

    #[test]
    fn a_code_that_issued_nothing_as_the_server_failed_is_kept_for_a_retry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("auth.toml"), "not toml [").unwrap();
        let flows = Mutex::new(Flows::default());
        authorize::lock(&flows).put_code("c1", authorize::sample_code());
        let request = |redirect_uri: Option<&str>| Request::Code {
            code: "c1".into(),
            verifier: VERIFIER.into(),
            client_id: "bdc_1".into(),
            redirect_uri: redirect_uri.map(str::to_string),
            resource: None,
        };
        for _ in 0..2 {
            assert_eq!(redeem(dir.path(), &flows, request(None)).unwrap_err().status, 500);
        }
        // A refusal for the request's sake ends it.
        let refused = redeem(dir.path(), &flows, request(Some("https://app.example/other"))).unwrap_err();
        assert_eq!(refused.description, "redirect_uri is not that of the authorization");
        assert_eq!(redeem(dir.path(), &flows, request(None)).unwrap_err().description, "the code was redeemed already");
    }
}
