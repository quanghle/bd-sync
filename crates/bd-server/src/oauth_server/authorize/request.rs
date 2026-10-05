//! Authorization requests: their parameters, client and redirect URI checked as `[oauth]` allows.

use std::collections::HashMap;

use bd_core::Error;

use super::super::clients::{self, Client};
use super::super::form;
use crate::mcp_http;
use crate::oauth::{self, OauthConfig};

use super::*;

/// The parameters of an authorization request, before its client is known.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Params {
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) state: Option<String>,
    /// The others, by name; the first given more than once, if any.
    pub(super) rest: HashMap<String, String>,
    pub(super) repeated: Option<String>,
}

/// The parameters of `query`; refused on a page when the client cannot be
/// told (no client or redirect URI, or an unusable `state`).
pub(super) fn parse(query: &str) -> Result<Params, Answer> {
    // The page tells the person nothing of it: the log tells the admin what the client got wrong.
    let malformed = |why: &str| {
        tracing::info!(target: "bd::serve", "OAuth authorization refused: {why}");
        Err(refused(400, MALFORMED))
    };
    let Some(pairs) = form::decode(query) else {
        return malformed("its query is not a valid form");
    };
    let mut rest = HashMap::new();
    let mut repeated = None;
    let seen = |name: &str| pairs.iter().filter(|(k, _)| k == name).count();
    for name in ["client_id", "redirect_uri", "state"] {
        if seen(name) > 1 {
            return malformed(&format!("{name} is given more than once"));
        }
    }
    let one = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let (Some(client_id), Some(redirect_uri)) = (one("client_id"), one("redirect_uri")) else {
        return malformed("it names no client_id or redirect_uri");
    };
    let state = one("state");
    if state.as_ref().is_some_and(|s| s.len() > MAX_STATE) {
        return malformed(&format!("its state is longer than {MAX_STATE} bytes"));
    }
    for (k, v) in &pairs {
        if matches!(k.as_str(), "client_id" | "redirect_uri" | "state") {
            continue;
        }
        if rest.insert(k.clone(), v.clone()).is_some() && repeated.is_none() {
            repeated = Some(k.clone());
        }
    }
    Ok(Params { client_id, redirect_uri, state, rest, repeated })
}

/// The authorization `params` ask for, from `client`: refused on a page if
/// it may not be sent back to the redirect URI, else with an error at it.
pub(super) fn check(
    params: Params,
    client: Client,
    oauth: &OauthConfig,
    issuer: &str,
) -> Result<Authorization, Answer> {
    if !client.redirects_to(&params.redirect_uri, oauth) {
        // The likeliest mistake setting up a client: the log names the URI and what to change.
        let registered = client.redirect_uris.iter().any(|u| u == &params.redirect_uri);
        tracing::info!(
            target: "bd::serve",
            client = %client.id,
            redirect_uri = %params.redirect_uri,
            "OAuth authorization refused: {}",
            match registered {
                true => "auth.toml's [oauth] does not allow this redirect URI (add it to redirect_uris)",
                false => "the client did not register this redirect URI, nor name it in its metadata document",
            }
        );
        let why = "The application asked to send you somewhere it isn't allowed to.";
        return Err(refused(400, why));
    }
    let error = |error: &str, description: &str| {
        let pairs = [("error", error), ("error_description", description)];
        Err(Answer::Redirect(answer_url(&params.redirect_uri, params.state.as_deref(), issuer, &pairs)))
    };
    if let Some(name) = &params.repeated {
        return error("invalid_request", &format!("{name} given more than once"));
    }
    let get = |name: &str| params.rest.get(name).map(String::as_str);
    match get("response_type") {
        Some("code") => {}
        None => return error("invalid_request", "response_type is missing"),
        Some(_) => return error("unsupported_response_type", "only the code response type is supported"),
    }
    if get("code_challenge_method") != Some("S256") {
        return error("invalid_request", "PKCE with code_challenge_method S256 is required");
    }
    let Some(challenge) = get("code_challenge").filter(|c| valid_challenge(c)) else {
        return error("invalid_request", "code_challenge must be an S256 challenge (43 base64url characters)");
    };
    let Some(resource) = get("resource") else {
        return error("invalid_request", "resource is required: the URL of the MCP endpoint (RFC 8707)");
    };
    let workspace = match mcp_http::resource_url(resource) {
        Ok((url, name)) if url == mcp_http::resource(issuer, &name) => name,
        _ => return error("invalid_target", "resource is not an MCP endpoint of this bd server"),
    };
    Ok(Authorization {
        challenge: challenge.to_string(),
        resource: mcp_http::resource(issuer, &workspace),
        workspace,
        redirect_uri: params.redirect_uri,
        state: params.state,
        client,
    })
}

fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The authorization request `query`, checked: its client found, its
/// redirect URI and parameters as `[oauth]` allows. At each step before a
/// sign-in, as no step keeps it.
pub(super) fn request_of(cx: &Ctx<'_>, oauth_config: &OauthConfig, query: &str) -> Result<Authorization, Answer> {
    let params = parse(query)?;
    let client = match clients::lookup(cx.root, cx.documents, &params.client_id) {
        Ok(c) => c,
        Err(Error::Invalid(why) | Error::Remote(why)) => {
            tracing::info!(target: "bd::serve", client = %params.client_id, error = %why, "OAuth client refused");
            return Err(refused(400, "This application isn't set up to connect to this server."));
        }
        Err(Error::Busy(_) | Error::Locked(_)) => {
            return Err(refused(503, "The server is busy. Try again in a moment."));
        }
        Err(e) => return Err(internal(&e, "looking up an OAuth client")),
    };
    check(params, client, oauth_config, cx.issuer)
}

/// Sign-in settings with `[oauth]`, or the page to answer with.
pub(super) fn oauth_settings(cx: &Ctx<'_>) -> Result<(oauth::SignIn, OauthConfig), Answer> {
    match oauth::load(cx.root) {
        Ok(Some(g)) => match g.oauth.clone() {
            Some(o) => Ok((g, o)),
            None => Err(refused(404, NO_APPS)),
        },
        Ok(None) => Err(refused(404, NO_APPS)),
        Err(e) => Err(internal(&e, "reading auth.toml for an authorization")),
    }
}
