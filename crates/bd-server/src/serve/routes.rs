//! Routing a request to its endpoint, by path and method.

use super::*;

/// `[/<prefix>]/w/<name>/v2/exec` -> `<name>`: a proxy may serve bd under a
/// path prefix without stripping it.
pub(super) fn exec_path(path: &str) -> Option<&str> {
    let (rest, version) = path.strip_suffix("/exec")?.rsplit_once("/v")?;
    let (_, name) = rest.rsplit_once("/w/")?;
    Some(name).filter(|w| version == PROTOCOL.to_string() && !w.is_empty() && !w.contains('/'))
}

/// `[/<prefix>]/w/<name>/mcp` -> `[/<prefix>]` and `<name>`.
pub(super) fn mcp_path(path: &str) -> Option<(&str, &str)> {
    let (prefix, name) = path.strip_suffix("/mcp")?.rsplit_once("/w/")?;
    // Valid names only: the name goes into the URLs of WWW-Authenticate challenges.
    Some((prefix, name)).filter(|(_, w)| valid_workspace_name(w))
}

/// A step of sign-in from the command line (the device flow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SignInStep {
    /// Get a one-time code.
    Device,
    /// Ask whether it was entered, and get the token once it was.
    Token,
}

/// `[/<prefix>]/v2/auth/<provider>/<device|token>` -> the provider and the step.
pub(super) fn sign_in_path(path: &str) -> Option<(String, SignInStep)> {
    let (_, rest) = path.rsplit_once(&format!("/v{PROTOCOL}/auth/"))?;
    let (provider, step) = rest.split_once('/')?;
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if provider.is_empty() || provider.len() > 32 || !provider.chars().all(plain) {
        return None;
    }
    let step = match step {
        "device" => SignInStep::Device,
        "token" => SignInStep::Token,
        _ => return None,
    };
    Some((provider.to_string(), step))
}

/// The authorization server's endpoint at `path`: under the public URL's
/// path, or with it stripped by a proxy, and nowhere else, so that a proxy
/// limiting requests to these paths sees them all.
pub(super) fn oauth_endpoint(server: &Server, path: &str) -> Option<&'static str> {
    let rest = under_issuer(server, path);
    use oauth_server::{AUTHORIZE, CALLBACK, CHOOSE, CONSENT, EVENTS, REGISTER, REVOKE, TOKEN};
    let fixed = [REGISTER, TOKEN, REVOKE, AUTHORIZE, CHOOSE, CONSENT].into_iter().find(|e| *e == rest);
    // Every provider's callback is the callback endpoint; the step reads which from the path. Notifications alike.
    fixed
        .or_else(|| oauth_server::callback_provider(rest).map(|_| CALLBACK))
        .or_else(|| oauth_server::events_provider(rest).map(|_| EVENTS))
}

/// `path` without the public URL's path, as the authorization server's
/// endpoints are named.
pub(super) fn under_issuer<'p>(server: &Server, path: &'p str) -> &'p str {
    let public = server.public_url.as_deref().and_then(|u| u.split_once("://")).map_or("", |(_, rest)| rest);
    let prefix = public.find('/').map_or("", |i| &public[i..]);
    path.strip_prefix(prefix).filter(|r| r.starts_with('/')).unwrap_or(path)
}

pub(super) async fn handle(
    server: Arc<Server>,
    req: Request<Incoming>,
) -> std::result::Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let oauth = oauth_endpoint(&server, &path);
    let response = if path == "/healthz" && req.method() == Method::GET {
        response(StatusCode::OK, "text/plain", Body::whole(Bytes::from_static(b"ok\n")))
    } else if path == "/metrics" {
        if req.method() == Method::GET {
            metrics_page(&server, &req)
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
            r
        }
    } else if let Some(workspace) = exec_path(&path) {
        if req.method() == Method::POST {
            exec(&server, workspace.to_string(), req).await
        } else {
            Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response()
        }
    } else if let Some((prefix, workspace)) = mcp_http::metadata_path(&path) {
        if req.method() == Method::GET {
            resource_metadata(&server, &prefix, workspace, &req)
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
            r
        }
    } else if path.contains(mcp_http::WELL_KNOWN) {
        Reject::new(StatusCode::NOT_FOUND, "not_found", "no such protected resource", 3).response()
    } else if path.contains(oauth_server::WELL_KNOWN) {
        if req.method() == Method::GET {
            authorization_server_metadata(&server, &path)
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
            r
        }
    } else if oauth == Some(oauth_server::REGISTER) {
        if req.method() == Method::POST {
            register_client(&server, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
            r
        }
    } else if oauth == Some(oauth_server::TOKEN) || oauth == Some(oauth_server::REVOKE) {
        if req.method() == Method::POST {
            let revoking = oauth == Some(oauth_server::REVOKE);
            oauth_tokens(&server, revoking, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
            r
        }
    } else if oauth == Some(oauth_server::AUTHORIZE) {
        if req.method() == Method::GET {
            authorizing(&server, Authorizing::Begin, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
            r
        }
    } else if oauth == Some(oauth_server::CHOOSE) {
        if req.method() == Method::GET {
            authorizing(&server, Authorizing::Choose, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
            r
        }
    } else if oauth == Some(oauth_server::CALLBACK) {
        if req.method() == Method::GET {
            authorizing(&server, Authorizing::Callback, req).await
        } else if req.method() == Method::POST {
            authorizing(&server, Authorizing::Relay, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET or POST", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
            r
        }
    } else if oauth == Some(oauth_server::EVENTS) {
        if req.method() == Method::POST {
            account_events(&server, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
            r
        }
    } else if oauth == Some(oauth_server::CONSENT) {
        if req.method() == Method::POST {
            authorizing(&server, Authorizing::Decide, req).await
        } else {
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
            r
        }
    } else if let Some((prefix, workspace)) = mcp_path(&path) {
        if req.method() == Method::POST {
            let endpoint = Endpoint::of(&server, prefix, workspace, &req);
            mcp(&server, endpoint, req).await
        } else {
            // No event stream to open (GET) and no session to end (DELETE).
            let msg = "use POST: this MCP endpoint opens no event streams and keeps no sessions";
            let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", msg, 2).response();
            r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
            r
        }
    } else if let Some((provider, step)) = sign_in_path(&path) {
        if req.method() == Method::POST {
            sign_in(&server, provider, step, req).await
        } else {
            Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response()
        }
    } else if path.ends_with(&format!("/v{PROTOCOL}/auth/revoke")) {
        if req.method() == Method::POST {
            revoke_own(&server, req).await
        } else {
            Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response()
        }
    } else if path.ends_with(&format!("/v{PROTOCOL}/auth/refresh")) {
        if req.method() == Method::POST {
            refresh(&server, req).await
        } else {
            Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response()
        }
    } else {
        let msg = format!("no such endpoint; workspaces are at /w/<name>/v{PROTOCOL}/exec");
        Reject::new(StatusCode::NOT_FOUND, "not_found", msg, 3).response()
    };
    metrics::answered(response.status().as_u16());
    Ok(response)
}

/// `GET /metrics`: the server's counters ([`metrics`]), for admin tokens
/// only, as they tell how busy the server is and how often it is refused.
fn metrics_page(server: &Server, req: &Request<Incoming>) -> Response<Body> {
    let token = match authenticate(server, req.headers(), peer(req.extensions())) {
        Ok(t) => t,
        Err(r) => return r.response(),
    };
    if let Some(resource) = &token.resource {
        let msg = format!("access token {} works only at MCP endpoint {resource}", token.name);
        log_refused(&metrics::REFUSED_FORBIDDEN, peer(req.extensions()), Some(&token.name), None, &msg);
        return Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7).response();
    }
    if token.role != Role::Admin {
        let msg = format!("access token {} is not an admin token; /metrics needs one", token.name);
        log_refused(&metrics::REFUSED_FORBIDDEN, peer(req.extensions()), Some(&token.name), None, &msg);
        return Reject::new(StatusCode::FORBIDDEN, "unauthorized", msg, 7).response();
    }
    let mut r = response(StatusCode::OK, "text/plain; version=0.0.4", Body::whole(Bytes::from(metrics::render())));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
