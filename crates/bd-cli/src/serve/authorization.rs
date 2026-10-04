//! The OAuth authorization server's endpoints (`oauth_server/`): metadata,
//! registration, the browser's steps, the token and revocation endpoints,
//! providers' account notifications, and the pages they answer with.

use super::*;

/// The protected resource metadata of a workspace's MCP endpoint (RFC 9728).
/// It needs no token, and says nothing of whether the workspace exists.
pub(super) fn resource_metadata<B>(server: &Server, prefix: &str, workspace: &str, req: &Request<B>) -> Response<Body> {
    let issuer = match server.issuer() {
        Ok(issuer) => issuer,
        Err(e) => return sign_in_misconfigured(&e),
    };
    match server.base_url(req.headers(), req.uri(), prefix) {
        Some(base) => json_response(StatusCode::OK, &mcp_http::metadata(&base, workspace, issuer.as_deref())),
        None => Reject::new(StatusCode::BAD_REQUEST, "invalid", "the request's Host header is not valid", 2).response(),
    }
}

/// The metadata of the server's authorization server (RFC 8414), at the
/// path its issuer gives. It needs no token.
pub(super) fn authorization_server_metadata(server: &Server, path: &str) -> Response<Body> {
    match server.issuer() {
        Ok(Some(issuer)) if path == oauth_server::metadata_path(&issuer) => {
            let registration = oauth::load_oauth(&server.root).ok().flatten().is_some_and(|o| o.registration);
            json_response(StatusCode::OK, &oauth_server::metadata(&issuer, registration))
        }
        Ok(_) => Reject::new(StatusCode::NOT_FOUND, "not_found", "no such authorization server", 3).response(),
        Err(e) => sign_in_misconfigured(&e),
    }
}

/// `POST <issuer>/oauth/register`: register a public OAuth client (RFC
/// 7591, `oauth_server/clients.rs`), without a token, if `[oauth]` is on.
/// Served at the public URL's path, or with it stripped ([`oauth_endpoint`]).
pub(super) async fn register_client(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let body =
        match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect()).await {
            Ok(Ok(b)) => b.to_bytes(),
            Ok(Err(e)) if e.is::<LengthLimitError>() => {
                let why = format!("the request is larger than {} KiB", MAX_SIGN_IN_BODY >> 10);
                return oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_client_metadata", &why);
            }
            Ok(Err(e)) => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &format!("reading the request: {e}"));
            }
            Err(_) => {
                let why = format!("the request body did not arrive within {}s", HEADER_TIMEOUT.as_secs());
                return oauth_error(StatusCode::REQUEST_TIMEOUT, "invalid_request", &why);
            }
        };
    if let Err(e) = server.issuer() {
        return sign_in_misconfigured(&e);
    }
    let Ok(permit) = server.registering.clone().try_acquire_owned() else {
        let why = "registering other clients; retry";
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", why);
    };
    let root = server.root.clone();
    let answer = blocking(move || {
        let _permit = permit;
        match oauth::load_oauth(&root)? {
            // With registration off, as if there were no such endpoint (its metadata names none).
            Some(o) if o.registration => oauth_server::clients::register(&root, &o, &body).map(Some),
            _ => Ok(None),
        }
    })
    .await;
    match answer {
        Ok(Some(Ok(registered))) => {
            let mut r = json_response(StatusCode::CREATED, &registered);
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Ok(Some(Err((error, why)))) => oauth_error(StatusCode::BAD_REQUEST, error, &why),
        Ok(None) => Reject::new(StatusCode::NOT_FOUND, "not_found", "no such authorization server", 3).response(),
        Err(Error::Busy(why)) => oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", &why),
        Err(e) => {
            tracing::error!(target: "bd::serve", error = %e, "registering an OAuth client");
            let why = "the server could not register the client; see the server log";
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", why)
        }
    }
}

/// `POST <issuer>/oauth/token` (or, `revoking`, `<issuer>/oauth/revoke`),
/// if `[oauth]` is on: tokens for an authorization code or a refresh token,
/// or a client's token revoked (`oauth_server/token.rs`). Each runs on a
/// blocking thread with a sign-in slot; a refresh token is refreshed once
/// at a time, so that a duplicate gets a retry, not its tokens revoked.
pub(super) async fn oauth_tokens(server: &Arc<Server>, revoking: bool, req: Request<Incoming>) -> Response<Body> {
    let body =
        match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect()).await {
            Ok(Ok(b)) => b.to_bytes(),
            Ok(Err(e)) if e.is::<LengthLimitError>() => {
                let why = format!("the request is larger than {} KiB", MAX_SIGN_IN_BODY >> 10);
                return oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request", &why);
            }
            Ok(Err(e)) => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &format!("reading the request: {e}"));
            }
            Err(_) => {
                let why = format!("the request body did not arrive within {}s", HEADER_TIMEOUT.as_secs());
                return oauth_error(StatusCode::REQUEST_TIMEOUT, "invalid_request", &why);
            }
        };
    match server.issuer() {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Reject::new(StatusCode::NOT_FOUND, "not_found", "no such authorization server", 3).response();
        }
        Err(e) => return sign_in_misconfigured(&e),
    }
    let Ok(body) = String::from_utf8(body.to_vec()) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "the request is not UTF-8");
    };
    let busy = || oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable", "the server is busy; retry");
    let request = if revoking {
        None
    } else {
        match token::parse(&body) {
            Ok(request) => Some(request),
            Err(refusal) => return refused(&refusal),
        }
    };
    let completing = match &request {
        Some(token::Request::Refresh { secret, .. }) => {
            let key = auth::hash(secret);
            if !lock(&server.refreshes).running.insert(key.clone()) {
                return busy();
            }
            Some(Completing { server: server.clone(), key, refresh: true })
        }
        _ => None,
    };
    // Refreshes have slots of their own, and a refresh token of no sign-in costs a lookup, never a slot.
    let slots = match &request {
        Some(token::Request::Refresh { secret, .. }) => {
            let (root, presented) = (server.root.clone(), secret.clone());
            match blocking(move || auth::find_refresh(&root, &presented)).await {
                Ok(Some(_)) => {}
                Ok(None) => return refused(&token::unknown_refresh()),
                Err(e) => {
                    tracing::error!(target: "bd::serve", error = %e, "looking up a refresh token");
                    return busy();
                }
            }
            &server.refreshing
        }
        _ => &server.sign_ins,
    };
    let Ok(permit) = slots.clone().try_acquire_owned() else { return busy() };
    let srv = server.clone();
    let answered = blocking(move || {
        let _held = (permit, completing);
        let answer = match request {
            None => token::revoke_named(&srv.root, &body).map(|()| None),
            Some(request @ token::Request::Code { .. }) => token::redeem(&srv.root, &srv.flows, request).map(Some),
            Some(request @ token::Request::Refresh { .. }) => token::refresh(&srv.root, request).map(Some),
        };
        Ok(answer)
    })
    .await;
    let mut r = match answered {
        Ok(Ok(Some(tokens))) => json_response(StatusCode::OK, &tokens),
        Ok(Ok(None)) => response(StatusCode::OK, "text/plain", Body::whole(Bytes::new())),
        Ok(Err(refusal)) => return refused(&refusal),
        Err(e) => {
            tracing::error!(target: "bd::serve", error = %e, "answering at the OAuth token endpoint");
            let why = "the server could not answer; see its log";
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", why);
        }
    };
    let headers = r.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

/// `POST <issuer>/oauth/<provider>/events`: a provider's account
/// notification (`oauth::account_event`). Answered 200 once handled (or
/// needing nothing), so the provider stops sending it; why one is refused
/// goes to the log only.
pub(super) async fn account_events(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let provider =
        oauth_server::events_provider(under_issuer(server, req.uri().path())).unwrap_or_default().to_string();
    let body =
        match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect()).await {
            Ok(Ok(b)) => b.to_bytes(),
            _ => {
                return Reject::new(StatusCode::BAD_REQUEST, "invalid", "the notification did not arrive whole", 2)
                    .response();
            }
        };
    let Ok(permit) = server.notified.clone().try_acquire_owned() else {
        return Reject::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy; retry", 5).response();
    };
    let root = server.root.clone();
    let handled = blocking(move || {
        let _permit = permit;
        oauth::account_event(&root, &provider, &body)
    })
    .await;
    match handled {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({})),
        Err(Error::NotFound { .. }) => {
            Reject::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint", 3).response()
        }
        Err(Error::Invalid(why)) => Reject::new(StatusCode::BAD_REQUEST, "invalid", &why, 2).response(),
        Err(e @ (Error::Remote(_) | Error::Busy(_))) => {
            tracing::warn!(target: "bd::serve", error = %e, "an account notification could not be handled now");
            Reject::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "try again later", 5).response()
        }
        Err(e) => Reject::internal(e).response(),
    }
}

/// The OAuth error answer of a token or revocation request refused.
pub(super) fn refused(refusal: &token::Refusal) -> Response<Body> {
    let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut r = oauth_error(status, refusal.error, refusal.description);
    r.headers_mut().insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

/// A step of an authorization (`oauth_server/authorize.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Authorizing {
    /// `GET <issuer>/oauth/authorize`: on to the provider, or to a page choosing one.
    Begin,
    /// `GET <issuer>/oauth/choose`: on to the provider chosen.
    Choose,
    /// `GET <issuer>/oauth/<provider>/callback`: back from the provider, to the consent page.
    Callback,
    /// `POST <issuer>/oauth/<provider>/callback`: the provider's answer posted, on to the GET.
    Relay,
    /// `POST <issuer>/oauth/consent`: back to the client.
    Decide,
}

/// A step of an authorization, if `[oauth]` is on, answered for a browser:
/// a page or a redirect. Sign-in at GitHub waits on GitHub on a blocking
/// thread, with a sign-in slot. The first step, which may fetch the client's
/// metadata document, runs on a blocking thread too, bounded by the
/// document fetches' own limits (`cimd`) rather than a slot.
pub(super) async fn authorizing(server: &Arc<Server>, step: Authorizing, req: Request<Incoming>) -> Response<Body> {
    let issuer = match server.issuer() {
        Ok(Some(issuer)) => issuer,
        Ok(None) => {
            return Reject::new(StatusCode::NOT_FOUND, "not_found", "no such authorization server", 3).response();
        }
        Err(e) => return sign_in_misconfigured(&e),
    };
    let browser = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| authorize::cookie(&issuer, h).map(str::to_string));
    let cookies: String =
        req.headers().get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; ");
    let query = req.uri().query().unwrap_or_default().to_string();
    let provider =
        oauth_server::callback_provider(under_issuer(server, req.uri().path())).unwrap_or_default().to_string();
    let srv = server.clone();
    let answered = match step {
        Authorizing::Begin => {
            blocking(move || Ok(srv.authorizing(&issuer, |cx| authorize::begin(cx, &query, browser.as_deref())))).await
        }
        Authorizing::Choose => {
            blocking(move || Ok(srv.authorizing(&issuer, |cx| authorize::choose(cx, &query, browser.as_deref())))).await
        }
        Authorizing::Callback => {
            let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
                let why = "Too many sign-ins are in progress. Reload this page in a moment.";
                return html_page(pages::refusal(503, "The server is busy", why, None));
            };
            blocking(move || {
                let _permit = permit;
                Ok(srv.authorizing(&issuer, |cx| {
                    authorize::callback(cx, &provider, &query, browser.as_deref(), &cookies)
                }))
            })
            .await
        }
        Authorizing::Relay => {
            let body = tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_RELAYED_BODY).collect());
            let Ok(Ok(body)) = body.await else {
                let why = "The sign-in didn't come back complete. Start again from the application.";
                return html_page(pages::refusal(400, "Couldn't connect the application", why, None));
            };
            let body = String::from_utf8_lossy(&body.to_bytes()).into_owned();
            Ok((server.authorizing(&issuer, |cx| authorize::relay(cx, &provider, &body)), Vec::new()))
        }
        Authorizing::Decide => {
            // Only the consent page posts here: SameSite keeps the cookie from other sites' forms, and this their
            // requests. Browsers say where a form came from (Origin, Sec-Fetch-Site); a post that says neither
            // is no browser's, or a very old one's.
            let origin = req.headers().get(header::ORIGIN);
            let site = req.headers().get("sec-fetch-site");
            let foreign = origin.is_some_and(|o| o.as_bytes() != authorize::origin(&issuer).as_bytes())
                || site.is_some_and(|s| s.as_bytes() != b"same-origin")
                || (origin.is_none() && site.is_none());
            if foreign {
                let why = "The decision came from another site. Start again from the application.";
                return html_page(pages::refusal(403, "Couldn't connect the application", why, None));
            }
            let body =
                match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_CONSENT_BODY).collect())
                    .await
                {
                    Ok(Ok(b)) => b.to_bytes(),
                    _ => {
                        let why = "The decision didn't arrive complete. Start again from the application.";
                        return html_page(pages::refusal(400, "Couldn't connect the application", why, None));
                    }
                };
            let body = String::from_utf8_lossy(&body);
            Ok((server.authorizing(&issuer, |cx| authorize::decide(cx, &body, &cookies)), Vec::new()))
        }
    };
    let (answer, cookies_set) = match answered {
        Ok(answered) => answered,
        Err(e) => return Reject::internal(e).response(),
    };
    let mut r = match answer {
        authorize::Answer::Page(page) => html_page(page),
        authorize::Answer::Redirect(url) => {
            let Ok(location) = HeaderValue::from_str(&url) else {
                tracing::error!(target: "bd::serve", %url, "an authorization redirect is not a valid header value");
                let why = "The server ran into a problem. Try again later.";
                return html_page(pages::refusal(500, "Something went wrong", why, None));
            };
            // After a POST, the browser must GET where it is sent.
            let posted = matches!(step, Authorizing::Decide | Authorizing::Relay);
            let status = if posted { StatusCode::SEE_OTHER } else { StatusCode::FOUND };
            let mut r = response(status, "text/plain", Body::whole(Bytes::new()));
            let headers = r.headers_mut();
            headers.insert(header::LOCATION, location);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
            r
        }
    };
    for cookie in cookies_set.iter().filter_map(|c| HeaderValue::from_str(c).ok()) {
        r.headers_mut().append(header::SET_COOKIE, cookie);
    }
    r
}

/// An authorization page for a browser, which no other site may frame,
/// with only what its Content-Security-Policy allows. The policy is
/// same-origin, so that the consent form's POST carries the page's Origin.
pub(super) fn html_page(page: pages::Page) -> Response<Body> {
    // A page is never sent without its policy: one that is not a valid
    // header value (which nothing makes now) is replaced by a fixed one.
    let Ok(csp) = HeaderValue::from_str(&page.csp) else {
        tracing::error!(target: "bd::serve", csp = %page.csp, "an authorization page's policy is not a header value");
        let why = "The server ran into a problem. Try again later.";
        return html_page(pages::refusal(500, "Something went wrong", why, None));
    };
    let status = StatusCode::from_u16(page.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut r = response(status, "text/html; charset=utf-8", Body::whole(page.html.into_bytes()));
    let headers = r.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // The page may be at a provider's callback URL, whose query holds its code and state: no other site gets it as
    // a referrer (RFC 9700 section 4.2.4). Not no-referrer: browsers then send `Origin: null` with the consent
    // form, which the consent POST's check needs to be this server's origin.
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}

/// An OAuth error answer (RFC 6749 section 5.2, RFC 7591 section 3.2.2).
pub(super) fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response<Body> {
    let mut r = json_response(status, &serde_json::json!({ "error": error, "error_description": description }));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// `auth.toml` or `--public-url` do not let sign-in work: the details go
/// to the log, not to whoever asked.
pub(super) fn sign_in_misconfigured(e: &str) -> Response<Body> {
    tracing::error!(target: "bd::serve", error = %e, "sign-in is misconfigured");
    let msg = "the server's sign-in settings are not valid; see the server log";
    Reject::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg, 1).response()
}
