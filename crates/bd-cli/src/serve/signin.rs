//! The sign-in endpoints of the command line: `/v2/auth/<provider>/{device,token}`
//! (no token), `/v2/auth/refresh`, `/v2/auth/revoke`.

use super::*;

/// A step of sign-in, for a client without a token yet. Each runs on a
/// blocking thread, as it waits on the provider (`oauth/`).
pub(super) async fn sign_in(
    server: &Arc<Server>,
    provider: String,
    step: SignInStep,
    req: Request<Incoming>,
) -> Response<Body> {
    // The body first, small and time-limited: a slow client holds no slot meanwhile.
    let body = match read_body(req.into_body(), MAX_SIGN_IN_BODY, HEADER_TIMEOUT).await {
        Ok(b) => b,
        Err(e) => return e.response("sign-in request", MAX_SIGN_IN_BODY),
    };
    let bad_body =
        |e: serde_json::Error| Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("bad request body: {e}"), 2);
    let answer = match step {
        SignInStep::Device => {
            let start: SignInStart = match serde_json::from_slice(&body) {
                Ok(s) => s,
                Err(e) => return bad_body(e).response(),
            };
            // Before anyone goes to the provider for it.
            if server.workspace(&start.workspace).is_none() {
                let msg = format!("workspace not found: {}", start.workspace);
                return Reject::new(StatusCode::NOT_FOUND, "not_found", msg, 3).response();
            }
            let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
                return busy("signing in other accounts");
            };
            let root = server.root.clone();
            // The permit goes with the work: a client that leaves does not end it.
            blocking(move || {
                let _permit = permit;
                Ok(serde_json::to_value(oauth::start(&root, &provider)?)?)
            })
            .await
        }
        SignInStep::Token => {
            let poll: SignInPoll = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(e) => return bad_body(e).response(),
            };
            if !oauth::device_code_ok(&poll.device_code) {
                return Reject::new(StatusCode::BAD_REQUEST, "invalid", "not a sign-in's device code", 2).response();
            }
            if server.workspace(&poll.workspace).is_none() {
                let msg = format!("workspace not found: {}", poll.workspace);
                return Reject::new(StatusCode::NOT_FOUND, "not_found", msg, 3).response();
            }
            let key = auth::hash(&poll.device_code);
            {
                let mut issued = lock(&server.issued);
                let now = Instant::now();
                issued.answers.retain(|_, (at, _)| now.duration_since(*at) < ISSUED_REPLAY);
                if let Some((_, answer)) = issued.answers.get(&key) {
                    return json_response(StatusCode::OK, answer);
                }
                // A retry while the first attempt still runs waits for its answer.
                if !issued.running.insert(key.clone()) {
                    return busy("completing this sign-in");
                }
            }
            let completing = Completing { server: server.clone(), key: key.clone(), refresh: false };
            let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
                return busy("signing in other accounts");
            };
            let srv = server.clone();
            blocking(move || {
                let _held = (permit, completing);
                let answer = oauth::poll(&srv.root, &provider, &poll)?;
                let value = serde_json::to_value(&answer)?;
                // Kept even if this client is gone: its retry gets the token GitHub will not give again.
                if let SignInAnswer::Issued(_) = answer {
                    let mut issued = lock(&srv.issued);
                    if issued.answers.len() >= MAX_ISSUED {
                        let oldest = issued.answers.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone());
                        issued.answers.remove(&oldest.unwrap_or_default());
                    }
                    issued.answers.insert(key, (Instant::now(), value.clone()));
                }
                Ok(value)
            })
            .await
        }
    };
    auth_answer(answer)
}

/// The answer to a sign-in or refresh step.
fn auth_answer(answer: Result<serde_json::Value>) -> Response<Body> {
    match answer {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(e) => {
            let status = match &e {
                Error::Unauthorized(_) => StatusCode::FORBIDDEN,
                Error::Invalid(_) => StatusCode::BAD_REQUEST,
                Error::Remote(_) => StatusCode::BAD_GATEWAY,
                Error::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
                _ => return Reject::internal(e).response(),
            };
            Reject::new(status, e.code(), e.to_string(), e.exit_code()).response()
        }
    }
}

/// `POST /v2/auth/refresh`: renew the sign-in whose refresh token is the
/// request's bearer token (`oauth::refresh`), on a blocking thread, as it
/// waits on GitHub. A retry with the same request id gets the answer that
/// issued tokens again, for [`ISSUED_REPLAY`]: the refresh token it sent is
/// spent, and any other request with it revokes the sign-in.
pub(super) async fn refresh(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let Some(secret) = bearer(req.headers()).map(str::to_string) else { return denied().response() };
    let body = match read_body(req.into_body(), MAX_SIGN_IN_BODY, HEADER_TIMEOUT).await {
        Ok(b) => b,
        Err(e) => return e.response("refresh request", MAX_SIGN_IN_BODY),
    };
    let request: RefreshRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("bad request body: {e}"), 2).response();
        }
    };
    let id = request.request_id.as_str();
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Reject::new(StatusCode::BAD_REQUEST, "invalid", "a refresh needs a request id", 2).response();
    }
    let running = auth::hash(&secret);
    let key = auth::hash(&format!("{secret} {id}"));
    {
        let mut refreshes = lock(&server.refreshes);
        let now = Instant::now();
        refreshes.answers.retain(|_, (at, _)| now.duration_since(*at) < ISSUED_REPLAY);
        if let Some((_, answer)) = refreshes.answers.get(&key) {
            return json_response(StatusCode::OK, answer);
        }
        // A retry while the first attempt still runs waits for its answer.
        if !refreshes.running.insert(running.clone()) {
            return busy("refreshing this sign-in");
        }
    }
    let completing = Completing { server: server.clone(), key: running, refresh: true };
    // A secret of no sign-in costs a lookup, never a slot of refreshes.
    match server.tokens.knows_refresh(&secret) {
        Ok(true) => {}
        Ok(false) => {
            let why = "this bd server does not know the sign-in (it was revoked, or has ended); sign in again: \
                       `bd remote login --provider <name>`";
            return auth_answer(Err(Error::Unauthorized(why.into())));
        }
        Err(e) => return auth_answer(Err(e)),
    }
    let Ok(permit) = server.refreshing.clone().try_acquire_owned() else {
        return busy("refreshing other sign-ins");
    };
    let (srv, request_id) = (server.clone(), request.request_id.clone());
    auth_answer(
        blocking(move || {
            let _held = (permit, completing);
            let refreshed = oauth::refresh(&srv.root, &secret, &request_id, None);
            let value = serde_json::to_value(refreshed?)?;
            // Kept even if this client is gone: its retry gets the tokens, as its refresh token is spent.
            let mut refreshes = lock(&srv.refreshes);
            if refreshes.answers.len() >= MAX_ISSUED {
                let oldest = refreshes.answers.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone());
                refreshes.answers.remove(&oldest.unwrap_or_default());
            }
            refreshes.answers.insert(key, (Instant::now(), value.clone()));
            Ok(value)
        })
        .await,
    )
}

/// How long the answer of a sign-in that issued a token is kept, for a
/// retry whose first answer was lost: GitHub gives a sign-in's token once.
const ISSUED_REPLAY: Duration = Duration::from_secs(5 * 60);
/// Answers of sign-ins kept at once; the oldest goes first.
const MAX_ISSUED: usize = 256;

/// Sign-ins completing, and the answers of those that issued a token, by
/// the SHA-256 of their device code.
#[derive(Default)]
pub(super) struct Issuances {
    pub(super) answers: HashMap<String, (Instant, serde_json::Value)>,
    pub(super) running: HashSet<String>,
}

/// A sign-in or refresh completing: no other attempt of it runs until this
/// is dropped.
pub(super) struct Completing {
    pub(super) server: Arc<Server>,
    pub(super) key: String,
    /// A refresh, not a sign-in.
    pub(super) refresh: bool,
}

impl Drop for Completing {
    fn drop(&mut self) {
        let running = if self.refresh { &self.server.refreshes } else { &self.server.issued };
        lock(running).running.remove(&self.key);
    }
}

/// `POST /v2/auth/revoke`: revoke the request's own token, if it came from
/// sign-in (`bd remote logout`). One an admin created is kept: it may
/// serve elsewhere too, and only the admin revokes it. An expired token may
/// still be revoked; an unknown one is refused like any request. A
/// sign-in's refresh secret revokes the sign-in too: its current one, or
/// the one its latest refresh spent with that refresh's request id (body
/// `{"request_id"}`), whose answer the client may never have got.
pub(super) async fn revoke_own(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let Some(secret) = bearer(req.headers()).map(str::to_string) else { return denied().response() };
    // An access token is checked before anything is read: an unknown one costs no wait for a body.
    let checked = match auth::refresh_family(&secret) {
        Some(_) => None,
        None => match server.tokens.verify(&secret) {
            Ok(Verified::Valid(t) | Verified::Expired(t)) => Some(t),
            Ok(Verified::Unknown) => return denied().response(),
            Err(e) => return Reject::internal(e).response(),
        },
    };
    // Small, so that the connection stays usable.
    let body = read_body(req.into_body(), MAX_SIGN_IN_BODY, HEADER_TIMEOUT).await;
    let token = if let Some(t) = checked {
        t
    } else {
        let request_id = match body {
            Ok(b) => serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| v["request_id"].as_str().map(String::from)),
            _ => None,
        };
        let root = server.root.clone();
        let found = blocking(move || {
            Ok(auth::find_refresh(&root, &secret)?.filter(|(t, current)| {
                *current
                    || t.refresh.as_ref().zip(request_id.as_deref()).is_some_and(|(r, id)| r.retries_last(&secret, id))
            }))
        })
        .await;
        match found {
            Ok(Some((t, _))) => t,
            Ok(None) => return denied().response(),
            Err(e) => return Reject::internal(e).response(),
        }
    };
    if token.identity.is_none() {
        return json_response(StatusCode::OK, &RevokeAnswer { name: token.name, revoked: false });
    }
    let (root, id) = (server.root.clone(), token.id.clone());
    let revoked = blocking(move || {
        let revoked = auth::revoke_by_id(&root, &id, "its holder logged out")?;
        Ok(revoked)
    })
    .await;
    match revoked {
        Ok(_) => {
            tracing::info!(target: "bd::serve", token = %token.name, actor = %token.actor, "access token revoked by its holder");
            json_response(StatusCode::OK, &RevokeAnswer { name: token.name, revoked: true })
        }
        Err(e) => Reject::internal(e).response(),
    }
}
