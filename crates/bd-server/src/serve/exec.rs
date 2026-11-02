//! `POST /w/<name>/v2/exec`: one bd command line, run in-process against
//! the workspace, its answer streamed back.

use super::*;

pub(super) async fn exec(server: &Arc<Server>, workspace: String, req: Request<Incoming>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let mut body = Some(body);
    let response = command(server, workspace, &parts.headers, peer(&parts.extensions), &mut body).await;
    drained(body, response).await
}

/// [`exec`], taking `body` once it reads it.
async fn command(
    server: &Arc<Server>,
    workspace: String,
    headers: &hyper::HeaderMap,
    peer: Option<std::net::IpAddr>,
    body: &mut Option<Incoming>,
) -> Response<Body> {
    let started = Instant::now();
    let token = match authenticate(server, headers, peer) {
        Ok(t) => t,
        Err(r) => return r.response(),
    };
    if let Some(resource) = &token.resource {
        let msg = format!("access token {} works only at MCP endpoint {resource}", token.name);
        log_refused(&metrics::REFUSED_FORBIDDEN, peer, Some(&token.name), Some(&workspace), &msg);
        return Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7).response();
    }
    if !token.allows_workspace(&workspace) {
        let msg = format!("access token {} may not use workspace {workspace}", token.name);
        log_refused(&metrics::REFUSED_FORBIDDEN, peer, Some(&token.name), Some(&workspace), &msg);
        return Reject::new(StatusCode::FORBIDDEN, "unauthorized", msg, 7).response();
    }
    let Some(ws) = server.workspace(&workspace) else {
        return Reject::new(StatusCode::NOT_FOUND, "not_found", format!("workspace not found: {workspace}"), 3)
            .response();
    };
    let declared = body.as_ref().and_then(|b| hyper::body::Body::size_hint(b).exact());
    if declared.is_some_and(|n| n > server.max_body as u64) {
        return too_large(server.max_body);
    }
    // Requests share one memory budget. A request holds what has arrived of
    // its body, and its answer's share only once it is known to run; what it
    // declares counts against its caller alone.
    let refused = |busy| refuse_busy(busy, peer, &token.name, &workspace).response();
    let caller = caller_of(&token);
    let (first, pledge) = first_and_pledge(declared, server.max_body, ANSWER_BUDGET);
    let mut upload = match server.budget.admit(&caller, first, pledge, QUEUE_WAIT).await {
        Ok(upload) => upload,
        Err(busy) => return refused(busy),
    };
    let body = match read_within(body.take().expect("not read yet"), server.max_body, &mut upload).await {
        Ok(b) => b,
        Err(BodyError::TooLarge) => return too_large(server.max_body),
        Err(e) => {
            refuse_body(&e, peer, &token.name, &workspace);
            return e.response("request", server.max_body);
        }
    };
    let mut request: ExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("bad request body: {e}"), 2).response();
        }
    };
    let body_size = body.len();
    drop(body);
    let bundled = request.argv.iter().any(|a| a == "--playbook-bundle" || a.starts_with("--playbook-bundle="));
    let planning = match bundled {
        false => None,
        true => match server.planning.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(TryAcquireError::NoPermits) => return busy("planning other playbooks"),
            Err(TryAcquireError::Closed) => return shutting_down(),
        },
    };
    let mut waited = None;
    let (body_held, answer_held) = match follow::requested(&request.argv) {
        Some((cli, wait)) if body_size <= MAX_WAITING_BODY => {
            // A waiting request holds no memory budget: its answer comes later,
            // and its body is parsed, small, and without the inputs `events` never reads.
            let left = upload.left();
            drop(upload);
            (request.stdin, request.files) = Default::default();
            // A request its token may not make is refused at once, by `run`.
            if resolve_actor(cli.global.actor.as_deref(), request.actor.as_deref(), request.session.as_deref(), &token)
                .is_ok()
            {
                match server.wait_for_events(&ws, wait).await {
                    Ok(w) => waited = Some(w),
                    Err(reject) => return reject.response(),
                }
            }
            match server.budget.take(&caller, ANSWER_BUDGET as u64, Class::Ordinary, left).await {
                Ok(answer) => (None, answer),
                Err(busy) => return refused(busy),
            }
        }
        wait => {
            if wait.is_some() {
                tracing::debug!(target: "bd::serve", workspace = %ws.name, bytes = body_size, "request too large to wait; not waiting");
            }
            match upload.answer(ANSWER_BUDGET as u64, class_of(body_size)).await {
                Ok(answer) => (Some(upload.finish()), answer),
                Err(busy) => return refused(busy),
            }
        }
    };
    let slot = match queue(&server.running, 1, "running other commands").await {
        Ok(permit) => permit,
        Err(reject) => return reject.response(),
    };
    // The command sends its answer's body when the answer starts: whole once
    // it finishes, or as soon as its output fills a chunk.
    let (answer, answered) = tokio::sync::oneshot::channel();
    let out = FrameWriter::new(answer, Limits::SERVE, Some(answer_held), Some(server.streams.clone()));
    let srv = server.clone();
    let job = tokio::task::spawn_blocking(move || {
        // Held until the command finishes, even if the client goes away meanwhile.
        let _held = (slot, body_held, planning);
        let ran = std::panic::catch_unwind(AssertUnwindSafe(|| {
            srv.run(&ws, &token, request, Received { at: started, peer }, waited, out)
        }));
        ran.unwrap_or_else(|_| {
            metrics::PANICS.add();
            tracing::error!(target: "bd::serve", workspace = %ws.name, "command panicked");
            Err(Reject::failed())
        })
    });
    match answered.await {
        Ok(body) => response(StatusCode::OK, FRAMES_CONTENT_TYPE, body),
        // No answer: refused before the command ran, or it panicked first.
        Err(_) => match job.await {
            Ok(Err(reject)) => reject.response(),
            Ok(Ok(())) | Err(_) => Reject::failed().response(),
        },
    }
}

pub(super) fn parse_failure(e: &clap::Error) -> ExecResponse {
    let text = e.render().to_string();
    if e.use_stderr() {
        ExecResponse { exit_code: e.exit_code(), stderr: text, ..Default::default() }
    } else {
        ExecResponse { exit_code: e.exit_code(), stdout: text, ..Default::default() }
    }
}

pub(super) fn failure(e: &Error, json: bool) -> ExecResponse {
    ExecResponse { exit_code: e.exit_code(), stderr: bd_cli::render_error(e, json, None), ..Default::default() }
}

/// Answer with a response known before the command runs.
pub(super) fn respond(out: &mut FrameWriter, response: &ExecResponse) -> std::result::Result<(), Reject> {
    out.respond(response);
    Ok(())
}

pub(super) fn lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// The rights the exit frame names: what a refusal said would get past it,
/// only when the request committed no write (`App::write` records each
/// committed one), so a client sending it again with such a token never
/// applies a part of it twice.
pub(super) fn needs_for(needs: Vec<bd_core::Need>, committed: bool) -> Vec<bd_core::Need> {
    if committed { Vec::new() } else { needs }
}
