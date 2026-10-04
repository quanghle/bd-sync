//! `POST /w/<name>/v2/exec`: one bd command line, run in-process against
//! the workspace, its answer streamed back.

use super::*;

pub(super) async fn exec(server: &Arc<Server>, workspace: String, req: Request<Incoming>) -> Response<Body> {
    let started = Instant::now();
    let token = match authenticate(server, req.headers()) {
        Ok(t) => t,
        Err(r) => return r.response(),
    };
    if let Some(resource) = &token.resource {
        let msg = format!("access token {} works only at MCP endpoint {resource}", token.name);
        return Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7).response();
    }
    if !token.allows_workspace(&workspace) {
        let msg = format!("access token {} may not use workspace {workspace}", token.name);
        return Reject::new(StatusCode::FORBIDDEN, "unauthorized", msg, 7).response();
    }
    let Some(ws) = server.workspace(&workspace) else {
        return Reject::new(StatusCode::NOT_FOUND, "not_found", format!("workspace not found: {workspace}"), 3)
            .response();
    };
    // Requests share one memory budget: reserve the body's declared size (or
    // the maximum, when it is sent chunked) before reading it, and the answer's share.
    let declared = hyper::body::Body::size_hint(req.body()).exact();
    if declared.is_some_and(|n| n > server.max_body as u64) {
        return too_large(server.max_body);
    }
    let reserve = declared.map_or(server.max_body, |n| usize::try_from(n).unwrap_or(server.max_body));
    let answer_permits = kib(ANSWER_BUDGET);
    let permits = kib(reserve.saturating_mul(BODY_COPIES)).saturating_add(answer_permits);
    let mut budget =
        match tokio::time::timeout(QUEUE_WAIT, server.body_budget.clone().acquire_many_owned(permits)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return shutting_down(),
            Err(_) => return busy("receiving other requests"),
        };
    let mut answer_budget = budget.split(answer_permits as usize);
    let mut budget = Some(budget);
    let body = match tokio::time::timeout(BODY_TIMEOUT, Limited::new(req.into_body(), server.max_body).collect()).await
    {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) if e.is::<LengthLimitError>() => return too_large(server.max_body),
        Ok(Err(e)) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("reading the request: {e}"), 2).response();
        }
        Err(_) => {
            let msg = format!("the request body did not arrive within {}s", BODY_TIMEOUT.as_secs());
            return Reject::new(StatusCode::REQUEST_TIMEOUT, "remote", msg, 8).response();
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
    let wait = follow::requested(&request.argv);
    if wait.is_some() && body_size > MAX_WAITING_BODY {
        tracing::debug!(target: "bd::serve", workspace = %ws.name, bytes = body_size, "request too large to wait; not waiting");
    } else if let Some((cli, wait)) = wait {
        // A waiting request holds no memory budget: its answer comes later,
        // and its body is parsed, small, and without the inputs `events` never reads.
        drop((budget.take(), answer_budget.take()));
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
        let permits = server.body_budget.clone().acquire_many_owned(answer_permits);
        answer_budget = match tokio::time::timeout(QUEUE_WAIT, permits).await {
            Ok(Ok(permit)) => Some(permit),
            Ok(Err(_)) => return shutting_down(),
            Err(_) => return busy("receiving other requests"),
        };
    }
    let slot = match tokio::time::timeout(QUEUE_WAIT, server.running.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return shutting_down(),
        Err(_) => return busy("running other commands"),
    };
    // The command sends its answer's body when the answer starts: whole once
    // it finishes, or as soon as its output fills a chunk.
    let (answer, answered) = tokio::sync::oneshot::channel();
    let out = FrameWriter::new(answer, Limits::SERVE, answer_budget, Some(server.streams.clone()));
    let srv = server.clone();
    let job = tokio::task::spawn_blocking(move || {
        // Held until the command finishes, even if the client goes away meanwhile.
        let _held = (slot, budget, planning);
        let ran = std::panic::catch_unwind(AssertUnwindSafe(|| srv.run(&ws, &token, request, started, waited, out)));
        ran.unwrap_or_else(|_| {
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
    ExecResponse { exit_code: e.exit_code(), stderr: crate::render_error(e, json, None), ..Default::default() }
}

/// Answer with a response known before the command runs.
pub(super) fn respond(out: &mut FrameWriter, response: &ExecResponse) -> std::result::Result<(), Reject> {
    out.respond(response);
    Ok(())
}

pub(super) fn lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}
