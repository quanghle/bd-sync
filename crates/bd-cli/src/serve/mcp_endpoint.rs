//! `POST /w/<name>/mcp`: MCP over Streamable HTTP, each tool call run as
//! `<token actor>/mcp` (`ToolRunner`).

use super::*;

/// A workspace's MCP endpoint, as a request reached it.
pub(super) struct Endpoint {
    pub(super) workspace: String,
    /// Its URL (the OAuth resource) and its metadata's, unless the request's
    /// host is not valid and no `--public-url` is set.
    pub(super) resource: Option<String>,
    pub(super) metadata: Option<String>,
}

impl Endpoint {
    pub(super) fn of<B>(server: &Server, prefix: &str, workspace: &str, req: &Request<B>) -> Endpoint {
        let base = server.base_url(req.headers(), req.uri(), prefix);
        Endpoint {
            workspace: workspace.to_string(),
            resource: base.as_deref().map(|b| mcp_http::resource(b, workspace)),
            metadata: base.as_deref().map(|b| mcp_http::metadata_url(b, workspace)),
        }
    }

    /// `reject` with a challenge pointing at the metadata, and its error code if any.
    pub(super) fn challenge(&self, reject: Reject, error: Option<&str>) -> Response<Body> {
        let challenge =
            mcp_http::challenge(self.metadata.as_deref(), error.map(|code| (code, reject.message.as_str())));
        let mut r = reject.response();
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
        r
    }
}

/// One MCP message for `workspace` (Streamable HTTP, see `mcp/http.rs`):
/// its tool calls run as [`Server::run`] runs a command line, on a blocking
/// thread with a command slot, acting as `<token actor>/mcp` (or
/// `/<session>` with `?session=<session>`), without the token's rights over
/// other actors' claims and human gates.
pub(super) async fn mcp(server: &Arc<Server>, endpoint: Endpoint, req: Request<Incoming>) -> Response<Body> {
    let started = Instant::now();
    if let Err(a) = mcp_http::check_origin(req.headers()) {
        return mcp_response(a, None);
    }
    let token = match authenticate(server, req.headers()) {
        Ok(t) => t,
        Err(r) if r.status == StatusCode::UNAUTHORIZED => {
            // A request without a token learns where to get one, with no error (RFC 6750).
            let error = bearer(req.headers()).is_some().then_some("invalid_token");
            return endpoint.challenge(r, error);
        }
        Err(r) => return r.response(),
    };
    if let Some(bound) = token.resource.as_ref().filter(|bound| endpoint.resource.as_ref() != Some(*bound)) {
        let msg = format!("access token {} works only at MCP endpoint {bound}", token.name);
        return endpoint
            .challenge(Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7), Some("invalid_token"));
    }
    if !token.allows_workspace(&endpoint.workspace) {
        let msg = format!("access token {} may not use workspace {}", token.name, endpoint.workspace);
        let reject = Reject::new(StatusCode::FORBIDDEN, "unauthorized", msg, 7);
        return endpoint.challenge(reject, Some("insufficient_scope"));
    }
    let workspace = endpoint.workspace;
    let Some(ws) = server.workspace(&workspace) else {
        return Reject::new(StatusCode::NOT_FOUND, "not_found", format!("workspace not found: {workspace}"), 3)
            .response();
    };
    let session = match mcp_session(req.uri().query()) {
        Ok(s) => s,
        Err(e) => return Reject::new(StatusCode::BAD_REQUEST, "invalid", e.to_string(), 2).response(),
    };
    if let Err(a) = mcp_http::check_content_type(req.headers()) {
        return mcp_response(a, None);
    }
    if hyper::body::Body::size_hint(req.body()).exact().is_some_and(|n| n > MAX_MCP_BODY as u64) {
        return mcp_too_large();
    }
    let permits = kib(MAX_MCP_BODY * BODY_COPIES + MCP_ANSWER_BUDGET);
    let budget = match tokio::time::timeout(QUEUE_WAIT, server.body_budget.clone().acquire_many_owned(permits)).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return shutting_down(),
        Err(_) => return busy("receiving other requests"),
    };
    let (parts, body) = req.into_parts();
    let body = match tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_MCP_BODY).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) if e.is::<LengthLimitError>() => return mcp_too_large(),
        Ok(Err(e)) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("reading the request: {e}"), 2).response();
        }
        Err(_) => {
            let msg = format!("the request body did not arrive within {}s", BODY_TIMEOUT.as_secs());
            return Reject::new(StatusCode::REQUEST_TIMEOUT, "remote", msg, 8).response();
        }
    };
    let slot = match tokio::time::timeout(QUEUE_WAIT, server.running.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return shutting_down(),
        Err(_) => return busy("running other commands"),
    };
    let srv = server.clone();
    let job = tokio::task::spawn_blocking(move || {
        // The answer's share is held until it is sent; the body's, and the slot, until the message is answered.
        let mut budget = budget;
        let answer_budget = budget.split(kib(MCP_ANSWER_BUDGET) as usize);
        let _held = (slot, budget);
        let runner = ToolRunner { server: &srv, ws: &ws, token: &token, session: &session };
        let mut mcp = mcp::Server::for_request(runner, token.role == Role::Read);
        let answer = std::panic::catch_unwind(AssertUnwindSafe(|| {
            mcp_response(mcp_http::answer(&mut mcp, &parts.headers, &body), answer_budget)
        }));
        tracing::debug!(target: "bd::serve", workspace = %ws.name, token = %token.name, ms = started.elapsed().as_millis() as u64, "mcp message");
        answer.map_err(|_| tracing::error!(target: "bd::serve", workspace = %ws.name, "MCP request panicked"))
    });
    match job.await {
        Ok(Ok(response)) => response,
        Ok(Err(())) | Err(_) => Reject::failed().response(),
    }
}

/// The session of `?session=<name>`, else `mcp`: tool calls act as
/// `<token actor>/<session>`.
pub(super) fn mcp_session(query: Option<&str>) -> Result<String> {
    let named = query.into_iter().flat_map(|q| q.split('&')).find_map(|p| p.strip_prefix("session="));
    match named {
        None => Ok("mcp".into()),
        Some(s) if actor::is_label(s) => Ok(s.into()),
        Some(s) => Err(Error::invalid(format!(
            "invalid session {s:?}: letters, digits, '.', '_' and '-', at most {} characters",
            actor::MAX_LABEL
        ))),
    }
}

/// The response to an MCP message, its body holding `budget` until sent.
pub(super) fn mcp_response(answer: mcp_http::Answer, budget: Option<OwnedSemaphorePermit>) -> Response<Body> {
    match answer {
        mcp_http::Answer::Accepted => response(StatusCode::ACCEPTED, "application/json", Body::whole(Bytes::new())),
        mcp_http::Answer::Message(status, message) => {
            let bytes = serde_json::to_vec(&message).unwrap_or_default();
            response(status, "application/json", Body::whole_within(bytes, budget))
        }
    }
}

pub(super) fn mcp_too_large() -> Response<Body> {
    let msg = format!("an MCP message is larger than {} MiB", MAX_MCP_BODY >> 20);
    Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "invalid", msg, 2).response()
}

/// Runs the tool calls of an MCP request in its workspace, as `token`.
pub(super) struct ToolRunner<'a> {
    pub(super) server: &'a Server,
    pub(super) ws: &'a Workspace,
    pub(super) token: &'a Token,
    pub(super) session: &'a str,
}

impl mcp::Runner for ToolRunner<'_> {
    fn run(&mut self, argv: &[String], _write: bool) -> Result<Ran> {
        let started = Instant::now();
        let cli = Cli::try_parse_from(std::iter::once("bd").chain(argv.iter().map(String::as_str)))
            .map_err(|e| Error::invalid(e.to_string().lines().next().unwrap_or("invalid command line").to_string()))?;
        let (access, resolved) = authorize(&cli, self.token, None, Some(self.session))?;
        let actor = resolved.actor.clone();
        let mut app = self.server.open_app(self.ws, self.token, &cli.global, resolved)?;
        // A model's tool calls never carry a person's rights: no admin-only
        // commands, other actors' claims or human gates.
        let policy = self.token.policy();
        let (buffer, capture) = Capture::buffered(mcp::local::OUTPUT_LIMIT);
        let capture = Capture {
            token_actor: policy.actor,
            max_claims: policy.max_claims,
            token: Some(self.token.clone()),
            ..capture
        };
        let (exit_code, captured) = io::capture(capture, || crate::execute(&mut app, &cli.command));
        if access == Access::Write {
            self.server.feeds.committed(&self.ws.name);
        }
        self.server.close_app(self.ws, self.token, &mut app);
        tracing::info!(
            target: "bd::serve",
            workspace = %self.ws.name,
            token = %self.token.name,
            %actor,
            command = crate::command_name(&cli.command),
            exit_code,
            ms = started.elapsed().as_millis() as u64,
            "mcp tool call"
        );
        let stdout = String::from_utf8_lossy(buffer.borrow().output()?).into_owned();
        Ok(Ran { exit_code, stdout, stderr: lossy(captured.stderr) })
    }
}
