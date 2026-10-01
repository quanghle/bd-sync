//! `bd serve`: share workspaces with remote bd clients over HTTP(S).
//!
//! A request carries one bd command line. The server runs it in-process
//! against the workspace's database, exactly as the CLI would on this host
//! (one command, normally one `Store::write` transaction), and answers with
//! its output and exit code. The database never leaves this machine, so
//! atomic claims, fencing tokens and the gapless event log keep their
//! guarantees: every write still takes SQLite's write lock.
//!
//! Layout: `<root>/<name>/.bd/bd.db` is workspace `<name>`, served at
//! `POST /w/<name>/v2/exec` (the wire format is in `protocol.rs`);
//! `<root>/tokens.json` holds the access tokens. `GET /healthz` answers `ok`
//! without a token.
//!
//! Memory and slots: up to `MAX_RUNNING` commands run at once. Requests in
//! progress share a budget (`MIN_BODY_BUDGET`, or more for one maximum-size
//! request): each reserves its body, twice, and a fixed share for its answer.
//! A read's answer streams (see `stream.rs`): its output reaches the client
//! as it is written, through buffers of a fixed size, so an export of any
//! size holds about the same memory as a claim. At most `MAX_STREAMING`
//! reads stream their answers at once (another is refused as busy, and its
//! client tries again), and their clients must keep up a minimum rate, so
//! slow readers cannot take the slots of short commands. A write's answer,
//! up to `REPLAY_LIMIT` of output, is held back while it runs, stored for
//! replays, released, and only then sent whole: a retry after a lost answer
//! always gets it. A write with more output streams, outside the lane: it is
//! never refused once it may have taken effect. Stderr is kept up to 64 KiB,
//! and a connection whose client takes nothing for `WRITE_STALL` is closed.
//!
//! Background jobs keep every workspace up without a client asking: lease
//! reclaim, gate checks, backups and pruning of request records (`jobs.rs`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{SocketAddr, ToSocketAddrs};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bd_core::{Error, OpenOptions, Result, Store};
use clap::Parser;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use crate::app::{App, RequestKey};
use crate::auth::{self, Role, Token, Verifier};
use crate::cli::*;
use crate::io::{self, Capture};
use crate::jobs;
use crate::protocol::{
    ErrorBody, ErrorDetail, ExecRequest, ExecResponse, Exit, FRAMES_CONTENT_TYPE, PROTOCOL, PROTOCOL_HEADER,
    valid_workspace_name,
};
use crate::stream::{FrameWriter, Limits, ResponseBody, Stalls};

/// Commands running at once; further requests wait for a slot.
const MAX_RUNNING: usize = 32;
/// Open connections; further ones are closed at once.
const MAX_CONNECTIONS: usize = 512;
/// Memory for requests in progress, across all connections: this much, or
/// enough for one maximum-size request if `--max-body-mib` is larger.
const MIN_BODY_BUDGET: usize = 256 << 20;
/// A request's body briefly exists twice (collected chunks and the parsed copy).
const BODY_COPIES: usize = 2;
/// How long a request waits for body budget or a command slot before the
/// client is asked to retry (503).
const QUEUE_WAIT: Duration = Duration::from_secs(15);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Matches the client's own limit for a whole request.
const BODY_TIMEOUT: Duration = Duration::from_secs(120);
/// Connections close after this long, so a client that stops reading cannot hold a response forever.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// hyper's per-connection read buffer, held before authentication (hyper's default is ~400 KiB).
const READ_BUFFER: usize = 64 << 10;
/// Idle database connections kept per workspace.
const MAX_POOLED: usize = 16;
/// Stack of the threads that run commands. Playbooks nest at most
/// `playbook::MAX_DEPTH` levels, far below this; it is address space,
/// committed only as it is used.
const THREAD_STACK: usize = 8 << 20;
/// Commands planning playbooks sent with them at once. Each may hold a few
/// tens of MiB while it parses and plans (bounded by the bundle and planning
/// limits); further ones are answered 503 at once, which clients retry, so
/// none waits holding memory or holds up other requests.
const MAX_PLANNING: usize = 4;
/// On shutdown, how long running commands may take to finish.
const COMMANDS_GRACE: Duration = Duration::from_secs(30);
/// On shutdown, how long running background jobs may take to finish.
const JOBS_GRACE: Duration = Duration::from_secs(10);
/// A write's output, held back while it runs and stored to replay its answer
/// to a retry; a write with more output streams, and is not kept.
const REPLAY_LIMIT: usize = 1 << 20;
/// Each request's share of the body budget for its answer, held until the
/// answer is written or dropped: a streamed answer's buffers, or a held one
/// sent whole (its output, a little larger once escaped in frames).
const ANSWER_BUDGET: usize = max(Limits::SERVE.memory(READ_BUFFER), REPLAY_LIMIT + REPLAY_LIMIT / 4);
/// Reads streaming their answers at once: each holds a command slot while
/// its client reads, so slow clients cannot take all of the slots.
const MAX_STREAMING: usize = 8;
/// A connection whose client takes nothing for this long is closed.
const WRITE_STALL: Duration = Duration::from_secs(60);

type Body = ResponseBody;

pub fn cmd_serve(app: &mut App, a: &ServeArgs) -> Result<()> {
    io::require_local("bd serve")?;
    match &a.action {
        Some(ServeAction::Token(cmd)) => auth::cmd_token(app, cmd),
        None => run(a),
    }
}

fn run(a: &ServeArgs) -> Result<()> {
    let root = a.root.as_ref().ok_or_else(|| {
        Error::invalid(
            "bd serve needs --root DIR (or $BD_SERVE_ROOT): the directory holding <name>/.bd/bd.db workspaces",
        )
    })?;
    let root = std::fs::canonicalize(root).map_err(|e| Error::invalid(format!("--root {}: {e}", root.display())))?;
    if !root.is_dir() {
        return Err(Error::invalid(format!("--root {}: not a directory", root.display())));
    }
    let addr = a
        .listen
        .to_socket_addrs()
        .map_err(|e| Error::invalid(format!("--listen {}: {e}", a.listen)))?
        .next()
        .ok_or_else(|| Error::invalid(format!("--listen {}: no address", a.listen)))?;
    let tls = match (&a.tls_cert, &a.tls_key) {
        (Some(cert), Some(key)) => Some(tls_acceptor(cert, key)?),
        _ => None,
    };
    if tls.is_none() && !addr.ip().is_loopback() && !a.insecure_http {
        return Err(Error::Refused(format!(
            "refusing plain HTTP on {addr}: access tokens would cross the network unencrypted. Pass --tls-cert and \
             --tls-key, or --insecure-http behind a TLS proxy or on an encrypted private network"
        )));
    }
    if !(1..=4096).contains(&a.max_body_mib) {
        return Err(Error::invalid(format!("--max-body-mib {}: use 1 to 4096", a.max_body_mib)));
    }
    let max_body = usize::try_from(a.max_body_mib << 20).unwrap_or(usize::MAX);
    let jobs = jobs::Config::from_args(a)?;
    // Before any request or background job: gate checks in this process use the server's defaults.
    io::mark_server_process();
    let server = Arc::new(Server::new(root, max_body));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bd-serve")
        .thread_stack_size(THREAD_STACK)
        .build()?;
    let served = runtime.block_on(serve(server, addr, tls, jobs));
    // Commands and jobs still running after their grace period are abandoned:
    // SQLite rolls back an unfinished transaction.
    runtime.shutdown_timeout(Duration::from_secs(1));
    served
}

fn tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let bad =
        |flag: &str, path: &Path, e: &dyn std::fmt::Display| Error::invalid(format!("{flag} {}: {e}", path.display()));
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|e| bad("--tls-cert", cert, &e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| bad("--tls-cert", cert, &e))?;
    if certs.is_empty() {
        return Err(bad("--tls-cert", cert, &"no certificate in the file"));
    }
    let key_der = PrivateKeyDer::from_pem_file(key).map_err(|e| bad("--tls-key", key, &e))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::invalid(format!("TLS: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| Error::invalid(format!("--tls-cert/--tls-key: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn serve(server: Arc<Server>, addr: SocketAddr, tls: Option<TlsAcceptor>, jobs: jobs::Config) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(|e| Error::invalid(format!("--listen {addr}: {e}")))?;
    let local = listener.local_addr()?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    // Tests and scripts read the bound address (with --listen ...:0) from this line.
    io::outln(format!("bd serve: listening on {scheme}://{local} (workspaces in {})", server.root.display()));
    tracing::info!(target: "bd::serve", %local, scheme, root = %server.root.display(), "listening");
    let jobs = jobs::start(jobs, server.root.clone(), server.open.clone());
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(target: "bd::serve", error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!(target: "bd::serve", %peer, "too many connections; closing this one");
            continue;
        };
        let server = server.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if tokio::time::timeout(MAX_CONNECTION_LIFETIME, connection(server, stream, peer, tls)).await.is_err() {
                tracing::debug!(target: "bd::serve", %peer, "connection closed at its maximum lifetime");
            }
        });
    }
    tracing::info!(target: "bd::serve", "shutting down after running commands finish");
    // GitHub gates are checked again after a restart; no need to wait for gh.
    crate::gates::cancel_gh_calls();
    let all = u32::try_from(MAX_RUNNING).unwrap_or(u32::MAX);
    let commands = tokio::time::timeout(COMMANDS_GRACE, server.running.acquire_many(all));
    let _ = tokio::join!(commands, jobs.stop(JOBS_GRACE));
    Ok(())
}

/// Serve the HTTP requests of one connection.
async fn connection(server: Arc<Server>, stream: TcpStream, peer: SocketAddr, tls: Option<TlsAcceptor>) {
    let _ = stream.set_nodelay(true);
    let stream = Stalls::new(stream, WRITE_STALL);
    let service = service_fn(move |req| handle(server.clone(), req));
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_buf_size(READ_BUFFER);
    let served = match tls {
        Some(acceptor) => match tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream)).await {
            Ok(Ok(stream)) => http.serve_connection(TokioIo::new(stream), service).await,
            Ok(Err(e)) => {
                tracing::debug!(target: "bd::serve", %peer, error = %e, "TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!(target: "bd::serve", %peer, "TLS handshake timed out");
                return;
            }
        },
        None => http.serve_connection(TokioIo::new(stream), service).await,
    };
    if let Err(e) = served {
        tracing::debug!(target: "bd::serve", %peer, error = %e, "connection closed");
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
}

/// An HTTP-level failure: the command did not run.
#[derive(Debug)]
struct Reject {
    status: StatusCode,
    code: &'static str,
    message: String,
    exit_code: i32,
}

impl Reject {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>, exit_code: i32) -> Reject {
        Reject { status, code, message: message.into(), exit_code }
    }

    fn failed() -> Reject {
        let msg = "the command failed on the server; see the server log";
        Reject::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg, 1)
    }

    fn internal(e: Error) -> Reject {
        tracing::error!(target: "bd::serve", error = %e, "request failed");
        let status = if matches!(e, Error::Busy(_)) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Reject::new(status, e.code(), e.to_string(), e.exit_code())
    }

    fn response(&self) -> Response<Body> {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code.to_string(),
                message: self.message.clone(),
                exit_code: self.exit_code,
            },
        };
        let mut r = json_response(self.status, &body);
        if self.status == StatusCode::UNAUTHORIZED {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        r
    }
}

fn response(status: StatusCode, content_type: &'static str, body: Body) -> Response<Body> {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    let headers = r.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert("bd-version", HeaderValue::from_static(env!("CARGO_PKG_VERSION")));
    headers.insert(PROTOCOL_HEADER, HeaderValue::from(PROTOCOL));
    r
}

fn json_response(status: StatusCode, body: &impl serde::Serialize) -> Response<Body> {
    response(status, "application/json", Body::whole(serde_json::to_vec(body).unwrap_or_default()))
}

/// `[/<prefix>]/w/<name>/v<N>/exec` -> (`<name>`, N): a proxy may serve bd
/// under a path prefix without stripping it.
fn exec_path(path: &str) -> Option<(&str, u32)> {
    let (rest, version) = path.strip_suffix("/exec")?.rsplit_once("/v")?;
    let version = version.parse().ok()?;
    let (_, name) = rest.rsplit_once("/w/")?;
    Some((name, version)).filter(|(w, _)| !w.is_empty() && !w.contains('/'))
}

async fn handle(server: Arc<Server>, req: Request<Incoming>) -> std::result::Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let response = if path == "/healthz" && req.method() == Method::GET {
        response(StatusCode::OK, "text/plain", Body::whole(Bytes::from_static(b"ok\n")))
    } else if let Some((workspace, version)) = exec_path(&path) {
        if version != PROTOCOL {
            let msg = format!(
                "this bd server (bd {}) speaks protocol {PROTOCOL}, and this client protocol {version}: use the same \
                 bd version on both",
                env!("CARGO_PKG_VERSION")
            );
            Reject::new(StatusCode::GONE, "remote", msg, 8).response()
        } else if req.method() == Method::POST {
            exec(&server, workspace.to_string(), req).await
        } else {
            Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use POST", 2).response()
        }
    } else {
        let msg = format!("no such endpoint; workspaces are at /w/<name>/v{PROTOCOL}/exec");
        Reject::new(StatusCode::NOT_FOUND, "not_found", msg, 3).response()
    };
    Ok(response)
}

fn authenticate(server: &Server, headers: &HeaderMap) -> std::result::Result<Token, Reject> {
    let denied = || {
        Reject::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid access token (sent as a bearer token in the Authorization header)",
            7,
        )
    };
    let value = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or_else(denied)?;
    let (scheme, secret) = value.trim().split_once(' ').ok_or_else(denied)?;
    if !scheme.eq_ignore_ascii_case("bearer") || secret.trim().is_empty() {
        return Err(denied());
    }
    match server.tokens.verify(secret.trim()) {
        Ok(Some(token)) => Ok(token),
        Ok(None) => Err(denied()),
        Err(e) => Err(Reject::internal(e)),
    }
}

async fn exec(server: &Arc<Server>, workspace: String, req: Request<Incoming>) -> Response<Body> {
    let started = Instant::now();
    let token = match authenticate(server, req.headers()) {
        Ok(t) => t,
        Err(r) => return r.response(),
    };
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
    let answer_budget = budget.split(answer_permits as usize);
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
    let request: ExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("bad request body: {e}"), 2).response();
        }
    };
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
        let ran = std::panic::catch_unwind(AssertUnwindSafe(|| srv.run(&ws, &token, request, started, out)));
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

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Semaphore permits for `bytes` of body budget (one per KiB).
fn kib(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(1024).max(1)).unwrap_or(u32::MAX)
}

fn too_large(max_body: usize) -> Response<Body> {
    let msg = format!("request larger than {} MiB (raise bd serve --max-body-mib)", max_body >> 20);
    Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "invalid", msg, 2).response()
}

fn busy(doing: &str) -> Response<Body> {
    let msg = format!("the server is busy {doing}; retry shortly");
    Reject::new(StatusCode::SERVICE_UNAVAILABLE, "busy", msg, 5).response()
}

fn shutting_down() -> Response<Body> {
    Reject::new(StatusCode::SERVICE_UNAVAILABLE, "remote", "the server is shutting down", 8).response()
}

struct Server {
    root: PathBuf,
    tokens: Verifier,
    workspaces: Mutex<HashMap<String, Arc<Workspace>>>,
    /// `<workspace>/<request id>` of writes running now.
    inflight: Mutex<HashSet<String>>,
    running: Arc<Semaphore>,
    /// Commands whose answers stream, a few of the running ones.
    streams: Arc<Semaphore>,
    /// Commands planning playbooks sent with them.
    planning: Arc<Semaphore>,
    /// Memory of requests in progress, in KiB permits.
    body_budget: Arc<Semaphore>,
    max_body: usize,
    open: OpenOptions,
}

struct Workspace {
    name: String,
    dir: PathBuf,
    db: PathBuf,
    pool: Mutex<Vec<Store>>,
}

impl Workspace {
    fn take(&self, open: &OpenOptions) -> Result<Store> {
        match lock(&self.pool).pop() {
            Some(store) => Ok(store),
            None => Store::open(&self.db, open.clone()),
        }
    }

    fn give(&self, store: Store) {
        let mut pool = lock(&self.pool);
        if pool.len() < MAX_POOLED {
            pool.push(store);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Marks a request id as running until dropped.
struct InFlight<'a> {
    server: &'a Server,
    key: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        lock(&self.server.inflight).remove(&self.key);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    /// Only on the machine holding the workspace.
    Local,
    Read,
    /// May write (admin-only operations check the role when they run).
    Write,
}

pub(crate) fn access(cmd: &Command) -> Access {
    use Command as C;
    match cmd {
        C::Init(_) | C::Serve(_) | C::Remote(_) | C::Bench(_) | C::BenchWorker(_) => Access::Local,
        C::Events(a) if a.follow => Access::Local,
        C::Events(a) if a.action.is_none() => Access::Read,
        C::Playbook(PlaybookCommand::Extract(a)) if a.save => Access::Local,
        C::Show(_)
        | C::List(_)
        | C::Ready(_)
        | C::Blocked(_)
        | C::Leases(_)
        | C::Comments(_)
        | C::Recall(_)
        | C::Memories(_)
        | C::History(_)
        | C::Prime(_)
        | C::Stats
        | C::Metrics(_)
        | C::Export(_)
        | C::Info
        | C::Version
        | C::Dep(DepCommand::List(_) | DepCommand::Tree(_) | DepCommand::Cycles)
        | C::Label(LabelCommand::List(_))
        | C::Comment(CommentCommand::List(_))
        | C::Memory(MemoryCommand::Get(_) | MemoryCommand::List(_))
        | C::Config(ConfigCommand::Get(_) | ConfigCommand::List)
        | C::Playbook(
            PlaybookCommand::List
            | PlaybookCommand::Show(_)
            | PlaybookCommand::Status(_)
            | PlaybookCommand::Runs(_)
            | PlaybookCommand::Extract(_),
        )
        | C::Gate(GateCommand::List(_) | GateCommand::Show(_)) => Access::Read,
        _ => Access::Write,
    }
}

/// The actor a request runs as: the one it asks for (`--actor`, then the
/// client's `$BD_ACTOR`) if the token allows it, else the token's.
fn resolve_actor(flag: Option<&str>, env: Option<&str>, token: &Token) -> Result<String> {
    match flag.or(env).map(str::trim).filter(|a| !a.is_empty()) {
        None => Ok(token.actor.clone()),
        // Actors end up in the server log and the event history.
        Some(a) if a.chars().any(char::is_control) => {
            Err(Error::invalid("actor names must not contain control characters"))
        }
        Some(a) if token.allows_actor(a) => Ok(a.to_string()),
        Some(a) => Err(Error::Unauthorized(format!(
            "access token {} acts as {1} or {1}/<agent>, not {a}",
            token.name, token.actor
        ))),
    }
}

fn parse_failure(e: &clap::Error) -> ExecResponse {
    let text = e.render().to_string();
    if e.use_stderr() {
        ExecResponse { exit_code: e.exit_code(), stderr: text, ..Default::default() }
    } else {
        ExecResponse { exit_code: e.exit_code(), stdout: text, ..Default::default() }
    }
}

fn failure(e: &Error, json: bool) -> ExecResponse {
    ExecResponse { exit_code: e.exit_code(), stderr: crate::render_error(e, json), ..Default::default() }
}

/// Answer with a response known before the command runs.
fn respond(out: &mut FrameWriter, response: &ExecResponse) -> std::result::Result<(), Reject> {
    out.respond(response);
    Ok(())
}

fn lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

impl Server {
    fn new(root: PathBuf, max_body: usize) -> Server {
        let budget =
            kib(max_body.saturating_mul(BODY_COPIES)).saturating_add(kib(ANSWER_BUDGET)).max(kib(MIN_BODY_BUDGET));
        Server {
            tokens: Verifier::new(&root),
            root,
            workspaces: Mutex::default(),
            inflight: Mutex::default(),
            running: Arc::new(Semaphore::new(MAX_RUNNING)),
            streams: Arc::new(Semaphore::new(MAX_STREAMING)),
            planning: Arc::new(Semaphore::new(MAX_PLANNING)),
            body_budget: Arc::new(Semaphore::new(budget as usize)),
            max_body,
            open: OpenOptions::default(),
        }
    }

    /// The workspace `<root>/<name>/.bd/bd.db`, if it exists.
    fn workspace(&self, name: &str) -> Option<Arc<Workspace>> {
        if !valid_workspace_name(name) {
            return None;
        }
        let mut map = lock(&self.workspaces);
        if let Some(ws) = map.get(name) {
            return Some(ws.clone());
        }
        let dir = self.root.join(name);
        let db = dir.join(".bd").join("bd.db");
        if !db.is_file() {
            return None;
        }
        let ws = Arc::new(Workspace { name: name.to_string(), dir, db, pool: Mutex::default() });
        map.insert(name.to_string(), ws.clone());
        Some(ws)
    }

    /// Run one command line for `token` in `ws` (on a blocking thread),
    /// answering through `out`. A request refused before the command runs
    /// returns its [`Reject`] instead.
    fn run(
        &self,
        ws: &Workspace,
        token: &Token,
        request: ExecRequest,
        started: Instant,
        mut out: FrameWriter,
    ) -> std::result::Result<(), Reject> {
        let cli = match Cli::try_parse_from(std::iter::once("bd".to_string()).chain(request.argv.iter().cloned())) {
            Ok(cli) => cli,
            Err(e) => return respond(&mut out, &parse_failure(&e)),
        };
        let json = cli.global.json;
        let name = crate::command_name(&cli.command);
        let access = access(&cli.command);
        if access == Access::Local {
            let e = Error::Refused(format!("bd {name} is not available through bd serve"));
            return respond(&mut out, &failure(&e, json));
        }
        if access == Access::Write && token.role == Role::Read {
            let e =
                Error::Unauthorized(format!("access token {} is read-only; bd {name} needs a write token", token.name));
            return respond(&mut out, &failure(&e, json));
        }
        let actor = match resolve_actor(cli.global.actor.as_deref(), request.actor.as_deref(), token) {
            Ok(a) => a,
            Err(e) => return respond(&mut out, &failure(&e, json)),
        };
        // A write is applied once per request id; a retry replays its response.
        let mut _running = None;
        let mut key = None;
        if let Some(id) = request.request_id.as_deref().filter(|_| access == Access::Write) {
            if let Err(e) = bd_core::requests::validate_id(id) {
                return respond(&mut out, &failure(&e, json));
            }
            _running = Some(self.start_request(ws, id)?);
            if let Some(replayed) = self.replay(ws, token, id, json)? {
                tracing::info!(target: "bd::serve", workspace = %ws.name, token = %token.name, request = id, "replayed");
                return respond(&mut out, &replayed);
            }
            key = Some(RequestKey { id: id.to_string(), principal: token.id.clone(), recorded: false });
        }
        if access == Access::Write {
            out.hold(REPLAY_LIMIT);
        }

        let store = ws.take(&self.open).map_err(Reject::internal)?;
        let read_only = token.role == Role::Read;
        if read_only {
            // Belt and braces: read tokens cannot write even through a misclassified command.
            store.connection().pragma_update(None, "query_only", true).map_err(|e| Reject::internal(e.into()))?;
        }
        // The pooled store brings the server's own options (busy timeout, durability).
        let mut g = cli.global.clone();
        g.db = Some(ws.db.clone());
        g.directory = Some(ws.dir.clone());
        g.remote = None;
        g.actor = Some(actor.clone());
        let mut app = App::new(g).map_err(Reject::internal)?;
        app.set_store(store);
        app.location = request.location;
        app.request = key;
        // What the token may override: admin-only commands, other actors' claims, human gates.
        let policy = token.policy();
        // Output streams to the client as the command writes it.
        let out = Rc::new(RefCell::new(out));
        let capture = Capture {
            stdin: request.stdin,
            files_in: request.files,
            admin: policy.admin,
            human: policy.human,
            token_actor: policy.actor,
            ..Capture::new(Box::new(out.clone()))
        };
        let (exit_code, captured) = io::capture(capture, || crate::execute(&mut app, &cli.command));
        let recorded = app.request.as_ref().filter(|k| k.recorded).map(|k| k.id.clone());
        if let Some(store) = app.take_store() {
            if !read_only || store.connection().pragma_update(None, "query_only", false).is_ok() {
                ws.give(store);
            }
        }
        let sent = out.borrow_mut().finish(Exit { exit_code, stderr: lossy(captured.stderr), replayed: false });
        let sent = match sent.held {
            // A write's answer is stored before it is sent, and the request
            // released: a retry after a lost answer gets the stored one.
            Some(answer) => {
                if let Some(id) = &recorded {
                    self.save_response(ws, &actor, id, &answer);
                }
                drop(_running);
                out.borrow_mut().respond(&answer)
            }
            None => {
                if let Some(id) = &recorded {
                    tracing::info!(target: "bd::serve", workspace = %ws.name, request = %id, "output too large to keep for replay");
                }
                sent
            }
        };
        if out.borrow().refused() {
            tracing::info!(target: "bd::serve", workspace = %ws.name, token = %token.name, command = name, "too many answers streaming");
            return Err(Reject::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "the server is busy sending other large answers; retry shortly",
                5,
            ));
        }
        tracing::info!(
            target: "bd::serve",
            workspace = %ws.name,
            token = %token.name,
            %actor,
            command = name,
            exit_code,
            bytes = sent.bytes,
            ms = started.elapsed().as_millis() as u64,
            "exec"
        );
        if sent.streamed {
            tracing::debug!(target: "bd::serve", workspace = %ws.name, bytes = sent.bytes, peak = sent.peak, "streamed");
        }
        Ok(())
    }

    fn start_request(&self, ws: &Workspace, id: &str) -> std::result::Result<InFlight<'_>, Reject> {
        let key = format!("{}/{id}", ws.name);
        if !lock(&self.inflight).insert(key.clone()) {
            let msg = format!("request {id} is still running; retry shortly");
            return Err(Reject::new(StatusCode::CONFLICT, "pending", msg, 8));
        }
        Ok(InFlight { server: self, key })
    }

    /// The stored outcome of an earlier attempt of request `id`, if any.
    fn replay(
        &self,
        ws: &Workspace,
        token: &Token,
        id: &str,
        json: bool,
    ) -> std::result::Result<Option<ExecResponse>, Reject> {
        let store = ws.take(&self.open).map_err(Reject::internal)?;
        let record = store.read(|r| bd_core::requests::get(r.conn(), id));
        ws.give(store);
        let Some(record) = record.map_err(Reject::internal)? else {
            return Ok(None);
        };
        if record.principal != token.id {
            let msg = format!("request id {id} belongs to another access token");
            return Err(Reject::new(StatusCode::CONFLICT, "conflict", msg, 13));
        }
        let mut response = match record.response.as_deref().map(serde_json::from_str::<ExecResponse>) {
            Some(Ok(r)) => r,
            // Applied, but its output was too large to keep, or the server stopped before storing it.
            _ => failure(
                &Error::AnswerLost(format!(
                    "request {id} was applied, but its answer was not kept (more than {} MiB of output, or the \
                     server stopped first)",
                    REPLAY_LIMIT >> 20
                )),
                json,
            ),
        };
        response.replayed = true;
        Ok(Some(response))
    }

    fn save_response(&self, ws: &Workspace, actor: &str, id: &str, response: &ExecResponse) {
        let saved = serde_json::to_string(response).map_err(Error::from).and_then(|text| {
            let mut store = ws.take(&self.open)?;
            let r = store.write("request.response", actor, |tx| tx.save_request_response(id, &text));
            ws.give(store);
            r
        });
        if let Err(e) = saved {
            tracing::warn!(target: "bd::serve", workspace = %ws.name, request = id, error = %e, "response not stored for replay");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_paths() {
        assert_eq!(exec_path("/w/bd-sync/v2/exec"), Some(("bd-sync", 2)));
        assert_eq!(exec_path("/bd/w/proj/v2/exec"), Some(("proj", 2)), "under an unstripped proxy prefix");
        assert_eq!(exec_path("/w/v2/v1/exec"), Some(("v2", 1)), "older clients learn the protocol changed");
        for bad in ["/w//v2/exec", "/w/a/b/v2/exec", "/v2/exec", "/w/x/v2/exec/", "/w/x/vx/exec", "/w/x"] {
            assert_eq!(exec_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn body_budget_permits_are_kib() {
        assert_eq!((kib(0), kib(1), kib(1024), kib(1025)), (1, 1, 1, 2));
        assert_eq!(kib((4096 << 20) * BODY_COPIES), 8 << 20, "the largest --max-body-mib fits");
        // A maximum-size request, with its answer's share, fits in the budget.
        for max_body in [1 << 20, 64 << 20, 4096 << 20] {
            let server = Server::new(PathBuf::from("."), max_body);
            let request = kib(max_body * BODY_COPIES) + kib(ANSWER_BUDGET);
            assert!(server.body_budget.available_permits() >= request as usize, "--max-body-mib {}", max_body >> 20);
        }
    }

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("bd").chain(args.iter().copied())).unwrap().command
    }

    #[test]
    fn commands_are_classified_for_remote_access() {
        for (args, want) in [
            (&["init"][..], Access::Local),
            (&["serve", "--root", "."][..], Access::Local),
            (&["bench"][..], Access::Local),
            (&["remote", "show"][..], Access::Local),
            (&["events", "--follow"][..], Access::Local),
            (&["playbook", "extract", "x", "--save"][..], Access::Local),
            (&["show", "t-1"][..], Access::Read),
            (&["ready"][..], Access::Read),
            (&["events"][..], Access::Read),
            (&["dep", "tree", "t-1"][..], Access::Read),
            (&["config", "get", "lease.ttl"][..], Access::Read),
            (&["playbook", "extract", "x"][..], Access::Read),
            (&["prime"][..], Access::Read),
            (&["create", "x"][..], Access::Write),
            (&["claim", "--next"][..], Access::Write),
            (&["dep", "add", "a", "b"][..], Access::Write),
            (&["events", "prune", "--keep", "1"][..], Access::Write),
            (&["config", "set", "lease.ttl", "1m"][..], Access::Write),
            (&["playbook", "plan", "x"][..], Access::Write),
            // A client's playbooks travel with the command and change nothing about it.
            (&["--playbook-bundle", "b.json", "playbook", "show", "x"][..], Access::Read),
            (&["--playbook-bundle", "b.json", "playbook", "plan", "x"][..], Access::Write),
            (&["--playbook-bundle", "b.json", "playbook", "run", "x"][..], Access::Write),
            (&["gate", "check"][..], Access::Write),
            (&["doctor"][..], Access::Write),
            (&["batch"][..], Access::Write),
        ] {
            assert_eq!(access(&parse(args)), want, "{args:?}");
        }
    }

    #[test]
    fn requested_actors_must_be_allowed_by_the_token() {
        let t = Token {
            id: "i".into(),
            name: "alice-laptop".into(),
            actor: "alice".into(),
            role: Role::Write,
            kind: auth::Kind::Agent,
            workspaces: vec!["*".into()],
            sha256: String::new(),
            created_at: String::new(),
            revoked_at: None,
        };
        assert_eq!(resolve_actor(None, None, &t).unwrap(), "alice");
        assert_eq!(resolve_actor(None, Some("alice/agent-2"), &t).unwrap(), "alice/agent-2");
        assert_eq!(resolve_actor(Some("alice/x"), Some("bob"), &t).unwrap(), "alice/x", "--actor wins over the env");
        assert_eq!(resolve_actor(Some("bob"), None, &t).unwrap_err().exit_code(), 7);
        assert_eq!(resolve_actor(Some("  "), None, &t).unwrap(), "alice");
        assert_eq!(resolve_actor(Some("alice/x\nforged log line"), None, &t).unwrap_err().exit_code(), 2);
    }
}
