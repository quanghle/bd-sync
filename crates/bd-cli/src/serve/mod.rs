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
//! `<root>/server.db` holds the access tokens (`server_db.rs`), and `<root>/auth.toml`
//! turns on sign-in, served at `POST /v2/auth/<provider>/{device,token}`
//! without a token (`oauth/`); `POST /v2/auth/revoke` revokes the token it
//! is sent with, if it came from sign-in, and `POST /v2/auth/refresh` renews
//! the sign-in whose refresh token it is sent with. `POST /w/<name>/mcp`
//! serves the workspace's MCP tools over Streamable HTTP (`mcp/http.rs`; tool
//! calls run as `run` runs a command line, through `ToolRunner`). `GET
//! /healthz` answers `ok` without a token.
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
//!
//! Followers: `events --since N --wait D` (what remote `events --follow`
//! sends) waits for a matching event before its command runs, without a
//! command slot, a database connection or memory budget (`follow.rs`). Up to
//! `--max-followers` requests wait at once, for at most `--max-wait`; others,
//! and requests too large to hold outside the budget, run at once, and their
//! clients poll.
//!
//! Here: the server's state (`Server`), workspaces, authorizing a request
//! and its actor, access classes (`access`). Beside it: `listen`
//! (connections, TLS, shutdown), `routes` (path and method to endpoint),
//! `exec` (`/v2/exec`), `signin` (`/v2/auth/…`), `authorization` (the OAuth
//! authorization server's endpoints and pages), `mcp_endpoint` (`/w/<name>/mcp`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{SocketAddr, ToSocketAddrs};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bd_core::{Error, OpenOptions, Queries, Result, Store};
use clap::Parser;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;

use crate::actor::{self, Resolved, Source};
use crate::app::{App, RequestKey};
use crate::auth::{self, Role, Token, Verified, Verifier};
use crate::cli::*;
use crate::follow::{self, Feeds, HeadReader, Subscription};
use crate::io::{self, Capture};
use crate::jobs;
use crate::mcp::{self, Ran, http as mcp_http};
use crate::oauth_server::{authorize, cimd, pages, token};
use crate::protocol::{
    ErrorBody, ErrorDetail, ExecRequest, ExecResponse, Exit, FRAMES_CONTENT_TYPE, PROTOCOL, PROTOCOL_HEADER,
    RefreshRequest, RevokeAnswer, SignInAnswer, SignInPoll, SignInStart, valid_workspace_name,
};
use crate::stream::{FrameWriter, Limits, ResponseBody, Stalls};
use crate::{oauth, oauth_server};

mod authorization;
mod check;
mod exec;
mod listen;
mod mcp_endpoint;
mod routes;
mod signin;

use authorization::*;
use exec::*;
use listen::*;
use mcp_endpoint::*;
use routes::*;
use signin::*;

/// Commands running at once; further requests wait for a slot.
const MAX_RUNNING: usize = 32;
/// Open connections; further ones are closed at once.
const MAX_CONNECTIONS: usize = 512;
/// Open connections from one address, unless it is this machine's (a proxy
/// in front, whose connections are everyone's): one host cannot take them all.
const MAX_CONNECTIONS_PER_PEER: usize = MAX_CONNECTIONS / 8;
/// Memory for requests in progress, across all connections: this much, or
/// enough for one maximum-size request if `--max-body-mib` is larger.
const MIN_BODY_BUDGET: usize = 256 << 20;
/// A request's body briefly exists twice (collected chunks and the parsed copy).
const BODY_COPIES: usize = 2;
/// How long a request waits for body budget or a command slot before the
/// client is asked to retry (503).
const QUEUE_WAIT: Duration = Duration::from_secs(15);
/// How long a request's headers may take, counted from when the connection
/// waits for them: so also how long an idle keep-alive connection is kept
/// for its next request (hyper times both as one). Long enough that a
/// client's next tool call reuses its connection (nginx's keep-alive
/// default); a client trickling headers is bounded by it and by
/// `MAX_CONNECTIONS_PER_PEER`.
const HEADER_TIMEOUT: Duration = Duration::from_secs(75);
/// Matches the client's own limit for a whole request.
const BODY_TIMEOUT: Duration = Duration::from_secs(120);
/// Connections close after this long, so a client that stops reading cannot hold a response forever: gracefully,
/// the answer in progress finished first, within `LIFETIME_GRACE`.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(15 * 60);
const LIFETIME_GRACE: Duration = Duration::from_secs(2 * 60);
/// hyper's per-connection read buffer, held before authentication (hyper's default is ~400 KiB).
const READ_BUFFER: usize = 64 << 10;
/// Idle database connections kept per workspace, each for at most `POOL_IDLE`.
const MAX_POOLED: usize = 16;
const POOL_IDLE: Duration = Duration::from_secs(5 * 60);
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
/// The most requests `--max-followers` lets wait for events: half the
/// connections, so that followers cannot take all of them.
const MAX_FOLLOWERS: usize = MAX_CONNECTIONS / 2;
/// The largest request that waits for events. A waiting request holds no
/// memory budget, only its parsed request, so all of them hold at most
/// `--max-followers` times this (their command lines are shorter still:
/// `follow::requested`). Larger ones (sent with stdin, say) run at once.
const MAX_WAITING_BODY: usize = 16 << 10;
/// The range of `--max-wait`.
const MAX_WAIT_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(5 * 60));
/// On shutdown, how long waiting followers may take to get their answers.
const FOLLOWERS_GRACE: Duration = Duration::from_secs(5);
/// GitHub sign-in requests handled at once, each waiting on GitHub; more
/// are answered 503 at once, which clients retry.
const MAX_SIGN_INS: usize = 8;
/// Account notifications handled at once.
const MAX_NOTIFIED: usize = 2;
/// OAuth client registrations handled at once, each rewriting the
/// registry; more are answered 503 at once.
const MAX_REGISTERING: usize = 2;
/// The largest body of a sign-in request.
const MAX_SIGN_IN_BODY: usize = 16 << 10;
/// The largest body of a consent page's decision.
const MAX_CONSENT_BODY: usize = 4 << 10;
/// The largest provider's answer posted to a callback (an ID token and the
/// user's name with the code, which are not read).
const MAX_RELAYED_BODY: usize = 32 << 10;
/// The longest MCP message a client may POST.
const MAX_MCP_BODY: usize = 1 << 20;
/// An MCP answer's share of the body budget: its tool's output (up to
/// `mcp::local::OUTPUT_LIMIT`) is held, escaped into the result's text, and
/// serialized, and the serialized answer is held until it is sent.
const MCP_ANSWER_BUDGET: usize = 3 * mcp::local::OUTPUT_LIMIT;

type Body = ResponseBody;

pub fn cmd_serve(app: &mut App, a: &ServeArgs) -> Result<()> {
    io::require_local("bd serve")?;
    match &a.action {
        Some(ServeAction::Token(cmd)) => auth::cmd_token(app, cmd),
        Some(ServeAction::Check(c)) => check::check(app, c),
        None => run(a),
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

    fn busy(doing: &str) -> Reject {
        let msg = format!("the server is busy {doing}; retry shortly");
        Reject::new(StatusCode::SERVICE_UNAVAILABLE, "busy", msg, 5)
    }

    fn shutting_down() -> Reject {
        Reject::new(StatusCode::SERVICE_UNAVAILABLE, "remote", "the server is shutting down", 8)
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

/// Run `f` on a blocking thread.
/// Why a request's body could not be had.
enum BodyError {
    /// Longer than allowed.
    TooLarge,
    Unreadable(String),
    /// Not all there within the wait.
    Late(Duration),
}

/// The whole body of a request, at most `max` bytes, within `wait`.
async fn read_body(body: Incoming, max: usize, wait: Duration) -> std::result::Result<Bytes, BodyError> {
    match tokio::time::timeout(wait, Limited::new(body, max).collect()).await {
        Ok(Ok(b)) => Ok(b.to_bytes()),
        Ok(Err(e)) if e.is::<LengthLimitError>() => Err(BodyError::TooLarge),
        Ok(Err(e)) => Err(BodyError::Unreadable(e.to_string())),
        Err(_) => Err(BodyError::Late(wait)),
    }
}

impl BodyError {
    /// The answer of bd's own endpoints (`what` the request is, at most `max` bytes).
    fn response(&self, what: &str, max: usize) -> Response<Body> {
        match self {
            BodyError::TooLarge => {
                let msg = format!("{what} larger than {} KiB", max >> 10);
                Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "invalid", msg, 2).response()
            }
            BodyError::Unreadable(e) => {
                Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("reading the request: {e}"), 2).response()
            }
            BodyError::Late(wait) => {
                let msg = format!("the request body did not arrive within {}s", wait.as_secs());
                Reject::new(StatusCode::REQUEST_TIMEOUT, "remote", msg, 8).response()
            }
        }
    }

    /// The answer of the OAuth endpoints (RFC 6749 section 5.2), `too_large` the code for a body too large.
    fn oauth(&self, too_large: &str, max: usize) -> Response<Body> {
        match self {
            BodyError::TooLarge => {
                let why = format!("the request is larger than {} KiB", max >> 10);
                oauth_error(StatusCode::PAYLOAD_TOO_LARGE, too_large, &why)
            }
            BodyError::Unreadable(e) => {
                oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &format!("reading the request: {e}"))
            }
            BodyError::Late(wait) => {
                let why = format!("the request body did not arrive within {}s", wait.as_secs());
                oauth_error(StatusCode::REQUEST_TIMEOUT, "invalid_request", &why)
            }
        }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) => Err(Error::Io(std::io::Error::other(format!("a sign-in step failed: {e}")))),
    }
}

fn denied() -> Reject {
    Reject::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or invalid access token (sent as a bearer token in the Authorization header)",
        7,
    )
}

/// The bearer token of the Authorization header, if it has one.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, secret) = value.trim().split_once(' ')?;
    Some(secret.trim()).filter(|s| scheme.eq_ignore_ascii_case("bearer") && !s.is_empty())
}

fn authenticate(server: &Server, headers: &HeaderMap) -> std::result::Result<Token, Reject> {
    let secret = bearer(headers).ok_or_else(denied)?;
    match server.tokens.verify(secret) {
        Ok(Verified::Valid(token)) => Ok(token),
        Ok(Verified::Expired(token)) => {
            let at = token.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default();
            let renew = match &token.identity {
                Some(g) => format!("sign in again: `bd remote login --provider {}`", g.provider),
                None => "the server's admin issues new ones".to_string(),
            };
            let msg = format!("access token {} expired at {at}; {renew}", token.name);
            Err(Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7))
        }
        Ok(Verified::Unknown) => Err(denied()),
        Err(Error::Busy(_)) => Err(Reject::busy("checking access tokens")),
        Err(e) => Err(Reject::internal(e)),
    }
}

/// The permission bits of the directory `dir` if its group or others may
/// do anything in it (Unix; never elsewhere).
fn dir_open_to_others(dir: &std::path::Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir).ok()?.permissions().mode() & 0o777;
        (mode & 0o077 != 0).then_some(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

/// The permission bits of `file` if its group or others may read or write
/// it (Unix; never elsewhere).
fn open_to_others(file: &std::path::Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(file).ok()?.permissions().mode() & 0o777;
        (mode & 0o066 != 0).then_some(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        None
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
    Reject::busy(doing).response()
}

fn shutting_down() -> Response<Body> {
    Reject::shutting_down().response()
}

/// The largest body read and dropped before a refusal sent without reading it.
const DRAIN_MAX: usize = 16 << 10;

/// `response`, once the request's `body` (if it was not read) is read and
/// dropped, when small: hyper closes a connection whose request body was
/// left unread, and a client's next request would need a new one (often
/// right after a refusal: the first, unauthenticated, MCP request).
async fn drained(body: Option<Incoming>, response: Response<Body>) -> Response<Body> {
    if let Some(body) = body {
        let _ = read_body(body, DRAIN_MAX, Duration::from_secs(1)).await;
    }
    response
}

/// Wait up to `QUEUE_WAIT` for `permits` of `slots`; past it the server is
/// busy `doing` what holds them.
async fn queue(slots: &Arc<Semaphore>, permits: u32, doing: &str) -> Result<OwnedSemaphorePermit, Reject> {
    match tokio::time::timeout(QUEUE_WAIT, slots.clone().acquire_many_owned(permits)).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(Reject::shutting_down()),
        Err(_) => Err(Reject::busy(doing)),
    }
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
    /// Requests waiting for events: one permit each.
    followers: Arc<Semaphore>,
    waits: Waits,
    feeds: Arc<Feeds>,
    /// Sign-in requests running, which anyone may send: device flows, the
    /// browser's sign-in at a provider, codes redeemed.
    sign_ins: Arc<Semaphore>,
    /// Refreshes running: of sign-ins, never waiting behind anyone's sign-in.
    refreshing: Arc<Semaphore>,
    /// Providers' account notifications being handled.
    notified: Arc<Semaphore>,
    /// OAuth client registrations running.
    registering: Arc<Semaphore>,
    /// OAuth clients' metadata documents, fetched and kept for a while.
    documents: cimd::Documents,
    /// Authorizations under way.
    flows: Mutex<authorize::Flows>,
    /// Sign-ins completing, and the answers of those that issued tokens.
    issued: Mutex<Issuances>,
    /// Refreshes running, by their refresh token, and the answers of those
    /// that issued tokens, by their refresh token and request id.
    refreshes: Mutex<Issuances>,
    /// Set when the server shuts down.
    stopping: watch::Sender<bool>,
    /// `--public-url`, normalized: MCP endpoints name themselves by it.
    public_url: Option<String>,
    /// Whether clients connect over TLS, for URLs derived from requests.
    https: bool,
}

/// How a request waiting for events ended its wait.
#[derive(Clone, Copy, Debug)]
struct Waited {
    took: Duration,
    /// No event matching the request's filters follows its `--since` up to
    /// here: its command runs from here, which prints the same events.
    since: i64,
}

/// Limits of requests waiting for events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waits {
    /// Requests waiting at once (`--max-followers`).
    followers: usize,
    /// The longest one waits (`--max-wait`).
    longest: Duration,
}

impl Default for Waits {
    fn default() -> Waits {
        Waits { followers: MAX_FOLLOWERS, longest: Duration::from_secs(25) }
    }
}

impl Waits {
    fn from_args(a: &ServeArgs) -> Result<Waits> {
        if a.max_followers > MAX_FOLLOWERS {
            return Err(Error::invalid(format!(
                "--max-followers {}: use 0 to {MAX_FOLLOWERS} (half of the {MAX_CONNECTIONS} connections the server \
                 accepts)",
                a.max_followers
            )));
        }
        let longest = bd_core::time::parse_duration(&a.max_wait)
            .map_err(|e| Error::invalid(format!("--max-wait {}: {e}", a.max_wait)))?;
        let (low, high) = MAX_WAIT_RANGE;
        if longest < low || longest > high {
            return Err(Error::invalid(format!("--max-wait {}: use 1s to 5m", a.max_wait)));
        }
        Ok(Waits { followers: a.max_followers, longest })
    }
}

struct Workspace {
    name: String,
    dir: PathBuf,
    db: PathBuf,
    /// Idle connections, the last given back on top, with when.
    pool: Mutex<Vec<(Store, Instant)>>,
}

impl Workspace {
    fn take(&self, open: &OpenOptions) -> Result<Store> {
        match lock(&self.pool).pop() {
            Some((store, _)) => Ok(store),
            None => Store::open(&self.db, open.clone()),
        }
    }

    /// Give `store` back; connections idle for `POOL_IDLE` (at the bottom,
    /// as the busiest are taken from the top) are closed, so a burst's
    /// connections and their caches do not stay.
    fn give(&self, store: Store) {
        let mut pool = lock(&self.pool);
        let idle = pool.iter().take_while(|(_, at)| at.elapsed() >= POOL_IDLE).count();
        let closed: Vec<(Store, Instant)> = pool.drain(..idle).collect();
        if pool.len() < MAX_POOLED {
            pool.push((store, Instant::now()));
        }
        drop(pool);
        drop(closed);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reads the events head of `ws` with a pooled connection.
fn head_reader(ws: Arc<Workspace>, open: OpenOptions) -> HeadReader {
    Arc::new(move || {
        let store = ws.take(&open)?;
        let head = store.read(|r| r.event_head());
        ws.give(store);
        head
    })
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
        C::Init(_) | C::Serve(_) | C::Mcp(_) | C::Remote(_) | C::Hook(_) | C::Bench(_) | C::BenchWorker(_) => {
            Access::Local
        }
        C::Events(a) if a.follow => Access::Local,
        C::Events(a) if a.action.is_none() => Access::Read,
        C::Playbook(PlaybookCommand::Extract(a)) if a.save => Access::Local,
        // They write into the client's checkout, reading the server's sets with Read requests.
        C::Agents(
            AgentsCommand::Status(_) | AgentsCommand::Pull(_) | AgentsCommand::Approve(_) | AgentsCommand::Watch(_),
        ) => Access::Local,
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
        | C::Gate(GateCommand::List(_) | GateCommand::Show(_))
        | C::Agents(AgentsCommand::Manifest(_) | AgentsCommand::Fetch(_)) => Access::Read,
        _ => Access::Write,
    }
}

/// Whether `token` may run `cli`'s command here, and the actor it runs as
/// (see [`resolve_actor`]).
fn authorize(cli: &Cli, token: &Token, env: Option<&str>, session: Option<&str>) -> Result<(Access, Resolved)> {
    let name = crate::command_name(&cli.command);
    let access = access(&cli.command);
    if access == Access::Local {
        return Err(Error::Refused(format!("bd {name} is not available through bd serve")));
    }
    if access == Access::Write && token.role == Role::Read {
        let msg = format!("access token {} is read-only; bd {name} needs a write token", token.name);
        return Err(Error::Unauthorized(msg));
    }
    Ok((access, resolve_actor(cli.global.actor.as_deref(), env, session, token)?))
}

/// The actor a request runs as: the one it asks for (`--actor`, then the
/// client's `$BD_ACTOR`) if the token allows it; else the token's actor, as
/// `<token actor>/<session>` when the client runs in an agent session.
fn resolve_actor(flag: Option<&str>, env: Option<&str>, session: Option<&str>, token: &Token) -> Result<Resolved> {
    let resolved = resolve_token_actor(flag, env, session, token)?;
    if auth::is_reserved_actor(&resolved.actor) {
        return Err(Error::Unauthorized(format!(
            "actor {} is reserved for bd serve's background writes; access token {} may not act as it",
            resolved.actor, token.name
        )));
    }
    Ok(resolved)
}

fn resolve_token_actor(
    flag: Option<&str>,
    env: Option<&str>,
    session: Option<&str>,
    token: &Token,
) -> Result<Resolved> {
    let named = |a: &str, source, from: &str| match a {
        // Actors end up in the server log and the event history.
        a if a.chars().any(char::is_control) => Err(Error::invalid("actor names must not contain control characters")),
        a if token.allows_actor(a) => Ok(Resolved::new(a, source, from)),
        a => Err(Error::Unauthorized(format!(
            "access token {} acts as {1} or {1}/<agent>, not {a}",
            token.name, token.actor
        ))),
    };
    if let Some(a) = flag.map(str::trim).filter(|a| !a.is_empty()) {
        return named(a, Source::Flag, "--actor");
    }
    if let Some(a) = env.map(str::trim).filter(|a| !a.is_empty()) {
        return named(a, Source::Env, "the client's $BD_ACTOR");
    }
    match session.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) if !actor::is_label(s) => Err(Error::invalid(format!(
            "invalid session name {s:?}: letters, digits, '.', '_' and '-', at most {} characters",
            actor::MAX_LABEL
        ))),
        Some(s) => {
            let a = format!("{}/{s}", token.actor);
            bd_core::store::validate_actor(&a)?;
            named(&a, Source::Session, "the access token's actor + the client's session")
        }
        None => Ok(Resolved::new(token.actor.clone(), Source::Default, "the access token's actor")),
    }
}

impl Server {
    fn new(root: PathBuf, max_body: usize, waits: Waits) -> Server {
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
            followers: Arc::new(Semaphore::new(waits.followers)),
            waits,
            feeds: Arc::new(Feeds::new(follow::HEAD_CHECK_EVERY, follow::HEAD_CHECK_GAP)),
            sign_ins: Arc::new(Semaphore::new(MAX_SIGN_INS)),
            refreshing: Arc::new(Semaphore::new(MAX_SIGN_INS)),
            notified: Arc::new(Semaphore::new(MAX_NOTIFIED)),
            registering: Arc::new(Semaphore::new(MAX_REGISTERING)),
            documents: cimd::Documents::new(),
            flows: Mutex::default(),
            issued: Mutex::default(),
            refreshes: Mutex::default(),
            stopping: watch::Sender::new(false),
            public_url: None,
            https: false,
        }
    }

    /// The issuer of the server's authorization server, if `auth.toml` turns
    /// it on (read for each request, as sign-ins do); an error if `auth.toml`
    /// is not valid or `--public-url` cannot be an issuer.
    fn issuer(&self) -> std::result::Result<Option<String>, String> {
        match oauth::load_oauth(&self.root) {
            Ok(Some(_)) => oauth_server::issuer(self.public_url.as_deref()).map(Some),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Run `f`, a step of an authorization, with what it needs of the server.
    fn authorizing<T>(&self, issuer: &str, f: impl FnOnce(&authorize::Ctx<'_>) -> T) -> T {
        let exists = |name: &str| self.workspace(name).is_some();
        f(&authorize::Ctx {
            root: &self.root,
            issuer,
            documents: &self.documents,
            flows: &self.flows,
            workspace_exists: &exists,
        })
    }

    /// The server's URL as clients reach it: `--public-url`, else derived
    /// from the request (`Host`, the path prefix before `/w/`).
    fn base_url(&self, headers: &HeaderMap, uri: &hyper::Uri, prefix: &str) -> Option<String> {
        if let Some(url) = &self.public_url {
            return Some(url.clone());
        }
        let host =
            headers.get(header::HOST).and_then(|h| h.to_str().ok()).or_else(|| uri.authority().map(|a| a.as_str()));
        mcp_http::request_base(self.https, host, prefix)
    }

    /// The workspace `<root>/<name>/.bd/bd.db`, if it exists.
    fn workspace(&self, name: &str) -> Option<Arc<Workspace>> {
        if !valid_workspace_name(name) {
            return None;
        }
        if let Some(ws) = lock(&self.workspaces).get(name) {
            return Some(ws.clone());
        }
        // The files are looked at without holding the map: other requests' workspaces are found meanwhile.
        let dir = self.root.join(name);
        let db = dir.join(".bd").join("bd.db");
        if !db.is_file() {
            return None;
        }
        // Only the directory's own name: on a case-insensitive filesystem, `PROJ` would open `proj` and get past
        // tokens and sign-in rules that name `proj`.
        let entries = std::fs::read_dir(&self.root).ok()?;
        if !entries.flatten().any(|e| e.file_name() == std::ffi::OsStr::new(name)) {
            return None;
        }
        let ws = Arc::new(Workspace { name: name.to_string(), dir, db, pool: Mutex::default() });
        Some(lock(&self.workspaces).entry(name.to_string()).or_insert(ws).clone())
    }

    /// Hold a request `events --since N --wait D` until an event matching its
    /// filters follows `N`, its wait ends (at most `--max-wait`), or the
    /// server stops. Meanwhile it holds no command slot, connection or
    /// budget: only a place among the followers, and it checks again each
    /// time the workspace's events head moves past what it has seen. Then
    /// the command runs; or the request is refused (busy, shutting down).
    async fn wait_for_events(
        self: &Arc<Self>,
        ws: &Arc<Workspace>,
        wait: follow::Wait,
    ) -> std::result::Result<Waited, Reject> {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + wait.wait.min(self.waits.longest);
        let mut stopping = self.stopping.subscribe();
        let args = Arc::new(wait.args);
        let mut cursor = wait.since;
        let mut follower: Option<(OwnedSemaphorePermit, Subscription)> = None;
        loop {
            if *stopping.borrow() {
                return Err(Reject::shutting_down());
            }
            let slot = queue(&self.running, 1, "running other commands").await?;
            let (srv, ws2, args2) = (self.clone(), ws.clone(), args.clone());
            let probed = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                srv.probe(&ws2, &args2, cursor)
            })
            .await;
            match probed {
                // Nothing up to the head matched: the next check starts there.
                Ok(Ok((false, head))) => cursor = cursor.max(head),
                // Found, or failed: the command prints the events, or reports the failure.
                _ => return Ok(Waited { took: started.elapsed(), since: cursor }),
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(Waited { took: started.elapsed(), since: cursor });
            }
            let feed = match &mut follower {
                Some((_, feed)) => feed,
                None => {
                    // Past the cap, the request runs at once, and its client polls.
                    let Ok(permit) = self.followers.clone().try_acquire_owned() else {
                        tracing::debug!(target: "bd::serve", workspace = %ws.name, "too many followers; not waiting");
                        return Ok(Waited { took: started.elapsed(), since: cursor });
                    };
                    tracing::debug!(target: "bd::serve", workspace = %ws.name, cursor, "waiting for events");
                    let feed = self.feeds.subscribe(&ws.name, || head_reader(ws.clone(), self.open.clone()));
                    &mut follower.insert((permit, feed)).1
                }
            };
            tokio::select! {
                _ = feed.past(cursor) => {}
                _ = tokio::time::sleep_until(deadline) => return Ok(Waited { took: started.elapsed(), since: cursor }),
                _ = stopping.wait_for(|stop| *stop) => return Err(Reject::shutting_down()),
            }
        }
    }

    /// Whether an event matching `args`' filters follows `cursor` in `ws`; and its events head.
    fn probe(&self, ws: &Workspace, args: &EventsArgs, cursor: i64) -> Result<(bool, i64)> {
        let store = ws.take(&self.open)?;
        let found = store.read(|r| {
            let q = crate::commands::event_query(r, args)?;
            crate::commands::events_after(r, &q, cursor)
        });
        ws.give(store);
        found
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
        waited: Option<Waited>,
        mut out: FrameWriter,
    ) -> std::result::Result<(), Reject> {
        let mut cli = match Cli::try_parse_from(std::iter::once("bd".to_string()).chain(request.argv.iter().cloned())) {
            Ok(cli) => cli,
            Err(e) => return respond(&mut out, &parse_failure(&e)),
        };
        if let (Some(w), Command::Events(a)) = (waited, &mut cli.command) {
            a.since = Some(w.since);
        }
        let json = cli.global.json;
        let name = crate::command_name(&cli.command);
        let (access, resolved) = match authorize(&cli, token, request.actor.as_deref(), request.session.as_deref()) {
            Ok(a) => a,
            Err(e) => return respond(&mut out, &failure(&e, json)),
        };
        let actor = resolved.actor.clone();
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

        let mut app = self.open_app(ws, token, &cli.global, resolved).map_err(Reject::internal)?;
        app.location = request.location;
        app.request = key;
        // What the token may override: admin-only commands, other actors' claims, human gates.
        let mut policy = token.policy();
        if request.tool_call {
            policy.admin = false;
            policy.human = false;
        }
        // Output streams to the client as the command writes it.
        let out = Rc::new(RefCell::new(out));
        let capture = Capture {
            stdin: request.stdin,
            files_in: request.files,
            admin: policy.admin,
            human: policy.human,
            token_actor: policy.actor,
            max_claims: policy.max_claims,
            token: Some(token.clone()),
            ..Capture::new(Box::new(out.clone()))
        };
        let (exit_code, captured) = io::capture(capture, || crate::execute(&mut app, &cli.command));
        if access == Access::Write {
            // Requests waiting for events check again.
            self.feeds.committed(&ws.name);
        }
        let recorded = app.request.as_ref().filter(|k| k.recorded).map(|k| k.id.clone());
        self.close_app(ws, token, &mut app);
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
            waited_ms = waited.map(|w| w.took.as_millis() as u64),
            "exec"
        );
        if sent.streamed {
            tracing::debug!(target: "bd::serve", workspace = %ws.name, bytes = sent.bytes, peak = sent.peak, "streamed");
        }
        Ok(())
    }

    /// An app for a command of `token` in `ws`, acting as `actor`, with a
    /// pooled store: read-only for a read token.
    fn open_app(&self, ws: &Workspace, token: &Token, global: &Global, actor: Resolved) -> Result<App> {
        let store = ws.take(&self.open)?;
        if token.role == Role::Read {
            // Belt and braces: read tokens cannot write even through a misclassified command.
            store.connection().pragma_update(None, "query_only", true)?;
        }
        // The pooled store brings the server's own options (busy timeout, durability).
        let mut g = global.clone();
        g.db = Some(ws.db.clone());
        g.directory = Some(ws.dir.clone());
        g.remote = None;
        let mut app = App::new(g)?;
        app.set_actor(actor);
        app.set_store(store);
        Ok(app)
    }

    /// Give the store of an app from [`Server::open_app`] back to the pool.
    fn close_app(&self, ws: &Workspace, token: &Token, app: &mut App) {
        if let Some(store) = app.take_store() {
            if token.role != Role::Read || store.connection().pragma_update(None, "query_only", false).is_ok() {
                ws.give(store);
            }
        }
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
    fn one_address_holds_its_share_of_connections_and_loopback_is_not_counted() {
        let peers: Arc<Mutex<HashMap<std::net::IpAddr, usize>>> = Arc::default();
        let far: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let mapped: std::net::IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let mut held: Vec<PeerSlot> =
            (0..MAX_CONNECTIONS_PER_PEER).map(|_| PeerSlot::take(&peers, far).unwrap()).collect();
        assert!(PeerSlot::take(&peers, far).is_none(), "its share is taken");
        assert!(PeerSlot::take(&peers, mapped).is_none(), "the same address, written as IPv6");
        assert!(PeerSlot::take(&peers, "203.0.113.8".parse().unwrap()).is_some(), "another's are not");
        let local: Vec<PeerSlot> =
            (0..MAX_CONNECTIONS).map(|_| PeerSlot::take(&peers, "127.0.0.1".parse().unwrap()).unwrap()).collect();
        assert_eq!(local.len(), MAX_CONNECTIONS, "a proxy on this machine is everyone");
        held.pop();
        assert!(PeerSlot::take(&peers, far).is_some(), "given back when a connection ends");
        drop(held);
        assert_eq!(lock(&peers).get(&far.to_canonical()), None, "all given back: forgotten");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_open_to_others_are_told() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret");
        std::fs::write(&file, "s").unwrap();
        for (mode, told) in
            [(0o600, None), (0o400, None), (0o640, Some(0o640)), (0o604, Some(0o604)), (0o620, Some(0o620))]
        {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(open_to_others(&file), told, "{mode:o}");
        }
        let dir = tempfile::tempdir().unwrap();
        for (mode, told) in [(0o700, None), (0o500, None), (0o750, Some(0o750)), (0o701, Some(0o701))] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(dir_open_to_others(dir.path()), told, "{mode:o}");
        }
        assert_eq!(open_to_others(&dir.path().join("missing")), None);
    }

    #[test]
    fn an_authorization_page_is_never_sent_without_its_policy() {
        let mut page = pages::refusal(403, "t", "w", None);
        page.csp.push('\n');
        let r = html_page(page);
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let csp = r.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
        assert!(csp.starts_with("default-src 'none';"), "{csp}");
        let r = html_page(pages::refusal(403, "t", "w", None));
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn exec_paths() {
        assert_eq!(exec_path("/w/bd-sync/v2/exec"), Some("bd-sync"));
        assert_eq!(exec_path("/bd/w/proj/v2/exec"), Some("proj"), "under an unstripped proxy prefix");
        assert_eq!(exec_path("/w/v2/v2/exec"), Some("v2"));
        for bad in
            ["/w//v2/exec", "/w/a/b/v2/exec", "/v2/exec", "/w/x/v2/exec/", "/w/x/vx/exec", "/w/x", "/w/x/v1/exec"]
        {
            assert_eq!(exec_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn oauth_endpoints_are_served_under_the_public_path_or_stripped_only() {
        let mut server = Server::new(PathBuf::from("."), 1, Waits::default());
        for public in [None, Some("https://bd.example.com")] {
            server.public_url = public.map(String::from);
            assert_eq!(oauth_endpoint(&server, "/oauth/token"), Some(oauth_server::TOKEN), "{public:?}");
            assert_eq!(oauth_endpoint(&server, "/bd/oauth/token"), None, "{public:?}");
        }
        server.public_url = Some("https://bd.example.com/bd".into());
        assert_eq!(oauth_endpoint(&server, "/bd/oauth/register"), Some(oauth_server::REGISTER));
        assert_eq!(oauth_endpoint(&server, "/oauth/github/callback"), Some(oauth_server::CALLBACK), "stripped");
        for elsewhere in ["/bd/x/oauth/token", "/bdx/oauth/token", "/bd/bd/oauth/token", "/w/proj/oauth/authorize"] {
            assert_eq!(oauth_endpoint(&server, elsewhere), None, "{elsewhere}");
        }
        assert_eq!(oauth_endpoint(&server, "/bd/oauth/token/"), None);
    }

    #[test]
    fn mcp_paths_and_sessions() {
        assert_eq!(mcp_path("/w/proj/mcp"), Some(("", "proj")));
        assert_eq!(mcp_path("/bd/w/proj/mcp"), Some(("/bd", "proj")), "under an unstripped proxy prefix");
        for bad in ["/w//mcp", "/w/a/b/mcp", "/mcp", "/w/proj/mcp/", "/w/proj/v2/exec", "/w/a\"b/mcp", "/w/-x/mcp"] {
            assert_eq!(mcp_path(bad), None, "{bad}");
        }
        assert_eq!(exec_path("/w/proj/mcp"), None);
        assert_eq!(mcp_session(None).unwrap(), "mcp");
        assert_eq!(mcp_session(Some("x=1&session=w-2")).unwrap(), "w-2");
        for bad in ["session=", "session=a/b", "session=a%20b"] {
            assert!(mcp_session(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn sign_in_paths() {
        assert_eq!(sign_in_path("/v2/auth/github/device"), Some(("github".into(), SignInStep::Device)));
        assert_eq!(
            sign_in_path("/bd/v2/auth/github/token"),
            Some(("github".into(), SignInStep::Token)),
            "under a proxy prefix"
        );
        assert_eq!(
            sign_in_path("/v2/auth/acme-sso/token"),
            Some(("acme-sso".into(), SignInStep::Token)),
            "any provider"
        );
        for bad in [
            "/v2/auth/github/",
            "/v2/auth/github/device/",
            "/v1/auth/github/token",
            "/v2/auth/Acme/token",
            "/v2/auth/refresh",
        ] {
            assert_eq!(sign_in_path(bad), None, "{bad}");
        }
        assert_eq!(exec_path("/v2/auth/github/token"), None);
    }

    #[test]
    fn body_budget_permits_are_kib() {
        assert_eq!((kib(0), kib(1), kib(1024), kib(1025)), (1, 1, 1, 2));
        assert_eq!(kib((4096 << 20) * BODY_COPIES), 8 << 20, "the largest --max-body-mib fits");
        // A maximum-size request, with its answer's share, fits in the budget.
        for max_body in [1 << 20, 64 << 20, 4096 << 20] {
            let server = Server::new(PathBuf::from("."), max_body, Waits::default());
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
            (&["agents", "status"][..], Access::Local),
            (&["agents", "pull", "--harness", "claude", "--force"][..], Access::Local),
            (&["agents", "approve", "github", "--harness", "codex"][..], Access::Local),
            (&["agents", "watch", "--harness", "claude", "--interval", "1s"][..], Access::Local),
            (&["show", "t-1"][..], Access::Read),
            (&["ready"][..], Access::Read),
            (&["events"][..], Access::Read),
            (&["events", "--since", "5", "--wait", "30s"][..], Access::Read),
            (&["dep", "tree", "t-1"][..], Access::Read),
            (&["config", "get", "lease.ttl"][..], Access::Read),
            (&["playbook", "extract", "x"][..], Access::Read),
            (&["prime"][..], Access::Read),
            (&["agents", "manifest"][..], Access::Read),
            (&["agents", "fetch", "--harness", "codex"][..], Access::Read),
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
            expires_at: None,
            identity: None,
            max_claims: None,
            refresh: None,
            resource: None,
            client: None,
        };
        let actor = |flag, env, session| resolve_actor(flag, env, session, &t).map(|r| (r.actor, r.source));
        let code = |flag, env, session| resolve_actor(flag, env, session, &t).unwrap_err().exit_code();
        assert_eq!(actor(None, None, None).unwrap(), ("alice".into(), Source::Default));
        assert_eq!(actor(None, Some("alice/agent-2"), None).unwrap(), ("alice/agent-2".into(), Source::Env));
        assert_eq!(actor(Some("alice/x"), Some("bob"), None).unwrap().0, "alice/x", "--actor wins over the env");
        assert_eq!(code(Some("bob"), None, None), 7);
        assert_eq!(actor(Some("  "), None, None).unwrap().0, "alice");
        assert_eq!(code(Some("alice/x\nforged log line"), None, None), 2);
        // A client's agent session is a sub-actor of the token's actor, never another actor.
        assert_eq!(
            actor(None, None, Some("copilot-b9bb2788")).unwrap(),
            ("alice/copilot-b9bb2788".into(), Source::Session)
        );
        assert_eq!(actor(None, Some("alice/w1"), Some("copilot-1")).unwrap().0, "alice/w1", "$BD_ACTOR wins");
        assert_eq!(actor(Some("alice"), None, Some("copilot-1")).unwrap().0, "alice", "--actor wins");
        assert_eq!(actor(None, None, Some(" ")).unwrap().0, "alice");
        for bad in ["../bob", "a/b", "x\nforged", "-x"] {
            assert_eq!(code(None, None, Some(bad)), 2, "{bad:?}");
        }
        // bd serve's own actor stays its own, even under a token that names it.
        let server = Token { actor: "bd-serve".into(), ..t.clone() };
        for (flag, session) in [(None, None), (Some("bd-serve/x"), None), (None, Some("copilot-1"))] {
            let e = resolve_actor(flag, None, session, &server).unwrap_err();
            assert!(e.exit_code() == 7 && e.to_string().contains("reserved"), "{flag:?} {session:?}: {e}");
        }
    }
}
