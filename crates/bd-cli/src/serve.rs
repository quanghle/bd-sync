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
//! turns on GitHub sign-in, served at `POST /v2/auth/github/{device,token}`
//! without a token (`oauth.rs`); `POST /v2/auth/revoke` revokes the token it
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
        None => run(a),
    }
}

fn run(a: &ServeArgs) -> Result<()> {
    let root = a.root.as_ref().ok_or_else(|| {
        Error::invalid(
            "bd serve needs --root DIR (or $BD_SERVE_ROOT): the directory holding <name>/.bd/bd.db workspaces",
        )
    })?;
    let root = crate::app::resolve_dir(root).map_err(|e| Error::invalid(format!("--root {}: {e}", root.display())))?;
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
    let waits = Waits::from_args(a)?;
    let jobs = jobs::Config::from_args(a)?;
    let public_url = a
        .public_url
        .as_deref()
        .map(mcp_http::public_url)
        .transpose()
        .map_err(|e| Error::invalid(format!("--public-url {e}")))?;
    // Opened now (created if new) so that an unwritable root or another bd's schema shows at once.
    crate::server_db::open(&root)?;
    // The workspaces' databases hold actors and their histories, readable by whoever may enter the root.
    if let Some(mode) = dir_open_to_others(&root) {
        tracing::warn!(
            target: "bd::serve",
            root = %root.display(),
            mode = format!("{mode:o}"),
            "the root is open to others than its owner, and the workspaces' databases with it: chmod 700 it"
        );
    }
    // Checked now so that a mistake shows at once; each sign-in reads the file again.
    if let Some(sign_in) = oauth::load(&root)? {
        if let Some(o) = &sign_in.oauth {
            let issuer = oauth_server::issuer(public_url.as_deref()).map_err(Error::invalid)?;
            tracing::info!(
                target: "bd::serve",
                %issuer,
                redirect_hosts = %o.redirect_hosts.join(","),
                loopback_redirects = o.loopback_redirects,
                "OAuth sign-in for MCP clients is on"
            );
        }
        let shown = |d: Duration| bd_core::time::format_duration_ms(i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        for file in sign_in.secret_files(&root) {
            if let Some(mode) = open_to_others(&file) {
                tracing::warn!(
                    target: "bd::serve",
                    file = %file.display(),
                    mode = format!("{mode:o}"),
                    "a sign-in secret file is readable by others than its owner: chmod 600 it"
                );
            }
        }
        let decider = if sign_in.authorizer.is_some() { "the authorizer" } else { "rules" };
        if let Some(github) = &sign_in.github {
            match sign_in.refreshes("github") {
                true => tracing::info!(
                    target: "bd::serve",
                    github = %github.url,
                    decider,
                    token_ttl = %shown(sign_in.token_ttl),
                    refresh_limit = %shown(sign_in.refresh_limit),
                    refresh_idle = %shown(sign_in.refresh_idle),
                    "GitHub sign-in is on, with refreshed tokens"
                ),
                false => tracing::warn!(
                    target: "bd::serve",
                    github = %github.url,
                    decider,
                    token_ttl = %shown(sign_in.token_ttl),
                    "GitHub sign-in is on; its tokens are not refreshed (rules need github.private_key to be applied \
                     again), so people sign in again each token_ttl"
                ),
            }
        }
        // Each OIDC provider's discovery, tried once now, so that a wrong issuer shows before anyone signs in.
        for oidc in &sign_in.oidc {
            match oidc.metadata() {
                Ok(md) => tracing::info!(
                    target: "bd::serve",
                    provider = %oidc.name,
                    issuer = %oidc.issuer,
                    device_flow = md.device_authorization_endpoint.is_some(),
                    token_ttl = %shown(sign_in.token_ttl),
                    "OIDC sign-in is on, with refreshed tokens"
                ),
                Err(e) => tracing::warn!(
                    target: "bd::serve",
                    provider = %oidc.name,
                    issuer = %oidc.issuer,
                    error = %e,
                    "OIDC sign-in is on, but its provider's discovery document cannot be had now: sign-ins fail until it can"
                ),
            }
        }
        if let Some(a) = &sign_in.authorizer {
            let by = match &a.how {
                crate::authorizer::How::Command { argv, .. } => format!("command {}", argv[0]),
                crate::authorizer::How::Https { url, .. } => format!("url {url}"),
            };
            tracing::info!(
                target: "bd::serve",
                by = %by,
                timeout = %shown(a.timeout),
                max_role = a.caps.max_role.as_str(),
                human = a.caps.human,
                max_claims = ?a.caps.max_claims,
                workspaces = %a.caps.workspaces.join(","),
                refresh_grace = %a.refresh_grace.map(shown).unwrap_or_else(|| "none".into()),
                "an authorizer decides who may sign in"
            );
        }
    }
    // Before any request or background job: gate checks in this process use the server's defaults.
    io::mark_server_process();
    let mut server = Server::new(root, max_body, waits);
    server.https = tls.is_some();
    server.public_url = public_url;
    let server = Arc::new(server);
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
    let feeds = server.feeds.clone();
    let committed = Arc::new(move |workspace: &str| feeds.committed(workspace));
    let jobs = jobs::start(jobs, server.root.clone(), server.open.clone(), committed);
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
    // Clients trying to connect are refused at once, and retry.
    drop(listener);
    // Requests waiting for events are answered at once, instead of at the end of their wait.
    server.stopping.send_replace(true);
    // GitHub gates are checked again after a restart; no need to wait for gh.
    crate::gates::cancel_gh_calls();
    let all = u32::try_from(MAX_RUNNING).unwrap_or(u32::MAX);
    let commands = tokio::time::timeout(COMMANDS_GRACE, server.running.acquire_many(all));
    let followers = u32::try_from(server.waits.followers).unwrap_or(u32::MAX);
    let followers = tokio::time::timeout(FOLLOWERS_GRACE, server.followers.acquire_many(followers));
    let _ = tokio::join!(commands, followers, jobs.stop(JOBS_GRACE));
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

/// `[/<prefix>]/w/<name>/v2/exec` -> `<name>`: a proxy may serve bd under a
/// path prefix without stripping it.
fn exec_path(path: &str) -> Option<&str> {
    let (rest, version) = path.strip_suffix("/exec")?.rsplit_once("/v")?;
    let (_, name) = rest.rsplit_once("/w/")?;
    Some(name).filter(|w| version == PROTOCOL.to_string() && !w.is_empty() && !w.contains('/'))
}

/// `[/<prefix>]/w/<name>/mcp` -> `[/<prefix>]` and `<name>`.
fn mcp_path(path: &str) -> Option<(&str, &str)> {
    let (prefix, name) = path.strip_suffix("/mcp")?.rsplit_once("/w/")?;
    // Valid names only: the name goes into the URLs of WWW-Authenticate challenges.
    Some((prefix, name)).filter(|(_, w)| valid_workspace_name(w))
}

/// A step of GitHub sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignIn {
    /// Get a one-time code.
    Device,
    /// Ask whether it was entered, and get the token once it was.
    Token,
}

/// `[/<prefix>]/v2/auth/<provider>/<device|token>` -> the provider and the step.
fn sign_in_path(path: &str) -> Option<(String, SignIn)> {
    let (_, rest) = path.rsplit_once(&format!("/v{PROTOCOL}/auth/"))?;
    let (provider, step) = rest.split_once('/')?;
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if provider.is_empty() || provider.len() > 32 || !provider.chars().all(plain) {
        return None;
    }
    let step = match step {
        "device" => SignIn::Device,
        "token" => SignIn::Token,
        _ => return None,
    };
    Some((provider.to_string(), step))
}

/// The authorization server's endpoint at `path`: under the public URL's
/// path, or with it stripped by a proxy, and nowhere else, so that a proxy
/// limiting requests to these paths sees them all.
fn oauth_endpoint(server: &Server, path: &str) -> Option<&'static str> {
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
fn under_issuer<'p>(server: &Server, path: &'p str) -> &'p str {
    let public = server.public_url.as_deref().and_then(|u| u.split_once("://")).map_or("", |(_, rest)| rest);
    let prefix = public.find('/').map_or("", |i| &public[i..]);
    path.strip_prefix(prefix).filter(|r| r.starts_with('/')).unwrap_or(path)
}

async fn handle(server: Arc<Server>, req: Request<Incoming>) -> std::result::Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let oauth = oauth_endpoint(&server, &path);
    let response = if path == "/healthz" && req.method() == Method::GET {
        response(StatusCode::OK, "text/plain", Body::whole(Bytes::from_static(b"ok\n")))
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
    Ok(response)
}

/// A step of GitHub sign-in, for a client without a token yet. Each runs on
/// a blocking thread, as it waits on GitHub (`oauth.rs`).
async fn sign_in(server: &Arc<Server>, provider: String, step: SignIn, req: Request<Incoming>) -> Response<Body> {
    // The body first, small and time-limited: a slow client holds no slot meanwhile.
    let body = match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect())
        .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) if e.is::<LengthLimitError>() => {
            let msg = format!("sign-in request larger than {} KiB", MAX_SIGN_IN_BODY >> 10);
            return Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "invalid", msg, 2).response();
        }
        Ok(Err(e)) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("reading the request: {e}"), 2).response();
        }
        Err(_) => {
            let msg = format!("the request body did not arrive within {}s", HEADER_TIMEOUT.as_secs());
            return Reject::new(StatusCode::REQUEST_TIMEOUT, "remote", msg, 8).response();
        }
    };
    let bad_body =
        |e: serde_json::Error| Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("bad request body: {e}"), 2);
    let answer = match step {
        SignIn::Device => {
            let start: SignInStart = match serde_json::from_slice(&body) {
                Ok(s) => s,
                Err(e) => return bad_body(e).response(),
            };
            // Before anyone goes to GitHub for it.
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
        SignIn::Token => {
            let poll: SignInPoll = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(e) => return bad_body(e).response(),
            };
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
async fn refresh(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let Some(secret) = bearer(req.headers()).map(str::to_string) else { return denied().response() };
    let body = match tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect())
        .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) => {
            return Reject::new(StatusCode::BAD_REQUEST, "invalid", format!("reading the request: {e}"), 2).response();
        }
        Err(_) => {
            let msg = format!("the request body did not arrive within {}s", HEADER_TIMEOUT.as_secs());
            return Reject::new(StatusCode::REQUEST_TIMEOUT, "remote", msg, 8).response();
        }
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
    let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
        return busy("signing in other accounts");
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
struct Issuances {
    answers: HashMap<String, (Instant, serde_json::Value)>,
    running: HashSet<String>,
}

/// A sign-in or refresh completing: no other attempt of it runs until this
/// is dropped.
struct Completing {
    server: Arc<Server>,
    key: String,
    /// A refresh, not a sign-in.
    refresh: bool,
}

impl Drop for Completing {
    fn drop(&mut self) {
        let running = if self.refresh { &self.server.refreshes } else { &self.server.issued };
        lock(running).running.remove(&self.key);
    }
}

/// `POST /v2/auth/revoke`: revoke the request's own token, if it came from
/// GitHub sign-in (`bd remote logout`). One an admin created is kept: it may
/// serve elsewhere too, and only the admin revokes it. An expired token may
/// still be revoked; an unknown one is refused like any request. A
/// sign-in's refresh secret revokes the sign-in too: its current one, or
/// the one its latest refresh spent with that refresh's request id (body
/// `{"request_id"}`), whose answer the client may never have got.
async fn revoke_own(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
    let Some(secret) = bearer(req.headers()).map(str::to_string) else { return denied().response() };
    // Small, so that the connection stays usable.
    let body = tokio::time::timeout(HEADER_TIMEOUT, Limited::new(req.into_body(), MAX_SIGN_IN_BODY).collect()).await;
    let token = if auth::refresh_family(&secret).is_some() {
        let request_id = match body {
            Ok(Ok(b)) => serde_json::from_slice::<serde_json::Value>(&b.to_bytes())
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
    } else {
        match server.tokens.verify(&secret) {
            Ok(Verified::Valid(t) | Verified::Expired(t)) => t,
            Ok(Verified::Unknown) => return denied().response(),
            Err(e) => return Reject::internal(e).response(),
        }
    };
    if token.identity.is_none() {
        return json_response(StatusCode::OK, &RevokeAnswer { name: token.name, revoked: false });
    }
    let (root, id) = (server.root.clone(), token.id.clone());
    let revoked = blocking(move || {
        let revoked = auth::revoke_by_id(&root, &id)?;
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

/// Run `f` on a blocking thread.
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
            let renew = match token.identity {
                Some(_) => "sign in again: `bd remote login`",
                None => "the server's admin issues new ones",
            };
            let msg = format!("access token {} expired at {at}; {renew}", token.name);
            Err(Reject::new(StatusCode::UNAUTHORIZED, "unauthorized", msg, 7))
        }
        Ok(Verified::Unknown) => Err(denied()),
        Err(e) => Err(Reject::internal(e)),
    }
}

async fn exec(server: &Arc<Server>, workspace: String, req: Request<Incoming>) -> Response<Body> {
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

/// A workspace's MCP endpoint, as a request reached it.
struct Endpoint {
    workspace: String,
    /// Its URL (the OAuth resource) and its metadata's, unless the request's
    /// host is not valid and no `--public-url` is set.
    resource: Option<String>,
    metadata: Option<String>,
}

impl Endpoint {
    fn of<B>(server: &Server, prefix: &str, workspace: &str, req: &Request<B>) -> Endpoint {
        let base = server.base_url(req.headers(), req.uri(), prefix);
        Endpoint {
            workspace: workspace.to_string(),
            resource: base.as_deref().map(|b| mcp_http::resource(b, workspace)),
            metadata: base.as_deref().map(|b| mcp_http::metadata_url(b, workspace)),
        }
    }

    /// `reject` with a challenge pointing at the metadata, and its error code if any.
    fn challenge(&self, reject: Reject, error: Option<&str>) -> Response<Body> {
        let challenge =
            mcp_http::challenge(self.metadata.as_deref(), error.map(|code| (code, reject.message.as_str())));
        let mut r = reject.response();
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            r.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
        r
    }
}

/// The protected resource metadata of a workspace's MCP endpoint (RFC 9728).
/// It needs no token, and says nothing of whether the workspace exists.
fn resource_metadata<B>(server: &Server, prefix: &str, workspace: &str, req: &Request<B>) -> Response<Body> {
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
fn authorization_server_metadata(server: &Server, path: &str) -> Response<Body> {
    match server.issuer() {
        Ok(Some(issuer)) if path == oauth_server::metadata_path(&issuer) => {
            json_response(StatusCode::OK, &oauth_server::metadata(&issuer))
        }
        Ok(_) => Reject::new(StatusCode::NOT_FOUND, "not_found", "no such authorization server", 3).response(),
        Err(e) => sign_in_misconfigured(&e),
    }
}

/// `POST <issuer>/oauth/register`: register a public OAuth client (RFC
/// 7591, `oauth_server/clients.rs`), without a token, if `[oauth]` is on.
/// Served at the public URL's path, or with it stripped ([`oauth_endpoint`]).
async fn register_client(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
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
            Some(o) => oauth_server::clients::register(&root, &o, &body).map(Some),
            None => Ok(None),
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
async fn oauth_tokens(server: &Arc<Server>, revoking: bool, req: Request<Incoming>) -> Response<Body> {
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
    let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else { return busy() };
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
async fn account_events(server: &Arc<Server>, req: Request<Incoming>) -> Response<Body> {
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
    let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
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
fn refused(refusal: &token::Refusal) -> Response<Body> {
    let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut r = oauth_error(status, refusal.error, refusal.description);
    r.headers_mut().insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

/// A step of an authorization (`oauth_server/authorize.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Authorizing {
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
async fn authorizing(server: &Arc<Server>, step: Authorizing, req: Request<Incoming>) -> Response<Body> {
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
                Ok(srv.authorizing(&issuer, |cx| authorize::callback(cx, &provider, &query, browser.as_deref())))
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
            Ok((server.authorizing(&issuer, |cx| authorize::relay(cx, &provider, &body)), None))
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
            Ok((server.authorizing(&issuer, |cx| authorize::decide(cx, &body, &cookies)), None))
        }
    };
    let (answer, cookie) = match answered {
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
    if let Some(cookie) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        r.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    r
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

/// An authorization page for a browser, which no other site may frame,
/// with only what its Content-Security-Policy allows. The policy is
/// same-origin, so that the consent form's POST carries the page's Origin.
fn html_page(page: pages::Page) -> Response<Body> {
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
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response<Body> {
    let mut r = json_response(status, &serde_json::json!({ "error": error, "error_description": description }));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// `auth.toml` or `--public-url` do not let sign-in work: the details go
/// to the log, not to whoever asked.
fn sign_in_misconfigured(e: &str) -> Response<Body> {
    tracing::error!(target: "bd::serve", error = %e, "sign-in is misconfigured");
    let msg = "the server's sign-in settings are not valid; see the server log";
    Reject::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg, 1).response()
}

/// One MCP message for `workspace` (Streamable HTTP, see `mcp/http.rs`):
/// its tool calls run as [`Server::run`] runs a command line, on a blocking
/// thread with a command slot, acting as `<token actor>/mcp` (or
/// `/<session>` with `?session=<session>`), without the token's rights over
/// other actors' claims and human gates.
async fn mcp(server: &Arc<Server>, endpoint: Endpoint, req: Request<Incoming>) -> Response<Body> {
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
fn mcp_session(query: Option<&str>) -> Result<String> {
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
fn mcp_response(answer: mcp_http::Answer, budget: Option<OwnedSemaphorePermit>) -> Response<Body> {
    match answer {
        mcp_http::Answer::Accepted => response(StatusCode::ACCEPTED, "application/json", Body::whole(Bytes::new())),
        mcp_http::Answer::Message(status, message) => {
            let bytes = serde_json::to_vec(&message).unwrap_or_default();
            response(status, "application/json", Body::whole_within(bytes, budget))
        }
    }
}

fn mcp_too_large() -> Response<Body> {
    let msg = format!("an MCP message is larger than {} MiB", MAX_MCP_BODY >> 20);
    Reject::new(StatusCode::PAYLOAD_TOO_LARGE, "invalid", msg, 2).response()
}

/// Runs the tool calls of an MCP request in its workspace, as `token`.
struct ToolRunner<'a> {
    server: &'a Server,
    ws: &'a Workspace,
    token: &'a Token,
    session: &'a str,
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
    /// GitHub sign-in requests running.
    sign_ins: Arc<Semaphore>,
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

fn parse_failure(e: &clap::Error) -> ExecResponse {
    let text = e.render().to_string();
    if e.use_stderr() {
        ExecResponse { exit_code: e.exit_code(), stderr: text, ..Default::default() }
    } else {
        ExecResponse { exit_code: e.exit_code(), stdout: text, ..Default::default() }
    }
}

fn failure(e: &Error, json: bool) -> ExecResponse {
    ExecResponse { exit_code: e.exit_code(), stderr: crate::render_error(e, json, None), ..Default::default() }
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
        let mut map = lock(&self.workspaces);
        if let Some(ws) = map.get(name) {
            return Some(ws.clone());
        }
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
        map.insert(name.to_string(), ws.clone());
        Some(ws)
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
            let slot = match tokio::time::timeout(QUEUE_WAIT, self.running.clone().acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return Err(Reject::shutting_down()),
                Err(_) => return Err(Reject::busy("running other commands")),
            };
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
        assert_eq!(sign_in_path("/v2/auth/github/device"), Some(("github".into(), SignIn::Device)));
        assert_eq!(
            sign_in_path("/bd/v2/auth/github/token"),
            Some(("github".into(), SignIn::Token)),
            "under a proxy prefix"
        );
        assert_eq!(sign_in_path("/v2/auth/acme-sso/token"), Some(("acme-sso".into(), SignIn::Token)), "any provider");
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
