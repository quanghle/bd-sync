//! Listening: the command (`run`), TLS, accepting connections (at most
//! `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_PEER` per address), serving each,
//! and shutting down.

use super::*;

pub(super) fn run(a: &ServeArgs) -> Result<()> {
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
    // Checked now so that a mistake shows at once; later loads read it again once it (or a secret file) changes.
    if let Some(sign_in) = oauth::load(&root)? {
        if let Some(o) = &sign_in.oauth {
            let issuer = oauth_server::issuer(public_url.as_deref()).map_err(Error::invalid)?;
            tracing::info!(
                target: "bd::serve",
                %issuer,
                redirect_uris = %o.redirect_uris.join(","),
                redirect_hosts = %o.redirect_hosts.join(","),
                loopback_redirects = o.loopback_redirects,
                registration = o.registration,
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
        // Every provider's sign-ins are refreshed: its rules or the authorizer decide again at each refresh.
        if let Some(github) = &sign_in.github {
            tracing::info!(
                target: "bd::serve",
                github = %github.url,
                decider,
                app = github.app.is_some(),
                token_ttl = %shown(sign_in.token_ttl),
                refresh_limit = %shown(sign_in.refresh_limit),
                refresh_idle = %shown(sign_in.refresh_idle),
                "GitHub sign-in is on, with refreshed tokens"
            );
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

/// One of [`MAX_CONNECTIONS_PER_PEER`] connections of an address, given back when dropped.
pub(super) struct PeerSlot {
    pub(super) peers: Arc<Mutex<HashMap<std::net::IpAddr, usize>>>,
    pub(super) ip: Option<std::net::IpAddr>,
}

impl PeerSlot {
    /// A slot for a connection from `ip`, unless it has all its own; loopback ones are not counted.
    pub(super) fn take(peers: &Arc<Mutex<HashMap<std::net::IpAddr, usize>>>, ip: std::net::IpAddr) -> Option<PeerSlot> {
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return Some(PeerSlot { peers: peers.clone(), ip: None });
        }
        let mut open = lock(peers);
        let n = open.entry(ip).or_insert(0);
        if *n >= MAX_CONNECTIONS_PER_PEER {
            return None;
        }
        *n += 1;
        Some(PeerSlot { peers: peers.clone(), ip: Some(ip) })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let Some(ip) = self.ip else { return };
        let mut open = lock(&self.peers);
        if let Some(n) = open.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                open.remove(&ip);
            }
        }
    }
}

pub(super) async fn serve(
    server: Arc<Server>,
    addr: SocketAddr,
    tls: Option<TlsAcceptor>,
    jobs: jobs::Config,
) -> Result<()> {
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
    let peers: Arc<Mutex<HashMap<std::net::IpAddr, usize>>> = Arc::default();
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
        let Some(from_peer) = PeerSlot::take(&peers, peer.ip()) else {
            tracing::warn!(target: "bd::serve", %peer, "too many connections from this address; closing this one");
            continue;
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            tracing::warn!(target: "bd::serve", %peer, "too many connections; closing this one");
            continue;
        };
        let server = server.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = (permit, from_peer);
            connection(server, stream, peer, tls).await;
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
pub(super) async fn connection(server: Arc<Server>, stream: TcpStream, peer: SocketAddr, tls: Option<TlsAcceptor>) {
    let _ = stream.set_nodelay(true);
    let stream = Stalls::new(stream, WRITE_STALL);
    let service = service_fn(move |req| handle(server.clone(), req));
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).max_buf_size(READ_BUFFER);
    let served = match tls {
        Some(acceptor) => match tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream)).await {
            Ok(Ok(stream)) => serve_until_lifetime(&http, TokioIo::new(stream), service, peer).await,
            Ok(Err(e)) => {
                tracing::debug!(target: "bd::serve", %peer, error = %e, "TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!(target: "bd::serve", %peer, "TLS handshake timed out");
                return;
            }
        },
        None => serve_until_lifetime(&http, TokioIo::new(stream), service, peer).await,
    };
    if let Err(e) = served {
        tracing::debug!(target: "bd::serve", %peer, error = %e, "connection closed");
    }
}

/// Serve `io` until the client closes it, or until `MAX_CONNECTION_LIFETIME`
/// has passed: then gracefully, the answer in progress (if any) finished and
/// the connection closed after it, or cut at `LIFETIME_GRACE`.
async fn serve_until_lifetime<I, S>(http: &http1::Builder, io: I, service: S, peer: SocketAddr) -> hyper::Result<()>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::HttpService<Incoming, ResBody = Body>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let conn = http.serve_connection(io, service);
    tokio::pin!(conn);
    tokio::select! {
        served = conn.as_mut() => return served,
        () = tokio::time::sleep(MAX_CONNECTION_LIFETIME) => {}
    }
    tracing::debug!(target: "bd::serve", %peer, "connection at its maximum lifetime: closing after its answer");
    conn.as_mut().graceful_shutdown();
    match tokio::time::timeout(LIFETIME_GRACE, conn).await {
        Ok(served) => served,
        Err(_) => {
            tracing::debug!(target: "bd::serve", %peer, "connection cut: its answer did not finish in time");
            Ok(())
        }
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
