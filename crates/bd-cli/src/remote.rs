//! Remote workspaces: forward commands to `bd serve`.
//!
//! A workspace is remote when `--remote URL` or `$BD_REMOTE` is set, or when
//! the nearest `.bd/` holds a `remote.toml` (written by `bd remote set`):
//!
//! ```toml
//! url = "https://bd.example.com/w/proj"
//! ca_cert = "ca.pem"   # optional, relative to this file: trust a private CA
//! ```
//!
//! The access token comes from `$BD_TOKEN`, else from the user's
//! credentials file (`bd remote login`, see [`crate::credentials`]), never
//! from a file in the repository. The command line travels unchanged; the
//! server runs it and streams back its output and exit code. Each invocation
//! gets a request id that its retries reuse, so a write whose answer was lost
//! is applied once: a write's answer is held until it has arrived whole, and
//! asked for again when it does not; one that cannot be recovered fails as
//! [`Error::AnswerLost`] (exit 9), never as safe to run again. A read prints
//! a large output as it arrives, so it is not retried once it has.
//! `events --follow` and `events --wait` are long polls whose answers say
//! where the next one continues (`follow_events`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bd_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::actor;
use crate::app::{App, Out};
use crate::auth::random_hex;
use crate::cli::*;
use crate::credentials::{self, Scope};
use crate::io;
use crate::playbooks;
use crate::protocol::{
    ErrorBody, ExecRequest, ExecResponse, Exit, FRAMES_CONTENT_TYPE, Frame, PROTOCOL, PROTOCOL_HEADER,
    valid_workspace_name,
};
use crate::stream::{Cut, FrameReader};

/// How long a request that failed in transit is retried, unless
/// `$BD_REMOTE_RETRY_SECS` says otherwise (0: one attempt). A write that may
/// have run gets it again from that failure, to ask for its stored answer.
const RETRY_BUDGET: Duration = Duration::from_secs(30);
/// `bd prime` runs from session hooks, which must not stall: it retries this long.
const PRIME_RETRY_BUDGET: Duration = Duration::from_secs(3);
/// A long poll that bd serve held at least this long, then refused (busy,
/// or shutting down), waited on a live server: its retries get a fresh
/// retry time, up to [`FRESH_WINDOWS`] times in a row.
const HELD: Duration = Duration::from_secs(1);
const FRESH_WINDOWS: u32 = 5;

fn retry_budget() -> Duration {
    env("BD_REMOTE_RETRY_SECS").and_then(|s| s.parse().ok()).map_or(RETRY_BUDGET, Duration::from_secs)
}

/// A workspace on a bd server.
pub struct Remote {
    /// Workspace URL without a trailing slash.
    pub url: String,
    token: String,
    /// The CA certificates to trust instead of the system's, as read by [`Trust::load`].
    roots: Option<Vec<ureq::tls::Certificate<'static>>>,
    /// How long failures in transit are retried.
    retry: Duration,
    connect_timeout: Duration,
    /// Limit for each step of an attempt: sending the request, the server's
    /// work until its answer starts, and each wait for more of the answer.
    attempt_timeout: Duration,
    /// Limit for a whole attempt, for commands that must answer quickly.
    total_timeout: Option<Duration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteFile {
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_cert: Option<PathBuf>,
}

/// Where the remote workspace setting came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--remote URL` or `$BD_REMOTE`.
    Flag,
    /// A `.bd/remote.toml` file.
    File(PathBuf),
}

/// The remote workspace an invocation uses, before its access token is looked up.
#[derive(Clone, Debug)]
pub struct Configured {
    pub url: String,
    pub source: Source,
    pub ca_cert: Option<PathBuf>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub fn env_actor() -> Option<String> {
    env("BD_ACTOR").or_else(|| env("BEADS_ACTOR"))
}

/// `argv` without its global `--session <name>` or `--session=<name>`: the
/// session label carries it (see [`identity`]), and a server that predates
/// the flag would refuse it. Arguments after `--` are left alone.
pub fn without_session_flag(argv: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut args = argv.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--" => {
                out.push(a);
                out.extend(args.by_ref());
            }
            "--session" => {
                args.next();
            }
            s if s.starts_with("--session=") => {}
            _ => out.push(a),
        }
    }
    out
}

/// Who a request asks to act as, besides an `--actor` in its argv: the
/// client's `$BD_ACTOR`, else its agent session ([`actor::session`]), which
/// the server turns into the sub-actor `<token actor>/<session>`.
pub fn identity() -> (Option<String>, Option<String>) {
    match env_actor() {
        Some(a) => (Some(a), None),
        None => (None, actor::session(&actor::env).map(|s| s.label)),
    }
}

fn missing_token(url: &str) -> Error {
    Error::Unauthorized(format!(
        "no access token for {url}: run `bd remote login`, or set BD_TOKEN (create one on the server with `bd serve \
         token create`)"
    ))
}

/// The remote workspace configured for this invocation, if any.
pub fn configured(app: &App) -> Result<Option<Configured>> {
    let g = &app.g;
    let (url, source, ca_cert) = match g.remote.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(_) if g.db.is_some() => {
            return Err(Error::invalid("both --remote ($BD_REMOTE) and --db ($BD_DB) are set; use one"));
        }
        Some(url) => (url.to_string(), Source::Flag, None),
        None if g.db.is_some() => return Ok(None),
        None => match remote_file(&app.cwd) {
            Some(path) => {
                let file = read_remote_file(&path)?;
                let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
                let ca = file.ca_cert.map(|c| if c.is_relative() { dir.join(c) } else { c });
                (file.url, Source::File(path), ca)
            }
            None => return Ok(None),
        },
    };
    let url = check_url(&url)?;
    let ca_cert = env("BD_CA_CERT").map(PathBuf::from).or(ca_cert);
    Ok(Some(Configured { url, source, ca_cert }))
}

/// An access token, and where it came from.
enum Token {
    Env(String),
    Saved(credentials::Saved),
}

impl Token {
    fn secret(self) -> String {
        match self {
            Token::Env(t) => t,
            Token::Saved(s) => s.token,
        }
    }
}

/// What a remote's server certificate is checked against, read once per
/// process: the saved-token check and every request use this same snapshot,
/// so a CA file changed meanwhile (a `git checkout`) cannot slip in.
#[derive(Clone)]
pub struct Trust {
    /// The CA file, or `None` for the system's certificate authorities.
    path: Option<PathBuf>,
    certs: Option<Vec<ureq::tls::Certificate<'static>>>,
    /// [`credentials::SYSTEM_CA`], or the SHA-256 of the certificates (DER, so
    /// line endings do not matter): what a saved token is bound to.
    anchor: String,
}

impl Trust {
    pub fn load(ca_cert: Option<&Path>) -> Result<Trust> {
        let Some(path) = ca_cert else {
            return Ok(Trust { path: None, certs: None, anchor: credentials::SYSTEM_CA.to_string() });
        };
        let certs = read_ca(path)?;
        let mut hash = Sha256::new();
        for cert in &certs {
            hash.update(cert.der());
        }
        let anchor = format!("sha256:{}", hash.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
        Ok(Trust { path: Some(path.to_path_buf()), certs: Some(certs), anchor })
    }
}

/// The access token for a workspace URL reached under `trust`: `$BD_TOKEN`,
/// else one saved by `bd remote login`.
fn token_for(url: &str, trust: &Trust) -> Result<Option<Token>> {
    if let Some(t) = env("BD_TOKEN") {
        return Ok(Some(Token::Env(t)));
    }
    let Some(saved) = credentials::lookup(url)? else { return Ok(None) };
    // A CA named by a checkout's remote.toml must be the one the token was
    // saved under, or a cloned repository could send it to a man in the
    // middle. $BD_CA_CERT is the user's own setting.
    if env("BD_CA_CERT").is_none() && trust.anchor != saved.ca {
        let ca_cert = trust.path.as_deref();
        let then = match (saved.ca.as_str(), ca_cert) {
            (credentials::SYSTEM_CA, _) => "the system's certificate authorities",
            (_, Some(_)) => "another CA certificate",
            (_, None) => "a CA certificate",
        };
        let now = ca_cert.map_or_else(
            || "the system's certificate authorities".to_string(),
            |p| format!("the CA certificate {}", p.display()),
        );
        return Err(Error::Unauthorized(format!(
            "the access token saved for {} is not sent to {url}: it was saved trusting {then}, and {url} is now \
             set up to trust {now}. If you trust that, log in again here (`bd remote login`); or set BD_TOKEN",
            saved.key
        )));
    }
    Ok(Some(Token::Saved(saved)))
}

/// The certificates of a PEM CA file.
fn read_ca(path: &Path) -> Result<Vec<ureq::tls::Certificate<'static>>> {
    let pem = std::fs::read(path).map_err(|e| Error::invalid(format!("CA certificate {}: {e}", path.display())))?;
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(Error::invalid(format!("CA certificate {}: no certificate in the file", path.display())));
    }
    Ok(certs)
}

/// The remote workspace this invocation uses, or `None` for a local one.
pub fn detect(app: &App) -> Result<Option<Remote>> {
    let Some(c) = configured(app)? else { return Ok(None) };
    let trust = Trust::load(c.ca_cert.as_deref())?;
    let token = token_for(&c.url, &trust)?.ok_or_else(|| missing_token(&c.url))?;
    Ok(Some(Remote::new(c, trust, token.secret())))
}

/// The nearest `.bd/remote.toml`, unless a nearer `.bd/bd.db` comes first.
fn remote_file(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let bd = dir.join(".bd");
        let path = bd.join("remote.toml");
        if path.is_file() {
            return Some(path);
        }
        if bd.join("bd.db").is_file() {
            return None;
        }
    }
    None
}

fn read_remote_file(path: &Path) -> Result<RemoteFile> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
}

/// `http(s)://host[:port][/prefix]/w/<workspace>`, without a trailing slash.
fn check_url(raw: &str) -> Result<String> {
    let url = raw.trim().trim_end_matches('/');
    let bad =
        |why: &str| Error::invalid(format!("remote URL {raw:?} {why}; expected https://host[:port]/w/<workspace>"));
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad("has no scheme"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, String::new()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad("needs a host and no embedded credentials"));
    }
    if url.contains(['?', '#']) {
        return Err(bad("must not have a query or fragment"));
    }
    if !path.rsplit_once("/w/").is_some_and(|(_, name)| valid_workspace_name(name)) {
        return Err(bad("does not end in /w/<workspace>"));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(url.to_string()),
        "http" if is_loopback(authority) || env("BD_INSECURE_HTTP").as_deref() == Some("1") => Ok(url.to_string()),
        "http" => Err(Error::invalid(format!(
            "refusing plain HTTP to {authority}: the access token would cross the network unencrypted. Use https, \
             or set BD_INSECURE_HTTP=1 on an encrypted private network"
        ))),
        _ => Err(bad("must use https or http")),
    }
}

fn is_loopback(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `bd prime` in text mode: session hooks run it, so it gives up quickly and
/// reports an unavailable workspace as context instead of failing the hook.
pub fn is_hook(cli: &Cli) -> bool {
    matches!(cli.command, Command::Prime(_)) && !cli.global.json
}

/// What `bd prime` prints in place of workspace context when the remote
/// workspace cannot be used. Exits 0, so the session hook still succeeds.
pub fn unavailable(e: &Error) -> i32 {
    io::outln("# bd workflow context");
    io::outln(format!("The remote bd workspace is unavailable: {e}"));
    io::outln(
        "bd commands fail until this is fixed; `bd remote show` checks the connection and the access token (BD_TOKEN \
         or `bd remote login`).",
    );
    0
}

/// Run the command on the server; returns the process exit code.
pub fn run(app: &mut App, remote: Remote, cli: &Cli) -> i32 {
    let hook = is_hook(cli);
    let remote = if hook { remote.quick() } else { remote };
    match forward(app, &remote, cli, hook) {
        Ok(response) if hook && response.exit_code != 0 => unavailable(&response_error(&response, &remote.url)),
        Ok(response) => {
            io::out(&response.stdout);
            let _ = std::io::stderr().write_all(response.stderr.as_bytes());
            response.exit_code
        }
        Err(e) if hook => unavailable(&e),
        Err(e) => crate::report(&e, app.g.json),
    }
}

/// Run the command remotely. Output files are written as they arrive, and
/// stdout printed if it is long; the result holds the rest, to print.
fn forward(app: &App, remote: &Remote, cli: &Cli, hook: bool) -> Result<ExecResponse> {
    match &cli.command {
        Command::Init(_) => {
            return Err(Error::Refused(format!(
                "this workspace is remote ({}); bd init creates a local one, so run it elsewhere or remove the remote \
                 configuration (`bd remote unset`)",
                remote.url
            )));
        }
        Command::Events(a) if a.follow => {
            let code = follow_events(app, remote, a)?;
            return Ok(ExecResponse { exit_code: code, ..Default::default() });
        }
        Command::Events(a @ EventsArgs { action: None, since: Some(since), wait: Some(wait), .. }) => {
            let code = wait_for_events(app, remote, a, *since, *wait)?;
            return Ok(ExecResponse { exit_code: code, ..Default::default() });
        }
        Command::Playbook(cmd) => {
            if let Some(code) = playbooks::client_command(app, remote, cmd)? {
                return Ok(ExecResponse { exit_code: code, ..Default::default() });
            }
        }
        _ => {}
    }
    let mut argv = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().map_err(|a| Error::invalid(format!("argument {a:?} is not valid UTF-8"))))
        .collect::<Result<Vec<_>>>()?;
    if app.g.session.is_some() {
        argv = without_session_flag(argv);
    }
    let (actor, session) = identity();
    let mut request = ExecRequest {
        argv,
        actor,
        session,
        request_id: Some(random_hex(16)?),
        location: Some(remote.url.clone()),
        ..Default::default()
    };
    attach_inputs(&cli.command, &mut request)?;
    playbooks::attach_bundle(app, &cli.command, &mut request)?;
    check_outputs(app, &cli.command)?;
    // A session hook prints `bd prime` only once it knows the command worked.
    let write = crate::serve::access(&cli.command) == crate::serve::Access::Write;
    remote.exec_into(&request, &mut Delivery::new(output_files(app, &cli.command), hook, write))
}

/// The error a failed command reported (its `--json` error, or its first stderr line).
fn response_error(r: &ExecResponse, url: &str) -> Error {
    let detail = r.stderr.lines().find_map(|l| serde_json::from_str::<ErrorBody>(l).ok()).map(|b| b.error);
    let message = match &detail {
        Some(d) => d.message.clone(),
        None => r.stderr.lines().next().unwrap_or("failed").trim_start_matches("error: ").to_string(),
    };
    match detail.map_or(r.exit_code, |d| d.exit_code) {
        7 => Error::Unauthorized(format!("{url}: {message}")),
        9 => Error::AnswerLost(format!("{url}: {message}")),
        2 => Error::invalid(format!("{url}: {message}")),
        3 => Error::NoWorkspace(format!("{url}: {message}")),
        _ => Error::Remote(format!("{url}: {message}")),
    }
}

/// Send the stdin and input files the command reads; the server never reads its own files for a client.
fn attach_inputs(cmd: &Command, request: &mut ExecRequest) -> Result<()> {
    fn attach(request: &mut ExecRequest, path: &str) -> Result<()> {
        if path == "-" {
            request.stdin = Some(io::read_stdin()?);
        } else {
            request.files.insert(path.to_string(), io::read_file(Path::new(path))?);
        }
        Ok(())
    }
    match cmd {
        Command::Import(a) => attach(request, &a.file),
        Command::Batch(a) => match &a.file {
            Some(f) => {
                request.files.insert(f.to_string_lossy().into_owned(), io::read_file(f)?);
                Ok(())
            }
            None => attach(request, "-"),
        },
        Command::Comment(CommentCommand::Add(a)) if a.stdin => attach(request, "-"),
        Command::Comment(CommentCommand::Add(a)) => match &a.file {
            Some(f) => attach(request, &f.to_string_lossy()),
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

fn extract_target(app: &App, path: &Path) -> PathBuf {
    if path.is_relative() { app.cwd.join(path) } else { path.to_path_buf() }
}

fn check_outputs(app: &App, cmd: &Command) -> Result<()> {
    if let Command::Playbook(PlaybookCommand::Extract(ExtractArgs { output: Some(p), force: false, .. })) = cmd {
        let target = extract_target(app, p);
        if target.exists() {
            return Err(Error::Refused(format!("{} exists; pass --force to overwrite", target.display())));
        }
    }
    Ok(())
}

/// The output files the command asked for, written where the local CLI would.
fn output_files(app: &App, cmd: &Command) -> Vec<OutputFile> {
    match cmd {
        Command::Export(ExportArgs { output: Some(path), .. }) => vec![OutputFile::new(path, path.clone(), false)],
        Command::Playbook(PlaybookCommand::Extract(ExtractArgs { output: Some(path), .. })) => {
            vec![OutputFile::new(path, extract_target(app, path), true)]
        }
        _ => Vec::new(),
    }
}

/// Where the frames of an answer go: stdout, and the output files the
/// command asked for. Files the server sends for any other path are ignored.
struct Delivery {
    /// A command that may write: its output is held until it is complete,
    /// so a lost answer can always be asked for again (same request id).
    write: bool,
    /// Keep stdout until the exit frame instead of printing it as it arrives.
    hold: bool,
    /// This attempt prints stdout as it arrives.
    printing: bool,
    /// Stdout of this attempt, when not printing it.
    held: String,
    /// Output reached the user, so the request cannot be tried again.
    printed: bool,
    files: Vec<OutputFile>,
    /// The cursor frame of this attempt.
    cursor: Option<i64>,
    /// The server may hold the request a long time before answering (a long
    /// poll): its retry time starts at its first failure.
    long_poll: bool,
}

/// An output file, written to `<target>.tmp` and renamed into place once the command succeeds.
struct OutputFile {
    /// The path as given on the command line, which names the file's frames.
    key: String,
    target: PathBuf,
    /// Create the target's directory first (`playbook extract -o`).
    mkdir: bool,
    /// This attempt's temporary file.
    temp: Option<(PathBuf, std::io::BufWriter<std::fs::File>)>,
}

impl Delivery {
    fn new(files: Vec<OutputFile>, hold: bool, write: bool) -> Delivery {
        // A command writing files prints a summary: it waits until the files are in place.
        let hold = hold || write || !files.is_empty();
        Delivery {
            write,
            hold,
            printing: false,
            held: String::new(),
            printed: false,
            files,
            cursor: None,
            long_poll: false,
        }
    }

    /// Everything kept in memory, for the client's own requests (reads).
    fn collect() -> Delivery {
        Delivery::new(Vec::new(), true, false)
    }

    /// An attempt's answer starts; a `whole` one is short, so it is printed when complete.
    fn start(&mut self, whole: bool) {
        self.discard();
        self.held.clear();
        self.cursor = None;
        self.printing = !self.hold && !whole;
    }

    fn stdout(&mut self, text: &str) -> Result<()> {
        if !self.printing {
            self.held.push_str(text);
            return Ok(());
        }
        self.printed = true;
        Ok(io::with_stdout(|w| w.write_all(text.as_bytes()))?)
    }

    fn file(&mut self, path: &str, data: &str) -> Result<()> {
        match self.files.iter_mut().find(|f| f.key == path) {
            Some(f) => f.write(data.as_bytes()),
            None => Ok(()),
        }
    }

    /// The command finished: its files go into place if it succeeded.
    fn exit(&mut self, exit: Exit) -> Result<ExecResponse> {
        if exit.exit_code == 0 {
            for f in &mut self.files {
                f.commit()?;
            }
        }
        self.discard();
        Ok(ExecResponse {
            exit_code: exit.exit_code,
            stdout: std::mem::take(&mut self.held),
            stderr: exit.stderr,
            replayed: exit.replayed,
            cursor: self.cursor.take(),
            ..Default::default()
        })
    }

    fn discard(&mut self) {
        for f in &mut self.files {
            f.discard();
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        self.discard();
    }
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

impl OutputFile {
    fn new(key: &Path, target: PathBuf, mkdir: bool) -> OutputFile {
        OutputFile { key: key.to_string_lossy().into_owned(), target, mkdir, temp: None }
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.temp.is_none() {
            if let Some(dir) = self.target.parent().filter(|_| self.mkdir) {
                std::fs::create_dir_all(dir).map_err(|e| path_error(dir, e))?;
            }
            let mut name = self.target.file_name().unwrap_or_default().to_os_string();
            name.push(".tmp");
            let temp = self.target.with_file_name(name);
            let file = std::fs::File::create(&temp).map_err(|e| path_error(&temp, e))?;
            self.temp = Some((temp, std::io::BufWriter::new(file)));
        }
        let Some((temp, w)) = self.temp.as_mut() else { return Ok(()) };
        w.write_all(data).map_err(|e| path_error(temp, e))
    }

    fn commit(&mut self) -> Result<()> {
        let Some((temp, w)) = self.temp.take() else { return Ok(()) };
        // Closed before the rename, which Windows refuses for an open file.
        let moved = w.into_inner().map_err(|e| e.into_error()).and_then(|file| {
            drop(file);
            crate::io::replace_file(&temp, &self.target)
        });
        moved.map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            path_error(&self.target, e)
        })
    }

    fn discard(&mut self) {
        if let Some((temp, w)) = self.temp.take() {
            drop(w);
            let _ = std::fs::remove_file(temp);
        }
    }
}

/// How long a remote follower asks the server to wait for a new event; the
/// server's `--max-wait` (25 s by default) caps it. The client waits up to
/// two minutes for an answer to start.
const FOLLOW_WAIT: Duration = Duration::from_secs(90);
/// Events per answer while following, as the local `events --follow` reads them.
const FOLLOW_BATCH: usize = 1000;

/// `events` on the server from `since`, at most `limit` events, waiting up
/// to `wait` for the first; with the command's filters and output format.
fn events_request(
    app: &App,
    remote: &Remote,
    a: &EventsArgs,
    since: Option<i64>,
    limit: Option<usize>,
    wait: Option<Duration>,
) -> ExecRequest {
    let mut argv: Vec<String> = Vec::new();
    if app.g.json {
        argv.push("--json".into());
    }
    if let Some(actor) = &app.g.actor {
        argv.extend(["--actor".into(), actor.clone()]);
    }
    argv.push("events".into());
    if let Some(c) = since {
        argv.extend(["--since".into(), c.to_string()]);
    }
    if let Some(n) = limit {
        argv.extend(["--limit".into(), n.to_string()]);
    }
    if let Some(w) = wait {
        argv.extend(["--wait".into(), format!("{}ms", w.as_millis())]);
    }
    if let Some(issue) = &a.issue {
        argv.extend(["--issue".into(), issue.clone()]);
    }
    for op in &a.ops {
        argv.extend(["--op".into(), op.clone()]);
    }
    if let Some(by) = &a.by_actor {
        argv.extend(["--by".into(), by.clone()]);
    }
    let (actor, session) = identity();
    ExecRequest { argv, actor, session, location: Some(remote.url.clone()), ..Default::default() }
}

/// Print the events of an answer; returns where they end (the cursor to
/// continue from), or the exit code of a failure, whose error is printed.
fn print_events(remote: &Remote, r: ExecResponse) -> Result<std::result::Result<i64, i32>> {
    if r.exit_code != 0 {
        let _ = std::io::stderr().write_all(r.stderr.as_bytes());
        return Ok(Err(r.exit_code));
    }
    let cursor = r.cursor.ok_or_else(|| Error::Remote(format!("{}: the server sent no event cursor", remote.url)))?;
    io::out(&r.stdout);
    Ok(Ok(cursor))
}

/// `events --follow`: long polls. Each request waits on the server until an
/// event matching the filters follows the cursor (or the server's wait
/// ends), and its answer says where to continue, so every event is printed
/// once, in order, however requests fail and are retried. Under load,
/// events arrive in batches: a request starts at most once per interval.
fn follow_events(app: &App, remote: &Remote, a: &EventsArgs) -> Result<i32> {
    let interval = Duration::from_millis(a.interval_ms.max(200));
    let mut cursor = match a.since {
        Some(since) => since,
        // First the most recent events, as the local command prints them.
        None => match print_events(remote, remote.exec(&events_request(app, remote, a, None, a.limit, None))?)? {
            Ok(cursor) => cursor,
            Err(code) => return Ok(code),
        },
    };
    let mut first = a.since.is_some();
    loop {
        let started = Instant::now();
        let limit = match a.limit {
            Some(n) if first => n.min(FOLLOW_BATCH),
            _ => FOLLOW_BATCH,
        };
        let response =
            remote.long_poll(&events_request(app, remote, a, Some(cursor), Some(limit), Some(FOLLOW_WAIT)))?;
        if response.exit_code == 6 && !first {
            // Retention pruned past the cursor (the follower fell far behind): resume at the head.
            let head = remote.event_head()?;
            io::errln(format!(
                "warning: events after #{cursor} were pruned before they were read; following from #{head}"
            ));
            cursor = head;
            continue;
        }
        cursor = match print_events(remote, response)? {
            Ok(next) => next,
            Err(code) => return Ok(code),
        };
        first = false;
        if let Some(rest) = interval.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

/// `events --since N --wait D`: long polls of at most [`FOLLOW_WAIT`] until
/// an event matching the filters follows `N`, or `D` has passed.
fn wait_for_events(app: &App, remote: &Remote, a: &EventsArgs, since: i64, wait: Duration) -> Result<i32> {
    let interval = Duration::from_millis(a.interval_ms.max(200));
    let started = Instant::now();
    let mut cursor = since;
    loop {
        let round = Instant::now();
        let left = wait.saturating_sub(started.elapsed());
        let request = events_request(app, remote, a, Some(cursor), a.limit, Some(left.min(FOLLOW_WAIT)));
        let response = remote.long_poll(&request)?;
        let found = !response.stdout.is_empty();
        cursor = match print_events(remote, response)? {
            Ok(next) => next,
            Err(code) => return Ok(code),
        };
        let left = wait.saturating_sub(started.elapsed());
        if found || left.is_zero() {
            return Ok(0);
        }
        // An answer before its wait ended (the server's followers are full): ask again after the interval.
        std::thread::sleep(interval.saturating_sub(round.elapsed()).min(left));
    }
}

impl Remote {
    /// The CA certificates come from `trust`, never from `c.ca_cert` again.
    pub fn new(c: Configured, trust: Trust, token: String) -> Remote {
        Remote {
            url: c.url,
            token,
            roots: trust.certs,
            retry: retry_budget(),
            connect_timeout: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(120),
            total_timeout: None,
        }
    }

    /// Settings for commands that must answer within seconds (`bd prime` in
    /// hooks, `bd remote show`). `$BD_REMOTE_RETRY_SECS` still wins.
    pub fn quick(mut self) -> Remote {
        if env("BD_REMOTE_RETRY_SECS").is_none() {
            self.retry = PRIME_RETRY_BUDGET;
        }
        self.connect_timeout = Duration::from_secs(3);
        self.attempt_timeout = Duration::from_secs(15);
        self.total_timeout = Some(self.attempt_timeout);
        self
    }

    fn agent(&self) -> Result<ureq::Agent> {
        let mut tls = ureq::tls::TlsConfig::builder();
        if let Some(certs) = &self.roots {
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(certs));
        }
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(self.connect_timeout))
            .timeout_send_request(Some(self.attempt_timeout))
            .timeout_send_body(Some(self.attempt_timeout))
            .timeout_recv_response(Some(self.attempt_timeout))
            .timeout_global(self.total_timeout)
            .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(tls.build())
            .build();
        Ok(config.into())
    }

    /// Send one request and collect its whole answer (the client's own small requests).
    pub fn exec(&self, request: &ExecRequest) -> Result<ExecResponse> {
        self.exec_into(request, &mut Delivery::collect())
    }

    /// Like [`Remote::exec`], for a request the server may hold until it has
    /// something to say: it is retried for as long after its first failure,
    /// not after it was sent.
    fn long_poll(&self, request: &ExecRequest) -> Result<ExecResponse> {
        let mut out = Delivery::collect();
        out.long_poll = true;
        self.exec_into(request, &mut out)
    }

    /// Send one request; its answer goes to `out`. Failures in transit and
    /// busy answers are retried with the same request id, for up to the
    /// remote's retry budget, as long as no output has reached the user. A
    /// write that may have run without its answer arriving fails with
    /// [`Error::AnswerLost`], never as safe to run again.
    fn exec_into(&self, request: &ExecRequest, out: &mut Delivery) -> Result<ExecResponse> {
        let agent = self.agent()?;
        let body = serde_json::to_vec(request)?;
        let endpoint = format!("{}/v{PROTOCOL}/exec", self.url);
        let authorization = format!("Bearer {}", self.token);
        let budget = self.retry;
        let mut deadline = (!out.long_poll).then(|| Instant::now() + budget);
        let mut delay = Duration::from_millis(200);
        let mut fresh_windows = 0;
        // Some attempt may have run the command on the server.
        let mut reached = false;
        let lost = |why: String| {
            Error::AnswerLost(format!("{}: {why}; the command may have taken effect on the server", self.url))
        };
        loop {
            let was_reached = reached;
            let attempt = Instant::now();
            // bd serve itself answered that it cannot run the command now (busy, or shutting down).
            let mut refused = false;
            let sent = agent
                .post(&endpoint)
                .header("authorization", &authorization)
                .header("accept", FRAMES_CONTENT_TYPE)
                .content_type("application/json")
                .send(&body[..]);
            let failure = match sent {
                Ok(response) if response.status() == 200 => match self.receive(response, out)? {
                    Ok(done) => return Ok(done),
                    // The command ran, but its answer cannot be read: asking again would not help.
                    Err(Cut::Malformed(why)) if out.write => return Err(lost(format!("unexpected answer: {why}"))),
                    Err(Cut::Malformed(why)) => {
                        return Err(Error::Remote(format!("{}: unexpected answer: {why}", self.url)));
                    }
                    // Only a read prints as it arrives: running it again is harmless.
                    Err(cut) if out.printed => {
                        return Err(Error::Remote(format!("{}: {cut}, so the output above is incomplete", self.url)));
                    }
                    Err(cut) => {
                        reached = true;
                        cut.to_string()
                    }
                },
                Ok(mut response) => {
                    let status = response.status().as_u16();
                    let bd = response.headers().contains_key(PROTOCOL_HEADER);
                    // bd serve answers 503 before running a command (busy, shutting down). Any other
                    // server error may come after the command ran: from bd serve, or from a proxy in
                    // front of it (a gateway timeout, Cloudflare's 520 and 524, Envoy's 503).
                    let may_have_run = status >= 500 && !(bd && status == 503);
                    match (status, response.body_mut().with_config().limit(1 << 20).read_to_string()) {
                        // 409 "pending": an earlier attempt of this request is still running.
                        (409, Ok(text)) if error_code(&text).as_deref() == Some("pending") => {
                            reached = true;
                            format!("HTTP {status}{}", error_message(&text))
                        }
                        // The command failed on the server, possibly after taking effect.
                        (500, Ok(text)) if bd && out.write => {
                            return Err(lost(format!("HTTP 500{}", error_message(&text))));
                        }
                        (429 | 503, Ok(text)) if !may_have_run => {
                            refused = bd && status == 503;
                            format!("HTTP {status}{}", error_message(&text))
                        }
                        (_, Ok(text)) if may_have_run && !bd => {
                            reached = true;
                            format!("HTTP {status}{}", error_message(&text))
                        }
                        (_, Ok(text)) if reached && out.write => {
                            let why = format!("HTTP {status}{}", error_message(&text));
                            return Err(lost(format!("{why}, after an earlier attempt that may have run")));
                        }
                        (_, Ok(text)) => return Err(http_error(status, &text, &self.url, bd)),
                        (_, Err(e)) => {
                            reached |= may_have_run || status == 409;
                            format!("HTTP {status}, reading the response: {e}")
                        }
                    }
                }
                Err(e) if retryable(&e) => {
                    reached |= !before_sending(&e);
                    e.to_string()
                }
                Err(e) => {
                    reached |= !before_sending(&e);
                    let e = format!("{e}{}", certificate_advice(&e.to_string()));
                    if reached && out.write {
                        return Err(lost(e));
                    }
                    return Err(Error::Remote(format!("{}: {e}", self.url)));
                }
            };
            // The first failure that may have run a write restarts the retry time: a gateway timeout
            // arrives only once the proxy's own has passed (Cloudflare's 524 after 100 s), maybe past
            // the retry time, and the write's stored answer must still be asked for.
            let now = Instant::now();
            let mut until = deadline.unwrap_or(now + budget);
            if reached && !was_reached && out.write && !budget.is_zero() {
                until = until.max(now + budget.max(delay));
            }
            // A long poll's retry may wait on the server too: when bd serve held it and then
            // refused it, the server is up, and the time went to waiting, not to reaching it.
            // Refused connections and timeouts never extend the retry time: a server that is
            // gone still ends the request after one.
            if out.long_poll && refused && now - attempt >= HELD && fresh_windows < FRESH_WINDOWS {
                fresh_windows += 1;
                until = until.max(now + budget);
                delay = Duration::from_millis(200);
            }
            deadline = Some(until);
            if now + delay > until {
                let failure = format!("{failure} (gave up after retrying for {}s)", budget.as_secs());
                if reached && out.write {
                    return Err(lost(failure));
                }
                return Err(Error::Remote(format!("{}: {failure}", self.url)));
            }
            tracing::debug!(target: "bd::remote", url = %self.url, %failure, "retrying");
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(4));
        }
    }

    /// Read a 200 answer into `out`: the command's outcome, or where the answer
    /// was cut off. An error is a local failure (writing stdout or an output
    /// file), which ends the request.
    fn receive(
        &self,
        response: ureq::http::Response<ureq::Body>,
        out: &mut Delivery,
    ) -> Result<std::result::Result<ExecResponse, Cut>> {
        let headers = response.headers();
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !content_type.starts_with(FRAMES_CONTENT_TYPE) {
            return Ok(Err(Cut::Malformed(format!("content type {content_type:?}, not a bd answer (check the URL)"))));
        }
        out.start(headers.contains_key("content-length"));
        let frames = FrameReader::spawn(response.into_body().into_reader(), self.attempt_timeout)?;
        loop {
            match frames.next() {
                Ok(Some(Frame::Stdout(text))) => out.stdout(&text)?,
                Ok(Some(Frame::File { path, data })) => out.file(&path, &data)?,
                Ok(Some(Frame::Cursor(seq))) => out.cursor = Some(seq),
                Ok(Some(Frame::Exit(exit))) => return out.exit(exit).map(Ok),
                Ok(None) => return Ok(Err(Cut::Broken("the answer ended before the command did".into()))),
                Err(cut) => return Ok(Err(cut)),
            }
        }
    }

    fn event_head(&self) -> Result<i64> {
        let (actor, session) = identity();
        let request = ExecRequest {
            argv: vec!["info".into(), "--json".into()],
            actor,
            session,
            location: Some(self.url.clone()),
            ..Default::default()
        };
        let response = self.exec(&request)?;
        if response.exit_code != 0 {
            return Err(Error::Remote(format!("{}: bd info failed: {}", self.url, response.stderr.trim())));
        }
        let info: serde_json::Value = serde_json::from_str(&response.stdout)?;
        info["events_head"].as_i64().ok_or_else(|| Error::Remote(format!("{}: bd info has no events_head", self.url)))
    }
}

// ------------------------------------------------------------ bd remote

pub fn cmd_remote(app: &mut App, cmd: &RemoteCommand) -> Result<i32> {
    io::require_local("bd remote")?;
    match cmd {
        RemoteCommand::Set(a) => set(app, a).map(|_| 0),
        RemoteCommand::Show => show(app),
        RemoteCommand::Unset => unset(app).map(|_| 0),
        RemoteCommand::Login(a) => login(app, a).map(|_| 0),
        RemoteCommand::Logout(a) => logout(app, a).map(|_| 0),
    }
}

/// The `.bd` directory `bd remote set` writes to: the nearest one, else `./.bd`.
fn config_dir(start: &Path) -> PathBuf {
    start.ancestors().map(|d| d.join(".bd")).find(|d| d.is_dir()).unwrap_or_else(|| start.join(".bd"))
}

fn set(app: &mut App, a: &RemoteSetArgs) -> Result<()> {
    no_extra_args("set", &a.extra)?;
    let url = check_url(url_arg(&a.url, "https://host[:port]/w/<workspace>")?)?;
    let dir = config_dir(&app.cwd);
    let db = dir.join("bd.db");
    if db.is_file() && !a.force {
        return Err(Error::Refused(format!(
            "{0} is a local workspace, which a remote.toml next to it would hide. Move its issues to the server first \
             (`bd --db {0} export -o issues.jsonl`, then `bd import issues.jsonl` with an admin token), then pass \
             --force",
            db.display()
        )));
    }
    let pem = match &a.ca_cert {
        Some(src) => {
            let src = if src.is_relative() { app.cwd.join(src) } else { src.clone() };
            let pem = std::fs::read(&src).map_err(|e| Error::invalid(format!("--ca-cert {}: {e}", src.display())))?;
            if !ureq::tls::parse_pem(&pem).any(|item| matches!(item, Ok(ureq::tls::PemItem::Certificate(_)))) {
                return Err(Error::invalid(format!("--ca-cert {}: no PEM certificate in the file", src.display())));
            }
            Some(pem)
        }
        None => None,
    };
    std::fs::create_dir_all(&dir)?;
    crate::commands::write_bd_gitignore(&dir)?;
    // The CA certificate is public: it goes next to remote.toml, so the checkout can commit both.
    let ca_cert = match pem {
        Some(pem) => {
            std::fs::write(dir.join("ca.pem"), pem)?;
            Some(PathBuf::from("ca.pem"))
        }
        None => None,
    };
    let path = dir.join("remote.toml");
    let body = toml::to_string(&RemoteFile { url: url.clone(), ca_cert: ca_cert.clone() })
        .map_err(|e| Error::invalid(format!("remote.toml: {e}")))?;
    std::fs::write(
        &path,
        format!(
            "# Commands in this checkout run on a bd server; `bd remote show` checks the connection.\n\
             # The access token comes from $BD_TOKEN or `bd remote login`: never commit it.\n{body}"
        ),
    )?;
    let checkout = dir.parent().unwrap_or(&dir).display().to_string();
    let mut out = Out::new(json!({ "path": path, "url": url, "ca_cert": ca_cert.as_ref().map(|c| dir.join(c)) }))
        .line(format!("✓ Commands under {checkout} now run on {url}"))
        .line(format!("  wrote {}{}", path.display(), if ca_cert.is_some() { " and ca.pem" } else { "" }));
    if app.g.remote.is_some() {
        out = out.line("  note: --remote or $BD_REMOTE is set, and takes precedence over this file");
    }
    let ca_path = ca_cert.as_ref().map(|c| dir.join(c));
    let has_token = Trust::load(ca_path.as_deref()).and_then(|t| token_for(&url, &t)).ok().flatten().is_some();
    out = out.line(if has_token {
        "  check the connection: bd remote show"
    } else {
        "  next: `bd remote login` (or set BD_TOKEN), then check the connection with `bd remote show`"
    });
    app.print(out.id(url));
    Ok(())
}

fn show(app: &mut App) -> Result<i32> {
    let Some(c) = configured(app)? else {
        let local = app.db_path().ok();
        let line = match &local {
            Some(p) => format!("No remote workspace: commands here use the local database {}", p.display()),
            None => "No workspace here: `bd remote set <url>` uses a bd server, `bd init` creates a local one".into(),
        };
        app.print(Out::new(json!({ "remote": null, "local": local })).line(line));
        return Ok(0);
    };
    let token = Trust::load(c.ca_cert.as_deref()).and_then(|trust| Ok((token_for(&c.url, &trust)?, trust)));
    let source = match &c.source {
        Source::Flag => "--remote or $BD_REMOTE".to_string(),
        Source::File(p) => p.display().to_string(),
    };
    let mut view = json!({
        "url": c.url,
        "source": source,
        "ca_cert": c.ca_cert,
        "token_set": matches!(token, Ok((Some(_), _))),
        "token_from": null,
        "credentials": null,
    });
    let mut lines = vec![format!("remote      {}", c.url), format!("from        {source}")];
    if let Some(ca) = &c.ca_cert {
        lines.push(format!("ca cert     {}", ca.display()));
    }
    lines.push(match &token {
        Ok((Some(Token::Env(_)), _)) => {
            view["token_from"] = json!("env");
            "token       $BD_TOKEN".to_string()
        }
        Ok((Some(Token::Saved(s)), _)) => {
            view["token_from"] = json!("credentials");
            view["credentials"] = json!({ "path": s.path, "key": s.key, "scope": s.scope.as_str() });
            format!("token       saved for {} in {}", s.key, s.path.display())
        }
        Ok((None, _)) => "token       none: run `bd remote login`, or set BD_TOKEN".to_string(),
        Err(_) => "token       not usable".to_string(),
    });
    let checked = match token {
        Ok((Some(t), trust)) => check(Remote::new(c.clone(), trust, t.secret()).quick(), identity()),
        Ok((None, _)) => Err(missing_token(&c.url)),
        Err(e) => Err(e),
    };
    let code = match checked {
        Ok(info) => {
            let s = |k: &str| info[k].as_str().map(String::from).unwrap_or_else(|| info[k].to_string());
            lines.push(format!("server      bd {}, schema v{}", s("version"), s("schema_version")));
            lines.push(format!(
                "workspace   prefix {}, {} issues, events head {}",
                s("prefix"),
                s("issues"),
                s("events_head")
            ));
            lines.push(format!("actor       {}", s("actor")));
            lines.push("✓ connected".into());
            view["connected"] = json!(true);
            view["server"] = info;
            0
        }
        Err(e) => {
            lines.push(format!("✗ {e}"));
            view["connected"] = json!(false);
            view["error"] = json!({ "code": e.code(), "message": e.to_string(), "exit_code": e.exit_code() });
            e.exit_code()
        }
    };
    app.print(Out::new(view).lines(lines));
    Ok(code)
}

/// `bd info` on the server: proves that the URL, certificate, token and actor all work.
fn check(remote: Remote, (actor, session): (Option<String>, Option<String>)) -> Result<Value> {
    let request = ExecRequest {
        argv: vec!["info".into(), "--json".into()],
        actor,
        session,
        location: Some(remote.url.clone()),
        ..Default::default()
    };
    let response = remote.exec(&request)?;
    if response.exit_code != 0 {
        return Err(response_error(&response, &remote.url));
    }
    Ok(serde_json::from_str(&response.stdout)?)
}

fn unset(app: &mut App) -> Result<()> {
    let mut out = match remote_file(&app.cwd) {
        Some(path) => {
            std::fs::remove_file(&path)?;
            let mut out = Out::new(json!({ "removed": path })).line(format!("✓ Removed {}", path.display()));
            if let Some(db) = path.parent().map(|d| d.join("bd.db")).filter(|db| db.is_file()) {
                out = out.line(format!("  commands here use the local database {} again", db.display()));
            }
            out
        }
        None => Out::new(json!({ "removed": null })).line("= No .bd/remote.toml applies here"),
    };
    if app.g.remote.is_some() {
        out = out.line("  note: --remote or $BD_REMOTE is still set, and keeps commands remote");
    }
    app.print(out);
    Ok(())
}

fn no_remote_here(command: &str) -> Error {
    Error::invalid(format!(
        "no remote workspace here: pass its URL (`bd remote {command} https://bd.example.com/w/proj`), or run `bd \
         remote set <url>` first"
    ))
}

/// The workspace `bd remote login` checks a token against: `url`, else the configured one.
fn login_target(app: &App, url: Option<&str>) -> Result<Configured> {
    let configured = configured(app);
    let Some(raw) = url else { return configured?.ok_or_else(|| no_remote_here("login")) };
    let url = check_url(url_arg(raw, "https://host[:port]/w/<workspace>")?)?;
    let same = |c: &Configured| credentials::keys(&c.url).ok() == credentials::keys(&url).ok();
    let ca_cert = match configured {
        Ok(Some(c)) if same(&c) => c.ca_cert,
        _ => env("BD_CA_CERT").map(PathBuf::from),
    };
    Ok(Configured { url, source: Source::Flag, ca_cert })
}

/// A URL argument of `bd remote login/logout`. Anything but a plain URL is
/// refused without repeating it: it may be a token pasted in the wrong place.
fn url_arg<'a>(raw: &'a str, expected: &str) -> Result<&'a str> {
    let arg = raw.trim();
    if looks_like_token(arg) {
        return Err(Error::invalid(format!(
            "that argument looks like an access token: never pass one on the command line, where shell history \
             keeps it (consider revoking it); {}",
            how_to_pipe()
        )));
    }
    if !arg.contains("://") || arg.chars().any(char::is_whitespace) {
        return Err(Error::invalid(format!("the URL argument is not a URL; expected {expected}")));
    }
    Ok(arg)
}

/// Refuse arguments after the URL without repeating them: clap would echo
/// a token pasted there.
fn no_extra_args(command: &str, extra: &[String]) -> Result<()> {
    if extra.is_empty() {
        return Ok(());
    }
    Err(Error::invalid(format!(
        "bd remote {command} takes one URL and never a token on the command line, where shell history keeps it (if \
         you passed one, consider revoking it); {}",
        how_to_pipe()
    )))
}

/// `bdt_<hex>`, the secrets `bd serve token create` prints.
fn looks_like_token(arg: &str) -> bool {
    arg.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("bdt_"))
}

fn login(app: &mut App, a: &RemoteLoginArgs) -> Result<()> {
    no_extra_args("login", &a.extra)?;
    let c = login_target(app, a.url.as_deref())?;
    let scope = if a.workspace_only { Scope::Workspace } else { Scope::Server };
    let keys = credentials::keys(&c.url)?;
    let path = credentials::default_path()?;
    let label = match scope {
        Scope::Server => keys.server.clone(),
        Scope::Workspace => c.url.clone(),
    };
    let trust = Trust::load(c.ca_cert.as_deref())?;
    let label = match &trust.path {
        Some(ca) => format!("{label}, trusting the CA certificate {}", ca.display()),
        None => label,
    };
    let token = read_token(&label)?;
    credentials::check_token(&token)?;
    let actor = if a.no_verify {
        None
    } else {
        // The token alone: $BD_ACTOR is checked per command, not saved.
        let info =
            check(Remote::new(c.clone(), trust.clone(), token.clone()).quick(), (None, None)).map_err(|e| match e {
                Error::Unauthorized(m) => Error::Unauthorized(format!("{m}; nothing was saved")),
                Error::Remote(m) => {
                    Error::Remote(format!("{m}; nothing was saved (--no-verify saves the token without checking it)"))
                }
                e => e,
            })?;
        info["actor"].as_str().map(String::from)
    };
    let saved = credentials::save(&path, &c.url, &token, &trust.anchor, scope)?;
    let reach = match scope {
        Scope::Server => format!("{} (every workspace it allows there)", saved.key),
        Scope::Workspace => saved.key.clone(),
    };
    let mut out = Out::new(json!({
        "url": c.url,
        "path": path,
        "key": saved.key,
        "scope": scope.as_str(),
        "verified": !a.no_verify,
        "actor": actor,
        "replaced": saved.replaced,
        "dropped": saved.dropped,
        "ca_cert": c.ca_cert,
    }))
    .line(format!("✓ Saved the access token for {reach} in {}", path.display()))
    .line(match &actor {
        Some(actor) => format!("  {} accepts it, as actor {actor}", c.url),
        None => "  not checked (--no-verify): `bd remote show` checks it".to_string(),
    });
    if let Some(ca) = &c.ca_cert {
        out = out.line(format!("  bound to the CA certificate {}: it is not sent trusting any other", ca.display()));
    }
    if saved.replaced {
        out = out.line("  it replaces the token saved there before");
    }
    if let Some(k) = &saved.dropped {
        out = out.line(format!("  removed the token saved for {k} only, which would have taken precedence"));
    }
    if let Some(mode) = saved.loose_mode {
        out = out.line(format!(
            "  note: other users could read this file (mode {mode:03o}); it is private now, but consider revoking the \
             tokens it held"
        ));
    }
    if env("BD_TOKEN").is_some() {
        out = out.line("  note: $BD_TOKEN is set, and takes precedence over saved tokens");
    }
    app.print(out.id(saved.key));
    Ok(())
}

fn logout(app: &mut App, a: &RemoteLogoutArgs) -> Result<()> {
    no_extra_args("logout", &a.extra)?;
    let url = match &a.url {
        Some(url) => url_arg(url, "https://host[:port][/prefix][/w/<workspace>]")?.to_string(),
        None => configured(app)?.ok_or_else(|| no_remote_here("logout"))?.url,
    };
    let path = credentials::default_path()?;
    let r = credentials::remove(&path, &url, a.workspace_only)?;
    let mut out = Out::new(json!({ "path": path, "removed": r.removed, "file_removed": r.file_removed }));
    if r.removed.is_empty() {
        out = out.line(format!("= No access token saved for {}", url.trim()));
    }
    for k in &r.removed {
        out = out.line(format!("✓ Removed the access token saved for {k}"));
        out = out.id(k.clone());
    }
    if r.file_removed {
        out = out.line(format!("  removed {}, which is empty now", path.display()));
    }
    if !r.removed.is_empty() {
        out = out.line("  the server still accepts the token until it is revoked there (`bd serve token revoke`)");
    }
    if env("BD_TOKEN").is_some() {
        out = out.line("  note: $BD_TOKEN is still set, and keeps providing a token");
    }
    app.print(out);
    Ok(())
}

/// The token to save: piped on stdin, or typed at a prompt that does not echo it.
fn read_token(label: &str) -> Result<String> {
    use std::io::IsTerminal;
    let text = if std::io::stdin().is_terminal() {
        prompt_hidden(&format!("Access token for {label} (input hidden): "))?
    } else {
        io::read_stdin()?
    };
    let token = text.trim();
    if token.is_empty() {
        return Err(Error::invalid(format!("no access token given; {}", how_to_pipe())));
    }
    Ok(token.to_string())
}

fn how_to_pipe() -> &'static str {
    if cfg!(windows) {
        "pipe it in, e.g. `Read-Host -MaskInput Token | bd remote login` in PowerShell 7"
    } else {
        "pipe it in, e.g. `printf %s \"$TOKEN\" | bd remote login`, or run it in a terminal to be prompted"
    }
}

/// Read a line from the terminal on stdin with echo turned off by `stty`.
/// Only for the machine-local `bd remote login`, so it uses the process's
/// stdio directly.
#[cfg(unix)]
fn prompt_hidden(prompt: &str) -> Result<String> {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let stty = |arg: &str| {
        Command::new("stty")
            .arg(arg)
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = Command::new("stty").arg(&self.0).stdin(Stdio::inherit()).stderr(Stdio::null()).status();
        }
    }
    let saved = stty("-g").map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty());
    let Some(restore) = saved.map(Restore) else {
        return Err(Error::invalid(format!("cannot turn off echo on this terminal; {}", how_to_pipe())));
    };
    if stty("-echo").is_none() {
        return Err(Error::invalid(format!("cannot turn off echo on this terminal; {}", how_to_pipe())));
    }
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    drop(restore);
    let _ = writeln!(stderr);
    read?;
    Ok(line)
}

#[cfg(not(unix))]
fn prompt_hidden(_: &str) -> Result<String> {
    Err(Error::invalid(format!("bd remote login does not prompt on this system; {}", how_to_pipe())))
}

/// Failures before the request was sent in full: the server cannot have run
/// it. Anything else (a reset, a malformed or oversized answer head) may come
/// after it ran.
fn before_sending(e: &ureq::Error) -> bool {
    use std::io::ErrorKind as K;
    use ureq::Error as E;
    use ureq::Timeout as T;
    match e {
        E::ConnectionFailed
        | E::HostNotFound
        | E::BadUri(_)
        | E::Http(_)
        | E::InvalidProxyUrl
        | E::ConnectProxyFailed(_)
        | E::RequireHttpsOnly(_)
        | E::TlsRequired
        | E::Tls(_)
        | E::Pem(_)
        | E::Rustls(_)
        | E::RedirectFailed
        | E::TooManyRedirects => true,
        E::Timeout(t) => matches!(t, T::Resolve | T::Connect | T::SendRequest | T::SendBody),
        // rustls reports certificate and handshake failures as InvalidData.
        E::Io(io) => matches!(
            io.kind(),
            K::ConnectionRefused | K::AddrNotAvailable | K::HostUnreachable | K::NetworkUnreachable | K::InvalidData
        ),
        _ => false,
    }
}

/// Failures worth retrying: the request may not have arrived, or its answer was lost.
fn retryable(e: &ureq::Error) -> bool {
    match e {
        // rustls reports certificate and handshake failures as InvalidData; retrying cannot fix those.
        ureq::Error::Io(io) => io.kind() != std::io::ErrorKind::InvalidData,
        ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed | ureq::Error::BodyStalled => true,
        _ => false,
    }
}

/// What to do about a rejected server certificate (rustls describes it only in text).
fn certificate_advice(error: &str) -> &'static str {
    if error.contains("CaUsedAsEndEntity") {
        " (the server's certificate is a CA certificate: issue it with basicConstraints CA:FALSE, or sign it with a \
         separate CA)"
    } else if error.contains("invalid peer certificate") {
        " (to trust a private CA or a self-signed certificate, set BD_CA_CERT or ca_cert in .bd/remote.toml)"
    } else {
        ""
    }
}

fn error_message(body: &str) -> String {
    serde_json::from_str::<ErrorBody>(body).map(|b| format!(": {}", b.error.message)).unwrap_or_default()
}

fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ErrorBody>(body).ok().map(|b| b.error.code)
}

/// The error of a non-200 answer; `bd` says whether a bd server sent it.
fn http_error(status: u16, body: &str, url: &str, bd: bool) -> Error {
    let detail = serde_json::from_str::<ErrorBody>(body).ok().map(|b| b.error);
    let message = detail.as_ref().map_or_else(|| format!("HTTP {status}"), |d| d.message.clone());
    match (status, detail.as_ref().map(|d| d.code.as_str())) {
        (401 | 403, _) | (_, Some("unauthorized")) => Error::Unauthorized(format!("{url}: {message}")),
        (404, _) if bd => Error::not_found("workspace", url),
        (404, _) => Error::Remote(format!("{url}: not a bd server ({message}); check the URL")),
        (400 | 413, _) => Error::invalid(format!("{url}: {message}")),
        _ => Error::Remote(format!("{url}: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_flag_is_not_forwarded() {
        let v = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert_eq!(
            without_session_flag(v(&["--session", "agent-1", "close", "t-1", "--session=x", "--reason", "r"])),
            v(&["close", "t-1", "--reason", "r"])
        );
        assert_eq!(
            without_session_flag(v(&["comment", "add", "t-1", "--", "--session", "x"])),
            v(&["comment", "add", "t-1", "--", "--session", "x"]),
            "after --, text"
        );
        assert_eq!(without_session_flag(v(&["create", "--session x"])), v(&["create", "--session x"]));
    }

    #[test]
    fn workspace_urls() {
        assert_eq!(check_url("https://bd.example.com/w/proj/").unwrap(), "https://bd.example.com/w/proj");
        assert!(check_url("https://example.com/bd/w/proj").is_ok(), "behind a path prefix");
        assert!(check_url("http://127.0.0.1:7420/w/proj").is_ok(), "loopback may use http");
        assert!(check_url("http://[::1]:7420/w/proj").is_ok());
        assert!(check_url("http://localhost/w/proj").is_ok());
        for bad in [
            "bd.example.com/w/proj",
            "https://bd.example.com",
            "https://bd.example.com/w/",
            "https://bd.example.com/w/a/b",
            "https://user:pw@bd.example.com/w/proj",
            "https://bd.example.com/w/proj?x=1",
            "ftp://bd.example.com/w/proj",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_http_only_to_loopback() {
        if env("BD_INSECURE_HTTP").is_none() {
            let e = check_url("http://bd.example.com/w/proj").unwrap_err();
            assert!(e.to_string().contains("unencrypted"), "{e}");
        }
        assert!(is_loopback("127.0.0.1:1") && is_loopback("[::1]:1") && is_loopback("LOCALHOST"));
        assert!(!is_loopback("10.0.0.1:7420") && !is_loopback("bd.example.com"));
    }

    #[test]
    fn http_errors_keep_their_exit_codes() {
        let body = |code: &str| format!(r#"{{"error":{{"code":"{code}","message":"m","exit_code":7}}}}"#);
        assert_eq!(http_error(401, &body("unauthorized"), "u", true).exit_code(), 7);
        assert_eq!(http_error(403, &body("unauthorized"), "u", true).exit_code(), 7);
        assert_eq!(http_error(404, &body("not_found"), "u", true).exit_code(), 3);
        assert_eq!(http_error(413, &body("invalid"), "u", true).exit_code(), 2);
        assert_eq!(http_error(500, "not json", "u", false).exit_code(), 8);
        let other = http_error(404, &body("not_found"), "u", false);
        assert_eq!(other.exit_code(), 8, "a 404 without the protocol header is not a missing workspace");
        assert!(other.to_string().contains("not a bd server"), "{other}");
    }

    #[test]
    fn certificate_errors_explain_the_fix() {
        let ca = "io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))";
        assert!(certificate_advice(ca).contains("CA:FALSE"));
        assert!(certificate_advice("io: invalid peer certificate: UnknownIssuer").contains("BD_CA_CERT"));
        assert_eq!(certificate_advice("io: Connection refused"), "");
    }
}
