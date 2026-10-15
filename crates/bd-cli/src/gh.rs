//! Running the GitHub CLI, shared by `bd gate` (probes) and `bd github`
//! (issue sync): one binary (`gh`, or `$BD_GH`), one timeout and one
//! cancellation flag. Each `gh` call is killed after [`GH_TIMEOUT`], and
//! [`cancel_gh_calls`] (tripped by `bd serve`'s shutdown) stops running calls
//! and fails later ones at once. Callers never run `gh` inside a write
//! transaction.
//!
//! [`gh_api`] runs `gh api --include`, so a caller sees the status and headers
//! of an answer (pagination links, rate limits) even when `gh` exits 1 on an
//! HTTP error.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::app::App;

pub(crate) fn gh_bin() -> String {
    std::env::var("BD_GH").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "gh".into())
}

/// How long one `gh` call may run before it is killed and reported as an error.
pub(crate) const GH_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) static GH_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Stop running `gh` calls in this process, and fail later ones at once:
/// `bd serve` is shutting down. Gates are reported as errors and left as
/// they are; a `bd github` run stops its GitHub writes.
pub fn cancel_gh_calls() {
    GH_CANCELLED.store(true, Ordering::Relaxed);
}

/// Whether [`cancel_gh_calls`] was called.
pub(crate) fn gh_cancelled() -> bool {
    GH_CANCELLED.load(Ordering::Relaxed)
}

/// Why [`output_within`] gave up on a command.
#[derive(Debug)]
pub(crate) enum Stopped {
    Failed(std::io::Error),
    TimedOut,
    Cancelled,
}

/// Collect a child's output on its own thread, so a full pipe never stalls it.
pub(crate) fn drain(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut pipe) = pipe {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
    }
    rx
}

/// Run `cmd` to completion like [`Command::output`], but kill it once
/// `timeout` passes or `cancel` is set. With `stdin`, the bytes are written
/// to the child's standard input from a thread, which then closes it.
pub(crate) fn output_within(
    mut cmd: Command,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cancel: &AtomicBool,
) -> std::result::Result<Output, Stopped> {
    if cancel.load(Ordering::Relaxed) {
        return Err(Stopped::Cancelled);
    }
    let deadline = Instant::now() + timeout;
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(Stopped::Failed)?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
            // Dropping the pipe closes the child's stdin.
        });
    }
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let mut pause = Duration::from_millis(1);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(Stopped::Failed)? {
            break status;
        }
        let stop = if cancel.load(Ordering::Relaxed) {
            Some(Stopped::Cancelled)
        } else if Instant::now() >= deadline {
            Some(Stopped::TimedOut)
        } else {
            None
        };
        if let Some(why) = stop {
            let _ = child.kill();
            let _ = child.wait();
            return Err(why);
        }
        std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
        pause = (pause * 2).min(Duration::from_millis(50));
    };
    // A grandchild may still hold a pipe open; do not wait past the deadline for it.
    let collect = |rx: mpsc::Receiver<Vec<u8>>| {
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(100)))
            .unwrap_or_default()
    };
    Ok(Output { status, stdout: collect(stdout), stderr: collect(stderr) })
}

fn run_gh(args: &[String], stdin: Option<Vec<u8>>, cwd: &Path) -> std::result::Result<Output, String> {
    let sub = args.first().map(String::as_str).unwrap_or_default();
    let mut cmd = Command::new(gh_bin());
    cmd.args(args).current_dir(cwd);
    output_within(cmd, stdin, GH_TIMEOUT, &GH_CANCELLED).map_err(|e| match e {
        Stopped::Failed(e) => format!("cannot run `{}`: {e} (install the GitHub CLI or set BD_GH)", gh_bin()),
        Stopped::TimedOut => format!("gh {sub}: no answer within {}s", GH_TIMEOUT.as_secs()),
        Stopped::Cancelled => format!("gh {sub}: cancelled, the server is shutting down"),
    })
}

/// Run `gh <args>` in `cwd` and parse its standard output as JSON.
pub(crate) fn gh_json(args: &[String], cwd: &Path) -> std::result::Result<Value, String> {
    let sub = args.first().map(String::as_str).unwrap_or_default();
    let out = run_gh(args, None, cwd)?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("gh {sub}: {}", err.trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("gh returned invalid JSON: {e}"))
}

/// The directory `gh` runs in: the workspace's (the parent of `.bd`), where
/// it finds the repository it defaults to.
pub(crate) fn workdir(app: &App) -> PathBuf {
    app.db_path()
        .ok()
        .and_then(|db| db.parent().and_then(Path::parent).map(Path::to_path_buf))
        .unwrap_or_else(|| app.cwd.clone())
}

/// One HTTP answer read from `gh api --include`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    /// Header names lowercased, in the order received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ApiResponse {
    /// The first value of header `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str())
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as JSON.
    pub fn json(&self) -> std::result::Result<Value, String> {
        serde_json::from_slice(&self.body)
            .map_err(|e| format!("GitHub returned invalid JSON (HTTP {}): {e}", self.status))
    }

    /// GitHub's `message` in an error body, else the start of the body.
    pub fn message(&self) -> String {
        let text = serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(String::from))
            .unwrap_or_else(|| String::from_utf8_lossy(&self.body).trim().chars().take(200).collect());
        text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
    }
}

/// Parse the output of `gh api --include`: a status line (`HTTP/2.0 200 OK`,
/// `HTTP/1.1 404 Not Found`), headers, a blank line, then the body. Lines
/// end with CRLF or LF. None without a status line.
pub(crate) fn parse_include(stdout: &[u8]) -> Option<ApiResponse> {
    let mut rest = stdout;
    let line = |rest: &mut &[u8]| -> Option<String> {
        if rest.is_empty() {
            return None;
        }
        let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        let l = String::from_utf8_lossy(&rest[..end]).trim_end_matches('\r').to_string();
        *rest = &rest[(end + 1).min(rest.len())..];
        Some(l)
    };
    let status_line = line(&mut rest)?;
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = Vec::new();
    while let Some(l) = line(&mut rest) {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Some(ApiResponse { status, headers, body: rest.to_vec() })
}

/// Whether a `Link` header names a next page.
pub(crate) fn next_page(resp: &ApiResponse) -> bool {
    resp.header("link").is_some_and(|l| l.split(',').any(|part| part.contains("rel=\"next\"")))
}

/// How long a rate-limited answer says to wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RateLimit {
    pub wait: Duration,
    /// When the limit resets, in seconds since the epoch.
    pub reset_at: u64,
}

/// For a 403 or 429 carrying a rate-limit signal (`x-ratelimit-remaining: 0`
/// with `x-ratelimit-reset`, or `retry-after`), how long to wait. None for
/// any other answer.
pub(crate) fn rate_limit_wait(resp: &ApiResponse, now_epoch_s: u64) -> Option<RateLimit> {
    if resp.status != 403 && resp.status != 429 {
        return None;
    }
    if let Some(secs) = resp.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(RateLimit { wait: Duration::from_secs(secs), reset_at: now_epoch_s + secs });
    }
    if resp.header("x-ratelimit-remaining").map(str::trim) == Some("0")
        && let Some(reset) = resp.header("x-ratelimit-reset").and_then(|v| v.trim().parse::<u64>().ok())
    {
        return Some(RateLimit { wait: Duration::from_secs(reset.saturating_sub(now_epoch_s)), reset_at: reset });
    }
    None
}

/// Call the GitHub API through `gh api --include`: `method` on `endpoint`
/// (relative, e.g. `repos/o/n/issues`), with `body` as JSON on stdin. The
/// answer is parsed whatever gh's exit status (it exits 1 on HTTP errors);
/// without a status line the call fails with gh's stderr.
pub(crate) fn gh_api(
    method: &str,
    endpoint: &str,
    host: Option<&str>,
    body: Option<&Value>,
    cwd: &Path,
) -> std::result::Result<ApiResponse, String> {
    // One token per flag, so a value can never be read as another flag; the endpoint last.
    let mut args = vec!["api".to_string(), format!("--method={method}"), "--include".to_string()];
    if let Some(h) = host {
        args.push(format!("--hostname={h}"));
    }
    if body.is_some() {
        args.push("--input=-".into());
    }
    args.push(endpoint.to_string());
    let stdin = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
    let out = run_gh(&args, stdin, cwd)?;
    parse_include(&out.stdout).ok_or_else(|| {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        format!("gh api {method} {endpoint}: {}", if err.is_empty() { "no answer" } else { err })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command that runs for about ten seconds.
    fn sleeper() -> Command {
        #[cfg(windows)]
        let c = {
            let mut c = Command::new("ping");
            c.args(["-n", "11", "127.0.0.1"]);
            c
        };
        #[cfg(not(windows))]
        let c = {
            let mut c = Command::new("sleep");
            c.arg("10");
            c
        };
        c
    }

    #[test]
    fn bounded_commands_return_their_output() {
        #[cfg(windows)]
        let (cmd, code, stderr) = {
            let mut c = Command::new("cmd");
            c.args(["/C", "echo out"]);
            (c, 0, "")
        };
        #[cfg(not(windows))]
        let (cmd, code, stderr) = {
            let mut c = Command::new("sh");
            c.args(["-c", "echo out; echo err >&2; exit 3"]);
            (c, 3, "err")
        };
        let out = output_within(cmd, None, Duration::from_secs(30), &AtomicBool::new(false)).unwrap();
        assert_eq!(out.status.code(), Some(code));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), stderr);
        let missing = Command::new("/nonexistent/bd-test-gh");
        assert!(matches!(
            output_within(missing, None, Duration::from_secs(1), &AtomicBool::new(false)),
            Err(Stopped::Failed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stdin_reaches_the_command() {
        let out = output_within(
            Command::new("cat"),
            Some(b"[1,2]".to_vec()),
            Duration::from_secs(30),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(out.stdout, b"[1,2]");
    }

    #[test]
    fn slow_commands_are_killed_at_the_timeout_or_when_cancelled() {
        let started = Instant::now();
        let r = output_within(sleeper(), None, Duration::from_millis(200), &AtomicBool::new(false));
        assert!(matches!(r, Err(Stopped::TimedOut)), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "killed at the timeout: {:?}", started.elapsed());

        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            flag.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let r = output_within(sleeper(), None, Duration::from_secs(60), &cancel);
        assert!(matches!(r, Err(Stopped::Cancelled)), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "killed when cancelled: {:?}", started.elapsed());
        canceller.join().unwrap();
        let r = output_within(sleeper(), None, Duration::from_secs(60), &cancel);
        assert!(matches!(r, Err(Stopped::Cancelled)), "nothing starts once cancelled: {r:?}");
    }

    #[test]
    fn include_output_is_parsed() {
        let r =
            parse_include(b"HTTP/2.0 200 OK\r\nContent-Type: application/json\r\nLink: <x>; rel=\"next\"\r\n\r\n[1]")
                .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.header("LINK"), Some("<x>; rel=\"next\""));
        assert_eq!(r.body, b"[1]");
        let r = parse_include(b"HTTP/1.1 404 Not Found\nX-GitHub-Request-Id: A\n\n").unwrap();
        assert_eq!((r.status, r.header("x-github-request-id"), r.body.is_empty()), (404, Some("A"), true));
        let r = parse_include(b"HTTP/2.0 204 No Content\r\n").unwrap();
        assert_eq!((r.status, r.headers.len(), r.body.len()), (204, 0, 0));
        assert!(parse_include(b"").is_none());
        assert!(parse_include(b"{\"message\":\"x\"}").is_none());
    }

    #[test]
    fn next_pages_are_found_in_link_headers() {
        let with = |v: &str| ApiResponse { status: 200, headers: vec![("link".into(), v.into())], body: vec![] };
        assert!(next_page(&with(
            "<https://api.github.com/x?page=2>; rel=\"next\", <https://api.github.com/x?page=5>; rel=\"last\""
        )));
        assert!(!next_page(&with(
            "<https://api.github.com/x?page=1>; rel=\"prev\", <https://api.github.com/x?page=1>; rel=\"first\""
        )));
        assert!(!next_page(&ApiResponse::default()));
    }

    #[test]
    fn rate_limits_say_how_long_to_wait() {
        let resp = |status: u16, h: &[(&str, &str)]| ApiResponse {
            status,
            headers: h.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: vec![],
        };
        let r = rate_limit_wait(&resp(403, &[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1030")]), 1000);
        assert_eq!(r, Some(RateLimit { wait: Duration::from_secs(30), reset_at: 1030 }));
        let r = rate_limit_wait(&resp(429, &[("retry-after", "5")]), 1000);
        assert_eq!(r, Some(RateLimit { wait: Duration::from_secs(5), reset_at: 1005 }));
        assert_eq!(rate_limit_wait(&resp(403, &[]), 1000), None);
        assert_eq!(rate_limit_wait(&resp(403, &[("x-ratelimit-remaining", "10")]), 1000), None);
        assert_eq!(rate_limit_wait(&resp(200, &[("retry-after", "5")]), 1000), None);
        let r = rate_limit_wait(&resp(429, &[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "900")]), 1000);
        assert_eq!(r.map(|r| r.wait), Some(Duration::ZERO));
    }
}
