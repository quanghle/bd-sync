//! Command I/O: the process's stdio and files, or a captured request.
//!
//! Commands write output and read input only through this module. Locally
//! that is stdout, stderr, stdin and the file system. When `bd serve` runs a
//! command, it installs a [`Capture`] on the request's thread: output is
//! buffered for the response, stdin and input files come from the request,
//! output files go back to the client, and the server's own files are never
//! read or written on a client's behalf.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use bd_core::{Error, Result};

/// The I/O of one command run by `bd serve`.
#[derive(Debug, Default)]
pub struct Capture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The client's stdin, for commands that read it.
    pub stdin: Option<String>,
    /// Input files sent by the client, keyed by the path on its command line.
    pub files_in: BTreeMap<String, String>,
    /// Output files for the client to write, keyed the same way.
    pub files_out: BTreeMap<String, String>,
    /// The request's access token may run admin-only commands.
    pub admin: bool,
    /// The request's access token is a person's: it may open human gates.
    pub human: bool,
    /// The request's access token's actor: claims held by it or its
    /// sub-actors are the caller's own.
    pub token_actor: String,
}

thread_local! {
    static CAPTURE: RefCell<Option<Capture>> = const { RefCell::new(None) };
}

/// Run `f` with `capture` installed on this thread. Returns `f`'s result and
/// the capture, with everything `f` wrote. The capture is removed even if
/// `f` panics.
pub fn capture<T>(capture: Capture, f: impl FnOnce() -> T) -> (T, Capture) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CAPTURE.with(|c| c.borrow_mut().take());
        }
    }
    CAPTURE.with(|c| *c.borrow_mut() = Some(capture));
    let reset = Reset;
    let out = f();
    let captured = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
    drop(reset);
    (out, captured)
}

/// True while a command runs inside `bd serve`.
pub fn serving() -> bool {
    CAPTURE.with(|c| c.borrow().is_some())
}

static SERVER_PROCESS: AtomicBool = AtomicBool::new(false);

/// Mark this process as `bd serve`: what it does on its own, outside any
/// request, is still done for remote clients.
pub fn mark_server_process() {
    SERVER_PROCESS.store(true, Ordering::Relaxed);
}

/// True anywhere in a `bd serve` process: on request threads and its own.
pub fn in_server_process() -> bool {
    SERVER_PROCESS.load(Ordering::Relaxed) || serving()
}

/// What the request's access token may override (see [`bd_core::policy`]);
/// `None` outside `bd serve`, where nothing is limited.
pub fn policy() -> Option<bd_core::Policy> {
    with_capture(|c| bd_core::Policy { actor: c.token_actor.clone(), admin: c.admin, human: c.human })
}

fn with_capture<T>(f: impl FnOnce(&mut Capture) -> T) -> Option<T> {
    CAPTURE.with(|c| c.borrow_mut().as_mut().map(f))
}

/// Write to stdout through `f`; locally this streams to the locked stdout.
/// `f` must not call the other output functions of this module.
pub fn with_stdout<T>(f: impl FnOnce(&mut dyn Write) -> T) -> T {
    match with_capture(|c| std::mem::take(&mut c.stdout)) {
        Some(mut buf) => {
            let out = f(&mut buf);
            with_capture(move |c| {
                buf.extend_from_slice(&c.stdout);
                c.stdout = buf;
            });
            out
        }
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let out = f(&mut lock);
            let _ = lock.flush();
            out
        }
    }
}

/// Print `text` on stdout as is. Write errors (a closed pipe) are ignored.
pub fn out(text: impl AsRef<str>) {
    with_stdout(|w| {
        let _ = w.write_all(text.as_ref().as_bytes());
    });
}

/// Print a line on stdout. Write errors (a closed pipe) are ignored.
pub fn outln(line: impl AsRef<str>) {
    with_stdout(|w| {
        let _ = writeln!(w, "{}", line.as_ref());
    });
}

/// Print a line on stderr.
pub fn errln(line: impl AsRef<str>) {
    let line = line.as_ref();
    if with_capture(|c| {
        let _ = writeln!(c.stderr, "{line}");
    })
    .is_none()
    {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// All of stdin: the client's, when serving.
pub fn read_stdin() -> Result<String> {
    if let Some(sent) = with_capture(|c| c.stdin.take()) {
        return sent.ok_or_else(|| Error::invalid("this command reads stdin, but the client sent none"));
    }
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

/// A text file: one the client sent, when serving.
pub fn read_file(path: &Path) -> Result<String> {
    let key = path.to_string_lossy();
    if let Some(sent) = with_capture(|c| c.files_in.get(key.as_ref()).cloned()) {
        return sent.ok_or_else(|| Error::invalid(format!("{key}: the client did not send this file")));
    }
    std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
}

/// A file path, or `-` for stdin.
pub fn read_input(path: &str) -> Result<String> {
    if path == "-" { read_stdin() } else { read_file(Path::new(path)) }
}

/// Hand an output file named on the command line back to the client.
/// Only valid while serving; locally, commands write the file themselves.
pub fn send_file(path: &Path, contents: Vec<u8>) -> Result<()> {
    let text = String::from_utf8(contents).map_err(|_| Error::invalid("output file is not UTF-8"))?;
    with_capture(|c| c.files_out.insert(path.to_string_lossy().into_owned(), text))
        .map(|_| ())
        .ok_or_else(|| Error::invalid("send_file outside bd serve"))
}

/// Refuse an admin-only operation when the request's token is not an admin.
pub fn require_admin(what: &str) -> Result<()> {
    match with_capture(|c| c.admin) {
        Some(false) => Err(Error::Unauthorized(format!("{what} needs an admin access token"))),
        _ => Ok(()),
    }
}

/// Refuse an operation that only runs on the machine holding the workspace.
pub fn require_local(what: &str) -> Result<()> {
    if serving() { Err(Error::Refused(format!("{what} is not available through bd serve"))) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_buffers_output_and_serves_inputs() {
        let mut files_in = BTreeMap::new();
        files_in.insert("in.jsonl".to_string(), "{}".to_string());
        let c = Capture { stdin: Some("piped".into()), files_in, ..Default::default() };
        let ((stdin, file, missing, again), c) = capture(c, || {
            outln("line 1");
            with_stdout(|w| write!(w, "streamed").unwrap());
            out("\n");
            errln("warn");
            send_file(Path::new("out.jsonl"), b"data".to_vec()).unwrap();
            (
                read_input("-").unwrap(),
                read_input("in.jsonl").unwrap(),
                read_file(Path::new("/etc/hosts")),
                read_stdin(),
            )
        });
        assert_eq!((stdin.as_str(), file.as_str()), ("piped", "{}"));
        assert!(missing.unwrap_err().to_string().contains("did not send"), "server files are never read");
        assert!(again.is_err(), "stdin is consumed once");
        assert_eq!(String::from_utf8(c.stdout).unwrap(), "line 1\nstreamed\n");
        assert_eq!(String::from_utf8(c.stderr).unwrap(), "warn\n");
        assert_eq!(c.files_out.get("out.jsonl").map(String::as_str), Some("data"));
        assert!(!serving(), "removed after the request");
    }

    #[test]
    fn capture_is_removed_after_a_panic() {
        let r = std::panic::catch_unwind(|| capture(Capture::default(), || panic!("boom")));
        assert!(r.is_err());
        assert!(!serving());
    }

    #[test]
    fn policy_checks_apply_only_when_serving() {
        assert!(require_admin("x").is_ok() && require_local("x").is_ok());
        let ((admin, local), _) =
            capture(Capture::default(), || (require_admin("config set"), require_local("bd init")));
        assert_eq!(admin.unwrap_err().exit_code(), 7);
        assert_eq!(local.unwrap_err().exit_code(), 2);
        let (admin, _) = capture(Capture { admin: true, ..Default::default() }, || require_admin("config set"));
        assert!(admin.is_ok());
    }

    #[test]
    fn requests_carry_their_token_policy() {
        assert_eq!(policy(), None, "nothing is limited locally");
        let (p, _) = capture(Capture::default(), policy);
        assert_eq!(p, Some(bd_core::Policy::default()), "a capture without token facts limits everything");
        let c = Capture { human: true, token_actor: "alice".into(), ..Default::default() };
        let (p, _) = capture(c, policy);
        assert_eq!(p, Some(bd_core::Policy { actor: "alice".into(), admin: false, human: true }));
    }
}
