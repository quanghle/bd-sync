//! Command I/O: the process's stdio and files, or a captured request.
//!
//! Commands write output and read input only through this module. Locally
//! that is stdout, stderr, stdin and the file system. When `bd serve` runs a
//! command, it installs a [`Capture`] on the request's thread: stdout and
//! output files go to the request's [`Sink`] as they are written (the
//! response stream, so a large export is never held whole), stderr is kept
//! for the end of the response, stdin and input files come from the
//! request, and the server's own files are never read or written on a
//! client's behalf.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use bd_core::{Error, Result};

/// Stderr kept for a served command's response. Commands print errors and
/// warnings there, which are short; anything past this is cut.
pub const STDERR_LIMIT: usize = 64 << 10;

/// Where a command run by `bd serve` sends its output, as it writes it.
pub trait Sink {
    /// The next bytes the command printed on stdout.
    fn stdout(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// The next bytes of the output file `path` (as named on the command
    /// line); the first call for a file may be empty.
    fn file(&mut self, path: &str, data: &[u8]) -> std::io::Result<()>;
}

/// A sink shared with the code that installed it, which reads it afterwards.
impl<S: Sink + ?Sized> Sink for Rc<RefCell<S>> {
    fn stdout(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.borrow_mut().stdout(data)
    }

    fn file(&mut self, path: &str, data: &[u8]) -> std::io::Result<()> {
        self.borrow_mut().file(path, data)
    }
}

/// The I/O of one command run by `bd serve`.
pub struct Capture {
    /// Receives stdout and output files.
    pub sink: Box<dyn Sink>,
    /// Stderr, up to [`STDERR_LIMIT`].
    pub stderr: Vec<u8>,
    /// The client's stdin, for commands that read it.
    pub stdin: Option<String>,
    /// Input files sent by the client, keyed by the path on its command line.
    pub files_in: BTreeMap<String, String>,
    /// The request's access token may run admin-only commands.
    pub admin: bool,
    /// The request's access token is a person's: it may open human gates.
    pub human: bool,
    /// The request's access token's actor: claims held by it or its
    /// sub-actors are the caller's own.
    pub token_actor: String,
}

impl Capture {
    /// A capture sending output to `sink`, with no client input and the
    /// policy of a token with no rights (not admin, not a person, owning no
    /// claims); a request sets its token's.
    pub fn new(sink: Box<dyn Sink>) -> Capture {
        Capture {
            sink,
            stderr: Vec::new(),
            stdin: None,
            files_in: BTreeMap::new(),
            admin: false,
            human: false,
            token_actor: String::new(),
        }
    }

    /// A capture whose stdout is kept in the returned buffer, up to `limit`
    /// bytes: for the commands `bd serve` runs for itself, which read it.
    pub fn buffered(limit: usize) -> (Rc<RefCell<Buffer>>, Capture) {
        let buffer = Rc::new(RefCell::new(Buffer { limit, stdout: Vec::new(), over: false }));
        (buffer.clone(), Capture::new(Box::new(buffer)))
    }
}

/// Stdout kept in memory, up to a limit (see [`Capture::buffered`]).
pub struct Buffer {
    limit: usize,
    stdout: Vec<u8>,
    over: bool,
}

impl Buffer {
    /// What the command printed, or an error if it printed more than the limit.
    pub fn output(&self) -> Result<&[u8]> {
        if self.over {
            return Err(Error::invalid(format!("the command printed more than {} KiB", self.limit >> 10)));
        }
        Ok(&self.stdout)
    }
}

impl Sink for Buffer {
    fn stdout(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.over || self.stdout.len() + data.len() > self.limit {
            self.over = true;
            self.stdout = Vec::new();
            return Err(std::io::Error::other(format!("more than {} KiB of output", self.limit >> 10)));
        }
        self.stdout.extend_from_slice(data);
        Ok(())
    }

    fn file(&mut self, path: &str, _: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other(format!("{path}: no output files here")))
    }
}

thread_local! {
    static CAPTURE: RefCell<Option<Capture>> = const { RefCell::new(None) };
}

/// Run `f` with `capture` installed on this thread. Returns `f`'s result and
/// the capture, with what `f` wrote on stderr. The capture is removed even
/// if `f` panics.
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
    let captured = CAPTURE.with(|c| c.borrow_mut().take()).expect("installed above");
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

/// Write to stdout through `f`: locally the locked stdout, under `bd serve`
/// the request's sink, which streams it to the client.
pub fn with_stdout<T>(f: impl FnOnce(&mut dyn Write) -> T) -> T {
    if serving() {
        return f(&mut Captured(None));
    }
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let out = f(&mut lock);
    let _ = lock.flush();
    out
}

/// A served command's stdout (`None`) or output file: each write goes to the request's sink.
struct Captured(Option<String>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let sent = with_capture(|c| match &self.0 {
            None => c.sink.stdout(buf),
            Some(path) => c.sink.file(path, buf),
        });
        sent.unwrap_or_else(|| Err(std::io::Error::other("the request's output is closed")))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    if with_capture(|c| keep_stderr(&mut c.stderr, line)).is_none() {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

fn keep_stderr(stderr: &mut Vec<u8>, line: &str) {
    const CUT: &[u8] = b"[bd serve: more stderr output was cut]\n";
    if stderr.ends_with(CUT) {
        return;
    }
    if stderr.len() + line.len() + 1 + CUT.len() <= STDERR_LIMIT {
        stderr.extend_from_slice(line.as_bytes());
        stderr.push(b'\n');
    } else {
        stderr.extend_from_slice(CUT);
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

/// Write an output file named on the command line through `f`, by sending
/// it to the client, which writes it locally. Only valid while serving;
/// locally, commands write the file themselves.
pub fn send_file<T>(path: &Path, f: impl FnOnce(&mut dyn Write) -> Result<T>) -> Result<T> {
    if !serving() {
        return Err(Error::invalid("send_file outside bd serve"));
    }
    let key = path.to_string_lossy().into_owned();
    // Announce the file, so that the client creates it even if it stays empty.
    with_capture(|c| c.sink.file(&key, b"")).unwrap_or(Ok(()))?;
    let mut w = std::io::BufWriter::with_capacity(16 << 10, Captured(Some(key)));
    let out = f(&mut w)?;
    w.flush()?;
    Ok(out)
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

    #[derive(Default)]
    struct Recorded {
        stdout: Vec<u8>,
        files: BTreeMap<String, Vec<u8>>,
    }

    impl Sink for Recorded {
        fn stdout(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.stdout.extend_from_slice(data);
            Ok(())
        }

        fn file(&mut self, path: &str, data: &[u8]) -> std::io::Result<()> {
            self.files.entry(path.to_string()).or_default().extend_from_slice(data);
            Ok(())
        }
    }

    fn recording() -> (Rc<RefCell<Recorded>>, Capture) {
        let sink = Rc::new(RefCell::new(Recorded::default()));
        (sink.clone(), Capture::new(Box::new(sink)))
    }

    #[test]
    fn capture_streams_output_and_serves_inputs() {
        let mut files_in = BTreeMap::new();
        files_in.insert("in.jsonl".to_string(), "{}".to_string());
        let (sink, c) = recording();
        let c = Capture { stdin: Some("piped".into()), files_in, ..c };
        let ((stdin, file, missing, again), c) = capture(c, || {
            outln("line 1");
            with_stdout(|w| {
                write!(w, "streamed").unwrap();
                outln(" (nested)");
            });
            errln("warn");
            send_file(Path::new("out.jsonl"), |w| Ok(w.write_all(b"data")?)).unwrap();
            send_file(Path::new("empty.jsonl"), |_| Ok(())).unwrap();
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
        assert_eq!(String::from_utf8(c.stderr).unwrap(), "warn\n");
        let sink = sink.borrow();
        assert_eq!(String::from_utf8_lossy(&sink.stdout), "line 1\nstreamed (nested)\n", "in the order written");
        assert_eq!(sink.files.get("out.jsonl").map(Vec::as_slice), Some(&b"data"[..]));
        assert_eq!(sink.files.get("empty.jsonl").map(Vec::len), Some(0), "an empty file is announced");
        assert!(!serving(), "removed after the request");
        assert!(send_file(Path::new("x"), |_| Ok(())).is_err(), "only while serving");
    }

    #[test]
    fn buffered_captures_keep_output_up_to_a_limit() {
        let (out, c) = Capture::buffered(16);
        let ((), _) = capture(c, || outln("[\"t-1\"]"));
        assert_eq!(out.borrow().output().unwrap(), b"[\"t-1\"]\n");

        let (out, c) = Capture::buffered(16);
        let (sent, _) = capture(c, || {
            outln("0123456789");
            outln("0123456789");
            send_file(Path::new("x.jsonl"), |_| Ok(()))
        });
        assert!(out.borrow().output().unwrap_err().to_string().contains("more than"), "never a partial output");
        assert!(sent.is_err(), "no output files");
    }

    #[test]
    fn served_stderr_is_cut_at_its_limit() {
        let (_, c) = recording();
        let ((), c) = capture(c, || {
            let line = "x".repeat(1000);
            for _ in 0..100 {
                errln(&line);
            }
            errln("last");
        });
        let text = String::from_utf8(c.stderr).unwrap();
        assert!(text.len() <= STDERR_LIMIT, "{}", text.len());
        assert!(text.ends_with("[bd serve: more stderr output was cut]\n"), "{}", &text[text.len() - 80..]);
        assert!(!text.contains("last"), "nothing after the cut");
    }

    #[test]
    fn capture_is_removed_after_a_panic() {
        let r = std::panic::catch_unwind(|| capture(recording().1, || panic!("boom")));
        assert!(r.is_err());
        assert!(!serving());
    }

    #[test]
    fn policy_checks_apply_only_when_serving() {
        assert!(require_admin("x").is_ok() && require_local("x").is_ok());
        let ((admin, local), _) = capture(recording().1, || (require_admin("config set"), require_local("bd init")));
        assert_eq!(admin.unwrap_err().exit_code(), 7);
        assert_eq!(local.unwrap_err().exit_code(), 2);
        let (admin, _) = capture(Capture { admin: true, ..recording().1 }, || require_admin("config set"));
        assert!(admin.is_ok());
    }

    #[test]
    fn requests_carry_their_token_policy() {
        assert_eq!(policy(), None, "nothing is limited locally");
        let (p, _) = capture(recording().1, policy);
        assert_eq!(p, Some(bd_core::Policy::default()), "a capture without token facts limits everything");
        let (p, _) = capture(Capture::buffered(16).1, policy);
        assert_eq!(p, Some(bd_core::Policy::default()), "nor do the server's own commands");
        let c = Capture { human: true, token_actor: "alice".into(), ..recording().1 };
        let (p, _) = capture(c, policy);
        assert_eq!(p, Some(bd_core::Policy { actor: "alice".into(), admin: false, human: true }));
    }
}
