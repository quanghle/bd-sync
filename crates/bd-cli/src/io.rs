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
    /// Where an event listing ends (see [`cursor`]); the last one counts.
    fn cursor(&mut self, _seq: i64) {}
}

/// A sink shared with the code that installed it, which reads it afterwards.
impl<S: Sink + ?Sized> Sink for Rc<RefCell<S>> {
    fn stdout(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.borrow_mut().stdout(data)
    }

    fn file(&mut self, path: &str, data: &[u8]) -> std::io::Result<()> {
        self.borrow_mut().file(path, data)
    }

    fn cursor(&mut self, seq: i64) {
        self.borrow_mut().cursor(seq)
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
    /// The most issues the token's actor and sub-actors may hold.
    pub max_claims: Option<u32>,
    /// The request's access token itself, which `bd info` describes to its
    /// client; the fields above are what it may override.
    pub token: Option<crate::auth::Token>,
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
            max_claims: None,
            token: None,
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
    with_capture(|c| bd_core::Policy {
        actor: c.token_actor.clone(),
        admin: c.admin,
        human: c.human,
        max_claims: c.max_claims,
    })
}

/// The access token of the request being served, if any.
pub fn request_token() -> Option<crate::auth::Token> {
    with_capture(|c| c.token.clone()).flatten()
}

fn with_capture<T>(f: impl FnOnce(&mut Capture) -> T) -> Option<T> {
    CAPTURE.with(|c| c.borrow_mut().as_mut().map(f))
}

/// Write to stdout through `f`: locally the locked stdout, under `bd serve`
/// the request's sink, which streams it to the client.
pub fn with_stdout<T>(f: impl FnOnce(&mut dyn Write) -> T) -> T {
    if serving() {
        return screened(&mut Captured(None), f);
    }
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let out = screened(&mut lock, f);
    let _ = lock.flush();
    out
}

/// Run `f` writing to `w` through an [`Escaper`].
fn screened<T>(w: &mut dyn Write, f: impl FnOnce(&mut dyn Write) -> T) -> T {
    let mut screen = Screened { inner: w, escaper: Escaper::default(), buf: Vec::new() };
    let out = f(&mut screen);
    screen.buf.clear();
    screen.escaper.finish(&mut screen.buf);
    let _ = screen.inner.write_all(&screen.buf);
    out
}

struct Screened<'a> {
    inner: &'a mut dyn Write,
    escaper: Escaper,
    buf: Vec<u8>,
}

impl Write for Screened<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.clear();
        self.escaper.feed(data, &mut self.buf);
        self.inner.write_all(&self.buf)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Whether printing `c` could do more than show a character: controls other
/// than newline and tab (terminal escape sequences, a carriage return that
/// overwrites the line) and bidirectional embeddings, overrides and isolates
/// (text that reads other than it is stored).
fn unsafe_char(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t') || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Escapes printed output as it streams, so that text stored by anyone who
/// may write to a workspace, or sent by a server, cannot drive the terminal
/// that shows it. Characters are escaped as `\uXXXX`, which inside a JSON
/// string means the same character, so `--json` output and exports keep
/// their data. A carriage return stays when a newline follows it (CRLF line
/// ends). Bytes that are not UTF-8 (bd prints none) are escaped as `\xNN`.
#[derive(Default)]
pub struct Escaper {
    /// The end of the last write: an incomplete character, or a carriage return.
    held: Vec<u8>,
}

impl Escaper {
    /// Escape the next bytes of the stream into `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let data = if self.held.is_empty() {
            std::borrow::Cow::Borrowed(data)
        } else {
            let mut joined = std::mem::take(&mut self.held);
            joined.extend_from_slice(data);
            std::borrow::Cow::Owned(joined)
        };
        let keep = escape(&data, out, false);
        self.held.extend_from_slice(&data[data.len() - keep..]);
    }

    /// The stream ended: escape what was held back into `out`.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        escape(&std::mem::take(&mut self.held), out, true);
    }
}

/// `text` as an [`Escaper`] prints it.
pub fn printable(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(unsafe_char) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = Vec::with_capacity(text.len() + 16);
    escape(text.as_bytes(), &mut out, true);
    std::borrow::Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Escape `data` into `out`. Returns how many bytes at its end are held back
/// for the next write (none at the `end` of the stream).
fn escape(data: &[u8], out: &mut Vec<u8>, end: bool) -> usize {
    let mut i = 0;
    while i < data.len() {
        let (text, bad) = match std::str::from_utf8(&data[i..]) {
            Ok(s) => (s, None),
            Err(e) => (std::str::from_utf8(&data[i..i + e.valid_up_to()]).unwrap_or_default(), Some(e.error_len())),
        };
        let bytes = text.as_bytes();
        let mut from = 0;
        let mut chars = text.char_indices().peekable();
        while let Some((at, c)) = chars.next() {
            if !unsafe_char(c) {
                continue;
            }
            if c == '\r' {
                match chars.peek() {
                    Some((_, '\n')) => continue,
                    // The newline may come with the next write.
                    None if bad.is_none() && !end => {
                        out.extend_from_slice(&bytes[from..at]);
                        return data.len() - (i + at);
                    }
                    _ => {}
                }
            }
            out.extend_from_slice(&bytes[from..at]);
            let _ = write!(out, "\\u{:04x}", c as u32);
            from = at + c.len_utf8();
        }
        out.extend_from_slice(&bytes[from..]);
        i += text.len();
        match bad {
            None => {}
            // A character the next write completes.
            Some(None) if !end => return data.len() - i,
            Some(len) => {
                let n = len.unwrap_or(data.len() - i);
                for b in &data[i..i + n] {
                    let _ = write!(out, "\\x{b:02x}");
                }
                i += n;
            }
        }
    }
    0
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
    let line = printable(line.as_ref());
    let line = line.as_ref();
    if with_capture(|c| keep_stderr(&mut c.stderr, line)).is_none() {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// Tell a remote client where the event listing just printed ends: the
/// `--since` value that continues after it. Locally it is not printed.
pub fn cursor(seq: i64) {
    with_capture(|c| c.sink.cursor(seq));
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

/// Waits between attempts of [`replace_file`] while the target is busy:
/// about 0.6 s in all.
const REPLACE_DELAYS_MS: [u64; 6] = [10, 20, 40, 80, 160, 320];

/// Move the finished temp file `tmp` over `target`. On Windows the rename
/// fails while another program (an editor, an indexer, antivirus) has
/// `target` open, so it is retried briefly. On failure `tmp` is removed.
pub fn replace_file(tmp: &Path, target: &Path) -> std::io::Result<()> {
    let delays = REPLACE_DELAYS_MS.map(std::time::Duration::from_millis);
    let moved = retry_busy(|| std::fs::rename(tmp, target), &delays, is_busy).map_err(|e| {
        if is_busy(&e) {
            std::io::Error::new(e.kind(), format!("{e} (is the file open in another program?)"))
        } else {
            e
        }
    });
    if moved.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    moved
}

/// Run `op`, again after each of `delays` while it fails with an error `busy` accepts.
fn retry_busy<T>(
    mut op: impl FnMut() -> std::io::Result<T>,
    delays: &[std::time::Duration],
    busy: impl Fn(&std::io::Error) -> bool,
) -> std::io::Result<T> {
    let mut delays = delays.iter();
    loop {
        match op() {
            Err(e) if busy(&e) => match delays.next() {
                Some(d) => std::thread::sleep(*d),
                None => return Err(e),
            },
            done => return done,
        }
    }
}

/// A sharing or lock violation: another process has the file open.
#[cfg(windows)]
fn is_busy(e: &std::io::Error) -> bool {
    // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
    matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

#[cfg(not(windows))]
fn is_busy(_: &std::io::Error) -> bool {
    false
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

    /// `chunks` through one [`Escaper`], as written one after another.
    fn escaped(chunks: &[&[u8]]) -> String {
        let (mut e, mut out) = (Escaper::default(), Vec::new());
        for c in chunks {
            e.feed(c, &mut out);
        }
        e.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn printed_output_cannot_drive_the_terminal() {
        let hostile = "a\u{1b}]52;c;Y3VybA==\u{7}b\u{9b}2J\u{7f}\u{0}c\u{202e}d\u{2066}e\rf";
        let shown = printable(hostile);
        assert_eq!(shown, r"a\u001b]52;c;Y3VybA==\u0007b\u009b2J\u007f\u0000c\u202ed\u2066e\u000df");
        assert!(!shown.contains(unsafe_char));
        assert_eq!(printable(&shown), shown, "escaping twice changes nothing");
        // Newlines, tabs, CRLF line ends and other text are printed as they are.
        for plain in ["line\n\tindented\r\nnext ünïcode ✓ 👨‍👩‍👧 שלום\u{200f}", ""] {
            assert_eq!(printable(plain), plain);
        }
        // Inside a JSON string the escapes mean the same characters: --json and exports keep their data.
        let json = serde_json::to_string(&serde_json::json!({ "title": hostile })).unwrap();
        let back: serde_json::Value = serde_json::from_str(&printable(&json)).unwrap();
        assert_eq!(back["title"], hostile);
    }

    #[test]
    fn the_escaper_holds_characters_and_crlf_split_across_writes() {
        let text = "é\r\n\u{1b}x\u{202e}";
        let bytes = text.as_bytes();
        let whole = escaped(&[bytes]);
        assert_eq!(whole, "é\r\n\\u001bx\\u202e");
        for at in 0..=bytes.len() {
            assert_eq!(escaped(&[&bytes[..at], &bytes[at..]]), whole, "split at {at}");
        }
        assert_eq!(escaped(&[b"a\r", b"b"]), r"a\u000db");
        assert_eq!(escaped(&[b"a\r"]), r"a\u000d", "a carriage return at the end");
        assert_eq!(escaped(&[b"a\xc3"]), r"a\xc3", "a character the stream never completes");
        assert_eq!(escaped(&[b"a\xff\x9bb"]), r"a\xff\x9bb", "bytes that are not UTF-8");
    }

    #[test]
    fn stdout_and_stderr_are_escaped_when_serving() {
        let (sink, c) = recording();
        let ((), c) = capture(c, || {
            with_stdout(|w| {
                w.write_all(b"t\xc3").unwrap();
                w.write_all(b"\xa9\x1b[2J\r").unwrap();
                w.write_all(b"\n").unwrap();
            });
            errln("bad \u{1b}]0;x\u{7}");
        });
        assert_eq!(String::from_utf8(sink.borrow().stdout.clone()).unwrap(), "té\\u001b[2J\r\n");
        assert_eq!(String::from_utf8(c.stderr).unwrap(), "bad \\u001b]0;x\\u0007\n");
    }

    #[test]
    fn retry_busy_retries_only_busy_errors_and_gives_up() {
        use std::io::{Error as IoError, ErrorKind};
        let delays = [std::time::Duration::ZERO; 3];
        let busy = |e: &IoError| e.kind() == ErrorKind::PermissionDenied;

        let mut calls = 0;
        let r = retry_busy(
            || {
                calls += 1;
                if calls < 3 { Err(IoError::from(ErrorKind::PermissionDenied)) } else { Ok(calls) }
            },
            &delays,
            busy,
        );
        assert_eq!(r.unwrap(), 3);

        let mut calls = 0;
        let r: std::io::Result<()> = retry_busy(
            || {
                calls += 1;
                Err(IoError::from(ErrorKind::PermissionDenied))
            },
            &delays,
            busy,
        );
        assert_eq!(r.unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(calls, 4);

        let mut calls = 0;
        let r: std::io::Result<()> = retry_busy(
            || {
                calls += 1;
                Err(IoError::from(ErrorKind::NotFound))
            },
            &delays,
            busy,
        );
        assert_eq!(r.unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(calls, 1);
    }

    #[test]
    fn replace_file_replaces_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let (tmp, target) = (dir.path().join("out.jsonl.tmp"), dir.path().join("out.jsonl"));
        std::fs::write(&target, "old").unwrap();
        std::fs::write(&tmp, "new").unwrap();
        replace_file(&tmp, &target).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists());

        std::fs::write(&tmp, "orphan").unwrap();
        assert!(replace_file(&tmp, &dir.path().join("missing").join("out.jsonl")).is_err());
        assert!(!tmp.exists());
    }

    #[cfg(windows)]
    #[test]
    fn replace_file_waits_for_a_reader_to_close_the_target() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (tmp, target) = (dir.path().join("out.jsonl.tmp"), dir.path().join("out.jsonl"));
        std::fs::write(&target, "old").unwrap();
        std::fs::write(&tmp, "new").unwrap();
        // FILE_SHARE_READ only, as many editors open files: renaming over it fails meanwhile.
        let held = std::fs::OpenOptions::new().read(true).share_mode(1).open(&target).unwrap();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(held);
        });
        replace_file(&tmp, &target).unwrap();
        reader.join().unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
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
        assert_eq!(p, Some(bd_core::Policy { actor: "alice".into(), admin: false, human: true, max_claims: None }));
    }
}
