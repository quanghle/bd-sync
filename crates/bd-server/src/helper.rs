//! The admin's helper commands, which `bd serve` runs with one JSON request
//! on stdin and reads one JSON answer from stdout: the authorizer's
//! (`authorizer.rs`) and the secrets helper's (`secrets.rs`). Both are
//! written in `auth.toml` alike (`command`, `env`, `timeout`) and run alike
//! (`run`): as is, no shell, in the root, with a cleared environment.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What of the command's stderr the log shows.
pub(crate) const MAX_STDERR: usize = 2 << 10;
/// What of the command's stderr is kept for the caller's filter, which runs
/// before it is cut to [`MAX_STDERR`]; the rest is read and dropped, so that
/// a command writing more is never stopped by a closed pipe.
const STDERR_KEPT: usize = 64 << 10;
/// Variables every command gets, from the server's environment, besides `env`.
const PASSED: &[&str] = &["PATH", "HOME", "LANG", "SystemRoot", "windir", "PATHEXT", "TEMP", "TMP", "USERPROFILE"];
/// The range of a command's `timeout`.
const TIMEOUT_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A helper command as `auth.toml` names it: the program and its
/// arguments, and the variables of the server's environment it gets
/// besides [`PASSED`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Helper {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub timeout: Duration,
}

/// `<table>.command`, `env` and `timeout` (`default` when not written),
/// checked.
pub(crate) fn parse(
    table: &str,
    argv: Vec<String>,
    env: Vec<String>,
    timeout: Option<&str>,
    default: Duration,
) -> Result<Helper, String> {
    if argv.is_empty() || argv[0].trim().is_empty() {
        return Err(format!("{table}.command is empty: name the program, then its arguments"));
    }
    if argv.iter().any(|a| a.contains('\0')) {
        return Err(format!("{table}.command holds a NUL character"));
    }
    for (i, name) in env.iter().enumerate() {
        let ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        // Never quoted: `NAME=value` would show the value, a credential perhaps.
        if !ok {
            return Err(format!(
                "{table}.env entry {} is not a variable name: name variables only, their values come from the \
                 server's environment",
                i + 1
            ));
        }
    }
    Ok(Helper { argv, env, timeout: self::timeout(table, timeout, default)? })
}

/// `<table>.timeout` as written (`default` when not), checked: 1s to 60s.
pub(crate) fn timeout(table: &str, raw: Option<&str>, default: Duration) -> Result<Duration, String> {
    let Some(raw) = raw else { return Ok(default) };
    let t = bd_core::time::parse_duration(raw).map_err(|e| format!("{table}.timeout: {e}"))?;
    if !(TIMEOUT_RANGE.0..=TIMEOUT_RANGE.1).contains(&t) {
        return Err(format!("{table}.timeout {raw:?}: use 1s to 60s"));
    }
    Ok(t)
}

/// `command` as `auth.toml` writes it: the program, then its arguments,
/// deserialized without ever quoting what was written in its place (a
/// command line holding a credential, perhaps).
pub(crate) fn argv<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    d.deserialize_any(Words {
        expecting: "a list: the program, then its arguments, such as [\"bin/helper\", \"--flag\"]",
        not_a_list: "command is a list: the program, then its arguments, such as [\"bin/helper\", \"--flag\"]",
    })
}

/// [`argv`], for a `command` that may be left out.
pub(crate) fn some_argv<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    argv(d).map(Some)
}

/// `env` as `auth.toml` writes it: a list of variable names, deserialized
/// without ever quoting what was written in its place (a credential,
/// perhaps).
pub(crate) fn env_names<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    d.deserialize_any(Words {
        expecting: "a list of variable names, such as [\"VAULT_ADDR\"]",
        not_a_list: "env is a list of variable names, such as [\"VAULT_ADDR\"]",
    })
}

/// A list of strings in `auth.toml`, read without quoting anything written
/// in its place or in an item's (serde's own messages quote a string, a
/// number or a boolean: a credential, perhaps).
struct Words {
    expecting: &'static str,
    /// What anything but a list is told.
    not_a_list: &'static str,
}

impl Words {
    /// Refused, `what` was written in the list's place (never quoted).
    fn refuse<E: serde::de::Error>(&self, what: &str) -> Result<Vec<String>, E> {
        Err(E::custom(format!("{}, not {what}", self.not_a_list)))
    }
}

impl<'de> serde::de::Visitor<'de> for Words {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Vec<String>, E> {
        self.refuse("a string")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Vec<String>, E> {
        self.refuse("a boolean")
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Vec<String>, E> {
        self.refuse("a number")
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Vec<String>, E> {
        self.refuse("a number")
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Vec<String>, E> {
        self.refuse("a number")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, _: A) -> Result<Vec<String>, A::Error> {
        self.refuse("a table")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
        let mut words = Vec::new();
        while let Some(Word(word)) = seq.next_element()? {
            words.push(word);
        }
        Ok(words)
    }
}

/// A string read without quoting anything written in its place.
pub(crate) struct Word(pub String);

impl<'de> serde::Deserialize<'de> for Word {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Word, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Word;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Word, E> {
                Ok(Word(s.to_string()))
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Word, E> {
                Err(E::custom("not a string (quote it)"))
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Word, E> {
                Err(E::custom("not a string (quote it)"))
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Word, E> {
                Err(E::custom("not a string (quote it)"))
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Word, E> {
                Err(E::custom("not a string (quote it)"))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// Why helper commands may not run in this process, if they may not
/// (`forbid`).
static FORBIDDEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Let no helper command run in this process from now on, for `why` (`bd
/// serve check` run by anyone but the root's owner): decided where commands
/// start, so no later read of `auth.toml` gets past it.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn forbid(why: String) {
    let _ = FORBIDDEN.set(why);
}

/// Why helper commands may not run in this process, if they may not
/// ([`forbid`]).
pub(crate) fn forbidden() -> Option<&'static str> {
    FORBIDDEN.get().map(String::as_str)
}

/// Run `helper` in `root` (made absolute, so that the command and its
/// directory are found alike however the root was named) with `body` on its
/// stdin: its stdout, if it exits 0 within its timeout with at most
/// `max_answer` bytes. On failure, its stderr (the first [`STDERR_KEPT`]
/// bytes, whole lines) goes into the error through `shown`, which leaves out
/// what the log must not keep, then cut to [`MAX_STDERR`]. It runs in a
/// process group of its own (on Unix), which is killed once it has answered
/// and exited (or ran out of time), so nothing it started outlives it or
/// keeps bd waiting on its output past the deadline; the processes of the
/// group that bd ends up the parent of are reaped. On Unix its output is
/// read here, never past the deadline, so a process that escaped its group
/// holding the output open holds nothing of bd's. [`end_all`] ends the
/// commands running when the server stops.
pub(crate) fn run(
    root: &Path,
    helper: &Helper,
    body: &[u8],
    max_answer: u64,
    shown: &dyn Fn(&str) -> String,
) -> Result<Vec<u8>, String> {
    let Helper { argv, env, timeout } = helper;
    if let Some(why) = forbidden() {
        return Err(why.to_string());
    }
    let deadline = Instant::now() + *timeout;
    let root = &std::path::absolute(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let program = Path::new(&argv[0]);
    let program = match program.is_relative() && program.components().count() > 1 {
        true => root.join(program),
        false => program.to_path_buf(),
    };
    let mut command = Command::new(&program);
    command.args(&argv[1..]).current_dir(root).env_clear();
    for name in PASSED.iter().copied().chain(env.iter().map(String::as_str)) {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().map_err(|e| format!("{} could not be run: {e}", program.display()))?;
    let group = Group::new(child.id());
    let mut stdin = child.stdin.take().expect("piped");
    let (stdout, stderr) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let body = body.to_vec();
    // Written on a thread, so that a command which does not read cannot stall the rest. A thread the system will
    // not start fails the run (the command killed), never the caller.
    let started = thread(move || {
        let _ = stdin.write_all(&body);
    });
    let output = started.map_err(|e| format!("it could not be run: {e}")).and_then(|()| {
        collect(stdout, stderr, max_answer, deadline, &group, &mut child)
            .map_err(|e| format!("reading its answer: {e}"))
    });
    // Whatever it left running goes, answered or not: the group is killed before the command is reaped, so its
    // id still names it, never another process's. Whether it had ended on its own: on Unix, by how it ended (a
    // kill shows as a signal); on Windows, a kill shows as an exit code, so asked first (no group id to reuse).
    #[cfg(not(unix))]
    let exited = matches!(child.try_wait(), Ok(Some(_)));
    let status = group.end(&mut child);
    #[cfg(unix)]
    let exited = status.as_ref().is_some_and(|s| s.code().is_some());
    let Output { out, err, answered } = output?;
    if !answered {
        let late = format!("it did not answer within {}", fmt_duration(*timeout));
        return Err(match exited {
            true => format!("{late}: it exited, but a process it started kept its output open"),
            false => late,
        });
    }
    let Some(status) = status else { return Err("waiting for it failed".into()) };
    // First: past the limit, it was left writing to a closed pipe, which may be why it failed.
    if out.len() as u64 > max_answer {
        return Err(format!("its answer is larger than {} KiB", max_answer >> 10));
    }
    if !status.success() {
        return Err(format!("it exited with {status}: {}", stderr_shown(&err, shown)));
    }
    Ok(out)
}

/// What of `err`, a command's stderr, the log shows: when it filled what is
/// kept, its last line (cut there, perhaps through a value) left out; then
/// what `shown` leaves out left out, and cut to [`MAX_STDERR`].
fn stderr_shown(err: &[u8], shown: &dyn Fn(&str) -> String) -> String {
    let whole = match err.len() >= STDERR_KEPT {
        true => err.iter().rposition(|&b| b == b'\n').map_or(&err[..0], |end| &err[..=end]),
        false => err,
    };
    let err = String::from_utf8_lossy(whole);
    crate::authorizer::clip(&shown(&err), MAX_STDERR).trim().to_string()
}

/// What a command wrote: its stdout (at most one byte past the limit),
/// whether that ended (or passed the limit) by the deadline, and its stderr
/// (at most [`STDERR_KEPT`] bytes).
struct Output {
    out: Vec<u8>,
    answered: bool,
    err: Vec<u8>,
}

/// How long the command has to exit once it answered (its stdout ended),
/// before it is killed (and its answer refused).
const EXIT_AFTER: Duration = Duration::from_secs(1);
/// How long stderr is read on once the command answered and exited (and,
/// on Unix, what it left running in its group was killed).
const STDERR_AFTER: Duration = Duration::from_millis(100);
/// How often whether the command exited is looked at, while waiting for it.
const EXIT_POLL: Duration = Duration::from_millis(5);
/// Stderr read in all (beyond [`STDERR_KEPT`], dropped) before it is closed:
/// a command still writing more is flooding it, and is stopped by the closed
/// pipe rather than read on until its deadline.
const STDERR_READ_MAX: u64 = 1 << 20;

/// Read the command's stdout and stderr until stdout ends and the command
/// exited (within [`EXIT_AFTER`]; then, its group killed, stderr a little
/// longer, [`STDERR_AFTER`]) or the deadline: on this thread, polling both,
/// one bounded read of each ready pipe per wake-up, so that the deadline is
/// looked at however fast they are written, and nothing is left reading
/// once it returns. Stdout past `max_answer`, and stderr past
/// [`STDERR_READ_MAX`], are closed. Whether it exited is looked at without
/// reaping it (`WNOWAIT`), so its group's id still names it.
#[cfg(unix)]
fn collect(
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    max_answer: u64,
    deadline: Instant,
    group: &Group,
    child: &mut std::process::Child,
) -> std::io::Result<Output> {
    use std::os::fd::AsRawFd;
    let mut out_pipe = Pipe::new(stdout)?;
    let mut err_pipe = Pipe::new(stderr)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut answered_at, mut exited_at): (Option<Instant>, Option<Instant>) = (None, None);
    loop {
        let now = Instant::now();
        if answered_at.is_some() && exited_at.is_none() && exited(child.id()) {
            exited_at = Some(now);
            // What it left running goes now: stderr they held ends at once.
            group.kill();
        }
        let limit = match (answered_at, exited_at) {
            (None, _) => deadline,
            (Some(at), None) => (at + EXIT_AFTER).min(deadline),
            (Some(_), Some(at)) => (at + STDERR_AFTER).min(deadline),
        };
        let ended = out_pipe.file.is_none() && err_pipe.file.is_none();
        if (ended && exited_at.is_some()) || now >= limit {
            break;
        }
        // A closed pipe's fd is negative: poll(2) leaves it out.
        let fd = |p: &Pipe| p.file.as_ref().map_or(-1, |f| f.as_raw_fd());
        let mut fds = [
            libc::pollfd { fd: fd(&out_pipe), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: fd(&err_pipe), events: libc::POLLIN, revents: 0 },
        ];
        let mut wait = limit.saturating_duration_since(now);
        // Its exit wakes no poll: looked at again shortly.
        if answered_at.is_some() && exited_at.is_none() {
            wait = wait.min(EXIT_POLL);
        }
        let wait = i32::try_from(wait.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: fds is a live array of two pollfd, its length passed with it.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[0].revents != 0 {
            out_pipe.read_once(&mut out, max_answer.saturating_add(1))?;
            // Past the limit, stdout is as good as ended: the answer is refused, and the writer stopped.
            if out.len() as u64 > max_answer {
                out_pipe.file = None;
            }
            if out_pipe.file.is_none() {
                answered_at.get_or_insert_with(Instant::now);
            }
        }
        if fds[1].revents != 0 {
            err_pipe.read_once(&mut err, STDERR_KEPT as u64)?;
            if err_pipe.read > STDERR_READ_MAX {
                err_pipe.file = None;
            }
        }
    }
    Ok(Output { out, answered: answered_at.is_some(), err })
}

/// Whether the process `pid`, a child of this one, has exited, looked at
/// without reaping it.
#[cfg(unix)]
fn exited(pid: u32) -> bool {
    // SAFETY: a zeroed siginfo_t is a valid one; waitid(2) writes into it, and WNOWAIT leaves the child unreaped.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
        libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) == 0 && info.si_pid() != 0
    }
}

/// A pipe of the command's output, read without blocking; `None` once
/// ended or closed (which a writer still writing sees as a broken pipe).
#[cfg(unix)]
struct Pipe {
    file: Option<std::fs::File>,
    /// Bytes read in all.
    read: u64,
}

#[cfg(unix)]
impl Pipe {
    fn new(fd: impl Into<std::os::fd::OwnedFd>) -> std::io::Result<Pipe> {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::from(fd.into());
        // SAFETY: fcntl(2) on an fd this process owns, changing its flags only.
        let set = unsafe {
            let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
            flags >= 0 && libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
        };
        if !set {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Pipe { file: Some(file), read: 0 })
    }

    /// One read of what is there: kept up to `max` bytes, the rest dropped;
    /// at its end, the pipe closed.
    fn read_once(&mut self, kept: &mut Vec<u8>, max: u64) -> std::io::Result<()> {
        let Some(file) = &mut self.file else { return Ok(()) };
        let mut buf = [0u8; 16 << 10];
        match file.read(&mut buf) {
            Ok(0) => self.file = None,
            Ok(n) => {
                self.read += n as u64;
                let room = usize::try_from(max).unwrap_or(usize::MAX).saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

/// Read the command's stdout and stderr until stdout ends and the command
/// exited (within [`EXIT_AFTER`]; then stderr a little longer) or the
/// deadline, on threads of their own: a thread a process that escaped the
/// command keeps writing to reads on after this returns (Windows has no
/// process groups to end it with), at most [`STDERR_READ_MAX`] of stderr.
#[cfg(not(unix))]
fn collect(
    mut stdout: std::process::ChildStdout,
    mut stderr: std::process::ChildStderr,
    max_answer: u64,
    deadline: Instant,
    _group: &Group,
    child: &mut std::process::Child,
) -> std::io::Result<Output> {
    let (out_tx, out_rx) = std::sync::mpsc::channel();
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    thread(move || {
        let mut out = Vec::new();
        let read = (&mut stdout).take(max_answer + 1).read_to_end(&mut out);
        let _ = out_tx.send(read.map(|_| out));
    })?;
    thread(move || {
        let mut err = Vec::new();
        let _ = (&mut stderr).take(STDERR_KEPT as u64).read_to_end(&mut err);
        // Read on, so a chatty command is not stopped by a closed pipe; past the cap, closed: a flood.
        let _ = std::io::copy(&mut (&mut stderr).take(STDERR_READ_MAX - STDERR_KEPT as u64), &mut std::io::sink());
        let _ = err_tx.send(err);
    })?;
    let (out, answered) = match out_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(read) => (read?, true),
        Err(_) => (Vec::new(), false),
    };
    if !answered {
        // Killed by run at once, by the deadline: its stderr goes unread, as on Unix.
        return Ok(Output { out, answered, err: Vec::new() });
    }
    // Time to exit, so a command closing its output first is not killed for it.
    let until = (Instant::now() + EXIT_AFTER).min(deadline);
    while !matches!(child.try_wait(), Ok(Some(_))) && Instant::now() < until {
        std::thread::sleep(EXIT_POLL);
    }
    // Killed first if it has not exited, so its stderr ends: then read on a little while.
    if !matches!(child.try_wait(), Ok(Some(_))) {
        let _ = child.kill();
    }
    let err = err_rx.recv_timeout(STDERR_AFTER).unwrap_or_default();
    Ok(Output { out, answered, err })
}

/// Start `f` on a thread of its own, or say why the system would not.
fn thread(f: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    std::thread::Builder::new().name("bd-helper".into()).spawn(f).map(|_| ())
}

pub(crate) fn fmt_duration(d: Duration) -> String {
    bd_core::time::format_duration_ms(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The process group of a helper command: its id, the command's own (Unix
/// only: elsewhere the command alone is killed). Listed in [`GROUPS`] from
/// its start until the command is reaped, so [`end_all`] never names
/// another's.
struct Group(u32);

/// The groups of the commands running now, and whether the server is
/// stopping (each command started from then on is killed at once).
static GROUPS: std::sync::Mutex<Groups> = std::sync::Mutex::new(Groups { running: Vec::new(), stopping: false });

struct Groups {
    running: Vec<u32>,
    stopping: bool,
}

fn groups() -> std::sync::MutexGuard<'static, Groups> {
    GROUPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Kill the process group `id` (Unix; nothing elsewhere).
fn kill_group(id: u32) {
    #[cfg(unix)]
    if let Ok(id) = i32::try_from(id) {
        // SAFETY: kill(2) with a negative pid signals the process group the command leads; it touches no memory of
        // this process.
        unsafe {
            libc::kill(-id, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = id;
}

/// End every helper command running now, and what it started, and any
/// started from now on (Unix): the server is stopping, and would leave them
/// running, with no deadline.
pub(crate) fn end_all() {
    let mut groups = groups();
    groups.stopping = true;
    for id in groups.running.iter().copied() {
        kill_group(id);
    }
}

#[cfg(all(test, target_os = "linux"))]
fn end_where(which: impl Fn(u32) -> bool) {
    for id in groups().running.iter().copied().filter(|id| which(*id)) {
        kill_group(id);
    }
}

impl Group {
    fn new(id: u32) -> Group {
        let mut groups = groups();
        groups.running.push(id);
        if groups.stopping {
            kill_group(id);
        }
        Group(id)
    }

    /// Kill every process of the group (the command, unless reaped: the
    /// group is never killed once it is).
    #[cfg(unix)]
    fn kill(&self) {
        kill_group(self.0);
    }

    /// Kill the command, if it still runs, and on Unix every process left in
    /// its group; then reap the command, and on Unix the processes of the
    /// group whose parent this process now is (bd serve as a container's
    /// first process): how the command ended (killed, if it still ran), if
    /// that can be told.
    fn end(&self, child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        {
            // Off the list before it is reaped, and killed meanwhile: its id never names another's group.
            let mut groups = groups();
            groups.running.retain(|id| *id != self.0);
            kill_group(self.0);
        }
        let _ = child.kill();
        let status = child.wait().ok();
        #[cfg(unix)]
        self.reap();
        status
    }

    /// Reap the group's processes this process is now the parent of, killed
    /// (orphans, reparented to it when it is a container's first process),
    /// for a little while: none, at once, for any other process.
    #[cfg(unix)]
    fn reap(&self) {
        let Ok(id) = i32::try_from(self.0) else { return };
        let until = Instant::now() + Duration::from_millis(50);
        loop {
            let mut status = 0;
            // SAFETY: waitpid(2) on this process's children in the group, writing their status into a local.
            match unsafe { libc::waitpid(-id, &mut status, libc::WNOHANG) } {
                0 if Instant::now() < until => std::thread::sleep(Duration::from_millis(1)),
                n if n > 0 => {}
                _ => return,
            }
        }
    }
}

// Linux only: `setsid` is not on every Unix.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A process the command starts in a session of its own escapes its group, and may hold its output open for
    /// good: the run ends by its deadline all the same, nothing of bd's left reading.
    #[test]
    fn a_process_that_escapes_the_group_holds_nothing_past_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("cmd");
        std::fs::write(&script, "#!/bin/sh\ncat >/dev/null\nsetsid sleep 30 &\necho $! > escaped.pid\nprintf ok\n")
            .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let helper =
            Helper { argv: vec!["/bin/sh".into(), "./cmd".into()], env: vec![], timeout: Duration::from_secs(1) };
        let at = Instant::now();
        let e = run(dir.path(), &helper, b"{}", 1024, &|e| e.to_string()).unwrap_err();
        assert!(at.elapsed() < Duration::from_secs(2), "{:?}", at.elapsed());
        assert!(e.contains("kept its output open"), "{e}");
        if let Ok(pid) = std::fs::read_to_string(dir.path().join("escaped.pid")) {
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    }

    fn command(dir: &Path, body: &str, timeout: Duration) -> Helper {
        let script = dir.join("cmd");
        std::fs::write(&script, format!("#!/bin/sh\ncat >/dev/null\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        // Run by sh, never exec'd itself: a script just written may still be open in a child another thread forks
        // meanwhile ("text file busy").
        Helper { argv: vec!["/bin/sh".into(), "./cmd".into()], env: vec![], timeout }
    }

    /// Floods of output never hold a run past its deadline, nor keep it reading once there is no more to learn.
    #[test]
    fn floods_end_by_the_deadline_and_an_answer_in_time_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let run_ = |body: &str, timeout: Duration| {
            let helper = command(dir.path(), body, timeout);
            let at = Instant::now();
            let ran = run(dir.path(), &helper, b"{}", 1024, &|e| e.chars().take(40).collect());
            (ran, at.elapsed())
        };
        // Both flooded, by processes of the group: the answer is too large, ended at once.
        let (ran, took) = run_("yes >&2 &\nyes", Duration::from_secs(2));
        assert!(ran.unwrap_err().contains("larger than"), "stdout past its limit");
        assert!(took < Duration::from_secs(2), "{took:?}");
        // Stderr flooded, stdout left open: closed past its cap, the writer stopped, no spinning to the deadline.
        let (ran, took) = run_("yes 'vault: retrying' >&2", Duration::from_secs(5));
        assert!(ran.unwrap_err().contains("exited with"), "stopped by the closed pipe");
        assert!(took < Duration::from_secs(2), "{took:?}");
        // An answer in time, while a process that left the group floods stderr: kept.
        let (ran, took) = run_("setsid sh -c 'yes >&2' >/dev/null &\nprintf ok", Duration::from_secs(5));
        assert_eq!(ran.unwrap(), b"ok");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    /// A command that closes its output before it exits (as `cat` and `printf` do) is not killed for it: its
    /// answer is kept. What it left behind holding stderr ends with its group.
    #[test]
    fn a_command_closing_its_output_first_is_heard_out() {
        let dir = tempfile::tempdir().unwrap();
        let helper = command(dir.path(), "printf ok\nexec >&- 2>&-\nsleep 0.2", Duration::from_secs(5));
        assert_eq!(run(dir.path(), &helper, b"{}", 1024, &|e| e.to_string()).unwrap(), b"ok");
        let helper =
            command(dir.path(), "sleep 30 >/dev/null &\necho $! > left.pid\nprintf ok", Duration::from_secs(5));
        assert_eq!(run(dir.path(), &helper, b"{}", 1024, &|e| e.to_string()).unwrap(), b"ok");
        let left = std::fs::read_to_string(dir.path().join("left.pid")).unwrap();
        let alive = Command::new("kill").args(["-0", left.trim()]).stderr(Stdio::null()).status().unwrap();
        assert!(!alive.success(), "what it left running was killed");
    }

    /// When this process is the parent the group's orphans are reparented to (bd serve as a container's first
    /// process; here, a subreaper), they are reaped, not left as zombies.
    #[test]
    fn the_groups_orphans_are_reaped() {
        // SAFETY: prctl(2) setting this process's own subreaper flag.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        let dir = tempfile::tempdir().unwrap();
        let helper =
            command(dir.path(), "echo $$ > group.pid\nsleep 30 >/dev/null 2>&1 &\nprintf ok", Duration::from_secs(5));
        assert_eq!(run(dir.path(), &helper, b"{}", 1024, &|e| e.to_string()).unwrap(), b"ok");
        let group: i32 = std::fs::read_to_string(dir.path().join("group.pid")).unwrap().trim().parse().unwrap();
        let mut status = 0;
        // SAFETY: waitpid(2) on this process's children in the group, writing their status into a local.
        let left = unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG) };
        assert_eq!(left, -1, "no child of the group left, zombie or not");
    }

    /// The server stopping ends the commands running.
    #[test]
    fn commands_running_end_when_the_server_stops() {
        let dir = tempfile::tempdir().unwrap();
        let helper = command(dir.path(), "echo $$ > group.pid\nsleep 30", Duration::from_secs(30));
        let root = dir.path().to_path_buf();
        let at = Instant::now();
        let ran = std::thread::spawn(move || run(&root, &helper, b"{}", 1024, &|e| e.to_string()));
        let pid = dir.path().join("group.pid");
        while std::fs::read_to_string(&pid).map_or(true, |p| p.trim().is_empty()) {
            assert!(at.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }
        let group: u32 = std::fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
        // This command's group only: other tests run commands meanwhile.
        end_where(|id| id == group);
        assert!(ran.join().unwrap().is_err());
        assert!(at.elapsed() < Duration::from_secs(10), "{:?}", at.elapsed());
    }
}

/// Tests of [`forbid`], which holds for the rest of the process: each runs again in a child process of its own
/// (the test binary, this one test), so no other test of this process is ever forbidden anything.
#[cfg(all(test, unix))]
pub(crate) mod forbid_tests {
    use super::*;

    /// Set, to the test's directory, only in the child a test runs again in.
    const CHILD: &str = "BD_TEST_FORBIDDEN_DIR";

    /// The test's directory, in the child process a test runs again in; `None` in the parent.
    pub(crate) fn child_dir() -> Option<std::path::PathBuf> {
        std::env::var_os(CHILD).map(std::path::PathBuf::from)
    }

    /// Run the test named `test` (`concat!(module_path!(), "::<name>")`) again, alone, in a child process of this
    /// test binary, with `dir` as its [`child_dir`]; it must pass, and run (a name matching none passes nothing).
    pub(crate) fn rerun(test: &str, dir: &Path) {
        let (_crate, name) = test.split_once("::").expect("a path within the crate");
        let out = Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD, dir)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{name} in a child process: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status
        );
    }

    /// A command that would leave `marker` in its directory.
    fn marking() -> Helper {
        Helper {
            argv: vec!["/bin/sh".into(), "-c".into(), "echo ran > marker".into()],
            env: vec![],
            timeout: Duration::from_secs(5),
        }
    }

    /// Once forbidden, no command runs: `run` says why, as is, and starts nothing.
    #[test]
    fn a_forbidden_process_runs_no_command() {
        if let Some(dir) = child_dir() {
            forbid("not in this process".into());
            let e = run(&dir, &marking(), b"{}", 1024, &|e| e.to_string()).unwrap_err();
            assert_eq!(e, "not in this process");
            assert!(!dir.join("marker").exists(), "the command ran");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        rerun(concat!(module_path!(), "::a_forbidden_process_runs_no_command"), dir.path());
        assert!(!dir.path().join("marker").exists(), "the command ran");
        // This process is never forbidden: the same command runs, and its marker shows it.
        let control = tempfile::tempdir().unwrap();
        run(control.path(), &marking(), b"{}", 1024, &|e| e.to_string()).unwrap();
        assert!(control.path().join("marker").exists(), "the control command ran");
    }
}
