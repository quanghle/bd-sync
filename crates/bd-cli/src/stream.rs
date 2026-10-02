//! Streamed answers of `bd serve`, with bounded memory at both ends.
//!
//! On the server, a command's stdout and output files go to a
//! [`FrameWriter`] (an [`io::Sink`](crate::io::Sink)), which cuts them into
//! protocol frames of [`Limits::chunk`] bytes of output. An answer whose
//! frames fit in one chunk is sent whole, with a `Content-Length`, once the
//! command finishes: claims, closes and most commands take this path.
//! A larger answer starts as soon as its first chunk is full and flows
//! through a [`Pipe`] that queues at most [`Limits::capacity`] bytes of
//! frames; it first takes a place in the server's lane of streamed answers,
//! or is refused. A command that writes faster than its client reads waits
//! for the client, for up to [`Limits::send_timeout`] at a time and at
//! [`Limits::min_rate`] on average; once the client goes away or falls
//! behind, the command's writes fail, so it ends and frees its slot. One
//! answer holds about [`Limits::memory`] bytes at most, whatever the size of
//! the output. A held answer (a write's, see [`FrameWriter::hold`]) is kept
//! whole until the command ends, so that the server can store it before
//! sending it. [`Stalls`] closes connections whose client stops reading.
//!
//! On the client, a [`FrameReader`] parses an answer on its own thread, so
//! that a stalled connection is given up after an idle timeout instead of a
//! deadline on the whole answer, which a large export could not meet.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::{self, BufRead, BufReader, Read};
use std::pin::Pin;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use hyper::body::{Body, Bytes, Frame as BodyFrame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::io::Sink;
use crate::protocol::{ExecResponse, Exit, Frame};

/// How a served answer is cut into frames and buffered.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Output bytes per frame; an answer whose frames fit in this many bytes is sent whole.
    pub chunk: usize,
    /// Bytes of frames queued for the client before the command waits for it.
    pub capacity: usize,
    /// How long a command waits for its client to take more output.
    pub send_timeout: Duration,
    /// The slowest a client may take a streamed answer, in bytes per second
    /// on average, after `grace`: a command streams for a bounded time.
    pub min_rate: u64,
    pub grace: Duration,
}

impl Limits {
    pub const SERVE: Limits = Limits {
        chunk: 64 << 10,
        capacity: 256 << 10,
        send_timeout: Duration::from_secs(60),
        min_rate: 64 << 10,
        grace: Duration::from_secs(30),
    };

    /// About the most memory one answer holds, for text output: the output
    /// not framed yet (a chunk), frames on their way into the pipe and out of
    /// it (up to two chunks each: JSON escaping makes a frame a little larger
    /// than its output, up to 6 times for control characters), the pipe, and
    /// hyper's `write_buffer`.
    pub const fn memory(&self, write_buffer: usize) -> usize {
        5 * self.chunk + self.capacity + write_buffer
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Frames on their way from a command (on a blocking thread) to its HTTP
/// answer (polled by hyper).
struct Pipe {
    state: Mutex<PipeState>,
    /// Signalled when frames leave the pipe, or it closes.
    space: Condvar,
    capacity: usize,
}

#[derive(Default)]
struct PipeState {
    frames: VecDeque<Bytes>,
    queued: usize,
    /// The most bytes queued at once.
    peak: usize,
    /// The last frame is queued.
    finished: bool,
    /// The writer stopped without finishing: the answer ends in an error.
    abandoned: bool,
    /// The answer was dropped (the client went away): nobody reads any more.
    closed: bool,
    waker: Option<Waker>,
}

impl Pipe {
    fn new(capacity: usize) -> Arc<Pipe> {
        Arc::new(Pipe { state: Mutex::default(), space: Condvar::new(), capacity })
    }

    /// Queue `frame`, waiting until `deadline` while the pipe is full. A frame
    /// larger than the pipe goes through once the pipe is empty.
    fn push(&self, frame: Bytes, deadline: Instant) -> io::Result<()> {
        let mut s = lock(&self.state);
        loop {
            if s.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the client went away"));
            }
            if s.queued == 0 || s.queued + frame.len() <= self.capacity {
                s.queued += frame.len();
                s.peak = s.peak.max(s.queued);
                s.frames.push_back(frame);
                let waker = s.waker.take();
                drop(s);
                if let Some(w) = waker {
                    w.wake();
                }
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "the client took no more output in time"));
            }
            s = match self.space.wait_timeout(s, deadline - now) {
                Ok((s, _)) => s,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// No more frames: the answer ends normally if `finished`, else in an error.
    fn end(&self, finished: bool) {
        let mut s = lock(&self.state);
        if finished {
            s.finished = true;
        } else {
            s.abandoned = true;
        }
        let waker = s.waker.take();
        drop(s);
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn peak(&self) -> usize {
        lock(&self.state).peak
    }

    fn poll_frame(&self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        let mut s = lock(&self.state);
        if let Some(frame) = s.frames.pop_front() {
            s.queued -= frame.len();
            drop(s);
            self.space.notify_one();
            return Poll::Ready(Some(Ok(frame)));
        }
        if s.finished {
            return Poll::Ready(None);
        }
        if s.abandoned {
            return Poll::Ready(Some(Err(io::Error::other("the command stopped before finishing its answer"))));
        }
        if !s.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            s.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    /// The answer is gone: drop what is queued and fail the writer's next push.
    fn close(&self) {
        let mut s = lock(&self.state);
        s.closed = true;
        s.frames.clear();
        s.queued = 0;
        s.waker = None;
        drop(s);
        self.space.notify_all();
    }
}

/// The body of a `bd serve` answer: whole, or streamed from a running command.
pub struct ResponseBody {
    kind: Kind,
    /// The answer's share of the server's memory budget, given back when hyper drops the body.
    _budget: Option<OwnedSemaphorePermit>,
}

enum Kind {
    Whole(Option<Bytes>),
    Stream(Arc<Pipe>),
}

impl ResponseBody {
    pub fn whole(bytes: impl Into<Bytes>) -> ResponseBody {
        ResponseBody { kind: Kind::Whole(Some(bytes.into())), _budget: None }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<io::Result<BodyFrame<Bytes>>>> {
        match &mut self.get_mut().kind {
            Kind::Whole(bytes) => Poll::Ready(bytes.take().map(|b| Ok(BodyFrame::data(b)))),
            Kind::Stream(pipe) => pipe.poll_frame(cx).map(|f| f.map(|r| r.map(BodyFrame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.kind, Kind::Whole(None))
    }

    fn size_hint(&self) -> SizeHint {
        match &self.kind {
            Kind::Whole(bytes) => SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64)),
            Kind::Stream(_) => SizeHint::default(),
        }
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        if let Kind::Stream(pipe) = &self.kind {
            pipe.close();
        }
    }
}

/// A connection's socket, whose writes fail once they make no progress for
/// `limit`. hyper has no write timeout: without this, a client that stops
/// reading would hold its answer, and the memory behind it, until the
/// connection's lifetime ends.
pub struct Stalls<T> {
    io: T,
    limit: Duration,
    /// Armed while a write waits for the client.
    waiting: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> Stalls<T> {
    pub fn new(io: T, limit: Duration) -> Stalls<T> {
        Stalls { io, limit, waiting: None }
    }

    fn watch<R>(&mut self, cx: &mut Context<'_>, polled: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        if polled.is_ready() {
            self.waiting = None;
            return polled;
        }
        let limit = self.limit;
        let waiting = self.waiting.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        match waiting.as_mut().poll(cx) {
            Poll::Ready(()) => {
                let msg = format!("the client took nothing for {}s", limit.as_secs());
                Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, msg)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Stalls<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Stalls<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        this.watch(cx, polled)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        this.watch(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_flush(cx);
        this.watch(cx, polled)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Turns a served command's output into frames and sends them: whole if the
/// command finishes within one chunk, else through a [`Pipe`] while it runs.
pub struct FrameWriter {
    limits: Limits,
    /// Where the answer's body goes once it is known; taken when sent.
    answer: Option<oneshot::Sender<ResponseBody>>,
    budget: Option<OwnedSemaphorePermit>,
    /// The server's lane of streamed answers, and this answer's place in it.
    lane: Option<Arc<Semaphore>>,
    in_lane: Option<OwnedSemaphorePermit>,
    /// Set once the answer streams.
    pipe: Option<Arc<Pipe>>,
    /// When the answer started streaming, and the bytes of frames pushed since.
    streaming: Option<(Instant, u64)>,
    /// Output not framed yet, all of it for `target`.
    raw: Vec<u8>,
    /// `None`: stdout; else the output file (as named on the command line).
    target: Option<String>,
    /// `target` is a file without a frame yet: even an empty file gets one.
    announce: bool,
    /// Frames not handed on yet; until the answer streams, all of them.
    frames: Vec<u8>,
    /// Why the client cannot be reached any more; writes fail from then on.
    broken: Option<(io::ErrorKind, String)>,
    /// The answer needed the streaming lane, which was full: the server answers busy instead.
    refused: bool,
    /// Sent whole however large (a known answer, bounded by its caller).
    whole: bool,
    finished: bool,
    bytes: u64,
    held: Option<Held>,
    /// The cursor frame of an event listing, sent before the exit frame.
    cursor: Option<i64>,
    /// The client reads cursor frames (it asked for them).
    send_cursor: bool,
}

/// Output held back while the command runs, in the order written, until it
/// outgrows `limit` (then it streams).
struct Held {
    limit: usize,
    size: usize,
    /// (target, bytes): `None` is stdout, else an output file.
    parts: Vec<(Option<String>, Vec<u8>)>,
}

/// What a finished answer amounted to.
#[derive(Debug)]
pub struct Sent {
    /// Output bytes (stdout and files).
    pub bytes: u64,
    /// The answer was sent while the command ran, not whole.
    pub streamed: bool,
    /// The most bytes of frames queued for the client at once.
    pub peak: usize,
    /// The whole answer, still to send: it was held (see [`FrameWriter::hold`]).
    pub held: Option<ExecResponse>,
}

/// Bytes at the end of `b` that begin a UTF-8 character still missing its last bytes.
fn unfinished_char(b: &[u8]) -> usize {
    for back in 1..=b.len().min(3) {
        let byte = b[b.len() - back];
        if byte & 0b1100_0000 != 0b1000_0000 {
            let len = match byte {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => 1,
            };
            return if len > back { back } else { 0 };
        }
    }
    0
}

fn lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// The latest a push may complete: within `send_timeout` of `now`, and in
/// time for the client to have taken `pushed` bytes at `min_rate` since
/// `started`, after `grace`. Also says which limit it is.
fn push_deadline(limits: &Limits, started: Instant, pushed: u64, now: Instant) -> (Instant, bool) {
    let stall = now + limits.send_timeout;
    let rate = started + limits.grace + Duration::from_secs_f64(pushed as f64 / limits.min_rate.max(1) as f64);
    if rate < stall { (rate.max(now), true) } else { (stall, false) }
}

impl FrameWriter {
    /// A writer whose answer body goes to `answer`, carrying `budget` until
    /// hyper drops it; an answer that streams first takes a permit of `lane`.
    pub fn new(
        answer: oneshot::Sender<ResponseBody>,
        limits: Limits,
        budget: Option<OwnedSemaphorePermit>,
        lane: Option<Arc<Semaphore>>,
    ) -> FrameWriter {
        FrameWriter {
            limits,
            answer: Some(answer),
            budget,
            lane,
            in_lane: None,
            pipe: None,
            streaming: None,
            raw: Vec::new(),
            target: None,
            announce: false,
            frames: Vec::new(),
            broken: None,
            refused: false,
            whole: false,
            finished: false,
            bytes: 0,
            held: None,
            cursor: None,
            send_cursor: false,
        }
    }

    /// Send the cursor frame of an event listing: the client asked for it
    /// ([`crate::protocol::ExecRequest::cursor`]); others may not know it.
    pub fn send_cursor(&mut self) {
        self.send_cursor = true;
    }

    /// Hold the output back while the command runs, up to `limit` bytes, so
    /// that [`FrameWriter::finish`] returns the whole answer to be stored
    /// before [`FrameWriter::respond`] sends it (a write's answer, replayed to
    /// retries). Output beyond `limit` streams, and is not kept. A held answer
    /// is never refused for want of a place in the streaming lane: by then
    /// the write may have taken effect.
    pub fn hold(&mut self, limit: usize) {
        self.held = Some(Held { limit, size: 0, parts: Vec::new() });
        self.lane = None;
    }

    /// The streaming lane was full, so this answer was not sent: the server
    /// answers busy instead, and the client tries again.
    pub fn refused(&self) -> bool {
        self.refused
    }

    /// Send an answer known in advance, whole: an early failure, a replay, or
    /// a held answer, all of a bounded size.
    pub fn respond(&mut self, r: &ExecResponse) -> Sent {
        self.whole = true;
        self.cursor = r.cursor;
        let _ = self.write(None, r.stdout.as_bytes());
        for (path, data) in &r.files {
            let _ = self.write(Some(path), data.as_bytes());
        }
        self.finish(Exit { exit_code: r.exit_code, stderr: r.stderr.clone(), replayed: r.replayed })
    }

    /// The command finished: send the rest of its output, then `exit`; or,
    /// for a held answer, return it whole without sending anything.
    pub fn finish(&mut self, exit: Exit) -> Sent {
        if let Some(held) = self.held.take() {
            let mut answer = ExecResponse {
                exit_code: exit.exit_code,
                stderr: exit.stderr,
                replayed: exit.replayed,
                cursor: self.cursor,
                ..Default::default()
            };
            for (target, data) in held.parts {
                match target {
                    None => answer.stdout.push_str(&lossy(data)),
                    Some(path) => answer.files.entry(path).or_default().push_str(&lossy(data)),
                }
            }
            // `respond` counts the output again as it sends it.
            let bytes = std::mem::take(&mut self.bytes);
            return Sent { bytes, streamed: false, peak: 0, held: Some(answer) };
        }
        if !self.finished {
            self.finished = true;
            let sent = self.frame(true).and_then(|()| {
                let cursor = self.cursor.filter(|_| self.send_cursor).map(Frame::Cursor);
                for frame in cursor.iter().chain([&Frame::Exit(exit)]) {
                    serde_json::to_writer(&mut self.frames, frame).map_err(io::Error::other)?;
                    self.frames.push(b'\n');
                }
                if self.pipe.is_some() {
                    return self.send();
                }
                let body = ResponseBody {
                    kind: Kind::Whole(Some(Bytes::from(std::mem::take(&mut self.frames)))),
                    _budget: self.budget.take(),
                };
                if let Some(answer) = self.answer.take() {
                    let _ = answer.send(body);
                }
                Ok(())
            });
            if let Some(pipe) = &self.pipe {
                pipe.end(sent.is_ok());
            }
            self.in_lane = None;
        }
        Sent {
            bytes: self.bytes,
            streamed: self.pipe.is_some(),
            peak: self.pipe.as_ref().map_or(0, |p| p.peak()),
            held: None,
        }
    }

    fn check(&self) -> io::Result<()> {
        match &self.broken {
            Some((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
            None => Ok(()),
        }
    }

    fn fail(&mut self, e: io::Error) -> io::Error {
        self.broken = Some((e.kind(), e.to_string()));
        e
    }

    fn write(&mut self, file: Option<&str>, data: &[u8]) -> io::Result<()> {
        self.bytes += data.len() as u64;
        if let Some(held) = &mut self.held {
            if held.size + data.len() <= held.limit {
                held.size += data.len();
                match held.parts.last_mut() {
                    Some((target, part)) if target.as_deref() == file => part.extend_from_slice(data),
                    _ => held.parts.push((file.map(str::to_string), data.to_vec())),
                }
                return Ok(());
            }
            // Too large to keep: it streams, starting with what was held.
            let held = self.held.take().map(|h| h.parts).unwrap_or_default();
            for (target, part) in held {
                self.put(target.as_deref(), &part)?;
            }
        }
        self.put(file, data)
    }

    fn put(&mut self, file: Option<&str>, mut data: &[u8]) -> io::Result<()> {
        self.check()?;
        if self.target.as_deref() != file {
            self.frame(true)?;
            self.target = file.map(str::to_string);
            self.announce = file.is_some();
        }
        while !data.is_empty() {
            let room = self.limits.chunk.saturating_sub(self.raw.len()).max(1);
            let (now, rest) = data.split_at(room.min(data.len()));
            self.raw.extend_from_slice(now);
            data = rest;
            if self.raw.len() >= self.limits.chunk {
                self.frame(false)?;
            }
        }
        Ok(())
    }

    /// Frame the output in `raw`: all of it if `last`, else up to an unfinished character.
    fn frame(&mut self, last: bool) -> io::Result<()> {
        let cut = self.raw.len() - if last { 0 } else { unfinished_char(&self.raw) };
        if cut == 0 && !self.announce {
            return Ok(());
        }
        {
            let text = String::from_utf8_lossy(&self.raw[..cut]);
            let frame = match &self.target {
                None => Frame::Stdout(text),
                Some(path) => Frame::File { path: Cow::Borrowed(path), data: text },
            };
            serde_json::to_writer(&mut self.frames, &frame).map_err(io::Error::other)?;
            self.frames.push(b'\n');
        }
        self.raw.drain(..cut);
        self.announce = false;
        if self.frames.len() >= self.limits.chunk && !self.whole { self.send() } else { Ok(()) }
    }

    /// Hand the frames so far to the client, starting a streamed answer if needed.
    fn send(&mut self) -> io::Result<()> {
        self.check()?;
        if self.frames.is_empty() {
            return Ok(());
        }
        let pipe = match &self.pipe {
            Some(pipe) => pipe.clone(),
            None => {
                // Slow clients may hold only the lane's few slots, never all of the commands'.
                if let Some(lane) = &self.lane {
                    match lane.clone().try_acquire_owned() {
                        Ok(permit) => self.in_lane = Some(permit),
                        Err(_) => {
                            self.refused = true;
                            self.answer = None;
                            let e = io::Error::other("the server is busy sending other large answers");
                            return Err(self.fail(e));
                        }
                    }
                }
                let pipe = Pipe::new(self.limits.capacity);
                self.pipe = Some(pipe.clone());
                let body = ResponseBody { kind: Kind::Stream(pipe.clone()), _budget: self.budget.take() };
                if !self.answer.take().is_some_and(|a| a.send(body).is_ok()) {
                    return Err(self.fail(io::Error::new(io::ErrorKind::BrokenPipe, "the client went away")));
                }
                pipe
            }
        };
        let frames = std::mem::replace(&mut self.frames, Vec::with_capacity(self.limits.chunk + self.limits.chunk / 4));
        let now = Instant::now();
        let (started, pushed) = self.streaming.get_or_insert((now, 0));
        *pushed += frames.len() as u64;
        let (deadline, by_rate) = push_deadline(&self.limits, *started, *pushed, now);
        match pipe.push(Bytes::from(frames), deadline) {
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                let msg = if by_rate {
                    format!("the client took its answer slower than {} KiB/s", self.limits.min_rate >> 10)
                } else {
                    format!("the client took no output for {}s", self.limits.send_timeout.as_secs())
                };
                Err(self.fail(io::Error::new(io::ErrorKind::TimedOut, msg)))
            }
            pushed => pushed.map_err(|e| self.fail(e)),
        }
    }
}

impl Sink for FrameWriter {
    fn stdout(&mut self, data: &[u8]) -> io::Result<()> {
        self.write(None, data)
    }

    fn file(&mut self, path: &str, data: &[u8]) -> io::Result<()> {
        self.write(Some(path), data)
    }

    fn cursor(&mut self, seq: i64) {
        self.cursor = Some(seq);
    }
}

impl Drop for FrameWriter {
    fn drop(&mut self) {
        // A writer dropped unfinished (a panic) ends a streamed answer in an
        // error; an answer not started yet is never sent, which the server
        // reports as a failure.
        if !self.finished {
            if let Some(pipe) = &self.pipe {
                pipe.end(false);
            }
        }
    }
}

/// The longest frame a client accepts: frames carry at most a chunk of output, escaped.
const MAX_FRAME: usize = 16 << 20;

/// Why reading an answer stopped before its exit frame.
#[derive(Debug)]
pub enum Cut {
    /// Nothing arrived for this long.
    Stalled(Duration),
    /// The connection failed, or the answer ended early.
    Broken(String),
    /// Not a frame of this protocol.
    Malformed(String),
}

impl std::fmt::Display for Cut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cut::Stalled(idle) => write!(f, "the server sent nothing for {}s", idle.as_secs()),
            Cut::Broken(why) | Cut::Malformed(why) => f.write_str(why),
        }
    }
}

/// The frames of an answer, parsed on a reader thread.
pub struct FrameReader {
    frames: Receiver<Result<Frame<'static>, Cut>>,
    idle: Duration,
}

impl FrameReader {
    /// Read the frames of `body` on a new thread; [`FrameReader::next`] waits
    /// up to `idle` for each.
    pub fn spawn(body: impl Read + Send + 'static, idle: Duration) -> io::Result<FrameReader> {
        // A few frames ahead: the reader thread waits while the caller writes them out.
        let (tx, rx) = sync_channel(4);
        std::thread::Builder::new().name("bd-answer".into()).spawn(move || {
            let mut body = BufReader::with_capacity(64 << 10, body);
            let mut line = Vec::new();
            loop {
                line.clear();
                let frame = match (&mut body).take(MAX_FRAME as u64 + 1).read_until(b'\n', &mut line) {
                    Ok(0) => return,
                    Ok(_) if line.last() != Some(&b'\n') && line.len() > MAX_FRAME => {
                        Err(Cut::Malformed(format!("a frame longer than {} MiB", MAX_FRAME >> 20)))
                    }
                    Ok(_) if line.last() != Some(&b'\n') => Err(Cut::Broken("the answer ended within a frame".into())),
                    Ok(_) if line.iter().all(u8::is_ascii_whitespace) => continue,
                    Ok(_) => match serde_json::from_slice::<Frame<'static>>(&line) {
                        Ok(frame) => Ok(frame),
                        // A frame added since: optional, so skipped.
                        Err(_) if unknown_frame_type(&line) => continue,
                        Err(e) => Err(Cut::Malformed(format!("not a bd frame ({e})"))),
                    },
                    Err(e) => Err(Cut::Broken(format!("reading the answer: {e}"))),
                };
                let last = frame.is_err();
                if tx.send(frame).is_err() || last {
                    return;
                }
            }
        })?;
        Ok(FrameReader { frames: rx, idle })
    }

    /// The next frame, or `None` at the end of the answer.
    pub fn next(&self) -> Result<Option<Frame<'static>>, Cut> {
        match self.frames.recv_timeout(self.idle) {
            Ok(frame) => frame.map(Some),
            Err(RecvTimeoutError::Timeout) => Err(Cut::Stalled(self.idle)),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}

/// Whether `line` is a frame of a type this version does not know: an
/// object with one member, not named after a known type.
fn unknown_frame_type(line: &[u8]) -> bool {
    match serde_json::from_slice::<BTreeMap<String, serde::de::IgnoredAny>>(line) {
        Ok(frame) => frame.len() == 1 && frame.keys().all(|tag| !Frame::TYPES.contains(&tag.as_str())),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use http_body_util::BodyExt;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    fn limits(chunk: usize, capacity: usize) -> Limits {
        Limits { chunk, capacity, send_timeout: Duration::from_secs(30), min_rate: 1, grace: Duration::from_secs(30) }
    }

    fn writer(limits: Limits) -> (FrameWriter, oneshot::Receiver<ResponseBody>) {
        let (answer, answered) = oneshot::channel();
        (FrameWriter::new(answer, limits, None, None), answered)
    }

    /// The frames of a whole answer body, gathered as the client would.
    fn gather(body: &[u8]) -> ExecResponse {
        let mut r = ExecResponse::default();
        let mut exited = false;
        for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            assert!(!exited, "the exit frame comes last");
            match serde_json::from_slice::<Frame<'static>>(line).unwrap() {
                Frame::Stdout(text) => r.stdout.push_str(&text),
                Frame::File { path, data } => r.files.entry(path.into_owned()).or_default().push_str(&data),
                Frame::Cursor(seq) => r.cursor = Some(seq),
                Frame::Exit(exit) => {
                    (r.exit_code, r.stderr, r.replayed) = (exit.exit_code, exit.stderr, exit.replayed);
                    exited = true;
                }
            }
        }
        assert!(exited, "no exit frame");
        r
    }

    async fn read_all(mut body: ResponseBody) -> std::result::Result<Vec<u8>, (Vec<u8>, io::Error)> {
        let mut got = Vec::new();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(f) => got.extend_from_slice(f.data_ref().expect("data frames only")),
                Err(e) => return Err((got, e)),
            }
        }
        Ok(got)
    }

    #[test]
    fn small_answers_are_sent_whole() {
        let (mut w, answered) = writer(Limits::SERVE);
        w.stdout(b"t-1  Design\n").unwrap();
        w.file("snap.jsonl", b"").unwrap();
        w.file("snap.jsonl", b"{\"_type\":\"header\"}\n").unwrap();
        w.file("empty.jsonl", b"").unwrap();
        w.stdout("✓ done\n".as_bytes()).unwrap();
        let sent = w.finish(Exit { exit_code: 3, stderr: "error: x\n".into(), replayed: false });
        assert!(!sent.streamed);
        assert_eq!(sent.bytes, 12 + 19 + 9);
        let body = answered.blocking_recv().unwrap();
        assert_eq!(body.size_hint().exact(), Some(body.size_hint().lower()), "sent with a Content-Length");
        let bytes = runtime().block_on(read_all(body)).unwrap();
        let r = gather(&bytes);
        assert_eq!(r.stdout, "t-1  Design\n✓ done\n");
        assert_eq!(r.files.get("snap.jsonl").map(String::as_str), Some("{\"_type\":\"header\"}\n"));
        assert_eq!(r.files.get("empty.jsonl").map(String::as_str), Some(""), "an empty file still has a frame");
        assert_eq!((r.exit_code, r.stderr.as_str()), (3, "error: x\n"));
    }

    #[test]
    fn event_listings_end_with_their_cursor() {
        let (mut w, answered) = writer(Limits::SERVE);
        w.send_cursor();
        w.stdout(b"#5 created t-1\n").unwrap();
        w.cursor(5);
        w.cursor(9);
        w.finish(Exit::default());
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text.lines().nth(1), Some("{\"cursor\":9}"), "the last one, before the exit frame: {text}");
        assert_eq!(gather(text.as_bytes()).cursor, Some(9));

        // Known answers carry theirs; other answers have none.
        let (mut w, answered) = writer(Limits::SERVE);
        w.send_cursor();
        w.respond(&ExecResponse { cursor: Some(3), ..Default::default() });
        assert_eq!(gather(&runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap()).cursor, Some(3));
        let (mut w, answered) = writer(Limits::SERVE);
        w.stdout(b"t-1\n").unwrap();
        w.finish(Exit::default());
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("cursor"));
    }

    #[test]
    fn only_clients_that_ask_get_cursor_frames() {
        // A client from before cursor frames: its frames are these (externally tagged, no catch-all).
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum OldFrame {
            Stdout(String),
            File { path: String, data: String },
            Exit(Exit),
        }
        let (mut w, answered) = writer(Limits::SERVE);
        w.stdout(b"#5 created t-1\n").unwrap();
        w.cursor(5);
        w.finish(Exit::default());
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        let frames: Vec<OldFrame> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(l))))
            .collect();
        assert!(matches!(frames[..], [OldFrame::Stdout(_), OldFrame::Exit(_)]));
        assert!(serde_json::from_str::<OldFrame>("{\"cursor\":5}").is_err(), "old clients fail on cursor frames");
    }

    #[test]
    fn characters_are_never_split_between_frames() {
        assert_eq!(unfinished_char(b"ab"), 0);
        assert_eq!(unfinished_char("é".as_bytes()), 0);
        assert_eq!(unfinished_char(&"é".as_bytes()[..1]), 1);
        assert_eq!(unfinished_char(&"日".as_bytes()[..2]), 2);
        assert_eq!(unfinished_char(&"😀".as_bytes()[..3]), 3);
        assert_eq!(unfinished_char(b"a\xff"), 0, "invalid, not unfinished");

        // Tiny chunks, and writes that cut characters in half.
        let text = "Ünïcödé 日本語 😀 plain ascii\n".repeat(40);
        let (mut w, answered) = writer(limits(7, 1 << 20));
        for piece in text.as_bytes().chunks(5) {
            w.stdout(piece).unwrap();
        }
        let sent = w.finish(Exit::default());
        assert!(sent.streamed, "more than a chunk");
        let body = answered.blocking_recv().unwrap();
        let bytes = runtime().block_on(read_all(body)).unwrap();
        assert_eq!(gather(&bytes).stdout, text, "no replacement characters");
    }

    #[test]
    fn large_answers_stream_through_a_bounded_pipe() {
        let (chunk, capacity) = (1024, 4096);
        let text: String = (0..3000).map(|i| format!("line {i}: {}\n", "é".repeat(i % 50))).collect();
        let (mut w, answered) = writer(limits(chunk, capacity));
        let expected = text.clone();
        let producer = std::thread::spawn(move || {
            for piece in text.as_bytes().chunks(333) {
                w.stdout(piece).unwrap();
            }
            w.finish(Exit { exit_code: 4, ..Default::default() })
        });
        let body = answered.blocking_recv().expect("the answer starts before the command ends");
        // The client is slow: the command fills the pipe, then waits for it.
        let Kind::Stream(pipe) = &body.kind else { panic!("a streamed answer") };
        let deadline = Instant::now() + Duration::from_secs(60);
        while pipe.peak() < capacity / 2 {
            assert!(Instant::now() < deadline, "the pipe never filled up");
            std::thread::sleep(Duration::from_millis(1));
        }
        let bytes = runtime().block_on(read_all(body)).unwrap();
        let sent = producer.join().unwrap();
        let r = gather(&bytes);
        assert_eq!((r.stdout.as_str(), r.exit_code), (expected.as_str(), 4));
        assert!(sent.streamed && sent.bytes == expected.len() as u64);
        let largest_frame = bytes.split(|b| *b == b'\n').map(<[u8]>::len).max().unwrap();
        assert!(sent.peak <= capacity + largest_frame, "peak {} for a pipe of {capacity}", sent.peak);
        assert!(bytes.len() > 20 * capacity, "far more output than the pipe holds");
    }

    #[test]
    fn a_client_that_goes_away_fails_the_writes_at_once() {
        let (mut w, answered) = writer(limits(16, 64));
        w.stdout(&[b'x'; 16]).unwrap();
        let body = answered.blocking_recv().expect("a full chunk starts the answer");
        drop(body);
        let started = Instant::now();
        let mut failed = None;
        for _ in 0..100 {
            if let Err(e) = w.stdout(&[b'y'; 100]) {
                failed = Some(e);
                break;
            }
        }
        let e = failed.expect("writes fail once the answer is gone");
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
        assert!(w.stdout(b"z").is_err(), "and keep failing");
        assert!(started.elapsed() < Duration::from_secs(10), "without waiting for the send timeout");
        assert!(w.finish(Exit::default()).streamed);
    }

    #[test]
    fn a_client_that_stops_reading_times_out_the_writer() {
        let (mut w, answered) = writer(Limits { send_timeout: Duration::from_millis(100), ..limits(16, 64) });
        w.stdout(&[b'x'; 40]).unwrap();
        let _body = answered.blocking_recv().unwrap();
        let e = (0..100).find_map(|_| w.stdout(&[b'y'; 40]).err()).expect("a full pipe times out");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(e.to_string().contains("took no output"), "{e}");
    }

    #[test]
    fn an_unfinished_writer_ends_its_answer_in_an_error() {
        let (mut w, answered) = writer(limits(16, 1 << 20));
        w.stdout(&[b'x'; 100]).unwrap();
        let body = answered.blocking_recv().unwrap();
        drop(w);
        let (got, e) = runtime().block_on(read_all(body)).unwrap_err();
        assert!(!got.is_empty(), "the frames sent before");
        assert!(e.to_string().contains("stopped before finishing"), "{e}");

        // Never started: no answer at all, which the server reports itself.
        let (w, answered) = writer(Limits::SERVE);
        drop(w);
        assert!(answered.blocking_recv().is_err());
    }

    #[test]
    fn held_answers_are_sent_only_when_asked_to() {
        let (mut w, mut answered) = writer(Limits::SERVE);
        w.hold(10);
        w.stdout(b"t-1\n").unwrap();
        let sent = w.finish(Exit { exit_code: 0, stderr: "warn\n".into(), replayed: false });
        let held = sent.held.expect("held whole");
        assert_eq!((held.stdout.as_str(), held.stderr.as_str(), sent.bytes), ("t-1\n", "warn\n", 4));
        assert!(answered.try_recv().is_err(), "nothing sent yet: the server stores it first");
        let sent = w.respond(&held);
        assert!(sent.held.is_none() && sent.bytes == 4);
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        assert_eq!(gather(&bytes), held);

        // A known answer goes whole, with a Content-Length, however many chunks it spans.
        let (mut w, answered) = writer(limits(16, 64));
        let big = ExecResponse { stdout: "x".repeat(1000), ..Default::default() };
        assert!(!w.respond(&big).streamed);
        let body = answered.blocking_recv().unwrap();
        assert!(body.size_hint().exact().is_some());
        assert_eq!(gather(&runtime().block_on(read_all(body)).unwrap()), big);

        // Too large to hold: sent like any other answer, and not kept.
        let (mut w, answered) = writer(Limits::SERVE);
        w.hold(10);
        w.stdout(b"0123456789abc").unwrap();
        let sent = w.finish(Exit::default());
        assert!(sent.held.is_none());
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        assert_eq!(gather(&bytes).stdout, "0123456789abc");

        // Outgrowing the limit while streaming keeps the order of what was held.
        let (mut w, answered) = writer(limits(16, 1 << 20));
        w.hold(40);
        w.stdout(&[b'a'; 20]).unwrap();
        w.file("f.jsonl", &[b'b'; 10]).unwrap();
        w.stdout(&[b'c'; 15]).unwrap();
        assert!(w.finish(Exit::default()).streamed);
        let bytes = runtime().block_on(read_all(answered.blocking_recv().unwrap())).unwrap();
        let targets: Vec<&str> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| match serde_json::from_slice::<Frame<'static>>(l).unwrap() {
                Frame::Stdout(_) => "stdout",
                Frame::File { .. } => "file",
                Frame::Cursor(_) => "cursor",
                Frame::Exit(_) => "exit",
            })
            .collect();
        assert_eq!(targets, ["stdout", "stdout", "file", "stdout", "exit"]);
        let r = gather(&bytes);
        assert_eq!(r.stdout, format!("{}{}", "a".repeat(20), "c".repeat(15)));
        assert_eq!(r.files["f.jsonl"], "b".repeat(10));
    }

    #[test]
    fn the_streaming_lane_refuses_answers_beyond_its_size() {
        let lane = Arc::new(Semaphore::new(1));
        let streamer = |lane: &Arc<Semaphore>| {
            let (answer, answered) = oneshot::channel();
            (FrameWriter::new(answer, limits(16, 1 << 20), None, Some(lane.clone())), answered)
        };
        let (mut first, first_answer) = streamer(&lane);
        first.stdout(&[b'x'; 100]).unwrap();
        let _body = first_answer.blocking_recv().expect("the first streams");

        let (mut second, second_answer) = streamer(&lane);
        let e = second.stdout(&[b'y'; 100]).unwrap_err();
        assert!(e.to_string().contains("busy"), "{e}");
        assert!(second.refused() && second_answer.blocking_recv().is_err(), "the server answers busy instead");
        assert!(!second.finish(Exit::default()).streamed);

        // A write's answer is never refused: the write may have taken effect.
        let (mut write, write_answer) = streamer(&lane);
        write.hold(10);
        write.stdout(&[b'w'; 100]).unwrap();
        assert!(!write.refused() && write_answer.blocking_recv().is_ok(), "streamed outside the lane");

        first.finish(Exit::default());
        let (mut third, third_answer) = streamer(&lane);
        third.stdout(&[b'z'; 100]).unwrap();
        assert!(third_answer.blocking_recv().is_ok(), "the lane's place was given back");
    }

    #[test]
    fn clients_must_keep_up_a_minimum_rate() {
        let l = Limits { min_rate: 1000, grace: Duration::from_secs(1), ..limits(16, 64) };
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        assert_eq!(push_deadline(&l, t0, 0, t0), (t0 + ms(1000), true), "the grace period");
        assert_eq!(push_deadline(&l, t0, 500, t0 + ms(200)), (t0 + ms(1500), true), "500 bytes at 1000 B/s");
        assert_eq!(push_deadline(&l, t0, 100, t0 + ms(5000)), (t0 + ms(5000), true), "behind: no waiting");
        let ahead = push_deadline(&l, t0, 10 << 20, t0 + ms(1000));
        assert_eq!(ahead, (t0 + ms(1000) + l.send_timeout, false), "ahead: a pause is still bounded");

        // A client taking about 300 B/s of an answer due at 2000 B/s.
        let (mut w, answered) = writer(Limits { min_rate: 2000, grace: Duration::ZERO, ..limits(16, 64) });
        w.stdout(&[b'x'; 16]).unwrap();
        let mut body = answered.blocking_recv().unwrap();
        let reader = std::thread::spawn(move || {
            runtime().block_on(async {
                while let Some(Ok(_)) = body.frame().await {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        });
        let e = (0..1000).find_map(|_| w.stdout(&[b'y'; 16]).err()).expect("the slow client is cut off");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(e.to_string().contains("slower than"), "{e}");
        drop(w);
        reader.join().unwrap();
    }

    async fn write_to<T: AsyncWrite + Unpin>(s: &mut T, data: &[u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| Pin::new(&mut *s).poll_write(cx, data)).await
    }

    async fn read_from<T: AsyncRead + Unpin>(s: &mut T, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| {
            let mut read = ReadBuf::new(&mut *buf);
            Pin::new(&mut *s).poll_read(cx, &mut read).map_ok(|()| read.filled().len())
        })
        .await
    }

    /// Both ends of a loopback connection.
    async fn connected() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let near = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        (near, listener.accept().await.unwrap().0)
    }

    #[test]
    fn stalled_connections_fail_their_writes() {
        runtime().block_on(async {
            let (near, _far) = connected().await;
            let mut stalled = Stalls::new(near, Duration::from_millis(200));
            let chunk = [b'x'; 64 << 10];
            let e = tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    if let Err(e) = write_to(&mut stalled, &chunk).await {
                        return e;
                    }
                }
            })
            .await
            .expect("writes fail once the socket stays full");
            assert_eq!(e.kind(), io::ErrorKind::TimedOut, "nobody reads: {e}");

            // A client that keeps reading, however slowly, is not cut off.
            let (near, mut far) = connected().await;
            let mut slow = Stalls::new(near, Duration::from_secs(5));
            let reader = tokio::spawn(async move {
                let (mut buf, mut total) = ([0u8; 4096], 0);
                loop {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    match read_from(&mut far, &mut buf).await {
                        Ok(0) | Err(_) => return total,
                        Ok(n) => total += n,
                    }
                }
            });
            let mut data: &[u8] = &[b'z'; 1 << 20];
            let sent = data.len();
            while !data.is_empty() {
                let n = write_to(&mut slow, data).await.unwrap();
                data = &data[n..];
            }
            drop(slow);
            assert_eq!(reader.await.unwrap(), sent);
        });
    }

    /// A body that blocks until `release` is dropped, then ends.
    struct Stuck(mpsc::Receiver<()>);

    impl Read for Stuck {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn frame_reader_parses_frames_and_reports_cuts() {
        let idle = Duration::from_secs(30);
        let body = "\n{\"stdout\":\"a\"}\n \n{\"exit\":{\"exit_code\":2}}\n";
        let r = FrameReader::spawn(io::Cursor::new(body), idle).unwrap();
        assert_eq!(r.next().unwrap(), Some(Frame::Stdout("a".into())), "blank lines are keep-alives");
        assert_eq!(r.next().unwrap(), Some(Frame::Exit(Exit { exit_code: 2, ..Default::default() })));
        assert_eq!(r.next().unwrap(), None);

        let r = FrameReader::spawn(io::Cursor::new("{\"stdout\":\"a\"}\n{\"std"), idle).unwrap();
        assert!(r.next().unwrap().is_some());
        assert!(matches!(r.next(), Err(Cut::Broken(_))), "cut within a frame");

        let r = FrameReader::spawn(io::Cursor::new("{\"exit_code\":0,\"stdout\":\"\"}\n"), idle).unwrap();
        assert!(matches!(r.next(), Err(Cut::Malformed(_))), "a protocol 1 answer is not a frame");

        // Frames of types added later are skipped; known types must be well-formed.
        let body = "{\"progress\":{\"done\":3}}\n{\"stdout\":\"a\"}\n{\"later\":[1]}\n{\"exit\":{\"exit_code\":0}}\n";
        let r = FrameReader::spawn(io::Cursor::new(body), idle).unwrap();
        assert_eq!(r.next().unwrap(), Some(Frame::Stdout("a".into())));
        assert_eq!(r.next().unwrap(), Some(Frame::Exit(Exit::default())));
        for bad in ["{\"cursor\":\"x\"}\n", "{\"stdout\":1}\n", "{\"a\":1,\"b\":2}\n", "[\"stdout\"]\n", "{}\n"] {
            let r = FrameReader::spawn(io::Cursor::new(bad), idle).unwrap();
            assert!(matches!(r.next(), Err(Cut::Malformed(_))), "{bad}");
        }

        let (release, stuck) = mpsc::channel();
        let r = FrameReader::spawn(Stuck(stuck), Duration::from_millis(50)).unwrap();
        assert!(matches!(r.next(), Err(Cut::Stalled(_))));
        drop(release);
    }
}
