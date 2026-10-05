//! Streamed answers of `bd serve`, read on the client: a [`FrameReader`]
//! parses an answer on its own thread, so that a stalled connection is given
//! up after an idle timeout instead of a deadline on the whole answer, which
//! a large export could not meet. The server's side, which cuts a command's
//! output into frames with bounded memory, is `bd-server`'s `stream`.

use std::io::{self, BufRead, BufReader, Read};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::Duration;

use crate::protocol::Frame;

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
                    Ok(_) => serde_json::from_slice::<Frame<'static>>(&line)
                        .map_err(|e| Cut::Malformed(format!("not a bd frame ({e})"))),
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::protocol::Exit;

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

        // Unknown frame types and ill-formed frames are not bd frames.
        for bad in [
            "{\"exit_code\":0,\"stdout\":\"\"}\n",
            "{\"progress\":{\"done\":3}}\n",
            "{\"cursor\":\"x\"}\n",
            "{\"stdout\":1}\n",
            "[\"stdout\"]\n",
            "{}\n",
        ] {
            let r = FrameReader::spawn(io::Cursor::new(bad), idle).unwrap();
            assert!(matches!(r.next(), Err(Cut::Malformed(_))), "{bad}");
        }

        let (release, stuck) = mpsc::channel();
        let r = FrameReader::spawn(Stuck(stuck), Duration::from_millis(50)).unwrap();
        assert!(matches!(r.next(), Err(Cut::Stalled(_))));
        drop(release);
    }
}
