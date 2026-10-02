//! A pseudo-terminal for tests of interactive commands, on Linux.

use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// A command running with a pseudo-terminal as its stdin and stderr, and its stdout piped.
pub struct Terminal {
    master: File,
    output: Receiver<Vec<u8>>,
    /// What the terminal showed that [`Terminal::expect`] has not consumed yet.
    unread: String,
    /// Everything the terminal showed (`\r` removed).
    shown: String,
    child: Option<Child>,
}

impl Terminal {
    pub fn spawn(mut cmd: Command) -> Terminal {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = File::options().read(true).write(true).open(name.to_str().unwrap()).unwrap();
        cmd.stdin(slave.try_clone().unwrap()).stderr(slave).stdout(Stdio::piped());
        let child = cmd.spawn().unwrap();
        // It holds this process's copies of the terminal's end: once the child exits, reading the master ends.
        drop(cmd);
        let master = File::from(master);
        let mut reader = master.try_clone().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Terminal { master, output: rx, unread: String::new(), shown: String::new(), child: Some(child) }
    }

    fn receive(&mut self, wait: Duration) -> std::result::Result<(), RecvTimeoutError> {
        let bytes = self.output.recv_timeout(wait)?;
        let text = String::from_utf8_lossy(&bytes).replace('\r', "");
        self.shown.push_str(&text);
        self.unread.push_str(&text);
        Ok(())
    }

    /// Wait for the terminal to show `text`: returns what it showed up to
    /// and including it since the last call.
    pub fn expect(&mut self, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(i) = self.unread.find(text) {
                return self.unread.drain(..i + text.len()).collect();
            }
            match self.receive(deadline.saturating_duration_since(Instant::now())) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => {
                    panic!("no {text:?} on the terminal in time; it showed:\n{}", self.shown)
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the terminal closed before showing {text:?}; it showed:\n{}", self.shown)
                }
            }
        }
    }

    /// Type `line` and Enter.
    pub fn answer(&mut self, line: &str) {
        self.master.write_all(format!("{line}\n").as_bytes()).unwrap();
    }

    /// The child's process id.
    pub fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Wait for the command to end: its output, and everything the terminal
    /// showed. Fails rather than hangs: see [`Terminal::finish_within`].
    pub fn finish(self) -> (Output, String) {
        self.finish_within(Duration::from_secs(30))
    }

    /// Wait up to `wait` for the command to end, typing end-of-input
    /// (Ctrl-D) for any further read of the terminal, so a question left
    /// unanswered gets no answer. Past `wait`, kill it and panic with what
    /// the terminal showed.
    pub fn finish_within(mut self, wait: Duration) -> (Output, String) {
        let mut child = self.child.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let reading = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout.read_to_end(&mut out);
            out
        });
        let deadline = Instant::now() + wait;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                while self.receive(Duration::from_millis(100)).is_ok() {}
                panic!("still running after {wait:?}, so it was killed; the terminal showed:\n{}", self.shown);
            }
            // Ctrl-D at the start of a line: a read of the terminal gets end-of-input.
            let _ = self.master.write_all(b"\x04");
            let _ = self.receive(Duration::from_millis(50));
        };
        let stdout = reading.join().unwrap();
        while self.receive(Duration::from_secs(5)).is_ok() {}
        (Output { status, stdout, stderr: Vec::new() }, std::mem::take(&mut self.shown))
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // A test that failed midway: the child goes, and with it the
        // terminal's last open end, which ends the reading thread.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
