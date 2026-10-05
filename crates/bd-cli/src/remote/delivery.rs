//! Where the frames of an answer go: stdout, held or printed as it arrives,
//! and the output files a command writes.

use std::io::Write;
use std::path::{Path, PathBuf};

use bd_core::{Error, Result};

use crate::io;
use crate::protocol::{ExecResponse, Exit};

/// Where the frames of an answer go: stdout, and the output files the
/// command asked for. Files the server sends for any other path are ignored.
pub(super) struct Delivery {
    /// A command that may write: its output is held until it is complete,
    /// so a lost answer can always be asked for again (same request id).
    pub(super) write: bool,
    /// Keep stdout until the exit frame instead of printing it as it arrives.
    hold: bool,
    /// This attempt prints stdout as it arrives.
    printing: bool,
    /// Stdout of this attempt, when not printing it.
    held: String,
    /// Output reached the user, so the request cannot be tried again.
    pub(super) printed: bool,
    files: Vec<OutputFile>,
    /// The issue frame of this attempt.
    pub(super) issue: Option<String>,
    /// The cursor frame of this attempt.
    pub(super) cursor: Option<i64>,
    /// The server may hold the request a long time before answering (a long
    /// poll): its retry time starts at its first failure.
    pub(super) long_poll: bool,
    /// Escapes stdout printed as it arrives, across frames.
    screen: io::Escaper,
    /// bd serve refused the access token (HTTP 401): it may have expired.
    pub(super) token_refused: bool,
}

/// An output file, written to `<target>.tmp` and renamed into place once the command succeeds.
pub(super) struct OutputFile {
    /// The path as given on the command line, which names the file's frames.
    key: String,
    target: PathBuf,
    /// Create the target's directory first (`playbook extract -o`).
    mkdir: bool,
    /// This attempt's temporary file.
    temp: Option<(PathBuf, std::io::BufWriter<std::fs::File>)>,
}

impl Delivery {
    pub(super) fn new(files: Vec<OutputFile>, hold: bool, write: bool) -> Delivery {
        // A command writing files prints a summary: it waits until the files are in place.
        let hold = hold || write || !files.is_empty();
        Delivery {
            write,
            hold,
            printing: false,
            held: String::new(),
            printed: false,
            files,
            issue: None,
            cursor: None,
            long_poll: false,
            screen: io::Escaper::default(),
            token_refused: false,
        }
    }

    /// Everything kept in memory, for the client's own requests (reads).
    pub(super) fn collect() -> Delivery {
        Delivery::new(Vec::new(), true, false)
    }

    /// An attempt's answer starts; a `whole` one is short, so it is printed when complete.
    pub(super) fn start(&mut self, whole: bool) {
        self.discard();
        self.held.clear();
        self.issue = None;
        self.cursor = None;
        self.screen = io::Escaper::default();
        self.printing = !self.hold && !whole;
    }

    pub(super) fn stdout(&mut self, text: &str) -> Result<()> {
        if !self.printing {
            self.held.push_str(text);
            return Ok(());
        }
        self.printed = true;
        let mut screened = Vec::new();
        self.screen.feed(text.as_bytes(), &mut screened);
        Ok(io::with_stdout(|w| w.write_all(&screened))?)
    }

    pub(super) fn file(&mut self, path: &str, data: &str) -> Result<()> {
        match self.files.iter_mut().find(|f| f.key == path) {
            Some(f) => f.write(data.as_bytes()),
            None => Ok(()),
        }
    }

    /// The command finished: its files go into place if it succeeded.
    pub(super) fn exit(&mut self, exit: Exit) -> Result<ExecResponse> {
        if self.printing {
            let mut rest = Vec::new();
            self.screen.finish(&mut rest);
            io::with_stdout(|w| w.write_all(&rest))?;
        }
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
            issue: self.issue.take(),
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
    pub(super) fn new(key: &Path, target: PathBuf, mkdir: bool) -> OutputFile {
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
