//! Runs a command with input on its stdin, written from a thread while the command's output drains, so
//! neither side blocks on a full pipe.

use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

/// Runs `cmd` with `input` on its stdin and returns its output. Only stdin is piped here: stdout and stderr
/// stay as the caller configured them (`wait_with_output` collects those that are piped).
pub fn output_with_input(cmd: &mut Command, input: impl Into<Vec<u8>>) -> Output {
    let input = input.into();
    let mut child = cmd.stdin(Stdio::piped()).spawn().unwrap();
    // The closure owns the handle and drops it when the write ends, so the child sees end of input.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().unwrap();
    // Joining is bounded: once the child has exited, the read end of its stdin is closed and a blocked
    // write fails.
    match writer.join() {
        Ok(Ok(())) => out,
        // The child exited or stopped reading: the caller's assertions report that, with its stderr.
        Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => out,
        Ok(Err(e)) => {
            panic!("writing the command's stdin: {e} ({}): {}", out.status, String::from_utf8_lossy(&out.stderr))
        }
        Err(p) => std::panic::resume_unwind(p),
    }
}
