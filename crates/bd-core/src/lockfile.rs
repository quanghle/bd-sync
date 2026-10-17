//! OS file locks (`flock` on Unix, `LockFileEx` on Windows) that serialize
//! bd processes over files outside the database: the system releases one
//! when its process ends, so a command that crashed or was interrupted
//! leaves nothing to clean up. A checkout's agent assets
//! (`.bd/agents.lock.mutex`) and a workspace's published areas
//! (`.bd/publish.lock`) are kept this way.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// A file's OS lock, held: released when dropped, or when the process ends.
#[derive(Debug)]
pub struct FileLock(File);

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// Take the exclusive lock of the file `path` (created if missing), waiting
/// up to `wait` for its holder to release it; past that, [`Error::Locked`]
/// (exit 5) with the message `busy` gives.
pub fn exclusive(path: &Path, wait: Duration, busy: impl FnOnce() -> String) -> Result<FileLock> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| path_error(path, e))?;
    take(file, path, wait, true, busy)
}

/// Take `file`'s OS lock (`path` names it in errors), exclusive or shared,
/// waiting up to `wait` for its holder to release it; past that,
/// [`Error::Locked`] with the message `busy` gives.
pub fn take(
    file: File,
    path: &Path,
    wait: Duration,
    exclusive: bool,
    busy: impl FnOnce() -> String,
) -> Result<FileLock> {
    let deadline = Instant::now() + wait;
    let mut delay = Duration::from_millis(5);
    loop {
        let tried = if exclusive { file.try_lock() } else { file.try_lock_shared() };
        match tried {
            Ok(()) => return Ok(FileLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(path_error(path, e)),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Locked(busy()));
        }
        std::thread::sleep(delay.min(left));
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_makes_others_wait_then_fail_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let held = exclusive(&path, Duration::ZERO, || "busy".into()).unwrap();
        let e = exclusive(&path, Duration::from_millis(30), || "held elsewhere".into()).unwrap_err();
        assert_eq!((e.exit_code(), e.to_string().as_str()), (5, "held elsewhere"));
        drop(held);
        exclusive(&path, Duration::ZERO, || "busy".into()).unwrap();
    }
}
