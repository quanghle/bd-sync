//! `<root>/approval-links.key`: the key `bd serve` seals the requests in its
//! operation approval links with (`bd_cli::approval_link`). 32 random bytes,
//! created at the first start (mode 0600 on Unix) and read at every later
//! one; never in `server.db` or its backups. Deleting it and restarting
//! invalidates every link made so far. Its bytes are never logged or shown.

use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use bd_cli::approval_link::LinkKey;
use bd_core::{Error, Result};
use ring::rand::{SecureRandom, SystemRandom};

/// The key file's name in the root.
pub(crate) const FILE: &str = "approval-links.key";

/// The key's length in bytes.
const LEN: usize = 32;

/// The path of the key file in `root`.
pub(crate) fn path(root: &Path) -> PathBuf {
    root.join(FILE)
}

/// The root's link key: read if the file exists, else created.
pub(crate) fn load_or_create(root: &Path) -> Result<LinkKey> {
    let path = path(root);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => return read(&path),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(&path, e)),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = match opts.open(&path) {
        Ok(f) => f,
        // Another process created it meanwhile: its key is the one.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return read(&path),
        Err(e) => return Err(io_error(&path, e)),
    };
    let mut bytes = [0u8; LEN];
    SystemRandom::new().fill(&mut bytes).map_err(|_| Error::invalid("no random bytes for the approval link key"))?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        // Never left half written, which the next start would refuse.
        let _ = std::fs::remove_file(&path);
        return Err(io_error(&path, e));
    }
    LinkKey::from_bytes(&bytes)
}

/// The key in the existing file `path`: a regular file of exactly 32 bytes.
fn read(path: &Path) -> Result<LinkKey> {
    let refused = |what: &str| {
        Error::invalid(format!(
            "{}: {what}; it must hold the {LEN}-byte approval link key. Delete it and restart bd serve to make a new \
             one (approval links made so far stop working)",
            path.display()
        ))
    };
    if !std::fs::symlink_metadata(path).map_err(|e| io_error(path, e))?.file_type().is_file() {
        return Err(refused("not a regular file"));
    }
    let file = std::fs::File::open(path).map_err(|e| io_error(path, e))?;
    if !file.metadata().map_err(|e| io_error(path, e))?.is_file() {
        return Err(refused("not a regular file"));
    }
    // One byte more than a key: a longer file is refused without reading it all.
    let mut bytes = Vec::with_capacity(LEN + 1);
    file.take(LEN as u64 + 1).read_to_end(&mut bytes).map_err(|e| io_error(path, e))?;
    if bytes.len() != LEN {
        return Err(refused(if bytes.len() > LEN { "longer than a key" } else { "shorter than a key" }));
    }
    LinkKey::from_bytes(&bytes)
}

fn io_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bd_cli::approval_link::{self, Op, Opened, OperationRequest};

    fn sealed(key: &LinkKey) -> String {
        let req = OperationRequest::new("proj".into(), Op::Close, "t-1".into(), "alice".into(), 1_000);
        approval_link::seal(key, &req).unwrap()
    }

    #[test]
    fn the_first_start_creates_the_key_and_later_ones_read_it() {
        let root = tempfile::tempdir().unwrap();
        let first = load_or_create(root.path()).unwrap();
        let bytes = std::fs::read(path(root.path())).unwrap();
        assert_eq!(bytes.len(), LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path(root.path())).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let token = sealed(&first);
        let second = load_or_create(root.path()).unwrap();
        assert_eq!(std::fs::read(path(root.path())).unwrap(), bytes, "never rewritten");
        assert!(matches!(approval_link::open(&second, &token, "proj", Op::Close, "t-1", 2_000), Opened::Valid(_)));
        let other = tempfile::tempdir().unwrap();
        let unrelated = load_or_create(other.path()).unwrap();
        assert!(matches!(approval_link::open(&unrelated, &token, "proj", Op::Close, "t-1", 2_000), Opened::Invalid));
    }

    #[test]
    fn a_file_of_another_length_is_refused_and_left_alone() {
        for len in [0, 31, 33, 64] {
            let root = tempfile::tempdir().unwrap();
            let bytes: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            std::fs::write(path(root.path()), &bytes).unwrap();
            let Err(e) = load_or_create(root.path()) else { panic!("{len} bytes accepted") };
            assert!(matches!(e, Error::Invalid(_)), "{len}: {e}");
            let msg = e.to_string();
            assert!(msg.contains(FILE) && msg.contains("Delete it and restart"), "{msg}");
            if len > 0 {
                assert!(!msg.contains(std::str::from_utf8(&bytes[..len.min(8)]).unwrap()), "bytes shown: {msg}");
            }
            assert_eq!(std::fs::read(path(root.path())).unwrap(), bytes, "{len}: changed");
        }
    }

    #[test]
    fn anything_but_a_regular_file_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(path(root.path())).unwrap();
        let e = load_or_create(root.path()).err().expect("a directory accepted");
        assert!(matches!(e, Error::Invalid(_)), "{e}");
        assert!(path(root.path()).is_dir());
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("elsewhere");
            std::fs::write(&target, [7u8; LEN]).unwrap();
            std::os::unix::fs::symlink(&target, path(root.path())).unwrap();
            let e = load_or_create(root.path()).err().expect("a symlink accepted");
            assert!(matches!(e, Error::Invalid(_)), "{e}");
        }
    }
}
