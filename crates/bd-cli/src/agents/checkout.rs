//! A checkout that bd places agent assets in: the skill files it reads and
//! writes, never through a symlink at or below a skill's directory; its
//! lock file; and the mutex that serializes changes to both.
//!
//! The mutex is an OS file lock on `.bd/agents.lock.mutex` (`flock` on
//! Unix, `LockFileEx` on Windows): the system releases it when its process
//! ends, so a pull that crashed or was interrupted leaves nothing to clean
//! up. Two bd processes starting at once in one checkout (the session
//! hooks of two agents, say) take turns.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bd_core::agents::{Harness, SkillFile, sha256_hex, under};
use bd_core::{Error, Result};
use sha2::{Digest, Sha256};

use super::lock::{LOCK_FILE, LockFile, skill_path};
use crate::auth::random_hex;
use crate::io;

/// The file whose OS lock serializes changes to `agents.lock` and to what it records.
pub const MUTEX_FILE: &str = "agents.lock.mutex";

/// A checkout: the directory holding a `.bd` directory.
#[derive(Clone, Debug)]
pub struct Checkout {
    pub root: PathBuf,
    /// Its `.bd` directory.
    pub bd: PathBuf,
}

/// A skill file's place in a checkout, as found there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    Missing,
    /// A regular file: the SHA-256 of its bytes, and whether it has an
    /// executable bit (never, where files have none).
    File {
        sha256: String,
        /// The SHA-256 of it with each CRLF as LF, if it has any: as
        /// [`bd_core::agents::lf_sha256`] gives it for a text.
        lf_sha256: Option<String>,
        executable: bool,
    },
    /// Something bd never writes over or through: at `at` (checkout-relative) is `what`.
    Blocked {
        at: String,
        what: &'static str,
    },
}

impl Found {
    /// Whether it is a file with the text whose digests are `sha256` and
    /// `lf_sha256` (see [`bd_core::agents::FileDigest`]): its bytes, or them
    /// with other line endings, as git checks text files out with CRLF ones
    /// on Windows (`core.autocrlf`).
    pub fn holds(&self, sha256: &str, lf_sha256: Option<&str>) -> bool {
        matches!(self, Found::File { sha256: s, lf_sha256: lf, .. }
            if s == sha256 || lf.as_deref().unwrap_or(s) == lf_sha256.unwrap_or(sha256))
    }
}

/// The checkout's mutex, held: released when dropped, or when the process ends.
pub struct Mutex(File);

impl Drop for Mutex {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

impl Checkout {
    /// The checkout whose `.bd` directory is `bd`.
    pub fn new(bd: PathBuf) -> Checkout {
        let root = bd.parent().map(Path::to_path_buf).unwrap_or_default();
        Checkout { root, bd }
    }

    pub fn lock_path(&self) -> PathBuf {
        self.bd.join(LOCK_FILE)
    }

    /// The lock file, checked; an empty one if there is none yet.
    pub fn read_lock(&self) -> Result<LockFile> {
        let path = self.lock_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(LockFile::default()),
            Err(e) => return Err(path_error(&path, e)),
        };
        let unusable = |e: &dyn std::fmt::Display| {
            Error::invalid(format!(
                "{}: not a usable agents lock file ({e}); remove it to start over (a pull then adopts the files and \
                 MCP entries that match the server's, and leaves the others alone)",
                path.display()
            ))
        };
        let lock: LockFile = serde_json::from_str(&text).map_err(|e| unusable(&e))?;
        lock.check().map_err(|e| unusable(&e))?;
        Ok(lock)
    }

    /// Write `lock` as the lock file, at once, unless the file holds it
    /// already. The first one written gets a line in `.bd/.gitignore`.
    /// Call with the mutex held.
    pub fn write_lock(&self, lock: &LockFile) -> Result<()> {
        let path = self.lock_path();
        let text = format!("{}\n", serde_json::to_string_pretty(lock)?);
        match std::fs::read_to_string(&path) {
            Ok(old) if old == text => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => crate::commands::ignore_agents_lock(&self.bd)?,
            Err(e) => return Err(path_error(&path, e)),
        }
        write_atomically(&path, text.as_bytes(), false, |_| Ok(()))
    }

    /// Take the checkout's mutex, to change the lock file or what it
    /// records; waits up to `wait` for another bd process to release it.
    pub fn exclusive(&self, wait: Duration) -> Result<Mutex> {
        let path = self.bd.join(MUTEX_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| path_error(&path, e))?;
        take(file, &path, wait, true)
    }

    /// Take the checkout's mutex shared, to read a consistent state while no
    /// other process changes it; `None` if no bd process has made it yet.
    pub fn shared(&self, wait: Duration) -> Result<Option<Mutex>> {
        let path = self.bd.join(MUTEX_FILE);
        match File::open(&path) {
            Ok(file) => take(file, &path, wait, false).map(Some),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(path_error(&path, e)),
        }
    }

    /// File `rel` of skill `name` of `harness`, as found, without following
    /// a symlink at or below the skill's directory (the skills directory and
    /// its parents may be symlinks).
    pub fn find_skill_file(&self, harness: Harness, name: &str, rel: &str) -> Result<Found> {
        let base = under(&self.root, harness.skills_dest());
        let blocked = Found::Blocked { at: harness.skills_dest().to_string(), what: "not a directory" };
        match std::fs::metadata(&base) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Found::Missing),
            // A file above it.
            Err(e) if e.kind() == ErrorKind::NotADirectory => return Ok(blocked),
            Err(e) => return Err(path_error(&base, e)),
            Ok(m) if !m.is_dir() => return Ok(blocked),
            Ok(_) => {}
        }
        let parts: Vec<&str> = std::iter::once(name).chain(rel.split('/')).collect();
        let (mut path, mut at) = (base, harness.skills_dest().to_string());
        for (i, part) in parts.iter().enumerate() {
            path.push(part);
            at = format!("{at}/{part}");
            let meta = match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Found::Missing),
                Err(e) => return Err(path_error(&path, e)),
                Ok(m) => m,
            };
            let last = i + 1 == parts.len();
            if last && meta.is_file() {
                let (sha256, lf_sha256) = hash_file(&path)?;
                return Ok(Found::File { sha256, lf_sha256, executable: executable(&meta) });
            }
            let what = if meta.file_type().is_symlink() {
                "a symlink"
            } else if !last && !meta.is_dir() {
                "a file where a directory belongs"
            } else if last && meta.is_dir() {
                "a directory"
            } else if last {
                "not a regular file"
            } else {
                continue;
            };
            return Ok(Found::Blocked { at, what });
        }
        unreachable!("the last part is a file, or something else in the way")
    }

    /// The bytes of file `rel` of skill `name` of `harness`, if it is a
    /// regular file reached through no symlink at or below the skill's
    /// directory (see [`Checkout::find_skill_file`]).
    pub fn read_skill_file(&self, harness: Harness, name: &str, rel: &str) -> Result<Option<Vec<u8>>> {
        if !matches!(self.find_skill_file(harness, name, rel)?, Found::File { .. }) {
            return Ok(None);
        }
        let path = under(&self.root, &format!("{}/{name}/{rel}", harness.skills_dest()));
        std::fs::read(&path).map(Some).map_err(|e| path_error(&path, e))
    }

    /// Write `file` as file `rel` of skill `name` of `harness`, at once (a
    /// temp file renamed into place), creating the directories it needs and
    /// never writing through a symlink below the skills directory. Returns
    /// whether the file system kept the executable bit it was given, as
    /// `set_executable` tells.
    pub fn write_skill_file(&self, harness: Harness, name: &str, rel: &str, file: &SkillFile) -> Result<bool> {
        if sha256_hex(file.text.as_bytes()) != file.sha256 {
            return Err(Error::invalid(format!(
                "{}: its text does not match its sha256",
                skill_path(harness, name, rel)
            )));
        }
        let base = under(&self.root, harness.skills_dest());
        std::fs::create_dir_all(&base).map_err(|e| path_error(&base, e))?;
        let parts: Vec<&str> = std::iter::once(name).chain(rel.split('/')).collect();
        let (file_name, dirs) = parts.split_last().expect("a skill and a file name");
        let mut dir = base;
        for d in dirs {
            dir.push(d);
            ensure_dir(&dir)?;
        }
        let target = dir.join(file_name);
        if std::fs::symlink_metadata(&target).is_ok_and(|m| !m.is_file()) {
            return Err(Error::Refused(format!(
                "{}: not a regular file, which bd never writes over",
                target.display()
            )));
        }
        let (executable, mut kept) = (file.executable, true);
        write_atomically(&target, file.text.as_bytes(), true, |f| {
            kept = set_executable(f, executable)?;
            Ok(())
        })?;
        Ok(kept)
    }

    /// Delete file `rel` of skill `name` of `harness` if it is still the
    /// regular file whose SHA-256 is `sha256`, then the directories that
    /// leaves empty below the skills directory. Returns whether it did.
    pub fn remove_skill_file(&self, harness: Harness, name: &str, rel: &str, sha256: &str) -> Result<bool> {
        if !matches!(self.find_skill_file(harness, name, rel)?, Found::File { sha256: s, .. } if s == sha256) {
            return Ok(false);
        }
        let base = under(&self.root, harness.skills_dest());
        let path = under(&base, &format!("{name}/{rel}"));
        std::fs::remove_file(&path).map_err(|e| path_error(&path, e))?;
        let mut dir = path.parent();
        while let Some(d) = dir.filter(|d| *d != base && d.starts_with(&base)) {
            if std::fs::remove_dir(d).is_err() {
                break;
            }
            dir = d.parent();
        }
        Ok(true)
    }

    /// Give file `rel` of skill `name` of `harness` its executable bits on
    /// Unix (where it has read bits), or take them away, if it is still the
    /// regular file whose SHA-256 is `sha256`. Returns `None` if it is not,
    /// else whether the file system kept the executable bit, as
    /// `set_executable` tells.
    pub fn set_skill_mode(
        &self,
        harness: Harness,
        name: &str,
        rel: &str,
        sha256: &str,
        executable: bool,
    ) -> Result<Option<bool>> {
        if !matches!(self.find_skill_file(harness, name, rel)?, Found::File { sha256: s, .. } if s == sha256) {
            return Ok(None);
        }
        let path = under(&self.root, &format!("{}/{name}/{rel}", harness.skills_dest()));
        let file = File::open(&path).map_err(|e| path_error(&path, e))?;
        set_executable(&file, executable).map(Some).map_err(|e| path_error(&path, e))
    }

    /// Whether the checkout-relative paths `a` and `b` reach the same file:
    /// on a file system that ignores case, two cases of one name do.
    pub fn same_file(&self, a: &str, b: &str) -> bool {
        match (file_id(&under(&self.root, a)), file_id(&under(&self.root, b))) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    /// Whether `dir` (checkout-relative) holds only files `keep` accepts
    /// (given their checkout-relative paths), in directories: no other
    /// file, no symlink, and no empty directory, so that it goes once they
    /// do. `true` if it does not exist; `false` if it is not a directory.
    pub fn holds_only(&self, dir: &str, keep: &mut dyn FnMut(&str) -> Result<bool>) -> Result<bool> {
        fn walk(dir: &Path, rel: &str, keep: &mut dyn FnMut(&str) -> Result<bool>) -> Result<bool> {
            let mut entries = std::fs::read_dir(dir).map_err(|e| path_error(dir, e))?.peekable();
            if entries.peek().is_none() {
                return Ok(false);
            }
            for entry in entries {
                let entry = entry.map_err(|e| path_error(dir, e))?;
                let rel = format!("{rel}/{}", entry.file_name().to_string_lossy());
                let kind = entry.file_type().map_err(|e| path_error(&entry.path(), e))?;
                let only = match kind {
                    k if k.is_dir() => walk(&entry.path(), &rel, keep)?,
                    k => k.is_file() && keep(&rel)?,
                };
                if !only {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        let path = under(&self.root, dir);
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => walk(&path, dir, keep),
            Ok(_) => Ok(false),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
            Err(e) => Err(path_error(&path, e)),
        }
    }
}

/// What tells files apart whatever path reaches them: the device and inode
/// on Unix (a symlink is not followed); elsewhere the canonical path, which
/// on Windows carries each name's case as stored on disk.
#[cfg(unix)]
fn file_id(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_id(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

#[cfg(unix)]
fn executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &std::fs::Metadata) -> bool {
    false
}

/// Take `file`'s OS lock, waiting up to `wait` for its holder to release it.
fn take(file: File, path: &Path, wait: Duration, exclusive: bool) -> Result<Mutex> {
    let deadline = Instant::now() + wait;
    let mut delay = Duration::from_millis(5);
    loop {
        // Called through the trait: std's own File::try_lock (Rust 1.89) is newer than bd's MSRV.
        let tried = if exclusive { fs4::FileExt::try_lock(&file) } else { fs4::FileExt::try_lock_shared(&file) };
        match tried {
            Ok(()) => return Ok(Mutex(file)),
            Err(fs4::TryLockError::WouldBlock) => {}
            Err(fs4::TryLockError::Error(e)) => return Err(path_error(path, e)),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Locked(format!(
                "another bd agents command is changing the agent assets of this checkout ({} is locked); retry",
                path.display()
            )));
        }
        std::thread::sleep(delay.min(left));
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

/// Make `dir` a directory unless something else is there, which is an
/// error: a symlink is never followed.
fn ensure_dir(dir: &Path) -> Result<()> {
    let refused = || {
        Error::Refused(format!(
            "{}: a symlink or a file where a directory belongs; bd never writes through it",
            dir.display()
        ))
    };
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(refused()),
        Err(e) if e.kind() == ErrorKind::NotFound => match std::fs::create_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) { Ok(()) } else { Err(refused()) }
            }
            Err(e) => Err(path_error(dir, e)),
        },
        Err(e) => Err(path_error(dir, e)),
    }
}

/// SHA-256 of a file's bytes, in lowercase hex, and of them with each CRLF
/// as LF if it has any ([`Hashes`]).
pub fn hash_file(path: &Path) -> Result<(String, Option<String>)> {
    let mut file = File::open(path).map_err(|e| path_error(path, e))?;
    let mut hashes = Hashes::default();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = file.read(&mut buf).map_err(|e| path_error(path, e))?;
        if n == 0 {
            break;
        }
        hashes.update(&buf[..n]);
    }
    Ok(hashes.finish())
}

/// The SHA-256 of bytes fed in pieces, and of them with each CRLF as LF, as
/// [`bd_core::agents::lf_sha256`] reads a text.
#[derive(Default)]
struct Hashes {
    bytes: Sha256,
    lf: Sha256,
    /// The last byte fed is a CR, which the next may make a CRLF: not in `lf` yet.
    cr: bool,
    has_crlf: bool,
}

impl Hashes {
    fn update(&mut self, data: &[u8]) {
        self.bytes.update(data);
        let mut lf = Vec::with_capacity(data.len() + 1);
        for &b in data {
            if std::mem::take(&mut self.cr) {
                if b == b'\n' {
                    self.has_crlf = true;
                    lf.push(b'\n');
                    continue;
                }
                lf.push(b'\r');
            }
            if b == b'\r' {
                self.cr = true;
            } else {
                lf.push(b);
            }
        }
        self.lf.update(&lf);
    }

    /// The SHA-256 of the bytes, and of them with each CRLF as LF if they have any.
    fn finish(mut self) -> (String, Option<String>) {
        if self.cr {
            self.lf.update(b"\r");
        }
        let hex = |h: Sha256| h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>();
        (hex(self.bytes), self.has_crlf.then(|| hex(self.lf)))
    }
}

/// Write `data` to `target` at once: into a temp file next to it (hidden,
/// if `hidden`), which `finish` may adjust (its permissions), then renamed
/// over it.
pub fn write_atomically(
    target: &Path,
    data: &[u8],
    hidden: bool,
    finish: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<()> {
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(Error::invalid(format!("{}: not a file path", target.display())));
    };
    let name = name.to_string_lossy();
    let suffix = random_hex(6)?;
    let tmp = dir.join(if hidden { format!(".{name}.{suffix}.tmp") } else { format!("{name}.{suffix}.tmp") });
    let written = OpenOptions::new().write(true).create_new(true).open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        finish(&f)
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(path_error(target, e));
    }
    io::replace_file(&tmp, target).map_err(|e| path_error(target, e))
}

/// Give `file` the executable bits where it has read bits (as git checks
/// scripts out), or take them away. Windows has no such bits.
///
/// Returns whether the file system kept an executable bit asked for: some
/// ignore chmod and show files without them (vfat or exfat, an SMB mount
/// whose fmask clears them), or refuse it (vfat without `quiet`), so the
/// mode is read back. An executable bit that stays where none was asked
/// for is kept (`true`), as file systems that show every file executable
/// (WSL's /mnt/c without metadata) are fine as they are.
#[cfg(unix)]
fn set_executable(file: &File, executable: bool) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode();
    let want = if executable { mode | ((mode & 0o444) >> 2) } else { mode & !0o111 };
    if want != mode && !chmod_ignored() {
        match file.set_permissions(std::fs::Permissions::from_mode(want)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Ok(!executable),
            Err(e) => return Err(e),
        }
    }
    Ok(!executable || file.metadata()?.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn set_executable(_: &File, _: bool) -> std::io::Result<bool> {
    Ok(true)
}

#[cfg(all(test, unix))]
thread_local! {
    /// Unit tests' [`chmod_ignored`], per thread as tests run side by side.
    pub(crate) static CHMOD_IGNORED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A test seam: whether to act as a file system where chmod succeeds and
/// changes nothing (`BD_TEST_CHMOD_IGNORED=1`, for the integration tests).
#[cfg(unix)]
fn chmod_ignored() -> bool {
    #[cfg(test)]
    if CHMOD_IGNORED.with(|c| c.get()) {
        return true;
    }
    std::env::var_os("BD_TEST_CHMOD_IGNORED").is_some_and(|v| v == "1")
}

/// Whether a mode set on a file in `dir` sticks: not where every file shows
/// as executable and chmod is ignored (WSL's /mnt/c without metadata).
#[cfg(all(test, unix))]
pub(crate) fn modes_stick(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join("mode-probe");
    std::fs::write(&probe, "").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o644)).unwrap();
    let sticks = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o777 == 0o644;
    std::fs::remove_file(probe).unwrap();
    sticks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn checkout() -> (tempfile::TempDir, Checkout) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let checkout = Checkout::new(dir.path().join(".bd"));
        (dir, checkout)
    }

    fn skill_file(text: &str, executable: bool) -> SkillFile {
        SkillFile { sha256: sha256_hex(text.as_bytes()), executable, text: text.to_string() }
    }

    #[test]
    fn skill_files_are_written_found_and_removed_with_their_directories() {
        let (_dir, c) = checkout();
        let h = Harness::Claude;
        assert_eq!(c.find_skill_file(h, "deploy", "SKILL.md").unwrap(), Found::Missing);
        c.write_skill_file(h, "deploy", "SKILL.md", &skill_file("# Deploy\n", false)).unwrap();
        c.write_skill_file(h, "deploy", "scripts/deep/run.sh", &skill_file("#!/bin/sh\r\n", true)).unwrap();
        let script = c.root.join(".claude/skills/deploy/scripts/deep/run.sh");
        assert_eq!(std::fs::read(&script).unwrap(), b"#!/bin/sh\r\n", "verbatim");
        #[cfg(unix)]
        if modes_stick(&c.root) {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode();
            assert_ne!(mode(&script) & 0o100, 0, "executable");
            assert_eq!(mode(&c.root.join(".claude/skills/deploy/SKILL.md")) & 0o111, 0);
        }
        let sha = sha256_hex(b"#!/bin/sh\r\n");
        assert_eq!(
            c.find_skill_file(h, "deploy", "scripts/deep/run.sh").unwrap(),
            Found::File { sha256: sha.clone(), lf_sha256: Some(sha256_hex(b"#!/bin/sh\n")), executable: cfg!(unix) }
        );
        let names: Vec<_> =
            std::fs::read_dir(script.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["run.sh"], "no temp files left");

        assert!(!c.remove_skill_file(h, "deploy", "scripts/deep/run.sh", &sha256_hex(b"other")).unwrap());
        assert!(script.exists(), "a file that changed is not deleted");
        assert!(c.remove_skill_file(h, "deploy", "scripts/deep/run.sh", &sha).unwrap());
        assert!(!c.root.join(".claude/skills/deploy/scripts").exists(), "emptied directories go");
        assert!(c.root.join(".claude/skills/deploy/SKILL.md").exists());
        let owned = BTreeSet::from([".claude/skills/deploy/SKILL.md".to_string()]);
        let mut keep = |rel: &str| Ok(owned.contains(rel));
        assert!(c.holds_only(".claude/skills/deploy", &mut keep).unwrap());
        std::fs::write(c.root.join(".claude/skills/deploy/notes.md"), "mine").unwrap();
        assert!(!c.holds_only(".claude/skills/deploy", &mut keep).unwrap());
        assert!(c.holds_only(".claude/skills/missing", &mut keep).unwrap());
        assert!(!c.holds_only(".claude/skills/deploy/SKILL.md", &mut keep).unwrap(), "not a directory");
        std::fs::remove_file(c.root.join(".claude/skills/deploy/notes.md")).unwrap();
        std::fs::create_dir(c.root.join(".claude/skills/deploy/empty")).unwrap();
        assert!(!c.holds_only(".claude/skills/deploy", &mut keep).unwrap(), "an empty directory would stay");
        std::fs::remove_dir(c.root.join(".claude/skills/deploy/empty")).unwrap();
        std::fs::write(c.root.join(".claude/skills/deploy/notes.md"), "mine").unwrap();
        assert!(c.remove_skill_file(h, "deploy", "SKILL.md", &sha256_hex(b"# Deploy\n")).unwrap());
        assert!(c.root.join(".claude/skills/deploy").is_dir(), "a directory holding other files stays");
        std::fs::remove_file(c.root.join(".claude/skills/deploy/notes.md")).unwrap();
        c.write_skill_file(h, "lint", "SKILL.md", &skill_file("x", false)).unwrap();
        assert!(c.remove_skill_file(h, "lint", "SKILL.md", &sha256_hex(b"x")).unwrap());
        assert!(!c.root.join(".claude/skills/lint").exists(), "the skill's directory goes when empty");
        assert!(c.root.join(".claude/skills").is_dir(), "the skills directory stays");

        let mut tampered = skill_file("x", false);
        tampered.text = "y".into();
        assert!(c.write_skill_file(h, "lint", "SKILL.md", &tampered).is_err());
    }

    #[test]
    fn files_are_hashed_with_crlf_line_endings_as_lf_too() {
        use bd_core::agents::lf_sha256;
        let hashes = |text: &str| (sha256_hex(text.as_bytes()), lf_sha256(text));
        let texts = ["", "a", "a\n", "a\r\n", "\r", "\n", "\r\n", "a\rb", "a\r\nb\nc\rd\r", "\r\r\n\n\r", "\n\r\n\r\r"];
        for text in texts {
            // In pieces of every size: a CR may end one, and its LF begin the next.
            for size in 1..=text.len().max(1) {
                let mut h = Hashes::default();
                for piece in text.as_bytes().chunks(size) {
                    h.update(piece);
                }
                assert_eq!(h.finish(), hashes(text), "{text:?} in pieces of {size}");
            }
        }

        // A file is read in 64 KiB pieces: here a CRLF spans two.
        let (_dir, c) = checkout();
        let text = format!("{}\r\nend\n", "a".repeat((64 << 10) - 1));
        std::fs::create_dir_all(c.root.join(".claude/skills/big")).unwrap();
        std::fs::write(c.root.join(".claude/skills/big/SKILL.md"), &text).unwrap();
        let found = c.find_skill_file(Harness::Claude, "big", "SKILL.md").unwrap();
        let Found::File { sha256, lf_sha256: lf, .. } = &found else { panic!("{found:?}") };
        assert_eq!((sha256.clone(), lf.clone()), hashes(&text));

        // A file holds a text whatever the line endings of either.
        let holds = |local: &str, server: &str| {
            let (sha256, lf) = hashes(local);
            let found = Found::File { sha256, lf_sha256: lf, executable: false };
            found.holds(&sha256_hex(server.as_bytes()), lf_sha256(server).as_deref())
        };
        let same = [
            ("a\nb", "a\nb"),
            ("a\r\nb\r\n", "a\nb\n"),
            ("a\nb\n", "a\r\nb\r\n"),
            ("a\r\nb\r\n", "a\r\nb\n"),
            ("a\rb\r\n", "a\rb\n"),
        ];
        for (local, server) in same {
            assert!(holds(local, server), "{local:?} holds {server:?}");
        }
        // Not with a CR of its own: a CR that ends no line is text.
        for (local, server) in [("a\r\r\n", "a\r\n"), ("a\r\n", "a\r\r\n"), ("a\r\n", "a\r"), ("a\nb", "a\nB")] {
            assert!(!holds(local, server), "{local:?} does not hold {server:?}");
        }
        assert!(!Found::Missing.holds(&sha256_hex(b""), None));
    }

    #[test]
    fn things_in_the_way_block_skill_files() {
        let (_dir, c) = checkout();
        let h = Harness::Copilot;
        std::fs::create_dir_all(c.root.join(".github/skills/deploy/SKILL.md")).unwrap();
        assert_eq!(
            c.find_skill_file(h, "deploy", "SKILL.md").unwrap(),
            Found::Blocked { at: ".github/skills/deploy/SKILL.md".into(), what: "a directory" }
        );
        assert!(c.write_skill_file(h, "deploy", "SKILL.md", &skill_file("x", false)).is_err());
        std::fs::write(c.root.join(".github/skills/lint"), "a file").unwrap();
        assert_eq!(
            c.find_skill_file(h, "lint", "a/b.md").unwrap(),
            Found::Blocked { at: ".github/skills/lint".into(), what: "a file where a directory belongs" }
        );
        assert!(c.write_skill_file(h, "lint", "a/b.md", &skill_file("x", false)).is_err());
        std::fs::create_dir_all(c.root.join(".agents")).unwrap();
        std::fs::write(c.root.join(".agents/skills"), "a file").unwrap();
        assert_eq!(
            c.find_skill_file(Harness::Codex, "x", "SKILL.md").unwrap(),
            Found::Blocked { at: ".agents/skills".into(), what: "not a directory" }
        );
        assert!(c.write_skill_file(Harness::Codex, "x", "SKILL.md", &skill_file("x", false)).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(c.root.join(".agents")).unwrap();
            std::fs::write(c.root.join(".agents"), "a file").unwrap();
            assert_eq!(
                c.find_skill_file(Harness::Codex, "x", "SKILL.md").unwrap(),
                Found::Blocked { at: ".agents/skills".into(), what: "not a directory" }
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_below_the_skills_directory_are_never_followed() {
        use std::os::unix::fs::symlink;
        let (_dir, c) = checkout();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("SKILL.md"), "theirs").unwrap();
        std::fs::create_dir_all(c.root.join(".claude/skills")).unwrap();
        symlink(elsewhere.path(), c.root.join(".claude/skills/deploy")).unwrap();
        let h = Harness::Claude;
        assert_eq!(
            c.find_skill_file(h, "deploy", "SKILL.md").unwrap(),
            Found::Blocked { at: ".claude/skills/deploy".into(), what: "a symlink" }
        );
        assert!(c.write_skill_file(h, "deploy", "SKILL.md", &skill_file("ours", false)).is_err());
        assert!(!c.remove_skill_file(h, "deploy", "SKILL.md", &sha256_hex(b"theirs")).unwrap());
        assert_eq!(std::fs::read_to_string(elsewhere.path().join("SKILL.md")).unwrap(), "theirs");

        // The skills directory itself may be a symlink.
        let shared = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(c.root.join(".agents")).unwrap();
        symlink(shared.path(), c.root.join(".agents/skills")).unwrap();
        c.write_skill_file(Harness::Codex, "triage", "SKILL.md", &skill_file("t", false)).unwrap();
        assert_eq!(std::fs::read_to_string(shared.path().join("triage/SKILL.md")).unwrap(), "t");
    }

    #[test]
    fn the_mutex_is_exclusive_and_waits_briefly() {
        let (_dir, c) = checkout();
        assert!(c.shared(Duration::ZERO).unwrap().is_none(), "nothing to share before any change");
        let held = c.exclusive(Duration::ZERO).unwrap();
        let e = c.exclusive(Duration::from_millis(50)).err().expect("held");
        assert_eq!((e.exit_code(), e.code()), (5, "busy"), "{e}");
        assert!(e.to_string().starts_with("another bd agents command is changing"), "{e}");
        assert!(!e.to_string().contains("database"), "{e}");
        assert!(c.shared(Duration::ZERO).is_err(), "readers wait for the writer");
        drop(held);
        let reader = c.shared(Duration::ZERO).unwrap().expect("the mutex file exists now");
        let other = c.shared(Duration::ZERO).unwrap().expect("readers share");
        assert!(c.exclusive(Duration::ZERO).is_err());
        drop((reader, other));
        let again = std::thread::spawn({
            let c = c.clone();
            move || c.exclusive(Duration::from_secs(5)).map(|_| ())
        });
        again.join().unwrap().unwrap();
    }

    #[test]
    fn lock_files_are_written_once_and_ignored_by_git() {
        let (_dir, c) = checkout();
        std::fs::write(c.bd.join(".gitignore"), "bd.db").unwrap();
        let mut lock = c.read_lock().unwrap();
        assert_eq!(lock, LockFile::default());
        lock.harnesses.insert(Harness::Codex, Default::default());
        c.write_lock(&lock).unwrap();
        assert_eq!(c.read_lock().unwrap(), lock);
        let gitignore = std::fs::read_to_string(c.bd.join(".gitignore")).unwrap();
        assert!(gitignore.starts_with("bd.db\n#") && gitignore.ends_with("\nagents.lock*\n"), "{gitignore}");
        let modified = std::fs::metadata(c.lock_path()).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        c.write_lock(&lock).unwrap();
        assert_eq!(std::fs::metadata(c.lock_path()).unwrap().modified().unwrap(), modified, "unchanged: not rewritten");
        std::fs::write(c.lock_path(), "{").unwrap();
        let e = c.read_lock().unwrap_err().to_string();
        assert!(e.contains("not a usable agents lock file") && e.contains("remove it to start over"), "{e}");
    }
}
