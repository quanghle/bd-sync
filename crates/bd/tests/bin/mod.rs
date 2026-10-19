//! The `bd` binary the end-to-end tests run: a private copy of the one cargo built, taken once per test
//! process.
//!
//! Cargo uplifts the binary to `target/debug/bd` (it removes the old file and links the new one in), and
//! every worktree sharing one `CARGO_TARGET_DIR` uplifts to that same path. A build in another worktree
//! while these tests run would swap the binary under them, so later tests would run another checkout's
//! `bd`, or fail to spawn one in the moment it is missing. [`bd_exe`] copies the binary on its first call
//! into `CARGO_TARGET_TMPDIR`, keyed by the build (its length and modification time), and every spawn runs
//! that copy. A build that lands before the first call is still copied as if it were this one's: that window
//! stays open, and is small next to a whole test run.
//!
//! Copies are shared by the processes of one build (the cli and remote binaries, and reruns), made atomically
//! (a temporary file, then a rename that never overwrites), and those of builds unused for a day are removed.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tempfile::TempPath;

/// The binary cargo built for these tests. Only [`bd_exe`] (and its test) may name it.
const CARGO_BD: &str = env!("CARGO_BIN_EXE_bd");
/// How many times a copy is tried while the source keeps changing under it.
const ATTEMPTS: usize = 3;
/// The pause between attempts, so an uplift under way (remove, then link) can finish.
const RETRY_AFTER: Duration = Duration::from_millis(200);
/// Key directories whose stamp is older than this are removed.
const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// The file each process rewrites in its key directory when it takes or reuses the copy.
const STAMP: &str = "last-used";
/// The prefix of a copy under way, renamed to the binary's own name once it is complete.
const PARTIAL: &str = ".partial-";

/// The private copy of the `bd` binary that every test spawns. The same path for the whole process.
pub fn bd_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bd-exe");
        private_copy(Path::new(CARGO_BD), &base, |from, to| fs::copy(from, to))
    })
}

/// What identifies one build of the source: a different one gets a different key directory.
#[derive(Debug, PartialEq, Eq)]
struct Build {
    len: u64,
    mtime: u128,
}

impl Build {
    fn of(path: &Path) -> io::Result<Build> {
        let meta = fs::metadata(path)?;
        let mtime = meta.modified()?.duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos();
        Ok(Build { len: meta.len(), mtime })
    }

    fn key(&self) -> String {
        format!("{}-{}", self.len, self.mtime)
    }
}

/// Copies `src` with `copy` to `<base>/<key>/<file name of src>`, or reuses the copy already there, and
/// returns its path. A source that cannot be read, a failed or short copy, or a source that changed while it
/// was copied is one failed attempt; the last of [`ATTEMPTS`] panics.
fn private_copy(src: &Path, base: &Path, copy: impl Fn(&Path, &Path) -> io::Result<u64>) -> PathBuf {
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(RETRY_AFTER);
        }
        match try_copy(src, base, &copy) {
            Ok(dest) => return dest,
            Err(why) => last = why,
        }
    }
    panic!(
        "{} changed while being copied {ATTEMPTS} times: a concurrent build (another worktree sharing \
         CARGO_TARGET_DIR?) is replacing it; last error: {last}",
        src.display()
    )
}

/// One attempt of [`private_copy`]: `Err` names why the source could not be copied as it was.
fn try_copy(src: &Path, base: &Path, copy: &impl Fn(&Path, &Path) -> io::Result<u64>) -> Result<PathBuf, String> {
    let name = src.file_name().unwrap_or_else(|| panic!("{} names no file", src.display()));
    let before = Build::of(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    let dir = base.join(before.key());
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    // Not empty, so writing it changes its modification time on every platform: pruning reads that.
    let _ = fs::write(dir.join(STAMP), std::process::id().to_string());
    let dest = dir.join(name);
    if !dest.is_file() {
        // A path, not an open file: the copy can replace it on Windows, and dropping it removes it.
        let tmp = tempfile::Builder::new()
            .prefix(PARTIAL)
            .tempfile_in(&dir)
            .unwrap_or_else(|e| panic!("creating a temporary file in {}: {e}", dir.display()))
            .into_temp_path();
        let copied = copy(src, &tmp).map_err(|e| format!("copying {}: {e}", src.display()))?;
        let after = Build::of(src).map_err(|e| format!("reading {} after copying it: {e}", src.display()))?;
        if after != before {
            return Err(format!("{before:?} became {after:?} while it was copied"));
        }
        if copied != before.len {
            return Err(format!("copied {copied} of its {} bytes", before.len));
        }
        persist(tmp, &dest);
    }
    prune(base, &dir);
    Ok(dest)
}

/// Renames a complete copy to `dest` without overwriting: if another process got there first, its copy (of
/// the same build) is kept and this one removed.
fn persist(tmp: TempPath, dest: &Path) {
    match tmp.persist_noclobber(dest) {
        Ok(()) => {}
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists && dest.is_file() => drop(e.path),
        Err(e) => panic!("keeping the copy at {}: {}", dest.display(), e.error),
    }
}

/// Removes the key directories under `base`, other than `keep`, unused for [`STALE_AFTER`]: the time of their
/// stamp, or of the directory without one. Best effort: every error is ignored.
fn prune(base: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(base) else { return };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if path == keep || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let used = fs::metadata(path.join(STAMP)).or_else(|_| entry.metadata()).and_then(|m| m.modified());
        if let Ok(used) = used
            && now.duration_since(used).is_ok_and(|age| age > STALE_AFTER)
        {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn real_copy(from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }

    /// A source file `name` holding `bytes`, in a directory of its own, and an empty base directory.
    fn setup(name: &str, bytes: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        let src = root.path().join("src").join(name);
        fs::write(&src, bytes).unwrap();
        let base = root.path().join("base");
        (root, src, base)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn copy_is_independent_of_the_source() {
        let (_root, src, base) = setup("bd", b"original");
        let copy = private_copy(&src, &base, real_copy);
        OpenOptions::new().write(true).open(&copy).unwrap().write_all(b"XX").unwrap();
        assert_eq!(fs::read(&src).unwrap(), b"original");
        fs::remove_file(&src).unwrap();
        fs::write(&src, b"rewritten").unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"XXiginal");
    }

    #[test]
    fn copy_keeps_the_file_name() {
        let (_root, src, base) = setup("bd.exe", b"binary");
        let copy = private_copy(&src, &base, real_copy);
        assert_eq!(copy.file_name(), src.file_name());
        assert!(copy.starts_with(&base));
    }

    #[cfg(unix)]
    #[test]
    fn copy_keeps_the_executable_bit() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_root, src, base) = setup("bd", b"#!/bin/sh\n");
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();
        let copy = private_copy(&src, &base, real_copy);
        let meta = fs::metadata(&copy).unwrap();
        assert_ne!(meta.permissions().mode() & 0o111, 0, "mode {:o}", meta.permissions().mode());
        assert_eq!(meta.nlink(), 1, "a copy, not a link");
        assert_eq!(fs::metadata(&src).unwrap().nlink(), 1);
    }

    #[test]
    fn same_source_reuses_one_copy() {
        let (_root, src, base) = setup("bd", b"binary");
        let first = private_copy(&src, &base, real_copy);
        let second = private_copy(&src, &base, real_copy);
        assert_eq!(first, second);
        let keys = names(&base);
        assert_eq!(keys.len(), 1, "{keys:?}");
        assert_eq!(names(&base.join(&keys[0])), ["bd", STAMP], "one copy, no partial files left");
    }

    #[test]
    fn changed_source_gets_a_new_key() {
        let (_root, src, base) = setup("bd", b"binary");
        let first = private_copy(&src, &base, real_copy);
        fs::write(&src, b"a longer binary").unwrap();
        let second = private_copy(&src, &base, real_copy);
        assert_ne!(first.parent(), second.parent());
        assert_eq!(fs::read(&first).unwrap(), b"binary");
        assert_eq!(fs::read(&second).unwrap(), b"a longer binary");
    }

    #[test]
    fn existing_copy_is_reused_not_overwritten() {
        let (_root, src, base) = setup("bd", b"binary");
        let dir = base.join(Build::of(&src).unwrap().key());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bd"), b"marker").unwrap();
        let copy = private_copy(&src, &base, |_: &Path, _: &Path| -> io::Result<u64> {
            panic!("an existing copy is not copied again")
        });
        assert_eq!(copy, dir.join("bd"));
        assert_eq!(fs::read(&copy).unwrap(), b"marker");
    }

    #[test]
    fn persist_reuses_a_winning_copy() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("bd");
        fs::write(&dest, b"winner").unwrap();
        let tmp = tempfile::Builder::new().prefix(PARTIAL).tempfile_in(dir.path()).unwrap().into_temp_path();
        fs::write(&tmp, b"loser").unwrap();
        let tmp_path = tmp.to_path_buf();
        persist(tmp, &dest);
        assert_eq!(fs::read(&dest).unwrap(), b"winner");
        assert!(!tmp_path.exists(), "the losing copy is removed");
    }

    #[test]
    fn prune_removes_only_stale_key_dirs() {
        let base = tempfile::tempdir().unwrap();
        let base = base.path();
        let two_days_ago = SystemTime::now() - Duration::from_secs(48 * 60 * 60);
        let key_dir = |name: &str, stamp_time: Option<SystemTime>| {
            let dir = base.join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("bd"), b"binary").unwrap();
            if let Some(time) = stamp_time {
                fs::write(dir.join(STAMP), b"1").unwrap();
                OpenOptions::new().write(true).open(dir.join(STAMP)).unwrap().set_modified(time).unwrap();
            }
            dir
        };
        let stale = key_dir("1-1", Some(two_days_ago));
        let fresh = key_dir("2-2", Some(SystemTime::now()));
        let own = key_dir("3-3", Some(two_days_ago));
        // No stamp: the directory's own time decides, and it was just made.
        let unstamped = key_dir("4-4", None);
        // A stamp that is not a file is still read for its time.
        let odd = key_dir("5-5", None);
        fs::create_dir(odd.join(STAMP)).unwrap();
        fs::write(base.join("stray"), b"not a key dir").unwrap();

        prune(base, &own);
        assert!(!stale.exists(), "a key dir unused for two days is removed");
        assert!(fresh.exists() && own.exists() && unstamped.exists() && odd.exists());
        assert!(base.join("stray").is_file());
        // A base that does not exist is ignored.
        prune(&base.join("missing"), &own);
    }

    #[test]
    fn source_changed_once_is_retried() {
        let (_root, src, base) = setup("bd", b"old build");
        let calls = AtomicUsize::new(0);
        let copy = private_copy(&src, &base, |from: &Path, to: &Path| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                fs::write(from, b"the new, longer build").unwrap();
            }
            fs::copy(from, to)
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&copy).unwrap(), b"the new, longer build");
        assert_eq!(copy.parent().unwrap(), base.join(Build::of(&src).unwrap().key()));
        for key in names(&base) {
            assert!(!names(&base.join(&key)).iter().any(|n| n.starts_with(PARTIAL)), "partial copy left in {key}");
        }
    }

    #[test]
    fn short_copy_is_retried() {
        let (_root, src, base) = setup("bd", b"binary");
        let calls = AtomicUsize::new(0);
        let copy = private_copy(&src, &base, |from: &Path, to: &Path| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                fs::write(to, b"bin")?;
                return Ok(3);
            }
            fs::copy(from, to)
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&copy).unwrap(), b"binary");
    }

    #[test]
    #[should_panic(expected = "concurrent build")]
    fn source_changing_every_time_panics() {
        let (_root, src, base) = setup("bd", b"build");
        let calls = AtomicUsize::new(0);
        private_copy(&src, &base, |from: &Path, to: &Path| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            fs::write(from, "x".repeat(10 + n)).unwrap();
            fs::copy(from, to)
        });
    }

    #[test]
    fn bd_exe_is_a_stable_private_copy() {
        let exe = bd_exe();
        assert!(std::ptr::eq(exe, bd_exe()));
        assert_ne!(exe, Path::new(CARGO_BD));
        assert!(exe.starts_with(Path::new(env!("CARGO_TARGET_TMPDIR")).join("bd-exe")), "{}", exe.display());
        assert_eq!(exe.file_name(), Path::new(CARGO_BD).file_name());
        assert!(exe.is_file());
    }

    /// Every test spawns [`bd_exe`]: no other file under `tests/` names the cargo binary. The needle is built
    /// with `concat!`, so this test's own text is not a use of it.
    #[test]
    fn only_the_helper_names_the_cargo_binary() {
        const NEEDLE: &str = concat!("CARGO_BIN_", "EXE_bd");
        fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display())) {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut files = Vec::new();
        rust_files(&tests, &mut files);
        let helper = tests.join("bin").join("mod.rs");
        assert!(files.contains(&helper), "{} not found among {files:?}", helper.display());
        let offenders: Vec<_> = files
            .iter()
            .filter(|path| **path != helper)
            .filter(|path| fs::read_to_string(path).unwrap().contains(NEEDLE))
            .map(|path| path.display().to_string())
            .collect();
        assert!(offenders.is_empty(), "spawn bin::bd_exe() instead of {NEEDLE} in {offenders:?}");
        assert!(fs::read_to_string(&helper).unwrap().contains(NEEDLE), "the helper names the binary itself");
    }
}
