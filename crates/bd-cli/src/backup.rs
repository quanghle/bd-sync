//! Backups of a workspace's database, taken by `bd serve`'s backup job
//! ([`crate::jobs`]) for every workspace it serves and by `bd backup` for a
//! local one. A backup is a [`Store::snapshot`] (`VACUUM INTO`, checked and
//! flushed) written under a temporary name and then renamed to
//! `<backup dir>/<name>/<name>-<UTC time>.db`; the newest `keep` are kept. The
//! next backup removes the temporary file of an unfinished one.

use std::path::{Path, PathBuf};

use bd_core::{Result, Store};

use crate::app::App;
use crate::cli::BackupArgs;
use crate::io;
use crate::protocol::valid_workspace_name;

/// Backup file times: UTC, sortable, and valid in file names everywhere.
pub const STAMP: &str = "%Y%m%dT%H%M%S%.3fZ";

/// A backup just written.
#[derive(Debug)]
pub struct Taken {
    pub file: PathBuf,
    pub bytes: u64,
    /// Older backups deleted to keep `keep`.
    pub removed: usize,
    /// Backups of the name in the directory now, the new one included.
    pub kept: usize,
    /// The newest other backup, when it is dated after the new one (the clock
    /// was ahead, then corrected): the oldest-dated backups are deleted first.
    pub newer: Option<PathBuf>,
    /// Old backups that could not be deleted now (open elsewhere, on
    /// Windows), left for the next backup.
    pub undeleted: Vec<(PathBuf, std::io::Error)>,
}

/// Back up `store` into `<base>/<name>/`, keeping the newest `keep` backups of
/// `name` there (0 keeps all), the new one included whatever its date.
pub fn take(store: &Store, base: &Path, name: &str, keep: usize) -> Result<Taken> {
    let dir = base.join(name);
    create_private_dir(&dir)?;
    remove_unfinished(&dir, name);
    let file_name = format!("{name}-{}.db", chrono::Utc::now().format(STAMP));
    let (tmp, file) = (dir.join(format!("{file_name}.tmp")), dir.join(&file_name));
    store.snapshot(&tmp)?;
    std::fs::rename(&tmp, &file).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    sync_dir(&dir);
    let bytes = std::fs::metadata(&file).map(|m| m.len()).unwrap_or_default();
    let others: Vec<PathBuf> = files(&dir, name)?.into_iter().filter(|f| f.file_name() != file.file_name()).collect();
    let newer = others.last().filter(|f| f.file_name() > file.file_name()).cloned();
    let (removed, undeleted) = retain(&others, keep);
    let kept = others.len() - removed + 1;
    Ok(Taken { file, bytes, removed, kept, newer, undeleted })
}

/// `20261001T212233.123Z`, as [`STAMP`] formats it.
pub fn is_stamp(s: &str) -> bool {
    s.len() == 20
        && s.bytes().enumerate().all(|(i, c)| match i {
            8 => c == b'T',
            15 => c == b'.',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// The finished backups of `name` in `dir`, oldest first.
pub fn files(dir: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let prefix = format!("{name}-");
    let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(|e| {
            let e = e.ok()?;
            let file = e.file_name().into_string().ok()?;
            let stamp = file.strip_prefix(&prefix)?.strip_suffix(".db")?;
            is_stamp(stamp).then(|| (file.clone(), e.path()))
        })
        .collect();
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// Delete backups so that `keep` remain (0 keeps all), counting the one just
/// written, which is never deleted, whatever its date. `others` are the rest,
/// oldest first. Returns how many were deleted, and those that could not be.
fn retain(others: &[PathBuf], keep: usize) -> (usize, Vec<(PathBuf, std::io::Error)>) {
    let mut undeleted = Vec::new();
    if keep == 0 {
        return (0, undeleted);
    }
    let excess = others.len().saturating_sub(keep - 1);
    let mut removed = 0;
    for old in &others[..excess] {
        match std::fs::remove_file(old) {
            Ok(()) => removed += 1,
            Err(e) => undeleted.push((old.clone(), e)),
        }
    }
    (removed, undeleted)
}

/// Create `dir` and its missing parents, on Unix readable by this user only
/// (0700): backups hold whole workspaces. Existing directories keep their mode.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Remove what an unfinished backup left behind (the process stopped during it).
fn remove_unfinished(dir: &Path, name: &str) {
    let prefix = format!("{name}-");
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_str().is_some_and(|f| f.starts_with(&prefix) && f.contains(".db.tmp")) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Make a rename durable. Windows has no directory handle to flush.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// `bd backup`: a backup of the local workspace, named after its issue prefix
/// unless `--name` says otherwise.
pub fn cmd_backup(app: &mut App, a: &BackupArgs) -> Result<()> {
    io::require_local("bd backup")?;
    if let Some(remote) = crate::remote::configured(app)? {
        return Err(bd_core::Error::Refused(format!(
            "this workspace is remote ({}); bd backup copies a local workspace's database: back up the server's \
             workspaces with `bd serve --backup-dir`",
            remote.url
        )));
    }
    let name = match &a.name {
        Some(n) if valid_workspace_name(n) => n.clone(),
        Some(n) => {
            return Err(bd_core::Error::invalid(format!(
                "--name {n:?}: use letters, digits, '.', '_' and '-', starting with a letter or digit (at most 100)"
            )));
        }
        None => app.read(|r| bd_core::config::prefix(r.conn()))?,
    };
    let base = if a.to.is_absolute() { a.to.clone() } else { app.cwd.join(&a.to) };
    let db = app.db_path()?;
    let taken = take(app.store()?, &base, &name, a.keep)?;
    if let Some(newer) = &taken.newer {
        io::errln(format!(
            "warning: {} is dated after the new backup: check the clock (the oldest-dated backups are deleted first)",
            newer.display()
        ));
    }
    for (file, e) in &taken.undeleted {
        io::errln(format!("warning: cannot delete the old backup {}: {e}", file.display()));
    }
    let file = taken.file.display().to_string();
    let out = crate::app::Out::new(serde_json::json!({
        "workspace": db.display().to_string(),
        "name": name,
        "file": file,
        "bytes": taken.bytes,
        "removed": taken.removed,
        "kept": taken.kept,
    }))
    .id(file.clone())
    .line(format!(
        "✓ Backed up {} to {file} ({} bytes); {} old {} removed, {} kept",
        db.display(),
        taken.bytes,
        taken.removed,
        if taken.removed == 1 { "backup" } else { "backups" },
        taken.kept
    ));
    app.print(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_keeps_the_newest_backups_and_nothing_else_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let files = [
            "proj-20260101T000000.000Z.db",
            "proj-20260103T000000.000Z.db",
            "proj-20260102T000000.000Z.db",
            "proj-20260104T000000.000Z.db.tmp",
            "proj-20260104T000000.000Z.db.tmp-journal",
            "proj-2-20260105T000000.000Z.db",
            "proj-latest.db",
            "notes.txt",
        ];
        for f in files {
            std::fs::write(dir.path().join(f), b"x").unwrap();
        }
        let names = |dir: &Path| {
            let mut v: Vec<String> =
                std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
            v.sort();
            v
        };
        let listed: Vec<PathBuf> = super::files(dir.path(), "proj").unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed[0].ends_with("proj-20260101T000000.000Z.db"), "oldest first: {listed:?}");

        // The newest was just written; retention looks at the others.
        assert_eq!(retain(&listed[..2], 0).0, 0, "0 keeps all");
        assert_eq!(retain(&listed[..2], 2).0, 1);
        assert_eq!(retain(&super::files(dir.path(), "proj").unwrap()[..1], 2).0, 0);
        remove_unfinished(dir.path(), "proj");
        assert_eq!(
            names(dir.path()),
            [
                "notes.txt",
                "proj-2-20260105T000000.000Z.db",
                "proj-20260102T000000.000Z.db",
                "proj-20260103T000000.000Z.db",
                "proj-latest.db"
            ]
        );
        assert!(is_stamp(&chrono::Utc::now().format(STAMP).to_string()));
    }

    #[test]
    fn a_backup_reports_what_retention_did() {
        let ws = tempfile::tempdir().unwrap();
        let init = bd_core::InitOptions { prefix: "t".into(), id_mode: Default::default() };
        let store = Store::init(&ws.path().join("bd.db"), init, bd_core::OpenOptions::default()).unwrap();
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let (old, future) = (dir.join("proj-20000101T000000.000Z.db"), dir.join("proj-29990101T000000.000Z.db"));
        for f in [&old, &future] {
            std::fs::write(f, b"x").unwrap();
        }
        let first = take(&store, out.path(), "proj", 2).unwrap();
        assert_eq!((first.removed, first.kept, first.newer.as_ref()), (1, 2, Some(&future)));
        assert!(first.undeleted.is_empty() && !old.exists());
        assert_eq!(first.bytes, std::fs::metadata(&first.file).unwrap().len());
        assert!(first.bytes > 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = take(&store, out.path(), "proj", 0).unwrap();
        assert_eq!((second.removed, second.kept), (0, 3), "0 keeps all");
        assert_eq!(files(&dir, "proj").unwrap(), [first.file, second.file, future]);
    }

    #[test]
    fn backups_that_cannot_be_deleted_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        // A directory with a backup's name: remove_file fails on it everywhere.
        let stuck = dir.path().join("proj-20260101T000000.000Z.db");
        std::fs::create_dir(&stuck).unwrap();
        let (removed, undeleted) = retain(std::slice::from_ref(&stuck), 1);
        assert_eq!((removed, undeleted.len()), (0, 1));
        assert_eq!(undeleted[0].0, stuck);
        assert!(stuck.is_dir());
    }
}
