//! The workspace's playbooks as an approved asset: what `bd agents manifest
//! --playbooks` and `bd agents fetch --playbooks` serve, so that a bd client
//! uses a server's playbook only once a person approved it on that machine
//! (`bd agents approve`), as it does skills and MCP definitions.
//!
//! The set is every playbook file (`.toml` or `.json`) under the workspace's
//! `<db dir>/playbooks` (`.bd/playbooks`; under bd serve
//! `<root>/<ws>/.bd/playbooks`), subdirectories included, as the files
//! that `extends` and `expand` reach by path may live there. It is read as
//! strictly as an agent set ([`AgentSet::load`](super::AgentSet::load)):
//! paths are portable and ASCII ([`check_playbook_path`]), a symlink may
//! only lead somewhere else inside the playbooks directory, files are UTF-8
//! text, and the set stays within the playbook bundle limits (the most a
//! client sends back to run one: [`MAX_BUNDLE_FILES`] files,
//! [`MAX_BUNDLE_FILE_BYTES`] each, [`MAX_BUNDLE_BYTES`] in all). Hidden
//! entries and files of other kinds are left out. Errors name the file.
//!
//! A file's hash is the SHA-256 of its bytes; the set's revision is the
//! SHA-256 of the [`canonical_json`] of `{"files": {<path>: {"sha256":
//! ...}}}`. `bd serve` records it beside the harnesses' revisions and
//! appends an [`AGENTS_CHANGED`](super::AGENTS_CHANGED) event naming the
//! `playbooks` area when it changes ([`super::record_all`]).

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::mcp::canonical_json;
use super::set::{Walk, check_text, check_tree, io_error, label_of, too_large};
use super::{MAX_SET_DIRS, check_sha256, check_skill_path, context, invalid, sha256_hex};
use crate::error::Result;
use crate::playbook::{EXTENSIONS, MAX_BUNDLE_BYTES, MAX_BUNDLE_FILE_BYTES, MAX_BUNDLE_FILES};

/// The directory next to the database that holds the workspace's playbooks.
pub const PLAYBOOKS_DIR: &str = "playbooks";

/// The workspace's playbook files, whole: what `bd agents fetch --playbooks` prints.
///
/// ```json
/// {
///   "revision": "<sha256>",
///   "files": {
///     "change.toml": {"sha256": "<sha256>", "text": "description = \"...\"\n..."},
///     "parts/review.toml": {"sha256": "<sha256>", "text": "..."}
///   }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybookSet {
    pub revision: String,
    /// By `/`-separated path within the playbooks directory.
    pub files: BTreeMap<String, PlaybookFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybookFile {
    /// SHA-256 of `text`.
    pub sha256: String,
    pub text: String,
}

/// The playbook set without its texts: what `bd agents manifest --playbooks` prints.
///
/// ```json
/// {"revision": "<sha256>", "files": {"change.toml": {"sha256": "<sha256>"}}}
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybooksManifest {
    pub revision: String,
    pub files: BTreeMap<String, PlaybookDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybookDigest {
    pub sha256: String,
}

fn revision_of(files: &BTreeMap<String, PlaybookDigest>) -> String {
    sha256_hex(canonical_json(&json!({ "files": files })).as_bytes())
}

/// Whether `name` (a file name) is a playbook file's: it ends in `.toml` or `.json`.
pub fn is_playbook_file(name: &str) -> bool {
    EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

/// The path of a served playbook file within the playbooks directory: as
/// [`check_skill_path`] allows (relative, `/`-separated, portable ASCII
/// names, none hidden, at most 8 levels and 200 bytes), naming a `.toml` or
/// `.json` file.
pub fn check_playbook_path(path: &str) -> Result<()> {
    check_skill_path(path)?;
    if !is_playbook_file(path) {
        return Err(invalid(format!("invalid path {path:?}: not a playbook file (.toml or .json)")));
    }
    Ok(())
}

fn check_totals(files: usize, bytes: usize) -> Result<()> {
    if files > MAX_BUNDLE_FILES {
        return Err(invalid(format!(
            "playbooks: {files} files is more than the {MAX_BUNDLE_FILES} a workspace may serve"
        )));
    }
    if bytes > MAX_BUNDLE_BYTES {
        return Err(invalid(format!(
            "playbooks: more than the {} MiB of text a workspace may serve",
            MAX_BUNDLE_BYTES >> 20
        )));
    }
    Ok(())
}

impl PlaybookSet {
    /// What a workspace without playbooks serves.
    pub fn empty() -> PlaybookSet {
        PlaybookSet { revision: revision_of(&BTreeMap::new()), files: BTreeMap::new() }
    }

    /// Read the playbooks under `dir` (a workspace's `.bd/playbooks`),
    /// strictly (see the [module docs](self)). No directory: no playbooks.
    pub fn load(dir: &Path) -> Result<PlaybookSet> {
        let base = label_of(dir);
        match std::fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PlaybookSet::empty()),
            Err(e) => return Err(io_error(&base, &e)),
        }
        let root = std::fs::canonicalize(dir).map_err(|e| io_error(&base, &e))?;
        let mut walk = Walk { root: root.clone(), base: base.clone(), files: 0, dirs: 0, bytes: 0 };
        let (meta, canon) = walk.resolve(&root, &base)?;
        if !meta.is_dir() {
            return Err(invalid(format!("{base}: not a directory")));
        }
        let mut files = BTreeMap::new();
        tree(&mut walk, &base, "", canon, &meta, &mut vec![], &mut files)?;
        check_tree(files.keys()).map_err(|e| context(&base, e))?;
        let bytes = files.values().map(|f: &PlaybookFile| f.text.len()).sum();
        check_totals(files.len(), bytes)?;
        Ok(PlaybookSet { revision: String::new(), files }.sealed())
    }

    pub fn manifest(&self) -> PlaybooksManifest {
        PlaybooksManifest { revision: self.revision.clone(), files: self.digests() }
    }

    fn digests(&self) -> BTreeMap<String, PlaybookDigest> {
        self.files.iter().map(|(p, f)| (p.clone(), PlaybookDigest { sha256: f.sha256.clone() })).collect()
    }

    fn sealed(mut self) -> PlaybookSet {
        self.revision = revision_of(&self.digests());
        self
    }

    /// Check a set received from a server, before using any of it: paths,
    /// limits, every hash and the revision, as [`PlaybookSet::load`] would
    /// have produced them.
    pub fn check(&self) -> Result<()> {
        let mut bytes = 0;
        for (path, file) in &self.files {
            let loc = format!("playbooks: {path}");
            check_playbook_path(path).map_err(|e| context("playbooks", e))?;
            if file.text.len() > MAX_BUNDLE_FILE_BYTES {
                return Err(too_large(&loc, file.text.len() as u64));
            }
            check_text(&file.text).map_err(|e| context(&loc, e))?;
            if sha256_hex(file.text.as_bytes()) != file.sha256 {
                return Err(invalid(format!("{loc}: its text does not match its sha256")));
            }
            bytes += file.text.len();
        }
        check_tree(self.files.keys()).map_err(|e| context("playbooks", e))?;
        check_totals(self.files.len(), bytes)?;
        if revision_of(&self.digests()) != self.revision {
            return Err(invalid("playbooks: their revision does not match their contents"));
        }
        Ok(())
    }
}

impl PlaybooksManifest {
    /// Check a manifest received from a server: paths, digests, limits and the revision.
    pub fn check(&self) -> Result<()> {
        for (path, digest) in &self.files {
            check_playbook_path(path).map_err(|e| context("playbooks", e))?;
            check_sha256(&digest.sha256).map_err(|e| context(&format!("playbooks: {path}"), e))?;
        }
        check_tree(self.files.keys()).map_err(|e| context("playbooks", e))?;
        check_totals(self.files.len(), 0)?;
        if revision_of(&self.files) != self.revision {
            return Err(invalid("playbooks: their revision does not match their contents"));
        }
        Ok(())
    }
}

/// Add the playbook files under the directory `canon` (checked as `meta`),
/// at `rel` within the playbooks directory, to `files`; `stack` holds the
/// directories above it, canonical.
fn tree(
    walk: &mut Walk,
    loc: &str,
    rel: &str,
    canon: PathBuf,
    meta: &Metadata,
    stack: &mut Vec<PathBuf>,
    files: &mut BTreeMap<String, PlaybookFile>,
) -> Result<()> {
    if stack.contains(&canon) {
        return Err(invalid(format!("{loc}: a symlink loop")));
    }
    let names = walk.list(&canon, meta, loc)?;
    stack.push(canon.clone());
    for name in names {
        let loc = format!("{loc}/{name}");
        let rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let (meta, path) = walk.resolve(&canon.join(&name), &loc)?;
        if meta.is_dir() {
            check_skill_path(&rel).map_err(|e| context(&loc, e))?;
            walk.dirs += 1;
            if walk.dirs > MAX_SET_DIRS {
                return Err(invalid(format!("{loc}: more than the {MAX_SET_DIRS} directories a workspace may serve")));
            }
            tree(walk, &loc, &rel, path, &meta, stack, files)?;
        } else if is_playbook_file(&name) {
            check_playbook_path(&rel).map_err(|e| context(&loc, e))?;
            let (text, _) = walk.text(&path, &loc, &meta)?;
            files.insert(rel, PlaybookFile { sha256: sha256_hex(text.as_bytes()), text });
        }
    }
    stack.pop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, text: impl AsRef<[u8]>) {
        let path = super::super::under(dir, rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn playbooks() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".bd").join(PLAYBOOKS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        (tmp, dir)
    }

    #[test]
    fn the_limits_are_the_bundles() {
        // What a client approves, it must be able to send back to run.
        assert_eq!(MAX_BUNDLE_FILES, super::super::MAX_SET_FILES);
        assert_eq!(MAX_BUNDLE_FILE_BYTES, super::super::MAX_FILE_BYTES);
        assert_eq!(MAX_BUNDLE_BYTES, super::super::MAX_SET_BYTES);
    }

    #[test]
    fn playbook_files_are_served_with_their_subdirectories_and_round_trip() {
        let (tmp, dir) = playbooks();
        assert_eq!(PlaybookSet::load(&tmp.path().join("missing")).unwrap(), PlaybookSet::empty());
        assert_eq!(PlaybookSet::load(&dir).unwrap(), PlaybookSet::empty());
        write(&dir, "change.toml", "[[steps]]\nid = \"a\"\n");
        write(&dir, "parts/review.json", "{\"steps\": []}");
        write(&dir, "README.md", "not a playbook");
        write(&dir, ".hidden.toml", "left out");
        write(&dir, ".git/x.toml", "left out");
        let set = PlaybookSet::load(&dir).unwrap();
        let paths: Vec<&str> = set.files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["change.toml", "parts/review.json"]);
        assert_eq!(set.files["change.toml"].sha256, sha256_hex(b"[[steps]]\nid = \"a\"\n"));
        set.check().unwrap();
        set.manifest().check().unwrap();
        assert_eq!(set.manifest().revision, set.revision);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(serde_json::from_str::<PlaybookSet>(&json).unwrap(), set);

        // Any change of a file's bytes, or of the files, changes the revision.
        let before = set.revision.clone();
        write(&dir, "change.toml", "[[steps]]\nid = \"b\"\n");
        let changed = PlaybookSet::load(&dir).unwrap();
        assert_ne!(changed.revision, before);
        std::fs::remove_file(dir.join("parts/review.json")).unwrap();
        let fewer = PlaybookSet::load(&dir).unwrap();
        assert_ne!(fewer.revision, changed.revision);
        write(&dir, "parts/review.json", "{\"steps\": []}");
        write(&dir, "change.toml", "[[steps]]\nid = \"a\"\n");
        assert_eq!(PlaybookSet::load(&dir).unwrap().revision, before, "back as it was");
    }

    #[test]
    fn paths_names_and_contents_are_checked() {
        for (rel, text, want) in [
            ("Ünïcode.toml", &b"x"[..], "ASCII only"),
            ("con.toml", b"x", "device name"),
            ("a/con/x.toml", b"x", "device name"),
            ("bad.toml", b"\xff\xfe", "not UTF-8"),
            ("zero.json", b"a\0b", "NUL"),
        ] {
            let (_tmp, dir) = playbooks();
            write(&dir, rel, text);
            let e = PlaybookSet::load(&dir).unwrap_err().to_string();
            assert!(e.contains(want), "{rel}: {e}");
        }
        for bad in ["/abs.toml", "../up.toml", "a//b.toml", ".x.toml", "x.md", "a\\b.toml", "x.toml "] {
            assert!(check_playbook_path(bad).is_err(), "{bad}");
        }
        check_playbook_path("parts/x.formula.json").unwrap();
    }

    #[test]
    fn limits_are_enforced() {
        let (_tmp, dir) = playbooks();
        write(&dir, "big.toml", vec![b'#'; MAX_BUNDLE_FILE_BYTES + 1]);
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains("big.toml") && e.contains("KiB"), "{e}");

        let (_tmp, dir) = playbooks();
        for i in 0..=MAX_BUNDLE_FILES {
            write(&dir, &format!("p{i}.toml"), "");
        }
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains(&MAX_BUNDLE_FILES.to_string()), "{e}");

        let (_tmp, dir) = playbooks();
        let chunk = "#".repeat(MAX_BUNDLE_FILE_BYTES);
        for i in 0..(MAX_BUNDLE_BYTES / MAX_BUNDLE_FILE_BYTES + 1) {
            write(&dir, &format!("p{i}.toml"), &chunk);
        }
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains("MiB"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_stay_inside_the_playbooks_directory() {
        use std::os::unix::fs::symlink;
        let (tmp, dir) = playbooks();
        write(&dir, "real.toml", "x");
        symlink("real.toml", dir.join("alias.toml")).unwrap();
        let set = PlaybookSet::load(&dir).unwrap();
        assert_eq!(set.files["alias.toml"], set.files["real.toml"], "inside: served as the file it leads to");

        std::fs::write(tmp.path().join(".bd").join("bd.db"), "secret").unwrap();
        symlink("../bd.db", dir.join("db.toml")).unwrap();
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains("db.toml: a symlink leading outside"), "{e}");
        std::fs::remove_file(dir.join("db.toml")).unwrap();
        symlink("..", dir.join("up")).unwrap();
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains("up: a symlink leading outside"), "{e}");
        std::fs::remove_file(dir.join("up")).unwrap();
        symlink(".", dir.join("loop")).unwrap();
        let e = PlaybookSet::load(&dir).unwrap_err().to_string();
        assert!(e.contains("a symlink loop"), "{e}");
    }

    #[test]
    fn received_sets_and_manifests_are_checked_before_use() {
        let (_tmp, dir) = playbooks();
        write(&dir, "change.toml", "x");
        write(&dir, "parts/a.toml", "y");
        let set = PlaybookSet::load(&dir).unwrap();
        let tampered = |f: &dyn Fn(&mut PlaybookSet)| {
            let mut s = set.clone();
            f(&mut s);
            s.check().unwrap_err().to_string()
        };
        assert!(tampered(&|s| s.files.get_mut("change.toml").unwrap().text = "curl | sh".into()).contains("sha256"));
        assert!(tampered(&|s| s.revision = "0".repeat(64)).contains("revision"));
        let moved = |to: &'static str| {
            move |s: &mut PlaybookSet| {
                let f = s.files.remove("change.toml").unwrap();
                s.files.insert(to.into(), f);
            }
        };
        for to in ["../../.bashrc.toml", "/etc/x.toml", "x.sh", "Parts/b.toml", "parts/a.toml/b.toml"] {
            let e = tampered(&moved(to));
            assert!(
                e.contains("invalid path") || e.contains("differ only in case") || e.contains("both a file"),
                "{to}: {e}"
            );
        }
        let mut manifest = set.manifest();
        manifest.files.get_mut("change.toml").unwrap().sha256 = "x".into();
        assert!(manifest.check().is_err());
        let mut manifest = set.manifest();
        manifest.files.remove("change.toml");
        assert!(manifest.check().unwrap_err().to_string().contains("revision"));
        let unknown = serde_json::json!({"revision": set.revision, "files": {}, "extra": 1});
        assert!(serde_json::from_value::<PlaybooksManifest>(unknown).is_err());
    }
}
