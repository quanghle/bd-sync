//! Harness sets: read from disk, checked, and sent whole or as a manifest.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::mcp::{McpServer, canonical_json, check_definition, check_server_name, mcp_digest, parse_mcp};
use super::{
    Harness, MAX_FILE_BYTES, MAX_MCP_SERVERS, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH, MAX_SET_BYTES,
    MAX_SET_DIRS, MAX_SET_FILES, McpFormat, SKILL_FILE, SKILLS_DIR, check_sha256, context, invalid, lf_sha256,
    sha256_hex,
};
use crate::error::{Error, Result};

/// A skill's files, by their `/`-separated path within the skill.
type SkillFiles<T> = BTreeMap<String, T>;

/// One harness's set, whole: what `bd agents fetch` prints.
///
/// ```json
/// {
///   "harness": "codex",
///   "revision": "<sha256>",
///   "skills": {
///     "deploy": {
///       "SKILL.md": {"sha256": "<sha256>", "text": "---\nname: deploy\n..."},
///       "scripts/run.sh": {"sha256": "<sha256>", "executable": true, "text": "#!/bin/sh\n..."}
///     }
///   },
///   "mcp_servers": {
///     "github": {
///       "sha256": "<sha256>",
///       "definition": {"command": "npx", "args": ["-y", "server-github"], "env_vars": ["GITHUB_TOKEN"]},
///       "toml": "[mcp_servers.github]\ncommand = \"npx\"\n..."
///     }
///   }
/// }
/// ```
///
/// Skills are keyed by name, then by the `/`-separated path of each file
/// within the skill. Its [`Manifest`] is the same without the contents
/// (`text`, `definition`, `toml`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSet {
    pub harness: Harness,
    /// The [`Manifest`]'s revision.
    pub revision: String,
    pub skills: BTreeMap<String, SkillFiles<SkillFile>>,
    pub mcp_servers: BTreeMap<String, McpServer>,
}

/// One file of a skill, as `bd agents fetch` sends it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillFile {
    /// SHA-256 of `text`.
    pub sha256: String,
    /// Executable on the server (a script). Servers on Windows never set it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
    pub text: String,
}

/// One harness's set without its contents: what `bd agents manifest` prints for it.
///
/// ```json
/// {
///   "harness": "codex",
///   "revision": "<sha256>",
///   "skills": {
///     "deploy": {"SKILL.md": {"sha256": "<sha256>"}, "scripts/run.sh": {"sha256": "<sha256>", "executable": true}}
///   },
///   "mcp_servers": {"github": {"sha256": "<sha256>"}}
/// }
/// ```
///
/// A skill file with CRLF line endings also has `lf_sha256`, the SHA-256
/// of its text with them as LF ([`lf_sha256`]).
///
/// The revision is the SHA-256 of the [`canonical_json`] of
/// `{"mcp_servers": ..., "skills": ...}`, as shown here: any change to a
/// skill file, its executable bit, or an MCP definition changes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub harness: Harness,
    pub revision: String,
    pub skills: BTreeMap<String, SkillFiles<FileDigest>>,
    pub mcp_servers: BTreeMap<String, McpDigest>,
}

/// A skill file in a [`Manifest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigest {
    pub sha256: String,
    /// [`lf_sha256`] of its text, which has CRLF line endings: what a
    /// client compares its file with, line endings aside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lf_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
}

/// An MCP server entry in a [`Manifest`]: [`mcp_digest`] of its definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpDigest {
    pub sha256: String,
}

type Digests = (BTreeMap<String, SkillFiles<FileDigest>>, BTreeMap<String, McpDigest>);

fn revision_of((skills, mcp_servers): &Digests) -> String {
    sha256_hex(canonical_json(&json!({ "skills": skills, "mcp_servers": mcp_servers })).as_bytes())
}

impl AgentSet {
    /// What a harness without a set gets.
    pub fn empty(harness: Harness) -> AgentSet {
        AgentSet { harness, revision: String::new(), skills: BTreeMap::new(), mcp_servers: BTreeMap::new() }.sealed()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty() && self.mcp_servers.is_empty()
    }

    /// Read `harness`'s set from `agents_dir` (a workspace's `.bd/agents`),
    /// strictly (see the [module docs](super)). A harness without a
    /// directory there has an empty set.
    pub fn load(agents_dir: &Path, harness: Harness) -> Result<AgentSet> {
        let base = label_of(agents_dir);
        let loc = format!("{base}/{harness}");
        let dir = agents_dir.join(harness.name());
        if let Err(e) = std::fs::symlink_metadata(&dir) {
            return match e.kind() {
                std::io::ErrorKind::NotFound => Ok(AgentSet::empty(harness)),
                _ => Err(io_error(&loc, &e)),
            };
        }
        let root = std::fs::canonicalize(agents_dir).map_err(|e| io_error(&base, &e))?;
        let mut walk = Walk { root: root.clone(), base, files: 0, dirs: 0, bytes: 0 };
        let (meta, canon) = walk.resolve(&dir, &loc)?;
        if !meta.is_dir() {
            return Err(invalid(format!(
                "{loc}: not a directory (a set is a directory holding {SKILLS_DIR}/ and {})",
                harness.mcp_file()
            )));
        }
        let mut set = AgentSet::empty(harness);
        for name in walk.list(&canon, &meta, &loc)? {
            let path = canon.join(&name);
            let loc = format!("{loc}/{name}");
            if name == SKILLS_DIR {
                let (meta, skills) = walk.resolve(&path, &loc)?;
                if !meta.is_dir() {
                    return Err(invalid(format!("{loc}: not a directory (it holds one directory per skill)")));
                }
                let mut stack = vec![root.clone(), canon.clone(), skills.clone()];
                set.skills = walk.skills(&skills, &meta, &loc, &mut stack)?;
            } else if name == harness.mcp_file() {
                let (meta, file) = walk.resolve(&path, &loc)?;
                let (text, _) = walk.text(&file, &loc, &meta)?;
                set.mcp_servers = parse_mcp(harness, &text, &loc)?;
            } else {
                return Err(invalid(format!(
                    "{loc}: unexpected here: a {harness} set holds {SKILLS_DIR}/ and {} only",
                    harness.mcp_file()
                )));
            }
        }
        Ok(set.sealed())
    }

    /// The set without its contents.
    pub fn manifest(&self) -> Manifest {
        let (skills, mcp_servers) = self.digests();
        Manifest { harness: self.harness, revision: self.revision.clone(), skills, mcp_servers }
    }

    /// Check a set received from a server, before writing any of it: names,
    /// paths, limits, every hash and the revision, as [`AgentSet::load`]
    /// would have produced them.
    pub fn check(&self) -> Result<()> {
        let set = format!("{} set", self.harness);
        let (mut files, mut bytes) = (0, 0);
        for (name, skill) in &self.skills {
            check_skill_name(name).map_err(|e| context(&set, e))?;
            let loc = format!("{set}: skill {name}");
            for (path, file) in skill {
                let loc = format!("{loc}: {path}");
                check_skill_path(path).map_err(|e| context(&loc, e))?;
                if file.text.len() > MAX_FILE_BYTES {
                    return Err(too_large(&loc, file.text.len() as u64));
                }
                check_text(&file.text).map_err(|e| context(&loc, e))?;
                if sha256_hex(file.text.as_bytes()) != file.sha256 {
                    return Err(invalid(format!("{loc}: its text does not match its sha256")));
                }
                files += 1;
                bytes += file.text.len();
            }
            check_skill_files(skill.keys()).map_err(|e| context(&loc, e))?;
        }
        check_totals(&set, files, bytes, self.mcp_servers.len())?;
        for (name, server) in &self.mcp_servers {
            check_server_name(name).map_err(|e| context(&set, e))?;
            let loc = format!("{set}: MCP server {name}");
            check_definition(&server.definition).map_err(|e| context(&loc, e))?;
            if mcp_digest(&server.definition) != server.sha256 {
                return Err(invalid(format!("{loc}: its definition does not match its sha256")));
            }
            match (self.harness.mcp_format(), &server.toml) {
                (McpFormat::Json, None) => {}
                (McpFormat::Toml, Some(text)) => {
                    let parsed = parse_mcp(self.harness, text, &format!("{loc}: toml"))?;
                    if parsed.len() != 1 || parsed.get(name).is_none_or(|p| p.definition != server.definition) {
                        return Err(invalid(format!("{loc}: its TOML table does not match its definition")));
                    }
                }
                (McpFormat::Toml, None) => return Err(invalid(format!("{loc}: no TOML table"))),
                (McpFormat::Json, Some(_)) => return Err(invalid(format!("{loc}: a TOML table for a JSON harness"))),
            }
        }
        if revision_of(&self.digests()) != self.revision {
            return Err(invalid(format!("{set}: its revision does not match its contents")));
        }
        Ok(())
    }

    fn digests(&self) -> Digests {
        let skills = self
            .skills
            .iter()
            .map(|(name, files)| {
                let files = files.iter().map(|(path, f)| {
                    let digest = FileDigest {
                        sha256: f.sha256.clone(),
                        lf_sha256: lf_sha256(&f.text),
                        executable: f.executable,
                    };
                    (path.clone(), digest)
                });
                (name.clone(), files.collect())
            })
            .collect();
        let mcp = self.mcp_servers.iter().map(|(n, s)| (n.clone(), McpDigest { sha256: s.sha256.clone() })).collect();
        (skills, mcp)
    }

    fn sealed(mut self) -> AgentSet {
        self.revision = revision_of(&self.digests());
        self
    }
}

impl Manifest {
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty() && self.mcp_servers.is_empty()
    }

    /// Check a manifest received from a server: names, paths, digests, limits and the revision.
    pub fn check(&self) -> Result<()> {
        let set = format!("{} set", self.harness);
        let mut files = 0;
        for (name, skill) in &self.skills {
            check_skill_name(name).map_err(|e| context(&set, e))?;
            let loc = format!("{set}: skill {name}");
            for (path, digest) in skill {
                let loc = format!("{loc}: {path}");
                check_skill_path(path).map_err(|e| context(&loc, e))?;
                check_sha256(&digest.sha256).map_err(|e| context(&loc, e))?;
                if let Some(lf) = &digest.lf_sha256 {
                    check_sha256(lf).map_err(|e| context(&format!("{loc}: lf_sha256"), e))?;
                }
            }
            check_skill_files(skill.keys()).map_err(|e| context(&loc, e))?;
            files += skill.len();
        }
        check_totals(&set, files, 0, self.mcp_servers.len())?;
        for (name, digest) in &self.mcp_servers {
            check_server_name(name).map_err(|e| context(&set, e))?;
            check_sha256(&digest.sha256).map_err(|e| context(&format!("{set}: MCP server {name}"), e))?;
        }
        if revision_of(&(self.skills.clone(), self.mcp_servers.clone())) != self.revision {
            return Err(invalid(format!("{set}: its revision does not match its contents")));
        }
        Ok(())
    }
}

fn check_totals(set: &str, files: usize, bytes: usize, servers: usize) -> Result<()> {
    if files > MAX_SET_FILES {
        return Err(invalid(format!("{set}: {files} files is more than the {MAX_SET_FILES} a set may hold")));
    }
    if bytes > MAX_SET_BYTES {
        return Err(invalid(format!("{set}: more than the {} MiB of text a set may hold", MAX_SET_BYTES >> 20)));
    }
    if servers > MAX_MCP_SERVERS {
        return Err(invalid(format!("{set}: {servers} MCP servers is more than the {MAX_MCP_SERVERS} a set may hold")));
    }
    Ok(())
}

/// A skill name, which is also its directory's: lowercase letters, digits,
/// `-`, `_` and `.`, starting with a letter or digit, not ending with `.`,
/// and not a device name on Windows.
pub fn check_skill_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
        && !name.ends_with('.');
    if !valid {
        return Err(invalid(format!(
            "invalid skill name {name:?}: lowercase letters, digits, '-', '_' and '.', starting with a letter or \
             digit, at most {MAX_NAME_BYTES} characters"
        )));
    }
    if device_name(name) {
        return Err(invalid(format!("invalid skill name {name:?}: a device name on Windows")));
    }
    Ok(())
}

/// The path of a file within its skill: relative and `/`-separated, at most
/// [`MAX_PATH_DEPTH`] components and [`MAX_PATH_BYTES`] bytes, each
/// component a name every client's file system holds as it is, and none
/// hidden (which also rules out `.` and `..`). Components are ASCII only:
/// file systems that ignore case fold and normalize other characters each
/// their own way, while ASCII names differing only in case are told apart
/// exactly.
pub fn check_skill_path(path: &str) -> Result<()> {
    let refuse = |why: String| Err(invalid(format!("invalid path {path:?}: {why}")));
    if path.len() > MAX_PATH_BYTES {
        return refuse(format!("{} bytes is more than the {MAX_PATH_BYTES} allowed", path.len()));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_PATH_DEPTH {
        return refuse(format!("more than {MAX_PATH_DEPTH} levels deep"));
    }
    for part in parts {
        if part.is_empty() {
            return refuse("an empty component (an absolute path, or a doubled '/')".into());
        }
        if part.starts_with('.') {
            return refuse(format!("{part:?} starts with '.' (hidden files, '.' and '..' are not served)"));
        }
        if let Some(c) = part.chars().find(|c| !c.is_ascii()) {
            return refuse(format!(
                "{part:?} holds {c:?}: skill file names are ASCII only, so every client's file system compares \
                 them the same way"
            ));
        }
        let odd = part.chars().find(|&c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'));
        if let Some(c) = odd {
            return refuse(format!("{part:?} holds {c:?}, which not every client's file system allows"));
        }
        if part.ends_with([' ', '.']) {
            return refuse(format!("{part:?} ends with a space or '.', which Windows drops"));
        }
        if device_name(part) {
            return refuse(format!("{part:?} is a device name on Windows"));
        }
    }
    Ok(())
}

/// `CON`, `nul.txt`, `com0`, `LPT²`, `conin$`, ...: names Windows reserves,
/// in any case and with any extension.
fn device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end().to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            let mut chars = n.chars();
            matches!((chars.next(), chars.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
        })
    };
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") || numbered("COM") || numbered("LPT")
}

/// A skill's file paths: they include [`SKILL_FILE`], none is also a
/// directory on the way to another, and no two paths (or directories on
/// their way) differ only in case, which clients on case-insensitive file
/// systems could not hold both of. The paths have passed
/// [`check_skill_path`], so they are ASCII and comparing them in ASCII
/// lowercase is exact.
fn check_skill_files<'a>(paths: impl IntoIterator<Item = &'a String>) -> Result<()> {
    // Each path and directory on the way, by its ASCII lowercase form: as written, and whether it is a file.
    let mut seen: BTreeMap<String, (&str, bool)> = BTreeMap::new();
    let mut has_skill_file = false;
    for path in paths {
        has_skill_file |= path == SKILL_FILE;
        let ends = path.match_indices('/').map(|(i, _)| i).chain([path.len()]);
        for end in ends {
            let prefix = &path[..end];
            let file = end == path.len();
            match seen.entry(prefix.to_ascii_lowercase()) {
                Entry::Vacant(v) => {
                    v.insert((prefix, file));
                }
                Entry::Occupied(o) if o.get().0 != prefix => {
                    return Err(invalid(format!(
                        "{} and {prefix} differ only in case, which a client on a case-insensitive file system \
                         cannot hold both of",
                        o.get().0
                    )));
                }
                Entry::Occupied(o) if o.get().1 || file => {
                    return Err(invalid(format!(
                        "{prefix} is both a file and a directory holding other files, which no file system can hold"
                    )));
                }
                Entry::Occupied(_) => {}
            }
        }
    }
    if !has_skill_file {
        return Err(invalid(format!("no {SKILL_FILE} (each skill directory holds one)")));
    }
    Ok(())
}

/// Text a set may hold: no NUL characters, which only binary files have.
fn check_text(text: &str) -> Result<()> {
    if text.contains('\0') {
        return Err(invalid("holds NUL characters: not a text file (a set holds text files only)"));
    }
    Ok(())
}

fn too_large(loc: &str, bytes: u64) -> Error {
    invalid(format!(
        "{loc}: {} KiB is more than the {} KiB a file in a set may hold",
        bytes.div_ceil(1024),
        MAX_FILE_BYTES >> 10
    ))
}

fn io_error(loc: &str, e: &std::io::Error) -> Error {
    invalid(format!("{loc}: {e}"))
}

/// How errors name the agents directory: its last two components (`.bd/agents`).
fn label_of(dir: &Path) -> String {
    let mut parts: Vec<String> =
        dir.components().rev().take(2).map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    parts.reverse();
    parts.join("/")
}

#[cfg(unix)]
fn executable(meta: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &Metadata) -> bool {
    false
}

/// Whether `a` and `b` are the metadata of the same file.
#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Whether `a` and `b` are the metadata of the same file, as far as stable
/// std tells on Windows: it has no file IDs there (`MetadataExt::file_index`
/// is unstable), so a swap for a file with the same times, size and
/// attributes goes unnoticed.
#[cfg(windows)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    a.creation_time() == b.creation_time()
        && a.last_write_time() == b.last_write_time()
        && a.file_size() == b.file_size()
        && a.file_attributes() == b.file_attributes()
}

#[cfg(not(any(unix, windows)))]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.file_type() == b.file_type() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

fn changed(loc: &str) -> Error {
    invalid(format!("{loc}: changed while the set was being read (replaced by a symlink or another file)"))
}

/// Where the open `file` really is, from the kernel: what a swap of a
/// directory above it for a symlink cannot hide. `None` without `/proc`.
#[cfg(target_os = "linux")]
fn opened_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

/// One read of a set from disk, with what it has read so far.
struct Walk {
    /// The agents directory, canonical: nothing outside it is read.
    root: PathBuf,
    /// How errors name it.
    base: String,
    files: usize,
    dirs: usize,
    bytes: usize,
}

impl Walk {
    /// What `path` leads to (following symlinks), which must be inside the
    /// agents directory: its metadata and its canonical path, which is all
    /// the walk uses from then on.
    fn resolve(&self, path: &Path, loc: &str) -> Result<(Metadata, PathBuf)> {
        let canon = std::fs::canonicalize(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => invalid(format!("{loc}: a symlink to nothing")),
            _ => io_error(loc, &e),
        })?;
        if !canon.starts_with(&self.root) {
            return Err(self.outside(loc));
        }
        // A canonical path ends in no symlink, unless one was swapped in since.
        let meta = std::fs::symlink_metadata(&canon).map_err(|e| io_error(loc, &e))?;
        if meta.file_type().is_symlink() {
            return Err(changed(loc));
        }
        Ok((meta, canon))
    }

    fn outside(&self, loc: &str) -> Error {
        invalid(format!("{loc}: a symlink leading outside {}; a set holds only what is inside it", self.base))
    }

    /// Open `canon`, checked by [`Walk::resolve`] as `meta`: without
    /// following a symlink swapped in there, nor blocking on a FIFO, and
    /// only if it is still the file that was checked, inside the agents
    /// directory. Returns the open file's own metadata.
    fn open(&self, canon: &Path, meta: &Metadata, loc: &str) -> Result<(File, Metadata)> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(canon).map_err(|e| {
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return changed(loc);
            }
            io_error(loc, &e)
        })?;
        let opened = file.metadata().map_err(|e| io_error(loc, &e))?;
        if !same_file(meta, &opened) {
            return Err(changed(loc));
        }
        #[cfg(target_os = "linux")]
        if opened_path(&file).is_some_and(|real| !real.starts_with(&self.root)) {
            return Err(self.outside(loc));
        }
        self.recheck(canon, &opened, loc)?;
        Ok((file, opened))
    }

    /// Fail unless `canon` still leads, through no symlink, to the file whose metadata is `meta`.
    fn recheck(&self, canon: &Path, meta: &Metadata, loc: &str) -> Result<()> {
        let now = std::fs::canonicalize(canon).ok();
        let again = std::fs::symlink_metadata(canon).ok();
        if now.as_deref() != Some(canon) || !again.is_some_and(|m| same_file(&m, meta)) {
            return Err(changed(loc));
        }
        Ok(())
    }

    /// The names in the directory `canon`, checked by [`Walk::resolve`] as
    /// `meta`, sorted, without hidden ones.
    fn list(&self, canon: &Path, meta: &Metadata, loc: &str) -> Result<Vec<String>> {
        #[cfg(unix)]
        {
            let (dir, opened) = self.open(canon, meta, loc)?;
            if !opened.is_dir() {
                return Err(changed(loc));
            }
            // List the open directory itself, which a later swap cannot redirect.
            #[cfg(target_os = "linux")]
            if opened_path(&dir).is_some() {
                use std::os::fd::AsRawFd;
                return self.entries(Path::new(&format!("/proc/self/fd/{}", dir.as_raw_fd())), loc);
            }
            drop(dir);
        }
        let names = self.entries(canon, loc)?;
        self.recheck(canon, meta, loc)?;
        Ok(names)
    }

    /// The names in `dir`, sorted, without hidden ones.
    fn entries(&self, dir: &Path, loc: &str) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| io_error(loc, &e))? {
            let name = entry.map_err(|e| io_error(loc, &e))?.file_name();
            let name = name
                .into_string()
                .map_err(|n| invalid(format!("{loc}/{}: a file name that is not UTF-8", n.to_string_lossy())))?;
            if name.starts_with('.') {
                continue;
            }
            if names.len() == MAX_SET_FILES {
                return Err(invalid(format!("{loc}: more than the {MAX_SET_FILES} entries a set may hold")));
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }

    /// The skills in the directory `dir` (canonical, checked as `meta`);
    /// `stack` holds the directories above it, canonical.
    fn skills(
        &mut self,
        dir: &Path,
        meta: &Metadata,
        loc: &str,
        stack: &mut Vec<PathBuf>,
    ) -> Result<BTreeMap<String, SkillFiles<SkillFile>>> {
        let mut skills = BTreeMap::new();
        for name in self.list(dir, meta, loc)? {
            let loc = format!("{loc}/{name}");
            check_skill_name(&name).map_err(|e| context(&loc, e))?;
            let (meta, canon) = self.resolve(&dir.join(&name), &loc)?;
            if !meta.is_dir() {
                return Err(invalid(format!(
                    "{loc}: not a directory (each skill is a directory holding {SKILL_FILE})"
                )));
            }
            let mut files = BTreeMap::new();
            self.subdir(&loc, "", canon, &meta, stack, &mut files)?;
            check_skill_files(files.keys()).map_err(|e| context(&loc, e))?;
            skills.insert(name, files);
        }
        Ok(skills)
    }

    /// Add the files under the directory `canon` (checked as `meta`), at
    /// `rel` within its skill, to `files`.
    fn subdir(
        &mut self,
        loc: &str,
        rel: &str,
        canon: PathBuf,
        meta: &Metadata,
        stack: &mut Vec<PathBuf>,
        files: &mut SkillFiles<SkillFile>,
    ) -> Result<()> {
        if stack.contains(&canon) {
            return Err(invalid(format!("{loc}: a symlink loop")));
        }
        let names = self.list(&canon, meta, loc)?;
        stack.push(canon.clone());
        for name in names {
            let loc = format!("{loc}/{name}");
            let rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            check_skill_path(&rel).map_err(|e| context(&loc, e))?;
            let (meta, path) = self.resolve(&canon.join(&name), &loc)?;
            if meta.is_dir() {
                self.dirs += 1;
                if self.dirs > MAX_SET_DIRS {
                    return Err(invalid(format!("{loc}: more than the {MAX_SET_DIRS} directories a set may hold")));
                }
                self.subdir(&loc, &rel, path, &meta, stack, files)?;
            } else {
                let (text, opened) = self.text(&path, &loc, &meta)?;
                files.insert(
                    rel,
                    SkillFile { sha256: sha256_hex(text.as_bytes()), executable: executable(&opened), text },
                );
            }
        }
        stack.pop();
        Ok(())
    }

    /// The text of the file `canon` (checked as `meta`), within the limits,
    /// and the open file's metadata.
    fn text(&mut self, canon: &Path, loc: &str, meta: &Metadata) -> Result<(String, Metadata)> {
        if !meta.is_file() {
            return Err(invalid(format!("{loc}: not a regular file")));
        }
        self.files += 1;
        if self.files > MAX_SET_FILES {
            return Err(invalid(format!("{loc}: more than the {MAX_SET_FILES} files a set may hold")));
        }
        let (file, opened) = self.open(canon, meta, loc)?;
        if !opened.is_file() {
            return Err(invalid(format!("{loc}: not a regular file")));
        }
        if opened.len() > MAX_FILE_BYTES as u64 {
            return Err(too_large(loc, opened.len()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| io_error(loc, &e))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(too_large(loc, bytes.len() as u64));
        }
        self.bytes += bytes.len();
        if self.bytes > MAX_SET_BYTES {
            return Err(invalid(format!(
                "{loc}: the set holds more than the {} MiB of text a set may hold",
                MAX_SET_BYTES >> 20
            )));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| invalid(format!("{loc}: not UTF-8 text (a set holds text files only)")))?;
        check_text(&text).map_err(|e| context(loc, e))?;
        Ok((text, opened))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, text: impl AsRef<[u8]>) {
        let path = super::super::under(dir, rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A workspace's `.bd/agents`, in a temp dir.
    fn agents() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".bd").join("agents");
        std::fs::create_dir_all(&dir).unwrap();
        (tmp, dir)
    }

    fn load_err(dir: &Path, harness: Harness) -> String {
        AgentSet::load(dir, harness).unwrap_err().to_string()
    }

    /// What a case is, the files it writes, and the error it expects.
    type Layout = (&'static str, &'static [(&'static str, &'static [u8])], &'static str);
    type Tamper<'a> = Box<dyn Fn(&mut AgentSet) + 'a>;

    const SKILL: &str = "---\nname: deploy\ndescription: Deploy the service\n---\nRun scripts/run.sh.\n";
    const MCP_JSON: &str = r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github"],
        "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}"#;

    #[test]
    fn a_set_is_read_as_it_is_and_round_trips() {
        let (_tmp, dir) = agents();
        write(&dir, "claude/skills/deploy/SKILL.md", SKILL);
        write(&dir, "claude/skills/deploy/scripts/run.sh", "#!/bin/sh\necho deploy\r\n");
        write(&dir, "claude/skills/deploy/reference/notes/deep.md", "# Notes\n");
        write(&dir, "claude/skills/triage/SKILL.md", "---\nname: triage\n---\n");
        write(&dir, "claude/mcp.json", MCP_JSON);
        // Hidden entries are ignored, binary or not.
        write(&dir, "claude/.DS_Store", [0u8, 0xff, 0xfe]);
        write(&dir, "claude/skills/.git/HEAD", "ref: main\n");
        write(&dir, "claude/skills/deploy/.SKILL.md.swp", [0u8, 1, 2]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let script = dir.join("claude/skills/deploy/scripts/run.sh");
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let set = AgentSet::load(&dir, Harness::Claude).unwrap();
        assert_eq!(set.harness, Harness::Claude);
        assert_eq!(set.skills.keys().collect::<Vec<_>>(), ["deploy", "triage"]);
        let deploy = &set.skills["deploy"];
        assert_eq!(deploy.keys().collect::<Vec<_>>(), ["SKILL.md", "reference/notes/deep.md", "scripts/run.sh"]);
        assert_eq!(deploy["SKILL.md"].text, SKILL);
        assert_eq!(deploy["scripts/run.sh"].text, "#!/bin/sh\necho deploy\r\n", "verbatim, line endings too");
        assert_eq!(deploy["SKILL.md"].sha256, sha256_hex(SKILL.as_bytes()));
        assert_eq!(deploy["scripts/run.sh"].executable, cfg!(unix));
        let manifest = set.manifest();
        let lf = |path: &str| manifest.skills["deploy"][path].lf_sha256.clone();
        assert_eq!(lf("scripts/run.sh"), Some(sha256_hex(b"#!/bin/sh\necho deploy\n")), "its text as LF");
        assert_eq!(lf("SKILL.md"), None, "LF already");
        assert!(!deploy["SKILL.md"].executable);
        assert_eq!(set.mcp_servers.keys().collect::<Vec<_>>(), ["github"]);
        assert_eq!(set.mcp_servers["github"].definition["env"]["GITHUB_TOKEN"], "${GITHUB_TOKEN}");
        set.check().unwrap();

        let manifest = set.manifest();
        manifest.check().unwrap();
        assert_eq!(manifest.revision, set.revision);
        assert_eq!(manifest.skills["deploy"]["SKILL.md"].sha256, deploy["SKILL.md"].sha256);
        assert_eq!(manifest.mcp_servers["github"].sha256, set.mcp_servers["github"].sha256);
        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["harness"], "claude");
        assert_eq!(json["skills"]["triage"]["SKILL.md"], json!({ "sha256": sha256_hex(b"---\nname: triage\n---\n") }));
        assert_eq!(
            json["revision"],
            sha256_hex(
                canonical_json(&json!({"skills": json["skills"], "mcp_servers": json["mcp_servers"]})).as_bytes()
            ),
            "the revision is the hash of the manifest's entries"
        );
        let sent: AgentSet = serde_json::from_str(&serde_json::to_string(&set).unwrap()).unwrap();
        assert_eq!(sent, set);
        let sent: Manifest = serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_eq!(sent, manifest);

        // The other harnesses have no set: an empty one each, the same for all.
        for h in [Harness::Codex, Harness::Copilot] {
            let other = AgentSet::load(&dir, h).unwrap();
            assert!(other.is_empty() && other.harness == h, "{h}");
            assert_eq!(other.revision, AgentSet::empty(Harness::Claude).revision);
            other.check().unwrap();
        }
        assert!(AgentSet::load(&dir.join("missing"), Harness::Claude).unwrap().is_empty());
    }

    #[test]
    fn the_revision_follows_content_but_not_formatting() {
        let (_tmp, dir) = agents();
        write(&dir, "codex/skills/deploy/SKILL.md", SKILL);
        write(&dir, "codex/mcp.toml", "[mcp_servers.github]\ncommand = \"npx\"\nargs = [\"-y\", \"server-github\"]\n");
        let first = AgentSet::load(&dir, Harness::Codex).unwrap();
        first.check().unwrap();
        assert!(first.mcp_servers["github"].toml.as_deref().unwrap().starts_with("[mcp_servers.github]"));

        write(
            &dir,
            "codex/mcp.toml",
            "# reformatted\n[mcp_servers]\ngithub = { args = [ \"-y\", \"server-github\" ], command = 'npx' }\n",
        );
        let reformatted = AgentSet::load(&dir, Harness::Codex).unwrap();
        assert_eq!(reformatted, first, "a formatting-only edit is no change");

        write(
            &dir,
            "codex/mcp.toml",
            "[mcp_servers.github]\ncommand = \"npx\"\nargs = [\"-y\", \"server-github@2\"]\n",
        );
        let changed = AgentSet::load(&dir, Harness::Codex).unwrap();
        assert_ne!(changed.mcp_servers["github"].sha256, first.mcp_servers["github"].sha256);
        assert_ne!(changed.revision, first.revision);

        write(&dir, "codex/skills/deploy/SKILL.md", format!("{SKILL}More.\n"));
        let edited = AgentSet::load(&dir, Harness::Codex).unwrap();
        assert_ne!(edited.revision, changed.revision);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let skill = dir.join("codex/skills/deploy/SKILL.md");
            std::fs::set_permissions(skill, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_ne!(AgentSet::load(&dir, Harness::Codex).unwrap().revision, edited.revision, "the mode counts");
        }
    }

    #[test]
    fn invalid_layouts_are_refused_naming_the_file() {
        let cases: &[Layout] = &[
            (
                "no SKILL.md",
                &[("claude/skills/deploy/README.md", b"x")],
                ".bd/agents/claude/skills/deploy: no SKILL.md",
            ),
            ("skill.md", &[("claude/skills/deploy/skill.md", b"x")], "deploy: no SKILL.md"),
            ("empty skill", &[("claude/skills/deploy/sub/x.md", b"x")], "deploy: no SKILL.md"),
            ("loose file", &[("claude/skills/notes.md", b"x")], "skills/notes.md: not a directory"),
            ("skills file", &[("claude/skills", b"x")], ".bd/agents/claude/skills: not a directory"),
            ("set file", &[("claude", b"x")], ".bd/agents/claude: not a directory"),
            ("unknown entry", &[("claude/README.md", b"x")], "claude/README.md: unexpected here"),
            ("other format", &[("codex/mcp.json", b"{}")], "codex/mcp.json: unexpected here"),
            ("uppercase", &[("claude/skills/Deploy/SKILL.md", b"x")], "invalid skill name \"Deploy\""),
            ("not UTF-8", &[("claude/skills/a/SKILL.md", b"\xff\xfe x")], "skills/a/SKILL.md: not UTF-8 text"),
            ("NUL", &[("claude/skills/a/SKILL.md", b"a\0b")], "skills/a/SKILL.md: holds NUL characters"),
            (
                "MCP keys",
                &[("copilot/mcp.json", br#"{"mcpServers": {}, "hooks": {}}"#)],
                "copilot/mcp.json: unknown key \"hooks\"",
            ),
            ("MCP UTF-8", &[("copilot/mcp.json", b"{\"mcpServers\": {\"\xff\": {}}}")], "copilot/mcp.json: not UTF-8"),
            (
                "deep",
                &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/1/2/3/4/5/6/7/8/9.md", b"x")],
                "more than 8 levels deep",
            ),
        ];
        refused(cases);
    }

    /// Names a server on Unix can hold, and clients on Windows could not.
    #[cfg(unix)]
    #[test]
    fn names_windows_cannot_hold_are_refused() {
        refused(&[
            ("device", &[("claude/skills/con/SKILL.md", b"x")], "a device name on Windows"),
            (
                "odd file",
                &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/what?.md", b"x")],
                "\"what?.md\" holds '?'",
            ),
            ("device file", &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/nul.txt", b"x")], "device name"),
            ("trailing dot", &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/x.", b"x")], "Windows drops"),
        ]);
    }

    #[test]
    fn names_that_are_not_ascii_are_refused() {
        let ascii = "skill file names are ASCII only";
        refused(&[
            ("accents", &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/résumé.md", b"x")], ascii),
            ("sigma", &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/σ.md", b"x")], ascii),
            ("long s", &[("claude/skills/a/SKILL.md", b"x"), ("claude/skills/a/ſ.md", b"x")], ascii),
            ("dotless i", &[("codex/skills/a/SKILL.md", b"x"), ("codex/skills/a/ı.md", b"x")], ascii),
            ("directory", &[("copilot/skills/a/SKILL.md", b"x"), ("copilot/skills/a/ü/x.md", b"x")], ascii),
            ("skill", &[("claude/skills/é/SKILL.md", b"x")], "invalid skill name"),
        ]);
        for bad in ["résumé.md", "σ.md", "ſ.md", "ı.md"] {
            let mut set = sample();
            let file = set.skills["deploy"]["SKILL.md"].clone();
            set.skills.get_mut("deploy").unwrap().insert(bad.into(), file);
            let set = set.sealed();
            for e in [set.check().unwrap_err(), set.manifest().check().unwrap_err()] {
                assert!(e.to_string().contains(&format!("{bad:?} holds")), "{bad}: {e}");
            }
        }
    }

    /// Each layout, in a fresh agents directory, fails to load with its error.
    fn refused(cases: &[Layout]) {
        for (what, files, want) in cases {
            let (_tmp, dir) = agents();
            for (rel, text) in *files {
                write(&dir, rel, text);
            }
            let harness = files[0].0.split('/').next().unwrap().parse().unwrap();
            let e = load_err(&dir, harness);
            assert!(e.contains(want), "{what}: {e}");
        }
    }

    #[test]
    fn limits_are_enforced() {
        let (_tmp, dir) = agents();
        write(&dir, "claude/skills/a/SKILL.md", "x".repeat(MAX_FILE_BYTES));
        AgentSet::load(&dir, Harness::Claude).unwrap();
        write(&dir, "claude/skills/a/SKILL.md", "x".repeat(MAX_FILE_BYTES + 1));
        let e = load_err(&dir, Harness::Claude);
        assert!(e.contains("skills/a/SKILL.md: 513 KiB is more than the 512 KiB"), "{e}");

        let (_tmp, dir) = agents();
        write(&dir, "claude/skills/a/SKILL.md", "x");
        for i in 0..MAX_SET_BYTES / MAX_FILE_BYTES {
            write(&dir, &format!("claude/skills/a/f{i:02}.md"), "x".repeat(MAX_FILE_BYTES));
        }
        let e = load_err(&dir, Harness::Claude);
        assert!(e.contains("more than the 8 MiB of text"), "{e}");

        let (_tmp, dir) = agents();
        for i in 0..MAX_SET_FILES {
            write(
                &dir,
                &format!(
                    "claude/skills/s{}/{}",
                    i / 100,
                    if i % 100 == 0 { "SKILL.md".into() } else { format!("{i}.md") }
                ),
                "x",
            );
        }
        AgentSet::load(&dir, Harness::Claude).unwrap();
        write(&dir, "claude/mcp.json", "{}");
        let e = load_err(&dir, Harness::Claude);
        assert!(e.contains(&format!("more than the {MAX_SET_FILES} files")), "{e}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn paths_differing_only_in_case_are_refused() {
        let (_tmp, dir) = agents();
        write(&dir, "claude/skills/a/SKILL.md", "x");
        write(&dir, "claude/skills/a/Notes/x.md", "x");
        write(&dir, "claude/skills/a/notes/y.md", "x");
        assert!(load_err(&dir, Harness::Claude).contains("Notes and notes differ only in case"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_stay_inside_the_agents_directory() {
        use std::os::unix::fs::symlink;
        let (tmp, dir) = agents();
        write(&dir, "claude/skills/deploy/SKILL.md", SKILL);
        write(&dir, "shared/conventions.md", "# Conventions\n");
        // Inside .bd/agents: followed.
        std::fs::create_dir_all(dir.join("codex/skills")).unwrap();
        symlink("../../claude/skills/deploy", dir.join("codex/skills/deploy")).unwrap();
        symlink("../../../shared/conventions.md", dir.join("claude/skills/deploy/conventions.md")).unwrap();
        let claude = AgentSet::load(&dir, Harness::Claude).unwrap();
        assert_eq!(claude.skills["deploy"]["conventions.md"].text, "# Conventions\n");
        let codex = AgentSet::load(&dir, Harness::Codex).unwrap();
        assert_eq!(codex.skills, claude.skills);

        let escape = |link: &Path, target: &Path, want: &str| {
            symlink(target, link).unwrap();
            for h in [Harness::Claude, Harness::Codex] {
                let e = load_err(&dir, h);
                assert!(e.contains(want), "{}: {e}", link.display());
            }
            std::fs::remove_file(link).unwrap();
        };
        let skill = dir.join("claude/skills/deploy");
        std::fs::write(tmp.path().join(".bd/bd.db"), "database").unwrap();
        escape(&skill.join("db"), Path::new("../../../../bd.db"), "deploy/db: a symlink leading outside .bd/agents");
        escape(&skill.join("hosts"), Path::new("/etc/hosts"), "deploy/hosts: a symlink leading outside");
        escape(&skill.join("up"), Path::new("../../../.."), "deploy/up: a symlink leading outside");
        escape(&skill.join("loop"), Path::new("."), "deploy/loop: a symlink loop");
        escape(&skill.join("parent"), Path::new(".."), "a symlink loop");
        escape(&skill.join("gone"), Path::new("missing.md"), "deploy/gone: a symlink to nothing");

        symlink(tmp.path(), dir.join("copilot")).unwrap();
        assert!(load_err(&dir, Harness::Copilot).contains(".bd/agents/copilot: a symlink leading outside"));
    }

    fn sample() -> AgentSet {
        let (_tmp, dir) = agents();
        write(&dir, "codex/skills/deploy/SKILL.md", SKILL);
        write(&dir, "codex/mcp.toml", "[mcp_servers.github]\ncommand = \"npx\"\n");
        AgentSet::load(&dir, Harness::Codex).unwrap()
    }

    #[test]
    fn received_sets_are_checked_before_use() {
        let set = sample();
        set.check().unwrap();
        let file = set.skills["deploy"]["SKILL.md"].clone();
        let tampered: Vec<(&str, Tamper)> = vec![
            (
                "traversal",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().insert("../../.bashrc".into(), file.clone());
                }),
            ),
            (
                "absolute",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().insert("/etc/profile".into(), file.clone());
                }),
            ),
            (
                "windows",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().insert("C:\\x".into(), file.clone());
                }),
            ),
            (
                "name",
                Box::new(|s: &mut AgentSet| {
                    let skill = s.skills["deploy"].clone();
                    s.skills.insert("..".into(), skill);
                }),
            ),
            (
                "no SKILL.md",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().remove("SKILL.md");
                }),
            ),
            (
                "text",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().get_mut("SKILL.md").unwrap().text.push('!');
                }),
            ),
            (
                "definition",
                Box::new(|s: &mut AgentSet| {
                    s.mcp_servers.get_mut("github").unwrap().definition["command"] = json!("curl");
                }),
            ),
            (
                "toml",
                Box::new(|s: &mut AgentSet| {
                    s.mcp_servers.get_mut("github").unwrap().toml =
                        Some("[mcp_servers.github]\ncommand = \"curl\"\n".into());
                }),
            ),
            (
                "no toml",
                Box::new(|s: &mut AgentSet| {
                    s.mcp_servers.get_mut("github").unwrap().toml = None;
                }),
            ),
            ("revision", Box::new(|s: &mut AgentSet| s.revision = AgentSet::empty(Harness::Codex).revision)),
            (
                "file and directory",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().insert("SKILL.md/x".into(), file.clone());
                }),
            ),
            (
                "file and directory in other case",
                Box::new(|s: &mut AgentSet| {
                    s.skills.get_mut("deploy").unwrap().insert("skill.md/x".into(), file.clone());
                }),
            ),
            (
                "file and directory below",
                Box::new(|s: &mut AgentSet| {
                    let skill = s.skills.get_mut("deploy").unwrap();
                    skill.insert("notes".into(), file.clone());
                    skill.insert("notes/a.md".into(), file.clone());
                }),
            ),
        ];
        for (what, tamper) in tampered {
            let mut s = set.clone();
            tamper(&mut s);
            assert!(s.check().is_err(), "{what}");
        }
        // Resealed, so only the clash is wrong.
        let mut s = set.clone();
        let skill = s.skills.get_mut("deploy").unwrap();
        skill.insert("notes".into(), file.clone());
        skill.insert("notes/a.md".into(), file.clone());
        let s = s.sealed();
        let e = s.check().unwrap_err().to_string();
        assert!(e.contains("skill deploy: notes is both a file and a directory"), "{e}");
        let e = s.manifest().check().unwrap_err().to_string();
        assert!(e.contains("skill deploy: notes is both a file and a directory"), "{e}");
        // Paths a case-insensitive client could not hold both of, beyond ASCII case: resealed, refused.
        for pair in [["σ.md", "ς.md"], ["s.md", "ſ.md"], ["i.md", "ı.md"], ["é.md", "e\u{301}.md"]] {
            let mut s = set.clone();
            for path in pair {
                s.skills.get_mut("deploy").unwrap().insert(path.into(), file.clone());
            }
            let s = s.sealed();
            let e = s.check().unwrap_err().to_string();
            assert!(e.contains("skill file names are ASCII only"), "{pair:?}: {e}");
            let e = s.manifest().check().unwrap_err().to_string();
            assert!(e.contains("skill file names are ASCII only"), "{pair:?}: {e}");
        }
        let mut manifest = set.manifest();
        manifest
            .skills
            .get_mut("deploy")
            .unwrap()
            .insert("../x".into(), FileDigest { sha256: String::new(), lf_sha256: None, executable: false });
        assert!(manifest.check().unwrap_err().to_string().contains("invalid path \"../x\""));
        let mut manifest = set.manifest();
        manifest.mcp_servers.clear();
        assert!(manifest.check().unwrap_err().to_string().contains("revision does not match"));
        // Digests that are not SHA-256s, even under a revision that covers them.
        let resealed = |mut m: Manifest| {
            m.revision = revision_of(&(m.skills.clone(), m.mcp_servers.clone()));
            m.check().unwrap_err().to_string()
        };
        fn skill_md(m: &mut Manifest) -> &mut FileDigest {
            m.skills.get_mut("deploy").and_then(|s| s.get_mut("SKILL.md")).unwrap()
        }
        let mut manifest = set.manifest();
        skill_md(&mut manifest).sha256 = "x".into();
        let e = resealed(manifest);
        assert!(e.contains("skill deploy: SKILL.md: \"x\" is not a SHA-256"), "{e}");
        let mut manifest = set.manifest();
        skill_md(&mut manifest).lf_sha256 = Some("\u{1b}".repeat(70));
        let e = resealed(manifest);
        assert!(e.contains(&format!("SKILL.md: lf_sha256: \"{}\"... is not", "\\u{1b}".repeat(64))), "{e}");
        let mut manifest = set.manifest();
        manifest.mcp_servers.get_mut("github").unwrap().sha256 = "X".repeat(64);
        let e = resealed(manifest);
        assert!(e.contains("MCP server github: \"XXXX"), "{e}");
    }

    #[test]
    fn names_and_paths() {
        for ok in ["deploy", "a", "web-search_2", "v1.2", "0day"] {
            check_skill_name(ok).unwrap();
        }
        for bad in [
            "",
            "Deploy",
            "-x",
            ".x",
            "x.",
            "a b",
            "a/b",
            "..",
            "nul",
            "com1",
            "com0",
            "lpt0.x",
            "lpt9.x",
            "résumé",
            &"a".repeat(65),
        ] {
            assert!(check_skill_name(bad).is_err(), "{bad:?}");
        }
        for ok in ["SKILL.md", "scripts/run.sh", "a b/c-d_e.f", "com10.txt", "con-x.md", "1/2/3/4/5/6/7/8"] {
            check_skill_path(ok).unwrap();
        }
        for bad in [
            "",
            "/x",
            "x/",
            "a//b",
            "../x",
            "a/../b",
            "./x",
            ".hidden",
            "a\\b",
            "c:x",
            "a\u{7}",
            "x.",
            "x ",
            "CON",
            "aux.md",
            "1/2/3/4/5/6/7/8/9",
        ] {
            assert!(check_skill_path(bad).is_err(), "{bad:?}");
        }
        assert!(check_skill_path(&"a".repeat(MAX_PATH_BYTES + 1)).is_err());
        for ok in ["com00.md", "com10.md", "lpt", "lpt10", "conin", "conout.md", "conin$x.md", "com1$.md"] {
            check_skill_path(ok).unwrap();
        }
        for bad in [
            "COM0",
            "com0.md",
            "LPT0.txt",
            "lpt9",
            "scripts/com0",
            "CONIN$",
            "conin$.txt",
            "CONOUT$",
            "ConOut$.log",
            "conout$ .md",
        ] {
            let e = check_skill_path(bad).unwrap_err().to_string();
            assert!(e.contains("a device name on Windows"), "{bad:?}: {e}");
        }
        // Not ASCII, so refused before the device check, which still knows the superscript device names.
        for (path, device) in [
            ("COM¹", true),
            ("com²", true),
            ("Com³.txt", true),
            ("LPT¹", true),
            ("lpt².md", true),
            ("LPT³.tar.gz", true),
            ("com¹0.md", false),
            ("lpt⁴", false),
        ] {
            assert_eq!(device_name(path), device, "{path:?}");
            let e = check_skill_path(path).unwrap_err().to_string();
            assert!(e.contains("skill file names are ASCII only"), "{path:?}: {e}");
        }
        for bad in ["résumé.md", "σ.md", "ς.md", "ſ.md", "ı.md", "e\u{301}.md", "notes/ü/a.md", "a\u{a0}b", "日本.md"]
        {
            let e = check_skill_path(bad).unwrap_err().to_string();
            assert!(e.contains("skill file names are ASCII only"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn a_path_is_never_both_a_file_and_a_directory() {
        let check = |paths: &[&str]| {
            let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
            check_skill_files(paths.iter()).map_err(|e| e.to_string())
        };
        check(&["SKILL.md", "notes/a.md", "notes/b/c.md", "notes.md"]).unwrap();
        for (paths, want) in [
            (&["SKILL.md", "notes", "notes/a.md"][..], "notes is both a file and a directory"),
            (&["SKILL.md", "notes/a.md", "notes"], "notes is both a file and a directory"),
            (&["SKILL.md", "SKILL.md/x"], "SKILL.md is both a file and a directory"),
            (&["SKILL.md", "a/b", "a/b/c/d.md"], "a/b is both a file and a directory"),
            (&["SKILL.md", "skill.md/x"], "SKILL.md and skill.md differ only in case"),
            (&["SKILL.md", "Notes", "notes/a.md"], "Notes and notes differ only in case"),
        ] {
            let e = check(paths).unwrap_err();
            assert!(e.contains(want), "{paths:?}: {e}");
        }
    }

    /// A walk over `dir`, as [`AgentSet::load`] starts one.
    #[cfg(unix)]
    fn walk(dir: &Path) -> Walk {
        Walk { root: std::fs::canonicalize(dir).unwrap(), base: label_of(dir), files: 0, dirs: 0, bytes: 0 }
    }

    /// Run `f` on another thread, failing if it takes more than a few seconds (blocked on a FIFO, say).
    #[cfg(unix)]
    fn promptly<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(f()).unwrap());
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("blocked")
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("mkfifo").arg(path).status().unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn fifos_are_refused_without_blocking() {
        let (_tmp, dir) = agents();
        write(&dir, "claude/skills/deploy/SKILL.md", SKILL);
        mkfifo(&dir.join("claude/skills/deploy/pipe.md"));
        let d = dir.clone();
        let e = promptly(move || load_err(&d, Harness::Claude));
        assert!(e.contains("skills/deploy/pipe.md: not a regular file"), "{e}");

        // Swapped in after the check: opened without blocking, then refused.
        std::fs::remove_file(dir.join("claude/skills/deploy/pipe.md")).unwrap();
        let file = dir.join("claude/skills/deploy/notes.md");
        write(&dir, "claude/skills/deploy/notes.md", "x");
        let mut w = walk(&dir);
        let (meta, canon) = w.resolve(&file, "notes.md").unwrap();
        // Renamed rather than removed, so the FIFO cannot reuse its inode number.
        std::fs::rename(&file, dir.join("claude/skills/deploy/old.md")).unwrap();
        mkfifo(&file);
        let e = promptly(move || w.text(&canon, "notes.md", &meta).map(|_| ()).unwrap_err().to_string());
        assert!(e.contains("notes.md: changed while the set was being read"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn files_swapped_after_the_check_are_refused() {
        use std::os::unix::fs::symlink;
        let (tmp, dir) = agents();
        write(&dir, "claude/skills/deploy/SKILL.md", SKILL);
        let outside = tmp.path().join("outside");
        write(&outside, "SKILL.md", "secret");
        write(&outside, "tokens.json", "secret");
        let skill = dir.join("claude/skills/deploy");
        let file = skill.join("SKILL.md");
        let mut w = walk(&dir);

        let (meta, canon) = w.resolve(&file, "SKILL.md").unwrap();
        assert_eq!(w.text(&canon, "SKILL.md", &meta).unwrap().0, SKILL, "unchanged: read");

        // Another file in its place.
        std::fs::rename(&file, skill.join("old.md")).unwrap();
        write(&skill, "SKILL.md", "other");
        let e = w.text(&canon, "SKILL.md", &meta).unwrap_err().to_string();
        assert!(e.contains("SKILL.md: changed while the set was being read"), "{e}");

        // A symlink to outside in its place.
        let (meta, canon) = w.resolve(&file, "SKILL.md").unwrap();
        std::fs::remove_file(&file).unwrap();
        symlink(outside.join("SKILL.md"), &file).unwrap();
        let e = w.text(&canon, "SKILL.md", &meta).unwrap_err().to_string();
        assert!(e.contains("SKILL.md: changed while the set was being read"), "{e}");
        std::fs::remove_file(&file).unwrap();
        write(&skill, "SKILL.md", SKILL);

        // The skill directory swapped for a symlink to outside, which holds a file of the same name.
        let (meta, canon) = w.resolve(&file, "SKILL.md").unwrap();
        std::fs::rename(&skill, dir.join("claude/skills/.moved")).unwrap();
        symlink(&outside, &skill).unwrap();
        let e = w.text(&canon, "SKILL.md", &meta).unwrap_err().to_string();
        assert!(e.contains("SKILL.md: changed while the set was being read"), "{e}");
        // Even had the check itself run after the swap, and seen the file outside: on Linux the
        // open file's own path gives it away, elsewhere the path checked again after the open.
        let outside_meta = std::fs::metadata(outside.join("SKILL.md")).unwrap();
        let e = w.text(&canon, "SKILL.md", &outside_meta).unwrap_err().to_string();
        let want = if cfg!(target_os = "linux") { "a symlink leading outside" } else { "changed while" };
        assert!(e.contains(&format!("SKILL.md: {want}")), "{e}");
        std::fs::remove_file(&skill).unwrap();
        std::fs::rename(dir.join("claude/skills/.moved"), &skill).unwrap();

        // A directory swapped for a symlink to outside after the check is not listed.
        let (meta, canon) = w.resolve(&skill, "deploy").unwrap();
        assert_eq!(w.list(&canon, &meta, "deploy").unwrap(), ["SKILL.md", "old.md"], "unchanged: listed");
        std::fs::rename(&skill, dir.join("claude/skills/.moved")).unwrap();
        symlink(&outside, &skill).unwrap();
        let e = w.list(&canon, &meta, "deploy").unwrap_err().to_string();
        assert!(e.contains("deploy: changed while the set was being read"), "{e}");
        // Nor one reached through a directory above it swapped so, even with its metadata.
        let set = dir.join("claude");
        let (_, canon) = w.resolve(&set, "claude").unwrap();
        std::fs::rename(&set, dir.join(".claude")).unwrap();
        symlink(tmp.path(), &set).unwrap();
        let outside_meta = std::fs::metadata(&outside).unwrap();
        let e = w.list(&canon.join("outside"), &outside_meta, "outside").unwrap_err().to_string();
        assert!(e.contains(&format!("outside: {want}")), "{e}");
    }
}
