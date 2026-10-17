//! `bd publish`: an admin publishes a source tree to a workspace's served
//! areas, its playbook directory (`<db dir>/playbooks`) and its agent sets
//! (`<db dir>/agents/<harness>`), which then mirror the source.
//!
//! A [`PublishBundle`] carries the source: playbook files by path, and each
//! harness's set as raw files (text and executable bit) and symlinks, so MCP
//! files keep their bytes and shared files their links. A remote client
//! sends it with the command; locally it is built from the source directory
//! the same way ([`read_tree`]). Nothing the client checked is trusted:
//!
//! 1. Under `<db dir>/publish.lock` (an OS file lock, so two publishes take
//!    turns; [`LOCK_FILE`]), every path is checked before anything is
//!    written ([`PublishBundle::check`]: relative, `/`-separated, no `..`,
//!    no hidden, empty or Windows-reserved components, ASCII without
//!    control characters, no two apart only in case, within the limits;
//!    symlinks only in agent sets, leading to another place inside
//!    `agents/`), then the bundle is written into a
//!    fresh private staging directory `<db dir>/.publish-<random>/` and
//!    validated there: each symlink resolved as the file system resolves
//!    it, then the real loaders: [`AgentSet::load`] for each
//!    harness, and every playbook through a [`Loader::contained`] rooted at
//!    the staged playbooks, so `extends` and `expand` stay inside. Any
//!    failure refuses the whole publish (exit 2, naming the file and the
//!    rule) and the staging directory is removed; ones left by a crash are
//!    swept at a later publish once an hour old.
//! 2. [`Prepared::apply`] copies the areas it changes to
//!    `<db dir>/publish.prev/` ([`PREV_DIR`], one generation, with the list
//!    of those areas, [`PREV_AREAS`], and a marker, [`APPLYING`], until
//!    [`Prepared::finish`]: a publish finding it keeps the copy from before
//!    the publish that never finished), then writes each new or changed file
//!    atomically (a temp file renamed over it, in its directory), sets
//!    executable bits and creates symlinks, renames entries the source
//!    spells otherwise in case only where names ignore case (`steps`),
//!    and only then removes what the source lacks, deepest first. Temp
//!    files an interrupted apply left are swept by the next publish. A reader sees, per file, the old or the
//!    new one, and at every moment all of both trees' files (removals come
//!    last). Nothing is written or removed through a symlink: each
//!    directory written into is checked to be a real one, and a symlink
//!    found where a file goes is renamed over, never followed. Entries
//!    whose names start with `.` are left alone.
//! 3. [`Prepared::record`] appends one [`PUBLISHED`] event (counts, per-file
//!    SHA-256, the client-reported source revision) and records the new
//!    agent set revisions with their `agents_changed` events, in the
//!    caller's write transaction; once it commits, [`Prepared::finish`].
//!
//! An area the source leaves empty is refused unless asked for
//! ([`Options::allow_empty`]): an empty source must never remove every
//! client's skills. `--rollback` restores, from `publish.prev`, the areas
//! the last publish changed through the same steps, so rolling back twice
//! gets back to where it started. Errors never name server paths.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::agents::{
    self, AGENTS_DIR, AgentSet, AgentsChanged, Harness, MAX_FILE_BYTES, MAX_SET_BYTES, MAX_SET_FILES, PlaybookSet,
    sha256_hex, under,
};
use crate::error::{Error, Result};
use crate::lockfile::{self, FileLock};
use crate::playbook::{EXTENSIONS, Loader};
use crate::store::WriteCtx;

/// The bundle format this bd reads and writes.
pub const PUBLISH_VERSION: u32 = 1;
/// Largest bundle, as JSON.
pub const MAX_PUBLISH_BYTES: usize = 16 << 20;
/// Most files and symlinks in one bundle, all areas together.
pub const MAX_PUBLISH_FILES: usize = 1024;
/// Largest file in a bundle (also a playbook file's limit, and an agent set's).
pub const MAX_PUBLISH_FILE_BYTES: usize = 512 << 10;
/// Longest path within an area, in bytes.
pub const MAX_PUBLISH_PATH_BYTES: usize = 512;
/// Most components in a path within an area.
pub const MAX_PUBLISH_DEPTH: usize = 12;
/// Longest component of a path, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Most entries `bd publish` reads in a target area or in `publish.prev`.
const MAX_SCAN_ENTRIES: usize = 64 * MAX_PUBLISH_FILES;

/// The op of the event a publish appends (its issue is none).
pub const PUBLISHED: &str = "published";
/// The workspace's playbook directory, next to the database.
pub use crate::agents::PLAYBOOKS_DIR;
/// Where the areas as they were before the last publish are kept, next to the database.
pub const PREV_DIR: &str = "publish.prev";
/// In `publish.prev`: the areas the last publish that changed anything
/// replaced (a JSON array), which a plain `--rollback` restores.
pub const PREV_AREAS: &str = "areas.json";
/// In `publish.prev`: there from before a publish writes anything until it
/// is recorded ([`Prepared::finish`]). A publish that finds it keeps what
/// `publish.prev` holds of those areas (the tree from before the publish
/// that never finished), rather than keeping the half-written tree.
pub const APPLYING: &str = "applying";
/// The file whose OS lock serializes publishes to a workspace, next to the database.
pub const LOCK_FILE: &str = "publish.lock";
/// The start of a staging directory's name, next to the database.
pub const STAGING_PREFIX: &str = ".publish-";
/// How old a staging directory left behind is when a publish removes it.
pub const STAGING_MAX_AGE: Duration = Duration::from_secs(3600);

/// A served area a publish replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Area {
    /// The playbook directory, `<db dir>/playbooks`.
    Playbooks,
    /// The agent sets, `<db dir>/agents/<harness>`.
    Agents,
}

impl Area {
    pub const ALL: [Area; 2] = [Area::Playbooks, Area::Agents];

    /// Its name, which is also its directory's, in the source and next to the database.
    pub fn name(self) -> &'static str {
        match self {
            Area::Playbooks => PLAYBOOKS_DIR,
            Area::Agents => AGENTS_DIR,
        }
    }
}

impl std::fmt::Display for Area {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Area {
    type Err = Error;

    fn from_str(s: &str) -> Result<Area> {
        Area::ALL
            .into_iter()
            .find(|a| a.name() == s)
            .ok_or_else(|| Error::invalid(format!("unknown area {s:?} (playbooks or agents)")))
    }
}

/// One file of an agent set in a bundle: a text file (`text`, and
/// `executable` for a script) or a symlink (`symlink`, its target, relative
/// and `/`-separated).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<String>,
}

/// Where a source came from, as its client reports it: informational only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    /// The git commit checked out (`git rev-parse HEAD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Whether the source directory had uncommitted changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

/// What a client sends to publish: the areas it replaces and their files.
///
/// ```json
/// {
///   "version": 1,
///   "areas": ["playbooks", "agents"],
///   "source": {"commit": "<sha>", "dirty": false},
///   "playbooks": {"change.toml": "formula = ...", "lib/base.toml": "..."},
///   "agents": {
///     "claude": {
///       "skills/deploy/SKILL.md": {"text": "---\nname: deploy\n..."},
///       "skills/deploy/run.sh": {"text": "#!/bin/sh\n...", "executable": true},
///       "mcp.json": {"text": "{\"mcpServers\": {}}"}
///     },
///     "codex": {"skills/deploy": {"symlink": "../../claude/skills/deploy"}}
///   }
/// }
/// ```
///
/// Paths are relative to their area (`playbooks/`) or harness directory
/// (`agents/<harness>/`). An area left out of `areas` must hold nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishBundle {
    pub version: u32,
    pub areas: Vec<Area>,
    #[serde(default)]
    pub source: SourceInfo,
    #[serde(default)]
    pub playbooks: BTreeMap<String, String>,
    #[serde(default)]
    pub agents: BTreeMap<Harness, BTreeMap<String, AgentFile>>,
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::invalid(msg)
}

fn io_at(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

impl PublishBundle {
    /// An empty bundle for `areas`.
    pub fn new(areas: Vec<Area>) -> PublishBundle {
        PublishBundle {
            version: PUBLISH_VERSION,
            areas,
            source: SourceInfo::default(),
            playbooks: BTreeMap::new(),
            agents: BTreeMap::new(),
        }
    }

    /// Read a bundle a client sent, refusing one over the limits or breaking
    /// a rule ([`PublishBundle::check`]).
    pub fn from_json(text: &str) -> Result<PublishBundle> {
        if text.len() > MAX_PUBLISH_BYTES {
            return Err(too_large(text.len()));
        }
        #[derive(Deserialize)]
        struct Head {
            version: Option<u32>,
        }
        let head: Head = serde_json::from_str(text).map_err(|e| invalid(format!("publish bundle: {e}")))?;
        if head.version != Some(PUBLISH_VERSION) {
            let found = head.version.map_or_else(|| "none".to_string(), |v| v.to_string());
            return Err(invalid(format!(
                "publish bundle: version {found} is not supported (this bd reads version {PUBLISH_VERSION}); run the \
                 same bd version on the client and the server"
            )));
        }
        let bundle: PublishBundle = serde_json::from_str(text).map_err(|e| invalid(format!("publish bundle: {e}")))?;
        bundle.check()?;
        Ok(bundle)
    }

    /// The bundle as JSON; fails for one a server would refuse.
    pub fn to_json(&self) -> Result<String> {
        self.check()?;
        let text = serde_json::to_string(self)?;
        if text.len() > MAX_PUBLISH_BYTES {
            return Err(too_large(text.len()));
        }
        Ok(text)
    }

    /// Whether the bundle carries `area`.
    pub fn carries(&self, area: Area) -> bool {
        self.areas.contains(&area)
    }

    /// Whether `area` has no files in the bundle.
    pub fn is_empty(&self, area: Area) -> bool {
        match area {
            Area::Playbooks => self.playbooks.is_empty(),
            Area::Agents => self.agents.values().all(BTreeMap::is_empty),
        }
    }

    /// Check every rule that can be checked before anything is written: the
    /// version, the areas, the limits, each path and symlink. Errors name the
    /// file by its path in the source (`playbooks/x.toml`, `agents/claude/...`).
    pub fn check(&self) -> Result<()> {
        if self.version != PUBLISH_VERSION {
            return Err(invalid(format!("publish bundle: version {} is not supported", self.version)));
        }
        if self.areas.is_empty() {
            return Err(invalid("publish bundle: no areas"));
        }
        let unique: BTreeSet<Area> = self.areas.iter().copied().collect();
        if unique.len() != self.areas.len() {
            return Err(invalid("publish bundle: an area named twice"));
        }
        for area in Area::ALL {
            if !self.carries(area) && !self.is_empty(area) {
                return Err(invalid(format!("publish bundle: holds {area} files but does not publish {area}")));
            }
        }
        if let Some(commit) = &self.source.commit {
            let ok = !commit.is_empty()
                && commit.len() <= 64
                && commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !ok {
                return Err(invalid("publish bundle: source commit is not a git commit id in lowercase hex"));
            }
        }
        let files = self.playbooks.len() + self.agents.values().map(BTreeMap::len).sum::<usize>();
        if files > MAX_PUBLISH_FILES {
            return Err(invalid(format!(
                "publish bundle: {files} files is more than the {MAX_PUBLISH_FILES} a publish may hold"
            )));
        }
        for (path, text) in &self.playbooks {
            let loc = format!("{PLAYBOOKS_DIR}/{path}");
            check_path(path).map_err(|why| invalid(format!("{loc}: invalid path: {why}")))?;
            if !EXTENSIONS.iter().any(|e| path.ends_with(e)) {
                return Err(invalid(format!(
                    "{loc}: not a playbook file (playbooks/ holds files ending in {})",
                    EXTENSIONS.join(", ")
                )));
            }
            check_file_text(&loc, text)?;
        }
        check_layout(PLAYBOOKS_DIR, self.playbooks.keys().map(String::as_str))?;
        for (harness, files) in &self.agents {
            let base = format!("{AGENTS_DIR}/{harness}");
            if files.len() > MAX_SET_FILES {
                return Err(invalid(format!(
                    "{base}: {} files is more than the {MAX_SET_FILES} a set may hold",
                    files.len()
                )));
            }
            let mut bytes = 0;
            for (path, file) in files {
                let loc = format!("{base}/{path}");
                check_path(path).map_err(|why| invalid(format!("{loc}: invalid path: {why}")))?;
                match (&file.text, &file.symlink) {
                    (Some(text), None) => {
                        check_file_text(&loc, text)?;
                        bytes += text.len();
                    }
                    (None, Some(target)) => {
                        if file.executable {
                            return Err(invalid(format!("{loc}: a symlink has no executable bit of its own")));
                        }
                        resolve_link(*harness, path, target).map_err(|why| invalid(format!("{loc}: {why}")))?;
                    }
                    _ => {
                        return Err(invalid(format!("{loc}: holds either text or a symlink target, exactly one")));
                    }
                }
            }
            if bytes > MAX_SET_BYTES {
                return Err(invalid(format!(
                    "{base}: more than the {} MiB of text a set may hold",
                    MAX_SET_BYTES >> 20
                )));
            }
            check_layout(&base, files.keys().map(String::as_str))?;
        }
        Ok(())
    }
}

fn too_large(bytes: usize) -> Error {
    invalid(format!(
        "publish bundle: {} MiB is more than the {} MiB a publish may send",
        bytes.div_ceil(1 << 20),
        MAX_PUBLISH_BYTES >> 20
    ))
}

fn check_file_text(loc: &str, text: &str) -> Result<()> {
    let limit = MAX_PUBLISH_FILE_BYTES.min(MAX_FILE_BYTES);
    if text.len() > limit {
        return Err(invalid(format!(
            "{loc}: {} KiB is more than the {} KiB a published file may hold",
            text.len().div_ceil(1024),
            limit >> 10
        )));
    }
    if text.contains('\0') {
        return Err(invalid(format!("{loc}: holds NUL characters: not a text file (bd publishes text files only)")));
    }
    Ok(())
}

/// Why `path` (relative to its area or harness directory) is not one a
/// publish may write: absolute, `\`-separated, a drive, `..`, hidden or
/// empty components, characters other than ASCII, control characters, names
/// Windows reserves or cannot hold, too deep or too long.
pub fn check_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Err("an empty path".into());
    }
    if path.len() > MAX_PUBLISH_PATH_BYTES {
        return Err(format!("{} bytes is more than the {MAX_PUBLISH_PATH_BYTES} allowed", path.len()));
    }
    if path.starts_with('/') {
        return Err("an absolute path (paths are relative to their area)".into());
    }
    if path.contains('\\') {
        return Err("a backslash (paths are '/'-separated)".into());
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_PUBLISH_DEPTH {
        return Err(format!("more than {MAX_PUBLISH_DEPTH} levels deep"));
    }
    for part in parts {
        if part.is_empty() {
            return Err("an empty component (a doubled or trailing '/')".into());
        }
        if part == ".." {
            return Err("'..' (paths stay inside their area)".into());
        }
        if part.starts_with('.') {
            return Err(format!("{part:?} starts with '.' (hidden files, '.' and '..' are not published)"));
        }
        if let Some(c) = part.chars().find(|c| !c.is_ascii()) {
            return Err(format!(
                "{part:?} holds {c:?}: published names are ASCII only, so every file system compares them the same \
                 way"
            ));
        }
        if part.len() > MAX_COMPONENT_BYTES {
            return Err(format!("a component longer than {MAX_COMPONENT_BYTES} bytes"));
        }
        if let Some(c) = part.chars().find(|c| c.is_control()) {
            return Err(format!("{part:?} holds the control character {c:?}"));
        }
        if part.contains(':') {
            return Err(format!("{part:?} holds ':' (a drive or a stream on Windows)"));
        }
        if let Some(c) = part.chars().find(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*')) {
            return Err(format!("{part:?} holds {c:?}, which Windows does not allow"));
        }
        if part.ends_with([' ', '.']) {
            return Err(format!("{part:?} ends with a space or '.', which Windows drops"));
        }
        if agents::device_name(part) {
            return Err(format!("{part:?} is a device name on Windows"));
        }
    }
    Ok(())
}

/// Where the symlink at `path` (in the set of `harness`) with `target`
/// leads, as components in the agents directory (`agents/`); an error unless
/// it stays inside it, below a set's own directory. Lexical: once staged,
/// each link is also resolved in the staged tree ([`Staging::check_links`]),
/// and the sets loaded there, which follow links as they are.
fn resolve_link(harness: Harness, path: &str, target: &str) -> std::result::Result<Vec<String>, String> {
    let outside = "a symlink leading outside agents/; a symlink may only lead to another file or directory of the \
                   agent sets (agents/<harness>/...)";
    if target.is_empty() {
        return Err("a symlink with an empty target".into());
    }
    if target.len() > MAX_PUBLISH_PATH_BYTES {
        return Err(format!("a symlink target longer than {MAX_PUBLISH_PATH_BYTES} bytes"));
    }
    if target.starts_with('/') || target.contains(['\\', ':']) {
        return Err(format!("{outside} (an absolute target, or one not '/'-separated)"));
    }
    let mut at: Vec<String> = std::iter::once(harness.name()).chain(path.split('/')).map(String::from).collect();
    at.pop();
    for part in target.split('/') {
        match part {
            "" => return Err("a symlink target with an empty component".into()),
            "." => {}
            ".." => {
                if at.pop().is_none() {
                    return Err(outside.into());
                }
            }
            p if p.starts_with('.') => return Err(format!("a symlink to the hidden name {p:?}")),
            p if p.chars().any(char::is_control) => return Err("a symlink target with a control character".into()),
            p => at.push(p.to_string()),
        }
    }
    if at.len() < 2 {
        return Err(format!("{outside} (it leads to agents/ or to a set's own directory)"));
    }
    Ok(at)
}

/// No path in `paths` (within `base`) is also a directory on the way to
/// another, and no two files or directories differ only in case (paths are
/// ASCII by then: [`check_path`]), which a file system that ignores case
/// would take for one.
fn check_layout<'a>(base: &str, paths: impl Iterator<Item = &'a str>) -> Result<()> {
    // Each file and each directory on the way to one, by its name in lower case:
    // its spelling, and for a directory the first path below it.
    let mut seen: BTreeMap<String, (&str, Option<&str>)> = BTreeMap::new();
    let mut entries = Vec::new();
    for path in paths {
        entries.extend(path.match_indices('/').map(|(i, _)| (&path[..i], Some(path))));
        entries.push((path, None));
    }
    for (entry, below) in entries {
        match seen.get(&entry.to_ascii_lowercase()) {
            None => {
                seen.insert(entry.to_ascii_lowercase(), (entry, below));
            }
            Some((other, _)) if *other != entry => {
                return Err(invalid(format!(
                    "{base}/{other} and {base}/{entry} differ only in case, which a case-insensitive file system \
                     cannot hold both of"
                )));
            }
            Some((_, other_below)) => {
                if let Some(path) = below.or(*other_below)
                    && below.is_none() != other_below.is_none()
                {
                    return Err(invalid(format!("{base}/{entry}: both a file and a directory holding {base}/{path}")));
                }
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------ source trees

/// Read the areas `areas` of the source directory `dir` (`dir/playbooks/**`,
/// `dir/agents/<harness>/**`) into a bundle, without following symlinks
/// and leaving out hidden entries. An area without a directory is empty.
pub fn read_tree(dir: &Path, areas: &[Area]) -> Result<PublishBundle> {
    read_tree_with(dir, areas, None)
}

/// What git records of a file (`git ls-files -s`): where the file system
/// keeps no executable bits or symlinks (Windows), they come from git.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitMode {
    File,
    Executable,
    Symlink,
}

/// The modes in the output of `git ls-files -s -z`, by path as git prints
/// it (relative to where it ran); other kinds of entry (submodules) left out.
pub fn parse_ls_files(out: &str) -> BTreeMap<String, GitMode> {
    out.split('\0')
        .filter_map(|entry| {
            let (meta, path) = entry.split_once('\t')?;
            let mode = match meta.split(' ').next()? {
                "100644" => GitMode::File,
                "100755" => GitMode::Executable,
                "120000" => GitMode::Symlink,
                _ => return None,
            };
            Some((path.to_string(), mode))
        })
        .collect()
}

/// [`read_tree`], with the agent sets' executable bits and symlinks taken
/// from `git` (by path relative to `dir`, as [`parse_ls_files`] gives them)
/// rather than the file system, when given: a file git records as a
/// symlink is one, its text the target (as git checks it out where
/// symlinks are not made). An agent set's file git does not record is
/// refused: nothing would say whether it is a script.
pub fn read_tree_with(dir: &Path, areas: &[Area], git: Option<&BTreeMap<String, GitMode>>) -> Result<PublishBundle> {
    let mut bundle = PublishBundle::new(areas.to_vec());
    let mut count = 0;
    for &area in areas {
        let root = dir.join(area.name());
        match std::fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_at(&root, e)),
            Ok(m) if !m.is_dir() => {
                return Err(invalid(format!("{}: not a directory", root.display())));
            }
            Ok(_) => {}
        }
        match area {
            Area::Playbooks => {
                let mut found = Vec::new();
                walk_source(&root, "", 0, &mut count, &mut found)?;
                for (rel, entry) in found {
                    match entry {
                        SourceEntry::File { text, .. } => {
                            bundle.playbooks.insert(rel, text);
                        }
                        SourceEntry::Symlink(_) => {
                            return Err(invalid(format!(
                                "{}: a symlink (playbooks/ holds files only)",
                                root.join(&rel).display()
                            )));
                        }
                    }
                }
            }
            Area::Agents => {
                for name in list_names(&root)? {
                    let path = root.join(&name);
                    let harness: Harness = name.parse().map_err(|_| {
                        invalid(format!("{}: not a harness's set (claude, codex or copilot)", path.display()))
                    })?;
                    let meta = std::fs::symlink_metadata(&path).map_err(|e| io_at(&path, e))?;
                    if !meta.is_dir() {
                        return Err(invalid(format!("{}: not a directory (a set is a directory)", path.display())));
                    }
                    let mut found = Vec::new();
                    walk_source(&path, "", 0, &mut count, &mut found)?;
                    let files = bundle.agents.entry(harness).or_default();
                    for (rel, entry) in found {
                        let file = match entry {
                            SourceEntry::File { text, executable } => match git {
                                None => AgentFile { text: Some(text), executable, symlink: None },
                                Some(modes) => {
                                    let key = format!("{AGENTS_DIR}/{name}/{rel}");
                                    match modes.get(&key) {
                                        Some(GitMode::Symlink) => AgentFile {
                                            symlink: Some(text.trim_end_matches(['\r', '\n']).to_string()),
                                            ..Default::default()
                                        },
                                        Some(mode) => AgentFile {
                                            text: Some(text),
                                            executable: *mode == GitMode::Executable,
                                            symlink: None,
                                        },
                                        None => {
                                            return Err(invalid(format!(
                                                "{}: not recorded by git: here the file system keeps no executable \
                                                 bits or symlinks, so bd publish takes those of agent sets from git \
                                                 (git add it, or publish from Linux or macOS)",
                                                root.join(&name).join(&rel).display()
                                            )));
                                        }
                                    }
                                }
                            },
                            SourceEntry::Symlink(target) => {
                                AgentFile { text: None, executable: false, symlink: Some(target) }
                            }
                        };
                        files.insert(rel, file);
                    }
                }
            }
        }
    }
    bundle.check()?;
    Ok(bundle)
}

enum SourceEntry {
    File { text: String, executable: bool },
    Symlink(String),
}

/// The names in `dir`, sorted, without hidden ones.
fn list_names(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_at(dir, e))? {
        let name = entry.map_err(|e| io_at(dir, e))?.file_name();
        let name = name
            .into_string()
            .map_err(|n| invalid(format!("{}: a file name that is not UTF-8", dir.join(n).display())))?;
        if !name.starts_with('.') {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn walk_source(
    dir: &Path,
    rel: &str,
    depth: usize,
    count: &mut usize,
    out: &mut Vec<(String, SourceEntry)>,
) -> Result<()> {
    if depth >= MAX_PUBLISH_DEPTH {
        return Err(invalid(format!("{}: more than {MAX_PUBLISH_DEPTH} levels deep", dir.display())));
    }
    for name in list_names(dir)? {
        let path = dir.join(&name);
        let rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let meta = std::fs::symlink_metadata(&path).map_err(|e| io_at(&path, e))?;
        if meta.is_dir() {
            walk_source(&path, &rel, depth + 1, count, out)?;
            continue;
        }
        *count += 1;
        if *count > MAX_PUBLISH_FILES {
            return Err(invalid(format!(
                "{}: more than the {MAX_PUBLISH_FILES} files a publish may hold",
                path.display()
            )));
        }
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| io_at(&path, e))?;
            let target = target
                .to_str()
                .ok_or_else(|| invalid(format!("{}: a symlink target that is not UTF-8", path.display())))?;
            let target = if cfg!(windows) { target.replace('\\', "/") } else { target.to_string() };
            out.push((rel, SourceEntry::Symlink(target)));
        } else if meta.is_file() {
            let text = read_capped(&path)?;
            out.push((rel, SourceEntry::File { text, executable: executable(&meta) }));
        } else {
            return Err(invalid(format!("{}: not a regular file, directory or symlink", path.display())));
        }
    }
    Ok(())
}

/// The text of the regular file `path`, refused past [`MAX_PUBLISH_FILE_BYTES`]
/// before more is read, without following a symlink there.
fn read_capped(path: &Path) -> Result<String> {
    let file = open_nofollow(path).map_err(|e| io_at(path, e))?;
    let too_large = || {
        invalid(format!(
            "{}: more than the {} KiB a published file may hold",
            path.display(),
            MAX_PUBLISH_FILE_BYTES >> 10
        ))
    };
    if file.metadata().map_err(|e| io_at(path, e))?.len() > MAX_PUBLISH_FILE_BYTES as u64 {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PUBLISH_FILE_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| io_at(path, e))?;
    if bytes.len() > MAX_PUBLISH_FILE_BYTES {
        return Err(too_large());
    }
    String::from_utf8(bytes)
        .map_err(|_| invalid(format!("{}: not UTF-8 text (bd publishes text files only)", path.display())))
}

fn open_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
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

// ------------------------------------------------------------ the target areas

/// An entry of an area on disk, as a publish compares them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Node {
    Dir,
    File {
        sha256: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        executable: bool,
    },
    Symlink {
        target: String,
    },
    /// A FIFO, socket or device: never published, removed if found.
    Other,
}

/// The entries under `root` by `/`-separated path, never following a
/// symlink and leaving out hidden names (and what is below them). A missing
/// `root` has none.
fn scan(root: &Path) -> Result<BTreeMap<String, Node>> {
    let mut out = BTreeMap::new();
    match std::fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(io_at(root, e)),
        Ok(m) if !m.is_dir() => return Ok(out),
        Ok(_) => {}
    }
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| io_at(&dir, e))? {
            let entry = entry.map_err(|e| io_at(&dir, e))?;
            let Ok(name) = entry.file_name().into_string() else {
                return Err(invalid(format!("{}: a file name that is not UTF-8", entry.path().display())));
            };
            if name.starts_with('.') {
                continue;
            }
            let path = dir.join(&name);
            let rel = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            let meta = std::fs::symlink_metadata(&path).map_err(|e| io_at(&path, e))?;
            let node = if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).map_err(|e| io_at(&path, e))?;
                Node::Symlink { target: target.to_string_lossy().replace('\\', "/") }
            } else if meta.is_dir() {
                stack.push((path, rel.clone()));
                Node::Dir
            } else if meta.is_file() {
                Node::File { sha256: hash_file(&path)?, executable: executable(&meta) }
            } else {
                Node::Other
            };
            out.insert(rel, node);
            if out.len() > MAX_SCAN_ENTRIES {
                return Err(invalid(format!("{}: more than {MAX_SCAN_ENTRIES} entries", root.display())));
            }
        }
    }
    Ok(out)
}

fn hash_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = open_nofollow(path).map_err(|e| io_at(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 << 10];
    loop {
        let n = file.read(&mut buf).map_err(|e| io_at(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// What a publish does to one file (or symlink) of an area.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Added,
    Changed,
    Removed,
    Unchanged,
}

/// One file (or symlink) of an area, compared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    pub area: Area,
    /// Within its area (`lib/base.toml`, `claude/skills/deploy/SKILL.md`).
    pub path: String,
    pub status: Status,
    /// What the area holds there now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<Node>,
    /// What it will hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<Node>,
}

/// One area's changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AreaPlan {
    pub area: Area,
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Every file and symlink of the source or the area, in path order.
    pub files: Vec<FileChange>,
}

fn plan_area(area: Area, source: &BTreeMap<String, Node>, target: &BTreeMap<String, Node>) -> AreaPlan {
    let mut plan = AreaPlan { area, added: 0, changed: 0, removed: 0, unchanged: 0, files: Vec::new() };
    let paths: BTreeSet<&String> = source.keys().chain(target.keys()).collect();
    for path in paths {
        let (new, old) = (source.get(path).filter(|n| **n != Node::Dir), target.get(path).filter(|n| **n != Node::Dir));
        let status = match (old, new) {
            (None, None) => continue,
            (None, Some(_)) => Status::Added,
            (Some(_), None) => Status::Removed,
            (Some(o), Some(n)) if o == n => Status::Unchanged,
            _ => Status::Changed,
        };
        match status {
            Status::Added => plan.added += 1,
            Status::Changed => plan.changed += 1,
            Status::Removed => plan.removed += 1,
            Status::Unchanged => plan.unchanged += 1,
        }
        plan.files.push(FileChange { area, path: path.clone(), status, old: old.cloned(), new: new.cloned() });
    }
    plan
}

// ------------------------------------------------------------ staging

/// A private directory next to the database, removed when dropped.
struct Staging {
    dir: PathBuf,
    /// Its own name, as errors from loaders may show it.
    name: String,
    /// Its canonical path, as errors may show it too.
    canonical: PathBuf,
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 16 hex digits nobody can guess ahead without this process's state; the
/// directory is also created exclusively, so a clash fails, never shares.
fn unique_hex() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let local = 0u8;
    let seed =
        format!("{}:{nanos}:{}:{:p}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed), &raw const local);
    sha256_hex(seed.as_bytes())[..16].to_string()
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

fn new_staging(db_dir: &Path) -> Result<Staging> {
    for _ in 0..8 {
        let name = format!("{STAGING_PREFIX}{}", unique_hex());
        let dir = db_dir.join(&name);
        match create_private_dir(&dir) {
            Ok(()) => {
                let canonical = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
                return Ok(Staging { dir, name, canonical });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io_at(&dir, e)),
        }
    }
    Err(invalid("could not create a staging directory next to the workspace's database"))
}

/// Remove staging directories older than `age` that publishes left behind
/// (a crash, a kill); returns how many.
fn sweep(db_dir: &Path, age: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(db_dir) else { return 0 };
    let mut swept = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(STAGING_PREFIX) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        let old = meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|e| e >= age);
        if meta.is_dir() && old && std::fs::remove_dir_all(&path).is_ok() {
            swept += 1;
        }
    }
    swept
}

fn set_mode(file: &File, executable: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, executable);
        Ok(())
    }
}

/// Write `bytes` to the new file `path` (it must not exist).
fn write_new(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| io_at(path, e))?;
    file.write_all(bytes).map_err(|e| io_at(path, e))?;
    set_mode(&file, executable).map_err(|e| io_at(path, e))?;
    file.sync_all().map_err(|e| io_at(path, e))
}

/// Create the symlink `link` to `target`; `dir_hint` tells Windows, which
/// creates file and directory symlinks apart, which it is.
fn make_symlink(target: &str, link: &Path, dir_hint: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let _ = dir_hint;
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        let target = target.replace('/', "\\");
        if dir_hint {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link, dir_hint);
        Err(std::io::Error::other("symlinks are not supported here"))
    }
}

/// Write the bundle's areas into the staging directory `dir`. Every path
/// passed [`PublishBundle::check`], so each lands below `dir` and none
/// passes through a symlink (no symlink is a directory on the way to
/// another path, and symlinks are made last).
fn stage(bundle: &PublishBundle, dir: &Path) -> Result<()> {
    let ensure_parent = |path: &Path| match path.parent() {
        Some(p) => std::fs::create_dir_all(p).map_err(|e| io_at(p, e)),
        None => Ok(()),
    };
    for area in &bundle.areas {
        let root = dir.join(area.name());
        std::fs::create_dir(&root).map_err(|e| io_at(&root, e))?;
    }
    let playbooks = dir.join(PLAYBOOKS_DIR);
    for (path, text) in &bundle.playbooks {
        let file = under(&playbooks, path);
        ensure_parent(&file)?;
        write_new(&file, text.as_bytes(), false)?;
    }
    let agents = dir.join(AGENTS_DIR);
    // Every set's files first, so a symlink to another set finds what it leads to.
    for (harness, files) in &bundle.agents {
        let set = agents.join(harness.name());
        for (path, file) in files {
            if let Some(text) = &file.text {
                let to = under(&set, path);
                ensure_parent(&to)?;
                write_new(&to, text.as_bytes(), file.executable)?;
            }
        }
    }
    for (harness, files) in &bundle.agents {
        let set = agents.join(harness.name());
        for (path, file) in files {
            if let Some(target) = &file.symlink {
                let link = under(&set, path);
                ensure_parent(&link)?;
                let at = resolve_link(*harness, path, target).map_err(invalid)?;
                let dir_hint = under(&agents, &at.join("/")).is_dir();
                make_symlink(target, &link, dir_hint).map_err(|e| io_at(&link, e))?;
            }
        }
    }
    Ok(())
}

impl Staging {
    /// `msg` without this directory's path or name: errors name files as the source does.
    fn scrub(&self, msg: &str) -> String {
        let mut out = msg.to_string();
        for prefix in [&self.canonical, &self.dir] {
            for sep in ['/', std::path::MAIN_SEPARATOR] {
                out = out.replace(&format!("{}{sep}", prefix.display()), "");
            }
        }
        out.replace(&format!("{}/", self.name), "").replace(&format!("{}{}", self.name, std::path::MAIN_SEPARATOR), "")
    }

    /// Resolve each staged symlink as the file system does, link by link:
    /// it must lead to something inside the staged `agents/` (the lexical
    /// check, [`resolve_link`], cannot see where another link it passes
    /// through leads).
    fn check_links(&self, bundle: &PublishBundle) -> Result<()> {
        let agents = self.dir.join(AGENTS_DIR);
        let Ok(root) = std::fs::canonicalize(&agents) else { return Ok(()) };
        for (harness, files) in &bundle.agents {
            for (path, file) in files {
                if file.symlink.is_none() {
                    continue;
                }
                let loc = format!("{AGENTS_DIR}/{harness}/{path}");
                match std::fs::canonicalize(under(&agents.join(harness.name()), path)) {
                    Ok(to) if to.starts_with(&root) && to != root => {}
                    Ok(_) => {
                        return Err(invalid(format!(
                            "{loc}: a symlink leading outside agents/; a symlink may only lead to another file or \
                             directory of the agent sets (agents/<harness>/...)"
                        )));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(invalid(format!("{loc}: a symlink to nothing in the published tree")));
                    }
                    Err(e) => return Err(invalid(format!("{loc}: {}", self.scrub(&e.to_string())))),
                }
            }
        }
        Ok(())
    }

    /// Validate the staged areas with the loaders that serve them: each
    /// harness's set, and every playbook through a loader held to the
    /// staged playbooks, and the playbooks as clients are served them for
    /// approval ([`PlaybookSet::load`]). Returns each set's revision (when
    /// agents are published) and the playbooks' (when they are).
    fn validate(&self, bundle: &PublishBundle) -> Result<(BTreeMap<Harness, String>, Option<String>)> {
        let refused = |loc: &str, e: Error| {
            let msg = self.scrub(&e.to_string());
            let msg = if loc.is_empty() || msg.contains(loc) { msg } else { format!("{loc}: {msg}") };
            invalid(msg)
        };
        let mut revisions = BTreeMap::new();
        if bundle.carries(Area::Agents) {
            let agents = self.dir.join(AGENTS_DIR);
            for h in Harness::ALL {
                let set = AgentSet::load(&agents, h).map_err(|e| refused("", e))?;
                revisions.insert(h, set.revision);
            }
        }
        let mut playbooks = None;
        if bundle.carries(Area::Playbooks) {
            let root = self.dir.join(PLAYBOOKS_DIR);
            playbooks = Some(PlaybookSet::load(&root).map_err(|e| refused("", e))?.revision);
            for path in bundle.playbooks.keys() {
                let loader = Loader::new(vec![root.clone()]).contained();
                loader.checked(&under(&root, path)).map_err(|e| refused(&format!("{PLAYBOOKS_DIR}/{path}"), e))?;
            }
        }
        Ok((revisions, playbooks))
    }
}

// ------------------------------------------------------------ prepare, apply, record

/// What to publish.
#[derive(Clone, Debug)]
pub enum Source {
    /// A bundle (a client's source tree).
    Bundle(PublishBundle),
    /// The areas kept in `publish.prev`, or only `only` of them.
    Rollback { only: Option<Area> },
}

/// How to publish.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// How long to wait for another publish to the workspace to finish.
    pub wait: Duration,
    /// Publish an area the source leaves empty (removing everything in it).
    pub allow_empty: bool,
}

/// A publish staged and validated, under the workspace's publish lock (held
/// until this is dropped, which also removes the staging directory).
pub struct Prepared {
    db_dir: PathBuf,
    staging: Staging,
    _lock: FileLock,
    applied: bool,
    /// Whether this restores `publish.prev`.
    pub rollback: bool,
    pub source: SourceInfo,
    /// Each area published, compared with what it holds now.
    pub plans: Vec<AreaPlan>,
    /// Each harness's set revision once published (when agents are).
    pub revisions: BTreeMap<Harness, String>,
    /// The playbooks' revision once published (when they are), as `bd agents
    /// manifest --playbooks` serves it.
    pub playbooks_revision: Option<String>,
    /// Each harness's set revision now, where its set can be read.
    pub previous: BTreeMap<Harness, String>,
    /// Staging directories left behind that this publish removed.
    pub swept: usize,
}

/// Stage and validate a publish to the workspace whose database lives in
/// `db_dir`, under its publish lock (waiting up to `opts.wait`, then exit 5).
pub fn prepare(db_dir: &Path, source: Source, opts: &Options) -> Result<Prepared> {
    prepare_in(db_dir, source, opts).map_err(|e| scrubbed(e, db_dir))
}

fn prepare_in(db_dir: &Path, source: Source, opts: &Options) -> Result<Prepared> {
    let lock = lockfile::exclusive(&db_dir.join(LOCK_FILE), opts.wait, || {
        format!(
            "another bd publish is changing this workspace's playbooks and agent sets ({LOCK_FILE} is locked); retry"
        )
    })?;
    let swept = sweep(db_dir, STAGING_MAX_AGE) + sweep_temps(db_dir);
    let (bundle, rollback) = match source {
        Source::Bundle(bundle) => {
            bundle.check()?;
            (bundle, false)
        }
        Source::Rollback { only } => (read_prev(db_dir, only)?, true),
    };
    for &area in &bundle.areas {
        if bundle.is_empty(area) && !opts.allow_empty {
            let what = if rollback { "the previous publish kept" } else { "the source" };
            return Err(Error::Refused(format!(
                "{what} has no {area}: publishing it would remove every {} the workspace serves; publish the other \
                 area alone (--only), or pass --allow-empty to empty it",
                match area {
                    Area::Playbooks => "playbook",
                    Area::Agents => "skill and MCP definition",
                }
            )));
        }
    }
    let staging = new_staging(db_dir)?;
    stage(&bundle, &staging.dir)?;
    staging.check_links(&bundle)?;
    let (revisions, playbooks_revision) = staging.validate(&bundle)?;
    let mut previous = BTreeMap::new();
    if bundle.carries(Area::Agents) {
        for h in Harness::ALL {
            if let Ok(set) = AgentSet::load(&db_dir.join(AGENTS_DIR), h) {
                previous.insert(h, set.revision);
            }
        }
    }
    let mut plans = Vec::new();
    for &area in &bundle.areas {
        let source = scan(&staging.dir.join(area.name()))?;
        let target = scan(&db_dir.join(area.name()))?;
        plans.push(plan_area(area, &source, &target));
    }
    Ok(Prepared {
        db_dir: db_dir.to_path_buf(),
        staging,
        _lock: lock,
        applied: false,
        rollback,
        source: bundle.source,
        plans,
        revisions,
        playbooks_revision,
        previous,
        swept,
    })
}

/// The areas recorded in `publish.prev` ([`PREV_AREAS`]); `None` if it holds no record.
fn prev_areas(prev: &Path) -> Option<BTreeSet<Area>> {
    let text = read_capped(&prev.join(PREV_AREAS)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The areas kept in `publish.prev`, as a bundle: `only`, else those the
/// last publish that changed anything replaced ([`PREV_AREAS`]; all kept
/// without that record).
fn read_prev(db_dir: &Path, only: Option<Area>) -> Result<PublishBundle> {
    let prev = db_dir.join(PREV_DIR);
    let kept = |a: &Area| std::fs::symlink_metadata(prev.join(a.name())).is_ok_and(|m| m.is_dir());
    let replaced = prev_areas(&prev);
    let areas: Vec<Area> = Area::ALL
        .into_iter()
        .filter(|a| match only {
            Some(o) => o == *a,
            None => replaced.as_ref().is_none_or(|r| r.contains(a)),
        })
        .filter(kept)
        .collect();
    if areas.is_empty() {
        let what = only.map_or_else(String::new, |a| format!(" of {a}"));
        return Err(Error::Refused(format!(
            "nothing to roll back to: no earlier publish{what} is kept ({PREV_DIR} is made by a publish)"
        )));
    }
    read_tree(&prev, &areas)
        .map_err(|e| invalid(format!("the previous publish kept in {PREV_DIR} cannot be restored: {e}")))
}

/// Make `dir` a real directory: a symlink or file there is removed first
/// (never followed), a missing one created.
fn ensure_real_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => remove_entry(dir)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_at(dir, e)),
    }
    std::fs::create_dir(dir).map_err(|e| io_at(dir, e))
}

/// Remove the file, symlink or directory tree at `path`, never following a
/// symlink (`remove_dir_all` removes a symlink, not what it leads to).
fn remove_entry(path: &Path) -> Result<()> {
    let removed = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_at(path, e)),
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        // A directory symlink on Windows is removed as a directory.
        Ok(_) => std::fs::remove_file(path).or_else(|e| if cfg!(windows) { std::fs::remove_dir(path) } else { Err(e) }),
    };
    match removed {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io_at(path, e)),
        _ => Ok(()),
    }
}

/// A temp name next to `path`, hidden (readers of the area skip it).
fn temp_beside(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.publish-{}", unique_hex()))
}

/// Put `tmp` (a file or symlink just made) in place of `path`: renamed over
/// a file or symlink there (which replaces the entry, never what a symlink
/// leads to), or over a directory once it is removed.
fn rename_over(tmp: &Path, path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        remove_entry(path)?;
    }
    std::fs::rename(tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        io_at(path, e)
    })
}

/// Copy the area `from` into `to` (a new directory): files, directories
/// and symlinks as they are, hidden entries and anything else left out.
fn copy_area(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir(to).map_err(|e| io_at(to, e))?;
    for (rel, node) in scan(from)? {
        let (src, dst) = (under(from, &rel), under(to, &rel));
        match node {
            Node::Dir => std::fs::create_dir(&dst).map_err(|e| io_at(&dst, e))?,
            Node::File { executable, .. } => {
                let mut bytes = Vec::new();
                open_nofollow(&src).and_then(|mut f| f.read_to_end(&mut bytes)).map_err(|e| io_at(&src, e))?;
                write_new(&dst, &bytes, executable)?;
            }
            Node::Symlink { target } => {
                let dir_hint = std::fs::metadata(&src).is_ok_and(|m| m.is_dir());
                make_symlink(&target, &dst, dir_hint).map_err(|e| io_at(&dst, e))?;
            }
            Node::Other => {}
        }
    }
    Ok(())
}

/// What a test sees after each change to an area.
type Observe<'a> = &'a mut dyn FnMut(&Path) -> Result<()>;

impl Prepared {
    /// Whether this publishes `area`.
    pub fn publishes(&self, area: Area) -> bool {
        self.plans.iter().any(|p| p.area == area)
    }

    /// The old and new text of a changed or added file, for a diff: `None`
    /// for a side that is not a UTF-8 file of at most [`MAX_PUBLISH_FILE_BYTES`].
    pub fn texts(&self, change: &FileChange) -> (Option<String>, Option<String>) {
        let read = |root: PathBuf, node: &Option<Node>| match node {
            Some(Node::File { .. }) => read_capped(&under(&root, &change.path)).ok(),
            _ => None,
        };
        let area = change.area.name();
        (read(self.db_dir.join(area), &change.old), read(self.staging.dir.join(area), &change.new))
    }

    /// Apply the publish: keep the areas it changes as they are in
    /// `publish.prev`, then write what is new or changed, then remove what
    /// the source lacks. Once the publish is recorded, [`Prepared::finish`].
    pub fn apply(&mut self) -> Result<()> {
        self.apply_observed(&mut |_| Ok(()))
    }

    fn apply_observed(&mut self, observe: Observe<'_>) -> Result<()> {
        self.apply_in(observe).map_err(|e| scrubbed(e, &self.db_dir))
    }

    fn apply_in(&mut self, observe: Observe<'_>) -> Result<()> {
        if self.applied {
            return Err(invalid("this publish was applied already"));
        }
        let prev = self.db_dir.join(PREV_DIR);
        let marker = prev.join(APPLYING);
        let changing: BTreeSet<Area> =
            self.plans.iter().filter(|p| p.added + p.changed + p.removed > 0).map(|p| p.area).collect();
        // A publish that never finished kept the tree from before it: that stays.
        let unfinished: BTreeSet<Area> = if std::fs::symlink_metadata(&marker).is_ok() {
            prev_areas(&prev).unwrap_or_else(|| Area::ALL.into_iter().collect())
        } else {
            BTreeSet::new()
        };
        if !changing.is_empty() {
            // The rollback generation of each area changed, complete before anything changes.
            let fresh: Vec<Area> = changing.difference(&unfinished).copied().collect();
            let snapshot = self.staging.dir.join("prev");
            std::fs::create_dir(&snapshot).map_err(|e| io_at(&snapshot, e))?;
            for area in &fresh {
                copy_area(&self.db_dir.join(area.name()), &snapshot.join(area.name()))?;
            }
            ensure_real_dir(&prev)?;
            for area in &fresh {
                let kept = prev.join(area.name());
                remove_entry(&kept)?;
                std::fs::rename(snapshot.join(area.name()), &kept).map_err(|e| io_at(&kept, e))?;
                observe(&kept)?;
            }
            let replaced: BTreeSet<Area> = unfinished.union(&changing).copied().collect();
            let record = prev.join(PREV_AREAS);
            replace_file(&record, &serde_json::to_vec(&replaced)?)?;
            observe(&record)?;
            // Last, once the copies and their list are in place: until here nothing in the areas changed, and a
            // crash leaves no marker beside another publish's list (the next publish takes its own copies again).
            if std::fs::symlink_metadata(&marker).is_err() {
                write_new(&marker, b"", false)?;
            }
        }
        for plan in &self.plans {
            let name = plan.area.name();
            apply_area(&self.staging.dir.join(name), &self.db_dir.join(name), observe)?;
        }
        self.applied = true;
        Ok(())
    }

    /// Once the applied publish is recorded (its write transaction
    /// committed): `publish.prev` holds the generation before it for good
    /// ([`APPLYING`]). Best effort: left behind, the next publish keeps an
    /// older generation, never a half-written one.
    pub fn finish(&self) {
        if self.applied {
            let _ = std::fs::remove_file(self.db_dir.join(PREV_DIR).join(APPLYING));
        }
    }

    /// What the [`PUBLISHED`] event records.
    pub fn record_data(&self) -> Published {
        let areas = self
            .plans
            .iter()
            .map(|plan| {
                let mut record = AreaRecord {
                    added: plan.added,
                    changed: plan.changed,
                    removed: plan.removed,
                    unchanged: plan.unchanged,
                    files: BTreeMap::new(),
                    symlinks: BTreeMap::new(),
                };
                for f in &plan.files {
                    match &f.new {
                        Some(Node::File { sha256, .. }) => {
                            record.files.insert(f.path.clone(), sha256.clone());
                        }
                        Some(Node::Symlink { target }) => {
                            record.symlinks.insert(f.path.clone(), target.clone());
                        }
                        _ => {}
                    }
                }
                (plan.area, record)
            })
            .collect();
        Published { rollback: self.rollback, source: self.source.clone(), areas, revisions: self.revisions.clone() }
    }

    /// Record the applied publish in the caller's write transaction: one
    /// [`PUBLISHED`] event, then the new revisions of the agent sets and the
    /// playbooks, with an `agents_changed` event for each that changed.
    /// Returns the agent sets' changes.
    pub fn record(&self, tx: &mut WriteCtx<'_>) -> Result<Vec<AgentsChanged>> {
        if !self.applied {
            return Err(invalid("a publish is recorded once it is applied"));
        }
        tx.emit(PUBLISHED, None, serde_json::to_value(self.record_data())?)?;
        let revisions = if self.publishes(Area::Agents) { self.revisions.clone() } else { BTreeMap::new() };
        let playbooks = self.playbooks_revision.as_ref().filter(|_| self.publishes(Area::Playbooks));
        Ok(agents::record_in(tx, &revisions, playbooks)?.harnesses)
    }
}

/// How an area on disk is made to mirror the staged one ([`steps`]).
#[derive(Debug, Default, PartialEq, Eq)]
struct Steps {
    /// Paths of the source to put in place (directories made real, files
    /// and symlinks written), parents first.
    writes: Vec<String>,
    /// Entries of the area the source spells otherwise, where names ignore
    /// case, to give the source's spelling: the path to the entry (under its
    /// parent as the source spells it), and the source's path. Parents first.
    renames: Vec<(String, String)>,
    /// Paths of the area the source lacks, deepest first.
    removals: Vec<String>,
}

/// The steps that make the area `target` mirror `source`. Where names
/// ignore case (`ignores_case`: APFS and NTFS by default), an entry of the
/// area that the source spells otherwise in case only is the same entry:
/// renamed to the source's spelling, never removed, as removing it would
/// remove what was just written there.
fn steps(source: &BTreeMap<String, Node>, target: &BTreeMap<String, Node>, ignores_case: bool) -> Steps {
    // ASCII only, as published names are: a legacy name is never taken for another by Unicode case rules.
    let key = |p: &str| if ignores_case { p.to_ascii_lowercase() } else { p.to_string() };
    let last = |p: &str| p.rsplit_once('/').map_or(p, |(_, l)| l).to_string();
    let found: BTreeMap<String, (&String, &Node)> = target.iter().map(|(p, n)| (key(p), (p, n))).collect();
    let mut steps = Steps::default();
    for (rel, node) in source {
        if *node == Node::Other {
            continue;
        }
        let there = found.get(&key(rel));
        if there.is_none_or(|(_, n)| *n != node) {
            steps.writes.push(rel.clone());
        }
        if let Some((spelled, _)) = there
            && last(spelled) != last(rel)
        {
            let from = match rel.rsplit_once('/') {
                Some((parent, _)) => format!("{parent}/{}", last(spelled)),
                None => last(spelled),
            };
            steps.renames.push((from, rel.clone()));
        }
    }
    let wanted: BTreeSet<String> = source.keys().map(|p| key(p)).collect();
    steps.removals = target.keys().rev().filter(|p| !wanted.contains(&key(p))).cloned().collect();
    steps
}

/// Whether the file system holding `dir` compares names without case: a
/// probe made there is found by its name in upper case.
fn ignores_case(dir: &Path) -> Result<bool> {
    let name = format!(".case.publish-{}", unique_hex());
    let probe = dir.join(&name);
    OpenOptions::new().write(true).create_new(true).open(&probe).map_err(|e| io_at(&probe, e))?;
    let found = std::fs::symlink_metadata(dir.join(name.to_ascii_uppercase())).is_ok();
    remove_entry(&probe)?;
    Ok(found)
}

/// Give the entry at `from` (where names ignore case, the entry at `to`)
/// the spelling of `to`, through a temp name; whether it was renamed.
fn respell(from: &Path, to: &Path) -> Result<bool> {
    let (Some(dir), Some(name)) = (to.parent(), to.file_name()) else { return Ok(false) };
    let entries = std::fs::read_dir(dir).map_err(|e| io_at(dir, e))?;
    if entries.flatten().any(|e| e.file_name() == name) {
        return Ok(false);
    }
    let tmp = temp_beside(to);
    std::fs::rename(from, &tmp).map_err(|e| io_at(from, e))?;
    std::fs::rename(&tmp, to).map_err(|e| io_at(to, e))?;
    Ok(true)
}

/// Make the area `dst` mirror the staged area `src`: writes first, then
/// case-only renames, removals last.
fn apply_area(src: &Path, dst: &Path, observe: Observe<'_>) -> Result<()> {
    match std::fs::symlink_metadata(dst) {
        Ok(m) if m.is_dir() => {}
        Ok(m) if m.file_type().is_symlink() => {
            return Err(Error::Refused(format!(
                "{} is a symlink; bd publish never writes through one (make it a directory)",
                dst.display()
            )));
        }
        Ok(_) => return Err(Error::Refused(format!("{} is not a directory", dst.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dst).map_err(|e| io_at(dst, e))?;
        }
        Err(e) => return Err(io_at(dst, e)),
    }
    let source = scan(src)?;
    let target = scan(dst)?;
    let steps = steps(&source, &target, ignores_case(dst)?);
    // Parents come before their entries, so each directory is made real before anything is written into it.
    for rel in &steps.writes {
        let to = under(dst, rel);
        match &source[rel] {
            Node::Dir => ensure_real_dir(&to)?,
            Node::File { executable, .. } => {
                let from = under(src, rel);
                let mut bytes = Vec::new();
                open_nofollow(&from).and_then(|mut f| f.read_to_end(&mut bytes)).map_err(|e| io_at(&from, e))?;
                let tmp = temp_beside(&to);
                write_new(&tmp, &bytes, *executable)?;
                rename_over(&tmp, &to)?;
            }
            Node::Symlink { target: link } => {
                let dir_hint = std::fs::metadata(under(src, rel)).is_ok_and(|m| m.is_dir());
                let tmp = temp_beside(&to);
                make_symlink(link, &tmp, dir_hint).map_err(|e| io_at(&tmp, e))?;
                rename_over(&tmp, &to)?;
            }
            Node::Other => continue,
        }
        observe(&to)?;
    }
    for (from, to) in &steps.renames {
        let to = under(dst, to);
        if respell(&under(dst, from), &to)? {
            observe(&to)?;
        }
    }
    // What the source holds now, by file identity: a directory may ignore case where the area's root does not
    // (Windows sets it per directory), and an entry that is one of these is never removed.
    let held: BTreeSet<FileId> = match steps.removals.is_empty() {
        true => BTreeSet::new(),
        false => source.keys().filter_map(|rel| file_id(&under(dst, rel))).collect(),
    };
    for rel in &steps.removals {
        let path = under(dst, rel);
        if file_id(&path).is_some_and(|id| held.contains(&id)) {
            continue;
        }
        match target[rel] {
            // Hidden entries left in it keep a directory.
            Node::Dir => {
                let _ = std::fs::remove_dir(&path);
            }
            _ => remove_entry(&path)?,
        }
        observe(&path)?;
    }
    Ok(())
}

/// What tells entries apart whatever name reaches them: the device and
/// inode on Unix (a symlink not followed); elsewhere the canonical path,
/// which on Windows carries each name's case as stored (none for a symlink,
/// whose canonical path is its target's).
#[cfg(unix)]
type FileId = (u64, u64);
#[cfg(not(unix))]
type FileId = PathBuf;

#[cfg(unix)]
fn file_id(path: &Path) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn file_id(path: &Path) -> Option<FileId> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() { None } else { std::fs::canonicalize(path).ok() }
}

/// Whether `name` is a temp name an apply makes (`.<name>.publish-<16 hex>`).
fn is_publish_temp(name: &str) -> bool {
    let Some((base, hex)) = name.strip_prefix('.').and_then(|rest| rest.rsplit_once(".publish-")) else {
        return false;
    };
    !base.is_empty() && hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Remove the temp files an interrupted apply left in the areas and in
/// `publish.prev` (under the publish lock, so none is in use); returns how
/// many. Never follows a symlink.
fn sweep_temps(db_dir: &Path) -> usize {
    let (mut swept, mut seen) = (0, 0);
    let mut stack: Vec<PathBuf> = Area::ALL
        .iter()
        .map(|a| db_dir.join(a.name()))
        .chain([db_dir.join(PREV_DIR)])
        .filter(|d| std::fs::symlink_metadata(d).is_ok_and(|m| m.is_dir()))
        .collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_SCAN_ENTRIES {
                return swept;
            }
            let (name, path) = (entry.file_name(), entry.path());
            let name = name.to_string_lossy();
            if is_publish_temp(&name) {
                swept += usize::from(remove_entry(&path).is_ok());
            } else if !name.starts_with('.') && std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                stack.push(path);
            }
        }
    }
    swept
}

/// Put `bytes` in the file `path`, atomically (a temp file renamed over it).
fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_beside(path);
    write_new(&tmp, bytes, false)?;
    rename_over(&tmp, path)
}

/// `msg` without the paths of the workspace's directory (`db_dir`, as given
/// and canonical) and of staging directories: errors name files by their
/// place in the areas (`playbooks/x.toml`), never where the server keeps them.
fn scrub_paths(msg: &str, db_dir: &Path) -> String {
    let canonical = std::fs::canonicalize(db_dir).unwrap_or_else(|_| db_dir.to_path_buf());
    let mut out = msg.to_string();
    for prefix in [&canonical, db_dir] {
        for sep in ['/', std::path::MAIN_SEPARATOR] {
            out = out.replace(&format!("{}{sep}", prefix.display()), "");
        }
        out = out.replace(&prefix.display().to_string(), ".");
    }
    // Staging directories by name: `.publish-<16 hex>/`.
    let (mut clean, mut rest) = (String::new(), out.as_str());
    while let Some(i) = rest.find(STAGING_PREFIX) {
        clean.push_str(&rest[..i]);
        let after = &rest[i + STAGING_PREFIX.len()..];
        let hex = after.bytes().take_while(u8::is_ascii_hexdigit).count();
        if hex == 16 && after[16..].starts_with(['/', std::path::MAIN_SEPARATOR]) {
            rest = &after[17..];
        } else {
            clean.push_str(STAGING_PREFIX);
            rest = after;
        }
    }
    clean.push_str(rest);
    clean
}

/// `e` with its message through [`scrub_paths`].
fn scrubbed(e: Error, db_dir: &Path) -> Error {
    match e {
        Error::Invalid(m) => Error::Invalid(scrub_paths(&m, db_dir)),
        Error::Refused(m) => Error::Refused(scrub_paths(&m, db_dir)),
        Error::Io(io) => Error::Io(std::io::Error::new(io.kind(), scrub_paths(&io.to_string(), db_dir))),
        e => e,
    }
}

/// What a [`PUBLISHED`] event holds:
///
/// ```json
/// {
///   "rollback": false,
///   "source": {"commit": "<sha>", "dirty": false},
///   "areas": {
///     "playbooks": {"added": 1, "changed": 0, "removed": 0, "unchanged": 3, "files": {"change.toml": "<sha256>"}},
///     "agents": {"added": 0, "changed": 1, "removed": 1, "unchanged": 9,
///                "files": {"claude/skills/deploy/SKILL.md": "<sha256>"},
///                "symlinks": {"codex/skills/deploy": "../../claude/skills/deploy"}}
///   },
///   "revisions": {"claude": "<sha256>", "codex": "<sha256>", "copilot": "<sha256>"}
/// }
/// ```
///
/// `source` is what the client reported; the hashes are the server's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    pub rollback: bool,
    #[serde(default)]
    pub source: SourceInfo,
    pub areas: BTreeMap<Area, AreaRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revisions: BTreeMap<Harness, String>,
}

/// One area in a [`Published`] event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AreaRecord {
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Each file's SHA-256, by path within the area.
    pub files: BTreeMap<String, String>,
    /// Each symlink's target, by path within the area.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub symlinks: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests;
