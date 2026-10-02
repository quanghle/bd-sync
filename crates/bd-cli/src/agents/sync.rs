//! The engine of `bd agents status` and `bd agents pull`: compare a
//! checkout with the sets a workspace serves and, for a pull, bring the
//! checkout up to date (the rules are in the [parent module](super)).
//!
//! [`run`] is the entry point: a [`Source`] supplies manifests and sets
//! (the server's, or a local workspace's own), [`Options`] say whether to
//! make the changes, and a [`Report`] says what changed or would change.
//! [`apply_approved`] writes MCP definitions a user approved.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use bd_core::agents::{AgentSet, FileDigest, Harness, Manifest, McpServer, mcp_digest};
use bd_core::{Error, Result};
use serde::Serialize;
use serde_json::Value;

use super::checkout::{Checkout, Found};
use super::lock::{Applied, LockFile, OwnedFile, OwnedMcp, skill_of, skill_path};
use super::mcp_file::{Change, McpFile, changed_fields, env_refs};

/// Where a workspace's sets come from: the server of a remote workspace,
/// or a local workspace's own `.bd/agents`. Each answer is checked
/// ([`Manifest::check`], [`AgentSet::check`]) before it is returned.
pub trait Source {
    /// The manifests of `harnesses`, one each.
    fn manifests(&mut self, harnesses: &[Harness]) -> Result<BTreeMap<Harness, Manifest>>;
    /// `harness`'s whole set.
    fn fetch(&mut self, harness: Harness) -> Result<AgentSet>;
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Make the changes (pull); without, only report them (status).
    pub apply: bool,
    /// Also replace or remove local edits of what bd wrote, and try again to
    /// set executable bits the file system did not keep. Never anything bd
    /// did not write, and MCP definitions still wait for approval.
    pub force: bool,
    /// How long to wait for another bd process changing the same checkout.
    pub lock_wait: Duration,
}

/// What [`run`] found and did: see the [parent module](super) for its JSON.
#[derive(Debug, Serialize)]
pub struct Report {
    /// The changes listed were made (pull), rather than would be (status).
    pub applied: bool,
    pub checkout: PathBuf,
    pub harnesses: BTreeMap<Harness, HarnessReport>,
}

#[derive(Debug, Default, Serialize)]
pub struct HarnessReport {
    pub server_revision: String,
    /// The server revision the checkout last pulled (after a pull: this one).
    pub applied_revision: Option<String>,
    pub skills: SkillsReport,
    pub mcp: McpReport,
    /// Environment variables the MCP definitions (in effect, or waiting for
    /// approval) take values from, and that are unset or empty here.
    pub unset_env: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct SkillsReport {
    /// Each skill with files written or removed, and how it changed.
    pub changed: BTreeMap<String, SkillChange>,
    pub added: Vec<SkillFileRef>,
    pub updated: Vec<SkillFileRef>,
    /// Files bd wrote that were deleted here, written again.
    pub restored: Vec<SkillFileRef>,
    /// Local edits of files bd wrote, replaced (`--force`).
    pub replaced: Vec<SkillFileRef>,
    pub removed: Vec<SkillFileRef>,
    /// Files bd did not write that hold the server's version already: now bd's, untouched.
    pub adopted: Vec<SkillFileRef>,
    /// Files bd wrote that were edited here, with no newer version on the server: kept.
    pub edited: Vec<SkillFileRef>,
    /// Executable files whose executable bit the file system here did not
    /// keep when bd set it (vfat, an SMB mount whose fmask clears it): they
    /// stay without it, and later pulls leave them be.
    pub not_executable: Vec<SkillFileRef>,
    pub conflicts: Vec<Conflict>,
    /// What stays where the server removed something: files bd did not write, symlinks.
    pub left: Vec<Conflict>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillChange {
    /// New in this checkout.
    Added,
    Updated,
    /// Gone from the server.
    Removed,
    Restored,
    Replaced,
}

#[derive(Debug, Serialize)]
pub struct SkillFileRef {
    pub skill: String,
    /// Checkout-relative, `/`-separated.
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct Conflict {
    pub skill: String,
    /// What is in the way, checkout-relative: the file, or a directory or symlink above it.
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default, Serialize)]
pub struct McpReport {
    /// The harness's MCP file, checkout-relative.
    pub file: String,
    /// New and changed definitions, waiting for `bd agents approve`.
    pub pending: Vec<Pending>,
    pub removed: Vec<String>,
    pub restored: Vec<String>,
    pub replaced: Vec<String>,
    pub adopted: Vec<String>,
    pub edited: Vec<String>,
    pub conflicts: Vec<McpConflict>,
}

#[derive(Debug, Serialize)]
pub struct Pending {
    pub name: String,
    pub change: PendingChange,
    /// For a changed entry, the top-level fields that differ from the
    /// definition approved before.
    pub fields: Vec<String>,
    /// The entry was edited here since it was approved: approving the
    /// server's definition replaces the edit.
    pub edited: bool,
    /// The definition approved before, for a changed entry.
    #[serde(skip)]
    pub approved: Option<Value>,
    /// The server's entry.
    #[serde(skip)]
    pub server: Option<McpServer>,
    /// [`mcp_digest`] of the MCP file's entry of this name, as found; `None`: there is none.
    #[serde(skip)]
    pub local: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingChange {
    New,
    Changed,
}

#[derive(Debug, Serialize)]
pub struct McpConflict {
    /// The entry; `None` for the whole file.
    pub name: Option<String>,
    pub reason: String,
    /// An entry bd did not write stands where the server has one.
    #[serde(skip)]
    pub foreign: bool,
}

/// What a pull does for one harness, and the report of it.
struct Plan {
    harness: Harness,
    revision: String,
    skills: Vec<SkillOp>,
    mcp: Vec<McpOp>,
    mcp_file: McpFile,
    report: HarnessReport,
}

enum SkillOp {
    /// Write the server's file.
    Write { skill: String, rel: String, digest: FileDigest },
    /// Delete the file if it still has this hash.
    Remove { skill: String, rel: String, sha256: String },
    /// Set the file's executable bits as the server's file has them, if it
    /// still has this hash, and record it as the server's. `quiet`: a retry
    /// of a bit the file system did not keep, reported only if it now does.
    Mode { skill: String, rel: String, sha256: String, digest: FileDigest, quiet: bool },
    /// Record a file as bd's.
    Record { path: String, digest: FileDigest },
    /// Drop a file from the record.
    Forget { path: String },
}

enum McpOp {
    /// Write the server's entry, as approved before.
    Put { name: String },
    /// Remove the file's entry.
    Remove { name: String },
    /// Record the file's entry as bd's.
    Record { name: String, owned: OwnedMcp },
    /// Drop an entry from the record.
    Forget { name: String },
}

impl Plan {
    /// Whether it writes files, which takes the set's contents.
    fn writes(&self) -> bool {
        self.skills.iter().any(|op| matches!(op, SkillOp::Write { .. }))
            || self.mcp.iter().any(|op| matches!(op, McpOp::Put { .. }))
    }

    /// Whether MCP changes wait for approval: showing them takes the set's definitions.
    fn pending(&self) -> bool {
        !self.report.mcp.pending.is_empty()
    }

    /// Whether a pull would change nothing: no file, and no record in
    /// `lock`, which a harness never pulled before has none of while
    /// nothing is served for it.
    fn idle(&self, lock: &LockFile) -> bool {
        self.skills.is_empty()
            && self.mcp.is_empty()
            && match lock.harnesses.get(&self.harness) {
                Some(applied) => applied.revision == self.revision,
                None => self.revision == AgentSet::empty(self.harness).revision,
            }
    }
}

/// Compare the checkout with the sets `source` serves for `harnesses` and,
/// with `opts.apply`, bring it up to date. Without changes to make, this is
/// one call of [`Source::manifests`]; a set is fetched whole only when its
/// files are to be written or its MCP changes shown.
pub fn run(checkout: &Checkout, source: &mut dyn Source, harnesses: &[Harness], opts: Options) -> Result<Report> {
    let manifests = source.manifests(harnesses)?;
    let manifest =
        |h: Harness| manifests.get(&h).ok_or_else(|| Error::Remote(format!("the workspace sent no {h} manifest")));
    // A first look, which a pull takes again under the mutex.
    let (first, mut plans) = {
        let _reading = if opts.apply { None } else { checkout.shared(opts.lock_wait)? };
        let lock = checkout.read_lock()?;
        let mut plans = Vec::new();
        for &h in harnesses {
            plans.push(plan(checkout, h, manifest(h)?, None, lock.harnesses.get(&h), opts.force)?);
        }
        (lock, plans)
    };
    let mut sets = BTreeMap::new();
    for p in &plans {
        if (opts.apply && p.writes()) || p.pending() {
            sets.insert(p.harness, source.fetch(p.harness)?);
        }
    }
    if !opts.apply {
        if !sets.is_empty() {
            let _reading = checkout.shared(opts.lock_wait)?;
            let lock = checkout.read_lock()?;
            for p in plans.iter_mut() {
                if let Some(set) = sets.get(&p.harness) {
                    let applied = lock.harnesses.get(&p.harness);
                    *p = plan(checkout, p.harness, &set.manifest(), Some(set), applied, opts.force)?;
                }
            }
        }
        return Ok(report(checkout, false, plans));
    }
    if sets.is_empty() && plans.iter().all(|p| p.idle(&first)) {
        return Ok(report(checkout, true, plans));
    }
    let _mutex = checkout.exclusive(opts.lock_wait)?;
    let mut lock = checkout.read_lock()?;
    let before = lock.clone();
    plans.clear();
    let pulled = pull(checkout, source, harnesses, &manifests, &mut sets, &mut lock, opts.force, &mut plans);
    // What was done is recorded, even when something failed.
    let recorded = if lock != before { checkout.write_lock(&lock) } else { Ok(()) };
    pulled?;
    recorded?;
    Ok(report(checkout, true, plans))
}

/// A pull, with the checkout's mutex held: plan each harness again, fetch
/// the sets that turn out to be needed, and make the changes, recording
/// them in `lock` as they are made.
#[allow(clippy::too_many_arguments)]
fn pull(
    checkout: &Checkout,
    source: &mut dyn Source,
    harnesses: &[Harness],
    manifests: &BTreeMap<Harness, Manifest>,
    sets: &mut BTreeMap<Harness, AgentSet>,
    lock: &mut LockFile,
    force: bool,
    plans: &mut Vec<Plan>,
) -> Result<()> {
    for &h in harnesses {
        let replan = |set: Option<&AgentSet>, lock: &LockFile| match set {
            Some(set) => plan(checkout, h, &set.manifest(), Some(set), lock.harnesses.get(&h), force),
            None => plan(checkout, h, &manifests[&h], None, lock.harnesses.get(&h), force),
        };
        let mut p = replan(sets.get(&h), lock)?;
        if (p.writes() || p.pending()) && !sets.contains_key(&h) {
            let set = source.fetch(h)?;
            p = replan(Some(&set), lock)?;
            sets.insert(h, set);
        }
        let applied = lock.harnesses.entry(h).or_default();
        apply(checkout, &mut p, sets.get(&h), applied)?;
        p.report.applied_revision = Some(applied.revision.clone());
        plans.push(p);
    }
    Ok(())
}

fn report(checkout: &Checkout, applied: bool, plans: Vec<Plan>) -> Report {
    let harnesses = plans.into_iter().map(|p| (p.harness, p.report)).collect();
    Report { applied, checkout: checkout.root.clone(), harnesses }
}

/// What a pull would do for `h`, from the server's `manifest` (with its
/// `set`, when fetched: it gives pending MCP changes their fields), what
/// the lock records (`applied`), and what the checkout holds.
fn plan(
    checkout: &Checkout,
    h: Harness,
    manifest: &Manifest,
    set: Option<&AgentSet>,
    applied: Option<&Applied>,
    force: bool,
) -> Result<Plan> {
    let mut p = Plan {
        harness: h,
        revision: manifest.revision.clone(),
        skills: Vec::new(),
        mcp: Vec::new(),
        mcp_file: McpFile::read(&checkout.root, h)?,
        report: HarnessReport {
            server_revision: manifest.revision.clone(),
            // Empty: MCP entries were approved, but nothing was pulled yet.
            applied_revision: applied.map(|a| a.revision.clone()).filter(|r| !r.is_empty()),
            ..Default::default()
        },
    };
    let none = Applied::default();
    let applied = applied.unwrap_or(&none);
    plan_skills(checkout, &mut p, manifest, applied, force)?;
    let mut env = BTreeSet::new();
    plan_mcp(&mut p, manifest, set, applied, force, &mut env);
    p.report.unset_env = env.into_iter().filter(|v| std::env::var_os(v).is_none_or(|v| v.is_empty())).collect();
    Ok(p)
}

/// Checkout-relative paths, found by their ASCII lowercase form (skill
/// file paths are ASCII).
struct Paths(BTreeMap<String, Vec<String>>);

impl Paths {
    fn new<'a>(paths: impl IntoIterator<Item = &'a String>) -> Paths {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for path in paths {
            map.entry(path.to_ascii_lowercase()).or_default().push(path.clone());
        }
        Paths(map)
    }

    /// Whether `rel` is one of the paths, or another case of one that
    /// reaches the same file (on a file system that ignores case).
    fn reaches(&self, checkout: &Checkout, rel: &str) -> bool {
        self.0
            .get(&rel.to_ascii_lowercase())
            .is_some_and(|paths| paths.iter().any(|path| path == rel || checkout.same_file(path, rel)))
    }
}

/// What becomes of one skill file.
enum FileDecision {
    Write(SkillChange),
    /// Record it as bd's: adopt it.
    Record,
    /// Record the server's digest for it: nothing changes on disk.
    Rerecord,
    /// Delete it, which has this hash.
    Remove(String),
    /// Give it the server's executable bits; it has the server's text, with this hash.
    Mode(String),
    /// Give it the server's executable bit again, which the file system did
    /// not keep last time: reported only if it keeps it now.
    RetryMode(String),
    Forget,
    /// Kept: edited here, and the server has nothing newer.
    Edited,
    /// Kept: edited here (it has this hash), where the server changed only
    /// the executable bit, which it gets.
    EditedMode(String),
    /// Kept: edited here, where the server changed only the executable bit,
    /// which a file system without such bits only records.
    EditedRecord,
    Nothing,
    /// Something in the way, at the path given.
    Conflict(String, String),
    /// In the way where the server removed a file: forgotten, and left there.
    Left(String, String),
}

fn plan_skills(checkout: &Checkout, p: &mut Plan, manifest: &Manifest, applied: &Applied, force: bool) -> Result<()> {
    use FileDecision as D;
    let h = p.harness;
    let mut server: BTreeMap<String, (&str, &str, &FileDigest)> = BTreeMap::new();
    for (name, files) in &manifest.skills {
        for (rel, digest) in files {
            server.insert(skill_path(h, name, rel), (name, rel, digest));
        }
    }
    let r = &mut p.report.skills;
    let mut changes: BTreeMap<String, BTreeSet<SkillChange>> = BTreeMap::new();
    let mut reported: BTreeSet<String> = BTreeSet::new();
    let paths: BTreeSet<&String> = server.keys().chain(applied.skills.keys()).collect();
    let mut found = BTreeMap::new();
    for &path in &paths {
        let (skill, rel) = match server.get(path) {
            Some(&(name, rel, _)) => (name, rel),
            None => skill_of(h, path).expect("lock file paths are checked when it is read"),
        };
        found.insert(path, (skill, rel, checkout.find_skill_file(h, skill, rel)?));
    }
    // The files the server removed that go, before anything is written: a
    // server file that only they stand in the way of is written after them.
    // That is a file of the same name as a new directory, or the other way
    // round, and, where the file system ignores case, the same file under a
    // name the server changed only in case (`Notes.md` to `notes.md`).
    let removing = Paths::new(found.iter().filter_map(|(path, (_, _, f))| {
        let owned = applied.skills.get(*path)?;
        let goes =
            !server.contains_key(*path) && matches!(f, Found::File { sha256, .. } if force || *sha256 == owned.sha256);
        goes.then_some(*path)
    }));
    for (path, (skill, rel, mut local)) in found {
        let in_the_way = match &local {
            _ if !server.contains_key(path) => false,
            Found::File { .. } => removing.reaches(checkout, path),
            Found::Blocked { at, .. } => {
                removing.reaches(checkout, at)
                    || checkout.holds_only(at, &mut |rel| Ok(removing.reaches(checkout, rel)))?
            }
            Found::Missing => false,
        };
        if in_the_way {
            local = Found::Missing;
        }
        let entry = server.get(path);
        // The server's file is executable: so must this one be (an extra
        // executable bit is left alone, as file systems without them show
        // every file executable).
        let mode_ok = |executable: bool, digest: &FileDigest| !cfg!(unix) || executable || !digest.executable;
        let digest = entry.map(|e| e.2);
        let decision = match (digest, applied.skills.get(path), local) {
            (Some(_), _, Found::Blocked { at, what }) => {
                D::Conflict(at, format!("{what}, which bd never writes over or through; left as it is"))
            }
            (None, _, Found::Blocked { at, what }) => {
                D::Left(at, format!("{what}, where the server removed a file; left as it is"))
            }
            (Some(_), None, Found::Missing) => D::Write(SkillChange::Added),
            (Some(s), None, Found::File { sha256: sha, executable: x }) if sha == s.sha256 => {
                if mode_ok(x, s) {
                    D::Record
                } else {
                    D::Mode(sha)
                }
            }
            (Some(_), None, Found::File { .. }) => D::Conflict(
                path.clone(),
                "differs from the server's and was not written by bd; left as it is (move it away to get the \
                 server's)"
                    .into(),
            ),
            (Some(_), Some(_), Found::Missing) => D::Write(SkillChange::Restored),
            // The server's text is here, as bd left it: only the mode may need a change.
            (Some(s), Some(o), Found::File { sha256: sha, executable: x }) if sha == o.sha256 && sha == s.sha256 => {
                match (o.executable != s.executable, mode_ok(x, s)) {
                    // The server changed the executable bit: applied either way.
                    (true, _) if cfg!(unix) => D::Mode(sha),
                    (true, _) => D::Rerecord,
                    // It has the bit the file system did not keep before (set by hand, or kept now).
                    (false, true) if o.executable_not_kept => D::Rerecord,
                    (false, true) => D::Nothing,
                    // The file system did not keep the bit: up to date without it. Tried
                    // again with --force, or quietly when the server's set changes.
                    (false, false) if o.executable_not_kept && force => D::Mode(sha),
                    (false, false) if o.executable_not_kept && applied.revision != manifest.revision => {
                        D::RetryMode(sha)
                    }
                    (false, false) if o.executable_not_kept => D::Nothing,
                    (false, false) => D::Mode(sha),
                }
            }
            (Some(_), Some(o), Found::File { sha256: sha, .. }) if sha == o.sha256 => D::Write(SkillChange::Updated),
            (Some(s), Some(_), Found::File { sha256: sha, executable: x }) if sha == s.sha256 => {
                if mode_ok(x, s) {
                    D::Record
                } else {
                    D::Mode(sha)
                }
            }
            (Some(_), Some(_), Found::File { .. }) if force => D::Write(SkillChange::Replaced),
            // Edited here, with the text bd wrote still the server's: a change of the executable
            // bit alone touches no text, so it never conflicts with the edit.
            (Some(s), Some(o), Found::File { sha256: sha, .. }) if o.sha256 == s.sha256 => {
                match (o.executable != s.executable, cfg!(unix)) {
                    (false, _) => D::Edited,
                    (true, true) => D::EditedMode(sha),
                    (true, false) => D::EditedRecord,
                }
            }
            (Some(_), Some(_), Found::File { .. }) => D::Conflict(
                path.clone(),
                "edited here and changed on the server; kept (`bd agents pull --force` replaces it)".into(),
            ),
            (None, Some(_), Found::Missing) => D::Forget,
            (None, Some(o), Found::File { sha256: sha, .. }) if force || sha == o.sha256 => D::Remove(sha),
            (None, Some(_), Found::File { .. }) => D::Conflict(
                path.clone(),
                "edited here and removed from the server; kept (`bd agents pull --force` removes it)".into(),
            ),
            (None, None, _) => unreachable!("every path is the server's or recorded"),
        };
        let file_ref = SkillFileRef { skill: skill.to_string(), path: path.clone() };
        match decision {
            D::Write(change) => {
                let digest = digest.expect("written from the server's").clone();
                p.skills.push(SkillOp::Write { skill: skill.to_string(), rel: rel.to_string(), digest });
                let list = match change {
                    SkillChange::Added => &mut r.added,
                    SkillChange::Updated => &mut r.updated,
                    SkillChange::Restored => &mut r.restored,
                    SkillChange::Replaced => &mut r.replaced,
                    SkillChange::Removed => &mut r.removed,
                };
                list.push(file_ref);
                changes.entry(skill.to_string()).or_default().insert(change);
            }
            D::Record => {
                let digest = digest.expect("recorded as the server's").clone();
                p.skills.push(SkillOp::Record { path: path.clone(), digest });
                r.adopted.push(file_ref);
            }
            D::Rerecord => {
                let digest = digest.expect("recorded as the server's").clone();
                p.skills.push(SkillOp::Record { path: path.clone(), digest });
            }
            D::Remove(sha256) => {
                p.skills.push(SkillOp::Remove { skill: skill.to_string(), rel: rel.to_string(), sha256 });
                r.removed.push(file_ref);
                changes.entry(skill.to_string()).or_default().insert(SkillChange::Removed);
            }
            D::Mode(sha256) => {
                let digest = digest.expect("the server's mode").clone();
                let op = SkillOp::Mode { skill: skill.to_string(), rel: rel.to_string(), sha256, digest, quiet: false };
                p.skills.push(op);
                r.updated.push(file_ref);
                changes.entry(skill.to_string()).or_default().insert(SkillChange::Updated);
            }
            D::RetryMode(sha256) => {
                let digest = digest.expect("the server's mode").clone();
                let op = SkillOp::Mode { skill: skill.to_string(), rel: rel.to_string(), sha256, digest, quiet: true };
                p.skills.push(op);
            }
            D::Forget => p.skills.push(SkillOp::Forget { path: path.clone() }),
            D::Edited => r.edited.push(file_ref),
            D::EditedMode(sha256) => {
                let digest = digest.expect("the server's mode").clone();
                let op = SkillOp::Mode { skill: skill.to_string(), rel: rel.to_string(), sha256, digest, quiet: false };
                p.skills.push(op);
                r.edited.push(SkillFileRef { skill: skill.to_string(), path: path.clone() });
                r.updated.push(file_ref);
                changes.entry(skill.to_string()).or_default().insert(SkillChange::Updated);
            }
            D::EditedRecord => {
                let digest = digest.expect("recorded as the server's").clone();
                p.skills.push(SkillOp::Record { path: path.clone(), digest });
                r.edited.push(file_ref);
            }
            D::Nothing => {}
            D::Conflict(at, reason) => {
                if reported.insert(at.clone()) {
                    r.conflicts.push(Conflict { skill: skill.to_string(), path: at, reason });
                }
            }
            D::Left(at, reason) => {
                p.skills.push(SkillOp::Forget { path: path.clone() });
                if reported.insert(at.clone()) {
                    r.left.push(Conflict { skill: skill.to_string(), path: at, reason });
                }
            }
        }
    }
    let owned_skills: BTreeSet<&str> =
        applied.skills.keys().filter_map(|path| skill_of(h, path).map(|(name, _)| name)).collect();
    for (skill, kinds) in changes {
        let only = |allowed: &[SkillChange]| kinds.iter().all(|k| allowed.contains(k));
        let change = if !manifest.skills.contains_key(&skill) {
            SkillChange::Removed
        } else if !owned_skills.contains(skill.as_str()) {
            // New here: its files are written, or adopted (an executable bit set, at most).
            SkillChange::Added
        } else if only(&[SkillChange::Restored]) {
            SkillChange::Restored
        } else if only(&[SkillChange::Restored, SkillChange::Replaced]) {
            SkillChange::Replaced
        } else {
            SkillChange::Updated
        };
        r.changed.insert(skill, change);
    }
    // A skill the server removed whose directory holds other files stays, with them.
    for skill in owned_skills.into_iter().filter(|s| !manifest.skills.contains_key(*s)) {
        let dir = format!("{}/{skill}", h.skills_dest());
        let owned = Paths::new(applied.skills.keys().filter(|path| skill_of(h, path).is_some_and(|(n, _)| n == skill)));
        if !reported.contains(&dir) && !checkout.holds_only(&dir, &mut |rel| Ok(owned.reaches(checkout, rel)))? {
            let reason = "removed from the server; the directory stays, as it holds what bd did not write".into();
            r.left.push(Conflict { skill: skill.to_string(), path: dir, reason });
        }
    }
    Ok(())
}

/// What becomes of one MCP server entry.
enum EntryDecision {
    Pending(PendingChange, bool),
    /// Record it as bd's (adopt it), as found here.
    Record,
    /// Up to date.
    Nothing,
    /// Write the approved definition: restore it (`false`) or replace a local edit (`true`).
    Put(bool),
    Remove,
    Forget,
    /// Kept: edited here, and the server has nothing newer.
    Edited,
    Conflict(String),
}

fn plan_mcp(
    p: &mut Plan,
    manifest: &Manifest,
    set: Option<&AgentSet>,
    applied: &Applied,
    force: bool,
    env: &mut BTreeSet<String>,
) {
    use EntryDecision as D;
    let h = p.harness;
    let file = &p.mcp_file;
    let r = &mut p.report.mcp;
    r.file = h.mcp_dest().to_string();
    if let Some(why) = &file.unusable {
        let reason = format!("{}: {why}; its MCP servers are left alone until it is fixed", r.file);
        r.conflicts.push(McpConflict { name: None, reason, foreign: false });
        return;
    }
    let refused = |what: &str| format!("not {what}: {}: {}", h.mcp_dest(), file.read_only.as_deref().unwrap_or(""));
    let writable = file.read_only.is_none();
    let names: BTreeSet<&String> = manifest.mcp_servers.keys().chain(applied.mcp_servers.keys()).collect();
    for name in names {
        let server = manifest.mcp_servers.get(name).map(|d| d.sha256.as_str());
        let owned = applied.mcp_servers.get(name);
        let local = file.entries.get(name).map(|def| (def, mcp_digest(def)));
        let entry = set.and_then(|s| s.mcp_servers.get(name));
        let decision = match (server, owned, &local) {
            (Some(_), None, None) => D::Pending(PendingChange::New, false),
            (Some(s), _, Some((_, sha))) if sha == s => {
                if owned.is_some_and(|o| o.sha256 == s) {
                    D::Nothing
                } else {
                    D::Record
                }
            }
            (Some(_), None, Some(_)) => D::Conflict(format!(
                "in {}, differs from the server's and was not written by bd; left as it is",
                h.mcp_dest()
            )),
            (Some(s), Some(o), None) if s == o.sha256 => {
                if writable {
                    D::Put(false)
                } else {
                    D::Conflict(refused("restored"))
                }
            }
            (Some(_), Some(_), None) => D::Pending(PendingChange::Changed, false),
            (Some(_), Some(o), Some((_, sha))) if *sha == o.sha256 => D::Pending(PendingChange::Changed, false),
            (Some(s), Some(o), Some(_)) if s == o.sha256 => {
                if force && writable {
                    D::Put(true)
                } else {
                    D::Edited
                }
            }
            (Some(_), Some(_), Some(_)) => D::Pending(PendingChange::Changed, true),
            (None, Some(_), None) => D::Forget,
            (None, Some(o), Some((_, sha))) if force || *sha == o.sha256 => {
                if writable {
                    D::Remove
                } else {
                    D::Conflict(refused("removed"))
                }
            }
            (None, Some(_), Some(_)) => D::Conflict(
                "edited here and removed from the server; kept (`bd agents pull --force` removes it)".into(),
            ),
            (None, None, _) => unreachable!("every name is the server's or recorded"),
        };
        // The variables of the definitions in effect here, and of those waiting for approval.
        let in_effect = match &decision {
            D::Record | D::Nothing | D::Edited | D::Pending(..) => local.as_ref().map(|(def, _)| *def),
            D::Put(_) => owned.map(|o| &o.definition),
            _ => None,
        };
        let waiting = if matches!(decision, D::Pending(..)) { entry.map(|e| &e.definition) } else { None };
        for def in in_effect.into_iter().chain(waiting) {
            env_refs(h, def, env);
        }
        match decision {
            D::Pending(change, edited) => r.pending.push(Pending {
                name: name.clone(),
                change,
                fields: match (owned, entry) {
                    (Some(o), Some(e)) if change == PendingChange::Changed => {
                        changed_fields(&o.definition, &e.definition)
                    }
                    _ => Vec::new(),
                },
                edited,
                approved: owned.map(|o| o.definition.clone()),
                server: entry.cloned(),
                local: local.as_ref().map(|(_, sha)| sha.clone()),
            }),
            D::Record => {
                let (def, sha) = local.expect("adopted as found");
                p.mcp.push(McpOp::Record {
                    name: name.clone(),
                    owned: OwnedMcp { sha256: sha, definition: def.clone() },
                });
                r.adopted.push(name.clone());
            }
            D::Nothing => {}
            D::Put(replaced) => {
                p.mcp.push(McpOp::Put { name: name.clone() });
                if replaced { r.replaced.push(name.clone()) } else { r.restored.push(name.clone()) }
            }
            D::Remove => {
                p.mcp.push(McpOp::Remove { name: name.clone() });
                r.removed.push(name.clone());
            }
            D::Forget => p.mcp.push(McpOp::Forget { name: name.clone() }),
            D::Edited => r.edited.push(name.clone()),
            D::Conflict(reason) => {
                let foreign = owned.is_none();
                r.conflicts.push(McpConflict { name: Some(name.clone()), reason, foreign });
            }
        }
    }
}

/// Make `p`'s changes, recording each in `applied` as it is made.
fn apply(checkout: &Checkout, p: &mut Plan, set: Option<&AgentSet>, applied: &mut Applied) -> Result<()> {
    let h = p.harness;
    let missing = |what: String| Error::Remote(format!("the workspace's {h} set lacks {what}"));
    // Removals first: a file the server removed may stand where one of its new files goes.
    let (removals, others): (Vec<&SkillOp>, Vec<&SkillOp>) =
        p.skills.iter().partition(|op| matches!(op, SkillOp::Remove { .. }));
    let r = &mut p.report.skills;
    for op in removals.into_iter().chain(others) {
        let file_ref =
            |skill: &str, rel: &str| SkillFileRef { skill: skill.to_string(), path: skill_path(h, skill, rel) };
        match op {
            SkillOp::Write { skill, rel, digest } => {
                let file =
                    set.and_then(|s| s.skills.get(skill)?.get(rel)).ok_or_else(|| missing(format!("{skill}/{rel}")))?;
                let owned = OwnedFile::of(digest, !checkout.write_skill_file(h, skill, rel, file)?);
                if owned.executable_not_kept {
                    r.not_executable.push(file_ref(skill, rel));
                }
                applied.skills.insert(skill_path(h, skill, rel), owned);
            }
            SkillOp::Remove { skill, rel, sha256 } => {
                // A file edited since it was planned for is left, and stays recorded.
                if checkout.remove_skill_file(h, skill, rel, sha256)? {
                    applied.skills.remove(&skill_path(h, skill, rel));
                }
            }
            SkillOp::Mode { skill, rel, sha256, digest, quiet } => {
                if let Some(kept) = checkout.set_skill_mode(h, skill, rel, sha256, digest.executable)? {
                    let owned = OwnedFile::of(digest, !kept);
                    match (owned.executable_not_kept, quiet) {
                        (true, false) => r.not_executable.push(file_ref(skill, rel)),
                        (false, true) => {
                            r.updated.push(file_ref(skill, rel));
                            r.changed.entry(skill.clone()).or_insert(SkillChange::Updated);
                        }
                        _ => {}
                    }
                    applied.skills.insert(skill_path(h, skill, rel), owned);
                }
            }
            SkillOp::Record { path, digest } => {
                applied.skills.insert(path.clone(), OwnedFile::of(digest, false));
            }
            SkillOp::Forget { path } => {
                applied.skills.remove(path);
            }
        }
    }
    let mut changes = Vec::new();
    for op in &p.mcp {
        match op {
            McpOp::Put { name } => {
                let entry =
                    set.and_then(|s| s.mcp_servers.get(name)).ok_or_else(|| missing(format!("MCP server {name}")))?;
                changes.push(Change::Put(name, entry));
            }
            McpOp::Remove { name } => changes.push(Change::Remove(name)),
            McpOp::Record { .. } | McpOp::Forget { .. } => {}
        }
    }
    if !changes.is_empty() {
        p.mcp_file.apply(&changes)?;
    }
    for op in &p.mcp {
        match op {
            McpOp::Put { name } => {
                let entry = &set.expect("checked above").mcp_servers[name];
                let owned = OwnedMcp { sha256: entry.sha256.clone(), definition: entry.definition.clone() };
                applied.mcp_servers.insert(name.clone(), owned);
            }
            McpOp::Record { name, owned } => {
                applied.mcp_servers.insert(name.clone(), owned.clone());
            }
            McpOp::Remove { name } | McpOp::Forget { name } => {
                applied.mcp_servers.remove(name);
            }
        }
    }
    applied.revision = p.revision.clone();
    Ok(())
}

/// An MCP server entry the user approved, with what the checkout held of
/// it when it was shown.
pub struct Approval<'a> {
    pub name: &'a str,
    /// The server's entry as shown: what is written.
    pub server: &'a McpServer,
    /// [`mcp_digest`] of the MCP file's entry when shown; `None`: there was none.
    pub local: Option<&'a str>,
    /// The sha256 `.bd/agents.lock` recorded for it when shown; `None`: none.
    pub recorded: Option<&'a str>,
}

/// What [`apply_approved`] did for one harness.
#[derive(Debug, Default)]
pub struct ApprovedEntries {
    /// The entries written (or already there, as approved) and recorded.
    pub written: Vec<String>,
    /// The entries left as they are, with why.
    pub skipped: Vec<(String, String)>,
}

/// Write MCP server entries the user approved into each harness's MCP
/// file, each replacing the file's entry of its name, and record them in
/// the lock as bd's: what `bd agents approve` does once the user has
/// answered. An entry whose place in the file or the lock changed since it
/// was shown is skipped, as is every entry of a file bd cannot write. Takes
/// the checkout's mutex, waiting up to `lock_wait`.
pub fn apply_approved(
    checkout: &Checkout,
    approvals: &BTreeMap<Harness, Vec<Approval<'_>>>,
    lock_wait: Duration,
) -> Result<BTreeMap<Harness, ApprovedEntries>> {
    for a in approvals.values().flatten() {
        if mcp_digest(&a.server.definition) != a.server.sha256 {
            return Err(Error::invalid(format!("MCP server {}: its definition does not match its sha256", a.name)));
        }
    }
    let _mutex = checkout.exclusive(lock_wait)?;
    let mut lock = checkout.read_lock()?;
    let before = lock.clone();
    let mut done = BTreeMap::new();
    let mut approve = || -> Result<()> {
        for (&h, list) in approvals {
            done.insert(h, approve_entries(checkout, h, list, &mut lock)?);
        }
        Ok(())
    };
    let approved = approve();
    // What was written is recorded, even when something failed.
    let recorded = if lock != before { checkout.write_lock(&lock) } else { Ok(()) };
    approved?;
    recorded?;
    Ok(done)
}

fn approve_entries(
    checkout: &Checkout,
    h: Harness,
    approvals: &[Approval<'_>],
    lock: &mut LockFile,
) -> Result<ApprovedEntries> {
    let mut done = ApprovedEntries::default();
    let rel = h.mcp_dest();
    let mut file = McpFile::read(&checkout.root, h)?;
    if let Some(why) = file.unusable.as_ref().or(file.read_only.as_ref()) {
        let reason = format!("{rel}: {why}; bd does not write it");
        done.skipped.extend(approvals.iter().map(|a| (a.name.to_string(), reason.clone())));
        return Ok(done);
    }
    let mut unchanged = Vec::new();
    for a in approvals {
        let local = file.entries.get(a.name).map(mcp_digest);
        let recorded = lock.harnesses.get(&h).and_then(|r| r.mcp_servers.get(a.name)).map(|o| o.sha256.as_str());
        if local.as_deref() == a.local && recorded == a.recorded {
            unchanged.push(a);
        } else {
            let reason = format!(
                "its entry in {rel} or .bd/agents.lock changed since it was shown; run `bd agents approve` again to \
                 review it"
            );
            done.skipped.push((a.name.to_string(), reason));
        }
    }
    if unchanged.is_empty() {
        return Ok(done);
    }
    let changes: Vec<Change<'_>> = unchanged.iter().map(|a| Change::Put(a.name, a.server)).collect();
    file.apply(&changes)?;
    let applied = lock.harnesses.entry(h).or_default();
    for a in unchanged {
        let owned = OwnedMcp { sha256: a.server.sha256.clone(), definition: a.server.definition.clone() };
        applied.mcp_servers.insert(a.name.to_string(), owned);
        done.written.push(a.name.to_string());
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bd_core::agents::{AGENTS_DIR, under};
    use std::path::Path;

    /// A local workspace serving `<dir>/.bd/agents` to its own checkout, `<dir>`.
    struct Fixture {
        _dir: tempfile::TempDir,
        checkout: Checkout,
        source: Counting,
    }

    /// Reads the sets from disk, counting the reads.
    struct Counting {
        dir: PathBuf,
        manifests: usize,
        fetches: usize,
    }

    impl Source for Counting {
        fn manifests(&mut self, harnesses: &[Harness]) -> Result<BTreeMap<Harness, Manifest>> {
            self.manifests += 1;
            harnesses.iter().map(|&h| Ok((h, AgentSet::load(&self.dir, h)?.manifest()))).collect()
        }

        fn fetch(&mut self, harness: Harness) -> Result<AgentSet> {
            self.fetches += 1;
            AgentSet::load(&self.dir, harness)
        }
    }

    impl Fixture {
        fn new() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let bd = dir.path().join(".bd");
            std::fs::create_dir_all(bd.join(AGENTS_DIR)).unwrap();
            let source = Counting { dir: bd.join(AGENTS_DIR), manifests: 0, fetches: 0 };
            Fixture { checkout: Checkout::new(bd), _dir: dir, source }
        }

        fn serve(&self, rel: &str, text: &str) {
            write(&self.source.dir, rel, text);
        }

        fn unserve(&self, rel: &str) {
            let path = under(&self.source.dir, rel);
            if path.is_dir() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) }.unwrap();
        }

        fn put(&self, rel: &str, text: &str) {
            write(&self.checkout.root, rel, text);
        }

        fn get(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(under(&self.checkout.root, rel)).ok()
        }

        fn run(&mut self, harnesses: &[Harness], apply: bool, force: bool) -> Report {
            let opts = Options { apply, force, lock_wait: Duration::from_secs(5) };
            run(&self.checkout, &mut self.source, harnesses, opts).unwrap()
        }

        fn pull(&mut self, h: Harness) -> HarnessReport {
            self.run(&[h], true, false).harnesses.remove(&h).unwrap()
        }

        fn force(&mut self, h: Harness) -> HarnessReport {
            self.run(&[h], true, true).harnesses.remove(&h).unwrap()
        }

        fn status(&mut self, h: Harness) -> HarnessReport {
            self.run(&[h], false, false).harnesses.remove(&h).unwrap()
        }

        /// The calls made of the source since the last time: (manifests, fetches).
        fn calls(&mut self) -> (usize, usize) {
            let calls = (self.source.manifests, self.source.fetches);
            (self.source.manifests, self.source.fetches) = (0, 0);
            calls
        }

        fn recorded(&self, h: Harness) -> Applied {
            self.checkout.read_lock().unwrap().harnesses.remove(&h).unwrap_or_default()
        }
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = under(root, rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// Approve `pending` as shown.
    fn approve(f: &Fixture, h: Harness, pending: &[Pending]) -> ApprovedEntries {
        let recorded: Vec<Option<String>> = pending.iter().map(|p| p.approved.as_ref().map(mcp_digest)).collect();
        let approvals = pending
            .iter()
            .zip(&recorded)
            .map(|(p, recorded)| Approval {
                name: &p.name,
                server: p.server.as_ref().unwrap(),
                local: p.local.as_deref(),
                recorded: recorded.as_deref(),
            })
            .collect();
        let mut done = apply_approved(&f.checkout, &BTreeMap::from([(h, approvals)]), Duration::from_secs(5)).unwrap();
        done.remove(&h).unwrap()
    }

    fn paths(files: &[SkillFileRef]) -> Vec<&str> {
        files.iter().map(|f| f.path.as_str()).collect()
    }

    fn conflicts(r: &HarnessReport) -> Vec<(&str, &str)> {
        r.skills.conflicts.iter().map(|c| (c.path.as_str(), c.reason.as_str())).collect()
    }

    const H: Harness = Harness::Claude;

    #[test]
    fn pulls_write_what_changed_and_read_only_the_manifest_otherwise() {
        let mut f = Fixture::new();
        f.serve("claude/skills/deploy/SKILL.md", "deploy v1");
        f.serve("claude/skills/deploy/scripts/run.sh", "#!/bin/sh\n");
        f.serve("codex/skills/triage/SKILL.md", "codex triage");

        let r = f.status(H);
        assert_eq!(paths(&r.skills.added), [".claude/skills/deploy/SKILL.md", ".claude/skills/deploy/scripts/run.sh"]);
        assert_eq!(r.skills.changed, BTreeMap::from([("deploy".to_string(), SkillChange::Added)]));
        assert_eq!(f.calls(), (1, 0), "status needs no contents for skills");
        assert!(f.get(".claude/skills/deploy/SKILL.md").is_none(), "status writes nothing");
        assert!(!f.checkout.lock_path().exists() && !f.checkout.bd.join("agents.lock.mutex").exists());

        let r = f.pull(H);
        assert_eq!(r.skills.changed["deploy"], SkillChange::Added);
        assert_eq!(f.calls(), (1, 1));
        assert_eq!(f.get(".claude/skills/deploy/SKILL.md").as_deref(), Some("deploy v1"));
        assert!(!f.checkout.root.join(".agents").exists(), "another harness's set is not touched");
        assert_eq!(r.applied_revision.as_deref(), Some(r.server_revision.as_str()));
        assert_eq!(f.recorded(H).skills.len(), 2);

        let r = f.pull(H);
        assert!(r.skills.changed.is_empty() && r.skills.adopted.is_empty(), "{r:?}");
        assert_eq!(f.calls(), (1, 0), "nothing to do: one manifest read");
        let r = f.status(H);
        assert!(r.skills.changed.is_empty());
        assert_eq!(f.calls(), (1, 0));

        f.serve("claude/skills/deploy/SKILL.md", "deploy v2");
        f.serve("claude/skills/lint/SKILL.md", "lint");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [".claude/skills/deploy/SKILL.md"]);
        assert_eq!(paths(&r.skills.added), [".claude/skills/lint/SKILL.md"]);
        let changed: Vec<_> = r.skills.changed.into_iter().collect();
        assert_eq!(changed, [("deploy".into(), SkillChange::Updated), ("lint".into(), SkillChange::Added)]);
        assert_eq!(f.get(".claude/skills/deploy/SKILL.md").as_deref(), Some("deploy v2"));

        // Both harnesses at once: each its own set.
        let r = f.run(&[Harness::Claude, Harness::Codex], true, false);
        assert_eq!(r.harnesses.keys().copied().collect::<Vec<_>>(), [Harness::Claude, Harness::Codex]);
        assert_eq!(f.get(".agents/skills/triage/SKILL.md").as_deref(), Some("codex triage"));
        assert_eq!(f.checkout.read_lock().unwrap().harnesses.len(), 2);
    }

    #[test]
    fn removed_skills_go_with_the_directories_they_leave_empty() {
        let mut f = Fixture::new();
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/scripts/deep/run.sh", "run");
        f.serve("claude/skills/old/SKILL.md", "old");
        f.serve("claude/skills/kept/SKILL.md", "kept");
        f.pull(H);
        f.put(".claude/skills/kept/notes.md", "mine");

        f.unserve("claude/skills/deploy/scripts");
        f.unserve("claude/skills/old");
        f.unserve("claude/skills/kept");
        let status = f.status(H);
        assert_eq!(paths(&status.skills.removed).len(), 3);
        assert!(f.get(".claude/skills/old/SKILL.md").is_some(), "status removes nothing");
        let r = f.pull(H);
        let changed: Vec<_> = r.skills.changed.into_iter().collect();
        assert_eq!(
            changed,
            [
                ("deploy".into(), SkillChange::Updated),
                ("kept".into(), SkillChange::Removed),
                ("old".into(), SkillChange::Removed)
            ]
        );
        let skills = f.checkout.root.join(".claude/skills");
        assert!(!skills.join("deploy/scripts").exists() && skills.join("deploy/SKILL.md").exists());
        assert!(!skills.join("old").exists(), "an emptied skill directory goes");
        assert_eq!(f.get(".claude/skills/kept/notes.md").as_deref(), Some("mine"));
        assert!(!skills.join("kept/SKILL.md").exists());
        assert_eq!(r.skills.left.len(), 1);
        assert_eq!(r.skills.left[0].path, ".claude/skills/kept");
        assert_eq!(f.recorded(H).skills.keys().collect::<Vec<_>>(), [".claude/skills/deploy/SKILL.md"]);

        // The whole set gone: the skills directory itself stays.
        f.unserve("claude");
        f.pull(H);
        assert!(skills.is_dir() && !skills.join("deploy").exists());
        assert!(f.recorded(H).skills.is_empty());
    }

    #[test]
    fn a_file_and_a_directory_of_the_same_name_trade_places_in_one_pull() {
        let mut f = Fixture::new();
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/reference", "a file");
        f.serve("claude/skills/deploy/notes/a.md", "a");
        f.serve("claude/skills/deploy/notes/deep/b.md", "b");
        f.pull(H);
        f.unserve("claude/skills/deploy/reference");
        f.serve("claude/skills/deploy/reference/index.md", "now a directory");
        f.unserve("claude/skills/deploy/notes");
        f.serve("claude/skills/deploy/notes", "now a file");
        let r = f.status(H);
        assert!(r.skills.conflicts.is_empty(), "{:?}", r.skills.conflicts);
        assert_eq!(paths(&r.skills.added), [".claude/skills/deploy/notes", ".claude/skills/deploy/reference/index.md"]);
        let r = f.pull(H);
        assert!(r.skills.conflicts.is_empty(), "{:?}", r.skills.conflicts);
        assert_eq!(f.get(".claude/skills/deploy/reference/index.md").as_deref(), Some("now a directory"));
        assert_eq!(f.get(".claude/skills/deploy/notes").as_deref(), Some("now a file"));
        assert!(f.pull(H).skills.changed.is_empty());

        // Something else of the user's in that directory: it stays, in the way.
        f.unserve("claude/skills/deploy/reference");
        f.serve("claude/skills/deploy/reference", "a file again");
        f.put(".claude/skills/deploy/reference/mine.md", "mine");
        let r = f.pull(H);
        assert_eq!(
            conflicts(&r),
            [(".claude/skills/deploy/reference", "a directory, which bd never writes over or through; left as it is")]
        );
        assert_eq!(f.get(".claude/skills/deploy/reference/mine.md").as_deref(), Some("mine"));
        assert!(f.get(".claude/skills/deploy/reference/index.md").is_none(), "bd's own file there goes");
    }

    /// Whether the file system holding `dir` ignores case.
    fn ignores_case(dir: &Path) -> bool {
        std::fs::write(dir.join("Case-Probe"), "").unwrap();
        let ignores = dir.join("case-probe").exists();
        std::fs::remove_file(dir.join("Case-Probe")).unwrap();
        ignores
    }

    /// Make the checkout-relative path `alias` reach the file `target`, as
    /// it does where the file system ignores case; elsewhere a hard link
    /// stands in on Unix. `false` where neither can.
    fn alias(f: &Fixture, target: &str, alias: &str) -> bool {
        if ignores_case(&f.checkout.root) {
            return true;
        }
        let alias = under(&f.checkout.root, alias);
        std::fs::create_dir_all(alias.parent().unwrap()).unwrap();
        cfg!(unix) && std::fs::hard_link(under(&f.checkout.root, target), alias).is_ok()
    }

    /// The names in a checkout directory, as they are on disk.
    fn names(f: &Fixture, rel: &str) -> Vec<String> {
        let entries = std::fs::read_dir(under(&f.checkout.root, rel)).unwrap();
        let mut names: Vec<String> = entries.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn names_the_server_changes_only_in_case_are_written_once_the_old_ones_go() {
        let mut f = Fixture::new();
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/Notes.md", "notes");
        f.serve("claude/skills/deploy/Guide.md", "guide v1");
        f.serve("claude/skills/deploy/Docs/a.md", "a");
        f.pull(H);
        // Renamed by case: the same text, other text, and a directory.
        f.unserve("claude/skills/deploy/Notes.md");
        f.serve("claude/skills/deploy/notes.md", "notes");
        f.unserve("claude/skills/deploy/Guide.md");
        f.serve("claude/skills/deploy/guide.md", "guide v2");
        f.unserve("claude/skills/deploy/Docs");
        f.serve("claude/skills/deploy/docs/a.md", "a");
        let dir = ".claude/skills/deploy";
        for name in ["Notes.md", "Guide.md", "Docs/a.md"] {
            if !alias(&f, &format!("{dir}/{name}"), &format!("{dir}/{}", name.to_ascii_lowercase())) {
                return;
            }
        }
        let gone =
            [".claude/skills/deploy/Docs/a.md", ".claude/skills/deploy/Guide.md", ".claude/skills/deploy/Notes.md"];
        let new =
            [".claude/skills/deploy/docs/a.md", ".claude/skills/deploy/guide.md", ".claude/skills/deploy/notes.md"];
        for r in [f.status(H), f.pull(H)] {
            assert!(r.skills.conflicts.is_empty() && r.skills.adopted.is_empty(), "{r:?}");
            assert_eq!((paths(&r.skills.removed), paths(&r.skills.added)), (gone.to_vec(), new.to_vec()));
            assert_eq!(r.skills.changed["deploy"], SkillChange::Updated);
        }
        assert_eq!(names(&f, dir), ["SKILL.md", "docs", "guide.md", "notes.md"], "the server's names");
        assert_eq!(names(&f, &format!("{dir}/docs")), ["a.md"]);
        assert_eq!(f.get(".claude/skills/deploy/guide.md").as_deref(), Some("guide v2"));
        assert_eq!(f.get(".claude/skills/deploy/notes.md").as_deref(), Some("notes"));
        let recorded: Vec<String> = f.recorded(H).skills.into_keys().collect();
        assert_eq!(recorded, [vec![".claude/skills/deploy/SKILL.md"], new.to_vec()].concat());
        let r = f.status(H);
        assert!(r.skills.changed.is_empty() && r.skills.conflicts.is_empty() && r.skills.adopted.is_empty(), "{r:?}");
    }

    #[test]
    fn a_file_of_the_users_named_like_a_removed_one_but_for_case_is_left_alone() {
        let mut f = Fixture::new();
        if ignores_case(&f.checkout.root) {
            return; // Two such files cannot both be here.
        }
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/Notes.md", "notes");
        f.pull(H);
        f.unserve("claude/skills/deploy/Notes.md");
        f.serve("claude/skills/deploy/notes.md", "notes v2");
        f.put(".claude/skills/deploy/notes.md", "the user's own");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.removed), [".claude/skills/deploy/Notes.md"]);
        assert_eq!(conflicts(&r).len(), 1);
        assert_eq!(conflicts(&r)[0].0, ".claude/skills/deploy/notes.md");
        assert!(conflicts(&r)[0].1.contains("not written by bd"));
        assert_eq!(f.get(".claude/skills/deploy/notes.md").as_deref(), Some("the user's own"));
        assert!(f.get(".claude/skills/deploy/Notes.md").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn executable_bits_follow_the_server_and_the_record() {
        use std::os::unix::fs::PermissionsExt;
        let chmod = |root: &Path, rel: &str, mode: u32| {
            std::fs::set_permissions(under(root, rel), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let executable = |f: &Fixture, rel: &str| {
            std::fs::metadata(under(&f.checkout.root, rel)).unwrap().permissions().mode() & 0o111 != 0
        };
        let in_sync = |r: &HarnessReport| r.skills.changed.is_empty() && r.skills.updated.is_empty();
        let mut f = Fixture::new();
        if !super::super::checkout::modes_stick(&f.checkout.root) {
            return; // Every file shows as executable here, whatever its mode is set to.
        }
        let (server, root) = (f.source.dir.clone(), f.checkout.root.clone());
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/run.sh", "#!/bin/sh\n");
        f.serve("claude/skills/deploy/edit.sh", "#!/bin/sh\necho v1\n");
        f.serve("claude/skills/deploy/flip.sh", "#!/bin/sh\necho flip\n");
        chmod(&server, "claude/skills/deploy/run.sh", 0o755);
        chmod(&server, "claude/skills/deploy/edit.sh", 0o755);
        // Here already, as the server has it but without its executable bit (committed from Windows, copied by hand).
        f.put(".claude/skills/deploy/run.sh", "#!/bin/sh\n");
        chmod(&root, ".claude/skills/deploy/run.sh", 0o644);
        let r = f.pull(H);
        assert!(paths(&r.skills.updated).contains(&".claude/skills/deploy/run.sh"), "{r:?}");
        assert!(r.skills.adopted.is_empty(), "{r:?}");
        assert!(executable(&f, ".claude/skills/deploy/run.sh") && executable(&f, ".claude/skills/deploy/edit.sh"));
        assert!(!executable(&f, ".claude/skills/deploy/flip.sh"));
        assert!(f.recorded(H).skills[".claude/skills/deploy/run.sh"].executable);
        assert!(in_sync(&f.status(H)));

        // Edited here into what the server has next, by a tool that dropped the bit.
        f.serve("claude/skills/deploy/edit.sh", "#!/bin/sh\necho v2\n");
        std::fs::remove_file(root.join(".claude/skills/deploy/edit.sh")).unwrap();
        f.put(".claude/skills/deploy/edit.sh", "#!/bin/sh\necho v2\n");
        assert!(!executable(&f, ".claude/skills/deploy/edit.sh"));
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [".claude/skills/deploy/edit.sh"]);
        assert!(executable(&f, ".claude/skills/deploy/edit.sh"));
        assert!(in_sync(&f.status(H)));

        // The server changes only the bit, either way: applied without writing the text.
        chmod(&server, "claude/skills/deploy/flip.sh", 0o755);
        chmod(&server, "claude/skills/deploy/run.sh", 0o644);
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [".claude/skills/deploy/flip.sh", ".claude/skills/deploy/run.sh"]);
        assert_eq!(r.skills.changed["deploy"], SkillChange::Updated);
        assert!(executable(&f, ".claude/skills/deploy/flip.sh") && !executable(&f, ".claude/skills/deploy/run.sh"));
        let recorded = f.recorded(H).skills;
        assert!(recorded[".claude/skills/deploy/flip.sh"].executable);
        assert!(!recorded[".claude/skills/deploy/run.sh"].executable);
        assert!(in_sync(&f.status(H)));

        // A bit taken away here comes back; one added to a file the server does not run is left alone.
        chmod(&root, ".claude/skills/deploy/flip.sh", 0o644);
        chmod(&root, ".claude/skills/deploy/SKILL.md", 0o755);
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [".claude/skills/deploy/flip.sh"]);
        assert!(executable(&f, ".claude/skills/deploy/flip.sh") && executable(&f, ".claude/skills/deploy/SKILL.md"));
        assert!(in_sync(&f.status(H)));
        assert!(in_sync(&f.pull(H)));
    }

    #[cfg(unix)]
    #[test]
    fn a_change_of_the_executable_bit_alone_keeps_local_edits() {
        use bd_core::agents::sha256_hex;
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        if !super::super::checkout::modes_stick(&f.checkout.root) {
            return; // Every file shows as executable here, whatever its mode is set to.
        }
        let chmod = |root: &Path, rel: &str, mode: u32| {
            std::fs::set_permissions(under(root, rel), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let executable = |f: &Fixture, rel: &str| {
            std::fs::metadata(under(&f.checkout.root, rel)).unwrap().permissions().mode() & 0o111 != 0
        };
        let server = f.source.dir.clone();
        let (up, down) = (".claude/skills/deploy/up.sh", ".claude/skills/deploy/down.sh");
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/up.sh", "echo up\n");
        f.serve("claude/skills/deploy/down.sh", "echo down\n");
        chmod(&server, "claude/skills/deploy/down.sh", 0o755);
        f.pull(H);
        f.put(up, "echo up, edited here\n");
        f.put(down, "echo down, edited here\n");
        // The server changes only the executable bits: up.sh gets one, down.sh loses its own.
        chmod(&server, "claude/skills/deploy/up.sh", 0o755);
        chmod(&server, "claude/skills/deploy/down.sh", 0o644);
        for r in [f.status(H), f.pull(H)] {
            assert!(r.skills.conflicts.is_empty(), "{:?}", r.skills.conflicts);
            assert_eq!(paths(&r.skills.edited), [down, up], "the edits are kept");
            assert_eq!(paths(&r.skills.updated), [down, up], "and the bits applied to them");
            assert_eq!(r.skills.changed["deploy"], SkillChange::Updated);
        }
        assert_eq!(f.get(up).as_deref(), Some("echo up, edited here\n"));
        assert_eq!(f.get(down).as_deref(), Some("echo down, edited here\n"));
        assert!(executable(&f, up) && !executable(&f, down));
        let recorded = f.recorded(H).skills;
        assert_eq!((recorded[up].sha256.as_str(), recorded[up].executable), (sha256_hex(b"echo up\n").as_str(), true));
        assert_eq!(
            (recorded[down].sha256.as_str(), recorded[down].executable),
            (sha256_hex(b"echo down\n").as_str(), false),
            "bd's text, with the server's bit"
        );
        // From then on: edits kept, nothing else.
        for r in [f.status(H), f.pull(H)] {
            assert_eq!(paths(&r.skills.edited), [down, up]);
            assert!(r.skills.conflicts.is_empty() && r.skills.updated.is_empty() && r.skills.changed.is_empty());
            assert!(r.mcp.pending.is_empty());
        }
        // A change of the text on the server still conflicts with the edit.
        f.serve("claude/skills/deploy/up.sh", "echo up, v2\n");
        let r = f.pull(H);
        assert_eq!(conflicts(&r).len(), 1);
        assert_eq!(conflicts(&r)[0].0, up);
        assert!(conflicts(&r)[0].1.starts_with("edited here and changed on the server"));
        assert_eq!(f.get(up).as_deref(), Some("echo up, edited here\n"));
    }

    #[cfg(unix)]
    #[test]
    fn executable_bits_the_file_system_does_not_keep_are_reported_once() {
        use super::super::checkout::CHMOD_IGNORED;
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        if !super::super::checkout::modes_stick(&f.checkout.root) {
            return; // Every file shows as executable here, whatever its mode is set to.
        }
        let chmod = |root: &Path, rel: &str, mode: u32| {
            std::fs::set_permissions(under(root, rel), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let executable = |f: &Fixture, rel: &str| {
            std::fs::metadata(under(&f.checkout.root, rel)).unwrap().permissions().mode() & 0o111 != 0
        };
        let not_kept = |f: &Fixture, rel: &str| f.recorded(H).skills[rel].executable_not_kept;
        let quiet = |r: &HarnessReport| {
            r.skills.changed.is_empty() && r.skills.updated.is_empty() && r.skills.not_executable.is_empty()
        };
        let (server, root) = (f.source.dir.clone(), f.checkout.root.clone());
        let (run, adopted) = (".claude/skills/deploy/run.sh", ".claude/skills/deploy/adopted.sh");
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/skills/deploy/run.sh", "#!/bin/sh\necho run\n");
        f.serve("claude/skills/deploy/adopted.sh", "#!/bin/sh\necho adopted\n");
        chmod(&server, "claude/skills/deploy/run.sh", 0o755);
        chmod(&server, "claude/skills/deploy/adopted.sh", 0o755);
        f.put(adopted, "#!/bin/sh\necho adopted\n");
        chmod(&root, adopted, 0o644);

        // A file system where chmod succeeds and changes nothing: said once, recorded.
        CHMOD_IGNORED.set(true);
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [adopted]);
        assert_eq!(paths(&r.skills.not_executable), [adopted, run]);
        assert!(!executable(&f, run) && !executable(&f, adopted));
        assert!(not_kept(&f, run) && not_kept(&f, adopted) && !not_kept(&f, ".claude/skills/deploy/SKILL.md"));
        f.calls();
        let (status, pulled) = (f.status(H), f.pull(H));
        assert!(quiet(&status) && quiet(&pulled), "{status:?} {pulled:?}");
        assert_eq!(f.calls(), (2, 0), "nothing to fetch");

        // A change of the set tries again, and says nothing of a bit still not kept.
        f.serve("claude/skills/deploy/a.md", "a");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.added), [".claude/skills/deploy/a.md"]);
        assert!(r.skills.updated.is_empty() && r.skills.not_executable.is_empty(), "{r:?}");
        assert!(not_kept(&f, run) && not_kept(&f, adopted));
        // --force tries again, and says so.
        let r = f.force(H);
        assert_eq!(paths(&r.skills.updated), [adopted, run]);
        assert_eq!(paths(&r.skills.not_executable), [adopted, run]);
        assert!(quiet(&f.pull(H)));

        // A bit set by hand is recorded as kept, without a word.
        CHMOD_IGNORED.set(false);
        chmod(&root, run, 0o755);
        assert!(quiet(&f.status(H)) && quiet(&f.pull(H)));
        assert!(!not_kept(&f, run) && not_kept(&f, adopted));
        // Where the file system keeps bits again, the next change of the set gives them.
        assert!(quiet(&f.pull(H)) && !executable(&f, adopted));
        f.serve("claude/skills/deploy/b.md", "b");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [adopted]);
        assert_eq!(r.skills.changed["deploy"], SkillChange::Updated);
        assert!(r.skills.not_executable.is_empty());
        assert!(executable(&f, adopted) && !not_kept(&f, adopted));
        assert!(quiet(&f.status(H)) && quiet(&f.pull(H)));

        // A new text is written and checked again.
        CHMOD_IGNORED.set(true);
        f.serve("claude/skills/deploy/run.sh", "#!/bin/sh\necho run v2\n");
        chmod(&server, "claude/skills/deploy/run.sh", 0o755);
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.updated), [run]);
        assert_eq!(paths(&r.skills.not_executable), [run]);
        assert!(not_kept(&f, run) && !executable(&f, run));
        assert!(quiet(&f.status(H)) && quiet(&f.pull(H)));
        CHMOD_IGNORED.set(false);
    }

    #[test]
    fn local_edits_and_files_bd_did_not_write_survive() {
        let mut f = Fixture::new();
        for name in ["edited", "conflict", "deleted", "theirs", "same", "gone"] {
            f.serve(&format!("claude/skills/{name}/SKILL.md"), name);
        }
        f.put(".claude/skills/theirs/SKILL.md", "written by hand");
        f.put(".claude/skills/same/SKILL.md", "same");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.adopted), [".claude/skills/same/SKILL.md"]);
        assert_eq!(conflicts(&r).len(), 1);
        assert!(conflicts(&r)[0].1.contains("not written by bd"), "{:?}", conflicts(&r));
        assert_eq!(f.get(".claude/skills/theirs/SKILL.md").as_deref(), Some("written by hand"));
        assert!(f.recorded(H).skills.contains_key(".claude/skills/same/SKILL.md"), "adopted: bd's now");
        assert!(!f.recorded(H).skills.contains_key(".claude/skills/theirs/SKILL.md"));

        f.put(".claude/skills/edited/SKILL.md", "edited here");
        f.put(".claude/skills/conflict/SKILL.md", "edited here");
        f.put(".claude/skills/gone/SKILL.md", "edited here");
        std::fs::remove_file(f.checkout.root.join(".claude/skills/deleted/SKILL.md")).unwrap();
        f.serve("claude/skills/conflict/SKILL.md", "conflict v2");
        f.serve("claude/skills/theirs/SKILL.md", "theirs v2");
        f.unserve("claude/skills/gone");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.edited), [".claude/skills/edited/SKILL.md"]);
        assert_eq!(paths(&r.skills.restored), [".claude/skills/deleted/SKILL.md"]);
        assert_eq!(r.skills.changed["deleted"], SkillChange::Restored);
        let found = conflicts(&r);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found[0].0.ends_with("conflict/SKILL.md") && found[0].1.contains("changed on the server"));
        assert!(found[1].0.ends_with("gone/SKILL.md") && found[1].1.contains("removed from the server"));
        assert!(found[2].0.ends_with("theirs/SKILL.md"));
        for name in ["edited", "conflict", "gone"] {
            assert_eq!(f.get(&format!(".claude/skills/{name}/SKILL.md")).as_deref(), Some("edited here"));
        }
        assert_eq!(f.get(".claude/skills/deleted/SKILL.md").as_deref(), Some("deleted"));

        // --force: bd's own files only.
        let r = f.force(H);
        assert_eq!(paths(&r.skills.replaced), [".claude/skills/conflict/SKILL.md", ".claude/skills/edited/SKILL.md"]);
        assert_eq!(paths(&r.skills.removed), [".claude/skills/gone/SKILL.md"]);
        assert_eq!(conflicts(&r).len(), 1, "what bd did not write stays a conflict");
        assert_eq!(f.get(".claude/skills/conflict/SKILL.md").as_deref(), Some("conflict v2"));
        assert_eq!(f.get(".claude/skills/edited/SKILL.md").as_deref(), Some("edited"));
        assert!(f.get(".claude/skills/gone/SKILL.md").is_none());
        assert_eq!(f.get(".claude/skills/theirs/SKILL.md").as_deref(), Some("written by hand"));

        // An edit that matches the server's newer version is adopted.
        f.serve("claude/skills/edited/SKILL.md", "edited v2");
        f.put(".claude/skills/edited/SKILL.md", "edited v2");
        let r = f.pull(H);
        assert_eq!(paths(&r.skills.adopted), [".claude/skills/edited/SKILL.md"]);
        assert!(r.skills.changed.is_empty());
    }

    #[test]
    fn mcp_changes_wait_for_approval_and_removals_apply() {
        let mut f = Fixture::new();
        let github = r#"{"command": "npx", "args": ["-y", "server-github"], "env": {"TOKEN": "${GH_TOKEN_UNSET_1}"}}"#;
        f.serve(
            "claude/mcp.json",
            &format!(r#"{{"mcpServers": {{"github": {github}, "linear": {{"url": "https://l"}}}}}}"#),
        );
        f.put(
            ".mcp.json",
            &format!(r#"{{"keep": 1, "mcpServers": {{"github": {github}, "mine": {{"command": "m"}}}}}}"#),
        );
        let before = f.get(".mcp.json");

        let r = f.pull(H);
        assert_eq!(r.mcp.adopted, ["github"]);
        assert_eq!(r.mcp.pending.len(), 1);
        assert_eq!((r.mcp.pending[0].name.as_str(), r.mcp.pending[0].change), ("linear", PendingChange::New));
        assert!(r.mcp.pending[0].server.is_some(), "the server's entry, for approval");
        assert_eq!(f.get(".mcp.json"), before, "nothing new is written");
        assert_eq!(r.unset_env, ["GH_TOKEN_UNSET_1"]);

        // A change waits too, naming the fields that change.
        f.calls();
        f.serve(
            "claude/mcp.json",
            r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github@2"], "env": {}}}}"#,
        );
        let r = f.status(H);
        assert_eq!(f.calls().1, 1, "the definitions are fetched to show the change");
        assert_eq!(r.mcp.pending.len(), 1);
        let p = &r.mcp.pending[0];
        assert_eq!(
            (p.name.as_str(), p.change, p.fields.clone(), p.edited),
            ("github", PendingChange::Changed, vec!["args".to_string(), "env".to_string()], false)
        );
        assert!(p.approved.as_ref().is_some_and(|d| d["args"][1] == "server-github"));
        assert_eq!(r.unset_env, ["GH_TOKEN_UNSET_1"], "the definition in effect still reads it");
        let r = f.force(H);
        assert_eq!(r.mcp.pending.len(), 1, "--force does not approve");
        assert_eq!(f.get(".mcp.json"), before);

        // Approval writes it and records it.
        assert_eq!(approve(&f, H, &r.mcp.pending).written, ["github"]);
        let r = f.pull(H);
        assert!(r.mcp.pending.is_empty() && r.mcp.conflicts.is_empty(), "{r:?}");
        let written: Value = serde_json::from_str(&f.get(".mcp.json").unwrap()).unwrap();
        assert_eq!(written["mcpServers"]["github"]["args"][1], "server-github@2");
        assert_eq!(written["keep"], 1);

        // Deleted here, unchanged on the server: written back. Edited here: kept, or replaced with --force.
        let mut doc = written.clone();
        doc["mcpServers"].as_object_mut().unwrap().remove("github");
        f.put(".mcp.json", &doc.to_string());
        let r = f.pull(H);
        assert_eq!(r.mcp.restored, ["github"]);
        doc["mcpServers"]["github"] = serde_json::json!({"command": "npx", "args": ["--local"]});
        f.put(".mcp.json", &doc.to_string());
        assert_eq!(f.pull(H).mcp.edited, ["github"]);
        assert_eq!(f.force(H).mcp.replaced, ["github"]);
        let written: Value = serde_json::from_str(&f.get(".mcp.json").unwrap()).unwrap();
        assert_eq!(written["mcpServers"]["github"]["args"][1], "server-github@2");

        // Edited here and changed on the server: waiting, flagged as edited.
        f.put(".mcp.json", &doc.to_string());
        f.serve("claude/mcp.json", r#"{"mcpServers": {"github": {"command": "uvx"}}}"#);
        let r = f.pull(H);
        assert!(r.mcp.pending[0].edited && r.mcp.pending[0].fields.contains(&"command".to_string()));

        // Removed on the server: an edited entry stays (until --force); an unedited one goes.
        f.serve("claude/mcp.json", r#"{"mcpServers": {}}"#);
        let r = f.pull(H);
        assert_eq!(r.mcp.conflicts.len(), 1);
        assert!(r.mcp.conflicts[0].reason.contains("removed from the server"));
        assert_eq!(f.force(H).mcp.removed, ["github"]);
        let written: Value = serde_json::from_str(&f.get(".mcp.json").unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({"keep": 1, "mcpServers": {"mine": {"command": "m"}}}));
        assert!(f.recorded(H).mcp_servers.is_empty());
    }

    #[test]
    fn approval_writes_only_entries_still_as_shown() {
        let mut f = Fixture::new();
        f.serve(
            "claude/mcp.json",
            r#"{"mcpServers": {"a": {"command": "a"}, "b": {"command": "b"}, "c": {"command": "c"}}}"#,
        );
        f.put(".mcp.json", r#"{"keep": true, "mcpServers": {}}"#);
        let shown = f.status(H).mcp.pending;
        assert_eq!(shown.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        assert!(shown.iter().all(|p| p.local.is_none() && p.change == PendingChange::New));

        // Meanwhile, b is written here by hand, and another approve writes c.
        f.put(".mcp.json", r#"{"keep": true, "mcpServers": {"b": {"command": "mine"}}}"#);
        let c: Vec<Pending> = f.status(H).mcp.pending.into_iter().filter(|p| p.name == "c").collect();
        assert_eq!(approve(&f, H, &c).written, ["c"]);
        let done = approve(&f, H, &shown);
        assert_eq!(done.written, ["a"]);
        let skipped: Vec<&str> = done.skipped.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(skipped, ["b", "c"]);
        assert!(done.skipped[0].1.contains("changed since it was shown"), "{:?}", done.skipped);
        let written: Value = serde_json::from_str(&f.get(".mcp.json").unwrap()).unwrap();
        assert_eq!(
            written,
            serde_json::json!({"keep": true, "mcpServers": {"a": {"command": "a"}, "b": {"command": "mine"}, "c": {"command": "c"}}})
        );
        assert_eq!(f.recorded(H).mcp_servers.keys().collect::<Vec<_>>(), ["a", "c"]);
        let r = f.status(H);
        assert!(r.mcp.pending.is_empty(), "{:?}", r.mcp.pending);
        assert_eq!(r.mcp.conflicts.len(), 1);
        assert!(r.mcp.conflicts[0].foreign && r.mcp.conflicts[0].name.as_deref() == Some("b"));

        // A changed definition replaces bd's entry, once; the server changing it again makes it pending again.
        f.serve("claude/mcp.json", r#"{"mcpServers": {"a": {"command": "a2"}, "c": {"command": "c"}}}"#);
        let shown = f.status(H).mcp.pending;
        assert_eq!((shown[0].name.as_str(), shown[0].change), ("a", PendingChange::Changed));
        f.serve("claude/mcp.json", r#"{"mcpServers": {"a": {"command": "a3"}, "c": {"command": "c"}}}"#);
        assert_eq!(approve(&f, H, &shown).written, ["a"], "what was shown is written");
        let written: Value = serde_json::from_str(&f.get(".mcp.json").unwrap()).unwrap();
        assert_eq!(written["mcpServers"]["a"], serde_json::json!({"command": "a2"}));
        let r = f.status(H);
        assert_eq!(r.mcp.pending.len(), 1);
        assert_eq!(r.mcp.pending[0].fields, ["command"]);
        assert_eq!(r.mcp.pending[0].approved, Some(serde_json::json!({"command": "a2"})));
    }

    #[cfg(unix)]
    #[test]
    fn approval_never_writes_through_a_symlink() {
        let mut f = Fixture::new();
        f.serve("claude/mcp.json", r#"{"mcpServers": {"a": {"command": "a"}}}"#);
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("mcp.json"), r#"{"mcpServers": {}}"#).unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("mcp.json"), f.checkout.root.join(".mcp.json")).unwrap();
        let shown = f.status(H).mcp.pending;
        let done = approve(&f, H, &shown);
        assert!(done.written.is_empty());
        assert!(done.skipped[0].1.contains("symlink"), "{:?}", done.skipped);
        let target = std::fs::read_to_string(elsewhere.path().join("mcp.json")).unwrap();
        assert_eq!(target, r#"{"mcpServers": {}}"#);
        assert!(f.recorded(H).mcp_servers.is_empty());
    }

    #[test]
    fn mcp_files_bd_cannot_use_are_conflicts() {
        let mut f = Fixture::new();
        f.serve("copilot/mcp.json", r#"{"mcpServers": {"github": {"command": "npx"}}}"#);
        f.put(".github/mcp.json", r#"{"github": {"command": "npx"}}"#);
        let r = f.pull(Harness::Copilot);
        assert_eq!(r.mcp.conflicts.len(), 1);
        assert_eq!(r.mcp.conflicts[0].name, None);
        assert!(r.mcp.conflicts[0].reason.contains("top level"), "{:?}", r.mcp.conflicts);
        assert!(r.mcp.pending.is_empty());
        assert_eq!(f.get(".github/mcp.json").as_deref(), Some(r#"{"github": {"command": "npx"}}"#));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_conflicts() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        f.serve("claude/skills/deploy/SKILL.md", "deploy");
        f.serve("claude/mcp.json", r#"{"mcpServers": {"github": {"command": "npx"}}}"#);
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("SKILL.md"), "theirs").unwrap();
        std::fs::create_dir_all(f.checkout.root.join(".claude/skills")).unwrap();
        symlink(elsewhere.path(), f.checkout.root.join(".claude/skills/deploy")).unwrap();
        std::fs::write(elsewhere.path().join("mcp.json"), r#"{"mcpServers": {"github": {"command": "npx"}}}"#).unwrap();
        symlink(elsewhere.path().join("mcp.json"), f.checkout.root.join(".mcp.json")).unwrap();
        let r = f.pull(H);
        assert_eq!(
            conflicts(&r),
            [(".claude/skills/deploy", "a symlink, which bd never writes over or through; left as it is")]
        );
        assert_eq!(std::fs::read_to_string(elsewhere.path().join("SKILL.md")).unwrap(), "theirs");
        assert_eq!(r.mcp.adopted, ["github"], "a symlinked MCP file is read");

        // Its entry removed on the server: the file is not written through the link.
        f.serve("claude/mcp.json", r#"{"mcpServers": {}}"#);
        let r = f.pull(H);
        assert!(r.mcp.removed.is_empty());
        assert!(r.mcp.conflicts[0].reason.contains("symlink"), "{:?}", r.mcp.conflicts);
        assert!(std::fs::symlink_metadata(f.checkout.root.join(".mcp.json")).unwrap().file_type().is_symlink());
    }
}
