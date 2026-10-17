//! A remote workspace's playbooks on a client: approved on this machine
//! before use, as skills and MCP definitions are.
//!
//! The server serves its playbook files with `bd agents manifest
//! --playbooks` and `bd agents fetch --playbooks`
//! ([`bd_core::agents::PlaybookSet`]). `bd agents approve` shows each new
//! or changed one (a new file whole, a changed one as a diff against the
//! version approved here) and keeps those approved, byte for byte, in the
//! checkout's `.bd/approved/playbooks` (by their path on the server), with
//! their SHA-256 in `.bd/agents.lock` ([`super::lock`]). Playbook commands
//! look a name up there after the checkout's own `.bd/playbooks`, and send
//! what they load to the server as a bundle, checked against the lock first
//! ([`verify_bundle`]), so the server compiles exactly the bytes approved
//! here, never its own copy. Until a change is approved, the version
//! approved before stays in use; a playbook never approved is unavailable.
//!
//! `status`, `pull`, `bd agents watch` and the session-start hook only
//! report new and changed playbooks. What adds nothing unapproved applies
//! ([`run`] with `apply`): a playbook the server no longer serves is removed
//! here (with the record), an approved one deleted or changed here is
//! written again when the server still serves the very bytes approved, and
//! otherwise discarded (its record dropped: it waits for approval again),
//! and anything else in the directory (a file bd did not write there) is
//! removed. Changes are made under the checkout's mutex, never through a
//! symlink ([`Checkout::write_approved_playbook`]).
//!
//! Playbooks are harness-independent: every `status`, `pull`, `approve` and
//! `watch` in a remote workspace includes them, whatever `--harness` names.
//! A local workspace has none of this: its `.bd/playbooks` are the user's
//! own files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use bd_core::agents::{PlaybookSet, PlaybooksManifest, sha256_hex};
use bd_core::playbook::{Bundle, is_path_like, name_of};
use bd_core::{Error, Result};
use serde::{Deserialize, Serialize};

use super::checkout::{APPROVED_PLAYBOOKS, Checkout};
use super::lock::{ApprovedPlaybook, LockFile};

/// Where the server's playbooks come from (its answers checked before they
/// are returned: [`PlaybooksManifest::check`], [`PlaybookSet::check`]).
pub trait Source {
    /// The manifest; `None` if the server does not serve its playbooks for
    /// approval (a bd that predates it).
    fn playbooks_manifest(&mut self) -> Result<Option<PlaybooksManifest>>;
    /// The playbooks, whole.
    fn playbooks(&mut self) -> Result<PlaybookSet>;
}

/// What [`run`] found, and did or would do. JSON, in `status` and `pull`:
///
/// ```json
/// "playbooks": {
///   "dir": ".bd/approved/playbooks",
///   "server_revision": "<sha256>",
///   "pending": [{"path": "change.toml", "change": "changed"}, {"path": "triage.toml", "change": "new"}],
///   "removed": ["old.toml"], "restored": [], "discarded": []
/// }
/// ```
#[derive(Clone, Debug, Default, Serialize)]
pub struct PlaybooksReport {
    /// The approved playbooks' directory, checkout-relative.
    pub dir: String,
    pub server_revision: String,
    /// New and changed playbooks waiting for `bd agents approve`.
    pub pending: Vec<PendingPlaybook>,
    /// Approved playbooks the server no longer serves: removed here.
    pub removed: Vec<String>,
    /// Approved playbooks deleted or changed here, written again with the bytes approved.
    pub restored: Vec<String>,
    /// Approved playbooks changed or deleted here that the server no longer
    /// serves as approved (dropped: they wait for approval again), and files
    /// bd did not write there: removed.
    pub discarded: Vec<String>,
    /// Why the server's playbooks could not be checked (a playbook directory
    /// the server cannot read, say): nothing about them changed here, and
    /// the skills and MCP definitions were worked on all the same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PlaybooksReport {
    /// The report of playbooks that could not be checked, for `e`.
    pub fn failed(e: &Error) -> PlaybooksReport {
        PlaybooksReport { dir: format!(".bd/{APPROVED_PLAYBOOKS}"), error: Some(e.to_string()), ..Default::default() }
    }
}

/// A playbook file waiting for approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPlaybook {
    /// Its path in the server's playbook directory.
    pub path: String,
    pub change: PlaybookChange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaybookChange {
    /// None of it is approved here.
    New,
    /// Another version is approved here, and stays in use until this one is.
    Changed,
}

impl PlaybookChange {
    pub fn as_str(self) -> &'static str {
        match self {
            PlaybookChange::New => "new",
            PlaybookChange::Changed => "changed",
        }
    }
}

/// What [`run`] returns: the report, and with `review` the server's
/// playbooks when some wait for approval.
pub struct Outcome {
    pub report: PlaybooksReport,
    pub set: Option<PlaybookSet>,
}

enum Op {
    /// Write the server's file, which has the bytes approved.
    Restore(String),
    /// Delete the file and drop its record.
    Drop(String),
    /// Delete what is there, which bd did not record.
    Stray(String),
}

/// What a pull would do, from the server's `manifest`, the approvals in
/// `lock` and what the approved directory holds.
fn plan(checkout: &Checkout, manifest: &PlaybooksManifest, lock: &LockFile) -> Result<(Vec<Op>, PlaybooksReport)> {
    let mut ops = Vec::new();
    let mut report = PlaybooksReport {
        dir: format!(".bd/{APPROVED_PLAYBOOKS}"),
        server_revision: manifest.revision.clone(),
        ..Default::default()
    };
    for (path, approved) in &lock.playbooks {
        let intact = checkout.read_approved_playbook(path)?.is_some_and(|b| sha256_hex(&b) == approved.sha256);
        match manifest.files.get(path) {
            None => {
                ops.push(Op::Drop(path.clone()));
                report.removed.push(path.clone());
            }
            Some(d) if d.sha256 == approved.sha256 => {
                if !intact {
                    ops.push(Op::Restore(path.clone()));
                    report.restored.push(path.clone());
                }
            }
            Some(_) if intact => {
                report.pending.push(PendingPlaybook { path: path.clone(), change: PlaybookChange::Changed });
            }
            Some(_) => {
                ops.push(Op::Drop(path.clone()));
                report.discarded.push(path.clone());
                report.pending.push(PendingPlaybook { path: path.clone(), change: PlaybookChange::New });
            }
        }
    }
    for path in manifest.files.keys().filter(|p| !lock.playbooks.contains_key(*p)) {
        report.pending.push(PendingPlaybook { path: path.clone(), change: PlaybookChange::New });
    }
    report.pending.sort_by(|a, b| a.path.cmp(&b.path));
    for entry in checkout.approved_playbook_entries()? {
        if !lock.playbooks.contains_key(&entry) {
            ops.push(Op::Stray(entry.clone()));
            report.discarded.push(entry);
        }
    }
    report.discarded.sort();
    Ok((ops, report))
}

/// Compare the approved playbooks here with the server's (`source`) and,
/// with `apply`, make the changes that need no approval (see the [module
/// docs](self)). With `review`, the server's playbooks are fetched whole
/// when some wait for approval. `None`: the server does not serve them.
pub fn run(
    checkout: &Checkout,
    source: &mut dyn Source,
    apply: bool,
    review: bool,
    wait: Duration,
) -> Result<Option<Outcome>> {
    let manifest = source.playbooks_manifest()?;
    run_with(checkout, source, manifest, apply, review, wait)
}

/// [`run`], with the server's refusal to serve its playbooks apart, as
/// `Ok(Err(refusal))`: its manifest answered with a refusal (exit 2: it
/// cannot load them), before anything here was read or changed. Anything
/// else (the checkout busy, the server unreachable, an answer lost or
/// unusable, a failure while applying) is an error, with its exit code.
pub fn run_or_refusal(
    checkout: &Checkout,
    source: &mut dyn Source,
    apply: bool,
    review: bool,
    wait: Duration,
) -> Result<std::result::Result<Option<Outcome>, Error>> {
    let manifest = match source.playbooks_manifest() {
        Ok(m) => m,
        Err(e) if e.exit_code() == 2 => return Ok(Err(e)),
        Err(e) => return Err(e),
    };
    run_with(checkout, source, manifest, apply, review, wait).map(Ok)
}

fn run_with(
    checkout: &Checkout,
    source: &mut dyn Source,
    manifest: Option<PlaybooksManifest>,
    apply: bool,
    review: bool,
    wait: Duration,
) -> Result<Option<Outcome>> {
    let Some(manifest) = manifest else { return Ok(None) };
    let (ops, report) = {
        let _reading = if apply { None } else { checkout.shared(wait)? };
        plan(checkout, &manifest, &checkout.read_lock()?)?
    };
    let set = if review && !report.pending.is_empty() { Some(source.playbooks()?) } else { None };
    if !apply || ops.is_empty() {
        return Ok(Some(Outcome { report, set }));
    }
    let _mutex = checkout.exclusive(wait)?;
    let mut lock = checkout.read_lock()?;
    let before = lock.clone();
    let (ops, mut report) = plan(checkout, &manifest, &lock)?;
    let mut fetched = set;
    let done = apply_ops(checkout, source, ops, &mut lock, &mut fetched, &mut report);
    let recorded = if lock != before { checkout.write_lock(&lock) } else { Ok(()) };
    done?;
    recorded?;
    Ok(Some(Outcome { report, set: fetched }))
}

fn apply_ops(
    checkout: &Checkout,
    source: &mut dyn Source,
    ops: Vec<Op>,
    lock: &mut LockFile,
    set: &mut Option<PlaybookSet>,
    report: &mut PlaybooksReport,
) -> Result<()> {
    for op in ops {
        match op {
            Op::Drop(path) => {
                checkout.remove_approved_playbook(&path)?;
                lock.playbooks.remove(&path);
            }
            Op::Stray(path) => {
                checkout.remove_approved_playbook(&path)?;
            }
            Op::Restore(path) => {
                if set.is_none() {
                    *set = Some(source.playbooks()?);
                }
                let approved = lock.playbooks.get(&path).map(|a| a.sha256.clone());
                // Only the very bytes approved; the server may have changed since its manifest.
                match set.as_ref().and_then(|s| s.files.get(&path)) {
                    Some(f) if Some(&f.sha256) == approved.as_ref() => {
                        checkout.write_approved_playbook(&path, &f.text)?
                    }
                    _ => report.restored.retain(|p| *p != path),
                }
            }
        }
    }
    Ok(())
}

/// A playbook not written, and why.
pub type Skipped = (String, String);

/// A playbook the user approved, as it was shown.
pub struct Approval<'a> {
    pub path: &'a str,
    /// The server's text shown, which is written.
    pub text: &'a str,
    /// What `.bd/agents.lock` recorded for it when it was shown.
    pub recorded: Option<&'a str>,
}

/// Write the playbooks approved, as they were shown, under the checkout's
/// mutex, recording each in the lock; one whose record changed since it was
/// shown is skipped. Returns the paths written and those skipped, with why.
pub fn apply_approved(
    checkout: &Checkout,
    approvals: &[Approval<'_>],
    wait: Duration,
) -> Result<(Vec<String>, Vec<Skipped>)> {
    let _mutex = checkout.exclusive(wait)?;
    let mut lock = checkout.read_lock()?;
    let before = lock.clone();
    let (mut written, mut skipped) = (Vec::new(), Vec::new());
    let mut result = Ok(());
    for a in approvals {
        let now = lock.playbooks.get(a.path).map(|p| p.sha256.as_str());
        if now != a.recorded {
            skipped.push((
                a.path.to_string(),
                "its approval in .bd/agents.lock changed since it was shown; run `bd agents approve` again".into(),
            ));
            continue;
        }
        if let Err(e) = checkout.write_approved_playbook(a.path, a.text) {
            result = Err(e);
            break;
        }
        lock.playbooks.insert(a.path.to_string(), ApprovedPlaybook { sha256: sha256_hex(a.text.as_bytes()) });
        written.push(a.path.to_string());
    }
    // What was written is recorded, even when something failed.
    let recorded = if lock != before { checkout.write_lock(&lock) } else { Ok(()) };
    result?;
    recorded?;
    Ok((written, skipped))
}

/// Whether `name` (given to `bd agents approve`) names the playbook file
/// `path`: its path, or its playbook name (`change` for `change.toml`).
pub fn names(name: &str, path: &str) -> bool {
    name == path || (!path.contains('/') && name_of(Path::new(path)).is_some_and(|n| n == name))
}

/// `path` with `.` and `..` resolved by its text alone.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// The path within `approved` (the approved playbooks directory) of the
/// bundle path `key`, if it is in there.
fn approved_rel(approved: &Path, key: &str) -> Option<String> {
    let rel = lexical(Path::new(key)).strip_prefix(lexical(approved)).ok()?.to_path_buf();
    let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Check a bundle about to be sent before it goes: every file in it from
/// the approved playbooks directory (`checkout`'s) must hold the very bytes
/// `.bd/agents.lock` records as approved, and a reference by path in one
/// of them must stay inside that directory (by name, references resolve on
/// the whole lookup path, as for any playbook found here).
pub fn verify_bundle(checkout: &Checkout, bundle: &Bundle) -> Result<()> {
    let approved = checkout.approved_playbooks();
    let lock = checkout.read_lock()?;
    for (from, refs) in &bundle.refs {
        let Some(holder) = approved_rel(&approved, from) else { continue };
        for (reference, target) in refs {
            if is_path_like(reference.trim()) && approved_rel(&approved, target).is_none() {
                return Err(Error::Refused(format!(
                    "approved playbook {holder} names {reference:?}, outside the approved playbooks \
                     ({}): not sent",
                    approved.display()
                )));
            }
        }
    }
    let mut checked = BTreeSet::new();
    for (key, file) in &bundle.files {
        let Some(rel) = approved_rel(&approved, key) else { continue };
        match lock.playbooks.get(&rel) {
            Some(a) if a.sha256 == sha256_hex(file.text.as_bytes()) => {
                checked.insert(rel);
            }
            Some(_) => {
                return Err(Error::Refused(format!(
                    "{}: changed since it was approved on this machine; run `bd agents pull` to restore the version \
                     approved, or `bd agents approve` in a terminal",
                    show_path(&approved, &rel)
                )));
            }
            None => {
                return Err(Error::Refused(format!(
                    "{}: not a playbook approved on this machine (`bd agents status` lists the server's playbooks \
                     waiting for approval; `bd agents approve` in a terminal approves them)",
                    show_path(&approved, &rel)
                )));
            }
        }
    }
    Ok(())
}

fn show_path(approved: &Path, rel: &str) -> String {
    bd_core::agents::under(approved, rel).display().to_string()
}

/// The text lines of a report: `applied` for a pull, else what a pull would
/// do; none when the server serves no playbooks and nothing changes here.
pub fn lines(r: &PlaybooksReport, applied: bool) -> Vec<String> {
    if let Some(e) = &r.error {
        let line = format!("playbooks not checked (nothing about them changed here): {e}");
        return vec![super::show::cap_line(super::show::printable(&line))];
    }
    let mut lines = Vec::new();
    for (paths, done, todo) in [
        (
            &r.removed,
            "removed here, as the server no longer serves them",
            "to remove here, as the server no longer serves them",
        ),
        (&r.restored, "restored as approved", "to restore as approved"),
        (
            &r.discarded,
            "discarded (changed here and not the server's as approved, or not written by bd)",
            "to discard (changed here and not the server's as approved, or not written by bd)",
        ),
    ] {
        if !paths.is_empty() {
            lines.push(format!("playbooks {}: {}", if applied { done } else { todo }, paths.join(", ")));
        }
    }
    if !r.pending.is_empty() {
        lines.push(format!(
            "playbooks waiting for approval: {}: not used here until approved (a changed one keeps its approved \
             version); review and approve with `bd agents approve` in a terminal",
            pending_list(&r.pending)
        ));
    }
    // A server that serves none, with nothing here to remove: nothing to say.
    if lines.is_empty() && r.server_revision != PlaybookSet::empty().revision {
        lines.push(if applied {
            "playbooks: up to date".to_string()
        } else {
            format!("playbooks: up to date (revision {})", r.server_revision.get(..12).unwrap_or_default())
        });
    }
    lines.iter().map(|l| super::show::printable(l)).collect()
}

/// `change.toml (changed), triage.toml (new)`.
pub fn pending_list(pending: &[PendingPlaybook]) -> String {
    pending.iter().map(|p| format!("{} ({})", p.path, p.change.as_str())).collect::<Vec<_>>().join(", ")
}

/// The text of each approved playbook a pending one changes, to show the
/// change against; `None` where there is none (new) or it cannot be read
/// as approved (then it is shown whole).
pub fn approved_texts(checkout: &Checkout, pending: &[PendingPlaybook]) -> Result<BTreeMap<String, String>> {
    let lock = checkout.read_lock()?;
    let mut texts = BTreeMap::new();
    for p in pending.iter().filter(|p| p.change == PlaybookChange::Changed) {
        let Some(approved) = lock.playbooks.get(&p.path) else { continue };
        if let Some(bytes) = checkout.read_approved_playbook(&p.path)?
            && sha256_hex(&bytes) == approved.sha256
            && let Ok(text) = String::from_utf8(bytes)
        {
            texts.insert(p.path.clone(), text);
        }
    }
    Ok(texts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bd_core::playbook::{BUNDLE_VERSION, BundleFile, Format};

    struct Fake {
        set: PlaybookSet,
        fetched: usize,
        /// The manifest's failure, if it fails.
        fails: Option<fn() -> Error>,
    }

    impl Source for Fake {
        fn playbooks_manifest(&mut self) -> Result<Option<PlaybooksManifest>> {
            match self.fails {
                Some(e) => Err(e()),
                None => Ok(Some(self.set.manifest())),
            }
        }
        fn playbooks(&mut self) -> Result<PlaybookSet> {
            self.fetched += 1;
            Ok(self.set.clone())
        }
    }

    fn served(files: &[(&str, &str)]) -> Fake {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = bd_core::agents::under(dir.path(), path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        Fake { set: PlaybookSet::load(dir.path()).unwrap(), fetched: 0, fails: None }
    }

    fn checkout() -> (tempfile::TempDir, Checkout) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bd")).unwrap();
        let c = Checkout::new(dir.path().join(".bd"));
        (dir, c)
    }

    const WAIT: Duration = Duration::from_secs(1);

    fn status(c: &Checkout, f: &mut Fake) -> PlaybooksReport {
        run(c, f, false, false, WAIT).unwrap().unwrap().report
    }

    fn pull(c: &Checkout, f: &mut Fake) -> PlaybooksReport {
        run(c, f, true, false, WAIT).unwrap().unwrap().report
    }

    fn approve_all(c: &Checkout, f: &mut Fake) -> Vec<String> {
        let outcome = run(c, f, false, true, WAIT).unwrap().unwrap();
        let set = outcome.set.unwrap_or_else(PlaybookSet::empty);
        let lock = c.read_lock().unwrap();
        let approvals: Vec<Approval<'_>> = outcome
            .report
            .pending
            .iter()
            .map(|p| Approval {
                path: &p.path,
                text: &set.files[&p.path].text,
                recorded: lock.playbooks.get(&p.path).map(|a| a.sha256.as_str()),
            })
            .collect();
        apply_approved(c, &approvals, WAIT).unwrap().0
    }

    fn pending(r: &PlaybooksReport) -> Vec<(&str, PlaybookChange)> {
        r.pending.iter().map(|p| (p.path.as_str(), p.change)).collect()
    }

    #[test]
    fn only_the_servers_refusal_is_reported_and_other_failures_keep_their_exit_codes() {
        let (_dir, c) = checkout();
        let mut f = served(&[("change.toml", "v1")]);
        f.fails = Some(|| Error::invalid("https://bd.example/w/x: playbooks/bad.toml: not UTF-8"));
        let refusal = run_or_refusal(&c, &mut f, true, false, WAIT).unwrap().err().expect("a refusal");
        assert!(refusal.to_string().contains("bad.toml"), "{refusal}");
        f.fails = Some(|| Error::Remote("unreachable".into()));
        assert_eq!(run_or_refusal(&c, &mut f, true, false, WAIT).err().expect("an error").exit_code(), 8);
        f.fails = Some(|| Error::AnswerLost("lost".into()));
        assert_eq!(run_or_refusal(&c, &mut f, false, false, WAIT).err().unwrap().exit_code(), 9);
        // The checkout busy: exit 5, never a report.
        f.fails = None;
        let _held = c.exclusive(Duration::ZERO).unwrap();
        let e = run_or_refusal(&c, &mut f, false, false, Duration::from_millis(50)).err().expect("busy");
        assert_eq!(e.exit_code(), 5, "{e}");
    }

    #[test]
    fn server_playbooks_wait_for_approval_and_only_removals_and_restores_apply() {
        let (_dir, c) = checkout();
        let mut f = served(&[("change.toml", "v1"), ("parts/review.toml", "r1")]);
        let r = status(&c, &mut f);
        assert_eq!(pending(&r), [("change.toml", PlaybookChange::New), ("parts/review.toml", PlaybookChange::New)]);
        let r = pull(&c, &mut f);
        assert_eq!(r.pending.len(), 2, "a pull approves nothing");
        assert!(!c.approved_playbooks().exists() && !c.lock_path().exists(), "nor writes anything");
        assert_eq!(f.fetched, 0, "nor fetches the texts");

        assert_eq!(approve_all(&c, &mut f), ["change.toml", "parts/review.toml"]);
        assert_eq!(c.read_approved_playbook("change.toml").unwrap().as_deref(), Some(&b"v1"[..]));
        assert_eq!(c.read_lock().unwrap().playbooks["change.toml"].sha256, sha256_hex(b"v1"));
        assert!(pull(&c, &mut f).pending.is_empty());
        assert_eq!(lines(&status(&c, &mut f), false)[0][..30], *"playbooks: up to date (revisio");

        // A change on the server waits; the version approved stays.
        let mut f2 = served(&[("change.toml", "v2"), ("parts/review.toml", "r1")]);
        let r = pull(&c, &mut f2);
        assert_eq!(pending(&r), [("change.toml", PlaybookChange::Changed)]);
        assert_eq!(c.read_approved_playbook("change.toml").unwrap().as_deref(), Some(&b"v1"[..]));
        let texts = approved_texts(&c, &r.pending).unwrap();
        assert_eq!(texts["change.toml"], "v1", "what the change is shown against");

        // Deleted here, restored with the bytes approved, never the server's newer ones.
        c.remove_approved_playbook("parts/review.toml").unwrap();
        std::fs::write(c.approved_playbooks().join("change.toml"), "edited").unwrap();
        let r = pull(&c, &mut f2);
        assert_eq!(r.restored, ["parts/review.toml"]);
        assert_eq!(r.discarded, ["change.toml"], "edited here, and the server has another version: dropped");
        assert_eq!(pending(&r), [("change.toml", PlaybookChange::New)]);
        assert_eq!(c.read_approved_playbook("parts/review.toml").unwrap().as_deref(), Some(&b"r1"[..]));
        assert_eq!(c.read_approved_playbook("change.toml").unwrap(), None);
        assert!(!c.read_lock().unwrap().playbooks.contains_key("change.toml"));

        // Removed on the server: removed here; a file bd did not write there goes too.
        std::fs::write(c.approved_playbooks().join("planted.toml"), "x").unwrap();
        let mut f3 = served(&[("change.toml", "v2")]);
        let r = status(&c, &mut f3);
        assert_eq!(
            (r.removed.clone(), r.discarded.clone()),
            (vec!["parts/review.toml".to_string()], vec!["planted.toml".to_string()])
        );
        assert!(c.approved_playbooks().join("planted.toml").exists(), "status changes nothing");
        pull(&c, &mut f3);
        assert_eq!(c.approved_playbook_entries().unwrap(), Vec::<String>::new());
        assert!(c.read_lock().unwrap().playbooks.is_empty());
    }

    #[test]
    fn an_approval_changed_meanwhile_is_skipped() {
        let (_dir, c) = checkout();
        let approvals = [Approval { path: "change.toml", text: "v1", recorded: Some(&"0".repeat(64)) }];
        let (written, skipped) = apply_approved(&c, &approvals, WAIT).unwrap();
        assert!(written.is_empty());
        assert!(skipped[0].1.contains("changed since it was shown"), "{skipped:?}");
        assert!(!c.approved_playbooks().exists());
    }

    #[test]
    fn names_are_paths_or_playbook_names() {
        assert!(names("change", "change.toml") && names("change.toml", "change.toml"));
        assert!(names("x", "x.formula.json"));
        assert!(names("parts/review.toml", "parts/review.toml") && !names("review", "parts/review.toml"));
        assert!(!names("chan", "change.toml"));
    }

    fn bundle(files: &[(&Path, &str)], refs: &[(&str, &str, &Path)]) -> Bundle {
        let mut b = Bundle { version: BUNDLE_VERSION, ..Default::default() };
        for (path, text) in files {
            let file = BundleFile { name: "x".into(), format: Format::Toml, text: text.to_string() };
            b.files.insert(path.to_str().unwrap().into(), file);
        }
        for (from, reference, to) in refs {
            b.refs.entry(from.to_string()).or_default().insert(reference.to_string(), to.to_str().unwrap().into());
        }
        b
    }

    #[test]
    fn bundles_send_only_the_bytes_approved_and_stay_inside_the_approved_playbooks() {
        let (dir, c) = checkout();
        let mut f = served(&[("change.toml", "v1"), ("base.toml", "b1")]);
        approve_all(&c, &mut f);
        let approved = c.approved_playbooks();
        let (change, base) = (approved.join("change.toml"), approved.join("base.toml"));
        let own = dir.path().join(".bd/playbooks/mine.toml");
        let from = change.to_str().unwrap();

        verify_bundle(&c, &bundle(&[(&change, "v1"), (&base, "b1"), (&own, "anything")], &[("", "change", &change)]))
            .unwrap();
        // A name may resolve anywhere on the lookup path, as for any playbook found here.
        verify_bundle(&c, &bundle(&[(&change, "v1"), (&own, "x")], &[(from, "mine", &own)])).unwrap();

        let e = verify_bundle(&c, &bundle(&[(&change, "v2")], &[])).unwrap_err();
        assert!(e.to_string().contains("changed since it was approved"), "{e}");
        let stray = approved.join("other.toml");
        let e = verify_bundle(&c, &bundle(&[(&stray, "x")], &[])).unwrap_err();
        assert!(e.to_string().contains("not a playbook approved on this machine"), "{e}");
        // `..` back into the approved directory is still checked.
        let sneaky = approved.join("sub/../other.toml");
        assert!(verify_bundle(&c, &bundle(&[(&sneaky, "x")], &[])).is_err());
        // A reference by path out of the approved playbooks (to read a file of this machine) is never sent.
        let secret = dir.path().join("secret.toml");
        let e =
            verify_bundle(&c, &bundle(&[(&change, "v1"), (&secret, "s")], &[(from, "../../../secret.toml", &secret)]))
                .unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains("outside the approved playbooks"), "{e}");
    }
}
