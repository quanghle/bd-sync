//! Finding playbook files and resolving `extends`.
//!
//! A loader serves one command. It keeps every playbook it merged and
//! checked, so a file reached twice (a diamond of `extends`, a playbook
//! expanded in a loop) is read, merged and checked once, and what it keeps
//! counts against [`MAX_LOAD_WORK`]. A merged playbook shares its parents'
//! steps and variable definitions, so keeping one per file of a long chain
//! costs pointers; the text a merge does copy counts against
//! [`MAX_INHERITED_BYTES`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::bundle::{self, Bundle, Sources};
use super::model::{MAX_RUN_ISSUES, Playbook, Step, parse_json, parse_toml};
use crate::error::{Error, Result};

/// File name suffixes tried for a playbook name, in order. The `.formula.*`
/// forms let beads formula files be used as they are.
pub const EXTENSIONS: [&str; 4] = [".toml", ".json", ".formula.toml", ".formula.json"];

/// Most steps and variables one command may load: each one read from a
/// playbook file or inherited from an `extends` parent counts. A loader keeps
/// them all until the command is done.
pub const MAX_LOAD_WORK: usize = 10 * MAX_RUN_ISSUES;

/// Most text one command may copy from `extends` parents: the description,
/// title and labels a playbook inherits, and the names of its variables.
/// Steps and variable definitions are shared, never copied.
pub const MAX_INHERITED_BYTES: usize = 16 << 20;

/// Resolves playbook references against an ordered list of directories, or
/// against the files of a [`Bundle`] a bd client sent.
#[derive(Clone, Debug, Default)]
pub struct Loader {
    pub search_paths: Vec<PathBuf>,
    files: Files,
    session: Arc<Mutex<Session>>,
}

/// What a loader has done for its command.
#[derive(Debug, Default)]
struct Session {
    /// Playbooks with their `extends` merged, by file.
    merged: HashMap<PathBuf, Arc<Playbook>>,
    /// Files whose merged playbook was also validated.
    checked: HashSet<PathBuf>,
    work: usize,
    inherited: usize,
}

/// Where a loader reads playbook files.
#[derive(Clone, Debug, Default)]
enum Files {
    #[default]
    Disk,
    /// The disk, noting every file read and every reference resolved, to build a [`Bundle`].
    Recording(Arc<Mutex<Bundle>>),
    /// Only a bundle's files: nothing is read from disk.
    Bundle(Arc<Sources>),
}

/// One file found by [`Loader::list`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Listed {
    pub name: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Declared variables; required ones end with `!`.
    pub vars: Vec<String>,
    pub steps: usize,
    pub ephemeral: bool,
    /// An earlier search directory has a playbook with the same name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowed_by: Option<PathBuf>,
    /// Set when the file does not parse or validate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A reference that names a file (`dir/x.toml`, `x.toml`) rather than a
/// playbook on the search path. A name is joined to each search directory, so
/// it must stay inside: no separators, and no colon, which on Windows starts a
/// drive-relative path (`C:x`).
pub fn is_path_like(reference: &str) -> bool {
    reference.contains(['/', '\\', ':']) || EXTENSIONS.iter().any(|e| reference.ends_with(e))
}

/// The playbook name a file stands for (`release.formula.toml` -> `release`).
pub fn name_of(path: &Path) -> Option<String> {
    let file = path.file_name()?.to_str()?;
    EXTENSIONS.iter().rev().find_map(|ext| file.strip_suffix(ext)).map(String::from)
}

/// The name a file's playbook gets when it does not set one.
pub(crate) fn default_name(path: &Path) -> String {
    name_of(path).unwrap_or_else(|| "playbook".into())
}

/// Files ending in `.json` are JSON; everything else is TOML.
pub(crate) fn is_json(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "json")
}

/// Parse a playbook's text; `path` names it in errors and becomes its `source`.
pub(crate) fn parse_source(text: &str, path: &Path, default_name: &str, json: bool) -> Result<Playbook> {
    let origin = path.display().to_string();
    let mut pb = if json { parse_json(text, &origin, default_name)? } else { parse_toml(text, &origin, default_name)? };
    pb.source = Some(path.to_path_buf());
    Ok(pb)
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn too_many_steps(name: &str, n: usize) -> Error {
    Error::invalid(format!("playbook {name}: has {n} steps (at most {MAX_RUN_ISSUES})"))
}

/// What holding a copy of `s` in a list or map costs: its text, plus about
/// 32 bytes for the string and its entry.
fn entry_bytes(s: &str) -> usize {
    s.len() + 32
}

impl Loader {
    pub fn new(search_paths: Vec<PathBuf>) -> Loader {
        Loader { search_paths, files: Files::Disk, session: Arc::default() }
    }

    /// Reads from disk like `Loader::new`, and notes what it reads in `bundle`.
    pub(crate) fn recording(search_paths: Vec<PathBuf>, bundle: Arc<Mutex<Bundle>>) -> Loader {
        Loader { search_paths, files: Files::Recording(bundle), session: Arc::default() }
    }

    /// Reads only the files of a bundle.
    pub(crate) fn of_sources(sources: Sources) -> Loader {
        Loader { search_paths: Vec::new(), files: Files::Bundle(Arc::new(sources)), session: Arc::default() }
    }

    /// Count `units` against [`MAX_LOAD_WORK`] and `inherited` bytes against
    /// [`MAX_INHERITED_BYTES`]. A client collecting its own files for a bundle
    /// is not held to them: the bundle's limits bound that, and the server
    /// applies these to what it loads.
    fn charge(&self, units: usize, inherited: usize) -> Result<()> {
        if matches!(self.files, Files::Recording(_)) {
            return Ok(());
        }
        let mut session = lock(&self.session);
        session.work = session.work.saturating_add(units);
        if session.work > MAX_LOAD_WORK {
            return Err(Error::invalid(format!(
                "loading needs more than {MAX_LOAD_WORK} steps and variables (read from playbook files or \
                 inherited through extends); extend or expand fewer or smaller playbooks"
            )));
        }
        session.inherited = session.inherited.saturating_add(inherited);
        if session.inherited > MAX_INHERITED_BYTES {
            return Err(Error::invalid(format!(
                "loading copies more than {} MiB of descriptions, titles, labels and variable names inherited \
                 through extends; extend fewer or smaller playbooks",
                MAX_INHERITED_BYTES >> 20
            )));
        }
        Ok(())
    }

    /// True when the files come from a bundle a client sent.
    pub fn is_bundle(&self) -> bool {
        matches!(self.files, Files::Bundle(_))
    }

    /// The file a reference names: a path (relative to `relative_to`, the
    /// directory of the command line, when given) or a name looked up in the
    /// search paths.
    pub fn locate(&self, reference: &str, relative_to: Option<&Path>) -> Result<PathBuf> {
        self.find(reference, None, relative_to)
    }

    /// The file a reference in the playbook file `from` names (`extends`,
    /// `expand`): a path relative to `from`'s directory, or a name.
    pub(crate) fn locate_ref(&self, reference: &str, from: Option<&Path>) -> Result<PathBuf> {
        self.find(reference, from, from.and_then(Path::parent))
    }

    fn find(&self, reference: &str, from: Option<&Path>, dir: Option<&Path>) -> Result<PathBuf> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(Error::invalid("empty playbook reference"));
        }
        if let Files::Bundle(sources) = &self.files {
            return sources.resolve(from, reference);
        }
        let path = self.find_on_disk(reference, dir)?;
        if let Files::Recording(bundle) = &self.files {
            bundle::record_ref(bundle, from, reference, &path)?;
        }
        Ok(path)
    }

    fn find_on_disk(&self, reference: &str, dir: Option<&Path>) -> Result<PathBuf> {
        if is_path_like(reference) {
            let p = PathBuf::from(reference);
            let p = match dir {
                Some(dir) if p.is_relative() => dir.join(p),
                _ => p,
            };
            return if p.is_file() { Ok(p) } else { Err(Error::not_found("playbook file", p.display().to_string())) };
        }
        for dir in &self.search_paths {
            for ext in EXTENSIONS {
                let p = dir.join(format!("{reference}{ext}"));
                if p.is_file() {
                    return Ok(p);
                }
            }
        }
        let searched: Vec<String> = self.search_paths.iter().map(|p| p.display().to_string()).collect();
        Err(Error::not_found(
            "playbook",
            format!(
                "{reference} (searched: {})",
                if searched.is_empty() { "nothing".into() } else { searched.join(", ") }
            ),
        ))
    }

    /// Parse one file without resolving `extends`.
    pub fn parse_file(path: &Path) -> Result<Playbook> {
        parse_source(&read_text(path)?, path, &default_name(path), is_json(path))
    }

    /// Parse one file this loader located, without resolving `extends`.
    fn read(&self, path: &Path) -> Result<Playbook> {
        let pb = match &self.files {
            Files::Disk => Loader::parse_file(path)?,
            Files::Bundle(sources) => sources.playbook(path)?,
            Files::Recording(bundle) => {
                let text = read_text(path)?;
                bundle::record_file(bundle, path, &text)?;
                parse_source(&text, path, &default_name(path), is_json(path))?
            }
        };
        self.charge(1 + pb.all_steps().len() + pb.vars.len(), 0)?;
        Ok(pb)
    }

    /// Load, resolve `extends`, and validate a playbook.
    pub fn load(&self, reference: &str) -> Result<Playbook> {
        self.load_from(reference, None)
    }

    pub fn load_from(&self, reference: &str, relative_to: Option<&Path>) -> Result<Playbook> {
        let path = self.locate(reference, relative_to)?;
        Ok(Playbook::clone(&*self.checked(&path)?))
    }

    /// The playbook a step of the playbook file `from` expands, shared by
    /// every expansion of it in this command.
    pub(crate) fn expansion(&self, reference: &str, from: Option<&Path>) -> Result<Arc<Playbook>> {
        let path = self.locate_ref(reference, from)?;
        self.checked(&path)
    }

    /// The playbook in `path`, merged and validated once per command.
    pub(crate) fn checked(&self, path: &Path) -> Result<Arc<Playbook>> {
        let pb = self.merged(path, &mut Vec::new())?;
        if lock(&self.session).checked.contains(path) {
            return Ok(pb);
        }
        pb.validate()?;
        // Expanded playbooks load when a run compiles; make sure they exist now.
        for step in pb.all_steps() {
            if let Some(target) = &step.expand {
                self.locate_ref(target, pb.source.as_deref()).map_err(|e| {
                    Error::invalid(format!("playbook {}: step {} expands {target}: {e}", pb.name, step.id))
                })?;
            }
        }
        lock(&self.session).checked.insert(path.to_path_buf());
        Ok(pb)
    }

    /// The playbook in `path` with its `extends` merged, once per command.
    fn merged(&self, path: &Path, chain: &mut Vec<String>) -> Result<Arc<Playbook>> {
        if let Some(pb) = lock(&self.session).merged.get(path) {
            return Ok(pb.clone());
        }
        let pb = Arc::new(self.resolve(self.read(path)?, chain)?);
        lock(&self.session).merged.insert(path.to_path_buf(), pb.clone());
        Ok(pb)
    }

    /// Merge `extends` parents (beads semantics): parents' steps come first
    /// and a child step with the same id replaces the parent's in place; for
    /// vars the child wins, then the first parent that declares it.
    fn resolve(&self, mut pb: Playbook, chain: &mut Vec<String>) -> Result<Playbook> {
        if pb.extends.is_empty() {
            return Ok(pb);
        }
        if chain.contains(&pb.name) {
            chain.push(pb.name.clone());
            return Err(Error::invalid(format!("circular extends: {}", chain.join(" -> "))));
        }
        // Merging is quadratic in the number of steps: refuse oversized playbooks first.
        let own = pb.all_steps().len();
        if own > MAX_RUN_ISSUES {
            return Err(too_many_steps(&pb.name, own));
        }
        chain.push(pb.name.clone());
        let mut vars = BTreeMap::new();
        let mut steps: Vec<Arc<Step>> = Vec::new();
        let (mut description, mut title, mut priority, mut labels, mut ephemeral) =
            (String::new(), None, None, Vec::new(), None);
        for parent_ref in &pb.extends {
            let path = self.locate_ref(parent_ref, pb.source.as_deref())?;
            // A parent reached again (a diamond) is merged from what was kept, never resolved twice.
            let parent = self
                .merged(&path, chain)
                .map_err(|e| Error::invalid(format!("{} extends {parent_ref}: {e}", pb.name)))?;
            // Steps and variable definitions are shared; the rest is copied, once per merge.
            let take_description = pb.description.is_empty() && description.is_empty();
            let take_title = pb.title.is_none() && title.is_none();
            let take_labels = pb.labels.is_empty() && labels.is_empty();
            let mut copied: usize = parent.vars.keys().map(|k| entry_bytes(k)).sum();
            if take_description {
                copied += parent.description.len();
            }
            if take_title {
                copied += parent.title.as_ref().map_or(0, String::len);
            }
            if take_labels {
                copied += parent.labels.iter().map(|l| entry_bytes(l)).sum::<usize>();
            }
            self.charge(1 + parent.all_steps().len() + parent.vars.len(), copied)?;
            for (k, v) in &parent.vars {
                vars.entry(k.clone()).or_insert_with(|| v.clone());
            }
            steps.extend(parent.steps.iter().cloned());
            if steps.len() > MAX_RUN_ISSUES {
                return Err(too_many_steps(&pb.name, steps.len()));
            }
            if take_description {
                description = parent.description.clone();
            }
            if take_title {
                title = parent.title.clone();
            }
            priority = priority.or(parent.priority);
            if take_labels {
                labels = parent.labels.clone();
            }
            ephemeral = ephemeral.or(parent.ephemeral);
        }
        chain.pop();
        vars.extend(std::mem::take(&mut pb.vars));
        for step in std::mem::take(&mut pb.steps) {
            match steps.iter().position(|s| s.id == step.id) {
                Some(i) => steps[i] = step,
                None => steps.push(step),
            }
        }
        pb.vars = vars;
        pb.steps = steps;
        if pb.description.is_empty() {
            pb.description = description;
        }
        pb.title = pb.title.or(title);
        pb.priority = pb.priority.or(priority);
        if pb.labels.is_empty() {
            pb.labels = labels;
        }
        pb.ephemeral = pb.ephemeral.or(ephemeral);
        Ok(pb)
    }

    /// Every playbook file in the search paths, in lookup order.
    pub fn list(&self) -> Vec<Listed> {
        let mut out: Vec<Listed> = Vec::new();
        for dir in &self.search_paths {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            let mut files: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            files.sort();
            for path in files {
                let Some(name) = name_of(&path) else { continue };
                if !path.is_file() {
                    continue;
                }
                let shadowed_by = out.iter().find(|l| l.name == name).map(|l| l.path.clone());
                // Each file on its own, as if it were the one a command names.
                let one = Loader::new(self.search_paths.clone());
                let loaded = one.merged(&path, &mut Vec::new()).and_then(|pb| {
                    pb.validate()?;
                    Ok(pb)
                });
                let mut listed = Listed {
                    name,
                    path: path.clone(),
                    description: String::new(),
                    vars: Vec::new(),
                    steps: 0,
                    ephemeral: false,
                    shadowed_by,
                    error: None,
                };
                match loaded {
                    Ok(pb) => {
                        listed.description = pb.description.clone();
                        listed.vars =
                            pb.vars.iter().map(|(k, v)| if v.required { format!("{k}!") } else { k.clone() }).collect();
                        listed.steps = pb.all_steps().len();
                        listed.ephemeral = pb.is_ephemeral();
                    }
                    Err(e) => listed.error = Some(e.to_string()),
                }
                out.push(listed);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_never_leave_the_search_directories() {
        for path in ["a/b", "a\\b", "x.toml", "x.formula.json", "C:x", "c:x.toml", "a:b", "C:\\x"] {
            assert!(is_path_like(path), "{path}");
        }
        for name in ["release", "my-playbook_2", "v1.2"] {
            assert!(!is_path_like(name), "{name}");
        }
        let dir = tempfile::tempdir().unwrap();
        let loader = Loader::new(vec![dir.path().to_path_buf()]);
        let err = loader.locate("C:evil", Some(dir.path())).unwrap_err();
        assert_eq!(err.code(), "not_found", "a drive-relative name is a path, not a name: {err}");
    }
}
