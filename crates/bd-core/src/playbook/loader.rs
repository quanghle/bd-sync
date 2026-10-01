//! Finding playbook files and resolving `extends`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::model::{Playbook, Step, parse_json, parse_toml};
use crate::error::{Error, Result};

/// File name suffixes tried for a playbook name, in order. The `.formula.*`
/// forms let beads formula files be used as they are.
pub const EXTENSIONS: [&str; 4] = [".toml", ".json", ".formula.toml", ".formula.json"];

/// Resolves playbook references against an ordered list of directories.
#[derive(Clone, Debug, Default)]
pub struct Loader {
    pub search_paths: Vec<PathBuf>,
}

/// One file found by [`Loader::list`].
#[derive(Clone, Debug, Serialize)]
pub struct Listed {
    pub name: String,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "String::is_empty")]
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

fn is_path_like(reference: &str) -> bool {
    reference.contains('/') || reference.contains('\\') || EXTENSIONS.iter().any(|e| reference.ends_with(e))
}

/// The playbook name a file stands for (`release.formula.toml` -> `release`).
pub fn name_of(path: &Path) -> Option<String> {
    let file = path.file_name()?.to_str()?;
    EXTENSIONS.iter().rev().find_map(|ext| file.strip_suffix(ext)).map(String::from)
}

impl Loader {
    pub fn new(search_paths: Vec<PathBuf>) -> Loader {
        Loader { search_paths }
    }

    /// The file a reference names: a path (relative to `relative_to`, the
    /// referencing file's directory, when given) or a name looked up in the
    /// search paths.
    pub fn locate(&self, reference: &str, relative_to: Option<&Path>) -> Result<PathBuf> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(Error::invalid("empty playbook reference"));
        }
        if is_path_like(reference) {
            let p = PathBuf::from(reference);
            let p = match relative_to {
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
        let text = std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{}: {e}", path.display())))?;
        let origin = path.display().to_string();
        let default_name = name_of(path).unwrap_or_else(|| "playbook".into());
        let mut pb = if path.extension().is_some_and(|e| e == "json") {
            parse_json(&text, &origin, &default_name)?
        } else {
            parse_toml(&text, &origin, &default_name)?
        };
        pb.source = Some(path.to_path_buf());
        Ok(pb)
    }

    /// Load, resolve `extends`, and validate a playbook.
    pub fn load(&self, reference: &str) -> Result<Playbook> {
        self.load_from(reference, None)
    }

    pub fn load_from(&self, reference: &str, relative_to: Option<&Path>) -> Result<Playbook> {
        let path = self.locate(reference, relative_to)?;
        let pb = self.resolve(Loader::parse_file(&path)?, &mut Vec::new())?;
        pb.validate()?;
        // Expanded playbooks load when a run compiles; make sure they exist now.
        let dir = pb.source.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        for step in pb.all_steps() {
            if let Some(target) = &step.expand {
                self.locate(target, dir.as_deref()).map_err(|e| {
                    Error::invalid(format!("playbook {}: step {} expands {target}: {e}", pb.name, step.id))
                })?;
            }
        }
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
        chain.push(pb.name.clone());
        let dir = pb.source.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        let mut vars = BTreeMap::new();
        let mut steps: Vec<Step> = Vec::new();
        let (mut description, mut title, mut priority, mut labels, mut ephemeral) =
            (String::new(), None, None, Vec::new(), None);
        for parent_ref in &pb.extends {
            let path = self.locate(parent_ref, dir.as_deref())?;
            let parent = Loader::parse_file(&path)
                .and_then(|p| self.resolve(p, chain))
                .map_err(|e| Error::invalid(format!("{} extends {parent_ref}: {e}", pb.name)))?;
            for (k, v) in parent.vars {
                vars.entry(k).or_insert(v);
            }
            steps.extend(parent.steps);
            if description.is_empty() {
                description = parent.description;
            }
            title = title.or(parent.title);
            priority = priority.or(parent.priority);
            if labels.is_empty() {
                labels = parent.labels;
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
                let loaded =
                    Loader::parse_file(&path).and_then(|pb| self.resolve(pb, &mut Vec::new())).and_then(|pb| {
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
