//! `bd setup <harness>`: write a harness's bd integration into the current
//! project. Claude Code, Codex and Copilot CLI get hooks, written through
//! [`session_hook`] as `bd agents pull` writes its session-start hook;
//! Cursor, Gemini CLI and opencode get a marked section of instructions
//! ([`section`]) pointing at `bd prime`.
//!
//! The project is the nearest directory, from the working directory up,
//! holding a `.bd` directory or a `.git` ([`project_root`]): a git worktree
//! nested in its main checkout is set up in itself. Setup takes the
//! checkout's mutex only when that project is the checkout `bd agents pull`
//! writes to ([`pull_checkout_is`]), the only writer it could race with.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bd_core::agents::{Harness, under};
use bd_core::{Error, Result};
use serde::Serialize;

use crate::agents::checkout::Checkout;
use crate::agents::session_hook::{self, Entry, Homes, HookReport, HookState, Outcome, Sources};
use crate::agents::show::printable;
use crate::app::{App, Out};
use crate::cli::{SetupArgs, SetupTarget};
use crate::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    /// Hook entries merged into a JSON hook file.
    Hooks,
    /// A marked Markdown section of instructions.
    Instructions,
}

/// What `bd setup` writes for one harness.
struct Recipe {
    target: SetupTarget,
    kind: Kind,
    /// The file, relative to the project root.
    file: &'static str,
    /// What a new instructions file starts with.
    header: Option<&'static str>,
    /// What to do once the file is written, if anything.
    next: Option<&'static str>,
}

const CURSOR_HEADER: &str = "---\ndescription: Task tracking with bd\nalwaysApply: true\n---\n";

fn recipe(target: SetupTarget) -> Recipe {
    let hooks = |file, next| Recipe { target, kind: Kind::Hooks, file, header: None, next: Some(next) };
    let text = |file, header| Recipe { target, kind: Kind::Instructions, file, header, next: None };
    match target {
        SetupTarget::Claude => hooks(".claude/settings.json", "start a new session, or review with /hooks"),
        SetupTarget::Codex => hooks(
            session_hook::target(Harness::Codex),
            "trust the hooks with /hooks (project .codex layers load only when trusted)",
        ),
        SetupTarget::Copilot => hooks(session_hook::target(Harness::Copilot), "start a new session"),
        SetupTarget::Cursor => text(".cursor/rules/bd.mdc", Some(CURSOR_HEADER)),
        // Not a `.gemini/settings.json` SessionStart hook: Gemini CLI's can return
        // `hookSpecificOutput.additionalContext`, but it needs JSON-only stdout (bd's
        // session-start output is plain text) and a Gemini harness identity bd does not
        // have, and it does not run after compression (PreCompress is advisory only).
        SetupTarget::Gemini => text("GEMINI.md", None),
        SetupTarget::Opencode => text("AGENTS.md", None),
    }
}

impl Recipe {
    /// The harness and hook entries of a hooks recipe, and where it looks
    /// for them already configured.
    fn hooks(&self) -> Option<(Harness, Vec<Entry>, Sources)> {
        match self.target {
            // Claude Code runs a handler once across settings files, so only the shared file and plugins count.
            SetupTarget::Claude => {
                Some((Harness::Claude, session_hook::claude_project_entries(), Sources::TargetAndPlugins))
            }
            SetupTarget::Codex => Some((Harness::Codex, session_hook::session_entries(Harness::Codex), Sources::All)),
            SetupTarget::Copilot => {
                Some((Harness::Copilot, session_hook::session_entries(Harness::Copilot), Sources::All))
            }
            SetupTarget::Cursor | SetupTarget::Gemini | SetupTarget::Opencode => None,
        }
    }

    /// Add (or with `remove`, take out) bd's integration under `root`;
    /// `apply` writes, else it only reports.
    fn run(&self, root: &Path, remove: bool, apply: bool) -> Result<Outcome> {
        if let Some((h, entries, sources)) = self.hooks() {
            return match remove {
                false => session_hook::ensure_entries(root, self.file, h, &entries, sources, apply, &Homes::from_env()),
                true => session_hook::remove_entries(root, self.file, &entries, apply),
            };
        }
        let path = under(root, self.file);
        let begin = section::begin(self.target.name());
        let report = |state, reason| Outcome {
            report: HookReport { file: self.file.to_string(), state, reason },
            events: Vec::new(),
        };
        let text = match session_hook::read_target(&path)? {
            Ok(text) => text,
            Err(why) => return Ok(report(HookState::Conflict, Some(why))),
        };
        let change = match remove {
            false => section::add(text.as_deref(), self.header, &begin),
            true => section::remove(text.as_deref(), self.header),
        };
        let (state, new) = match change {
            Ok(change) => change,
            Err(why) => return Ok(report(HookState::Conflict, Some(why))),
        };
        if apply {
            match new {
                Some(section::NewText::Write(text)) => session_hook::write_target(&path, &text)?,
                Some(section::NewText::Delete) => session_hook::delete_target(&path)?,
                None => {}
            }
        }
        Ok(report(state, None))
    }
}

/// The project `bd setup` works on: the nearest of `cwd` and its ancestors
/// holding a `.bd` directory or a `.git` (a directory, or a worktree's
/// file). Neither a `remote.toml` nor a database further up wins over a
/// closer `.git`.
fn project_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors().find(|d| d.join(".bd").is_dir() || d.join(".git").exists()).map(Path::to_path_buf)
}

/// Whether the checkout `bd agents pull` writes to, found as pull finds it,
/// is `root`'s: setup then serializes with pull through its mutex. Any
/// error finding it means no.
fn pull_checkout_is(app: &App, root: &Path) -> bool {
    let remote = crate::remote::configured(app).ok().flatten().is_some();
    match crate::agents::find_checkout(app, remote) {
        Ok(c) => same_dir(&c.bd, &root.join(".bd")),
        Err(_) => false,
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// One file in a [`SetupReport`].
#[derive(Serialize)]
struct SetupFile {
    #[serde(flatten)]
    report: HookReport,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events: Vec<&'static str>,
}

#[derive(Serialize)]
struct SetupReport {
    harness: &'static str,
    action: &'static str,
    dry_run: bool,
    root: String,
    files: Vec<SetupFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<&'static str>,
}

pub fn cmd_setup(app: &mut App, a: &SetupArgs) -> Result<i32> {
    io::require_local("bd setup")?;
    let root = project_root(&app.cwd).ok_or_else(|| {
        Error::invalid(format!(
            "no .bd or .git in {} or above it: run bd setup inside a project, or pass -C",
            printable(&app.cwd.display().to_string())
        ))
    })?;
    if a.list {
        return list(app, &root);
    }
    let Some(target) = a.harness else {
        return Err(Error::invalid("name the harness to set up, or pass --list"));
    };
    let recipe = recipe(target);
    let apply = !a.dry_run;
    let mutex = match apply && pull_checkout_is(app, &root) {
        true => Some(Checkout::new(root.join(".bd")).exclusive(Duration::from_millis(app.g.busy_timeout_ms))?),
        false => None,
    };
    let outcome = recipe.run(&root, a.remove, apply)?;
    drop(mutex);
    let conflict = outcome.report.state == HookState::Conflict;
    let added = outcome.report.state == HookState::Added && !a.remove;
    let report = SetupReport {
        harness: target.name(),
        action: if a.remove { "remove" } else { "add" },
        dry_run: a.dry_run,
        root: root.display().to_string(),
        next: recipe.next.filter(|_| added),
        files: vec![SetupFile { report: outcome.report, events: outcome.events }],
    };
    let lines = text_lines(&report, &recipe);
    app.print(Out::new(&report).lines(lines));
    Ok(if conflict { 1 } else { 0 })
}

fn text_lines(r: &SetupReport, recipe: &Recipe) -> Vec<String> {
    let mut lines = vec![format!("bd setup {} in {}", r.harness, r.root)];
    let would = |done: &str, todo: &str| if r.dry_run { todo.to_string() } else { done.to_string() };
    for f in &r.files {
        let file = recipe.file;
        let what = match recipe.kind {
            Kind::Hooks => format!("{} hooks", f.events.join(", ")),
            Kind::Instructions => "bd section".to_string(),
        };
        lines.push(match f.report.state {
            HookState::Added => format!("✓ {file}: {} {what}", would("added", "would add")),
            HookState::Removed => format!("✓ {file}: {} {what}", would("removed", "would remove")),
            HookState::Updated => format!("↻ {file}: section {}", would("updated", "would be updated")),
            HookState::Absent => format!("· {file}: nothing of bd setup's to remove"),
            HookState::Conflict => {
                format!("✗ {file}: left as it is: {}", f.report.reason.as_deref().unwrap_or_default())
            }
            HookState::Present => {
                let mut line = format!("· {file}: already set up");
                let found = f.report.file.as_str();
                if found != file {
                    line.push_str(&format!(" in {found}"));
                    if Path::new(found).is_absolute() || found.ends_with(".local.json") {
                        line.push_str(" (personal: not shared with the project)");
                    }
                }
                line
            }
        });
    }
    if let Some(next) = r.next.filter(|_| !r.dry_run) {
        lines.push(format!("next: {next}"));
    }
    // Paths and reasons may quote what a file holds.
    lines.iter().map(|l| printable(l)).collect()
}

#[derive(Serialize)]
struct ListItem {
    name: &'static str,
    kind: Kind,
    files: Vec<&'static str>,
    /// present, partial, missing, outdated or conflict.
    state: &'static str,
}

fn list(app: &App, root: &Path) -> Result<i32> {
    let mut items = Vec::new();
    for target in SetupTarget::ALL {
        let recipe = recipe(target);
        let outcome = recipe.run(root, false, false)?;
        let all = recipe.hooks().map_or(1, |(_, entries, _)| entries.len());
        let state = match outcome.report.state {
            HookState::Present => "present",
            HookState::Added if outcome.events.len() < all && recipe.kind == Kind::Hooks => "partial",
            HookState::Added => "missing",
            HookState::Updated => "outdated",
            _ => "conflict",
        };
        items.push(ListItem { name: target.name(), kind: recipe.kind, files: vec![recipe.file], state });
    }
    let kind = |k: Kind| match k {
        Kind::Hooks => "hooks",
        Kind::Instructions => "instructions",
    };
    let mut lines = vec![format!("bd setup recipes for {}", root.display())];
    lines.extend(
        items.iter().map(|i| format!("{:<9} {:<13} {:<28} {}", i.name, kind(i.kind), i.files.join(", "), i.state)),
    );
    let lines: Vec<String> = lines.iter().map(|l| printable(l)).collect();
    app.print(Out::new(&items).lines(lines));
    Ok(0)
}

/// The Markdown section of instructions bd writes, between marker lines, so
/// that it is found, replaced and removed exactly and nothing else is.
pub(crate) mod section {
    use super::HookState;

    /// What starts a begin marker line.
    const BEGIN_PREFIX: &str = "<!-- BEGIN bd setup";
    const END: &str = "<!-- END bd setup -->";

    /// The section's text, between the markers.
    pub const SECTION: &str = "\
## Task tracking with bd

This project tracks its work with bd. Run `bd prime` at the start of a
session, and again after the conversation is compacted or summarized: it
prints your actor, your claims with their lease tokens, the ready work and
the project's memories.

- `bd ready` lists unblocked work; `bd claim --next` (or `bd claim <id>`)
  claims one and prints its lease token.
- `bd heartbeat <id> --token <t>` renews the lease during long work;
  `bd close <id> --reason \"what was done\"` finishes it.
- `bd create \"Title\" -d \"why and what\"` records work found on the way.
- Add `--json` to a command whose output you parse.
- If bd prime lists feature specs, link each change you close to its spec
  or requirement (`bd spec link <id> <spec>`) or mark it
  `bd spec none <id> -r '<why>'`.
- Track tasks in bd, not in markdown TODO lists.";

    /// The begin marker line for the harness `target`.
    pub fn begin(target: &str) -> String {
        format!("<!-- BEGIN bd setup: bd setup {target} --remove removes this section -->")
    }

    /// What to do with the file.
    #[derive(Debug, PartialEq, Eq)]
    pub enum NewText {
        Write(String),
        Delete,
    }

    /// The lines of `text` without their line endings.
    fn lines(text: &str) -> Vec<&str> {
        text.split_inclusive('\n').map(|l| l.trim_end_matches('\n').trim_end_matches('\r')).collect()
    }

    /// The line ending of `text`: CRLF if it has any.
    fn eol(text: &str) -> &'static str {
        if text.contains("\r\n") { "\r\n" } else { "\n" }
    }

    /// The begin and end lines of bd's section in `lines`, if there is one;
    /// `Err` when the markers are not one well-formed pair.
    fn find(lines: &[&str]) -> std::result::Result<Option<(usize, usize)>, String> {
        let begins: Vec<usize> =
            (0..lines.len()).filter(|&i| lines[i].trim_start().starts_with(BEGIN_PREFIX)).collect();
        let ends: Vec<usize> = (0..lines.len()).filter(|&i| lines[i].trim() == END).collect();
        match (&begins[..], &ends[..]) {
            ([], []) => Ok(None),
            ([b], [e]) if b < e => Ok(Some((*b, *e))),
            _ => Err(format!(
                "its bd setup markers are not one `{BEGIN_PREFIX} ...` line followed by one `{END}` line; fix or \
                 remove them by hand"
            )),
        }
    }

    fn section_lines(begin: &str) -> Vec<&str> {
        let mut out = vec![begin];
        out.extend(SECTION.lines());
        out.push(END);
        out
    }

    fn join(lines: &[&str], eol: &str) -> String {
        lines.iter().map(|l| format!("{l}{eol}")).collect()
    }

    /// `text` (`None`: no file) with bd's section added or brought up to
    /// date: the state, and the new text unless it is unchanged.
    pub fn add(
        text: Option<&str>,
        header: Option<&str>,
        begin: &str,
    ) -> std::result::Result<(HookState, Option<NewText>), String> {
        let ours = section_lines(begin);
        let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
            let mut new = String::new();
            if let Some(header) = header {
                new.push_str(header);
                new.push('\n');
            }
            new.push_str(&join(&ours, "\n"));
            return Ok((HookState::Added, Some(NewText::Write(new))));
        };
        let eol = eol(text);
        let all = lines(text);
        match find(&all)? {
            None => {
                let mut new = text.to_string();
                if !new.ends_with('\n') {
                    new.push_str(eol);
                }
                new.push_str(eol);
                new.push_str(&join(&ours, eol));
                Ok((HookState::Added, Some(NewText::Write(new))))
            }
            Some((b, e)) if all[b..=e] == ours[..] => Ok((HookState::Present, None)),
            Some((b, e)) => {
                let mut kept = all[..b].to_vec();
                kept.extend(&ours);
                kept.extend(&all[e + 1..]);
                let mut new = join(&kept, eol);
                if !text.ends_with('\n') && e + 1 < all.len() {
                    new.truncate(new.len() - eol.len());
                }
                Ok((HookState::Updated, Some(NewText::Write(new))))
            }
        }
    }

    /// `text` without bd's section and the blank line bd put before it; the
    /// file goes when nothing but `header` is left.
    pub fn remove(
        text: Option<&str>,
        header: Option<&str>,
    ) -> std::result::Result<(HookState, Option<NewText>), String> {
        let Some(text) = text else { return Ok((HookState::Absent, None)) };
        let all = lines(text);
        let Some((mut b, e)) = find(&all)? else { return Ok((HookState::Absent, None)) };
        if b > 0 && all[b - 1].trim().is_empty() {
            b -= 1;
        }
        let mut kept = all[..b].to_vec();
        kept.extend(&all[e + 1..]);
        let mut new = join(&kept, eol(text));
        if !text.ends_with('\n') && e + 1 < all.len() {
            new.truncate(new.len() - eol(text).len());
        }
        let rest = new.replace("\r\n", "\n");
        if rest.trim().is_empty() || header.is_some_and(|h| rest.trim() == h.trim()) {
            return Ok((HookState::Removed, Some(NewText::Delete)));
        }
        Ok((HookState::Removed, Some(NewText::Write(new))))
    }
}

#[cfg(test)]
mod tests {
    use super::section::{NewText, SECTION, add, begin, remove};
    use super::*;

    fn written(r: std::result::Result<(HookState, Option<NewText>), String>) -> (HookState, String) {
        match r.unwrap() {
            (state, Some(NewText::Write(text))) => (state, text),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn sections_are_added_once_and_kept_up_to_date() {
        let b = begin("opencode");
        let (state, created) = written(add(None, None, &b));
        assert_eq!(state, HookState::Added);
        assert!(
            created.starts_with(&b) && created.contains("bd prime") && created.ends_with("<!-- END bd setup -->\n")
        );
        assert_eq!(add(Some(&created), None, &b).unwrap(), (HookState::Present, None));

        let user = "# Notes\n\nKeep this.\n";
        let (_, appended) = written(add(Some(user), None, &b));
        assert!(appended.starts_with("# Notes\n\nKeep this.\n\n<!-- BEGIN bd setup"), "{appended}");
        assert_eq!(add(Some(&appended), None, &b).unwrap(), (HookState::Present, None));
        assert_eq!(remove(Some(&appended), None).unwrap(), (HookState::Removed, Some(NewText::Write(user.into()))));

        // An older bd's text is replaced in place, around the user's text.
        let old = format!("{user}\n{b}\n## Old text\n<!-- END bd setup -->\nAfter.\n");
        let (state, updated) = written(add(Some(&old), None, &b));
        assert_eq!(state, HookState::Updated);
        assert!(updated.starts_with(user) && updated.ends_with("<!-- END bd setup -->\nAfter.\n"), "{updated}");
        assert!(updated.contains(SECTION.lines().next().unwrap()) && !updated.contains("Old text"));
    }

    #[test]
    fn malformed_markers_are_conflicts() {
        let b = begin("gemini");
        for text in [
            format!("{b}\nno end\n"),
            "<!-- END bd setup -->\n<!-- BEGIN bd setup: x -->\n".to_string(),
            format!("{b}\n<!-- END bd setup -->\n{b}\n<!-- END bd setup -->\n"),
        ] {
            assert!(add(Some(&text), None, &b).unwrap_err().contains("markers"), "{text}");
            assert!(remove(Some(&text), None).is_err(), "{text}");
        }
    }

    #[test]
    fn crlf_files_keep_their_line_endings() {
        let b = begin("gemini");
        let user = "Line one\r\nLine two\r\n";
        let (_, text) = written(add(Some(user), None, &b));
        assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
        assert_eq!(add(Some(&text), None, &b).unwrap(), (HookState::Present, None));
        assert_eq!(remove(Some(&text), None).unwrap(), (HookState::Removed, Some(NewText::Write(user.into()))));
    }

    #[test]
    fn a_header_only_file_is_removed() {
        let b = begin("cursor");
        let (_, text) = written(add(None, Some(CURSOR_HEADER), &b));
        assert!(text.starts_with("---\ndescription: Task tracking with bd\nalwaysApply: true\n---\n\n<!-- BEGIN"));
        assert_eq!(remove(Some(&text), Some(CURSOR_HEADER)).unwrap(), (HookState::Removed, Some(NewText::Delete)));
        assert_eq!(remove(Some("# Notes\n"), None).unwrap(), (HookState::Absent, None));
        assert_eq!(remove(None, None).unwrap(), (HookState::Absent, None));
    }

    #[test]
    fn project_root_prefers_the_closest_bd_or_git() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("outer");
        let inner = outer.join(".claude/worktrees/w");
        std::fs::create_dir_all(outer.join(".bd")).unwrap();
        std::fs::create_dir_all(inner.join("src")).unwrap();
        assert_eq!(project_root(&inner.join("src")), Some(outer.clone()));
        std::fs::write(inner.join(".git"), "gitdir: /elsewhere\n").unwrap();
        assert_eq!(project_root(&inner.join("src")), Some(inner.clone()));
        assert_eq!(project_root(&inner), Some(inner.clone()));

        let other = dir.path().join("other");
        std::fs::create_dir_all(other.join(".git")).unwrap();
        std::fs::create_dir_all(other.join("sub/.bd")).unwrap();
        std::fs::create_dir_all(other.join("sub/deep")).unwrap();
        assert_eq!(project_root(&other.join("sub/deep")), Some(other.join("sub")));

        let bare = tempfile::tempdir().unwrap();
        if bare.path().ancestors().all(|d| !d.join(".bd").is_dir() && !d.join(".git").exists()) {
            assert_eq!(project_root(bare.path()), None);
        }
    }

    #[test]
    fn every_target_has_a_recipe_naming_bd_prime() {
        for target in SetupTarget::ALL {
            let r = recipe(target);
            assert_eq!(r.hooks().is_some(), r.kind == Kind::Hooks, "{target:?}");
        }
        assert!(SECTION.contains("`bd prime`"));
    }
}
