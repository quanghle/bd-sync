//! `bd edit`: one field of an issue in an external editor, written back
//! conditionally on the revision read before editing.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use bd_core::{Error, Guard, IssuePatch, Queries, Result};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::{io, tokens};

fn field_name(f: EditField) -> &'static str {
    match f {
        EditField::Title => "title",
        EditField::Description => "description",
        EditField::Design => "design",
        EditField::Acceptance => "acceptance",
        EditField::Notes => "notes",
    }
}

/// The editor command: `$VISUAL`, else `$EDITOR` (empty values ignored),
/// else `vi` (`notepad` on Windows). `env` reads an environment variable.
fn editor_command(env: &dyn Fn(&str) -> Option<String>) -> String {
    ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|name| env(name))
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| if cfg!(windows) { "notepad" } else { "vi" }.to_string())
}

/// Text as compared before and after editing: Unix line ends, no trailing
/// line ends (editors add one).
fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").trim_end_matches('\n').to_string()
}

/// Create the temporary file holding `text`, readable by its owner only.
fn create_temp(id: &str, field: &str, text: &str) -> Result<PathBuf> {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!("bd-edit-{id}-{field}-{}.md", tokens::random_hex(6)?));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&path)?;
    let mut body = text.to_string();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    file.write_all(body.as_bytes())?;
    Ok(path)
}

/// Keeps bd alive through the terminal's interrupts while held. The terminal
/// sends Ctrl-C to the whole foreground group, and editors use it (vi leaves
/// insert mode with it): if bd died, the editor would keep the terminal and
/// the edited text would go nowhere. A caught signal is reset to its default
/// by exec, so the editor keeps its own handling. The signals are never read,
/// only absorbed.
///
/// Dropping it does not give the signals back their default handling: tokio
/// (signal-hook-registry) never unregisters its process-wide handler, so the
/// rest of the process goes on ignoring Ctrl-C and Ctrl-\. That is why only
/// `bd edit` absorbs, and only around the editor: what follows it is short (read
/// the file, one write transaction, print) and the process then exits. Nothing
/// long-running may follow an edit in the same process.
struct Absorbing {
    _runtime: tokio::runtime::Runtime,
    #[cfg(unix)]
    _signals: (tokio::signal::unix::Signal, tokio::signal::unix::Signal),
    #[cfg(windows)]
    _signals: tokio::signal::windows::CtrlC,
}

/// Start absorbing interrupts; `None` if that fails, and the edit goes on
/// without it.
fn absorb_interrupts() -> Option<Absorbing> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().ok()?;
    let _context = runtime.enter();
    #[cfg(unix)]
    let signals = {
        use tokio::signal::unix::{SignalKind, signal};
        (signal(SignalKind::interrupt()).ok()?, signal(SignalKind::quit()).ok()?)
    };
    #[cfg(windows)]
    let signals = tokio::signal::windows::ctrl_c().ok()?;
    drop(_context);
    Some(Absorbing { _runtime: runtime, _signals: signals })
}

/// Run `editor` on `path` with the terminal's stdio.
fn run_editor(editor: &str, path: &Path) -> Result<()> {
    let mut cmd;
    #[cfg(unix)]
    {
        // Through the shell, as git does, so a value like `code --wait` works.
        // A Ctrl-C reaches the shell too; one that waits on the editor (dash
        // does, bash execs it) must outlive it. A trap, not an ignored
        // signal, so the editor starts with Ctrl-C's default again.
        cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(format!("trap : INT; {editor} \"$@\"")).arg(editor).arg(path);
    }
    #[cfg(windows)]
    {
        // A path to a program can hold spaces and backslashes: not split.
        if Path::new(editor).is_file() {
            cmd = std::process::Command::new(editor);
        } else {
            let words = shlex::split(editor)
                .filter(|w| !w.is_empty())
                .ok_or_else(|| Error::invalid(format!("cannot parse the editor command {editor:?}")))?;
            cmd = std::process::Command::new(&words[0]);
            cmd.args(&words[1..]);
        }
        cmd.arg(path);
    }
    // Registered before the spawn, so no Ctrl-C finds bd without a handler;
    // the handler outlives this (see `Absorbing`).
    let _absorbing = absorb_interrupts();
    let status = cmd
        .spawn()
        .and_then(|mut child| child.wait())
        .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("cannot run editor `{editor}`: {e}"))))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::other(format!("editor `{editor}` exited with {status}; nothing changed"))))
    }
}

pub fn cmd_edit(app: &mut App, a: &EditArgs) -> Result<()> {
    io::require_local("bd edit")?;
    let field = field_name(a.field);
    if !std::io::stdin().is_terminal() {
        return Err(Error::Refused(format!(
            "bd edit opens an editor and runs only in a terminal (stdin is not one); use `bd update {} --{field} ...`",
            a.id
        )));
    }
    let (id, issue) = app.read(|r| {
        let id = r.resolve_id(&a.id)?;
        let issue = r.issue(&id)?;
        Ok((id, issue))
    })?;
    let rev = issue.revision;
    let original = match a.field {
        EditField::Title => issue.title.clone(),
        EditField::Description => issue.description.clone(),
        EditField::Design => issue.design.clone(),
        EditField::Acceptance => issue.acceptance_criteria.clone(),
        EditField::Notes => issue.notes.clone(),
    };

    let editor = editor_command(&|name| std::env::var(name).ok());
    let path = create_temp(&id, field, &original)?;
    if let Err(e) = run_editor(&editor, &path) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    let edited = match std::fs::read(&path).map_err(Error::from).and_then(|b| {
        String::from_utf8(b).map_err(|_| Error::invalid("the edited file is not valid UTF-8".to_string()))
    }) {
        Ok(text) => text,
        Err(e) => return Err(keep(&path, e)),
    };

    let mut text = normalize(&edited);
    let mut before = normalize(&original);
    if a.field == EditField::Title {
        text = text.trim().to_string();
        before = before.trim().to_string();
    }
    if text == before {
        let _ = std::fs::remove_file(&path);
        let out = Out::new(json!({ "id": id, "field": field, "changed": false, "revision": rev }))
            .line(format!("= {id} {field} unchanged (revision {rev})"))
            .id(id.clone());
        app.print(out);
        return Ok(());
    }
    if a.field == EditField::Title && (text.is_empty() || text.contains('\n')) {
        return Err(keep(&path, Error::invalid("a title must be one non-empty line")));
    }

    let mut patch = IssuePatch::default();
    match a.field {
        EditField::Title => patch.title = Some(text),
        EditField::Description => patch.description = Some(text),
        EditField::Design => patch.design = Some(text),
        EditField::Acceptance => patch.acceptance_criteria = Some(text),
        EditField::Notes => patch.notes = Some(text),
    }
    let guard = Guard { if_revision: Some(rev), ..Guard::default() };
    let out = match app.write("edit", |tx| tx.update_issue(&id, &patch, &guard, false)) {
        Ok(out) => out,
        Err(e) => return Err(keep(&path, e)),
    };
    let _ = std::fs::remove_file(&path);
    let line = if out.changed.is_empty() {
        format!("= {id} {field} unchanged (revision {})", out.issue.revision)
    } else {
        format!("✓ Updated {id}: {} (revision {})", out.changed.join(", "), out.issue.revision)
    };
    app.print(Out::new(&out).line(line).id(id));
    Ok(())
}

/// Tell where the edited text stays, and pass `e` on.
fn keep(path: &Path, e: Error) -> Error {
    io::errln(format!("bd edit: the edited text is kept in {}", path.display()));
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
    }

    #[test]
    fn the_editor_is_visual_then_editor_then_the_platform_default() {
        let default = if cfg!(windows) { "notepad" } else { "vi" };
        assert_eq!(editor_command(&env(&[("VISUAL", "code --wait"), ("EDITOR", "nano")])), "code --wait");
        assert_eq!(editor_command(&env(&[("EDITOR", "nano")])), "nano");
        assert_eq!(editor_command(&env(&[])), default);
        // Empty and blank values are ignored.
        assert_eq!(editor_command(&env(&[("VISUAL", ""), ("EDITOR", "nano")])), "nano");
        assert_eq!(editor_command(&env(&[("VISUAL", "  "), ("EDITOR", " ")])), default);
    }

    #[test]
    fn text_is_compared_without_editor_line_ends() {
        assert_eq!(normalize("a\r\nb\r\n"), "a\nb");
        assert_eq!(normalize("a\n\n\n"), "a");
        assert_eq!(normalize("a\n b "), "a\n b ");
        assert_eq!(normalize("\n"), "");
    }
}
