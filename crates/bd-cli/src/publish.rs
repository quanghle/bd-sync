//! `bd publish`: the workspace's playbooks and agent sets from a source
//! directory ([`bd_core::publish`]).
//!
//! Locally the source is read, staged, validated and applied in-process. In
//! a remote workspace the client reads the source into a bundle and sends
//! it with the command (named by the hidden `--publish-bundle`), and the
//! server, which never reads a client's paths, does the rest. `--rollback`
//! sends nothing: the server restores what it kept.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bd_core::publish::{
    self, Area, FileChange, GitMode, Node, Options, Prepared, PublishBundle, Source, SourceInfo, Status,
    parse_ls_files, read_tree_with,
};
use bd_core::{Error, Result};
use serde_json::{Value, json};
use similar::{ChangeTag, TextDiff};

use crate::app::App;
use crate::cli::{Command, PublishArgs};
use crate::io;
use crate::protocol::{ExecRequest, ExecResponse};

/// Where a client puts the bundle among a request's files.
const BUNDLE_FILE: &str = "publish.bundle.json";
/// Names the bundle on the command line.
const BUNDLE_FLAG: &str = "--publish-bundle";
/// The default source directory, in the checkout's `.bd`.
const SOURCE_DIR: &str = "source";
/// Most lines of diff shown for one file, and for a whole dry run.
const DIFF_LINES_PER_FILE: usize = 200;
const DIFF_LINES_TOTAL: usize = 2000;
/// Most changed paths named in a server log line.
const LOGGED_PATHS: usize = 20;

pub fn cmd_publish(app: &mut App, a: &PublishArgs) -> Result<i32> {
    let started = Instant::now();
    let result = publish(app, a);
    match &result {
        Ok((prepared, _)) => log_publish(prepared, a, started),
        // Never the message: a loader's error quotes the file's text.
        Err(e) => tracing::info!(
            target: "bd::serve",
            rollback = a.rollback,
            dry_run = a.dry_run,
            exit_code = e.exit_code(),
            code = e.code(),
            file = refused_file(e).as_deref(),
            "publish refused"
        ),
    }
    let (prepared, changed) = result?;
    print_publish(app, &prepared, &changed, a.dry_run);
    Ok(0)
}

/// The file a refusal names (`playbooks/x.toml`, `agents/claude/...`, as
/// its message starts), for a log line that holds nothing of its text.
fn refused_file(e: &Error) -> Option<String> {
    let msg = e.to_string();
    let (file, _) = msg.split_once(": ")?;
    let ours = [publish::PLAYBOOKS_DIR, bd_core::agents::AGENTS_DIR].iter().any(|a| file.starts_with(&format!("{a}/")));
    (ours && file.len() <= publish::MAX_PUBLISH_PATH_BYTES + 64 && !file.contains(char::is_whitespace))
        .then(|| file.to_string())
}

fn publish(app: &mut App, a: &PublishArgs) -> Result<(Prepared, Vec<bd_core::agents::AgentsChanged>)> {
    io::require_admin_human("bd publish")?;
    let db = app.db_path()?;
    let db_dir = db.parent().map(Path::to_path_buf).unwrap_or_default();
    let only = a.only.map(Area::from);
    let source = if a.rollback {
        Source::Rollback { only }
    } else {
        let bundle = match &app.g.publish_bundle {
            Some(file) => PublishBundle::from_json(&io::read_file(file)?)?,
            // A server never reads a client's paths: the client sends its source.
            None if io::serving() => {
                return Err(Error::invalid("bd serve publishes only the source a bd client sends with the command"));
            }
            None => build_bundle(app, a)?,
        };
        if let Some(o) = only
            && bundle.areas != [o]
        {
            return Err(Error::invalid(format!("--only {o}: the bundle publishes other areas too")));
        }
        Source::Bundle(bundle)
    };
    if !io::serving() && db_dir.file_name().is_some_and(|n| n == ".bd") {
        // What a publish keeps next to a local workspace is local state.
        crate::commands::ignore_publish(&db_dir)?;
    }
    let opts = Options { wait: Duration::from_millis(app.g.busy_timeout_ms), allow_empty: a.allow_empty };
    // Staged and validated under the publish lock, which `prepared` holds until it is dropped.
    let mut prepared = publish::prepare(&db_dir, source, &opts)?;
    if a.dry_run {
        return Ok((prepared, Vec::new()));
    }
    prepared.apply()?;
    // Under the publish lock still, so events follow the order publishes were applied in.
    let changed = app.write("publish", |tx| prepared.record(tx))?;
    prepared.finish();
    Ok((prepared, changed))
}

fn log_publish(p: &Prepared, a: &PublishArgs, started: Instant) {
    let counts = |area: Area| {
        p.plans
            .iter()
            .find(|plan| plan.area == area)
            .map(|plan| format!("+{} ~{} -{} ={}", plan.added, plan.changed, plan.removed, plan.unchanged))
    };
    let mut paths: Vec<String> = p
        .plans
        .iter()
        .flat_map(|plan| plan.files.iter())
        .filter(|f| f.status != Status::Unchanged)
        .map(|f| {
            let hash = match &f.new {
                Some(Node::File { sha256, .. }) => format!(" {}", &sha256[..12]),
                _ => String::new(),
            };
            format!("{} {}/{}{hash}", sign(f.status), f.area, f.path)
        })
        .collect();
    let more = paths.len().saturating_sub(LOGGED_PATHS);
    paths.truncate(LOGGED_PATHS);
    if more > 0 {
        paths.push(format!("... {more} more"));
    }
    let revisions: Vec<String> = p.revisions.iter().map(|(h, r)| format!("{h}:{}", &r[..12])).collect();
    tracing::info!(
        target: "bd::serve",
        rollback = a.rollback,
        dry_run = a.dry_run,
        playbooks = counts(Area::Playbooks).as_deref(),
        agents = counts(Area::Agents).as_deref(),
        commit = p.source.commit.as_deref(),
        dirty = p.source.dirty,
        revisions = %revisions.join(","),
        changed = %paths.join(", "),
        swept = p.swept,
        ms = started.elapsed().as_millis() as u64,
        "published"
    );
}

/// The source directory: `--from` (relative to the working directory), else
/// `.bd/source` in the checkout.
fn source_dir(app: &App, a: &PublishArgs) -> Result<PathBuf> {
    let dir = match &a.from {
        Some(dir) if dir.is_relative() => app.cwd.join(dir),
        Some(dir) => dir.clone(),
        None => match crate::playbooks::checkout_bd(app)? {
            Some(bd) => bd.join(SOURCE_DIR),
            None => return Err(Error::NoWorkspace("no .bd directory here or above to publish from".into())),
        },
    };
    if !dir.is_dir() {
        return Err(Error::invalid(format!(
            "{}: no publish source here (it holds playbooks/ and agents/<harness>/; name another with --from)",
            dir.display()
        )));
    }
    Ok(dir)
}

/// Read the source directory into a bundle, with its git revision when it is in a repository.
fn build_bundle(app: &App, a: &PublishArgs) -> Result<PublishBundle> {
    let dir = source_dir(app, a)?;
    let areas = match a.only {
        Some(o) => vec![Area::from(o)],
        None => Area::ALL.to_vec(),
    };
    // Where the file system keeps no executable bits or symlinks, an agent set's come from git.
    let sets = dir.join(bd_core::agents::AGENTS_DIR);
    let from_git = areas.contains(&Area::Agents)
        && has_sets(&sets)
        && modes_from_git(cfg!(unix), git_ignores_modes(&dir), keeps_no_modes(&sets));
    let modes = if from_git { Some(git_modes(&dir)?) } else { None };
    let mut bundle = read_tree_with(&dir, &areas, modes.as_ref())?;
    bundle.source = git_source(&dir);
    Ok(bundle)
}

/// Whether the source's `agents/` holds any entry a publish reads (hidden ones are left out).
fn has_sets(sets: &Path) -> bool {
    std::fs::read_dir(sets).is_ok_and(|d| d.flatten().any(|e| !e.file_name().to_string_lossy().starts_with('.')))
}

/// Whether the agent sets' executable bits and symlinks come from git
/// rather than the file system: always off Unix (`unix`), which keeps none;
/// on Unix when the checkout tells git not to trust file modes
/// (`git_ignores_modes`: `core.filemode` false, as git sets it on a file
/// system that keeps none), or the file system reports every file of the
/// sets as mode 0777 (`all_0777`: WSL's DrvFs under `/mnt/<drive>`).
fn modes_from_git(unix: bool, git_ignores_modes: bool, all_0777: bool) -> bool {
    !unix || git_ignores_modes || all_0777
}

/// Whether the git checkout holding `dir` has `core.filemode` set to false.
fn git_ignores_modes(dir: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--get", "core.filemode"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "false")
}

/// Whether every regular file under `dir` (at least one; symlinks not
/// followed, hidden entries left out) has mode 0777: a file system that
/// keeps no modes and reports that for all.
#[cfg(unix)]
fn keeps_no_modes(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let (mut stack, mut files, mut seen) = (vec![dir.to_path_buf()], 0, 0);
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { return false };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 4 * publish::MAX_PUBLISH_FILES || entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { return false };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                if meta.permissions().mode() & 0o777 != 0o777 {
                    return false;
                }
                files += 1;
            }
        }
    }
    files > 0
}

#[cfg(not(unix))]
fn keeps_no_modes(_: &Path) -> bool {
    false
}

/// What git records of the agent sets in the source `dir` (`git ls-files -s`).
fn git_modes(dir: &Path) -> Result<BTreeMap<String, GitMode>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "-s", "-z", "--", bd_core::agents::AGENTS_DIR])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success());
    match out {
        Some(o) => Ok(parse_ls_files(&String::from_utf8_lossy(&o.stdout))),
        None => Err(Error::invalid(format!(
            "{}: this file system keeps no executable bits or symlinks, so bd publish takes those of the agent sets \
             from git, and git cannot tell here (not a git checkout?): publish the agent sets from a git checkout, \
             or from Linux or macOS, or publish playbooks alone with --only playbooks",
            dir.display()
        ))),
    }
}

/// The commit checked out where `dir` is, and whether `dir` has uncommitted
/// changes; nothing when git cannot tell.
fn git_source(dir: &Path) -> SourceInfo {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let commit = git(&["rev-parse", "HEAD"]).map(|s| s.trim().to_string()).filter(|c| {
        !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    });
    let dirty = commit.as_ref().and_then(|_| git(&["status", "--porcelain", "--", "."])).map(|s| !s.trim().is_empty());
    SourceInfo { commit, dirty }
}

/// In a remote workspace: read the source and send it with the command.
pub fn attach_bundle(app: &App, cmd: &Command, request: &mut ExecRequest) -> Result<()> {
    let Command::Publish(a) = cmd else { return Ok(()) };
    if a.rollback {
        return Ok(());
    }
    if let Some(file) = &app.g.publish_bundle {
        // A bundle named on the command line travels like any input file.
        request.files.insert(file.to_string_lossy().into_owned(), io::read_file(file)?);
        return Ok(());
    }
    let bundle = build_bundle(app, a)?.to_json()?;
    request.files.insert(BUNDLE_FILE.to_string(), bundle);
    request.argv.splice(0..0, [BUNDLE_FLAG.to_string(), BUNDLE_FILE.to_string()]);
    Ok(())
}

/// A server older than `bd publish` refuses its arguments: say so plainly.
pub fn from_older_server(mut response: ExecResponse, json: bool) -> ExecResponse {
    let refused_args =
        response.stderr.contains("unexpected argument") || response.stderr.contains("unrecognized subcommand");
    let ours = response.stderr.contains(BUNDLE_FLAG) || response.stderr.contains("'publish'");
    if response.exit_code == 2 && refused_args && ours {
        let e = Error::invalid(format!(
            "the bd server does not know bd publish: upgrade the bd server to bd {} or later",
            env!("CARGO_PKG_VERSION")
        ));
        response.stderr = crate::render_error(&e, json, None);
    }
    response
}

fn sign(status: Status) -> char {
    match status {
        Status::Added => '+',
        Status::Changed => '~',
        Status::Removed => '-',
        Status::Unchanged => '=',
    }
}

/// The node as JSON fields: `sha256` and `executable`, or `symlink`.
fn node_json(node: &Option<Node>) -> Value {
    match node {
        Some(Node::File { sha256, executable }) => json!({ "sha256": sha256, "executable": executable }),
        Some(Node::Symlink { target }) => json!({ "symlink": target }),
        Some(Node::Dir) => json!({ "directory": true }),
        Some(Node::Other) => json!({ "other": true }),
        None => Value::Null,
    }
}

/// A unified diff of `old` and `new`, by line, with three lines of context,
/// at most `limit` lines.
fn diff_lines(old: &str, new: &str, limit: usize) -> Vec<String> {
    let diff = TextDiff::configure().timeout(Duration::from_secs(2)).diff_lines(old, new);
    let mut out = Vec::new();
    for group in diff.grouped_ops(3) {
        let (first, last) = (&group[0], &group[group.len() - 1]);
        let (o, n) = (first.old_range().start..last.old_range().end, first.new_range().start..last.new_range().end);
        out.push(format!("@@ -{},{} +{},{} @@", o.start + 1, o.len(), n.start + 1, n.len()));
        for op in &group {
            for change in diff.iter_changes(op) {
                let sign = match change.tag() {
                    ChangeTag::Equal => ' ',
                    ChangeTag::Delete => '-',
                    ChangeTag::Insert => '+',
                };
                let line = change.value();
                out.push(format!("{sign}{}", line.strip_suffix('\n').unwrap_or(line)));
            }
        }
        if out.len() > limit {
            out.truncate(limit);
            out.push("... (diff cut short)".into());
            break;
        }
    }
    out
}

/// The diff of a changed or added text file, if both sides are text.
fn file_diff(p: &Prepared, f: &FileChange, limit: usize) -> Option<Vec<String>> {
    if !matches!(f.status, Status::Changed | Status::Added) || limit == 0 {
        return None;
    }
    let (old, new) = p.texts(f);
    let new = new?;
    let old = match (&f.old, old) {
        (None, _) => String::new(),
        (Some(_), Some(old)) => old,
        (Some(_), None) => return None,
    };
    if old == new {
        return None;
    }
    Some(diff_lines(&old, &new, limit))
}

fn print_publish(app: &App, p: &Prepared, changed: &[bd_core::agents::AgentsChanged], dry_run: bool) {
    let mut budget = DIFF_LINES_TOTAL;
    let mut areas = Vec::new();
    let mut text = vec![match (dry_run, p.rollback) {
        (true, false) => "Dry run: bd publish would change (nothing was changed):".to_string(),
        (true, true) => "Dry run: bd publish --rollback would change (nothing was changed):".to_string(),
        (false, false) => "Published:".to_string(),
        (false, true) => "Rolled back to the previous publish:".to_string(),
    }];
    for plan in &p.plans {
        text.push(format!(
            "  {}: {} added, {} changed, {} removed, {} unchanged",
            plan.area, plan.added, plan.changed, plan.removed, plan.unchanged
        ));
        let mut files = Vec::new();
        for f in &plan.files {
            let mut entry = json!({ "path": f.path, "status": f.status });
            if let Some(node) = node_json(&f.new).as_object() {
                entry.as_object_mut().unwrap().extend(node.clone());
            }
            if f.old.is_some() && f.status != Status::Unchanged {
                entry["old"] = node_json(&f.old);
            }
            if f.status != Status::Unchanged {
                let kind = match &f.new {
                    Some(Node::Symlink { target }) => format!(" -> {target}"),
                    _ => String::new(),
                };
                text.push(format!("    {} {}/{}{kind}", sign(f.status), plan.area, f.path));
            }
            if dry_run && let Some(lines) = file_diff(p, f, budget.min(DIFF_LINES_PER_FILE)) {
                budget = budget.saturating_sub(lines.len());
                text.extend(lines.iter().map(|l| format!("      {l}")));
                entry["diff"] = json!(lines.join("\n"));
            }
            files.push(entry);
        }
        areas.push(json!({
            "area": plan.area,
            "added": plan.added,
            "changed": plan.changed,
            "removed": plan.removed,
            "unchanged": plan.unchanged,
            "files": files,
        }));
    }
    let mut revisions = serde_json::Map::new();
    for (h, r) in &p.revisions {
        let previous = p.previous.get(h);
        revisions.insert(h.to_string(), json!({ "revision": r, "previous": previous }));
        if previous != Some(r) {
            let was = previous.map_or_else(|| "unreadable".to_string(), |r| r[..12].to_string());
            text.push(format!("  agents/{h}: revision {} (was {was})", &r[..12]));
        }
    }
    if !dry_run && p.publishes(Area::Agents) {
        text.push("  Clients pick the sets up at their next `bd agents pull`; new or changed skills and MCP definitions wait for `bd agents approve` there.".into());
    }
    let v = json!({
        "dry_run": dry_run,
        "rollback": p.rollback,
        "source": p.source,
        "areas": areas,
        "revisions": revisions,
        "agents_changed": changed,
    });
    let mut out = crate::app::Out::new(v);
    for line in text {
        out = out.line(line);
    }
    app.print(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_come_from_git_where_the_file_system_keeps_none() {
        assert!(!modes_from_git(true, false, false), "Unix with real modes: the file system");
        assert!(modes_from_git(false, false, false), "Windows");
        assert!(modes_from_git(true, true, false), "core.filemode false");
        assert!(modes_from_git(true, false, true), "every file 0777 (WSL DrvFs)");

        let tmp = tempfile::tempdir().unwrap();
        let sets = tmp.path().join("agents");
        assert!(!has_sets(&sets) && !keeps_no_modes(&sets), "no agents/");
        std::fs::create_dir_all(&sets).unwrap();
        std::fs::write(sets.join(".gitkeep"), "").unwrap();
        assert!(!has_sets(&sets), "hidden entries only");
        std::fs::create_dir_all(sets.join("claude/skills/deploy")).unwrap();
        assert!(has_sets(&sets));
        assert!(!keeps_no_modes(&sets), "no file to tell");
        let (a, b) = (sets.join("claude/skills/deploy/SKILL.md"), sets.join("claude/skills/deploy/run.sh"));
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
            mode(&a, 0o644);
            mode(&b, 0o755);
            assert!(!keeps_no_modes(&sets), "real modes");
            mode(&a, 0o777);
            mode(&b, 0o777);
            assert!(keeps_no_modes(&sets), "all 0777");
        }
    }

    #[test]
    fn a_checkout_with_core_filemode_false_takes_modes_from_git() {
        let tmp = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| std::process::Command::new("git").arg("-C").arg(tmp.path()).args(args).output();
        if !git(&["init", "-q"]).is_ok_and(|o| o.status.success()) {
            return;
        }
        git(&["config", "core.filemode", "true"]).unwrap();
        assert!(!git_ignores_modes(tmp.path()));
        git(&["config", "core.filemode", "false"]).unwrap();
        assert!(git_ignores_modes(tmp.path()));
        assert!(!git_ignores_modes(&tmp.path().join("nowhere")), "not a checkout");
    }

    #[test]
    fn an_older_server_refusing_the_flag_is_named() {
        let clap = |stderr: &str| ExecResponse { exit_code: 2, stderr: stderr.into(), ..Default::default() };
        for stderr in [
            "error: unexpected argument '--publish-bundle' found\n\nUsage: bd [OPTIONS] <COMMAND>\n",
            "error: unrecognized subcommand 'publish'\n\nUsage: bd [OPTIONS] <COMMAND>\n",
        ] {
            let out = from_older_server(clap(stderr), false);
            assert!(out.stderr.starts_with("error: the bd server does not know bd publish: upgrade"), "{}", out.stderr);
            let json: Value = serde_json::from_str(&from_older_server(clap(stderr), true).stderr).unwrap();
            assert_eq!(json["error"]["exit_code"], 2);
        }
        // Other refusals are left as they are.
        let other = from_older_server(clap("error: publish refused: playbooks/x.toml: ...\n"), false);
        assert!(other.stderr.contains("playbooks/x.toml"));
    }

    #[test]
    fn diffs_are_unified_and_bounded() {
        let lines = diff_lines("a\nb\nc\n", "a\nB\nc\n", 100);
        assert_eq!(lines, ["@@ -1,3 +1,3 @@", " a", "-b", "+B", " c"]);
        let old: String = (0..1000).map(|i| format!("{i}\n")).collect();
        let new: String = (0..1000).map(|i| format!("{}\n", i * 2)).collect();
        let cut = diff_lines(&old, &new, 50);
        assert_eq!(cut.len(), 51);
        assert_eq!(cut.last().unwrap(), "... (diff cut short)");
    }
}
