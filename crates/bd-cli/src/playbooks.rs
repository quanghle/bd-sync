//! `bd playbook ...` and `bd purge`.
//!
//! In a remote workspace a name is looked up in the checkout's
//! `.bd/playbooks` first, then on the server's playbook path, then in the
//! client's `$BD_PLAYBOOK_PATH` and user config directory; file paths are the
//! client's. `show`, `plan` and `run` of a playbook found on the client send
//! its files with the command (a bundle, named by `--playbook-bundle`), and
//! the server loads it from the bundle alone. `list` shows all of them, and
//! `extract --save` writes into the checkout.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bd_core::playbook::{
    self, Bundle, CompactOptions, DiscardOptions, Listed, Loader, MAX_BUNDLE_FILE_BYTES, Playbook, RunRequest,
    RunStatus, RunsQuery, StartOptions, Step, StepState,
};
use bd_core::time::parse_duration;
use bd_core::{Error, Queries, Result};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::rel;
use crate::io;
use crate::paths::user_config_dir;
use crate::protocol::{ErrorBody, ExecRequest, ExecResponse};
use crate::remote::{self, Remote};

/// Where playbooks are looked up, in order: the workspace's `.bd/playbooks`,
/// `$BD_PLAYBOOK_PATH`, then `$XDG_CONFIG_HOME/bd/playbooks` (or
/// `~/.config/bd/playbooks`; `%APPDATA%\bd\playbooks` on Windows).
pub fn search_paths(app: &App) -> Vec<PathBuf> {
    match app.db_path() {
        Ok(db) => with_user_paths(db.parent().map(|d| d.join("playbooks"))),
        Err(_) => with_user_paths(Some(app.cwd.join(".bd").join("playbooks"))),
    }
}

/// `first`, then `$BD_PLAYBOOK_PATH` and the user config directory.
fn with_user_paths(first: Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = first.into_iter().collect();
    if let Some(extra) = std::env::var_os("BD_PLAYBOOK_PATH") {
        paths.extend(std::env::split_paths(&extra).filter(|p| !p.as_os_str().is_empty()));
    }
    if let Some(c) = user_config_dir() {
        paths.push(c.join("bd").join("playbooks"));
    }
    paths
}

/// The playbooks a command naming `reference` reads: the bundle named by
/// `--playbook-bundle` (sent by a remote client; under bd serve it is never
/// read from disk), or the search path.
fn loader(app: &App, reference: &str) -> Result<Loader> {
    let Some(file) = &app.g.playbook_bundle else { return Ok(Loader::new(search_paths(app))) };
    let bundle = Bundle::from_json(&io::read_file(file)?)?;
    // A playbook from the client's own path gives way to the workspace's of
    // the same name. Names only: a path a client names is never looked up here.
    if bundle.server_first && !playbook::is_path_like(reference.trim()) {
        let own = Loader::new(search_paths(app));
        if own.locate(reference, None).is_ok() {
            return Ok(own);
        }
    }
    Loader::from_bundle(bundle)
}

/// Under bd serve without a bundle, playbooks come from the server's own playbook path.
fn on_server(loader: &Loader) -> bool {
    io::serving() && !loader.is_bundle()
}

fn load(app: &App, loader: &Loader, reference: &str) -> Result<Playbook> {
    let r = reference.trim();
    let on_server = on_server(loader);
    if on_server && playbook::is_path_like(r) {
        // A path would name a file on the server, not the client's.
        return Err(Error::Refused(format!(
            "playbook {r:?}: bd serve runs playbooks by name from the workspace's playbook directory on the server \
             (a bd client sends the playbooks of its checkout with the command)"
        )));
    }
    loader.load_from(reference, Some(&app.cwd)).map_err(|e| match e {
        Error::NotFound { kind, id } if on_server => {
            Error::NotFound { kind, id: format!("{id} on the bd server (bd clients look in their checkout first)") }
        }
        e => e,
    })
}

fn parse_vars(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut vars = BTreeMap::new();
    for v in raw {
        let (k, val) =
            v.split_once('=').ok_or_else(|| Error::invalid(format!("--var expects NAME=VALUE, got {v:?}")))?;
        let k = k.trim();
        if vars.insert(k.to_string(), val.to_string()).is_some() {
            return Err(Error::invalid(format!("--var {k} given twice")));
        }
    }
    Ok(vars)
}

pub fn cmd_playbook(app: &mut App, cmd: &PlaybookCommand) -> Result<()> {
    match cmd {
        PlaybookCommand::List => cmd_list(app),
        PlaybookCommand::Show(a) => cmd_show(app, a),
        PlaybookCommand::Plan(a) => cmd_run(app, a, true),
        PlaybookCommand::Run(a) => cmd_run(app, a, a.dry_run),
        PlaybookCommand::Status(a) => cmd_status(app, a),
        PlaybookCommand::Runs(a) => cmd_runs(app, a),
        PlaybookCommand::Compact(a) => cmd_compact(app, a),
        PlaybookCommand::Discard(a) => cmd_discard(app, a),
        PlaybookCommand::Extract(a) => cmd_extract(app, a),
    }
}

fn cmd_list(app: &mut App) -> Result<()> {
    let loader = Loader::new(search_paths(app));
    let listed = loader.list();
    let json = json!({ "search_paths": loader.search_paths, "playbooks": listed });
    let entries: Vec<(Listed, bool)> = listed.into_iter().map(|l| (l, false)).collect();
    let searched: Vec<(PathBuf, bool)> = loader.search_paths.iter().map(|p| (p.clone(), false)).collect();
    app.print(list_out(json, &entries, &searched));
    Ok(())
}

/// What `bd playbook list` prints. Entries and searched directories marked
/// `true` are on the server.
fn list_out(json: Value, entries: &[(Listed, bool)], searched: &[(PathBuf, bool)]) -> Out {
    let mut out = Out::new(json);
    if entries.is_empty() {
        out = out.line("No playbooks found. Searched:");
        for (p, on_server) in searched {
            out = out.line(format!("  {}{}", p.display(), if *on_server { " (on the server)" } else { "" }));
        }
        out = out.line("Create one at .bd/playbooks/<name>.toml (see `bd playbook show <file>` to validate it).");
    }
    for (l, on_server) in entries {
        let place = if *on_server { " (on the server)" } else { "" };
        let mut line = format!("{:<20} {}{place}", l.name, l.path.display());
        if let Some(e) = &l.error {
            line = format!("✗ {line}\n    {}", e.replace('\n', "\n    "));
        } else {
            let vars = if l.vars.is_empty() { String::new() } else { format!("  vars: {}", l.vars.join(" ")) };
            let eph = if l.ephemeral { "  (ephemeral)" } else { "" };
            line = format!(
                "• {line}\n    {} step(s){vars}{eph}{}",
                l.steps,
                if l.description.is_empty() { String::new() } else { format!(" — {}", l.description) }
            );
        }
        if let Some(by) = &l.shadowed_by {
            line.push_str(&format!("\n    shadowed by {}", by.display()));
        }
        out = out.line(line).id(l.name.clone());
    }
    out
}

fn step_lines(steps: &[Arc<Step>], depth: usize, out: &mut Vec<String>) {
    for s in steps {
        let mut notes = Vec::new();
        if !s.needs.is_empty() {
            notes.push(format!("needs {}", s.needs.join(", ")));
        }
        if let Some(w) = &s.waits_for {
            notes.push(format!("waits for {}", w.as_spec()));
        }
        if let Some(c) = &s.condition {
            notes.push(format!("if {c}"));
        }
        if let Some(l) = &s.repeat {
            let over = match &l.over {
                playbook::LoopOver::Count(c) => format!("count {c}"),
                playbook::LoopOver::Range(r) => format!("range {r}"),
                playbook::LoopOver::Items(i) => format!("items {}", i.join(", ")),
                playbook::LoopOver::Over(o) => format!("over {o}"),
            };
            notes.push(format!("loop {} = {over}{}", l.var, if l.sequential { ", one at a time" } else { "" }));
        }
        if let Some(e) = &s.expand {
            notes.push(format!("expands {e}"));
        }
        if let Some(g) = &s.gate {
            let mut gate = format!("gate {}", g.kind);
            if let Some(a) = &g.await_id {
                gate.push_str(&format!(" {a}"));
            }
            if let Some(b) = &g.branch {
                gate.push_str(&format!(" on {b}"));
            }
            if let Some(e) = &g.event {
                gate.push_str(&format!(" for {e}"));
            }
            if let Some(t) = &g.timeout {
                gate.push_str(&format!(" ({t})"));
            }
            notes.push(gate);
        }
        let kind = match &s.issue_type {
            Some(t) => format!(" [{t}]"),
            None if s.is_group() => " [group]".into(),
            None => String::new(),
        };
        let notes = if notes.is_empty() { String::new() } else { format!("  · {}", notes.join(" · ")) };
        out.push(format!("{}{}{kind} — {}{notes}", "  ".repeat(depth + 1), s.id, s.title));
        step_lines(&s.children, depth + 1, out);
    }
}

fn cmd_show(app: &mut App, a: &PlaybookRefArgs) -> Result<()> {
    let loader = loader(app, &a.playbook)?;
    let pb = load(app, &loader, &a.playbook)?;
    let server = on_server(&loader);
    let mut text = vec![format!(
        "{}{}{}",
        pb.name,
        if pb.description.is_empty() { String::new() } else { format!(" — {}", pb.description) },
        pb.source
            .as_ref()
            .map(|p| format!("  ({}{})", p.display(), if server { " on the server" } else { "" }))
            .unwrap_or_default()
    )];
    let mut facts = Vec::new();
    if pb.is_ephemeral() {
        facts.push("ephemeral runs".to_string());
    }
    if !pb.extends.is_empty() {
        facts.push(format!("extends {}", pb.extends.join(", ")));
    }
    if let Some(t) = &pb.title {
        facts.push(format!("run title \"{t}\""));
    }
    if !facts.is_empty() {
        text.push(format!("  {}", facts.join(" · ")));
    }
    if !pb.vars.is_empty() {
        text.push("Vars:".into());
        for (k, v) in &pb.vars {
            let mut d = Vec::new();
            if v.required {
                d.push("required".to_string());
            }
            if let Some(def) = &v.default {
                d.push(format!("default {def:?}"));
            }
            if !v.choices.is_empty() {
                d.push(format!("one of {}", v.choices.join(", ")));
            }
            if let Some(p) = &v.pattern {
                d.push(format!("matches {p}"));
            }
            if v.kind != playbook::VarKind::String {
                d.push(format!("{:?}", v.kind).to_lowercase());
            }
            let desc = if v.description.is_empty() { String::new() } else { format!(" — {}", v.description) };
            text.push(format!("  {k} ({}){desc}", d.join(", ")));
        }
    }
    text.push("Steps:".into());
    step_lines(&pb.steps, 0, &mut text);
    let mut json = json!({ "source": pb.source, "playbook": pb });
    if server {
        json["server"] = json!(true);
    }
    let out = Out::new(json).lines(text).id(pb.name.clone());
    app.print(out);
    Ok(())
}

fn status_lines(s: &RunStatus) -> Vec<String> {
    let p = &s.progress;
    let mut parts = vec![format!("{}/{} done", p.done, p.total)];
    for (n, what) in [(p.failed, "failed"), (p.active, "active"), (p.ready, "ready"), (p.blocked, "blocked")] {
        if n > 0 {
            parts.push(format!("{n} {what}"));
        }
    }
    if p.gates_open > 0 {
        parts.push(format!(
            "{} gate(s) shut{}",
            p.gates_open,
            if p.escalated > 0 { format!(", {} escalated", p.escalated) } else { String::new() }
        ));
    }
    let run = &s.run;
    let head_state = match (run.status, run.close_outcome) {
        (bd_core::Status::Closed, Some(bd_core::Outcome::Failed)) => "✗",
        (bd_core::Status::Closed, _) => "✓",
        _ => "▸",
    };
    let mut lines = vec![format!(
        "{head_state} {} {}{} · {}",
        run.id,
        run.title,
        s.playbook.as_ref().map(|p| format!(" · playbook {p}")).unwrap_or_default(),
        parts.join(", ")
    )];
    let width = s.nodes.iter().map(|n| n.id.len() + 2 * n.depth).max().unwrap_or(0);
    for n in &s.nodes {
        let indent = "  ".repeat(n.depth);
        let pad = width.saturating_sub(n.id.len() + 2 * n.depth);
        let mut line = format!("{indent}{} {}{} {}", n.state.icon(), n.id, " ".repeat(pad), n.title);
        let mut detail = Vec::new();
        if let Some(a) = n.assignee.as_ref().filter(|_| n.state != StepState::Active) {
            detail.push(format!("@{a}"));
        }
        if let Some(d) = &n.detail {
            detail.push(d.clone());
        }
        let state = serde_json::to_value(n.state).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        line.push_str(&format!("  [{state}]"));
        if !detail.is_empty() {
            line.push_str(&format!(" {}", detail.join(" · ")));
        }
        lines.push(line);
    }
    lines
}

fn cmd_run(app: &mut App, a: &RunArgs, dry_run: bool) -> Result<()> {
    let loader = loader(app, &a.playbook)?;
    let pb = load(app, &loader, &a.playbook)?;
    let req = RunRequest {
        vars: parse_vars(&a.vars)?,
        ephemeral: if a.ephemeral {
            Some(true)
        } else if a.persistent {
            Some(false)
        } else {
            None
        },
        assignee: a.assignee.clone().filter(|s| !s.trim().is_empty()),
        title: a.title.clone().filter(|s| !s.trim().is_empty()),
    };
    let plan = playbook::compile(&pb, &req, &loader)?;
    let (started, status) = app.write("playbook.run", |tx| {
        let opts = StartOptions {
            parent: a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?,
            after: a.after.iter().filter(|x| !x.trim().is_empty()).map(|x| tx.resolve_id(x)).collect::<Result<_>>()?,
        };
        let started = tx.start_run(&plan, &opts)?;
        let status = playbook::run_status(tx.conn(), &started.run.id, tx.now())?;
        if dry_run {
            tx.set_rollback_only();
        }
        Ok((started, status))
    })?;
    let run = &started.run;
    let kind = if started.ephemeral { "ephemeral run" } else { "run" };
    let gates = if started.gates > 0 { format!(", {} gate(s)", started.gates) } else { String::new() };
    let mut out = if dry_run {
        Out::new(json!({ "dry_run": true, "plan": plan, "run": run.id, "status": status }))
            .line(format!(
                "Plan: {} would start {kind} {} \"{}\" ({} step(s){gates})",
                pb.name, run.id, run.title, started.steps
            ))
            .lines(status_lines(&status).into_iter().skip(1))
            .line("Dry run: nothing was written.".to_string())
    } else {
        Out::new(&started)
            .line(format!("✓ Started {kind} {}: {} ({}, {} step(s){gates})", run.id, run.title, pb.name, started.steps))
    };
    if !dry_run {
        if started.ready.is_empty() {
            out = out.line("  nothing is ready yet (the run waits on --after issues)");
        }
        for r in &started.ready {
            out = out.line(format!("  ready: {} {}", r.id, r.title));
        }
        out = out.line(format!("  progress: bd playbook status {}", run.id));
    }
    app.print(out.id(run.id.clone()));
    Ok(())
}

fn cmd_status(app: &mut App, a: &IdArg) -> Result<()> {
    let status = app.read(|r| playbook::run_status(r.conn(), &r.resolve_id(&a.id)?, r.now()))?;
    let ids: Vec<String> = status.nodes.iter().map(|n| n.id.clone()).collect();
    let out = Out::new(&status).lines(status_lines(&status));
    app.print(Out { ids, ..out });
    Ok(())
}

fn cmd_runs(app: &mut App, a: &RunsArgs) -> Result<()> {
    let q = RunsQuery { include_closed: a.all, playbook: a.playbook.clone(), limit: (a.limit > 0).then_some(a.limit) };
    let (runs, now) = app.read(|r| Ok((playbook::runs(r.conn(), &q, r.now())?, r.now())))?;
    let mut out = Out::new(&runs);
    if runs.is_empty() {
        out = out.line(if a.all { "No runs" } else { "No open runs (--all includes finished ones)" });
    }
    for r in &runs {
        let icon = match (r.status, r.outcome) {
            (bd_core::Status::Closed, Some(bd_core::Outcome::Failed)) => "✗",
            (bd_core::Status::Closed, _) => "✓",
            _ => "▸",
        };
        let p = &r.progress;
        let mut extra = Vec::new();
        for (n, what) in [(p.active, "active"), (p.ready, "ready"), (p.failed, "failed")] {
            if n > 0 {
                extra.push(format!("{n} {what}"));
            }
        }
        if p.gates_open > 0 {
            extra.push(format!("{} gate(s) shut", p.gates_open));
        }
        if r.ephemeral {
            extra.push("ephemeral".into());
        }
        out = out
            .line(format!(
                "{icon} {} {} [{}] {}/{} done{} · started {}",
                r.id,
                r.title,
                r.playbook.as_deref().unwrap_or("?"),
                p.done,
                p.total,
                if extra.is_empty() { String::new() } else { format!(" ({})", extra.join(", ")) },
                rel(r.created_at, now)
            ))
            .id(r.id.clone());
    }
    app.print(out);
    Ok(())
}

fn cmd_compact(app: &mut App, a: &CompactArgs) -> Result<()> {
    let opts =
        CompactOptions { summary: a.summary.clone(), force: a.force, take_over: a.take_over, dry_run: a.dry_run };
    let r = app.write("playbook.compact", |tx| {
        let id = tx.resolve_id(&a.id)?;
        tx.compact_run(&id, &opts)
    })?;
    let mut out = Out::new(&r);
    if r.dry_run {
        out = out
            .line(format!(
                "Would remove {} issue(s) from {} and append this digest to its notes:",
                r.removed.len(),
                r.run.id
            ))
            .line(String::new())
            .lines(r.digest.lines().map(String::from));
    } else {
        out = out.line(format!(
            "✓ Compacted {}: {} issue(s) folded into its notes (kept for good)",
            r.run.id,
            r.removed.len()
        ));
    }
    app.print(out.id(r.run.id.clone()));
    Ok(())
}

fn cmd_discard(app: &mut App, a: &DiscardArgs) -> Result<()> {
    let r = app.write("playbook.discard", |tx| {
        let id = tx.resolve_id(&a.id)?;
        tx.discard_run(&id, &DiscardOptions { force: a.force, take_over: a.take_over, dry_run: a.dry_run })
    })?;
    let verb = if r.dry_run { "Would discard" } else { "✓ Discarded" };
    let mut out = Out::new(&r).line(format!("{verb} {} issue(s): {}", r.deleted.len(), r.deleted.join(", ")));
    if !r.detached.is_empty() {
        out = out.line(format!("  edges dropped from: {}", r.detached.join(", ")));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    app.print(out);
    Ok(())
}

fn cmd_extract(app: &mut App, a: &ExtractArgs) -> Result<()> {
    if a.save {
        io::require_local("playbook extract --save")?;
    }
    let pb = app.read(|r| playbook::extract(r.conn(), &r.resolve_id(&a.id)?, a.name.as_deref()))?;
    let text = playbook::to_toml(&pb)?;
    too_large_to_send(app, &text);
    let target = match (&a.output, a.save) {
        // Under bd serve the client writes the file, relative to its own directory.
        (Some(p), _) if io::serving() => Some(p.clone()),
        (Some(p), _) => Some(if p.is_relative() { app.cwd.join(p) } else { p.clone() }),
        (None, true) => {
            let dir = search_paths(app).into_iter().next().ok_or_else(|| Error::invalid("no playbook directory"))?;
            Some(dir.join(format!("{}.toml", pb.name)))
        }
        (None, false) => None,
    };
    match target {
        None => {
            if app.g.json {
                app.print_json(&json!({ "playbook": pb, "toml": text }));
            } else {
                io::out(&text);
            }
        }
        Some(path) => {
            if io::serving() {
                // The client checked --force against its own file before sending.
                io::send_file(&path, |w| Ok(w.write_all(text.as_bytes())?))?;
            } else {
                write_playbook(&path, &text, a.force)?;
            }
            app.print(wrote(&path, &pb));
        }
    }
    Ok(())
}

/// A playbook this large runs where it is a file, but a bd client cannot send
/// it to a server: say so where it is made.
fn too_large_to_send(app: &App, text: &str) {
    if text.len() > MAX_BUNDLE_FILE_BYTES && !app.g.json {
        io::errln(format!(
            "note: this playbook is {} KiB, more than the {} KiB a bd client sends to a server in one file: run it \
             locally, or from the server's playbook directory",
            text.len() >> 10,
            MAX_BUNDLE_FILE_BYTES >> 10
        ));
    }
}

fn write_playbook(path: &Path, text: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Refused(format!("{} exists; pass --force to overwrite", path.display())));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn wrote(path: &Path, pb: &Playbook) -> Out {
    Out::new(json!({ "path": path, "playbook": pb.name, "steps": pb.all_steps().len() }))
        .line(format!("✓ Wrote playbook {} to {} ({} step(s))", pb.name, path.display(), pb.all_steps().len()))
        .line(format!("  run it with: bd playbook run {}", pb.name))
        .id(path.display().to_string())
}

pub fn cmd_purge(app: &mut App, a: &PurgeArgs) -> Result<()> {
    let older = a.older_than.as_deref().map(parse_duration).transpose()?;
    let r = app.write("purge", |tx| tx.purge_ephemeral(older, a.dry_run))?;
    let verb = if r.dry_run { "Would purge" } else { "✓ Purged" };
    let mut out = Out::new(&r);
    out = if r.deleted.is_empty() {
        out.line("Nothing to purge (no closed ephemeral issues past the cutoff)")
    } else {
        out.line(format!("{verb} {} closed ephemeral issue(s)", r.deleted.len()))
    };
    if !r.detached.is_empty() {
        out = out.line(format!("  edges dropped from: {}", r.detached.join(", ")));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    app.print(out);
    Ok(())
}

// ------------------------------------------------------------ remote clients

/// Where a client puts the bundle among a request's files.
const BUNDLE_FILE: &str = "playbooks.bundle.json";
/// Names the bundle on the command line.
const BUNDLE_FLAG: &str = "--playbook-bundle";

/// A remote workspace's checkout playbooks: `.bd/playbooks` next to
/// `remote.toml`, else in the nearest `.bd` directory.
fn checkout_playbooks(app: &App) -> Result<PathBuf> {
    let bd = match remote::configured(app)?.map(|c| c.source) {
        Some(remote::Source::File(file)) => file.parent().map(Path::to_path_buf),
        _ => app.cwd.ancestors().map(|d| d.join(".bd")).find(|d| d.is_dir()),
    };
    Ok(bd.unwrap_or_else(|| app.cwd.join(".bd")).join("playbooks"))
}

/// Runs the `bd playbook` commands a remote workspace's client handles
/// itself: `list` (the checkout's playbooks, the server's, then the user's
/// own) and `extract --save` (into the checkout). `None`: the server runs it.
pub fn client_command(app: &App, remote: &Remote, cmd: &PlaybookCommand) -> Result<Option<i32>> {
    match cmd {
        PlaybookCommand::List => client_list(app, remote).map(Some),
        PlaybookCommand::Extract(a) if a.save => client_extract(app, remote, a).map(Some),
        _ => Ok(None),
    }
}

/// `show`, `plan` and `run` of a playbook found on the client: send its
/// files (a bundle) with the command. A name not found here is left to the
/// server's playbook path; a path not found here is an error.
pub fn attach_bundle(app: &App, cmd: &Command, request: &mut ExecRequest) -> Result<()> {
    let Command::Playbook(
        PlaybookCommand::Show(PlaybookRefArgs { playbook: reference })
        | PlaybookCommand::Plan(RunArgs { playbook: reference, .. })
        | PlaybookCommand::Run(RunArgs { playbook: reference, .. }),
    ) = cmd
    else {
        return Ok(());
    };
    if let Some(file) = &app.g.playbook_bundle {
        // A bundle named on the command line travels like any input file.
        request.files.insert(file.to_string_lossy().into_owned(), io::read_file(file)?);
        return Ok(());
    }
    // The checkout's playbooks and file paths shadow the server's; the user's
    // own ($BD_PLAYBOOK_PATH, the config directory) only stand in for names
    // the server lacks, which the server decides. Inside a playbook found
    // here, references resolve on the whole client path, as locally.
    let checkout = checkout_playbooks(app)?;
    let loader = Loader::new(with_user_paths(Some(checkout.clone())));
    let r = reference.trim();
    let server_first = if playbook::is_path_like(r) || Loader::new(vec![checkout]).locate(r, None).is_ok() {
        false
    } else {
        match loader.locate(r, None) {
            Ok(_) => true,
            // Not on the client: a playbook on the server's path.
            Err(Error::NotFound { .. }) => return Ok(()),
            Err(e) => return Err(e),
        }
    };
    let mut bundle = match server_first {
        true => loader.bundle_lenient(reference, Some(&app.cwd))?,
        false => loader.bundle(reference, Some(&app.cwd))?,
    };
    bundle.server_first = server_first;
    let bundle = bundle.to_json()?;
    request.files.insert(BUNDLE_FILE.to_string(), bundle);
    request.argv.splice(0..0, [BUNDLE_FLAG.to_string(), BUNDLE_FILE.to_string()]);
    Ok(())
}

/// A read the client composes (in JSON) rather than the user's command line.
fn server_read(app: &App, remote: &Remote, mut argv: Vec<String>) -> Result<ExecResponse> {
    if let Some(actor) = &app.g.actor {
        argv.splice(0..0, ["--actor".to_string(), actor.clone()]);
    }
    let (actor, session) = remote::identity();
    let request = ExecRequest { argv, actor, session, location: Some(remote.url.clone()), ..Default::default() };
    remote.exec(&request)
}

/// Print the error of a read the client composed, in the user's format; returns its exit code.
fn relay_failure(app: &App, response: &ExecResponse) -> i32 {
    match response.stderr.lines().find_map(|l| serde_json::from_str::<ErrorBody>(l).ok()) {
        Some(body) if !app.g.json => io::errln(format!("error: {}", body.error.message)),
        _ => io::errln(response.stderr.trim_end()),
    }
    response.exit_code
}

fn client_list(app: &App, remote: &Remote) -> Result<i32> {
    #[derive(Deserialize)]
    struct ServerList {
        search_paths: Vec<PathBuf>,
        playbooks: Vec<Listed>,
    }
    let checkout = checkout_playbooks(app)?;
    let users = with_user_paths(None);
    let response = server_read(app, remote, vec!["--json".into(), "playbook".into(), "list".into()])?;
    if response.exit_code != 0 {
        return Ok(relay_failure(app, &response));
    }
    let theirs: ServerList = serde_json::from_str(&response.stdout)
        .map_err(|e| Error::Remote(format!("{}: unexpected playbook list: {e}", remote.url)))?;
    // In lookup order: the checkout's, the server's, then the user's own.
    let mut entries: Vec<(Listed, bool)> = Vec::new();
    let found = Loader::new(vec![checkout.clone()]).list().into_iter().map(|l| (l, false));
    let found = found.chain(theirs.playbooks.into_iter().map(|l| (l, true)));
    for (mut l, server) in found.chain(Loader::new(users.clone()).list().into_iter().map(|l| (l, false))) {
        l.shadowed_by = entries.iter().find(|(m, _)| m.name == l.name).map(|(m, _)| m.path.clone());
        entries.push((l, server));
    }
    let playbooks: Vec<Value> = entries
        .iter()
        .map(|(l, server)| {
            let mut v = json!(l);
            if *server {
                v["server"] = json!(true);
            }
            v
        })
        .collect();
    let mut searched = vec![(checkout.clone(), false)];
    searched.extend(theirs.search_paths.iter().map(|p| (p.clone(), true)));
    searched.extend(users.iter().map(|p| (p.clone(), false)));
    let client: Vec<&PathBuf> = std::iter::once(&checkout).chain(&users).collect();
    let json = json!({
        "search_paths": client,
        "server": { "url": remote.url, "search_paths": theirs.search_paths },
        "playbooks": playbooks,
    });
    app.print(list_out(json, &entries, &searched));
    Ok(0)
}

/// `extract --save` in a remote workspace: the server extracts, the client
/// writes the file into its checkout's playbook directory.
fn client_extract(app: &App, remote: &Remote, a: &ExtractArgs) -> Result<i32> {
    let mut argv: Vec<String> = vec!["--json".into(), "playbook".into(), "extract".into()];
    if let Some(name) = &a.name {
        argv.extend(["--name".into(), name.clone()]);
    }
    argv.extend(["--".into(), a.id.clone()]);
    let response = server_read(app, remote, argv)?;
    if response.exit_code != 0 {
        return Ok(relay_failure(app, &response));
    }
    let unexpected =
        |e: &dyn std::fmt::Display| Error::Remote(format!("{}: unexpected extract output: {e}", remote.url));
    let extracted: Value = serde_json::from_str(&response.stdout).map_err(|e| unexpected(&e))?;
    let text = extracted["toml"].as_str().ok_or_else(|| unexpected(&"no toml"))?;
    // Parsing checks the playbook, and its name before it becomes a file name here.
    let pb = playbook::parse_toml(text, "the extracted playbook", "extracted")?;
    let path = checkout_playbooks(app)?.join(format!("{}.toml", pb.name));
    write_playbook(&path, text, a.force)?;
    too_large_to_send(app, text);
    app.print(wrote(&path, &pb));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn the_bundle_flag_parses() {
        assert!(Cli::try_parse_from(["bd", BUNDLE_FLAG, BUNDLE_FILE, "playbook", "list"]).is_ok());
    }
}
