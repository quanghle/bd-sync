//! `bd playbook ...` and `bd purge`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bd_core::playbook::{
    self, CompactOptions, Loader, Playbook, RunRequest, RunStatus, RunsQuery, StartOptions, Step, StepState,
};
use bd_core::time::parse_duration;
use bd_core::{Error, Queries, Result};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::rel;
use crate::io;

/// Where playbooks are looked up, in order: the workspace's `.bd/playbooks`,
/// `$BD_PLAYBOOK_PATH`, then `$XDG_CONFIG_HOME/bd/playbooks` (or
/// `~/.config/bd/playbooks`; `%APPDATA%\bd\playbooks` on Windows).
pub fn search_paths(app: &App) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match app.db_path() {
        Ok(db) => paths.extend(db.parent().map(|d| d.join("playbooks"))),
        Err(_) => paths.push(app.cwd.join(".bd").join("playbooks")),
    }
    if let Some(extra) = std::env::var_os("BD_PLAYBOOK_PATH") {
        paths.extend(std::env::split_paths(&extra).filter(|p| !p.as_os_str().is_empty()));
    }
    if let Some(c) = user_config_dir() {
        paths.push(c.join("bd").join("playbooks"));
    }
    paths
}

/// `$XDG_CONFIG_HOME` on every OS, else the platform's per-user config dir.
fn user_config_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    var("XDG_CONFIG_HOME").or_else(
        || {
            if cfg!(windows) { var("APPDATA") } else { var("HOME").map(|h| h.join(".config")) }
        },
    )
}

fn loader(app: &App) -> Loader {
    Loader::new(search_paths(app))
}

fn load(app: &App, reference: &str) -> Result<Playbook> {
    let r = reference.trim();
    if io::serving() && (r.contains(['/', '\\']) || playbook::EXTENSIONS.iter().any(|e| r.ends_with(e))) {
        // A path would name a file on the server, not the client's.
        return Err(Error::Refused(format!(
            "playbook {r:?}: bd serve runs playbooks by name from the workspace's playbook directory on the server"
        )));
    }
    loader(app).load_from(reference, Some(&app.cwd))
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
    let loader = loader(app);
    let listed = loader.list();
    let mut out = Out::new(json!({ "search_paths": loader.search_paths, "playbooks": listed }));
    if listed.is_empty() {
        out = out.line("No playbooks found. Searched:");
        for p in &loader.search_paths {
            out = out.line(format!("  {}", p.display()));
        }
        out = out.line("Create one at .bd/playbooks/<name>.toml (see `bd playbook show <file>` to validate it).");
    }
    for l in &listed {
        let mut line = format!("{:<20} {}", l.name, l.path.display());
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
    app.print(out);
    Ok(())
}

fn step_lines(steps: &[Step], depth: usize, out: &mut Vec<String>) {
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
    let pb = load(app, &a.playbook)?;
    let mut text = vec![format!(
        "{}{}{}",
        pb.name,
        if pb.description.is_empty() { String::new() } else { format!(" — {}", pb.description) },
        pb.source.as_ref().map(|p| format!("  ({})", p.display())).unwrap_or_default()
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
    let out = Out::new(json!({ "source": pb.source, "playbook": pb })).lines(text).id(pb.name.clone());
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
    let pb = load(app, &a.playbook)?;
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
    let plan = playbook::compile(&pb, &req, &loader(app))?;
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
    let opts = CompactOptions { summary: a.summary.clone(), force: a.force, dry_run: a.dry_run };
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
        tx.discard_run(&id, a.force, a.dry_run)
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
                io::send_file(&path, text.into_bytes())?;
            } else {
                if path.exists() && !a.force {
                    return Err(Error::Refused(format!("{} exists; pass --force to overwrite", path.display())));
                }
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                std::fs::write(&path, &text)?;
            }
            let out = Out::new(json!({ "path": path, "playbook": pb.name, "steps": pb.all_steps().len() }))
                .line(format!("✓ Wrote playbook {} to {} ({} step(s))", pb.name, path.display(), pb.all_steps().len()))
                .line(format!("  run it with: bd playbook run {}", pb.name))
                .id(path.display().to_string());
            app.print(out);
        }
    }
    Ok(())
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
