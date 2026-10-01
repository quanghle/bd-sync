//! `bd gate ...`: listing, checking, resolving and creating gates.
//!
//! `bd gate check` reads the open gates from one snapshot, evaluates them
//! (GitHub gates through the `gh` CLI, outside any transaction, so slow
//! network calls never hold the write lock), then applies the verdicts in one
//! write transaction that re-checks each gate is still open.

use std::path::{Path, PathBuf};
use std::process::Command;

use bd_core::gates::{self, GateKind, GatePhase, GateSpec, GateView, NewGate, Verdict};
use bd_core::{Error, Queries, Result, Timestamp, WriteCtx};
use serde::Serialize;
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::rel;

fn phase_icon(p: GatePhase) -> &'static str {
    match p {
        GatePhase::Waiting => "⧗",
        GatePhase::Armed => "⏳",
        GatePhase::Escalated => "!",
        GatePhase::Resolved => "✓",
    }
}

fn condition(g: &GateView) -> String {
    match &g.spec {
        Some(s) => {
            let mut c = s.kind.to_string();
            if let Some(a) = &s.await_id {
                c.push_str(&format!(" {a}"));
            }
            if let Some(r) = &s.repo {
                c.push_str(&format!(" in {r}"));
            }
            if let Some(t) = &s.timeout {
                c.push_str(if s.kind == GateKind::Timer { " " } else { " timeout " });
                c.push_str(t);
            }
            c
        }
        None => format!("invalid ({})", g.spec_error.as_deref().unwrap_or("?")),
    }
}

fn ago(t: Timestamp, now: Timestamp) -> String {
    if now.since(t).abs() < 1000 { "just now".into() } else { rel(t, now) }
}

fn state_text(g: &GateView, now: Timestamp) -> String {
    match g.phase {
        GatePhase::Waiting => "waiting for its work's prerequisites".into(),
        GatePhase::Resolved => format!(
            "resolved {}{}",
            g.closed_at.map(|t| ago(t, now)).unwrap_or_default(),
            g.close_reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default()
        ),
        GatePhase::Escalated => format!("escalated: {}", g.escalation.as_deref().unwrap_or_default()),
        GatePhase::Armed => {
            let since = g.armed_at.map(|t| format!("armed {}", ago(t, now))).unwrap_or_else(|| "armed".into());
            match (g.spec.as_ref().map(|s| s.kind), g.deadline) {
                (Some(GateKind::Timer), Some(d)) => format!("{since}, opens {}", rel(d, now)),
                (_, Some(d)) => format!("{since}, escalates {}", rel(d, now)),
                _ => since,
            }
        }
    }
}

fn gate_line(g: &GateView, now: Timestamp) -> String {
    let holds: Vec<&str> = g.blocks.iter().map(|b| b.id.as_str()).collect();
    format!(
        "{} {} [{}] {} — {}{}",
        phase_icon(g.phase),
        g.id,
        condition(g),
        g.title,
        state_text(g, now),
        if holds.is_empty() { String::new() } else { format!(" (holds {})", holds.join(", ")) }
    )
}

pub fn cmd_gate(app: &mut App, cmd: &GateCommand) -> Result<()> {
    match cmd {
        GateCommand::List(a) => {
            let (list, now) = app.read(|r| Ok((gates::list(r.conn(), a.all)?, r.now())))?;
            let mut out = Out::new(&list);
            if list.is_empty() {
                out = out.line(if a.all { "No gates" } else { "No open gates" });
            }
            for g in &list {
                out = out.line(gate_line(g, now)).id(g.id.clone());
            }
            app.print(out);
        }
        GateCommand::Show(a) => {
            let (g, now) = app.read(|r| Ok((gates::view(r.conn(), &r.resolve_id(&a.id)?)?, r.now())))?;
            let mut out = Out::new(&g)
                .line(format!("{} {} · {}", phase_icon(g.phase), g.id, g.title))
                .line(format!("  condition: {}", condition(&g)))
                .line(format!("  state: {}", state_text(&g, now)));
            if let Some(a) = &g.assignee {
                out = out.line(format!("  assignee: {a}"));
            }
            if let Some(r) = &g.run_id {
                out = out.line(format!("  watching GitHub run {r}"));
            }
            for b in &g.blocks {
                out = out.line(format!("  holds back: {} {} [{}]", b.id, b.title, b.status));
            }
            if g.phase == GatePhase::Armed || g.phase == GatePhase::Escalated {
                out = out.line(format!("  open it by hand: bd gate resolve {}", g.id));
            }
            app.print(out.id(g.id.clone()));
        }
        GateCommand::Check(a) => cmd_check(app, a)?,
        GateCommand::Resolve(a) => {
            let out = app.write("gate.resolve", |tx| exec_resolve(tx, a))?;
            app.print(out);
        }
        GateCommand::Create(a) => {
            let out = app.write("gate.create", |tx| exec_create(tx, a))?;
            app.print(out);
        }
    }
    Ok(())
}

pub fn exec_resolve(tx: &mut WriteCtx<'_>, a: &GateResolveArgs) -> Result<Out> {
    let mut out = Out::new(Value::Null);
    let mut results = Vec::new();
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let r = tx.resolve_gate(&id, a.reason.as_deref(), a.force)?;
        out = out.line(if r.already_closed {
            format!("= {id} was already open")
        } else {
            format!("✓ Opened gate {id}: {}", r.issue.title)
        });
        for u in &r.unblocked {
            out = out.line(format!("  ↳ unblocked {} {}", u.id, u.title));
        }
        for c in &r.completed {
            out = out.line(format!("  ✓ completed {} {}", c.id, c.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = if results.len() == 1 { json!(results[0]) } else { json!(results) };
    Ok(out)
}

pub fn exec_create(tx: &mut WriteCtx<'_>, a: &GateCreateArgs) -> Result<Out> {
    let spec = GateSpec {
        kind: GateKind::parse(&a.kind)?,
        await_id: a.await_id.clone().filter(|s| !s.trim().is_empty()),
        timeout: a.timeout.clone().filter(|s| !s.trim().is_empty()),
        repo: a.repo.clone().filter(|s| !s.trim().is_empty()),
    };
    let blocks =
        a.blocks.iter().filter(|b| !b.trim().is_empty()).map(|b| tx.resolve_id(b)).collect::<Result<Vec<_>>>()?;
    let gate = tx.create_gate(NewGate {
        spec,
        blocks: blocks.clone(),
        title: a.title.clone(),
        description: a.description.clone().unwrap_or_default(),
        assignee: a.assignee.clone(),
        parent: a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?,
        priority: a.priority,
        ephemeral: false,
    })?;
    let view = gates::view_of(tx.conn(), &gate)?;
    let now = tx.now();
    Ok(Out::new(&view)
        .line(format!("✓ Created gate {}: {} (holds back {})", gate.id, gate.title, blocks.join(", ")))
        .line(format!("  {}", state_text(&view, now)))
        .id(gate.id))
}

/// What checking one gate found.
#[derive(Clone, Debug, Serialize)]
struct Checked {
    id: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(flatten)]
    verdict: Verdict,
    /// What happened: opened, escalated, unchanged, error.
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unblocked: Vec<String>,
}

fn gh_bin() -> String {
    std::env::var("BD_GH").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "gh".into())
}

fn gh_json(args: &[String], cwd: &Path) -> std::result::Result<Value, String> {
    let out = Command::new(gh_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("cannot run `{}`: {e} (install the GitHub CLI or set BD_GH)", gh_bin()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("gh {}: {}", args.first().map(String::as_str).unwrap_or_default(), err.trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("gh returned invalid JSON: {e}"))
}

fn repo_args(spec: &GateSpec) -> Vec<String> {
    // One token per flag, so a value can never be read as another flag.
    spec.repo.as_ref().map(|r| vec![format!("--repo={r}")]).unwrap_or_default()
}

fn run_verdict(run: &Value) -> Verdict {
    let id = run.get("databaseId").map(|v| v.to_string()).unwrap_or_default();
    let name = run.get("name").or_else(|| run.get("workflowName")).and_then(Value::as_str).unwrap_or("workflow");
    let status = run.get("status").and_then(Value::as_str).unwrap_or_default();
    let conclusion = run.get("conclusion").and_then(Value::as_str).unwrap_or_default();
    let label = if id.is_empty() { format!("'{name}'") } else { format!("'{name}' (run {id})") };
    if status != "completed" {
        return Verdict::Pending(format!("{label} is {}", if status.is_empty() { "pending" } else { status }));
    }
    match conclusion {
        "success" | "skipped" | "neutral" => Verdict::Resolve(format!("{label} succeeded")),
        other => Verdict::Escalate(format!(
            "{label} concluded {}",
            if other.is_empty() { "without a result" } else { other }
        )),
    }
}

/// Probe a GitHub gate. Returns the verdict and, for gh:run, the run to pin.
fn probe_github(g: &GateView, spec: &GateSpec, cwd: &Path) -> std::result::Result<(Verdict, Option<String>), String> {
    let target = spec.await_id.clone().unwrap_or_default();
    match spec.kind {
        GateKind::GhPr => {
            let n = target.trim_start_matches('#').to_string();
            let mut args: Vec<String> =
                ["pr", "view", &n, "--json", "state,title,url"].iter().map(|s| s.to_string()).collect();
            args.extend(repo_args(spec));
            let pr = gh_json(&args, cwd)?;
            let title = pr.get("title").and_then(Value::as_str).unwrap_or_default();
            Ok((
                match pr.get("state").and_then(Value::as_str).unwrap_or_default() {
                    "MERGED" => Verdict::Resolve(format!("PR #{n} merged: {title}")),
                    "CLOSED" => Verdict::Escalate(format!("PR #{n} was closed without merging: {title}")),
                    state => Verdict::Pending(format!("PR #{n} is {}", state.to_lowercase())),
                },
                None,
            ))
        }
        GateKind::GhRun => {
            let pinned = g
                .run_id
                .clone()
                .or_else(|| (!target.is_empty() && target.chars().all(|c| c.is_ascii_digit())).then(|| target.clone()));
            if let Some(id) = pinned {
                let mut args: Vec<String> = ["run", "view", &id, "--json", "databaseId,status,conclusion,name,url"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                args.extend(repo_args(spec));
                return Ok((run_verdict(&gh_json(&args, cwd)?), None));
            }
            // A workflow name: the first run that started after the gate armed.
            let workflow = format!("--workflow={target}");
            let mut args: Vec<String> = [
                "run",
                "list",
                &workflow,
                "--json",
                "databaseId,status,conclusion,name,createdAt,url",
                "--limit",
                "50",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            args.extend(repo_args(spec));
            let runs = gh_json(&args, cwd)?;
            let armed = g.armed_at.unwrap_or(g.created_at);
            let first = runs
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| {
                    let created =
                        r.get("createdAt").and_then(Value::as_str).and_then(|s| Timestamp::parse_rfc3339(s).ok())?;
                    (created >= armed).then_some((created, r))
                })
                .min_by_key(|(created, _)| *created);
            match first {
                None => Ok((
                    Verdict::Pending(format!("no run of {target} has started since the gate armed ({armed})")),
                    None,
                )),
                Some((_, run)) => {
                    let id = run.get("databaseId").map(|v| v.to_string());
                    Ok((run_verdict(run), id))
                }
            }
        }
        _ => Err(format!("{} gates are not GitHub gates", spec.kind)),
    }
}

fn workdir(app: &App) -> PathBuf {
    app.db_path()
        .ok()
        .and_then(|db| db.parent().and_then(Path::parent).map(Path::to_path_buf))
        .unwrap_or_else(|| app.cwd.clone())
}

fn cmd_check(app: &mut App, a: &GateCheckArgs) -> Result<()> {
    let kind_filter: Option<Vec<GateKind>> = match a.kind.as_deref().map(str::trim) {
        None | Some("") | Some("all") => None,
        Some("gh") => Some(vec![GateKind::GhRun, GateKind::GhPr]),
        Some(k) => Some(vec![GateKind::parse(k)?]),
    };
    let cwd = workdir(app);
    let (candidates, local, now) = app.read(|r| {
        let ids: Vec<String> = a.ids.iter().map(|i| r.resolve_id(i)).collect::<Result<_>>()?;
        let mut list = gates::list(r.conn(), false)?;
        for id in &ids {
            if !list.iter().any(|g| &g.id == id) {
                let g = gates::view(r.conn(), id)?;
                return Err(Error::invalid(format!("{id} is not an open gate ({})", g.phase.as_str())));
            }
        }
        list.retain(|g| ids.is_empty() || ids.contains(&g.id));
        list.retain(|g| match (&kind_filter, &g.spec) {
            (None, _) => true,
            (Some(kinds), Some(s)) => kinds.contains(&s.kind),
            (Some(_), None) => false,
        });
        let now = r.now();
        let local = list.iter().map(|g| gates::evaluate_local(r.conn(), g, now)).collect::<Result<Vec<_>>>()?;
        Ok((list, local, now))
    })?;

    let mut checked: Vec<Checked> = Vec::new();
    for (g, verdict) in candidates.iter().zip(local) {
        let kind = g.spec.as_ref().map(|s| s.kind.to_string());
        let (verdict, run_id, error) = match verdict {
            Some(v) => (v, None, None),
            None => match probe_github(g, g.spec.as_ref().expect("local evaluation handles malformed gates"), &cwd) {
                Ok((v, pin)) => (v, pin, None),
                Err(e) => (Verdict::Pending(e.clone()), None, Some(e)),
            },
        };
        // Timeouts escalate whatever is still shut.
        let verdict = match (&verdict, gates::overdue(g, now)) {
            (Verdict::Pending(_), Some(reason)) if g.is_armed() => Verdict::Escalate(reason),
            _ => verdict,
        };
        let action = if error.is_some() { "error" } else { "unchanged" };
        checked.push(Checked { id: g.id.clone(), kind, verdict, action: action.into(), run_id, unblocked: Vec::new() });
    }

    let needs_write = checked
        .iter()
        .any(|c| c.action != "error" && (c.run_id.is_some() || !matches!(c.verdict, Verdict::Pending(_))));
    if needs_write && !a.dry_run {
        checked = app.write("gate.check", |tx| {
            for c in checked.iter_mut().filter(|c| c.action != "error") {
                let Some(issue) = tx.find_issue(&c.id)? else { continue };
                // Resolved, or no longer armed, since the snapshot: leave it.
                if issue.status.is_terminal() || issue.is_blocked {
                    continue;
                }
                if let Some(run) = &c.run_id {
                    tx.pin_gate_run(&c.id, run)?;
                }
                match &c.verdict {
                    Verdict::Resolve(detail) => {
                        let r = tx.resolve_gate(&c.id, Some(detail), false)?;
                        c.action = "opened".into();
                        c.unblocked = r.unblocked.iter().map(|u| u.id.clone()).collect();
                    }
                    Verdict::Escalate(detail) => {
                        if tx.escalate_gate(&c.id, detail)? {
                            c.action = "escalated".into();
                        }
                    }
                    Verdict::Pending(_) => {}
                }
            }
            Ok(checked)
        })?;
    } else if a.dry_run {
        for c in checked.iter_mut().filter(|c| c.action != "error") {
            c.action = match &c.verdict {
                Verdict::Resolve(_) => "would open".into(),
                Verdict::Escalate(_) => "would escalate".into(),
                Verdict::Pending(_) => "unchanged".into(),
            };
        }
    }

    let count = |action: &str| checked.iter().filter(|c| c.action == action).count();
    let mut out = Out::new(json!({ "dry_run": a.dry_run, "checked": checked }));
    if checked.is_empty() {
        out = out.line("No open gates to check");
    }
    for c in &checked {
        let icon = match c.action.as_str() {
            "opened" | "would open" => "✓",
            "escalated" | "would escalate" => "!",
            "error" => "✗",
            _ => "…",
        };
        let verb = match c.action.as_str() {
            "unchanged" => match &c.verdict {
                Verdict::Escalate(_) => "already escalated".to_string(),
                _ => "shut".to_string(),
            },
            other => other.to_string(),
        };
        out = out.line(format!("{icon} {} {verb}: {}", c.id, c.verdict.detail())).id(c.id.clone());
        for u in &c.unblocked {
            out = out.line(format!("  ↳ unblocked {u}"));
        }
    }
    if !checked.is_empty() {
        let prefix = if a.dry_run { "Dry run: " } else { "" };
        out = out.line(format!(
            "{prefix}checked {} gate(s): {} opened, {} escalated, {} errors",
            checked.len(),
            count("opened") + count("would open"),
            count("escalated") + count("would escalate"),
            count("error")
        ));
    }
    app.print(out);
    Ok(())
}
