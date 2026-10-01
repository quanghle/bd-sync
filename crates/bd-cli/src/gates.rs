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
            if let Some(b) = &s.branch {
                c.push_str(&format!(" on {b}"));
            }
            if let Some(e) = &s.event {
                c.push_str(&format!(" for {e}"));
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
        branch: a.branch.clone().filter(|s| !s.trim().is_empty()),
        event: a.event.clone().filter(|s| !s.trim().is_empty()),
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
    /// The run watched before a re-pin.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pin_reason: Option<String>,
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

/// Runs created this long before a `gh:run` gate armed still count: the gate
/// arms on this machine's clock, GitHub stamps runs with its own.
const RUN_CLOCK_SKEW_MS: i64 = 60_000;

const RUN_FIELDS: &str = "databaseId,status,conclusion,name,createdAt,url,headBranch,headSha,event";

/// A run for a `gh:run` gate to watch (newly or instead of another).
struct Pin {
    run_id: String,
    why: Option<String>,
}

fn run_id_of(run: &Value) -> Option<String> {
    run.get("databaseId")
        .filter(|v| !v.is_null())
        .map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
}

fn run_created(run: &Value) -> Option<Timestamp> {
    run.get("createdAt").and_then(Value::as_str).and_then(|s| Timestamp::parse_rfc3339(s).ok())
}

fn run_field<'a>(run: &'a Value, key: &str) -> Option<&'a str> {
    run.get(key).and_then(Value::as_str)
}

/// `gh` filters by branch and event already; this guards against a run it
/// let through anyway. A field `gh` did not return matches.
fn run_matches(run: &Value, key: &str, want: &Option<String>) -> bool {
    match (want, run_field(run, key)) {
        (Some(w), Some(v)) => v == w,
        _ => true,
    }
}

fn view_run(id: &str, spec: &GateSpec, cwd: &Path) -> std::result::Result<Value, String> {
    let mut args: Vec<String> = ["run", "view", id, "--json", RUN_FIELDS].iter().map(|s| s.to_string()).collect();
    args.extend(repo_args(spec));
    gh_json(&args, cwd)
}

/// Probe a GitHub gate. Returns the verdict and, for gh:run, a run to pin.
fn probe_github(g: &GateView, spec: &GateSpec, cwd: &Path) -> std::result::Result<(Verdict, Option<Pin>), String> {
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
            if let Some(id) = spec.run_id() {
                return Ok((run_verdict(&view_run(id, spec, cwd)?), None));
            }
            // Without a branch, a pinned run stays pinned: no need to list runs again.
            if let (Some(id), None) = (&g.run_id, &spec.branch) {
                return Ok((run_verdict(&view_run(id, spec, cwd)?), None));
            }
            // A workflow: the first run created after the gate armed. With a
            // branch, the first run for the branch's newest head, so a
            // re-created tag or a newer push moves the gate to its run.
            let mut args: Vec<String> = vec!["run".into(), "list".into(), format!("--workflow={target}")];
            if let Some(b) = &spec.branch {
                args.push(format!("--branch={b}"));
            }
            if let Some(e) = &spec.event {
                args.push(format!("--event={e}"));
            }
            args.extend(["--json", RUN_FIELDS, "--limit", "50"].iter().map(|s| s.to_string()));
            args.extend(repo_args(spec));
            let listed = gh_json(&args, cwd)?;
            let armed = g.armed_at.unwrap_or(g.created_at);
            let since = Timestamp(armed.millis().saturating_sub(RUN_CLOCK_SKEW_MS));
            let runs: Vec<(Timestamp, &Value)> = listed
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| run_matches(r, "headBranch", &spec.branch) && run_matches(r, "event", &spec.event))
                .filter_map(|r| run_created(r).filter(|c| *c >= since).map(|c| (c, r)))
                .collect();
            let head = spec
                .branch
                .as_ref()
                .and_then(|_| runs.iter().max_by_key(|(c, _)| *c))
                .and_then(|(_, r)| run_field(r, "headSha"));
            let first = runs
                .iter()
                .filter(|(_, r)| head.is_none() || run_field(r, "headSha") == head)
                .min_by_key(|(c, _)| *c)
                .map(|(_, r)| *r);

            if let Some(pinned) = &g.run_id {
                let current = match runs.iter().find(|(_, r)| run_id_of(r).as_deref() == Some(pinned.as_str())) {
                    Some((_, r)) => (*r).clone(),
                    None => view_run(pinned, spec, cwd)?,
                };
                let moved = head.is_some() && run_field(&current, "headSha") != head;
                return match first.filter(|_| moved) {
                    Some(run) => {
                        let why = format!(
                            "{} now points at {}",
                            spec.branch.as_deref().unwrap_or_default(),
                            head.map(|h| &h[..h.len().min(12)]).unwrap_or_default()
                        );
                        Ok((run_verdict(run), run_id_of(run).map(|run_id| Pin { run_id, why: Some(why) })))
                    }
                    None => Ok((run_verdict(&current), None)),
                };
            }
            match first {
                None => {
                    let mut which = target.clone();
                    if let Some(b) = &spec.branch {
                        which.push_str(&format!(" on {b}"));
                    }
                    if let Some(e) = &spec.event {
                        which.push_str(&format!(" for {e}"));
                    }
                    Ok((
                        Verdict::Pending(format!("no run of {which} has started since the gate armed ({armed})")),
                        None,
                    ))
                }
                Some(run) => Ok((run_verdict(run), run_id_of(run).map(|run_id| Pin { run_id, why: None }))),
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
        let (verdict, pin, error) = match verdict {
            Some(v) => (v, None, None),
            None => match probe_github(g, g.spec.as_ref().expect("local evaluation handles malformed gates"), &cwd) {
                Ok((v, pin)) => (v, pin, None),
                Err(e) => (Verdict::Pending(e.clone()), None, Some(e)),
            },
        };
        let previous_run_id = pin.as_ref().and(g.run_id.clone());
        let (run_id, pin_reason) = pin.map(|p| (Some(p.run_id), p.why)).unwrap_or_default();
        // Timeouts escalate whatever is still shut.
        let verdict = match (&verdict, gates::overdue(g, now)) {
            (Verdict::Pending(_), Some(reason)) if g.is_armed() => Verdict::Escalate(reason),
            _ => verdict,
        };
        let action = if error.is_some() { "error" } else { "unchanged" };
        checked.push(Checked {
            id: g.id.clone(),
            kind,
            verdict,
            action: action.into(),
            run_id,
            previous_run_id,
            pin_reason,
            unblocked: Vec::new(),
        });
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
                    tx.pin_gate_run(&c.id, run, c.pin_reason.as_deref())?;
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
        if let (Some(run), Some(prev)) = (&c.run_id, &c.previous_run_id) {
            let why = c.pin_reason.as_ref().map(|w| format!(" ({w})")).unwrap_or_default();
            let verb = if a.dry_run { "would watch" } else { "now watching" };
            out = out.line(format!("  ↻ {verb} run {run} instead of {prev}{why}"));
        }
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
