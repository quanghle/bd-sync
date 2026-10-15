//! Views over issues: `bd query`, `bd epic`, `bd children`, `bd stale`,
//! `bd orphans` and `bd graph`.

use std::time::Duration;

use bd_core::hierarchy::{self, EpicStatus};
use bd_core::subgraph::EdgeSet;
use bd_core::time::format_duration_ms;
use bd_core::{
    CloseOptions, DepType, Error, Issue, ListSort, Outcome, Queries, QueryRequest, Result, Timestamp, WriteCtx, query,
};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::{self, rel};
use crate::graph_view;
use crate::io;

pub fn cmd_query(app: &mut App, a: &QueryArgs) -> Result<()> {
    let source = a.source();
    if a.parse_only {
        // Parsing needs no workspace: nothing is opened.
        let expr = query::parse_query(&source)?;
        if app.g.json {
            app.print_json(&expr);
        } else {
            io::outln(expr.to_string());
        }
        return Ok(());
    }
    let json = app.g.json;
    let (issues, parents, now) = app.read(|r| {
        let q = QueryRequest {
            expr: source.clone(),
            sort: ListSort::parse(&a.sort)?,
            reverse: a.reverse,
            limit: (a.limit > 0).then_some(a.limit),
        };
        let issues = r.query(&q)?;
        let parents = if json { Vec::new() } else { issues.iter().map(|i| r.parent(&i.id)).collect::<Result<_>>()? };
        Ok((issues, parents, r.now()))
    })?;
    let n = issues.len();
    let mut out = Out::default();
    if !json {
        let lines = fmt::nest(&issues, &parents)
            .into_iter()
            .map(|(depth, i)| format!("{}{}", bd_core::graph::indent(depth), fmt::issue_line(i, now)));
        out = out.lines(lines).line(if n == 0 { "No issues".to_string() } else { format!("-- {n} issue(s)") });
    }
    out.ids = issues.iter().map(|i| i.id.clone()).collect();
    app.print(out.items(issues));
    Ok(())
}

/// One `bd epic status` line: progress, then whether the epic can close.
fn epic_line(e: &EpicStatus) -> String {
    let mut s = format!("{} {} [{}] {}  ", e.status.icon(), e.id, e.issue_type, e.title);
    match e.percent {
        None => s.push_str("no children"),
        Some(p) => s.push_str(&format!(
            "{}/{} closed ({p}%), {} in progress, {} blocked",
            e.closed, e.total, e.in_progress, e.blocked
        )),
    }
    if e.close_eligible {
        s.push_str("  ✓ eligible to close");
    }
    s
}

pub fn cmd_epic_status(app: &mut App, a: &EpicStatusArgs) -> Result<()> {
    if let Some(raw) = &a.id {
        let status = app.read(|r| r.epic_status(&r.resolve_id(raw)?))?;
        let line = epic_line(&status);
        let id = status.id.clone();
        app.print(Out::new(status).line(line).id(id));
        return Ok(());
    }
    let epics = app.read(|r| r.epics(a.all))?;
    let mut out = Out::new(&epics);
    if epics.is_empty() {
        out = out.line(if a.all { "No epics" } else { "No open epics" });
    }
    for e in &epics {
        out = out.line(epic_line(e)).id(e.id.clone());
    }
    app.print(out);
    Ok(())
}

pub fn cmd_close_eligible(app: &mut App, a: &CloseEligibleArgs) -> Result<()> {
    if a.close {
        let out = app.write("epic-close", |tx| exec_close_eligible(tx, a))?;
        app.print(out);
        return Ok(());
    }
    let (epics, now) = app.read(|r| {
        let epics = r.close_eligible_epics()?.iter().map(|id| r.issue(id)).collect::<Result<Vec<Issue>>>()?;
        Ok((epics, r.now()))
    })?;
    let n = epics.len();
    let mut out = Out::default().lines(epics.iter().map(|e| fmt::issue_line(e, now)));
    out = out.line(if n == 0 {
        "No epics eligible to close".to_string()
    } else {
        format!("-- {n} epic(s) eligible to close (close them with `bd epic close-eligible --close`)")
    });
    out.ids = epics.iter().map(|e| e.id.clone()).collect();
    app.print(out.items(epics));
    Ok(())
}

/// Close every epic eligible to close, all or none: other actors' live
/// claims among them are refused first (naming the holder) unless
/// `--take-over` is given, which `--force` never implies.
pub fn exec_close_eligible(tx: &mut WriteCtx<'_>, a: &CloseEligibleArgs) -> Result<Out> {
    let ids = hierarchy::close_eligible(tx.conn())?;
    if ids.is_empty() {
        return Ok(Out::new(Vec::<()>::new()).line("No epics eligible to close"));
    }
    tx.check_take_over(&ids, a.take_over, &format!("closing {}", ids.join(", ")))?;
    let opts = CloseOptions {
        reason: Some(a.reason.clone().unwrap_or_else(|| "All children closed".to_string())),
        outcome: Some(Outcome::Done),
        force: a.force,
        take_over: a.take_over,
        ..Default::default()
    };
    let mut results = Vec::with_capacity(ids.len());
    let mut out = Out::default();
    for id in ids {
        let r = tx.close_issue(&id, &opts)?;
        out = out.line(format!("✓ Closed {id}: {}", r.issue.title));
        for u in &r.unblocked {
            out = out.line(format!("  ↳ unblocked {} [P{}] {}", u.id, u.priority, u.title));
        }
        for c in &r.completed {
            out = out.line(format!("  ✓ completed {} {}", c.id, c.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = serde_json::to_value(&results).unwrap_or_default();
    Ok(out)
}

/// Lines of `issues` nested under their parents as `bd list` prints them.
fn nested_lines(issues: &[Issue], parents: &[Option<String>], now: Timestamp) -> Vec<String> {
    fmt::nest(issues, parents)
        .into_iter()
        .map(|(depth, i)| format!("{}{}", bd_core::graph::indent(depth), fmt::issue_line(i, now)))
        .collect()
}

pub fn cmd_children(app: &mut App, a: &ChildrenArgs) -> Result<()> {
    let json = app.g.json;
    let (issues, parents, now) = app.read(|r| {
        let id = r.resolve_id(&a.id)?;
        let issues = r.child_issues(&id, a.recursive)?;
        let parents = if json { Vec::new() } else { issues.iter().map(|i| r.parent(&i.id)).collect::<Result<_>>()? };
        Ok((issues, parents, r.now()))
    })?;
    let n = issues.len();
    let mut out = Out::default();
    if !json {
        out = out.lines(nested_lines(&issues, &parents, now)).line(if n == 0 {
            "No children".to_string()
        } else {
            format!("-- {n} issue(s)")
        });
    }
    out.ids = issues.iter().map(|i| i.id.clone()).collect();
    app.print(out.items(issues));
    Ok(())
}

pub fn cmd_stale(app: &mut App, a: &StaleArgs) -> Result<()> {
    let older_than = Duration::from_secs(u64::from(a.days) * 86_400);
    let (rows, now) = app.read(|r| Ok((r.stale(older_than, (a.limit > 0).then_some(a.limit))?, r.now())))?;
    let mut out = Out::default();
    for s in &rows {
        let mut line =
            format!("{}  idle {}", fmt::issue_line(&s.issue, now), format_duration_ms(now.since(s.issue.updated_at)));
        if let (Some(holder), Some(at)) = (&s.lease_holder, s.lease_expired_at) {
            line.push_str(&format!("  [lease expired {}, held by {holder}]", rel(at, now)));
        }
        out = out.line(line).id(s.issue.id.clone());
    }
    let n = rows.len();
    out = out.line(if n == 0 { "No stale issues".to_string() } else { format!("-- {n} issue(s)") });
    app.print(out.items(rows));
    Ok(())
}

pub fn cmd_orphans(app: &mut App, a: &OrphansArgs) -> Result<()> {
    let orphans = app.read(|r| {
        let prefix = match &a.prefix {
            Some(p) => p.trim().to_string(),
            None => r.config_value("issue_prefix")?,
        };
        r.orphans(&prefix)
    })?;
    let mut out = Out::default();
    if orphans.is_empty() {
        out = out.line("No dangling references");
    }
    for o in &orphans {
        out = out.line(format!("{} {}", o.id, o.title)).id(o.id.clone());
        for r in &o.references {
            out = out.line(format!("    → {} ({})", r.id, r.field));
        }
    }
    app.print(out.items(orphans));
    Ok(())
}

/// `--edges`: none given is the default set, `all` every type, else the types named.
fn edge_set(names: &[String]) -> Result<EdgeSet> {
    let names: Vec<&str> = names.iter().map(|n| n.trim()).filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        return Ok(EdgeSet::Default);
    }
    if names.iter().any(|n| n.eq_ignore_ascii_case("all")) {
        return Ok(EdgeSet::All);
    }
    let mut types: Vec<DepType> = Vec::new();
    for name in names {
        let t = DepType::parse(name).map_err(|e| Error::invalid(format!("--edges: {e}")))?;
        if !types.contains(&t) {
            types.push(t);
        }
    }
    Ok(EdgeSet::Only(types))
}

pub fn cmd_graph(app: &mut App, a: &GraphArgs) -> Result<()> {
    if a.id.is_none() && !a.all {
        return Err(Error::invalid("bd graph needs an issue id, or --all for every open issue"));
    }
    let edges = edge_set(&a.edges)?;
    let max_nodes = a.max_nodes as usize;
    let (g, heading) = app.read(|r| {
        let root = a.id.as_deref().map(|raw| r.resolve_id(raw)).transpose()?;
        let g = r.subgraph(root.as_deref(), &edges, max_nodes)?;
        let heading = match &root {
            Some(id) => format!("Issues around {id}: {}", r.issue(id)?.title),
            None => "Open issues".to_string(),
        };
        Ok((g, heading))
    })?;
    let render = || match a.format {
        GraphFormat::Text => graph_view::text(&g),
        GraphFormat::Dot => graph_view::dot(&g),
        GraphFormat::Html => graph_view::html(&g, &heading),
    };
    let Some(path) = &a.output else {
        if app.g.json {
            app.print_json(&g);
        } else {
            io::out(render());
        }
        return Ok(());
    };
    super::write_output(path, render().as_bytes())?;
    let (n, m) = (g.nodes.len(), g.edges.len());
    let mut line = format!(
        "✓ Wrote graph ({}, {}) to {}",
        graph_view::plural(n, "issue", "issues"),
        graph_view::plural(m, "edge", "edges"),
        path.display()
    );
    if g.truncated {
        line.push_str(&format!(" (truncated at --max-nodes {max_nodes})"));
    }
    let summary = json!({ "output": path, "nodes": n, "edges": m, "truncated": g.truncated });
    app.print(Out::new(summary).line(line));
    Ok(())
}
