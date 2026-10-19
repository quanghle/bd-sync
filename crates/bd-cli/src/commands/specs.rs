//! `bd spec`: feature specs (experimental), over `bd_core::specs`.

use bd_core::spec_edit::Sentence;
use bd_core::specs::{self, Drift};
use bd_core::time::parse_filter_time;
use bd_core::{Error, Guard, IssuePatch, IssueRef, Queries, Result, Status, WriteCtx, issues};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::io;

pub fn cmd_spec(app: &mut App, cmd: &SpecCommand) -> Result<i32> {
    match cmd {
        SpecCommand::List => cmd_spec_list(app).map(|_| 0),
        SpecCommand::Show(a) => cmd_spec_show(app, a).map(|_| 0),
        SpecCommand::Drift(a) => cmd_spec_drift(app, a),
        SpecCommand::Candidates => cmd_spec_candidates(app).map(|_| 0),
        SpecCommand::None(a) => {
            let out = app.write("spec-none", |tx| exec_spec_none(tx, a))?;
            app.print(out);
            Ok(0)
        }
        SpecCommand::New(a) => {
            let out = app.write("spec-new", |tx| exec_spec_new(tx, a))?;
            app.print(out);
            Ok(0)
        }
        SpecCommand::Add(a) => {
            let out = app.write("spec-add", |tx| exec_spec_add(tx, a))?;
            app.print(out);
            Ok(0)
        }
        SpecCommand::Change(a) => {
            let out = app.write("spec-change", |tx| exec_spec_change(tx, a))?;
            app.print(out);
            Ok(0)
        }
        SpecCommand::Remove(a) => {
            let out = app.write("spec-remove", |tx| exec_spec_remove(tx, a))?;
            app.print(out);
            Ok(0)
        }
        SpecCommand::Link(a) => {
            let out = app.write("spec-link", |tx| exec_spec_link(tx, a))?;
            app.print(out);
            Ok(0)
        }
    }
}

/// Issue text as views print it: control and direction characters escaped.
fn p(text: &str) -> String {
    io::printable(text).into_owned()
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn cmd_spec_list(app: &mut App) -> Result<()> {
    let list = app.read(|r| {
        specs::require_on(r.conn())?;
        specs::list(r.conn())
    })?;
    let mut out = Out::new(&list);
    if list.is_empty() {
        out = out.line("No open specs");
    }
    for s in &list {
        let mut line = format!("{} {} {}", s.status.icon(), s.id, p(&s.title));
        if !s.areas.is_empty() {
            line.push_str(&format!(" [{}]", p(&s.areas.join(", "))));
        }
        if let Some(parent) = &s.parent {
            line.push_str(&format!(" (sub-spec of {parent})"));
        } else if let Some(closed) = &s.closed_parent {
            line.push_str(&format!(" (orphaned: parent spec {closed} is closed)"));
        }
        if s.status != Status::Pinned {
            line.push_str(&format!(" ({}, not pinned)", s.status.as_str()));
        }
        line.push_str(&format!(
            ": {} requirement{}, {} non-goal{}, {} linked issue{}",
            s.requirements,
            plural(s.requirements),
            s.non_goals,
            plural(s.non_goals),
            s.linked,
            plural(s.linked)
        ));
        out = out.line(line).id(s.id.clone());
    }
    if !list.is_empty() {
        out = out.line(format!("-- {} open spec{}; `bd spec show <spec>` prints one", list.len(), plural(list.len())));
    }
    app.print(out);
    Ok(())
}

fn cmd_spec_show(app: &mut App, a: &SpecShowArgs) -> Result<()> {
    let views = app.read(|r| {
        specs::require_on(r.conn())?;
        specs::show(r.conn(), &a.target)
    })?;
    if app.g.json {
        app.print_json(&views);
    } else if app.g.quiet {
        views.iter().for_each(|v| io::outln(&v.spec.id));
    } else {
        let text: Vec<String> = views.iter().map(|v| specs::render(v, a.history, 1)).collect();
        io::out(p(&text.join("\n")));
    }
    Ok(())
}

/// One issue in a drift section.
fn ref_line(i: &IssueRef) -> String {
    format!("- {} [{}] {} ({})", i.id, i.issue_type, p(&i.title), i.status)
}

fn section(out: Out, title: &str, lines: Vec<String>) -> Out {
    let n = lines.len();
    let mut out = out.line(String::new()).line(format!("## {title} ({n})"));
    if lines.is_empty() {
        out = out.line("- (none)");
    }
    out.lines(lines)
}

fn drift_text(d: &Drift) -> Out {
    let head = match d.since {
        Some(t) => format!("Spec drift since {t}: {} problem{}", d.count(), plural(d.count())),
        None => format!(
            "Spec drift: {} problem{} (experimental.specs.since is unset, so no work is checked: \
             bd config set experimental.specs.since <time>)",
            d.count(),
            plural(d.count())
        ),
    };
    let mut out = Out::default().line(head);
    out = section(out, "Unlinked: work closed since then with no spec link", d.unlinked.iter().map(ref_line).collect());
    out = section(
        out,
        "Shaky: requirements in force whose source was reopened or failed",
        d.shaky
            .iter()
            .map(|s| {
                format!(
                    "- {} {} — source {} {} is {}",
                    s.requirement.id,
                    p(&s.requirement.title),
                    s.source.id,
                    p(&s.source.title),
                    s.why
                )
            })
            .collect(),
    );
    out = section(
        out,
        "Bad status: specs and requirements neither pinned nor closed",
        d.bad_status.iter().map(ref_line).collect(),
    );
    out = section(
        out,
        "Orphaned: open specs under a closed spec",
        d.orphaned
            .iter()
            .map(|o| format!("- {} {} (parent spec {} is closed)", o.spec.id, p(&o.spec.title), o.parent))
            .collect(),
    );
    out = section(
        out,
        "To link: open work since then, not linked yet (not drift)",
        d.to_link.iter().map(ref_line).collect(),
    );
    out.line(String::new())
        .line("Link work with `bd spec link <id> <spec or requirement>`, or mark it `bd spec none <id> -r '<why>'`.")
}

fn cmd_spec_drift(app: &mut App, a: &SpecDriftArgs) -> Result<i32> {
    let drift = app.read(|r| {
        specs::require_on(r.conn())?;
        let since = match &a.since {
            Some(s) => Some(parse_filter_time(s, r.now())?),
            None => specs::since(r.conn())?,
        };
        specs::drift(r.conn(), since)
    })?;
    let count = drift.count();
    let mut out = drift_text(&drift);
    let mut json = serde_json::to_value(&drift)?;
    json["count"] = json!(count);
    out.json = json;
    out.ids = drift
        .unlinked
        .iter()
        .map(|i| i.id.clone())
        .chain(drift.shaky.iter().map(|s| s.requirement.id.clone()))
        .chain(drift.bad_status.iter().map(|i| i.id.clone()))
        .chain(drift.orphaned.iter().map(|o| o.spec.id.clone()))
        .collect();
    app.print(out);
    Ok(if count > 0 { 1 } else { 0 })
}

fn cmd_spec_candidates(app: &mut App) -> Result<()> {
    let groups = app.read(|r| {
        specs::require_on(r.conn())?;
        let since = specs::since(r.conn())?;
        specs::candidates(r.conn(), since)
    })?;
    let mut out = Out::new(&groups);
    if groups.is_empty() {
        out = out.line("No candidates: every closed issue is linked to a spec or needs none");
    }
    for g in &groups {
        let title = g.title.as_deref().map(|t| format!(" {}", p(t))).unwrap_or_default();
        out = out.line(format!("## {}{title} ({})", p(&g.key), g.issues.len()));
        for i in &g.issues {
            out = out.line(format!("- {} {}", i.id, p(&i.title))).id(i.id.clone());
        }
    }
    app.print(out);
    Ok(())
}

/// `bd spec none`: label each issue `spec:none` and comment the reason, in
/// this transaction; refuses spec issues themselves, and leaves an issue
/// already marked as it is. Status, assignee and claims are left alone.
pub fn exec_spec_none(tx: &mut WriteCtx<'_>, a: &SpecNoneArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let reason = a.reason.trim();
    if reason.is_empty() {
        return Err(Error::invalid("give the reason the work touches no spec (-r)"));
    }
    // Each issue is read once: (id, already marked spec:none). The ids are
    // distinct, so marking one in the loop below never changes another's labels.
    let mut ids: Vec<(String, bool)> = Vec::new();
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let issue = issues::require(tx.conn(), &id)?;
        if specs::is_spec_part(&issue.labels) {
            return Err(Error::invalid(format!(
                "{id} is part of a spec (labelled spec, requirement or non-goal): only other work is marked spec:none"
            )));
        }
        if !ids.iter().any(|(i, _)| *i == id) {
            let already = issue.labels.iter().any(|l| l == specs::NONE);
            ids.push((id, already));
        }
    }
    let mut out = Out::default();
    let mut done = Vec::new();
    for (id, already) in &ids {
        if *already {
            out = out.line(format!("= {id} is already marked spec:none")).id(id.clone());
            done.push(json!({ "id": id, "already": true }));
            continue;
        }
        let patch = IssuePatch { add_labels: vec![specs::NONE.to_string()], ..Default::default() };
        let updated = tx.update_issue(id, &patch, &Guard::default(), false)?;
        let comment = tx.add_comment(id, &format!("No spec: {reason}"))?;
        out = out.line(format!("✓ {id} marked spec:none")).id(id.clone());
        done.push(json!({ "id": id, "already": false, "labels": updated.issue.labels, "comment_id": comment.id }));
    }
    out.json = json!(done);
    Ok(out)
}

/// Each non-blank `--from`, resolved to its full id (the engine dedupes them).
fn resolve_from(tx: &WriteCtx<'_>, from: &[String]) -> Result<Vec<String>> {
    from.iter().filter(|f| !f.trim().is_empty()).map(|f| tx.resolve_id(f)).collect()
}

fn sentence(tx: &WriteCtx<'_>, words: &[String], description: &Option<String>, from: &[String]) -> Result<Sentence> {
    Ok(Sentence {
        title: words.join(" "),
        description: description.clone().unwrap_or_default(),
        from: resolve_from(tx, from)?,
    })
}

fn kind(non_goal: bool) -> &'static str {
    if non_goal { "non-goal" } else { "requirement" }
}

/// `bd spec new`: a pinned feature labelled `spec` and `area:AREA`, under
/// `--parent` (a spec in force) when given, with related edges to `--from`.
pub fn exec_spec_new(tx: &mut WriteCtx<'_>, a: &SpecNewArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let parent = a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?;
    let s = sentence(tx, &a.title, &a.description, &a.from)?;
    let made = tx.spec_new(&a.area, &s, parent.as_deref())?;
    let id = made.spec.id.clone();
    let mut out =
        Out::new(&made).line(format!("✓ Created spec {id}: {} [area:{}]", p(&made.spec.title), p(&made.area)));
    if let Some(parent) = &made.parent {
        out = out.line(format!("  sub-spec of {parent}"));
    }
    Ok(out.id(id))
}

/// `bd spec add`: a pinned requirement (or non-goal) under a spec in force,
/// with related edges to `--from`.
pub fn exec_spec_add(tx: &mut WriteCtx<'_>, a: &SpecAddArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let spec = tx.resolve_id(&a.spec)?;
    let s = sentence(tx, &a.sentence, &a.description, &a.from)?;
    let made = tx.spec_add(&spec, &s, a.non_goal)?;
    let id = made.requirement.id.clone();
    let line = format!("✓ Added {} {id} to {}: {}", kind(made.non_goal), made.spec, p(&made.requirement.title));
    Ok(Out::new(&made).line(line).id(id))
}

/// `bd spec change`: the new requirement under the old one's spec, then the
/// old one superseded by it, all or nothing.
pub fn exec_spec_change(tx: &mut WriteCtx<'_>, a: &SpecChangeArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let old = tx.resolve_id(&a.req)?;
    let s = sentence(tx, &a.sentence, &a.description, &a.from)?;
    let made = tx.spec_change(&old, &s)?;
    let id = made.requirement.id.clone();
    let line = format!("✓ Changed {} -> {id} in {}: {}", made.superseded.id, made.spec, p(&made.requirement.title));
    Ok(Out::new(&made).line(line).id(id))
}

/// `bd spec remove`: close a requirement with the reason `removed: WHY`,
/// after related edges to `--from`.
pub fn exec_spec_remove(tx: &mut WriteCtx<'_>, a: &SpecRemoveArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let req = tx.resolve_id(&a.req)?;
    let from = resolve_from(tx, &a.from)?;
    let done = tx.spec_remove(&req, &a.reason, &from)?;
    let id = done.requirement.id.clone();
    let line = format!("✓ Removed {id} from {}: {}", done.spec, p(&done.why));
    Ok(Out::new(&done).line(line).id(id))
}

/// `bd spec link`: related edges from the work to each spec or requirement
/// in force, those already linked left as they are.
pub fn exec_spec_link(tx: &mut WriteCtx<'_>, a: &SpecLinkArgs) -> Result<Out> {
    specs::require_on(tx.conn())?;
    let issue = tx.resolve_id(&a.issue)?;
    let targets = a.targets.iter().map(|t| tx.resolve_id(t)).collect::<Result<Vec<_>>>()?;
    let links = tx.spec_link(&issue, &targets)?;
    let mut out = Out::new(&links);
    for l in &links {
        out = out.line(if l.already {
            format!("= {} is already linked to {}", l.issue, l.target)
        } else {
            format!("✓ {} linked to {}", l.issue, l.target)
        });
    }
    Ok(out.id(issue))
}
