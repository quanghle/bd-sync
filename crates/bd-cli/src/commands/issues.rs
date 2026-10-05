//! Issue lifecycle: create, update, close, reopen, defer, delete; show, list, ready, blocked.

use bd_core::time::parse_when;
use bd_core::{
    ClaimOptions, CloseOptions, DeleteOptions, Error, IssuePatch, ListQuery, ListSort, NewIssue, Outcome, Queries,
    ReadyQuery, Result, SortPolicy, Status, WriteCtx,
};
use serde_json::Value;

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::{self, rel};
use crate::io;

use super::claims::claim_out;
use super::{clearable, clearable_time, dep_spec, filter_from, guard_from, json_object, key_value, one_or_many};

pub fn exec_create(tx: &mut WriteCtx<'_>, a: &CreateArgs) -> Result<Out> {
    let now = tx.now();
    let parent = a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?;
    let deps = a.deps.iter().filter(|d| !d.trim().is_empty()).map(|d| dep_spec(tx, d)).collect::<Result<Vec<_>>>()?;
    let new = NewIssue {
        id: a.id.clone(),
        title: a.title.join(" "),
        description: a.description.clone().unwrap_or_default(),
        design: a.design.clone().unwrap_or_default(),
        acceptance_criteria: a.acceptance.clone().unwrap_or_default(),
        notes: a.notes.clone().unwrap_or_default(),
        issue_type: a.issue_type.clone(),
        priority: a.priority,
        status: a.pinned.then_some(Status::Pinned),
        assignee: a.assignee.clone(),
        labels: a.labels.clone(),
        parent,
        deps,
        external_ref: a.external_ref.clone(),
        estimated_minutes: a.estimate,
        due_at: a.due.as_deref().map(|s| parse_when(s, now)).transpose()?,
        defer_until: a.defer.as_deref().map(|s| parse_when(s, now)).transpose()?,
        metadata: a.metadata.as_deref().map(|m| json_object(m, "--metadata")).transpose()?,
        ephemeral: a.ephemeral,
    };
    let issue = tx.create_issue(new)?;
    let mut out = if a.claim {
        let claim = tx.claim(&issue.id, &ClaimOptions::default())?;
        claim_out(&claim, now).line(String::new())
    } else {
        Out::new(&issue)
    };
    out.text.insert(0, format!("✓ Created {}: {}", issue.id, issue.title));
    if issue.is_blocked {
        let blockers: Vec<String> = tx.blockers(&issue.id)?.into_iter().map(|b| b.id).collect();
        out.text.insert(1, format!("  blocked by: {}", blockers.join(", ")));
    }
    out.text.retain(|l| !l.is_empty());
    Ok(out.id(issue.id))
}

pub fn exec_update(tx: &mut WriteCtx<'_>, a: &UpdateArgs) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let now = tx.now();
    let patch = IssuePatch {
        title: a.title.clone(),
        description: a.description.clone(),
        design: a.design.clone(),
        acceptance_criteria: a.acceptance.clone(),
        notes: a.notes.clone(),
        append_notes: a.append_notes.clone(),
        status: a.status.as_deref().map(Status::parse).transpose()?,
        priority: a.priority,
        issue_type: a.issue_type.clone(),
        assignee: clearable(&a.assignee),
        external_ref: clearable(&a.external_ref),
        estimated_minutes: match &a.estimate {
            None => None,
            Some(s) if s.trim().is_empty() => Some(None),
            Some(s) => Some(Some(
                s.trim().parse::<i64>().map_err(|_| Error::invalid(format!("invalid estimate {s:?} (minutes)")))?,
            )),
        },
        due_at: clearable_time(&a.due, now)?,
        defer_until: clearable_time(&a.defer, now)?,
        metadata: a.metadata.as_deref().map(|m| json_object(m, "--metadata")).transpose()?,
        set_metadata: a.set_metadata.iter().map(|s| key_value(s)).collect::<Result<_>>()?,
        unset_metadata: a.unset_metadata.clone(),
        add_labels: a.add_labels.clone(),
        remove_labels: a.remove_labels.clone(),
        set_labels: a.set_labels.clone(),
        parent: match &a.parent {
            None => None,
            Some(p) if p.trim().is_empty() => Some(None),
            Some(p) => Some(Some(tx.resolve_id(p)?)),
        },
        ephemeral: a.ephemeral,
    };
    if patch.is_empty() {
        return Err(Error::invalid("nothing to update: pass at least one field flag"));
    }
    let out = tx.update_issue(&id, &patch, &guard_from(&a.guard)?, a.take_over)?;
    let text = if out.changed.is_empty() {
        format!("= {id} unchanged (revision {})", out.issue.revision)
    } else {
        format!("✓ Updated {id}: {} (revision {})", out.changed.join(", "), out.issue.revision)
    };
    // A claim moved to the caller (a takeover) comes with a new lease token,
    // which the old one no longer renews; a retry shows it again.
    let moved_to_me = a.assignee.is_some()
        && out.issue.status == Status::InProgress
        && out.issue.assignee.as_deref() == Some(tx.actor());
    let lease = if moved_to_me { tx.lease(&id)? } else { None };
    let mut o = Out::new(&out).line(text).id(id.clone());
    if let Some(l) = lease {
        o = o.line(format!(
            "  lease token {}, expires {} (renew: bd heartbeat {id} --token {})",
            l.token,
            rel(l.expires_at, now),
            l.token
        ));
        o.json["lease"] = serde_json::to_value(&l)?;
    }
    Ok(o)
}

pub fn exec_close(tx: &mut WriteCtx<'_>, a: &CloseArgs) -> Result<Out> {
    let opts = CloseOptions {
        reason: a.reason.clone(),
        outcome: Some(if a.failed { Outcome::Failed } else { Outcome::Done }),
        force: a.force,
        take_over: a.take_over,
        guard: guard_from(&a.guard)?,
        token: a.token,
    };
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    if ids.len() > 1 {
        // Every claim of another actor among them, before any close is refused for something else.
        tx.check_take_over(&ids, a.take_over, &format!("closing {}", ids.join(", ")))?;
    }
    // Deepest first, so children listed alongside their parent close before it.
    let depths = tx.depths(&ids)?;
    let mut keyed: Vec<_> = depths.into_iter().map(std::cmp::Reverse).zip(ids).collect();
    keyed.sort();
    keyed.dedup();
    let mut results = Vec::new();
    let mut out = Out::new(Value::Null);
    for (_, id) in keyed {
        let r = tx.close_issue(&id, &opts)?;
        if r.already_closed {
            out = out.line(format!("= {id} already closed"));
        } else {
            let outcome = if a.failed { " (failed)" } else { "" };
            out = out.line(format!("✓ Closed {id}{outcome}: {}", r.issue.title));
        }
        for u in &r.unblocked {
            out = out.line(format!("  ↳ unblocked {} [P{}] {}", u.id, u.priority, u.title));
        }
        for c in &r.completed {
            out = out.line(format!("  ✓ completed {} {}", c.id, c.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = one_or_many(&results);
    Ok(out)
}

pub fn exec_reopen(tx: &mut WriteCtx<'_>, a: &ReopenArgs) -> Result<Out> {
    let mut results = Vec::new();
    let mut out = Out::new(Value::Null);
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let r = tx.reopen_issue(&id, a.reason.as_deref())?;
        out = out.line(if r.already_open {
            format!("= {id} is not closed")
        } else {
            format!("✓ Reopened {id}: {}", r.issue.title)
        });
        for b in &r.newly_blocked {
            out = out.line(format!("  ↳ blocks again {} {}", b.id, b.title));
        }
        for p in &r.reopened {
            out = out.line(format!("  ↺ reopened {} {}", p.id, p.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = one_or_many(&results);
    Ok(out)
}

pub fn exec_defer(tx: &mut WriteCtx<'_>, a: &DeferArgs) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let now = tx.now();
    let until = a.until.as_deref().map(|s| parse_when(s, now)).transpose()?;
    let out = tx.defer_issue(&id, until)?;
    let text = match until {
        Some(t) => format!("❄ Deferred {id} until {t} ({})", rel(t, now)),
        None => format!("❄ Deferred {id} indefinitely (bd undefer {id} to resume)"),
    };
    Ok(Out::new(&out).line(text).id(id))
}

pub fn exec_undefer(tx: &mut WriteCtx<'_>, a: &IdArg) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let out = tx.undefer_issue(&id)?;
    let text = if out.changed.is_empty() { format!("= {id} was not deferred") } else { format!("✓ Undeferred {id}") };
    Ok(Out::new(&out).line(text).id(id))
}

pub fn exec_delete(tx: &mut WriteCtx<'_>, a: &DeleteArgs) -> Result<Out> {
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    let opts = DeleteOptions { cascade: a.cascade, force: a.force, take_over: a.take_over, dry_run: a.dry_run };
    let r = tx.delete_issues(&ids, &opts)?;
    let verb = if r.dry_run { "Would delete" } else { "✓ Deleted" };
    let mut out = Out::new(&r).line(format!("{verb} {} issue(s): {}", r.deleted.len(), r.deleted.join(", ")));
    if !r.detached.is_empty() {
        out = out.line(format!(
            "  {} edges from: {}",
            if r.dry_run { "would drop" } else { "dropped" },
            r.detached.join(", ")
        ));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    Ok(out)
}

pub fn cmd_show(app: &mut App, a: &ShowArgs) -> Result<()> {
    let (all, now) = app.read(|r| {
        let all = a.ids.iter().map(|raw| r.details(&r.resolve_id(raw)?)).collect::<Result<Vec<_>>>()?;
        Ok((all, r.now()))
    })?;
    if app.g.json && all.len() > 1 {
        app.print(Out::default().items(all));
    } else if app.g.json {
        app.print_json(&one_or_many(&all));
    } else if app.g.quiet {
        all.iter().for_each(|d| io::outln(&d.issue.id));
    } else {
        for (n, d) in all.iter().enumerate() {
            if n > 0 {
                io::outln("");
            }
            fmt::details(d, now).iter().for_each(io::outln);
        }
    }
    Ok(())
}

pub fn cmd_list(app: &mut App, a: &ListArgs) -> Result<()> {
    let json = app.g.json;
    let (issues, parents, now) = app.read(|r| {
        let q = ListQuery {
            filter: filter_from(r, &a.filter)?,
            statuses: a.status.iter().map(|s| Status::parse(s)).collect::<Result<_>>()?,
            all: a.all,
            blocked_only: a.blocked,
            search: a.search.clone(),
            sort: ListSort::parse(&a.sort)?,
            reverse: a.reverse,
            limit: (a.limit > 0).then_some(a.limit),
        };
        let issues = r.list(&q)?;
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

pub fn cmd_ready(app: &mut App, a: &ReadyArgs) -> Result<()> {
    let (issues, stats, now) = app.read(|r| {
        let filter = filter_from(r, &a.filter)?;
        let include_epics = a.include_epics || filter.types.iter().any(|t| t == "epic");
        let q = ReadyQuery {
            filter,
            sort: SortPolicy::parse(&a.sort)?,
            limit: (a.limit > 0).then_some(a.limit),
            include_deferred: a.include_deferred,
            include_epics,
        };
        Ok((r.ready(&q)?, r.stats()?, r.now()))
    })?;
    let mut out = Out::default();
    if issues.is_empty() {
        out = out.line(format!(
            "No ready work ({} blocked, {} in progress, {} deferred, {} waiting on children)",
            stats.blocked,
            stats.by_status.get("in_progress").copied().unwrap_or(0),
            stats.deferred,
            stats.waiting_on_children
        ));
    } else {
        out = out.line(format!("Ready work ({} shown, queue order):", issues.len()));
        for (n, i) in issues.iter().enumerate() {
            out = out.line(format!("{:>3}. {}", n + 1, fmt::issue_line(i, now)));
        }
    }
    out.ids = issues.iter().map(|i| i.id.clone()).collect();
    app.print(out.items(issues));
    Ok(())
}

pub fn cmd_blocked(app: &mut App, a: &BlockedArgs) -> Result<()> {
    let (blocked, now) = app.read(|r| {
        let f = filter_from(r, &a.filter)?;
        Ok((r.blocked(&f, (a.limit > 0).then_some(a.limit))?, r.now()))
    })?;
    let mut out = Out::default();
    if blocked.is_empty() {
        out = out.line("Nothing is blocked");
    }
    for b in &blocked {
        out = out.line(fmt::issue_line(&b.issue, now));
        for x in &b.blockers {
            out = out.line(format!("    ← {} {}: {}", x.id, x.title, x.detail));
        }
        out = out.id(b.issue.id.clone());
    }
    app.print(out.items(blocked));
    Ok(())
}
