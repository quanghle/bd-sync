//! Issue lifecycle: create, update, close, reopen, defer, delete; show, list, ready, blocked.

use bd_core::asof::Point;
use bd_core::spec_context::{self, Coverage, Governing};
use bd_core::specs;
use bd_core::time::{parse_duration, parse_when};
use bd_core::{
    Claim, ClaimOptions, CloseOptions, DeleteOptions, Error, ExplainOptions, Guard, IssueBrief, IssueDetails,
    IssuePatch, ListQuery, ListSort, NewIssue, NextFrom, NotReady, Outcome, Queries, ReadCtx, Readiness, ReadyQuery,
    Result, SortPolicy, Status, WorkFilter, WriteCtx,
};
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::{self, rel};
use crate::io;

use super::claims::{claim_out, claim_specs};
use super::events::events_issue;
use super::{
    clearable, clearable_time, dep_spec, filter_from, filter_time, guard_from, json_object, key_value, one_or_many,
    time_filter_into,
};

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
        claim_out(&claim, now, None).line(String::new())
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
        via: None,
    };
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    // The next issue's query and --ttl, parsed before anything is written
    // (a bad one fails even when nothing would be closed); the search starts
    // under the first named issue's parent unless --parent says where.
    let ttl = a.next.ttl.as_deref().map(|t| parse_duration(t).and_then(bd_core::claims::validate_ttl)).transpose()?;
    let next = if a.claim_next || a.suggest_next {
        let q = next_query(tx, &a.next)?;
        let near = match (&q.filter.parent, ids.first()) {
            (None, Some(first)) => tx.parent(first)?,
            _ => None,
        };
        Some((q, near))
    } else {
        None
    };
    if ids.len() > 1 {
        // Every claim of another actor among them, before any close is refused for something else.
        tx.check_take_over(&ids, a.take_over, &format!("closing {}", ids.join(", ")))?;
    }
    // The issues named, in command-line order, each once: the order the
    // unlinked-spec hint (`unlinked_note`, run by the caller) lists them in.
    let mut named: Vec<String> = Vec::with_capacity(ids.len());
    for id in &ids {
        if !named.contains(id) {
            named.push(id.clone());
        }
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
    if specs::is_on(tx.conn())? {
        out.close_hint = named
            .iter()
            .filter(|id| results.iter().any(|r| &r.issue.id == *id && !r.already_closed))
            .cloned()
            .collect();
    }
    let closed = one_or_many(&results);
    let Some((q, near)) = next else {
        out.json = closed;
        return Ok(out);
    };
    let now = tx.now();
    let from_text = |from: NextFrom| match (from, &near) {
        (NextFrom::Siblings, Some(p)) => format!("from siblings under {p}"),
        _ => "from the queue".to_string(),
    };
    // The subtree searched for the issue found, if any.
    let searched = |from: NextFrom| match from {
        NextFrom::Siblings => near.clone(),
        NextFrom::Queue => q.filter.parent.clone(),
    };
    let mut json = json!({ "closed": closed, "next": Value::Null });
    if a.claim_next {
        if results.iter().all(|r| r.already_closed) {
            // A retried close must not claim a second issue.
            json["next_note"] = json!("nothing closed: not claiming");
            out = out.line("No issue closed: not claiming next");
        } else {
            match tx.claim_next_near(&q, near.as_deref(), &ClaimOptions { ttl, ..Default::default() })? {
                Some((c, from)) => {
                    let g = claim_specs(tx, &c.issue.id)?;
                    json["next"] = next_json(from, searched(from), &c.issue, Some(&c), g.as_ref());
                    let claimed = claim_out(&c, now, g.as_ref());
                    out = out.line(format!("→ Next ({}):", from_text(from))).lines(claimed.text).id(c.issue.id.clone());
                }
                None => out = out.line("No ready work to claim next"),
            }
        }
    } else {
        // The issue --claim-next would claim, dead claims it would reclaim first included.
        match tx.suggest_next(&q, near.as_deref())? {
            Some((issue, from)) => {
                json["next"] = next_json(from, searched(from), &issue, None, None);
                out = out
                    .line(format!(
                        "→ Suggested next ({}): {} (bd claim {})",
                        from_text(from),
                        fmt::issue_line(&issue, now),
                        issue.id
                    ))
                    .id(issue.id.clone());
            }
            None => out = out.line("No ready work to claim next"),
        }
    }
    out.json = json;
    Ok(out)
}

/// Most issues the unlinked-spec hint names before `+N more`.
const HINT_IDS: usize = 5;

/// With feature specs on, the stderr hint naming those of `ids` (in their
/// order) that, at call time, still exist, are closed, need a spec link and
/// have none: not exempt ([`specs::is_exempt`], `spec:none` included) and
/// not covered by a link. A walk cut short before a link
/// ([`Coverage::Unknown`]) counts as covered, so the hint never names work
/// it could not look at in full. Callers call it at the end of their write
/// transaction with the ids a close recorded in [`Out::close_hint`], so a
/// later operation of the same transaction that links one, marks it
/// `spec:none`, reopens it or deletes it leaves it out. Read-only (no SQL of
/// its own, no writes, events or `graph::recompute`), it never refuses: an
/// id that is gone is skipped. [`Out::note`] prints it only after commit.
pub fn unlinked_note(tx: &WriteCtx<'_>, ids: &[String]) -> Result<Option<String>> {
    if ids.is_empty() || !specs::is_on(tx.conn())? {
        return Ok(None);
    }
    let mut unlinked = Vec::new();
    for id in ids {
        let Some(issue) = tx.find_issue(id)? else {
            continue;
        };
        if issue.status != Status::Closed || specs::is_exempt(tx.conn(), &issue)? {
            continue;
        }
        if spec_context::covered(tx.conn(), id)? == Coverage::NotLinked {
            unlinked.push(id.as_str());
        }
    }
    if unlinked.is_empty() {
        return Ok(None);
    }
    let mut list = unlinked.iter().take(HINT_IDS).copied().collect::<Vec<_>>().join(", ");
    if unlinked.len() > HINT_IDS {
        list.push_str(&format!(" +{} more", unlinked.len() - HINT_IDS));
    }
    Ok(Some(format!(
        "hint: not linked to a feature spec: {list} (bd dep add <id> <spec or requirement> --type related, \
         or bd spec none <id> -r '<why>'; bd spec drift lists unlinked work)"
    )))
}

/// The ready query `bd close --claim-next`/`--suggest-next` searches, from
/// the subset of `bd claim --next`'s filters close takes.
fn next_query(tx: &WriteCtx<'_>, n: &NextArgs) -> Result<ReadyQuery> {
    let norm = |v: &[String]| v.iter().map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
    let filter = WorkFilter {
        assignee: n.assignee.clone(),
        unassigned: n.unassigned,
        types: norm(&n.types),
        labels_all: n.labels.clone(),
        parent: n.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?,
        ..Default::default()
    };
    let include_epics = filter.types.iter().any(|t| t == "epic");
    Ok(ReadyQuery {
        filter,
        sort: SortPolicy::parse(n.sort.as_deref().unwrap_or("priority"))?,
        limit: Some(1),
        include_deferred: false,
        include_epics,
    })
}

/// `next` in close's JSON: where the issue was found, the issue, and the
/// claim's lease (and what it reclaimed) when it was claimed, and with
/// `specs` (a claim with feature specs on) the specs governing it.
fn next_json(
    from: NextFrom,
    parent: Option<String>,
    issue: &bd_core::Issue,
    claim: Option<&Claim>,
    specs: Option<&Governing>,
) -> Value {
    let mut v = json!({ "from": from, "issue": issue });
    if let Some(p) = parent {
        v["parent"] = json!(p);
    }
    if let Some(c) = claim {
        v["lease"] = json!(c.lease);
        if let Some(r) = &c.reclaimed {
            v["reclaimed"] = json!(r);
        }
    }
    if let (Some(g), Some(m)) = (specs, v.as_object_mut()) {
        fmt::insert_specs(m, g, false);
    }
    v
}

pub fn exec_reopen(tx: &mut WriteCtx<'_>, a: &ReopenArgs) -> Result<Out> {
    let mut results = Vec::new();
    let mut out = Out::new(Value::Null);
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    for (id, r) in ids.iter().zip(tx.reopen_issues(&ids, a.reason.as_deref(), a.force)?) {
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
        out = out.id(id.clone());
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

/// Comments `bd show --brief` keeps without --comments-tail.
const BRIEF_COMMENTS: usize = 3;

pub fn cmd_show(app: &mut App, a: &ShowArgs) -> Result<()> {
    if let Some(when) = &a.as_of {
        return cmd_show_as_of(app, a, when);
    }
    if a.brief {
        return show_brief(app, a);
    }
    let (all, whys, govs, now) = app.read(|r| {
        let ids = a.ids.iter().map(|raw| r.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
        let all = ids.iter().map(|id| r.details(id)).collect::<Result<Vec<_>>>()?;
        Ok((all, whys(r, a, &ids)?, governing(r, &ids)?, r.now()))
    })?;
    // --comments-tail keeps the last N comments and says how many there are.
    let all: Vec<(IssueDetails, usize)> = all
        .into_iter()
        .map(|mut d| {
            let total = d.comments.len();
            if let Some(n) = a.comments_tail {
                d.comments.drain(..total.saturating_sub(n));
            }
            (d, total)
        })
        .collect();
    if app.g.json {
        let values: Vec<Value> = all
            .iter()
            .zip(why_values(&whys, all.len()))
            .enumerate()
            .map(|(n, ((d, total), why))| {
                let mut v = serde_json::to_value(d).unwrap_or(Value::Null);
                if let Some(m) = v.as_object_mut() {
                    if a.comments_tail.is_some() {
                        m.insert("comments_total".into(), Value::from(*total));
                    }
                    if let Some(why) = why {
                        m.insert("why".into(), why);
                    }
                    if let Some(g) = govs.as_ref().and_then(|v| v.get(n)) {
                        fmt::insert_specs(m, g, false);
                    }
                }
                v
            })
            .collect();
        if values.len() > 1 {
            app.print(Out::default().items(values));
        } else {
            app.print_json(&one_or_many(&values));
        }
    } else if app.g.quiet {
        all.iter().for_each(|(d, _)| io::outln(&d.issue.id));
    } else {
        for (n, (d, total)) in all.iter().enumerate() {
            if n > 0 {
                io::outln("");
            }
            fmt::details(d, now, *total, whys.get(n), govs.as_ref().and_then(|v| v.get(n))).iter().for_each(io::outln);
        }
    }
    Ok(())
}

/// `--why`: each issue's readiness, counted as plain `bd ready` counts it
/// (epics and gates left out); empty without `--why`.
fn whys(r: &ReadCtx<'_>, a: &ShowArgs, ids: &[String]) -> Result<Vec<Readiness>> {
    if !a.why {
        return Ok(Vec::new());
    }
    ids.iter().map(|id| r.explain(id, ExplainOptions::default())).collect()
}

/// With feature specs on, the specs governing each of `ids`; nothing with
/// them off, which reads only the config key.
fn governing(r: &ReadCtx<'_>, ids: &[String]) -> Result<Option<Vec<Governing>>> {
    if !specs::is_on(r.conn())? {
        return Ok(None);
    }
    ids.iter().map(|id| spec_context::governing(r.conn(), id)).collect::<Result<Vec<_>>>().map(Some)
}

/// The `why` value of each of `n` JSON objects: `{ready, reasons}`, or
/// nothing without `--why`.
fn why_values(whys: &[Readiness], n: usize) -> Vec<Option<Value>> {
    (0..n).map(|k| whys.get(k).map(|w| json!({"ready": w.ready, "reasons": w.reasons}))).collect()
}

fn show_brief(app: &mut App, a: &ShowArgs) -> Result<()> {
    let tail = a.comments_tail.unwrap_or(BRIEF_COMMENTS);
    let (all, whys, govs, now) = app.read(|r| {
        let ids = a.ids.iter().map(|raw| r.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
        let all = ids.iter().map(|id| r.show_brief(id, tail)).collect::<Result<Vec<_>>>()?;
        Ok((all, whys(r, a, &ids)?, governing(r, &ids)?, r.now()))
    })?;
    if app.g.json {
        let values: Vec<Value> = all
            .iter()
            .zip(why_values(&whys, all.len()))
            .enumerate()
            .map(|(n, (b, why))| {
                let mut v = serde_json::to_value(b).unwrap_or(Value::Null);
                if let Some(m) = v.as_object_mut() {
                    if let Some(why) = why {
                        m.insert("why".into(), why);
                    }
                    if let Some(g) = govs.as_ref().and_then(|v| v.get(n)) {
                        fmt::insert_specs(m, g, true);
                    }
                }
                v
            })
            .collect();
        if values.len() > 1 {
            app.print(Out::default().items(values));
        } else {
            app.print_json(&one_or_many(&values));
        }
    } else if app.g.quiet {
        all.iter().for_each(|b| io::outln(&b.brief.id));
    } else {
        for (n, b) in all.iter().enumerate() {
            if n > 0 {
                io::outln("");
            }
            fmt::show_brief(b, whys.get(n), now, govs.as_ref().and_then(|v| v.get(n))).iter().for_each(io::outln);
        }
    }
    Ok(())
}

/// `bd show --as-of`: each issue rebuilt from its events at a point.
fn cmd_show_as_of(app: &mut App, a: &ShowArgs, when: &str) -> Result<()> {
    let all = app.read(|r| {
        let point = Point::parse(when, r.now())?;
        // Deleted issues keep their history.
        a.ids.iter().map(|raw| r.issue_as_of(&events_issue(r, raw)?.0, point)).collect::<Result<Vec<_>>>()
    })?;
    if app.g.json && all.len() > 1 {
        app.print(Out::default().items(all));
    } else if app.g.json {
        app.print_json(&one_or_many(&all));
    } else if app.g.quiet {
        all.iter().for_each(|d| io::outln(&d.id));
    } else {
        for (n, d) in all.iter().enumerate() {
            if n > 0 {
                io::outln("");
            }
            fmt::as_of(d).iter().for_each(io::outln);
        }
    }
    Ok(())
}

/// What `bd compact --summary` reads: `Some("-")` for stdin, `Some(path)`
/// for `@path`, `None` for the summary itself.
pub fn summary_input(summary: &str) -> Option<&str> {
    match summary {
        "-" => Some("-"),
        s => s.strip_prefix('@'),
    }
}

/// The apply form of `bd compact`: `summary` replaces the closed issue's
/// text if it is still at `if_revision`.
pub fn exec_compact(tx: &mut WriteCtx<'_>, raw: &str, summary: &str, if_revision: i64) -> Result<Out> {
    let id = tx.resolve_id(raw)?;
    let guard = Guard { if_revision: Some(if_revision), ..Default::default() };
    let out = tx.compact_issue(&id, summary, &guard)?;
    let line = format!(
        "✓ Compacted {id} (level {}): {} -> {} bytes; `bd history {id} --diff` shows the original",
        out.level, out.original_size, out.size
    );
    Ok(Out::new(&out).line(line).id(id))
}

/// `compact` in `bd batch`: the summary is on the line, as the batch's own
/// input is the stdin or file `-` and `@FILE` would read.
pub fn exec_batch_compact(tx: &mut WriteCtx<'_>, a: &BatchCompactArgs) -> Result<Out> {
    if summary_input(&a.summary).is_some() {
        return Err(Error::invalid(
            "compact in bd batch takes the summary itself: --summary - and --summary @FILE are not read inside a batch",
        ));
    }
    let raw = a.id.as_deref().or(a.apply.as_deref()).ok_or_else(|| Error::invalid("compact needs an issue id"))?;
    exec_compact(tx, raw, &a.summary, a.if_revision)
}

/// `bd compact`: list candidates, apply a summary, or count.
pub fn cmd_issue_compact(app: &mut App, a: &IssueCompactArgs) -> Result<()> {
    let older_than = parse_duration(a.older_than.as_deref().unwrap_or("30d"))?;
    if let Some(raw) = &a.apply {
        let summary = match a.summary.as_deref() {
            Some(s) => match summary_input(s) {
                Some(input) => io::read_input(input)?,
                None => s.to_string(),
            },
            None => return Err(Error::invalid("--apply needs --summary")),
        };
        let if_revision = a.if_revision.ok_or_else(|| Error::invalid("--apply needs --if-revision"))?;
        let out = app.write("compact", |tx| exec_compact(tx, raw, &summary, if_revision))?;
        app.print(out);
        return Ok(());
    }
    if a.stats {
        let s = app.read(|r| r.compact_stats(older_than))?;
        let levels = s.by_level.iter().map(|(l, n)| format!("level {l}: {n}")).collect::<Vec<_>>().join(", ");
        let out = Out::new(&s)
            .line(format!("closed issues:     {}", s.closed))
            .line(format!(
                "compacted:         {}{}",
                s.compacted,
                if levels.is_empty() { String::new() } else { format!(" ({levels})") }
            ))
            .line(format!("original bytes:    {}", s.original_bytes))
            .line(format!("current bytes:     {}", s.current_bytes))
            .line(format!("saved bytes:       {}", s.saved_bytes))
            .line(format!("candidates:        {} ({} bytes)", s.candidates, s.candidate_bytes));
        app.print(out);
        return Ok(());
    }
    let limit = (a.limit > 0).then_some(a.limit);
    let candidates = app.read(|r| r.compact_candidates(older_than, limit))?;
    let mut out = Out::default();
    for c in &candidates {
        out = out
            .line(format!("{} {} (closed {}, revision {}, {} bytes)", c.id, c.title, c.closed_at, c.revision, c.size));
        out = out.line(format!("  apply: bd compact --apply {} --if-revision {} --summary -", c.id, c.revision));
        out = out.lines(fmt::text_blocks(&[
            ("Description", &c.description),
            ("Design", &c.design),
            ("Acceptance criteria", &c.acceptance_criteria),
            ("Notes", &c.notes),
        ]));
        out = out.line(String::new()).id(c.id.clone());
    }
    out = out.line(match candidates.len() {
        0 => "No issues to compact".to_string(),
        n => format!("-- {n} candidate(s)"),
    });
    app.print(out.items(candidates));
    Ok(())
}

pub fn cmd_list(app: &mut App, a: &ListArgs) -> Result<()> {
    let json = app.g.json;
    let (issues, parents, briefs, now) = app.read(|r| {
        let mut filter = filter_from(r, &a.filter)?;
        time_filter_into(r, &a.times, &mut filter)?;
        filter.closed_after = filter_time("closed-after", &a.closed_after, r.now())?;
        filter.closed_before = filter_time("closed-before", &a.closed_before, r.now())?;
        // Only closed issues have a closed time, and list hides them by default.
        let closed_bound = filter.closed_after.is_some() || filter.closed_before.is_some();
        let q = ListQuery {
            filter,
            statuses: a.status.iter().map(|s| Status::parse(s)).collect::<Result<_>>()?,
            all: a.all || (closed_bound && a.status.is_empty()),
            blocked_only: a.blocked,
            search: a.search.clone(),
            sort: ListSort::parse(&a.sort)?,
            reverse: a.reverse,
            limit: (a.limit > 0).then_some(a.limit),
        };
        let issues = r.list(&q)?;
        let briefs = if a.brief { r.briefs(&issues)? } else { Vec::new() };
        let parents =
            if json || a.brief { Vec::new() } else { issues.iter().map(|i| r.parent(&i.id)).collect::<Result<_>>()? };
        Ok((issues, parents, briefs, r.now()))
    })?;
    let n = issues.len();
    let mut out = Out { ids: issues.iter().map(|i| i.id.clone()).collect(), ..Out::default() };
    if a.brief {
        if !json {
            out = out.lines(briefs.iter().map(fmt::brief_line));
            out = out.line(if n == 0 { "No issues".to_string() } else { format!("-- {n} issue(s)") });
        }
        app.print(out.items(briefs));
        return Ok(());
    }
    if !json {
        let lines = fmt::nest(&issues, &parents)
            .into_iter()
            .map(|(depth, i)| format!("{}{}", bd_core::graph::indent(depth), fmt::issue_line(i, now)));
        out = out.lines(lines).line(if n == 0 { "No issues".to_string() } else { format!("-- {n} issue(s)") });
    }
    app.print(out.items(issues));
    Ok(())
}

pub fn cmd_ready(app: &mut App, a: &ReadyArgs) -> Result<()> {
    if a.explain {
        return ready_explained(app, a);
    }
    let (issues, more, briefs, stats, now) = app.read(|r| {
        let q = ready_query(r, a)?;
        let (issues, more) = cut(r.ready(&q)?, a.limit);
        let briefs = if a.brief { r.briefs(&issues)? } else { Vec::new() };
        Ok((issues, more, briefs, r.stats()?, r.now()))
    })?;
    let mut out = Out::default();
    if issues.is_empty() {
        out = out.line(no_ready_work(&stats));
    } else {
        out = out.line(format!("Ready work ({} shown, queue order):", issues.len()));
        if a.brief {
            for (n, b) in briefs.iter().enumerate() {
                out = out.line(format!("{:>3}. {}", n + 1, fmt::brief_line(b)));
            }
        } else {
            for (n, i) in issues.iter().enumerate() {
                out = out.line(format!("{:>3}. {}", n + 1, fmt::issue_line(i, now)));
            }
        }
        if more {
            out = out.line(MORE_READY);
        }
    }
    out.ids = issues.iter().map(|i| i.id.clone()).collect();
    if a.brief {
        app.print(out.items(briefs));
    } else {
        app.print(out.items(issues));
    }
    Ok(())
}

const MORE_READY: &str = "-- more ready issues not shown: raise -n (-n 0 for all)";

/// `bd ready`'s query, asking for one more issue than `-n` shows, to tell
/// whether the list was cut.
fn ready_query(r: &ReadCtx<'_>, a: &ReadyArgs) -> Result<ReadyQuery> {
    let mut filter = filter_from(r, &a.filter)?;
    time_filter_into(r, &a.times, &mut filter)?;
    let include_epics = a.include_epics || filter.types.iter().any(|t| t == "epic");
    Ok(ReadyQuery {
        filter,
        sort: SortPolicy::parse(&a.sort)?,
        limit: (a.limit > 0).then(|| a.limit.saturating_add(1)),
        include_deferred: a.include_deferred,
        include_epics,
    })
}

/// The first `limit` of `items` (all with 0), and whether there were more.
fn cut<T>(mut items: Vec<T>, limit: usize) -> (Vec<T>, bool) {
    let more = limit > 0 && items.len() > limit;
    if more {
        items.truncate(limit);
    }
    (items, more)
}

fn no_ready_work(stats: &bd_core::metrics::Stats) -> String {
    format!(
        "No ready work ({} blocked, {} in progress, {} deferred, {} waiting on children)",
        stats.blocked,
        stats.by_status.get("in_progress").copied().unwrap_or(0),
        stats.deferred,
        stats.waiting_on_children
    )
}

/// The brief issue's JSON object with `extra`'s keys added.
fn brief_with(b: &IssueBrief, extra: Value) -> Value {
    let mut v = serde_json::to_value(b).unwrap_or(Value::Null);
    if let (Some(m), Value::Object(extra)) = (v.as_object_mut(), extra) {
        m.extend(extra);
    }
    v
}

/// `bd ready --explain`: the ready issues with their order keys, then the
/// open issues the same filters match that are not ready, with the reasons;
/// each list bounded by `-n`. Reads each not-ready issue's lookups, never a
/// recompute.
fn ready_explained(app: &mut App, a: &ReadyArgs) -> Result<()> {
    struct Explained {
        ready: Vec<(IssueBrief, String)>,
        more_ready: bool,
        not_ready: Vec<(IssueBrief, Vec<NotReady>)>,
        more_not_ready: bool,
        sort: SortPolicy,
        stats: bd_core::metrics::Stats,
        now: bd_core::Timestamp,
    }
    let e = app.read(|r| {
        let q = ready_query(r, a)?;
        let now = r.now();
        let (ready, more_ready) = cut(r.ready(&q)?, a.limit);
        let (not_ready, more_not_ready) = cut(r.not_ready(&q)?, a.limit);
        let opts = ExplainOptions {
            include_deferred: q.include_deferred,
            include_epics: q.include_epics,
            include_gates: q.filter.types.iter().any(|t| t == bd_core::GATE_TYPE),
        };
        let orders = ready.iter().map(|i| bd_core::ready::order_key(i, q.sort, now));
        let ready = r.briefs(&ready)?.into_iter().zip(orders).collect();
        let reasons = not_ready.iter().map(|i| Ok(r.explain(&i.id, opts)?.reasons)).collect::<Result<Vec<_>>>()?;
        let not_ready = r.briefs(&not_ready)?.into_iter().zip(reasons).collect();
        Ok(Explained { ready, more_ready, not_ready, more_not_ready, sort: q.sort, stats: r.stats()?, now })
    })?;
    let mut out = Out::new(json!({
        "sort": e.sort,
        "ready": e.ready.iter().enumerate().map(|(n, (b, order))| brief_with(b, json!({"rank": n + 1, "order": order}))).collect::<Vec<_>>(),
        "more_ready": e.more_ready,
        "not_ready": e.not_ready.iter().map(|(b, reasons)| brief_with(b, json!({"reasons": reasons}))).collect::<Vec<_>>(),
        "more_not_ready": e.more_not_ready,
    }));
    out.ids = e.ready.iter().map(|(b, _)| b.id.clone()).collect();
    if e.ready.is_empty() {
        out = out.line(no_ready_work(&e.stats));
    } else {
        out = out.line(format!("Ready work ({} shown, queue order):", e.ready.len()));
        for (n, (b, order)) in e.ready.iter().enumerate() {
            out = out.line(format!("{:>3}. {}", n + 1, fmt::brief_line(b)));
            out = out.line(format!("       order: {order}"));
        }
        if e.more_ready {
            out = out.line(MORE_READY);
        }
    }
    if e.not_ready.is_empty() {
        out = out.line("Not ready: none");
    } else {
        out = out.line(format!("Not ready ({} shown):", e.not_ready.len()));
        for (b, reasons) in &e.not_ready {
            let mut lines = vec![format!("  {}", fmt::brief_line(b))];
            for reason in reasons {
                fmt::reason_lines(reason, &b.id, e.now, "    ", &mut lines);
            }
            out = out.lines(lines);
        }
        if e.more_not_ready {
            out = out.line("-- more issues that are not ready not shown: raise -n (-n 0 for all)");
        }
    }
    app.print(out);
    Ok(())
}

/// Most pairs `find-duplicates` returns through `bd serve`, whatever `-n` asks.
const MAX_SERVED_PAIRS: usize = 1000;

pub fn cmd_find_duplicates(app: &mut App, a: &FindDuplicatesArgs) -> Result<()> {
    let issues = app.read(|r| r.list(&ListQuery::default()))?;
    let limit = if crate::io::serving() {
        Some(if a.limit == 0 { MAX_SERVED_PAIRS } else { a.limit.min(MAX_SERVED_PAIRS) })
    } else if a.limit == 0 {
        None
    } else {
        Some(a.limit)
    };
    let pairs = bd_core::duplicates::similar_pairs(&issues, a.threshold, limit);
    let mut out = Out::default();
    if pairs.is_empty() {
        out = out.line("No likely duplicates");
    }
    for p in &pairs {
        out = out
            .line(format!("{:.2}  {}  {}", p.score, p.a.id, p.a.title))
            .line(format!("{:6}{}  {}", "", p.b.id, p.b.title));
    }
    if !pairs.is_empty() {
        out = out.line(format!(
            "-- {} likely duplicate pair(s); close one with bd duplicate <id> --of <canonical>",
            pairs.len()
        ));
    }
    app.print(out.items(pairs));
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
