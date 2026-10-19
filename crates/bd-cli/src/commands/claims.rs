//! Claims and leases: claim, heartbeat, release; leases, reclaim.

use bd_core::spec_context::{self, Governing};
use bd_core::specs;
use bd_core::time::parse_duration;
use bd_core::{
    Claim, ClaimOptions, Guard, Queries, ReadyQuery, ReclaimOptions, ReleaseOptions, Result, SortPolicy, Timestamp,
    WorkFilter, WriteCtx,
};
use serde_json::Value;

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::{self, rel};
use crate::io::printable;

use super::{filter_from, one_or_many};

/// How many governing specs a claim's text lists, and how many requirement
/// titles under each, and how long each title may be.
const CLAIM_SPECS: usize = 5;
const CLAIM_REQUIREMENTS: usize = 8;
const CLAIM_TITLE: usize = 100;

/// A claim's output; with `specs` (feature specs on), the specs governing
/// the claimed issue in its JSON and as lines after the lease line.
pub(super) fn claim_out(c: &Claim, now: Timestamp, specs: Option<&Governing>) -> Out {
    let verb = if c.already_held { "Already holding" } else { "Claimed" };
    let holder = c.issue.assignee.as_deref().map(|a| format!(" as {a}")).unwrap_or_default();
    let mut out = Out::new(c).line(format!("✓ {verb} {}{holder}: {}", c.issue.id, c.issue.title));
    if let Some(r) = &c.reclaimed {
        out = out.line(format!(
            "  reclaimed from {} (lease token {} expired {})",
            r.previous_holder,
            r.token,
            rel(r.expired_at, now)
        ));
    }
    out = out.line(format!(
        "  lease token {}, expires {} (renew: bd heartbeat {} --token {})",
        c.lease.token,
        rel(c.lease.expires_at, now),
        c.issue.id,
        c.lease.token
    ));
    if let Some(g) = specs {
        if let Some(m) = out.json.as_object_mut() {
            fmt::insert_specs(m, g, false);
        }
        out = out.lines(claim_spec_lines(g, &c.issue.id));
    }
    out.id(c.issue.id.clone())
}

/// The spec lines of a claim: per governing spec (the first
/// [`CLAIM_SPECS`]), its counts, the requirements to keep in mind (those
/// linked directly first, then the rest in force; the first
/// [`CLAIM_REQUIREMENTS`], titles cut to [`CLAIM_TITLE`] characters) and the
/// specs it inherits from. Non-goals are only counted; no truncation line
/// (the JSON carries `specs_truncated`).
fn claim_spec_lines(g: &Governing, issue_id: &str) -> Vec<String> {
    let plural = |n: usize, one: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") };
    let mut lines = Vec::new();
    for e in g.specs.iter().take(CLAIM_SPECS) {
        let areas = if e.areas.is_empty() { String::new() } else { format!(" [{}]", printable(&e.areas.join(", "))) };
        lines.push(format!(
            "  spec {} {}{areas}: {}, {} (bd spec show {})",
            e.id,
            printable(&e.title),
            plural(e.requirements.len(), "requirement"),
            plural(e.non_goals.len(), "non-goal"),
            e.id
        ));
        let mut listed: Vec<(&str, &str)> =
            e.linked.iter().filter(|p| !p.non_goal).map(|p| (p.id.as_str(), p.title.as_str())).collect();
        for r in &e.requirements {
            if !listed.iter().any(|(id, _)| *id == r.id) {
                listed.push((&r.id, &r.title));
            }
        }
        for (id, title) in listed.iter().take(CLAIM_REQUIREMENTS) {
            lines.push(format!("    - {id} {}", printable(&fmt::truncate(title, CLAIM_TITLE))));
        }
        if listed.len() > CLAIM_REQUIREMENTS {
            lines.push(format!("    … {} more", listed.len() - CLAIM_REQUIREMENTS));
        }
        if !e.inherits.is_empty() {
            lines.push(format!("    inherits from {}", e.inherits.join(", ")));
        }
    }
    if g.specs.len() > CLAIM_SPECS {
        lines.push(format!("  … {} more specs: bd show {issue_id}", g.specs.len() - CLAIM_SPECS));
    }
    lines
}

/// The specs governing `id` when feature specs are on: read-only lookups
/// inside the caller's write transaction (no event, nothing recomputed).
pub(super) fn claim_specs(tx: &WriteCtx<'_>, id: &str) -> Result<Option<Governing>> {
    if !specs::is_on(tx.conn())? {
        return Ok(None);
    }
    spec_context::governing(tx.conn(), id).map(Some)
}

pub fn exec_claim(tx: &mut WriteCtx<'_>, a: &ClaimArgs) -> Result<Out> {
    let now = tx.now();
    let ttl = a.ttl.as_deref().map(parse_duration).transpose()?;
    if a.next {
        let filter = filter_from(tx, &a.filter)?;
        let include_epics = filter.types.iter().any(|t| t == "epic");
        let q = ReadyQuery {
            filter,
            sort: SortPolicy::parse(&a.sort)?,
            limit: Some(1),
            include_deferred: false,
            include_epics,
        };
        match tx.claim_next(&q, &ClaimOptions { ttl, ..Default::default() })? {
            Some(c) => {
                let g = claim_specs(tx, &c.issue.id)?;
                Ok(claim_out(&c, now, g.as_ref()))
            }
            None => Ok(Out::new(Value::Null).line("No ready work to claim")),
        }
    } else {
        let id = tx.resolve_id(a.id.as_deref().unwrap_or_default())?;
        let opts = ClaimOptions {
            ttl,
            allow_blocked: a.allow_blocked,
            guard: Guard { if_revision: a.if_revision, ..Default::default() },
            token: a.token,
        };
        let c = tx.claim(&id, &opts)?;
        let g = claim_specs(tx, &c.issue.id)?;
        Ok(claim_out(&c, now, g.as_ref()))
    }
}

pub fn exec_heartbeat(tx: &mut WriteCtx<'_>, a: &HeartbeatArgs) -> Result<Out> {
    let now = tx.now();
    let ttl = a.ttl.as_deref().map(parse_duration).transpose()?;
    let mut leases = Vec::new();
    let mut out = Out::new(Value::Null);
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let lease = tx.heartbeat(&id, a.token, ttl)?;
        out = out
            .line(format!("♥ {id} lease renewed, expires {} (token {})", rel(lease.expires_at, now), lease.token))
            .id(id);
        leases.push(lease);
    }
    out.json = one_or_many(&leases);
    Ok(out)
}

pub fn exec_release(tx: &mut WriteCtx<'_>, a: &ReleaseArgs) -> Result<Out> {
    let opts = ReleaseOptions {
        reason: a.reason.clone(),
        take_over: a.take_over,
        guard: Guard { if_assignee: a.if_assignee.as_ref().map(|x| Some(x.trim().to_string())), ..Default::default() },
        token: a.token,
    };
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    if ids.len() > 1 {
        tx.check_release_take_over(&ids, a.take_over, &format!("releasing {}", ids.join(", ")))?;
    }
    let mut issues = Vec::new();
    let mut out = Out::new(Value::Null);
    for id in ids {
        let issue = tx.release(&id, &opts)?;
        out = out.line(format!("✓ Released {id} (now {})", issue.status)).id(id);
        issues.push(issue);
    }
    out.json = one_or_many(&issues);
    Ok(out)
}

pub fn cmd_leases(app: &mut App, a: &LeasesArgs) -> Result<()> {
    let (mut leases, now) = app.read(|r| Ok((r.leases()?, r.now())))?;
    if a.expired {
        leases.retain(|l| l.expired);
    }
    let mut out = Out::default();
    if leases.is_empty() {
        out = out.line("No leases");
    }
    for l in &leases {
        out = out
            .line(format!("◐ {} {} — {}", l.lease.issue_id, l.title, fmt::lease_text(&l.lease, now)))
            .id(l.lease.issue_id.clone());
    }
    app.print(out.items(leases));
    Ok(())
}

pub fn cmd_reclaim(app: &mut App, a: &ReclaimArgs) -> Result<()> {
    let grace = a.grace.as_deref().map(parse_duration).transpose()?;
    let (reclaimed, now) = app.write("reclaim", |tx| {
        let ids = a.ids.iter().map(|i| tx.resolve_id(i)).collect::<Result<Vec<_>>>()?;
        let opts = ReclaimOptions {
            grace,
            filter: WorkFilter {
                assignee: a.assignee.clone(),
                labels_all: a.labels.clone(),
                ids,
                ..Default::default()
            },
            dry_run: a.dry_run,
            take_over: a.take_over,
        };
        Ok((tx.reclaim_expired(&opts)?, tx.now()))
    })?;
    let verb = if a.dry_run { "would reclaim" } else { "↺ Reclaimed" };
    let mut out = Out::new(&reclaimed);
    if reclaimed.is_empty() {
        out = out.line("No stale leases past the grace window");
    }
    for r in &reclaimed {
        out = out
            .line(format!(
                "{verb} {} from {} (lease expired {}, token {})",
                r.issue_id,
                r.previous_holder,
                rel(r.expired_at, now),
                r.token
            ))
            .id(r.issue_id.clone());
    }
    app.print(out);
    Ok(())
}
