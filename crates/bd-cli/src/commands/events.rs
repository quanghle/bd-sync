//! `bd events` and `bd history`.

use std::io::Write;
use std::time::Duration;

use bd_core::time::parse_duration;
use bd_core::{Error, EventQuery, PruneOptions, Queries, Result};

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt;
use crate::io;

/// Events `bd events` reads and prints at a time.
const EVENT_BATCH: usize = 1000;

pub fn cmd_events(app: &mut App, a: &EventsArgs) -> Result<()> {
    if let Some(EventsAction::Prune(p)) = &a.action {
        io::require_admin("events prune")?;
        let opts = PruneOptions {
            before: p.before,
            older_than: p.older_than.as_deref().map(parse_duration).transpose()?,
            keep: p.keep,
        };
        let r = app.write("events.prune", |tx| tx.prune_events(&opts))?;
        let out = Out::new(&r).line(format!("✓ Pruned {} event(s); retained seq {}..={}", r.deleted, r.floor, r.head));
        app.print(out);
        return Ok(());
    }
    let mut q = app.read(|r| event_query(r, a))?;
    if let Some(id) = &q.issue_id {
        io::issue(id);
    }
    if a.follow {
        // Remote clients follow with `--wait` requests instead, which bd
        // serve answers without holding a command slot while they wait.
        io::require_local("events --follow")?;
    }
    // Under bd serve, the server waited before running the command.
    if let Some(wait) = a.wait.filter(|_| !io::serving()) {
        q.since = Some(wait_for_events(app, &q, wait, a.interval_ms)?);
    }
    let json = app.g.json;
    let print = |w: &mut dyn Write, events: &[bd_core::Event]| -> std::io::Result<()> {
        for e in events {
            match json {
                true => writeln!(w, "{}", serde_json::to_string(e).unwrap_or_default())?,
                false => writeln!(w, "{}", fmt::event_line(e))?,
            }
        }
        Ok(())
    };
    // A batch at a time, so that a long page (`--since` without `--limit`) is never whole in memory; in one read
    // transaction, so that it is the same page. Output that can no longer be written (a closed pipe, a client
    // gone) ends the command quietly, as no one reads the rest.
    let mut last = None;
    let mut closed = false;
    let read = io::with_stdout(|w| {
        let mut w = std::io::BufWriter::new(w);
        let read = app.read(|r| {
            r.events_each(&q, EVENT_BATCH, &mut |events| {
                print(&mut w, events).inspect_err(|_| closed = true)?;
                last = events.last().map(|e| e.seq);
                Ok(())
            })
        });
        closed |= w.flush().is_err();
        read
    });
    let head = match read {
        _ if closed => return Ok(()),
        Err(e @ Error::EventsTruncated { floor, .. }) => {
            // A follower that fell behind continues at the oldest event kept.
            io::cursor(floor - 1);
            return Err(e);
        }
        read => read?.0,
    };
    let mut cursor = last.unwrap_or(head.max(q.since.unwrap_or(0)));
    if !a.follow {
        io::cursor(cursor);
        return Ok(());
    }
    q.limit = Some(1000);
    loop {
        std::thread::sleep(Duration::from_millis(a.interval_ms.max(10)));
        q.since = Some(cursor);
        let page = app.read(|r| r.events(&q))?;
        if let Some(last) = page.events.last() {
            cursor = last.seq;
        } else {
            cursor = cursor.max(page.head);
        }
        if io::with_stdout(|w| print(w, &page.events)).is_err() {
            return Ok(());
        }
    }
}

/// The query `bd events` runs for `a`: its cursor, limit and filters, with
/// `--issue` resolved by [`events_issue`], so a follower of a deleted issue
/// sees its deletion and is not cut off by it.
pub fn event_query(r: &bd_core::ReadCtx<'_>, a: &EventsArgs) -> Result<EventQuery> {
    let issue_id = match &a.issue {
        Some(raw) => Some(events_issue(r, raw)?.0),
        None => None,
    };
    Ok(EventQuery { since: a.since, limit: a.limit, issue_id, ops: a.ops.clone(), actor: a.by_actor.clone() })
}

/// The issue whose events `bd events --issue` and `bd history` read, and
/// whether it still exists: a deleted issue keeps its events. An exact id,
/// as given and then with the workspace prefix (`1` for `t-1`), wins whether
/// its issue exists or only its events do, so a deleted issue never resolves
/// to the issues its id is a prefix of (`t-1` of `t-10`, `bd-a1b2` of
/// `bd-a1b2.1`); otherwise a unique prefix of an existing issue's id.
fn events_issue(r: &bd_core::ReadCtx<'_>, raw: &str) -> Result<(String, bool)> {
    let raw = raw.trim();
    let resolved = r.resolve_id(raw);
    let prefixed = format!("{}-{raw}", bd_core::config::prefix(r.conn())?);
    for exact in [raw, prefixed.as_str()] {
        if resolved.as_ref().is_ok_and(|id| id == exact) {
            return Ok((exact.to_string(), true));
        }
        if has_events(r, exact)? {
            return Ok((exact.to_string(), false));
        }
    }
    resolved.map(|id| (id, true))
}

fn has_events(r: &bd_core::ReadCtx<'_>, issue: &str) -> Result<bool> {
    let q = EventQuery { limit: Some(1), issue_id: Some(issue.to_string()), ..Default::default() };
    Ok(!r.events(&q)?.events.is_empty())
}

/// Whether an event matching `q`'s filters follows `cursor`; and the events head.
pub fn events_after(r: &bd_core::ReadCtx<'_>, q: &EventQuery, cursor: i64) -> Result<(bool, i64)> {
    let page = r.events(&EventQuery { since: Some(cursor), limit: Some(1), ..q.clone() })?;
    Ok((!page.events.is_empty(), page.head))
}

/// `events --wait` here: poll every `interval_ms` until an event matching
/// `q` follows its cursor, or `wait` has passed. Returns the cursor to list
/// from: past the events the filters skipped meanwhile, which retention may
/// delete without failing the listing.
fn wait_for_events(app: &mut App, q: &EventQuery, wait: Duration, interval_ms: u64) -> Result<i64> {
    let started = std::time::Instant::now();
    let mut cursor = q.since.unwrap_or(0);
    loop {
        let (found, head) = app.read(|r| events_after(r, q, cursor))?;
        let left = wait.saturating_sub(started.elapsed());
        if found || left.is_zero() {
            return Ok(cursor);
        }
        // Nothing up to the head matched: later checks start there.
        cursor = cursor.max(head);
        std::thread::sleep(Duration::from_millis(interval_ms.max(10)).min(left));
    }
}

pub fn cmd_history(app: &mut App, a: &HistoryArgs) -> Result<()> {
    let (id, exists, events) = app.read(|r| {
        // Deleted issues keep their history.
        let (id, exists) = events_issue(r, &a.id)?;
        let events = r.history(&id)?;
        Ok((id, exists, events))
    })?;
    if events.is_empty() && !exists {
        return Err(Error::not_found("issue", id));
    }
    let mut out = Out::default();
    out = if events.is_empty() {
        out.line(format!("No retained history for {id} (events were pruned)"))
    } else {
        out.line(format!("History of {id} ({} events):", events.len()))
    };
    for e in &events {
        out = out.line(fmt::event_line(e)).id(e.seq.to_string());
    }
    app.print(out.items(events));
    Ok(())
}
