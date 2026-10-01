//! Transactional event history.
//!
//! Every mutation appends its events in the same transaction as the change,
//! so the log and the state can never disagree. Sequence numbers are gapless
//! and commit-ordered: a consumer that tails `seq > cursor` never misses a
//! row. Pruning removes the oldest rows; a cursor that falls behind the
//! retained window is reported as truncated rather than silently skipped.

use std::time::Duration;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::Serialize;
use serde_json::json;

use crate::config;
use crate::error::{Error, Result};
use crate::filter::{placeholders, text_values};
use crate::model::{Event, empty_object};
use crate::store::{WriteCtx, bump_counter_in};

fn event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    let data: String = r.get(6)?;
    Ok(Event {
        seq: r.get(0)?,
        tx: r.get(1)?,
        ts: r.get(2)?,
        actor: r.get(3)?,
        op: r.get(4)?,
        issue_id: r.get(5)?,
        data: serde_json::from_str(&data).unwrap_or_else(|_| empty_object()),
    })
}

/// Highest sequence number ever allocated (0 if none).
pub fn head(conn: &Connection) -> Result<i64> {
    Ok(conn
        .prepare_cached("SELECT seq FROM sqlite_sequence WHERE name = 'events'")?
        .query_row([], |r| r.get(0))
        .optional()?
        .unwrap_or(0))
}

/// Oldest retained sequence number (`head + 1` when the log is empty).
pub fn floor(conn: &Connection) -> Result<i64> {
    let min: Option<i64> = conn.prepare_cached("SELECT MIN(seq) FROM events")?.query_row([], |r| r.get(0))?;
    match min {
        Some(m) => Ok(m),
        None => Ok(head(conn)? + 1),
    }
}

#[derive(Clone, Debug, Default)]
pub struct EventQuery {
    /// Strict cursor: return events with `seq > since`; fails with
    /// `EventsTruncated` if events after the cursor were pruned.
    /// `None` = the most recent `limit` events.
    pub since: Option<i64>,
    pub limit: Option<usize>,
    pub issue_id: Option<String>,
    pub ops: Vec<String>,
    pub actor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub head: i64,
    pub floor: i64,
}

pub fn query(conn: &Connection, q: &EventQuery) -> Result<EventPage> {
    let head = head(conn)?;
    let floor = floor(conn)?;
    if let Some(since) = q.since {
        if since < 0 {
            return Err(Error::invalid("event cursor must be >= 0"));
        }
        if since < floor - 1 && since < head {
            return Err(Error::EventsTruncated { since, floor });
        }
    }
    let mut conds = String::new();
    let mut params: Vec<SqlValue> = Vec::new();
    if let Some(since) = q.since {
        conds.push_str(" AND seq > ?");
        params.push(SqlValue::Integer(since));
    }
    if let Some(id) = &q.issue_id {
        conds.push_str(" AND issue_id = ?");
        params.push(SqlValue::Text(id.clone()));
    }
    if !q.ops.is_empty() {
        conds.push_str(&format!(" AND op IN {}", placeholders(q.ops.len())));
        params.extend(text_values(&q.ops));
    }
    if let Some(actor) = &q.actor {
        conds.push_str(" AND actor = ?");
        params.push(SqlValue::Text(actor.clone()));
    }
    let cols = "seq, tx, ts, actor, op, issue_id, data";
    let sql = match (q.since, q.limit) {
        (Some(_), Some(n)) => {
            params.push(SqlValue::Integer(n as i64));
            format!("SELECT {cols} FROM events WHERE 1=1{conds} ORDER BY seq LIMIT ?")
        }
        (Some(_), None) => format!("SELECT {cols} FROM events WHERE 1=1{conds} ORDER BY seq"),
        (None, n) => {
            params.push(SqlValue::Integer(n.unwrap_or(50) as i64));
            format!("SELECT * FROM (SELECT {cols} FROM events WHERE 1=1{conds} ORDER BY seq DESC LIMIT ?) ORDER BY seq")
        }
    };
    let mut stmt = conn.prepare_cached(&sql)?;
    let events = stmt.query_map(params_from_iter(params), event_from_row)?.collect::<rusqlite::Result<_>>()?;
    Ok(EventPage { events, head, floor })
}

/// Full retained history of one issue, oldest first.
pub fn history(conn: &Connection, issue_id: &str) -> Result<Vec<Event>> {
    let mut stmt = conn
        .prepare_cached("SELECT seq, tx, ts, actor, op, issue_id, data FROM events WHERE issue_id = ?1 ORDER BY seq")?;
    let rows = stmt.query_map([issue_id], event_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Events grouped by op with counts, optionally only since a timestamp.
pub fn op_counts(conn: &Connection, since_ts: Option<i64>) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare_cached("SELECT op, COUNT(*) FROM events WHERE ts >= ?1 GROUP BY op ORDER BY op")?;
    let rows = stmt.query_map([since_ts.unwrap_or(i64::MIN)], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[derive(Clone, Debug, Default)]
pub struct PruneOptions {
    /// Delete events with `seq < before`.
    pub before: Option<i64>,
    /// Delete events older than this.
    pub older_than: Option<Duration>,
    /// Keep at most this many of the newest events.
    pub keep: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PruneOutcome {
    pub deleted: u64,
    pub floor: i64,
    pub head: i64,
}

/// Lowest seq that must survive under `opts` (everything below is pruned).
/// Criteria combine conservatively: an event survives if any criterion keeps it.
fn prune_bound(conn: &Connection, opts: &PruneOptions, now_ms: i64) -> Result<Option<i64>> {
    let mut bound: Option<i64> = opts.before;
    let mut tighten = |b: i64| bound = Some(bound.map_or(b, |x| x.min(b)));
    if let Some(age) = opts.older_than {
        let cutoff = now_ms - i64::try_from(age.as_millis()).unwrap_or(i64::MAX);
        let first_kept: Option<i64> =
            conn.prepare_cached("SELECT MIN(seq) FROM events WHERE ts >= ?1")?.query_row([cutoff], |r| r.get(0))?;
        tighten(first_kept.unwrap_or(head(conn)? + 1));
    }
    if let Some(keep) = opts.keep {
        let first_kept: Option<i64> = conn
            .prepare_cached("SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1")?
            .query_row([keep.saturating_sub(1) as i64], |r| r.get(0))
            .optional()?;
        if keep == 0 {
            tighten(head(conn)? + 1);
        } else if let Some(s) = first_kept {
            tighten(s);
        }
    }
    Ok(bound)
}

impl WriteCtx<'_> {
    /// Delete old events. Records a `pruned` event (which itself survives).
    pub fn prune_events(&mut self, opts: &PruneOptions) -> Result<PruneOutcome> {
        let Some(bound) = prune_bound(self.conn(), opts, self.now().millis())? else {
            return Err(Error::invalid("nothing to prune: pass before, older_than, or keep"));
        };
        let deleted = self.conn().prepare_cached("DELETE FROM events WHERE seq < ?1")?.execute([bound])? as u64;
        if deleted > 0 {
            self.emit("pruned", None, json!({ "before": bound, "deleted": deleted }))?;
        }
        Ok(PruneOutcome { deleted, floor: floor(self.conn())?, head: head(self.conn())? })
    }

    /// Apply `events.retain_days` / `events.retain_rows`, at most once per
    /// 512 new events. Called by the store after successful writes.
    pub(crate) fn auto_prune_events(&mut self) -> Result<()> {
        let days = config::retain_days(self.conn())?;
        let rows = config::retain_rows(self.conn())?;
        if days == 0 && rows == 0 {
            return Ok(());
        }
        let head = head(self.conn())?;
        let mark: i64 = self
            .conn()
            .prepare_cached("SELECT value FROM counters WHERE name = 'events_prune_mark'")?
            .query_row([], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        if head - mark < 512 {
            return Ok(());
        }
        let opts = PruneOptions {
            before: None,
            older_than: (days > 0).then(|| Duration::from_secs(days * 86_400)),
            keep: (rows > 0).then_some(rows),
        };
        if let Some(bound) = prune_bound(self.conn(), &opts, self.now().millis())? {
            self.conn().prepare_cached("DELETE FROM events WHERE seq < ?1")?.execute([bound])?;
        }
        self.conn()
            .prepare_cached(
                "INSERT INTO counters (name, value) VALUES ('events_prune_mark', ?1)
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            )?
            .execute(params![head])?;
        bump_counter_in(self.conn(), "auto_prunes", 1)?;
        Ok(())
    }
}
