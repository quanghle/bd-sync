//! Hierarchy views: an epic's progress over its subtree, the epics ready to
//! close, an issue's children, stale work, and text references to issues
//! that do not exist.
//!
//! The walks start from the edges and reach issues by id (`CROSS JOIN`,
//! `INDEXED BY sqlite_autoindex_issues_1`), as [`crate::graph`]'s do, so
//! their plans hold whatever statistics a database has.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use rusqlite::{Connection, params};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::ids;
use crate::issues::{self, ISSUE_COLUMN_COUNT, ISSUE_COLUMNS, SUBTREE_CTE, issue_from_row};
use crate::model::{Issue, Status};
use crate::rename::{id_tokens, is_id_char};
use crate::time::Timestamp;

/// Progress of an issue's subtree (`bd epic status`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EpicStatus {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub issue_type: String,
    /// Every issue below, at any depth.
    pub total: i64,
    pub closed: i64,
    pub open: i64,
    pub in_progress: i64,
    /// Live descendants (not closed or pinned) with the materialized blocked
    /// flag set: these overlap `open` and `in_progress`.
    pub blocked: i64,
    /// `floor(100 * closed / total)`; none without descendants.
    pub percent: Option<u8>,
    /// An epic, not closed, with children, every direct child closed: what
    /// [`close_eligible`] lists.
    pub close_eligible: bool,
}

/// The progress of `id`'s subtree, counted recursively.
pub fn epic_status(conn: &Connection, id: &str) -> Result<EpicStatus> {
    let issue = issues::require(conn, id)?;
    let sql = format!(
        "{SUBTREE_CTE} SELECT COUNT(*), COALESCE(SUM(i.status = 'closed'), 0), COALESCE(SUM(i.status = 'open'), 0),
            COALESCE(SUM(i.status = 'in_progress'), 0),
            COALESCE(SUM(i.is_blocked = 1 AND i.status NOT IN ('closed','pinned')), 0)
         FROM sub CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = sub.id"
    );
    let (total, closed, open, in_progress, blocked): (i64, i64, i64, i64, i64) =
        conn.prepare_cached(&sql)?.query_row([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    let percent = (total > 0).then(|| (closed * 100 / total) as u8);
    let close_eligible = is_close_eligible(conn, &issue)?;
    Ok(EpicStatus {
        id: issue.id,
        title: issue.title,
        status: issue.status,
        issue_type: issue.issue_type,
        total,
        closed,
        open,
        in_progress,
        blocked,
        percent,
        close_eligible,
    })
}

/// [`close_eligible`]'s rule for one issue.
fn is_close_eligible(conn: &Connection, issue: &Issue) -> Result<bool> {
    if issue.issue_type != "epic" || issue.status == Status::Closed {
        return Ok(false);
    }
    let sql = "SELECT EXISTS (SELECT 1 FROM dependencies d WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child')
           AND NOT EXISTS (SELECT 1 FROM dependencies d
                           CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
                           WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' AND c.status <> 'closed')";
    Ok(conn.prepare_cached(sql)?.query_row([&issue.id], |r| r.get(0))?)
}

/// The status of every epic not closed (every epic with `include_closed`),
/// in id order.
pub fn epics(conn: &Connection, include_closed: bool) -> Result<Vec<EpicStatus>> {
    let ids: Vec<String> = {
        let mut stmt = conn.prepare_cached(
            "SELECT e.id FROM issues e WHERE e.issue_type = 'epic' AND (?1 OR e.status <> 'closed') ORDER BY e.id",
        )?;
        let rows = stmt.query_map([include_closed], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    ids.iter().map(|id| epic_status(conn, id)).collect()
}

/// Epics not closed whose children are all closed (and that have some), in
/// id order: `bd stats`'s closable epics and `bd epic close-eligible`.
pub fn close_eligible(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT e.id FROM issues e
         WHERE e.issue_type = 'epic' AND e.status <> 'closed'
           AND EXISTS (SELECT 1 FROM dependencies d WHERE d.depends_on_id = e.id AND d.dep_type = 'parent-child')
           AND NOT EXISTS (SELECT 1 FROM dependencies d
                           CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id
                           WHERE d.depends_on_id = e.id AND d.dep_type = 'parent-child' AND c.status <> 'closed')
         ORDER BY e.id",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The children of `id` (every descendant with `recursive`), of every
/// status, in creation order.
pub fn child_issues(conn: &Connection, id: &str, recursive: bool) -> Result<Vec<Issue>> {
    issues::require(conn, id)?;
    if recursive {
        // A stable sort over rowid order: (created_at, rowid), as below.
        let mut all = issues::descendants(conn, id)?;
        all.sort_by_key(|i| i.created_at);
        return Ok(all);
    }
    let sql = format!(
        "SELECT {ISSUE_COLUMNS}
         FROM dependencies d CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = d.issue_id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' ORDER BY i.created_at, i.rowid"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([id], issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// An issue `bd stale` lists: not updated for a while, or claimed under a
/// lease that expired.
#[derive(Clone, Debug, Serialize)]
pub struct StaleIssue {
    #[serde(flatten)]
    pub issue: Issue,
    /// Not updated within the window asked for.
    pub stale: bool,
    /// The holder of an expired lease on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_holder: Option<String>,
    /// When that lease expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expired_at: Option<Timestamp>,
}

/// Open and in-progress issues not updated within `older_than` of `now`, or
/// held under a lease that expired by `now`, least recently updated first
/// (then by id), up to `limit`.
pub fn stale(conn: &Connection, now: Timestamp, older_than: Duration, limit: Option<usize>) -> Result<Vec<StaleIssue>> {
    let cutoff = now.minus(older_than);
    let sql = format!(
        "SELECT {ISSUE_COLUMNS}, le.holder, le.expires_at
         FROM issues i INDEXED BY idx_issues_ready LEFT JOIN leases le ON le.issue_id = i.id
         WHERE i.status IN ('open','in_progress') AND (i.updated_at < ?1 OR le.expires_at <= ?2)
         ORDER BY i.updated_at, i.id LIMIT ?3"
    );
    // A negative limit is none: one statement either way.
    let limit = limit.map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![cutoff, now, limit], |r| {
        let issue = issue_from_row(r)?;
        let holder: Option<String> = r.get(ISSUE_COLUMN_COUNT)?;
        let expires_at: Option<Timestamp> = r.get(ISSUE_COLUMN_COUNT + 1)?;
        let expired = expires_at.is_some_and(|t| t <= now);
        Ok(StaleIssue {
            stale: issue.updated_at < cutoff,
            lease_holder: holder.filter(|_| expired),
            lease_expired_at: expires_at.filter(|_| expired),
            issue,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// A reference in an issue's text to an issue that does not exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrphanRef {
    /// The id named.
    pub id: String,
    /// Where: `title`, `description`, `design`, `acceptance_criteria`,
    /// `notes`, `close_reason` or `comment`.
    pub field: String,
}

/// An issue whose text names issues that do not exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Orphan {
    pub id: String,
    pub title: String,
    pub references: Vec<OrphanRef>,
}

/// An issue's dangling references while [`orphans`] scans: its title (once
/// read), and each reference as (id named, index in [`FIELDS`]).
#[derive(Default)]
struct Dangling {
    title: Option<String>,
    refs: BTreeSet<(String, usize)>,
}

/// The text fields scanned, in the order references are listed in.
const FIELDS: [&str; 7] = ["title", "description", "design", "acceptance_criteria", "notes", "close_reason", "comment"];

/// The issues whose text (title, description, design, acceptance criteria,
/// notes, close reason, comments) names a `<prefix>-` id that does not
/// exist, in id order. A reference is a whole token as `rename-prefix` reads
/// one (see [`crate::rename`]); it dangles when neither it nor any part of it
/// before a `.` (`t-1.5` names t-1's child) is an issue. Each reference is
/// listed once per field, by id, then field.
///
/// Dependency edges are not checked: they cannot dangle, as foreign keys
/// (`ON DELETE CASCADE`) are enforced on every connection and imports skip
/// edges to missing issues; `bd doctor` checks foreign keys in a damaged file.
pub fn orphans(conn: &Connection, prefix: &str) -> Result<Vec<Orphan>> {
    if prefix.is_empty() || !prefix.bytes().all(is_id_char) {
        return Err(Error::invalid(format!("invalid prefix {prefix:?}: letters, digits, '_', '.' and '-' only")));
    }
    let needle = format!("{prefix}-");
    let mut known: HashMap<String, bool> = HashMap::new();
    let mut exists = |id: &str| -> Result<bool> {
        if let Some(&e) = known.get(id) {
            return Ok(e);
        }
        let e = ids::exists(conn, id)?;
        known.insert(id.to_string(), e);
        Ok(e)
    };
    let mut found: BTreeMap<String, Dangling> = BTreeMap::new();
    let mut scan = |issue: &str, title: Option<&str>, field: usize, text: &str| -> Result<()> {
        for (_, token) in id_tokens(text, prefix) {
            if token.len() <= needle.len() || !token.starts_with(&needle) {
                continue;
            }
            let named = exists(token)?
                || token[needle.len()..]
                    .match_indices('.')
                    .map(|(dot, _)| &token[..needle.len() + dot])
                    .try_fold(false, |any, part| Ok::<_, Error>(any || exists(part)?))?;
            if !named {
                let entry = found.entry(issue.to_string()).or_default();
                if entry.title.is_none() {
                    entry.title = title.map(str::to_string);
                }
                entry.refs.insert((token.to_string(), field));
            }
        }
        Ok(())
    };
    {
        let mut stmt = conn.prepare_cached(
            "SELECT id, title, description, design, acceptance_criteria, notes, close_reason FROM issues
             WHERE instr(title, ?1) > 0 OR instr(description, ?1) > 0 OR instr(design, ?1) > 0
                OR instr(acceptance_criteria, ?1) > 0 OR instr(notes, ?1) > 0 OR instr(close_reason, ?1) > 0
             ORDER BY id",
        )?;
        let mut rows = stmt.query([&needle])?;
        while let Some(r) = rows.next()? {
            let id: String = r.get(0)?;
            let title: String = r.get(1)?;
            for field in 0..6 {
                let text: Option<String> = r.get(field + 1)?;
                if let Some(text) = text {
                    scan(&id, Some(&title), field, &text)?;
                }
            }
        }
    }
    {
        let mut stmt =
            conn.prepare_cached("SELECT issue_id, text FROM comments WHERE instr(text, ?1) > 0 ORDER BY issue_id, id")?;
        let mut rows = stmt.query([&needle])?;
        while let Some(r) = rows.next()? {
            let id: String = r.get(0)?;
            let text: String = r.get(1)?;
            scan(&id, None, 6, &text)?;
        }
    }
    let mut out = Vec::with_capacity(found.len());
    for (id, Dangling { title, refs }) in found {
        let title = match title {
            Some(t) => t,
            None => issues::require(conn, &id)?.title,
        };
        let references =
            refs.into_iter().map(|(id, field)| OrphanRef { id, field: FIELDS[field].to_string() }).collect();
        out.push(Orphan { id, title, references });
    }
    Ok(out)
}
