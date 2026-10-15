//! Compaction of old closed issues' text: an agent reads the candidates
//! ([`candidates`]), writes a summary of each, and [`WriteCtx::compact_issue`]
//! puts the summary in place of the description, design, acceptance
//! criteria and notes. The original text stays in the `compacted` event
//! (`changes`, old and new), so `bd history --diff` and `bd show --as-of`
//! show it for as long as retention keeps that event. Not to be confused
//! with compacting a playbook run (`bd playbook compact`), which folds its
//! steps into the run issue.

use std::collections::BTreeMap;
use std::time::Duration;

use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::error::{Error, Result};
use crate::issues::{self, UpdateEvent};
use crate::model::{Guard, Issue, IssuePatch, Status};
use crate::store::WriteCtx;
use crate::time::Timestamp;

/// A closed issue whose text an agent may summarise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub closed_at: Timestamp,
    pub close_reason: Option<String>,
    /// For `--if-revision`: the summary describes this revision of the text.
    pub revision: i64,
    /// UTF-8 bytes of the four text fields.
    pub size: usize,
    pub description: String,
    pub design: String,
    pub acceptance_criteria: String,
    pub notes: String,
}

/// Bytes of an issue's four text fields.
pub fn text_size(issue: &Issue) -> usize {
    issue.description.len() + issue.design.len() + issue.acceptance_criteria.len() + issue.notes.len()
}

/// The issues a candidate must be: closed at least `older_than` before
/// `?1`, not ephemeral (`bd purge` deletes those), never compacted, with
/// text to summarise.
const CANDIDATE: &str = "status = 'closed' AND closed_at <= ?1 AND ephemeral = 0
    AND json_type(metadata, '$.compaction') IS NULL
    AND (description <> '' OR design <> '' OR acceptance_criteria <> '' OR notes <> '')";

/// The closed issues to compact, oldest closed first (then by id), at most
/// `limit`.
pub fn candidates(
    conn: &Connection,
    now: Timestamp,
    older_than: Duration,
    limit: Option<usize>,
) -> Result<Vec<Candidate>> {
    let sql = format!(
        "SELECT id, title, closed_at, close_reason, revision, description, design, acceptance_criteria, notes
         FROM issues WHERE {CANDIDATE} ORDER BY closed_at, id LIMIT ?2"
    );
    let limit = limit.map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![now.minus(older_than), limit], |r| {
        let (description, design, acceptance_criteria, notes): (String, String, String, String) =
            (r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?);
        Ok(Candidate {
            id: r.get(0)?,
            title: r.get(1)?,
            closed_at: r.get(2)?,
            close_reason: r.get(3)?,
            revision: r.get(4)?,
            size: description.len() + design.len() + acceptance_criteria.len() + notes.len(),
            description,
            design,
            acceptance_criteria,
            notes,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// What compaction did to closed issues, and could still do.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompactStats {
    pub closed: i64,
    /// Closed issues compacted.
    pub compacted: i64,
    /// Those by level.
    pub by_level: BTreeMap<i64, i64>,
    /// Text bytes of the compacted issues before their first compaction.
    pub original_bytes: i64,
    /// Their text bytes now.
    pub current_bytes: i64,
    pub saved_bytes: i64,
    /// Candidates now, under the age threshold given.
    pub candidates: i64,
    pub candidate_bytes: i64,
}

const TEXT_BYTES: &str = "length(CAST(description AS BLOB)) + length(CAST(design AS BLOB))
    + length(CAST(acceptance_criteria AS BLOB)) + length(CAST(notes AS BLOB))";

pub fn stats(conn: &Connection, now: Timestamp, older_than: Duration) -> Result<CompactStats> {
    let mut out = CompactStats {
        closed: conn
            .prepare_cached("SELECT COUNT(*) FROM issues WHERE status = 'closed'")?
            .query_row([], |r| r.get(0))?,
        ..Default::default()
    };
    let sql = format!(
        "SELECT json_extract(metadata, '$.compaction.level'), COUNT(*),
                COALESCE(SUM(json_extract(metadata, '$.compaction.original_size')), 0), COALESCE(SUM({TEXT_BYTES}), 0)
         FROM issues WHERE status = 'closed' AND json_type(metadata, '$.compaction') = 'object' GROUP BY 1 ORDER BY 1"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, Option<i64>>(0)?.unwrap_or(0), r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
    })?;
    for row in rows {
        let (level, count, original, current) = row?;
        *out.by_level.entry(level).or_default() += count;
        out.compacted += count;
        out.original_bytes += original;
        out.current_bytes += current;
    }
    out.saved_bytes = out.original_bytes - out.current_bytes;
    let sql = format!("SELECT COUNT(*), COALESCE(SUM({TEXT_BYTES}), 0) FROM issues WHERE {CANDIDATE}");
    (out.candidates, out.candidate_bytes) =
        conn.prepare_cached(&sql)?.query_row([now.minus(older_than)], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(out)
}

/// What [`WriteCtx::compact_issue`] did.
#[derive(Clone, Debug, Serialize)]
pub struct CompactIssueOutcome {
    pub issue: Issue,
    pub level: i64,
    /// Text bytes before the first compaction.
    pub original_size: i64,
    /// Text bytes now: the summary's.
    pub size: i64,
}

impl WriteCtx<'_> {
    /// Replace the text of closed issue `id` (description, design, acceptance
    /// criteria and notes) with `summary`, which must be shorter, recording
    /// one `compacted` event whose changes keep the original, and
    /// `metadata.compaction` ({level, compacted_at, original_size}). Title,
    /// close reason, labels, edges and comments stay. Compacting again raises
    /// the level and keeps the first original size.
    pub fn compact_issue(&mut self, id: &str, summary: &str, guard: &Guard) -> Result<CompactIssueOutcome> {
        let issue = issues::require(self.conn(), id)?;
        guard.check(&issue)?;
        if issue.status != Status::Closed {
            return Err(Error::Refused(format!("{id} is {}: only closed issues are compacted", issue.status)));
        }
        let summary = summary.trim_end();
        if summary.trim().is_empty() {
            return Err(Error::invalid("the summary is empty"));
        }
        let current = text_size(&issue);
        if summary.len() >= current {
            return Err(Error::Refused(format!(
                "summary ({} bytes) is not shorter than the text it replaces ({current} bytes)",
                summary.len()
            )));
        }
        let previous = issue.metadata.get("compaction").filter(|c| c.is_object());
        let level = previous.and_then(|c| c["level"].as_i64()).unwrap_or(0) + 1;
        let original_size =
            previous.and_then(|c| c["original_size"].as_i64()).unwrap_or(i64::try_from(current).unwrap_or(i64::MAX));
        let size = i64::try_from(summary.len()).unwrap_or(i64::MAX);
        let compaction =
            json!({ "level": level, "compacted_at": self.now().to_rfc3339(), "original_size": original_size });
        let patch = IssuePatch {
            description: Some(summary.to_string()),
            design: Some(String::new()),
            acceptance_criteria: Some(String::new()),
            notes: Some(String::new()),
            set_metadata: vec![("compaction".into(), compaction)],
            ..Default::default()
        };
        let mut extra = Map::new();
        extra.insert("level".into(), Value::from(level));
        extra.insert("original_size".into(), Value::from(original_size));
        extra.insert("size".into(), Value::from(size));
        let event = UpdateEvent { op: "compacted", extra: Some(extra) };
        let out = self.update_issue_as(id, &patch, guard, false, false, event)?;
        Ok(CompactIssueOutcome { issue: out.issue, level, original_size, size })
    }
}
