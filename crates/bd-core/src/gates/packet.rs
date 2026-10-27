//! The approval packet of a human gate: the workspace-authored material the
//! browser page for approving it shows below its own facts, so a person
//! decides on more than titles.
//!
//! The packet is a view read when the page loads, never a record of what is
//! approved. Its sources, in display order:
//!
//! 1. the gate;
//! 2. the work it directly holds back, at most [`MAX_HELD`] issues in id
//!    order, each followed by its decision records;
//! 3. the gate's playbook run (its nearest ancestor with
//!    `metadata.playbook.role = "run"`), else its parent;
//! 4. for a playbook gate only, its same-run scheduling prerequisites:
//!    the issues reached through `blocks`, `conditional-blocks` and
//!    `waits-for` out-edges from the gate and its in-run held work, kept
//!    only while their nearest run is the gate's, by creation, each followed
//!    by its decision records.
//!
//! Decision records are the direct children of type `decision` of held and
//! prerequisite steps, each shown once, after the step it was first found
//! under. Informational edges (`related`, `discovered-from` and the like),
//! later steps, the decision children of the gate, the run or a decision,
//! files and URLs are never followed. A record already shown as a decision
//! that a scheduling path reaches keeps its place, but its own prerequisites
//! are still followed.
//!
//! Everything is bounded before Rust allocates it ([`Limits`]): every
//! statement is fixed, reaches issues by key and binds its LIMIT; titles and
//! authors are cut in SQL, fields and comments read as a byte prefix and
//! their length. Every dependency row read is charged against
//! [`Limits::edges`]; the walk stops at the first limit and says where
//! ([`Note`]). The text shown is cut on a UTF-8 boundary and says how much
//! there was ([`Text`]). Reading only: nothing here writes, emits events or
//! recomputes, and a database error fails the whole packet.

use std::collections::{HashMap, HashSet, VecDeque};

use rusqlite::{Connection, OptionalExtension, params};

use crate::comments;
use crate::error::Result;
use crate::graph;
use crate::model::{IssueRef, Status};
use crate::time::Timestamp;

/// How many records a packet holds at most.
pub const MAX_RECORDS: usize = 32;
/// How many dependency rows the walks read at most.
pub const MAX_EDGES: usize = 256;
/// How many of each record's newest comments are shown.
pub const MAX_COMMENTS: usize = 8;
/// How many bytes of one field or comment are shown.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// How many bytes of fields and comments a packet shows in all.
pub const MAX_SOURCE_BYTES: usize = 128 * 1024;
/// How many of the issues a gate holds back are included.
pub const MAX_HELD: usize = 8;

/// The packet's bounds: the `MAX_*` constants by default; tests pass smaller ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub records: usize,
    pub edges: usize,
    pub comments: usize,
    pub text_bytes: usize,
    pub source_bytes: usize,
    pub held: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            records: MAX_RECORDS,
            edges: MAX_EDGES,
            comments: MAX_COMMENTS,
            text_bytes: MAX_TEXT_BYTES,
            source_bytes: MAX_SOURCE_BYTES,
            held: MAX_HELD,
        }
    }
}

/// Why a record is in the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Gate,
    Held,
    Run,
    Parent,
    Prerequisite,
    Decision,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Gate => "Gate",
            Role::Held => "Held work",
            Role::Run => "Run",
            Role::Parent => "Parent",
            Role::Prerequisite => "Prerequisite",
            Role::Decision => "Decision record",
        }
    }
}

/// An issue's text fields, in the order they are shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Description,
    AcceptanceCriteria,
    Design,
    Notes,
}

impl FieldKind {
    pub const ALL: [FieldKind; 4] =
        [FieldKind::Description, FieldKind::AcceptanceCriteria, FieldKind::Design, FieldKind::Notes];

    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Description => "Description",
            FieldKind::AcceptanceCriteria => "Acceptance criteria",
            FieldKind::Design => "Design",
            FieldKind::Notes => "Notes",
        }
    }
}

/// Text as stored, or as much of it as the limits let through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Text {
    Full(String),
    /// The first bytes of a longer text, cut on a character boundary;
    /// `total_bytes` is the stored length.
    Truncated {
        text: String,
        total_bytes: u64,
    },
    /// None of it: the packet's [`Limits::source_bytes`] were spent.
    Omitted {
        total_bytes: u64,
    },
}

/// One nonempty field of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    pub text: Text,
}

/// One comment on a record; the author is cut to 256 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketComment {
    pub author: String,
    pub created_at: Timestamp,
    pub text: Text,
}

/// One record of the packet. `id` is the full stored id; `title` is cut to
/// 500 characters; `under` is the step a [`Role::Decision`] belongs to.
/// `comments` are the newest, oldest first; `earlier_comments` counts the
/// rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub role: Role,
    pub id: String,
    pub title: String,
    pub status: Status,
    pub under: Option<String>,
    pub fields: Vec<Field>,
    pub comments: Vec<PacketComment>,
    pub earlier_comments: u64,
}

/// Which walk a graph limit stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// Looking up a record's run or parent.
    Run,
    /// Following scheduling prerequisites.
    Prerequisites,
    /// Enumerating a step's decision records.
    Decisions,
}

/// Material the packet leaves out, and where. `at` is the record whose lookup
/// or expansion stopped: the gate (or a held issue whose run was being
/// looked up) for [`Walk::Run`], else the record being expanded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    /// More held issues than [`Limits::held`]: `more` left out of gate `gate`.
    HeldLimit { gate: String, more: usize },
    /// [`Limits::records`] reached.
    RecordLimit { at: String, during: Walk },
    /// [`Limits::edges`] dependency rows read.
    EdgeLimit { at: String, during: Walk },
    /// A held issue (or the gate) that does not exist.
    Unavailable { id: String },
}

/// The approval packet of a gate. `playbook` is set when the gate belongs to
/// a playbook run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub playbook: bool,
    pub sources: Vec<Source>,
    pub notes: Vec<Note>,
}

/// The packet of gate `gate_id`, holding back `held`, within the default [`Limits`].
pub fn collect(conn: &Connection, gate_id: &str, held: &[IssueRef]) -> Result<Packet> {
    collect_with(conn, gate_id, held, &Limits::default())
}

/// [`collect`] within `limits`.
pub fn collect_with(conn: &Connection, gate_id: &str, held: &[IssueRef], limits: &Limits) -> Result<Packet> {
    let mut w = Walker {
        conn,
        limits,
        edges: 0,
        parents: HashMap::new(),
        runs: HashMap::new(),
        nearest: HashMap::new(),
        picked: vec![Picked { id: gate_id.to_string(), role: Role::Gate, under: None }],
        selected: HashMap::from([(gate_id.to_string(), Role::Gate)]),
        notes: Vec::new(),
    };
    let mut held_ids: Vec<&str> = held.iter().map(|h| h.id.as_str()).filter(|h| *h != gate_id).collect();
    held_ids.sort_unstable();
    held_ids.dedup();
    let more = held_ids.len().saturating_sub(limits.held);
    held_ids.truncate(limits.held);
    for h in &held_ids {
        w.pick(h, Role::Held, None);
    }
    if more > 0 {
        w.notes.push(Note::HeldLimit { gate: gate_id.to_string(), more });
    }
    let mut playbook = false;
    match w.nearest_run(gate_id)? {
        Err(OutOfEdges) => w.notes.push(Note::EdgeLimit { at: gate_id.to_string(), during: Walk::Run }),
        Ok(Some(run)) => {
            playbook = true;
            if !w.selected.contains_key(&run) {
                w.pick(&run, Role::Run, None);
            }
            w.walk(gate_id, &run, &held_ids)?;
        }
        Ok(None) => {
            // The lookup above read the gate's parent already: no charge.
            if let Ok(Some(parent)) = w.parent(gate_id)?
                && !w.selected.contains_key(&parent)
            {
                w.pick(&parent, Role::Parent, None);
            }
        }
    }
    let Walker { picked, mut notes, .. } = w;

    let mut budget = limits.source_bytes;
    let mut read: Vec<Read> = Vec::with_capacity(picked.len());
    let mut missing = HashSet::new();
    for p in picked {
        match read_source(conn, p, limits, &mut budget)? {
            Ok(r) => read.push(r),
            Err(id) => {
                missing.insert(id.clone());
                notes.push(Note::Unavailable { id });
            }
        }
    }
    read.retain(|r| r.source.under.as_ref().is_none_or(|u| !missing.contains(u)));
    Ok(Packet { playbook, sources: display_order(read), notes })
}

/// The dependency-row budget ran out.
struct OutOfEdges;

/// What a budgeted graph read gives: the rows, or [`OutOfEdges`].
type Walked<T> = std::result::Result<T, OutOfEdges>;

/// A record chosen by the walk, before its text is read.
struct Picked {
    id: String,
    role: Role,
    under: Option<String>,
}

struct Walker<'c> {
    conn: &'c Connection,
    limits: &'c Limits,
    /// Dependency rows charged so far.
    edges: usize,
    parents: HashMap<String, Option<String>>,
    runs: HashMap<String, bool>,
    nearest: HashMap<String, Option<String>>,
    /// The records chosen, in collection order.
    picked: Vec<Picked>,
    /// Their roles, by id: each record is chosen once.
    selected: HashMap<String, Role>,
    notes: Vec<Note>,
}

fn limit(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Walker<'_> {
    fn pick(&mut self, id: &str, role: Role, under: Option<&str>) {
        if self.selected.insert(id.to_string(), role).is_none() {
            self.picked.push(Picked { id: id.to_string(), role, under: under.map(str::to_string) });
        }
    }

    fn room(&self) -> usize {
        self.limits.edges.saturating_sub(self.edges)
    }

    /// The parent of `id`, read once and charged one row.
    fn parent(&mut self, id: &str) -> Result<Walked<Option<String>>> {
        if let Some(p) = self.parents.get(id) {
            return Ok(Ok(p.clone()));
        }
        if self.room() == 0 {
            return Ok(Err(OutOfEdges));
        }
        self.edges += 1;
        let p = graph::parent_of(self.conn, id)?;
        self.parents.insert(id.to_string(), p.clone());
        Ok(Ok(p))
    }

    /// Whether `id` is a playbook run: a boolean, so its metadata never
    /// reaches Rust.
    fn is_run(&mut self, id: &str) -> Result<bool> {
        if let Some(&r) = self.runs.get(id) {
            return Ok(r);
        }
        let run = self
            .conn
            .prepare_cached(
                "SELECT json_extract(i.metadata, '$.playbook.role') IS 'run' FROM issues i WHERE i.id = ?1",
            )?
            .query_row([id], |r| r.get::<_, i64>(0))
            .optional()?
            .is_some_and(|v| v != 0);
        self.runs.insert(id.to_string(), run);
        Ok(run)
    }

    /// The nearest ancestor of `id` that is a playbook run; a parent cycle
    /// ends the walk.
    fn nearest_run(&mut self, id: &str) -> Result<Walked<Option<String>>> {
        if let Some(r) = self.nearest.get(id) {
            return Ok(Ok(r.clone()));
        }
        let mut seen = HashSet::from([id.to_string()]);
        let mut cur = id.to_string();
        let found = loop {
            let Ok(parent) = self.parent(&cur)? else {
                return Ok(Err(OutOfEdges));
            };
            let Some(p) = parent else { break None };
            if !seen.insert(p.clone()) {
                break None;
            }
            if self.is_run(&p)? {
                break Some(p);
            }
            if let Some(r) = self.nearest.get(&p) {
                break r.clone();
            }
            cur = p;
        };
        self.nearest.insert(id.to_string(), found.clone());
        Ok(Ok(found))
    }

    /// The scheduling prerequisites of `id`, every row charged.
    fn prerequisites(&mut self, id: &str) -> Result<Walked<Vec<String>>> {
        let room = self.room();
        let rows: Vec<String> = {
            let mut stmt = self.conn.prepare_cached(
                "SELECT depends_on_id FROM dependencies
                 WHERE issue_id = ?1 AND dep_type IN ('blocks','conditional-blocks','waits-for')
                 ORDER BY dep_type, depends_on_id LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![id, limit(room.saturating_add(1))], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        Ok(self.charge(room, rows))
    }

    /// The children of `id`, each with whether it is a decision record, every
    /// row charged.
    fn children(&mut self, id: &str) -> Result<Walked<Vec<(String, bool)>>> {
        let room = self.room();
        let rows: Vec<(String, bool)> = {
            let mut stmt = self.conn.prepare_cached(
                "SELECT d.issue_id, c.issue_type = 'decision'
                 FROM (SELECT issue_id FROM dependencies
                       WHERE depends_on_id = ?1 AND dep_type = 'parent-child' ORDER BY issue_id LIMIT ?2) d
                 CROSS JOIN issues c INDEXED BY sqlite_autoindex_issues_1 ON c.id = d.issue_id",
            )?;
            let rows = stmt
                .query_map(params![id, limit(room.saturating_add(1))], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        Ok(self.charge(room, rows))
    }

    /// Charge `rows`, read with a LIMIT of `room + 1`: the extra row means
    /// the budget ran out, and every walk stops.
    fn charge<T>(&mut self, room: usize, rows: Vec<T>) -> Walked<Vec<T>> {
        if rows.len() > room {
            self.edges = self.limits.edges;
            return Err(OutOfEdges);
        }
        self.edges += rows.len();
        Ok(rows)
    }

    /// The breadth-first walk of a playbook gate's prerequisites and decision
    /// records. `selected` dedups records; `scheduled` tracks whose
    /// prerequisites were queued, so a decision record a scheduling path
    /// reaches is still followed. Stops at the first limit, with its note.
    fn walk(&mut self, gate: &str, run: &str, held: &[&str]) -> Result<()> {
        let mut scheduled: HashSet<String> = self.selected.keys().cloned().collect();
        let mut queue: VecDeque<(String, bool)> = VecDeque::from([(gate.to_string(), false)]);
        for h in held {
            match self.nearest_run(h)? {
                Err(OutOfEdges) => {
                    self.notes.push(Note::EdgeLimit { at: h.to_string(), during: Walk::Run });
                    return Ok(());
                }
                Ok(r) if r.as_deref() == Some(run) => queue.push_back((h.to_string(), true)),
                Ok(_) => {}
            }
        }
        while let Some((node, children)) = queue.pop_front() {
            if children {
                let Ok(kids) = self.children(&node)? else {
                    self.notes.push(Note::EdgeLimit { at: node, during: Walk::Decisions });
                    return Ok(());
                };
                for (kid, decision) in kids {
                    if !decision || self.selected.contains_key(&kid) {
                        continue;
                    }
                    if self.selected.len() >= self.limits.records {
                        self.notes.push(Note::RecordLimit { at: node, during: Walk::Decisions });
                        return Ok(());
                    }
                    self.pick(&kid, Role::Decision, Some(&node));
                }
            }
            let Ok(targets) = self.prerequisites(&node)? else {
                self.notes.push(Note::EdgeLimit { at: node, during: Walk::Prerequisites });
                return Ok(());
            };
            for target in targets {
                if !scheduled.insert(target.clone()) {
                    continue;
                }
                match self.nearest_run(&target)? {
                    Err(OutOfEdges) => {
                        self.notes.push(Note::EdgeLimit { at: node, during: Walk::Prerequisites });
                        return Ok(());
                    }
                    // Outside the run: not part of this approval, by rule rather than a limit.
                    Ok(r) if r.as_deref() != Some(run) => continue,
                    Ok(_) => {}
                }
                if self.selected.contains_key(&target) {
                    // A decision record keeps its place; only its prerequisites are followed.
                    queue.push_back((target, false));
                    continue;
                }
                if self.selected.len() >= self.limits.records {
                    self.notes.push(Note::RecordLimit { at: node, during: Walk::Prerequisites });
                    return Ok(());
                }
                self.pick(&target, Role::Prerequisite, None);
                queue.push_back((target, true));
            }
        }
        Ok(())
    }
}

/// A record with its text, and what orders it.
struct Read {
    source: Source,
    created_at: Timestamp,
    rowid: i64,
}

/// A field's or comment's byte prefix and stored length.
type Prefix = (Option<Vec<u8>>, Option<i64>);

/// The text of `p`, charged against `budget`; `Err(id)` when the record does not exist.
fn read_source(
    conn: &Connection,
    p: Picked,
    limits: &Limits,
    budget: &mut usize,
) -> Result<std::result::Result<Read, String>> {
    type Row = (String, Status, Timestamp, i64, [Prefix; 4]);
    let row: Option<Row> = conn
        .prepare_cached(
            "SELECT substr(i.title,1,500), i.status, i.created_at, i.rowid,
                    CAST(substr(CAST(i.description AS BLOB),1,?2) AS BLOB), length(CAST(i.description AS BLOB)),
                    CAST(substr(CAST(i.acceptance_criteria AS BLOB),1,?2) AS BLOB),
                    length(CAST(i.acceptance_criteria AS BLOB)),
                    CAST(substr(CAST(i.design AS BLOB),1,?2) AS BLOB), length(CAST(i.design AS BLOB)),
                    CAST(substr(CAST(i.notes AS BLOB),1,?2) AS BLOB), length(CAST(i.notes AS BLOB))
             FROM issues i WHERE i.id = ?1",
        )?
        .query_row(params![p.id, limit(limits.text_bytes)], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                [(r.get(4)?, r.get(5)?), (r.get(6)?, r.get(7)?), (r.get(8)?, r.get(9)?), (r.get(10)?, r.get(11)?)],
            ))
        })
        .optional()?;
    let Some((title, status, created_at, rowid, texts)) = row else {
        return Ok(Err(p.id));
    };
    let mut fields = Vec::new();
    for (kind, (prefix, total)) in FieldKind::ALL.into_iter().zip(texts) {
        let (text, whole, total) = prefix_text(prefix, total);
        if total == 0 || (whole && text.trim().is_empty()) {
            continue;
        }
        fields.push(Field { kind, text: charge_text(text, whole, total, limits, budget) });
    }

    let newest: Vec<(String, Timestamp, Prefix)> = {
        let mut stmt = conn.prepare_cached(
            "SELECT substr(author,1,256), created_at,
                    CAST(substr(CAST(text AS BLOB),1,?2) AS BLOB), length(CAST(text AS BLOB))
             FROM comments WHERE issue_id = ?1 ORDER BY created_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![p.id, limit(limits.text_bytes), limit(limits.comments)], |r| {
            Ok((r.get(0)?, r.get(1)?, (r.get(2)?, r.get(3)?)))
        })?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let shown = newest.len();
    let mut comments: Vec<PacketComment> = newest
        .into_iter()
        .map(|(author, created_at, (prefix, total))| {
            let (text, whole, total) = prefix_text(prefix, total);
            PacketComment { author, created_at, text: charge_text(text, whole, total, limits, budget) }
        })
        .collect();
    comments.reverse();
    let earlier_comments = if shown >= limits.comments {
        u64::try_from(comments::count(conn, &p.id)?).unwrap_or(0).saturating_sub(shown as u64)
    } else {
        0
    };
    Ok(Ok(Read {
        source: Source { role: p.role, id: p.id, title, status, under: p.under, fields, comments, earlier_comments },
        created_at,
        rowid,
    }))
}

/// A prefix as text, whether it is the whole text, and the stored length.
fn prefix_text(prefix: Option<Vec<u8>>, total: Option<i64>) -> (String, bool, u64) {
    let prefix = prefix.unwrap_or_default();
    let total = total.and_then(|t| u64::try_from(t).ok()).unwrap_or(0);
    let whole = total <= prefix.len() as u64;
    (utf8_prefix(prefix), whole, total)
}

/// `text` (`whole` when nothing was cut in SQL) within the per-text limit and
/// what is left of `budget`, which it is charged against.
fn charge_text(mut text: String, whole: bool, total: u64, limits: &Limits, budget: &mut usize) -> Text {
    let cap = limits.text_bytes.min(*budget);
    let cut = !whole || text.len() > cap;
    if text.len() > cap {
        text.truncate(text.floor_char_boundary(cap));
    }
    if cut && text.is_empty() {
        return Text::Omitted { total_bytes: total };
    }
    *budget -= text.len();
    if cut { Text::Truncated { text, total_bytes: total } } else { Text::Full(text) }
}

/// A byte prefix as text: an incomplete character at its end is dropped,
/// anything else that is not UTF-8 replaced.
fn utf8_prefix(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            let err = e.utf8_error();
            let mut bytes = e.into_bytes();
            if err.error_len().is_none() {
                bytes.truncate(err.valid_up_to());
            }
            match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
            }
        }
    }
}

/// The gate; each held issue and its decision records; the run or parent;
/// the prerequisites by creation, each with its decision records.
fn display_order(read: Vec<Read>) -> Vec<Source> {
    let mut decisions: HashMap<String, Vec<Read>> = HashMap::new();
    let mut prerequisites = Vec::new();
    let mut work = Vec::new();
    let mut context = Vec::new();
    for r in read {
        match r.source.role {
            Role::Decision => decisions.entry(r.source.under.clone().unwrap_or_default()).or_default().push(r),
            Role::Prerequisite => prerequisites.push(r),
            Role::Run | Role::Parent => context.push(r),
            Role::Gate | Role::Held => work.push(r),
        }
    }
    for list in decisions.values_mut() {
        list.sort_by_key(|r| (r.created_at, r.rowid));
    }
    prerequisites.sort_by_key(|r| (r.created_at, r.rowid));
    let mut sources = Vec::new();
    for r in work.into_iter().chain(context).chain(prerequisites) {
        let under = decisions.remove(&r.source.id).unwrap_or_default();
        sources.push(r.source);
        sources.extend(under.into_iter().map(|d| d.source));
    }
    sources
}

#[cfg(test)]
mod tests;
