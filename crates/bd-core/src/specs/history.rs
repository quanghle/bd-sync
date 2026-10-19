//! Specs at a past point (`bd spec show --as-of`) and what changed in them
//! between two (`bd spec changes`), from the event log.
//!
//! Every issue is rebuilt by [`crate::asof`]: one [`History`] per command,
//! each issue's events loaded once ([`Rebuilder`]) and replayed at each point
//! asked. [`show_as_of`] runs the spec tree of [`super::spec_views`] over an
//! [`AsOfSource`], whose nodes are the issues as they were at the point.
//!
//! Membership at a point: an issue is a requirement, non-goal or sub-spec of
//! spec S then iff it existed, its parent-child edge pointed at S and it was
//! labelled `requirement`, `non-goal` or `spec`. The children a point can
//! have had are the current children of S plus every issue the events after
//! the point tie to S ([`After`], [`raw_candidates`]): moved away, deleted
//! or updated by an import (by their snapshots), or purged or compacted
//! (which name no parent: probed before they count). What the history cannot
//! tell is never guessed: a child whose membership, status or title is
//! unknown is not placed but listed in the view's `unknown`; one whose
//! description or edges are unknown is placed, with those keys listed.
//!
//! [`changes`] reads the events after `--since` once, takes the specs in
//! scope at either end, and classifies every candidate child of them (not
//! filtered by membership, so items that were members only inside the
//! window are seen) at `--since` and after each of its transactions in the
//! window; a transition with an unknown side is listed in `unknown`, never
//! reported as a change.
//!
//! Everything here reads, inside the caller's one read transaction.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    Brief, MAX_DEPTH, NON_GOAL, Node, REQUIREMENT, SPEC, Source, SpecView, clean, edges_in, labelled, spec_views,
    strip_removed,
};
use crate::asof::{History, IssueAsOf, Loaded, Point, PointView};
use crate::error::{Error, Result};
use crate::issues;
use crate::model::{Event, Status};
use crate::time::{Timestamp, parse_duration};

/// The most issues one command rebuilds (`bd spec show --as-of`,
/// `bd spec changes`): past it the command is refused (exit 2). An id only
/// a later purge, compaction or import names counts only once its probed
/// history ties it to the specs asked about ([`Rebuilder`]).
pub const MAX_HISTORY_ISSUES: usize = 2000;

/// The most events one command replays over all its rebuilds (each rebuild
/// replays the issue's whole loaded history): past it the command is
/// refused (exit 2), so many transactions of one issue cannot make a
/// command's work grow without bound.
pub const MAX_HISTORY_REPLAY: usize = 2_000_000;

/// A child the history cannot place, or a value of a placed one it cannot
/// tell: the issue, the key (`exists`, a field, `label:NAME`, `dep:ID`) and
/// why, as [`crate::asof`] says it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnknownItem {
    pub id: String,
    pub key: String,
    pub reason: String,
}

impl UnknownItem {
    fn new(id: &str, key: &str, reason: &str) -> UnknownItem {
        UnknownItem { id: clean(id), key: clean(key), reason: clean(reason) }
    }
}

/// A bound of a window (`--since`, `--until`) or a point: what
/// [`Point::parse`] reads (`N` or `#N` a seq, `-DURATION` ago, a date or
/// time), and a bare duration (`30d`) also counts back from `now`.
pub fn parse_bound(input: &str, now: Timestamp) -> Result<Point> {
    let s = input.trim();
    let digits = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if digits || s.starts_with('#') || s.starts_with('-') || s.starts_with('+') {
        return Point::parse(input, now);
    }
    match parse_duration(s) {
        Ok(d) => Ok(Point::Time(now.minus(d))),
        Err(_) => Point::parse(input, now),
    }
}

/// The ops that can change what a spec shows: an issue's existence, text,
/// status, labels and edges. `references_renamed` rewrites titles and
/// descriptions (`bd rename-prefix`).
macro_rules! history_ops {
    () => {
        "'created','imported','updated','compacted','closed','reopened','dep_added','dep_removed','dep_updated',\
         'deleted','purged','run_compacted','references_renamed'"
    };
}

/// The events after a seq: a rowid range.
const AFTER_SEQ: &str = concat!(
    "SELECT seq, tx, ts, actor, op, issue_id, data FROM events WHERE seq > ?1 AND seq <= ?2 AND op IN (",
    history_ops!(),
    ") ORDER BY seq"
);

/// The events after a time: a range of `idx_events_ts`.
const AFTER_TS: &str = concat!(
    "SELECT seq, tx, ts, actor, op, issue_id, data FROM events INDEXED BY idx_events_ts WHERE ts > ?1 AND ts <= ?2 \
     AND op IN (",
    history_ops!(),
    ") ORDER BY seq"
);

/// The retained events of the history ops after `since` and, with `until`,
/// at or before it, in seq order: one bounded read.
pub(crate) fn events_after(
    conn: &Connection,
    hist: &History,
    since: Point,
    until: Option<Point>,
) -> Result<Vec<Event>> {
    let row = |r: &rusqlite::Row<'_>| {
        let data: String = r.get(6)?;
        Ok(Event {
            seq: r.get(0)?,
            tx: r.get(1)?,
            ts: r.get(2)?,
            actor: r.get(3)?,
            op: r.get(4)?,
            issue_id: r.get(5)?,
            data: serde_json::from_str(&data).unwrap_or_else(|_| json!({})),
        })
    };
    let events: Vec<Event> = match since {
        Point::Seq(n) => {
            let hi = match until {
                Some(Point::Seq(u)) => u,
                _ => hist.head(),
            };
            let mut stmt = conn.prepare_cached(AFTER_SEQ)?;
            stmt.query_map(params![n, hi], row)?.collect::<rusqlite::Result<_>>()?
        }
        Point::Time(t) => {
            let hi = match until {
                Some(Point::Time(u)) => u,
                _ => Timestamp(i64::MAX),
            };
            let mut stmt = conn.prepare_cached(AFTER_TS)?;
            stmt.query_map(params![t, hi], row)?.collect::<rusqlite::Result<_>>()?
        }
    };
    Ok(events.into_iter().filter(|e| !since.includes(e) && until.is_none_or(|u| u.includes(e))).collect())
}

/// What the events after a point say about the issues a spec can have held
/// then: the issues whose parent-child edge to a spec was added, removed or
/// changed later, or that were deleted, or updated by an import, with one
/// (`kids`, by spec, from the deletion's or the import's snapshots); those
/// purged or compacted away later, which name no parent, and those updated
/// by an import that kept no previous snapshot (`maybe`); and every issue
/// that may have been a spec then but is not labelled one now (`specs`).
/// A create-mode import adds nothing: the issue did not exist before it,
/// and its edges have `dep_added` events of their own (an import's, of any
/// type, counts as one to its target in `kids`: it may have replaced a
/// parent-child edge). `hidden` holds the ids only a purge, a compaction or
/// an import with no previous snapshot names, minus those a snapshot or an
/// update shows labelled spec: [`Rebuilder`] probes them before they count.
/// `kids` does not take an id out of `hidden`, since it holds edges to any
/// target (epics, runs), not only specs; edges are checked by the probe.
#[derive(Clone, Debug, Default)]
pub(crate) struct After {
    pub(crate) kids: HashMap<String, BTreeSet<String>>,
    pub(crate) maybe: BTreeSet<String>,
    pub(crate) specs: BTreeSet<String>,
    pub(crate) hidden: BTreeSet<String>,
}

impl After {
    /// From `events`, those after `point`.
    pub(crate) fn of(events: &[Event], point: Point) -> After {
        let mut out = After::default();
        // Ids named only by a purge, a compaction or an import, and those with direct evidence.
        let mut named: BTreeSet<String> = BTreeSet::new();
        let mut direct: BTreeSet<String> = BTreeSet::new();
        for e in events.iter().filter(|e| !point.includes(e)) {
            let d = &e.data;
            let id = e.issue_id.as_deref();
            match e.op.as_str() {
                // An import's dep_added may have replaced a parent-child edge it did not record.
                "dep_added" | "dep_removed" | "dep_updated"
                    if d["type"] == json!("parent-child") || (e.op == "dep_added" && d["import"] == json!(true)) =>
                {
                    if let (Some(id), Some(target)) = (id, d["target"].as_str()) {
                        out.kids.entry(target.to_string()).or_default().insert(id.to_string());
                    }
                }
                "deleted" => {
                    let Some(id) = id else { continue };
                    out.snapshot(id, &d["issue"], &mut direct);
                }
                "purged" | "run_compacted" => {
                    for x in d["ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                        out.maybe.insert(x.to_string());
                        out.specs.insert(x.to_string());
                        named.insert(x.to_string());
                    }
                }
                "imported" if d["mode"] == json!("update") => {
                    let Some(id) = id else { continue };
                    for snap in [&d["previous"], &d["issue"]] {
                        if snap.is_object() {
                            out.snapshot(id, snap, &mut direct);
                        }
                    }
                    if !d["previous"].is_object() {
                        out.maybe.insert(id.to_string());
                        out.specs.insert(id.to_string());
                        named.insert(id.to_string());
                    }
                }
                "updated" => {
                    let removed = d.pointer("/changes/labels/removed").and_then(Value::as_array);
                    if let Some(id) = id
                        && removed.is_some_and(|l| l.iter().any(|l| l == SPEC))
                    {
                        out.specs.insert(id.to_string());
                        direct.insert(id.to_string());
                    }
                }
                _ => {}
            }
        }
        out.hidden = named.difference(&direct).cloned().collect();
        out
    }

    /// What issue `id`'s snapshot `snap` (of a deletion or an import) says:
    /// its parent-child edges, and whether it was labelled a spec.
    fn snapshot(&mut self, id: &str, snap: &Value, direct: &mut BTreeSet<String>) {
        for dep in snap["dependencies"].as_array().into_iter().flatten() {
            if dep["type"] == json!("parent-child")
                && let Some(target) = dep["target"].as_str()
            {
                self.kids.entry(target.to_string()).or_default().insert(id.to_string());
            }
        }
        if snap["labels"].as_array().is_some_and(|l| l.iter().any(|l| l == SPEC)) {
            self.specs.insert(id.to_string());
            direct.insert(id.to_string());
        }
    }
}

/// What a child is to a spec: `Direct` when an edge (now, or in a later
/// event or snapshot) ties it to the spec, `Maybe` when only a later purge,
/// compaction or import that kept no previous snapshot could have hidden
/// one (those in [`After::hidden`] are probed before they are rebuilt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    Direct,
    Maybe,
}

/// Every issue that may have been a child of `id` at the point `after` was
/// read for: its current children and the issues the later events tie to
/// it, deletions' and update-mode imports' snapshots included (`Direct`),
/// and those purged or compacted later, or imported later with no previous
/// snapshot (`Maybe`), in id order. No membership filter: [`classify`]
/// decides.
pub(crate) fn raw_candidates(conn: &Connection, after: &After, id: &str) -> Result<Vec<(String, Origin)>> {
    let mut out: BTreeMap<String, Origin> = BTreeMap::new();
    for c in edges_in(conn, id, "parent-child")? {
        out.insert(c, Origin::Direct);
    }
    for c in after.kids.get(id).into_iter().flatten() {
        out.insert(c.clone(), Origin::Direct);
    }
    for c in &after.maybe {
        out.entry(c.clone()).or_insert(Origin::Maybe);
    }
    out.remove(id);
    Ok(out.into_iter().collect())
}

/// An issue rebuilt at a point, with its creation time then (or why the
/// history cannot tell it).
#[derive(Clone, Debug)]
pub(crate) struct Rebuilt {
    pub(crate) d: IssueAsOf,
    pub(crate) created_at: std::result::Result<Timestamp, String>,
    /// The seq of its retained creation by then: rows are inserted in
    /// creation order, so this orders ties of `created_at` as rowids do.
    pub(crate) created_seq: Option<i64>,
}

impl Rebuilt {
    fn unknown(&self, key: &str) -> Option<&crate::asof::Unknown> {
        self.d.unknown.iter().find(|u| u.key == key)
    }

    fn str_field(&self, field: &str) -> Option<&str> {
        self.d.fields.get(field).and_then(Value::as_str)
    }

    fn status(&self) -> Option<Status> {
        self.str_field("status").and_then(|s| Status::parse(s).ok())
    }

    fn has(&self, label: &str) -> bool {
        self.d.labels.iter().any(|l| l == label)
    }

    fn parent(&self) -> Option<&str> {
        self.d.dependencies.iter().find(|x| x.dep_type == "parent-child").map(|x| x.target.as_str())
    }

    /// The targets of its edges of `dep_type`, in id order.
    fn deps(&self, dep_type: &str) -> Vec<String> {
        let mut out: Vec<String> =
            self.d.dependencies.iter().filter(|x| x.dep_type == dep_type).map(|x| x.target.clone()).collect();
        out.sort();
        out
    }

    fn closed_at(&self) -> Option<Timestamp> {
        self.str_field("closed_at").and_then(|s| Timestamp::parse_rfc3339(s).ok())
    }

    /// The unknown keys of what a spec view shows of it, `closed` or not:
    /// its description, edges, membership and area labels, close and
    /// creation details.
    fn shown_unknowns(&self, closed: bool) -> Vec<(String, String)> {
        let shown = |k: &str| {
            matches!(k, "description" | "label:requirement" | "label:non-goal" | "label:spec")
                || k.starts_with("dep:")
                || k.starts_with("label:area:")
                || (closed && matches!(k, "close_reason" | "closed_at"))
        };
        let mut out: Vec<(String, String)> =
            self.d.unknown.iter().filter(|u| shown(&u.key)).map(|u| (u.key.clone(), u.reason.clone())).collect();
        if let Err(reason) = &self.created_at {
            out.push(("created_at".into(), reason.clone()));
        }
        out
    }

    /// The spec tree's node, when it existed and its title and status are known.
    fn node(&self) -> Option<Node> {
        if !self.d.exists {
            return None;
        }
        Some(Node {
            id: self.d.id.clone(),
            title: self.str_field("title")?.to_string(),
            description: self.str_field("description").unwrap_or_default().to_string(),
            status: self.status()?,
            labels: self.d.labels.clone(),
            parent: self.parent().map(String::from),
            created_at: self.created_at.clone().unwrap_or(Timestamp(i64::MAX)),
            related: self.deps("related"),
            supersedes: self.deps("supersedes"),
            close_reason: self.str_field("close_reason").map(String::from),
            closed_at: self.closed_at(),
        })
    }
}

/// The seq of `d`'s retained creation, when it counts by `point`.
fn created_by(d: &IssueAsOf, point: Point) -> Option<i64> {
    d.created
        .as_ref()
        .filter(|c| match point {
            Point::Seq(n) => c.seq <= n,
            Point::Time(t) => c.ts <= t,
        })
        .map(|c| c.seq)
}

/// When `d` was created, at `point`: its retained creation by then (the
/// `created_at` its snapshot recorded, which an import keeps from its
/// input, else the event's time), else (none retained) the live row's;
/// unknown when its creation by then is pruned.
fn created_at(d: &IssueAsOf, loaded: &Loaded, point: Point) -> std::result::Result<Timestamp, String> {
    match &d.created {
        Some(c) if created_by(d, point).is_some() => Ok(loaded
            .history
            .iter()
            .find(|e| e.seq == c.seq)
            .and_then(|e| e.data.pointer("/issue/created_at"))
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse_rfc3339(s).ok())
            .unwrap_or(c.ts)),
        Some(_) => Err("its creation is not retained".into()),
        None => loaded
            .row
            .as_ref()
            .and_then(|r| r["created_at"].as_str())
            .and_then(|s| Timestamp::parse_rfc3339(s).ok())
            .ok_or_else(|| "its creation is not retained".into()),
    }
}

/// What a child is to a spec at a point.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Member {
    /// Not one of its requirements, non-goals or sub-specs.
    Out,
    /// The history cannot tell: the key it cannot tell, and why.
    Unknown {
        key: String,
        reason: String,
    },
    In(Item),
}

/// What a member is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ItemKind {
    Requirement,
    NonGoal,
    Spec,
}

impl ItemKind {
    /// Its name in `bd spec changes`' output.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ItemKind::Requirement => "requirement",
            ItemKind::NonGoal => "non-goal",
            ItemKind::Spec => "spec",
        }
    }
}

/// A member at a point: raw text (cleaned where it is shown).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Item {
    /// The spec it is a child of.
    pub(crate) spec: String,
    pub(crate) item: ItemKind,
    pub(crate) closed: bool,
    pub(crate) title: String,
    /// Empty when unknown (then listed in `unknown_keys`).
    pub(crate) description: String,
    /// Its outgoing `related` edges, in id order.
    pub(crate) sources: Vec<String>,
    /// Its outgoing `supersedes` edges, in id order.
    pub(crate) supersedes: Vec<String>,
    pub(crate) close_reason: Option<String>,
    pub(crate) closed_at: Option<Timestamp>,
    /// `Timestamp(i64::MAX)` when unknown.
    pub(crate) created_at: Timestamp,
    /// [`Rebuilt::created_seq`].
    pub(crate) created_seq: Option<i64>,
    /// The keys of what is shown of it that the history cannot tell, and why.
    pub(crate) unknown_keys: Vec<(String, String)>,
}

/// Whether `r` is a member of a spec `parents` accepts, in this order:
/// existence; an unknown edge to an accepted spec (which may be its parent
/// edge); its parent edge; its membership labels; its status and title.
pub(crate) fn classify(r: &Rebuilt, parents: &dyn Fn(&str) -> bool) -> Member {
    let unknown = |u: &crate::asof::Unknown| Member::Unknown { key: u.key.clone(), reason: u.reason.clone() };
    if let Some(u) = r.unknown("exists") {
        return unknown(u);
    }
    if !r.d.exists {
        return Member::Out;
    }
    if let Some(u) = r.d.unknown.iter().find(|u| u.key.strip_prefix("dep:").is_some_and(parents)) {
        return unknown(u);
    }
    let Some(spec) = r.parent().filter(|p| parents(p)).map(String::from) else { return Member::Out };
    let kinds = [(NON_GOAL, ItemKind::NonGoal), (REQUIREMENT, ItemKind::Requirement), (SPEC, ItemKind::Spec)];
    let Some(item) = kinds.iter().find(|(l, _)| r.has(l)).map(|(_, k)| *k) else {
        return match kinds.iter().find_map(|(l, _)| r.unknown(&format!("label:{l}"))) {
            Some(u) => unknown(u),
            None => Member::Out,
        };
    };
    if let Some(u) = r.unknown("status").or_else(|| r.unknown("title")) {
        return unknown(u);
    }
    let (Some(title), Some(status)) = (r.str_field("title"), r.status()) else {
        return Member::Unknown { key: "status".into(), reason: "not a recorded value".into() };
    };
    let closed = status == Status::Closed;
    Member::In(Item {
        spec,
        item,
        closed,
        title: title.to_string(),
        description: r.str_field("description").unwrap_or_default().to_string(),
        sources: r.deps("related"),
        supersedes: r.deps("supersedes"),
        close_reason: r.str_field("close_reason").map(String::from),
        closed_at: r.closed_at(),
        created_at: r.created_at.clone().unwrap_or(Timestamp(i64::MAX)),
        created_seq: r.created_seq,
        unknown_keys: r.shown_unknowns(closed),
    })
}

/// Whether an unknown `member` of origin `origin` is listed for spec `id`:
/// always when an edge ties it to the spec, else only when the unknown is
/// its edge to the spec.
pub(crate) fn record_unknown(origin: Origin, member: &Member, id: &str) -> bool {
    match (origin, member) {
        (Origin::Direct, _) => true,
        (Origin::Maybe, Member::Unknown { key, .. }) => key.strip_prefix("dep:") == Some(id),
        _ => false,
    }
}

/// What a command may rebuild: at most `issues` distinct issues charged
/// ([`MAX_HISTORY_ISSUES`]), and at most `replay` events replayed over all
/// its rebuilds ([`MAX_HISTORY_REPLAY`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub issues: usize,
    pub replay: usize,
}

impl Limits {
    /// At most `issues` issues, and the default replay budget.
    pub fn issues(issues: usize) -> Limits {
        Limits { issues, replay: MAX_HISTORY_REPLAY }
    }
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { issues: MAX_HISTORY_ISSUES, replay: MAX_HISTORY_REPLAY }
    }
}

/// The command a [`Rebuilder`] works for, which its refusals fit.
#[derive(Clone, Debug)]
pub(crate) enum Refusal {
    /// `bd spec show --as-of`, at the point's label.
    Show(String),
    /// `bd spec changes`: a narrower window or one spec helps.
    Changes,
}

impl Refusal {
    fn error(&self, what: String) -> Error {
        Error::invalid(match self {
            Refusal::Show(label) => format!("{what} at {label}"),
            Refusal::Changes => format!("{what}: name a narrower window or one spec"),
        })
    }
}

/// What a probe of a hidden id ([`After::hidden`]) found in its own events
/// and row: every edge target and whether it was ever labelled a spec, which
/// are all a rebuild could know of its membership (the removals naming it
/// carry neither, so they are not read). Nothing else is kept.
struct Probe {
    targets: BTreeSet<String>,
    spec_label: bool,
}

impl Probe {
    /// From the id's own events and its row's snapshot, if it has a row.
    fn of(history: &[Event], row: Option<&Value>) -> Probe {
        let mut targets = BTreeSet::new();
        let mut spec_label = false;
        let mut snapshot = |snap: &Value, targets: &mut BTreeSet<String>| {
            for d in snap.get("dependencies").and_then(Value::as_array).into_iter().flatten() {
                if let Some(t) = d.get("target").and_then(Value::as_str) {
                    targets.insert(t.to_string());
                }
            }
            if snap.get("labels").and_then(Value::as_array).is_some_and(|l| l.iter().any(|l| l == SPEC)) {
                spec_label = true;
            }
        };
        if let Some(row) = row {
            snapshot(row, &mut targets);
        }
        for e in history {
            let d = &e.data;
            for key in ["issue", "previous"] {
                if let Some(snap) = d.get(key).filter(|v| v.is_object()) {
                    snapshot(snap, &mut targets);
                }
            }
            if e.op.starts_with("dep_")
                && let Some(t) = d.get("target").and_then(Value::as_str)
            {
                targets.insert(t.to_string());
            }
        }
        // The labels an update added or removed.
        let changed = history.iter().any(|e| {
            ["added", "removed"].iter().any(|side| {
                e.data
                    .pointer(&format!("/changes/labels/{side}"))
                    .and_then(Value::as_array)
                    .is_some_and(|l| l.iter().any(|l| l == SPEC))
            })
        });
        Probe { targets, spec_label: spec_label || changed }
    }
}

/// Rebuilds issues at points over one [`History`], each issue's events
/// loaded once; at most [`Limits::issues`] distinct issues charged and
/// [`Limits::replay`] events replayed. The ids only a later removal or
/// import names ([`After::hidden`]) are probed first, uncharged
/// ([`Rebuilder::relevant_kid`], [`Rebuilder::relevant_spec`]), from their
/// own events and row only (never [`History::load_issue`], which scans and
/// clones the removals naming them): only those whose history could make
/// them a child of the spec (an edge to it) or a spec (a `spec` label) are
/// charged, then loaded and rebuilt.
pub(crate) struct Rebuilder<'c> {
    conn: &'c Connection,
    hist: History,
    /// By id, charged; `None` when the workspace has neither a row nor events of it.
    loaded: RefCell<HashMap<String, Option<Rc<Loaded>>>>,
    /// Hidden ids probed, uncharged: what each probe found, never a [`Loaded`].
    probed: RefCell<HashMap<String, Rc<Probe>>>,
    limits: Limits,
    replayed: Cell<usize>,
    refusal: Refusal,
    incomplete: Cell<bool>,
}

impl<'c> Rebuilder<'c> {
    pub(crate) fn new(conn: &'c Connection, limits: Limits, refusal: Refusal) -> Result<Rebuilder<'c>> {
        Ok(Rebuilder {
            conn,
            hist: History::load(conn)?,
            loaded: RefCell::default(),
            probed: RefCell::default(),
            limits,
            replayed: Cell::new(0),
            refusal,
            incomplete: Cell::new(false),
        })
    }

    pub(crate) fn conn(&self) -> &'c Connection {
        self.conn
    }

    pub(crate) fn hist(&self) -> &History {
        &self.hist
    }

    /// Whether any rebuild relied on history written by an older bd.
    pub(crate) fn incomplete(&self) -> bool {
        self.incomplete.get()
    }

    fn read(&self, id: &str) -> Result<Option<Rc<Loaded>>> {
        #[cfg(test)]
        READS.with(|r| r.set(r.get() + 1));
        match self.hist.load_issue(self.conn, id) {
            Ok(l) => Ok(Some(Rc::new(l))),
            Err(Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn load(&self, id: &str) -> Result<Option<Rc<Loaded>>> {
        if let Some(l) = self.loaded.borrow().get(id) {
            return Ok(l.clone());
        }
        if self.loaded.borrow().len() >= self.limits.issues {
            return Err(self.refusal.error(format!("more than {} issues to rebuild", self.limits.issues)));
        }
        let loaded = self.read(id)?;
        self.loaded.borrow_mut().insert(id.to_string(), loaded.clone());
        Ok(loaded)
    }

    /// Hidden id `id`'s probe, read once and never charged: its own events
    /// and row, never the removals naming it. No row and no events: nothing.
    fn probe(&self, id: &str) -> Result<Rc<Probe>> {
        if let Some(p) = self.probed.borrow().get(id) {
            return Ok(p.clone());
        }
        let history = crate::events::history(self.conn, id)?;
        let row = match issues::get(self.conn, id)? {
            Some(_) => Some(issues::snapshot(self.conn, id)?),
            None => None,
        };
        let p = Rc::new(Probe::of(&history, row.as_ref()));
        self.probed.borrow_mut().insert(id.to_string(), p.clone());
        Ok(p)
    }

    /// Whether hidden id `id` could have been a child of a spec `parent`
    /// accepts at any point: an edge of its, in an event, a snapshot or its
    /// row, to one. Charged ids are always relevant: rebuilding them costs
    /// nothing more.
    pub(crate) fn relevant_kid(&self, id: &str, parent: &dyn Fn(&str) -> bool) -> Result<bool> {
        if self.loaded.borrow().contains_key(id) {
            return Ok(true);
        }
        let p = self.probe(id)?;
        Ok(p.targets.iter().any(|t| parent(t)))
    }

    /// Whether hidden id `id` could have been a spec at any point: a `spec`
    /// label in a snapshot, an update's labels or its row.
    pub(crate) fn relevant_spec(&self, id: &str) -> Result<bool> {
        if self.loaded.borrow().contains_key(id) {
            return Ok(true);
        }
        let p = self.probe(id)?;
        Ok(p.spec_label)
    }

    /// `id` at `point`; `None` when the workspace has never held it.
    pub(crate) fn at(&self, id: &str, point: Point) -> Result<Option<Rebuilt>> {
        let Some(loaded) = self.load(id)? else { return Ok(None) };
        let replayed = self.replayed.get().saturating_add(loaded.history.len().max(1));
        if replayed > self.limits.replay {
            return Err(self.refusal.error(format!("more than {} events to replay", self.limits.replay)));
        }
        self.replayed.set(replayed);
        let d = self.hist.rebuild(self.conn, &loaded, point)?;
        if d.incomplete {
            self.incomplete.set(true);
        }
        let created_at = created_at(&d, &loaded, point);
        let created_seq = created_by(&d, point);
        Ok(Some(Rebuilt { d, created_at, created_seq }))
    }
}

#[cfg(test)]
thread_local! {
    /// The issues this thread's [`Rebuilder`]s loaded through [`History::load_issue`].
    pub(crate) static READS: Cell<usize> = const { Cell::new(0) };
}

/// Whether an issue was a spec at a point.
enum SpecAt {
    Spec(Node),
    /// The history cannot tell: why.
    Unknown(String),
    No,
}

/// A [`Source`] of the issues as they were at a point: children are the
/// members ([`classify`]) among the [`raw_candidates`]; what it cannot place
/// is collected by the spec it would be under.
pub(crate) struct AsOfSource<'r, 'c> {
    rb: &'r Rebuilder<'c>,
    point: Point,
    after: &'r After,
    rebuilt: RefCell<HashMap<String, Option<Rc<Rebuilt>>>>,
    nodes: RefCell<HashMap<String, Option<Node>>>,
    kids: RefCell<HashMap<String, Vec<String>>>,
    unknown: RefCell<BTreeMap<String, Vec<UnknownItem>>>,
}

impl<'r, 'c> AsOfSource<'r, 'c> {
    pub(crate) fn new(rb: &'r Rebuilder<'c>, point: Point, after: &'r After) -> AsOfSource<'r, 'c> {
        AsOfSource {
            rb,
            point,
            after,
            rebuilt: RefCell::default(),
            nodes: RefCell::default(),
            kids: RefCell::default(),
            unknown: RefCell::default(),
        }
    }

    /// `id` at the point, each issue rebuilt once.
    pub(crate) fn rebuilt(&self, id: &str) -> Result<Option<Rc<Rebuilt>>> {
        if let Some(r) = self.rebuilt.borrow().get(id) {
            return Ok(r.clone());
        }
        let r = self.rb.at(id, self.point)?.map(Rc::new);
        self.rebuilt.borrow_mut().insert(id.to_string(), r.clone());
        Ok(r)
    }

    /// List `key` of issue `id` as unknown under spec `under`, once.
    fn note(&self, under: &str, id: &str, key: &str, reason: &str) {
        let item = UnknownItem::new(id, key, reason);
        let mut all = self.unknown.borrow_mut();
        let list = all.entry(under.to_string()).or_default();
        if !list.iter().any(|u| u.id == item.id && u.key == item.key) {
            list.push(item);
        }
    }

    /// List what the history cannot tell of what is shown of spec `id` itself, under it.
    fn note_own(&self, id: &str) -> Result<()> {
        if let Some(r) = self.rebuilt(id)? {
            let closed = r.status() == Some(Status::Closed);
            for (key, reason) in r.shown_unknowns(closed) {
                self.note(id, id, &key, &reason);
            }
        }
        Ok(())
    }

    /// List under root `root` what the history cannot tell of the specs it
    /// inherits from, where that ends the chain [`super::ancestors`] walks:
    /// a parent whose existence, spec label, title or status is unknown, or
    /// an edge of one that may be its parent edge.
    fn note_ancestry(&self, root: &str) -> Result<()> {
        let mut seen: BTreeSet<String> = BTreeSet::from([root.to_string()]);
        let mut parent = self.rebuilt(root)?.and_then(|r| r.parent().map(String::from));
        for _ in 0..MAX_DEPTH {
            let Some(p) = parent.take() else { break };
            if !seen.insert(p.clone()) {
                break;
            }
            let Some(r) = self.rebuilt(&p)? else { break };
            if let Some(u) = r.unknown("exists") {
                self.note(root, &p, &u.key, &u.reason);
                break;
            }
            if !r.d.exists {
                break;
            }
            if !r.has(SPEC) {
                if let Some(u) = r.unknown(&format!("label:{SPEC}")) {
                    self.note(root, &p, &u.key, &u.reason);
                }
                break;
            }
            let Some(node) = self.node(&p)? else {
                if let Some(u) = r.unknown("title").or_else(|| r.unknown("status")) {
                    self.note(root, &p, &u.key, &u.reason);
                }
                break;
            };
            if node.status == Status::Closed {
                break;
            }
            match r.parent() {
                Some(next) => parent = Some(next.to_string()),
                // No known parent: an unknown edge of its may be its parent edge.
                None => {
                    for u in r.d.unknown.iter().filter(|u| u.key.starts_with("dep:")) {
                        self.note(root, &p, &u.key, &u.reason);
                    }
                }
            }
        }
        Ok(())
    }

    /// What was collected, by the spec it is under.
    pub(crate) fn take_unknown(&self) -> BTreeMap<String, Vec<UnknownItem>> {
        std::mem::take(&mut *self.unknown.borrow_mut())
    }

    fn spec_at(&self, id: &str) -> Result<SpecAt> {
        let Some(r) = self.rebuilt(id)? else { return Ok(SpecAt::No) };
        if let Some(u) = r.unknown("exists") {
            return Ok(SpecAt::Unknown(format!("{id} {}: {}", u.key, u.reason)));
        }
        if !r.d.exists {
            return Ok(SpecAt::No);
        }
        if !r.has(SPEC) {
            return Ok(match r.unknown(&format!("label:{SPEC}")) {
                Some(u) => SpecAt::Unknown(format!("{id} {}: {}", u.key, u.reason)),
                None => SpecAt::No,
            });
        }
        match self.node(id)? {
            Some(n) => Ok(SpecAt::Spec(n)),
            None => {
                let u = r.unknown("title").or_else(|| r.unknown("status"));
                Ok(SpecAt::Unknown(match u {
                    Some(u) => format!("{id} {}: {}", u.key, u.reason),
                    None => format!("{id} status: not a recorded value"),
                }))
            }
        }
    }
}

impl Source for AsOfSource<'_, '_> {
    fn node(&self, id: &str) -> Result<Option<Node>> {
        if let Some(n) = self.nodes.borrow().get(id) {
            return Ok(n.clone());
        }
        let node = self.rebuilt(id)?.and_then(|r| r.node());
        self.nodes.borrow_mut().insert(id.to_string(), node.clone());
        Ok(node)
    }

    fn kids(&self, id: &str) -> Result<Vec<String>> {
        if let Some(k) = self.kids.borrow().get(id) {
            return Ok(k.clone());
        }
        // As `hierarchy::child_issues` orders them: by created_at, then rowid (creation order), then id.
        let mut members: Vec<(Timestamp, bool, Option<i64>, String)> = Vec::new();
        for (c, origin) in raw_candidates(self.rb.conn(), self.after, id)? {
            if origin == Origin::Maybe && self.after.hidden.contains(&c) && !self.rb.relevant_kid(&c, &|x| x == id)? {
                continue;
            }
            let Some(r) = self.rebuilt(&c)? else { continue };
            match classify(&r, &|x| x == id) {
                Member::Out => {}
                m @ Member::Unknown { .. } => {
                    if record_unknown(origin, &m, id)
                        && let Member::Unknown { key, reason } = &m
                    {
                        self.note(id, &c, key, reason);
                    }
                }
                Member::In(item) => {
                    for (key, reason) in &item.unknown_keys {
                        self.note(id, &c, key, reason);
                    }
                    members.push((item.created_at, item.created_seq.is_none(), item.created_seq, c));
                }
            }
        }
        members.sort();
        let ids: Vec<String> = members.into_iter().map(|(_, _, _, c)| c).collect();
        self.kids.borrow_mut().insert(id.to_string(), ids.clone());
        Ok(ids)
    }
}

/// The spec issues `arg` names at the point, as [`super::show`] resolves
/// them now: an id that was a spec then, else the area's specs open then
/// (in id order), else an id `bd show` resolves now that was a spec then.
/// When it names none, why the history cannot tell (empty when it can).
fn resolve_at(
    src: &AsOfSource<'_, '_>,
    conn: &Connection,
    arg: &str,
) -> Result<std::result::Result<Vec<Node>, Vec<String>>> {
    let mut why: Vec<String> = Vec::new();
    match src.spec_at(arg)? {
        SpecAt::Spec(n) => return Ok(Ok(vec![n])),
        SpecAt::Unknown(r) => why.push(r),
        SpecAt::No => {}
    }
    let area = format!("area:{arg}");
    let mut ids: BTreeSet<String> = labelled(conn, SPEC)?.into_iter().collect();
    ids.extend(src.after.specs.iter().cloned());
    let mut found = Vec::new();
    for id in ids {
        if src.after.hidden.contains(&id) && !src.rb.relevant_spec(&id)? {
            continue;
        }
        match src.spec_at(&id)? {
            SpecAt::Spec(n) if n.has(&area) && n.status != Status::Closed => found.push(n),
            SpecAt::Spec(_) => {
                if let Some(r) = src.rebuilt(&id)?
                    && let Some(u) = r.unknown(&format!("label:{area}"))
                {
                    why.push(format!("{id} {}: {}", u.key, u.reason));
                }
            }
            SpecAt::Unknown(r) => {
                if src.rebuilt(&id)?.is_some_and(|x| x.has(&area)) {
                    why.push(r);
                }
            }
            SpecAt::No => {}
        }
    }
    if !found.is_empty() {
        return Ok(Ok(found));
    }
    if let Some(id) = issues::lookup_id(conn, arg)?
        && id != arg
    {
        match src.spec_at(&id)? {
            SpecAt::Spec(n) => return Ok(Ok(vec![n])),
            SpecAt::Unknown(r) => why.push(r),
            SpecAt::No => {}
        }
    }
    Ok(Err(why))
}

/// Not found (exit 3): `arg` named no spec at `label`, and why the history
/// cannot tell.
fn not_found_at(arg: &str, label: &str, why: &[String]) -> Error {
    let mut msg = format!("{arg} at {label} (name a spec issue's id or its area:<name> label)");
    if !why.is_empty() {
        msg.push_str(": the history cannot tell ");
        msg.push_str(&why.join("; "));
    }
    Error::not_found("spec", clean(&msg))
}

/// [`resolve_at`], not found (exit 3) when `arg` named no spec then.
fn resolve(src: &AsOfSource<'_, '_>, conn: &Connection, arg: &str, label: &str) -> Result<Vec<Node>> {
    resolve_at(src, conn, arg)?.map_err(|why| not_found_at(arg, label, &why))
}

/// Set each view's `unknown`, its sub-specs' too, from `unknown`.
fn fill(view: &mut SpecView, unknown: &BTreeMap<String, Vec<UnknownItem>>) {
    view.unknown = Some(unknown.get(&view.spec.id).cloned().unwrap_or_default());
    for s in &mut view.subspecs {
        fill(s, unknown);
    }
}

/// The views of the specs `arg` names, as they were at `point`, from the
/// retained events (see the [module](self) docs): [`super::show`] at a past
/// point. Not found (exit 3) when `arg` named no spec then; a point before
/// retained history is [`Error::HistoryPruned`] (exit 6); more than
/// [`MAX_HISTORY_ISSUES`] issues to rebuild, or [`MAX_HISTORY_REPLAY`]
/// events to replay, is refused (exit 2).
pub fn show_as_of(conn: &Connection, arg: &str, point: Point) -> Result<Vec<SpecView>> {
    show_as_of_with_cap(conn, arg, point, Limits::default())
}

/// [`show_as_of`] within `limits`.
pub fn show_as_of_with_cap(conn: &Connection, arg: &str, point: Point, limits: Limits) -> Result<Vec<SpecView>> {
    let label = PointView::of(point).label();
    let rb = Rebuilder::new(conn, limits, Refusal::Show(label.clone()))?;
    rb.hist().check(point)?;
    let events = events_after(conn, rb.hist(), point, None)?;
    let after = After::of(&events, point);
    let src = AsOfSource::new(&rb, point, &after);
    let roots = resolve(&src, conn, arg.trim(), &label)?;
    for r in &roots {
        src.note_own(&r.id)?;
        src.note_ancestry(&r.id)?;
    }
    let mut views = spec_views(&roots, &src)?;
    let unknown = src.take_unknown();
    for v in &mut views {
        fill(v, &unknown);
        // Inherited requirements are shown on the top view: so are their unknowns.
        let mut list = v.unknown.take().unwrap_or_default();
        for a in &v.inherited {
            for u in unknown.get(&a.spec.id).into_iter().flatten() {
                if !list.iter().any(|x| x.id == u.id && x.key == u.key) {
                    list.push(u.clone());
                }
            }
        }
        v.unknown = Some(list);
        v.as_of = Some(PointView::of(point));
        v.incomplete = Some(rb.incomplete());
        v.retained_from = Some(rb.hist().retained());
    }
    Ok(views)
}

// ---------------------------------------------------------------------------
// bd spec changes.

/// One change to a spec's requirements, non-goals or sub-specs in a window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    /// The event of the transaction that made it (its last of the item's).
    pub seq: i64,
    pub at: Timestamp,
    pub actor: String,
    /// The spec it is attributed to: the item's own parent spec.
    pub spec: String,
    pub id: String,
    /// `requirement`, `non-goal` or `spec`.
    pub item: &'static str,
    /// `added`, `superseded`, `removed` or `edited`.
    pub kind: &'static str,
    pub title: String,
    /// Its outgoing `related` edges then.
    pub sources: Vec<String>,
    /// `superseded` only: the replacement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<Brief>,
    /// `removed` only: the close reason, `moved to <id>`, `moved out`,
    /// `relabelled <kind>`, `unlabelled <kind>`, `deleted` or `purged`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `edited` only: the title before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_title: Option<String>,
    /// `edited` only: whether the description changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_changed: Option<bool>,
}

/// What changed in the specs between two points (`bd spec changes`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Changes {
    pub since: PointView,
    pub until: PointView,
    /// The specs in scope, at either end, in id order.
    pub specs: Vec<Brief>,
    /// In seq order, a removal before an addition at the same seq.
    pub changes: Vec<Change>,
    /// Memberships the history cannot tell, never reported as changes.
    pub unknown: Vec<UnknownItem>,
    /// Whether a rebuild relied on history written by an older bd.
    pub incomplete: bool,
}

/// Whether `since` is before `until`. Points of one kind compare directly;
/// a seq and a time by the seq's event time, taken as before when that
/// event is not retained (the window is then only possibly empty).
fn ordered(conn: &Connection, since: Point, until: Point) -> Result<bool> {
    let ts = |n: i64| -> Result<Option<Timestamp>> {
        Ok(conn.prepare_cached("SELECT ts FROM events WHERE seq = ?1")?.query_row([n], |r| r.get(0)).optional()?)
    };
    Ok(match (since, until) {
        (Point::Seq(a), Point::Seq(b)) => a < b,
        (Point::Time(a), Point::Time(b)) => a < b,
        (Point::Seq(n), Point::Time(t)) => ts(n)?.is_none_or(|x| x <= t),
        (Point::Time(t), Point::Seq(n)) => ts(n)?.is_none_or(|x| x > t),
    })
}

/// The specs in scope at a point: `target`'s ([`resolve_at`]) and their open
/// sub-specs then (to [`MAX_DEPTH`]), or every spec then. When `target`
/// named none then, why the history cannot tell.
fn scope_at(
    src: &AsOfSource<'_, '_>,
    conn: &Connection,
    target: Option<&str>,
) -> Result<std::result::Result<BTreeSet<String>, Vec<String>>> {
    let mut out = BTreeSet::new();
    let Some(arg) = target else {
        let mut ids: BTreeSet<String> = labelled(conn, SPEC)?.into_iter().collect();
        ids.extend(src.after.specs.iter().cloned());
        for id in ids {
            if src.after.hidden.contains(&id) && !src.rb.relevant_spec(&id)? {
                continue;
            }
            if let SpecAt::Spec(_) = src.spec_at(&id)? {
                out.insert(id);
            }
        }
        return Ok(Ok(out));
    };
    let roots = match resolve_at(src, conn, arg)? {
        Ok(roots) => roots,
        Err(why) => return Ok(Err(why)),
    };
    fn subs(src: &AsOfSource<'_, '_>, id: &str, depth: usize, out: &mut BTreeSet<String>) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Ok(());
        }
        for k in src.kids(id)? {
            if let Some(n) = src.node(&k)?
                && n.is_spec()
                && n.status != Status::Closed
                && out.insert(k.clone())
            {
                subs(src, &k, depth + 1, out)?;
            }
        }
        Ok(())
    }
    for r in &roots {
        out.insert(r.id.clone());
    }
    for r in &roots {
        subs(src, &r.id, 1, &mut out)?;
    }
    Ok(Ok(out))
}

/// A candidate at a point: what it is to the specs in scope, whether it was
/// gone (never held, or known not to exist), and its parent then.
struct State {
    member: Member,
    gone: bool,
    parent: Option<String>,
}

impl State {
    fn of(r: Option<&Rebuilt>, scope: &BTreeSet<String>) -> State {
        match r {
            None => State { member: Member::Out, gone: true, parent: None },
            Some(r) => State {
                member: classify(r, &|x| scope.contains(x)),
                gone: !r.d.exists && r.unknown("exists").is_none(),
                parent: r.parent().map(String::from),
            },
        }
    }

    /// The member, when it was one in force.
    fn open(&self) -> Option<&Item> {
        match &self.member {
            Member::In(i) if !i.closed => Some(i),
            _ => None,
        }
    }
}

/// The unknown `key` among `item`'s.
fn item_unknown<'i>(item: &'i Item, key: &str) -> Option<&'i (String, String)> {
    item.unknown_keys.iter().find(|(k, _)| k == key)
}

/// The changes of a candidate's transaction, from `before` to `after`;
/// `ev` its last event of the candidate's, `ops` the ops of them. Values
/// the comparison needed and the history cannot tell are pushed to `unknown`.
#[allow(clippy::too_many_arguments)]
fn transition(
    rb: &Rebuilder<'_>,
    id: &str,
    point: i64,
    ev: &Event,
    ops: &[&str],
    before: &State,
    after: &State,
    unknown: &mut Vec<(String, String)>,
) -> Result<Vec<Change>> {
    let change = |kind: &'static str, item: &Item, title: &str| Change {
        seq: point,
        at: ev.ts,
        actor: clean(&ev.actor),
        spec: clean(&item.spec),
        id: clean(id),
        item: item.item.as_str(),
        kind,
        title: clean(title),
        sources: item.sources.iter().map(|s| clean(s)).collect(),
        by: None,
        reason: None,
        old_title: None,
        description_changed: None,
    };
    let removed =
        |item: &Item, reason: String| Change { reason: Some(clean(&reason)), ..change("removed", item, &item.title) };
    let sources_of = |item: &Item, unknown: &mut Vec<(String, String)>| {
        unknown.extend(item.unknown_keys.iter().filter(|(k, _)| k.starts_with("dep:")).cloned());
    };
    let mut out = Vec::new();
    if matches!(before.member, Member::Unknown { .. }) || matches!(after.member, Member::Unknown { .. }) {
        return Ok(out);
    }
    match (before.open(), &after.member) {
        (Some(b), Member::In(a)) if !a.closed => {
            if b.spec != a.spec || b.item != a.item {
                let reason = if b.spec != a.spec {
                    format!("moved to {}", a.spec)
                } else {
                    format!("relabelled {}", a.item.as_str())
                };
                sources_of(b, unknown);
                sources_of(a, unknown);
                out.push(removed(b, reason));
                out.push(change("added", a, &a.title));
            } else {
                let desc = [b, a].iter().find_map(|i| item_unknown(i, "description"));
                if let Some(u) = desc {
                    unknown.push(u.clone());
                }
                let description_changed = desc.is_none() && b.description != a.description;
                if b.title != a.title || description_changed {
                    sources_of(a, unknown);
                    out.push(Change {
                        old_title: Some(clean(&b.title)),
                        description_changed: Some(description_changed),
                        ..change("edited", a, &a.title)
                    });
                }
            }
        }
        (Some(b), Member::In(a)) => {
            // Closed: superseded when it has a replacement then, else removed.
            match a.supersedes.first() {
                Some(by) => {
                    let title = rb
                        .at(by, Point::Seq(point))?
                        .and_then(|r| r.str_field("title").map(String::from))
                        .unwrap_or_default();
                    sources_of(a, unknown);
                    out.push(Change {
                        by: Some(Brief { id: clean(by), title: clean(&title) }),
                        ..change("superseded", a, &a.title)
                    });
                }
                None => {
                    sources_of(b, unknown);
                    out.push(removed(b, a.close_reason.clone().unwrap_or_default()));
                }
            }
        }
        (Some(b), Member::Out) => {
            let reason = if after.gone {
                if ops.iter().any(|o| matches!(*o, "purged" | "run_compacted")) { "purged" } else { "deleted" }
                    .to_string()
            } else if after.parent.as_deref() != Some(b.spec.as_str()) {
                match &after.parent {
                    Some(p) => format!("moved to {p}"),
                    None => "moved out".into(),
                }
            } else {
                format!("unlabelled {}", b.item.as_str())
            };
            sources_of(b, unknown);
            out.push(removed(b, reason));
        }
        (None, Member::In(a)) if !a.closed => {
            sources_of(a, unknown);
            out.push(change("added", a, &a.title));
        }
        _ => {}
    }
    Ok(out)
}

/// Whether event `e` cannot change what [`State::of`] and [`transition`]
/// read of its issue: an update of other fields only, or an edge of a type
/// that neither places nor sources an item. An import's `dep_added` is
/// never inert: it may have replaced an edge of another type that it did
/// not record (asof treats it so). A transaction of such events alone keeps
/// the state and is not rebuilt.
fn inert(e: &Event) -> bool {
    match e.op.as_str() {
        "updated" => e.data["changes"].as_object().is_some_and(|c| {
            c.keys().all(|k| {
                !matches!(
                    k.as_str(),
                    "title" | "description" | "status" | "labels" | "parent" | "close_reason" | "closed_at"
                )
            })
        }),
        "dep_added" | "dep_removed" | "dep_updated" => {
            e.data["import"] != json!(true)
                && e.data["type"].as_str().is_some_and(|t| !matches!(t, "parent-child" | "related" | "supersedes"))
        }
        _ => false,
    }
}

/// What changed in the specs `target` names (or every spec) between `since`
/// and `until`: the events `e` with `since < e <= until`. Attributed to each
/// item's own parent spec among the specs in scope at either end and their
/// sub-specs. A `since` before retained history is [`Error::HistoryPruned`]
/// (exit 6); `since` not before `until` is refused (exit 2), and so are more
/// than [`MAX_HISTORY_ISSUES`] issues to rebuild or [`MAX_HISTORY_REPLAY`]
/// events to replay. Reads only.
pub fn changes(conn: &Connection, target: Option<&str>, since: Point, until: Point) -> Result<Changes> {
    changes_with_cap(conn, target, since, until, Limits::default())
}

/// [`changes`] within `limits`.
pub fn changes_with_cap(
    conn: &Connection,
    target: Option<&str>,
    since: Point,
    until: Point,
    limits: Limits,
) -> Result<Changes> {
    let target = target.map(str::trim);
    let rb = Rebuilder::new(conn, limits, Refusal::Changes)?;
    let hist = rb.hist();
    hist.check(since)?;
    hist.check(until)?;
    // With seq 1 retained nothing was pruned: a time before the first event
    // (`--since 30d` in a younger workspace) is a window from the start.
    if hist.floor() > 1 && hist.before_retention(since) {
        return Err(Error::HistoryPruned {
            id: clean(target.unwrap_or("the specs")),
            floor: hist.floor(),
            floor_ts: hist.floor_ts(),
        });
    }
    if !ordered(conn, since, until)? {
        return Err(Error::invalid("--since must be before --until"));
    }
    let (since_label, until_label) = (PointView::of(since).label(), PointView::of(until).label());

    // One read of the events after since: the window, and what follows each end.
    let events = events_after(conn, hist, since, None)?;
    let window: Vec<&Event> = events.iter().filter(|e| until.includes(e)).collect();
    let after_s = After::of(&events, since);
    let after_u = After::of(&events, until);
    let src_s = AsOfSource::new(&rb, since, &after_s);
    let src_u = AsOfSource::new(&rb, until, &after_u);

    let mut scope = BTreeSet::new();
    let mut why = Vec::new();
    let mut found = false;
    for src in [&src_s, &src_u] {
        match scope_at(src, conn, target)? {
            Ok(s) => {
                found = true;
                scope.extend(s);
            }
            Err(w) => why.extend(w.into_iter().filter(|w| !why.contains(w)).collect::<Vec<_>>()),
        }
    }
    if let Some(arg) = target
        && !found
    {
        return Err(not_found_at(arg, &format!("{since_label} or {until_label}"), &why));
    }

    // Candidates: every issue that may have been a child of a spec in scope
    // at since or later, unfiltered (the events after since cover those
    // after until). Direct evidence wins.
    let mut candidates: BTreeMap<String, Origin> = BTreeMap::new();
    for s in &scope {
        for (c, origin) in raw_candidates(conn, &after_s, s)? {
            let e = candidates.entry(c).or_insert(origin);
            if origin == Origin::Direct {
                *e = Origin::Direct;
            }
        }
    }

    // The window's events by the issue they change (purges by every id they name).
    let mut by_issue: HashMap<&str, Vec<&Event>> = HashMap::new();
    for e in &window {
        if let Some(id) = e.issue_id.as_deref() {
            by_issue.entry(id).or_default().push(e);
        }
        if matches!(e.op.as_str(), "purged" | "run_compacted") {
            for x in e.data["ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if Some(x) != e.issue_id.as_deref() {
                    by_issue.entry(x).or_default().push(e);
                }
            }
        }
    }

    let mut out: Vec<Change> = Vec::new();
    let mut unknown: Vec<UnknownItem> = Vec::new();
    let mut note = |id: &str, origin: Origin, key: &str, reason: &str| {
        let listed = match origin {
            Origin::Direct => true,
            Origin::Maybe => key.strip_prefix("dep:").is_some_and(|x| scope.contains(x)),
        };
        let item = UnknownItem::new(id, key, reason);
        if listed && !unknown.iter().any(|u| u.id == item.id && u.key == item.key) {
            unknown.push(item);
        }
    };
    for (c, origin) in &candidates {
        if *origin == Origin::Maybe && after_s.hidden.contains(c) && !rb.relevant_kid(c, &|x| scope.contains(x))? {
            continue;
        }
        let mut state = State::of(src_s.rebuilt(c)?.as_deref(), &scope);
        if let Member::Unknown { key, reason } = &state.member {
            note(c, *origin, key, reason);
        }
        // Its transactions in the window, in order: (last event, its events).
        let mut txs: Vec<(i64, Vec<&Event>)> = Vec::new();
        for e in by_issue.get(c.as_str()).into_iter().flatten() {
            match txs.last_mut() {
                Some((tx, list)) if *tx == e.tx => list.push(e),
                _ => txs.push((e.tx, vec![e])),
            }
        }
        for (_, list) in txs {
            if list.iter().all(|e| inert(e)) {
                continue;
            }
            let last = list.last().expect("a transaction has an event");
            let ops: Vec<&str> = list.iter().map(|e| e.op.as_str()).collect();
            let next = State::of(rb.at(c, Point::Seq(last.seq))?.as_ref(), &scope);
            if let Member::Unknown { key, reason } = &next.member {
                note(c, *origin, key, reason);
            }
            let mut keys = Vec::new();
            out.extend(transition(&rb, c, last.seq, last, &ops, &state, &next, &mut keys)?);
            for (key, reason) in keys {
                note(c, *origin, &key, &reason);
            }
            state = next;
        }
    }

    // A replacement added in the window under the spec of what it superseded is folded into the supersede.
    let replaced: BTreeSet<(String, String)> = out
        .iter()
        .filter(|c| c.kind == "superseded")
        .filter_map(|c| c.by.as_ref().map(|b| (c.spec.clone(), b.id.clone())))
        .collect();
    out.retain(|c| !(c.kind == "added" && replaced.contains(&(c.spec.clone(), c.id.clone()))));
    out.sort_by_key(|c| (c.seq, c.kind != "removed"));

    let mut specs = Vec::with_capacity(scope.len());
    for id in &scope {
        let title = match src_u.node(id)? {
            Some(n) => n.title,
            None => src_s.node(id)?.map(|n| n.title).unwrap_or_default(),
        };
        specs.push(Brief { id: clean(id), title: clean(&title) });
    }
    Ok(Changes {
        since: PointView::of(since),
        until: PointView::of(until),
        specs,
        changes: out,
        unknown,
        incomplete: rb.incomplete(),
    })
}

/// `changes` as Markdown: a section per spec with changes (`Added`,
/// `Changed`, `Removed`), then what the history cannot tell.
pub fn render_changes(changes: &Changes) -> String {
    let (since, until) = (changes.since.label(), changes.until.label());
    let mut lines: Vec<String> = Vec::new();
    if changes.changes.is_empty() {
        lines.push(format!("No spec changes between {since} and {until}."));
        lines.push(String::new());
    } else {
        lines.push(format!("# Spec changes between {since} and {until}"));
        lines.push(String::new());
        for s in &changes.specs {
            let mine: Vec<&Change> = changes.changes.iter().filter(|c| c.spec == s.id).collect();
            if mine.is_empty() {
                continue;
            }
            lines.push(format!("## {} ({})", s.title, s.id));
            lines.push(String::new());
            let sections: [(&str, &[&str]); 3] =
                [("Added", &["added"]), ("Changed", &["superseded", "edited"]), ("Removed", &["removed"])];
            for (heading, kinds) in sections {
                let items: Vec<String> =
                    mine.iter().filter(|c| kinds.contains(&c.kind)).map(|c| change_line(c)).collect();
                if items.is_empty() {
                    continue;
                }
                lines.push(format!("### {heading}"));
                lines.push(String::new());
                lines.extend(items);
                lines.push(String::new());
            }
        }
    }
    for u in &changes.unknown {
        lines.push(format!("> Unknown: {} {}: {}", u.id, u.key, u.reason));
        lines.push(String::new());
    }
    format!("{}\n", lines.join("\n").trim_end())
}

/// One change's line.
fn change_line(c: &Change) -> String {
    let stamp = c.at.to_rfc3339();
    let date = stamp.get(..10).unwrap_or(&stamp).to_string();
    let from = (!c.sources.is_empty()).then(|| format!("from {}", c.sources.join(", ")));
    let refs = |head: Option<&str>, tail: Option<&str>| {
        let mut r: Vec<String> = head.map(String::from).into_iter().collect();
        r.extend(from.clone());
        r.push(date.clone());
        r.extend(tail.map(String::from));
        r.join("; ")
    };
    match c.kind {
        "added" => {
            let prefix = match c.item {
                "non-goal" => "Non-goal: ",
                "spec" => "Sub-spec: ",
                _ => "",
            };
            format!("- {prefix}{} ({})", c.title, refs(Some(&c.id), None))
        }
        "superseded" => {
            let (by_id, by_title) = c.by.as_ref().map(|b| (b.id.as_str(), b.title.as_str())).unwrap_or_default();
            format!("- {} ({}) -> {by_title} ({by_id}) ({})", c.title, c.id, refs(None, None))
        }
        "edited" => {
            let tail = (c.description_changed == Some(true)).then_some("description changed");
            let old = c.old_title.as_deref().unwrap_or_default();
            format!("- {old} ({}) -> {} ({}) ({})", c.id, c.title, c.id, refs(None, tail))
        }
        _ => format!(
            "- {} ({}): {}",
            c.title,
            refs(Some(&c.id), None),
            strip_removed(c.reason.as_deref().unwrap_or_default())
        ),
    }
}

#[cfg(test)]
mod tests;
