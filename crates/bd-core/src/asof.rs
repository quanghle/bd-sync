//! An issue as it was at a past moment, rebuilt from the event log.
//!
//! [`issue_as_of`] makes two passes over the issue's retained events. The
//! forward pass applies the "after" side of each event at or before the
//! point, from nothing known; the backward pass starts from the final state
//! (the live row, or nothing but its deletion) and undoes the "before" side
//! of each later event. A value both passes know and agree on is reported;
//! one only one pass knows is that pass's; one they disagree on was changed
//! without a recorded event, and is reported unknown, as is anything neither
//! pass can tell. Nothing is guessed.
//!
//! Gate arming (`metadata.gate.armed_at`) is derived from the `blocked` and
//! `unblocked` events, which every arming write but one goes with (see
//! [`crate::gates`]); that one records `gate_armed`.
//!
//! History before the `history_complete_from` marker (schema v4) was written
//! by an older bd, which made three kinds of writes without recording them:
//! gate arming, the text rewrites of `bd rename-prefix`, and the edges a
//! deletion dropped from surviving issues. A value whose evidence spans such
//! retained events is reported unknown where one of those writes could have
//! changed it, and the answer says its history is incomplete.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::error::{Error, Result};
use crate::events;
use crate::issues;
use crate::model::Event;
use crate::schema::HISTORY_COMPLETE_FROM;
use crate::store::meta_get;
use crate::time::{Timestamp, parse_duration, parse_when};

/// A moment in an issue's history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// The state just after the event with this seq.
    Seq(i64),
    /// The state after every event recorded at or before this time.
    Time(Timestamp),
}

impl Point {
    /// `N` or `#N`: an event seq; `-DURATION`: that long before `now`;
    /// anything else a time as [`parse_when`] reads it.
    pub fn parse(input: &str, now: Timestamp) -> Result<Point> {
        let s = input.trim();
        if let Some(n) = s.strip_prefix('#') {
            return n
                .parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .map(Point::Seq)
                .ok_or_else(|| Error::invalid(format!("invalid event seq {input:?} (a number, e.g. #120)")));
        }
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return s.parse().map(Point::Seq).map_err(|_| Error::invalid(format!("invalid event seq {input:?}")));
        }
        if let Some(ago) = s.strip_prefix('-') {
            return Ok(Point::Time(now.minus(parse_duration(ago)?)));
        }
        parse_when(s, now).map(Point::Time)
    }

    /// Whether `e` happened at or before this point.
    pub fn includes(&self, e: &Event) -> bool {
        match *self {
            Point::Seq(n) => e.seq <= n,
            Point::Time(t) => e.ts <= t,
        }
    }
}

/// An event by seq and time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventRef {
    pub seq: i64,
    pub ts: Timestamp,
}

impl EventRef {
    fn of(e: &Event) -> EventRef {
        EventRef { seq: e.seq, ts: e.ts }
    }
}

/// The point asked for: a seq or a time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PointView {
    pub seq: Option<i64>,
    pub time: Option<Timestamp>,
}

/// One dependency (outgoing edge) of the rebuilt issue.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DepAsOf {
    pub target: String,
    #[serde(rename = "type")]
    pub dep_type: String,
    pub metadata: Value,
}

/// A value the history cannot determine, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unknown {
    /// A field name, `label:NAME`, `dep:ID` or `exists`.
    pub key: String,
    pub reason: String,
}

/// The oldest event retention kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Retained {
    pub seq: i64,
    pub ts: Option<Timestamp>,
}

/// An issue as of a point.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IssueAsOf {
    pub id: String,
    pub point: PointView,
    /// Whether the issue existed then (created and not yet deleted). False,
    /// with no values reported, also when the history cannot tell: then
    /// `exists` is listed in `unknown`.
    pub exists: bool,
    /// Its creation: the latest at or before the point, else the first after it.
    pub created: Option<EventRef>,
    /// Its deletion following that creation, if one is retained.
    pub deleted: Option<EventRef>,
    /// Its fields, those the history determines, by name, in the JSON shape of an issue.
    pub fields: Map<String, Value>,
    pub labels: Vec<String>,
    pub dependencies: Vec<DepAsOf>,
    /// What the history cannot determine; left out of the values above.
    pub unknown: Vec<Unknown>,
    /// The issue's last event at or before the point.
    pub last_event: Option<i64>,
    pub retained_from: Retained,
    /// The seq from which every write records its full payload.
    pub history_complete_from: i64,
    /// Whether the answer relies on history written by an older bd, which
    /// did not record every change: values it could not confirm are unknown.
    pub incomplete: bool,
}

impl IssueAsOf {
    /// Whether the history cannot tell if the issue existed then.
    pub fn existence_unknown(&self) -> bool {
        self.unknown.iter().any(|u| u.key == "exists")
    }

    /// Whether the deletion is at or before the point.
    pub fn deleted_by_then(&self) -> bool {
        self.deleted.as_ref().is_some_and(|d| match (self.point.seq, self.point.time) {
            (Some(n), _) => d.seq <= n,
            (None, Some(t)) => d.ts <= t,
            (None, None) => false,
        })
    }
}

/// The fields rebuilt, in the JSON shape of [`crate::Issue`].
pub const FIELDS: [&str; 18] = [
    "title",
    "description",
    "design",
    "acceptance_criteria",
    "notes",
    "status",
    "priority",
    "issue_type",
    "assignee",
    "external_ref",
    "estimated_minutes",
    "due_at",
    "defer_until",
    "ephemeral",
    "metadata",
    "close_reason",
    "close_outcome",
    "closed_at",
];

const TIME_FIELDS: [&str; 3] = ["due_at", "defer_until", "closed_at"];
const TEXT_FIELDS: [&str; 7] =
    ["title", "description", "design", "acceptance_criteria", "notes", "close_reason", "metadata"];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Exists,
    Field(&'static str),
    Label(String),
    Dep(String),
}

impl Key {
    fn name(&self) -> String {
        match self {
            Key::Exists => "exists".into(),
            Key::Field(f) => (*f).into(),
            Key::Label(l) => format!("label:{l}"),
            Key::Dep(d) => format!("dep:{d}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Side {
    Known(Value),
    Unknown(String),
}

/// What a pass knows of a key, and the event that set it (`None`: no event;
/// for the backward pass, the final state).
#[derive(Clone, Debug)]
struct Slot {
    side: Side,
    at: Option<i64>,
}

/// One key an event changes: its value before and after, `None` for a side
/// the event leaves alone.
struct Change {
    key: Key,
    before: Option<Side>,
    after: Option<Side>,
}

enum Effect {
    Changes(Vec<Change>),
    /// A `blocked` (true) or `unblocked` event: gate arming.
    Block(bool),
}

#[derive(Default)]
struct Universe {
    labels: BTreeSet<String>,
    deps: BTreeSet<String>,
}

impl Universe {
    fn keys(&self) -> Vec<Key> {
        let mut keys = vec![Key::Exists];
        keys.extend(FIELDS.iter().map(|f| Key::Field(f)));
        keys.extend(self.labels.iter().cloned().map(Key::Label));
        keys.extend(self.deps.iter().cloned().map(Key::Dep));
        keys
    }

    fn add_snapshot(&mut self, snap: &Value) {
        for l in snap.get("labels").and_then(Value::as_array).into_iter().flatten() {
            if let Some(l) = l.as_str() {
                self.labels.insert(l.to_string());
            }
        }
        for d in snap.get("dependencies").and_then(Value::as_array).into_iter().flatten() {
            if let Some(t) = d.get("target").and_then(Value::as_str) {
                self.deps.insert(t.to_string());
            }
        }
    }

    fn add_event(&mut self, e: &Event) {
        let d = &e.data;
        for key in ["issue", "previous"] {
            if let Some(snap) = d.get(key).filter(|v| v.is_object()) {
                self.add_snapshot(snap);
            }
        }
        if let Some(labels) = d.pointer("/changes/labels") {
            for side in ["added", "removed"] {
                for l in labels.get(side).and_then(Value::as_array).into_iter().flatten() {
                    if let Some(l) = l.as_str() {
                        self.labels.insert(l.to_string());
                    }
                }
            }
        }
        if e.op.starts_with("dep_")
            && let Some(t) = d.get("target").and_then(Value::as_str)
        {
            self.deps.insert(t.to_string());
        }
    }
}

/// `v` as [`crate::Issue`] serializes field `field`: times in RFC 3339 with
/// milliseconds, a missing `ephemeral` false, missing metadata `{}`.
fn canonical(field: &str, v: Option<&Value>) -> Value {
    let v = v.cloned().unwrap_or(Value::Null);
    if TIME_FIELDS.contains(&field) {
        return match &v {
            Value::String(s) => Timestamp::parse_rfc3339(s).map(|t| json!(t)).unwrap_or(v),
            Value::Number(n) => n.as_i64().map(|ms| json!(Timestamp(ms))).unwrap_or(v),
            _ => v,
        };
    }
    match (field, &v) {
        ("ephemeral", Value::Null) => json!(false),
        ("metadata", Value::Null) => json!({}),
        _ => v,
    }
}

fn dep_value(dep_type: Option<&Value>, metadata: Option<&Value>) -> Value {
    let metadata = metadata.filter(|m| !m.is_null()).cloned().unwrap_or_else(|| json!({}));
    json!({ "type": dep_type.cloned().unwrap_or(Value::Null), "metadata": metadata })
}

/// Every key's value in an issue snapshot (an event's `issue` or `previous`).
fn snapshot_sides(snap: &Value, u: &Universe) -> Vec<(Key, Side)> {
    let mut out = Vec::new();
    for f in FIELDS {
        let present = snap.get(f).or_else(|| match f {
            "acceptance_criteria" => snap.get("acceptance"),
            "issue_type" => snap.get("type"),
            _ => None,
        });
        // Required in an issue's JSON; the others default.
        let side = match (f, present) {
            ("title" | "status" | "priority" | "issue_type", None) => Side::Unknown("missing from the snapshot".into()),
            ("description" | "design" | "acceptance_criteria" | "notes", None) => Side::Known(json!("")),
            _ => Side::Known(canonical(f, present)),
        };
        out.push((Key::Field(f), side));
    }
    let labels: BTreeSet<&str> =
        snap.get("labels").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    for l in &u.labels {
        out.push((Key::Label(l.clone()), Side::Known(json!(labels.contains(l.as_str())))));
    }
    let deps: BTreeMap<&str, &Value> = snap
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|d| Some((d.get("target")?.as_str()?, d)))
        .collect();
    for t in &u.deps {
        let v = deps.get(t.as_str()).map_or(Value::Null, |d| dep_value(d.get("type"), d.get("metadata")));
        out.push((Key::Dep(t.clone()), Side::Known(v)));
    }
    out
}

fn reason(e: &Event, what: &str) -> String {
    format!("{} #{} {what}", e.op, e.seq)
}

/// The value of `d[key]`, or unknown when an older bd did not record it.
fn recorded(e: &Event, d: &Value, key: &str, field: &str) -> Side {
    match d.get(key) {
        Some(v) => Side::Known(canonical(field, Some(v))),
        None => Side::Unknown(reason(e, "did not record it")),
    }
}

fn change(key: Key, before: Side, after: Side) -> Change {
    Change { key, before: Some(before), after: Some(after) }
}

fn known(v: Value) -> Side {
    Side::Known(v)
}

/// What event `e` did to issue `id`.
fn effect(e: &Event, id: &str, u: &Universe) -> Effect {
    let d = &e.data;
    let mut out = Vec::new();
    let creation = |out: &mut Vec<Change>, snap: &Value| {
        out.push(change(Key::Exists, known(json!(false)), known(json!(true))));
        for (key, after) in snapshot_sides(snap, u) {
            out.push(change(key, Side::Unknown(reason(e, "created it")), after));
        }
    };
    match e.op.as_str() {
        "created" => creation(&mut out, &d["issue"]),
        "imported" if d["mode"] != json!("update") => creation(&mut out, &d["issue"]),
        "imported" => {
            out.push(change(Key::Exists, known(json!(true)), known(json!(true))));
            let after = snapshot_sides(&d["issue"], u);
            let before = match d.get("previous").filter(|p| p.is_object()) {
                Some(p) => snapshot_sides(p, u).into_iter().map(|(_, s)| s).collect(),
                None => vec![Side::Unknown(reason(e, "did not record the previous value")); after.len()],
            };
            for ((key, after), before) in after.into_iter().zip(before) {
                out.push(change(key, before, after));
            }
        }
        "closed" => {
            out.push(change(Key::Field("status"), recorded(e, d, "previous_status", "status"), known(json!("closed"))));
            out.push(change(Key::Field("close_reason"), known(Value::Null), known(d["reason"].clone())));
            out.push(change(Key::Field("close_outcome"), known(Value::Null), known(d["outcome"].clone())));
            out.push(change(Key::Field("closed_at"), known(Value::Null), known(json!(e.ts))));
        }
        "reopened" => {
            out.push(change(Key::Field("status"), known(json!("closed")), known(json!("open"))));
            let previous = d.get("previous").filter(|p| p.is_object());
            for f in ["close_reason", "close_outcome", "closed_at"] {
                let before = match previous {
                    Some(p) => known(canonical(f, p.get(f))),
                    None => Side::Unknown(reason(e, "did not record the previous value")),
                };
                out.push(change(Key::Field(f), before, known(Value::Null)));
            }
        }
        "claimed" => {
            out.push(change(Key::Field("status"), known(json!("open")), known(json!("in_progress"))));
            out.push(change(
                Key::Field("assignee"),
                recorded(e, d, "previous_assignee", "assignee"),
                known(json!(e.actor)),
            ));
        }
        "released" => {
            let (before, after) = match d.get("previous_status") {
                Some(s) if s == "in_progress" => (known(s.clone()), known(json!("open"))),
                Some(s) => (known(s.clone()), known(s.clone())),
                None => {
                    let unknown = Side::Unknown(reason(e, "did not record the previous status"));
                    (unknown.clone(), unknown)
                }
            };
            out.push(change(Key::Field("status"), before, after));
            out.push(change(Key::Field("assignee"), recorded(e, d, "previous_holder", "assignee"), known(Value::Null)));
        }
        "reclaimed" => {
            out.push(change(Key::Field("status"), known(json!("in_progress")), known(json!("open"))));
            out.push(change(Key::Field("assignee"), recorded(e, d, "previous_holder", "assignee"), known(Value::Null)));
        }
        "dep_added" | "dep_removed" | "dep_updated" => {
            let Some(target) = d.get("target").and_then(Value::as_str) else { return Effect::Changes(out) };
            let key = Key::Dep(target.to_string());
            let edge = known(dep_value(d.get("type"), d.get("metadata")));
            match e.op.as_str() {
                "dep_added" if d["import"] == json!(true) => {
                    // An import may have replaced an edge it did not record.
                    out.push(change(key, Side::Unknown(reason(e, "may have replaced an edge")), edge));
                }
                "dep_added" => out.push(change(key, known(Value::Null), edge)),
                "dep_removed" => out.push(change(key, edge, known(Value::Null))),
                _ => {
                    let before = match d.get("previous") {
                        Some(p) => known(dep_value(d.get("type"), Some(p))),
                        None => Side::Unknown(reason(e, "did not record the previous value")),
                    };
                    out.push(change(key, before, edge));
                }
            }
        }
        "deleted" => {
            out.push(change(Key::Exists, known(json!(true)), known(json!(false))));
            if let Some(snap) = d.get("issue").filter(|s| s.is_object()) {
                for (key, before) in snapshot_sides(snap, u) {
                    out.push(Change { key, before: Some(before), after: None });
                }
            }
        }
        "purged" | "run_compacted" => {
            if d.get("ids").and_then(Value::as_array).is_some_and(|ids| ids.iter().any(|x| x == id)) {
                out.push(change(Key::Exists, known(json!(true)), known(json!(false))));
            }
        }
        "blocked" => return Effect::Block(true),
        "unblocked" => return Effect::Block(false),
        "gate_escalated" | "gate_updated" if !d["changes"].is_object() => {
            let unknown = Side::Unknown(reason(e, "did not record the change"));
            out.push(change(Key::Field("metadata"), unknown.clone(), unknown));
        }
        _ => {}
    }
    if let Some(changes) = d.get("changes").and_then(Value::as_object) {
        for (name, v) in changes {
            if name == "labels" {
                for (side, present) in [("added", true), ("removed", false)] {
                    for l in v.get(side).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        out.push(change(Key::Label(l.to_string()), known(json!(!present)), known(json!(present))));
                    }
                }
            } else if let Some(f) = FIELDS.iter().find(|f| **f == name) {
                out.push(change(Key::Field(f), known(canonical(f, v.get("old"))), known(canonical(f, v.get("new")))));
            }
        }
    }
    Effect::Changes(out)
}

type State = BTreeMap<Key, Slot>;

fn known_str<'a>(state: &'a State, field: &'static str) -> Option<&'a str> {
    match &state.get(&Key::Field(field))?.side {
        Side::Known(v) => v.as_str(),
        Side::Unknown(_) => None,
    }
}

fn is_known(state: &State, field: &'static str) -> bool {
    matches!(state.get(&Key::Field(field)).map(|s| &s.side), Some(Side::Known(_)))
}

/// Whether the pass's issue type is a gate, or could be.
fn may_be_gate(state: &State) -> bool {
    !is_known(state, "issue_type") || known_str(state, "issue_type") == Some(crate::model::GATE_TYPE)
}

/// Forward: apply the "after" side of `events` from nothing known.
fn forward(events: &[(&Event, Effect)], keys: &[Key]) -> State {
    let mut state: State =
        keys.iter().map(|k| (k.clone(), Slot { side: Side::Unknown("no retained record".into()), at: None })).collect();
    for (e, eff) in events {
        match eff {
            Effect::Changes(changes) => {
                for c in changes {
                    if let Some(after) = &c.after {
                        state.insert(c.key.clone(), Slot { side: after.clone(), at: Some(e.seq) });
                    }
                }
            }
            Effect::Block(blocked) => {
                if !may_be_gate(&state) {
                    continue;
                }
                let meta = Key::Field("metadata");
                let status = known_str(&state, "status").map(String::from);
                let current = match &state[&meta].side {
                    Side::Known(v) if is_known(&state, "issue_type") && is_known(&state, "status") => Some(v.clone()),
                    _ => None,
                };
                let Some(mut v) = current else {
                    let side = Side::Unknown(reason(e, "may have armed or disarmed it"));
                    state.insert(meta, Slot { side, at: Some(e.seq) });
                    continue;
                };
                let changed = match v.get_mut("gate").and_then(Value::as_object_mut) {
                    Some(gate) if *blocked => gate.remove("armed_at").is_some(),
                    Some(gate) if !matches!(status.as_deref(), Some("closed" | "pinned")) => {
                        gate.insert("armed_at".into(), json!(e.ts.to_rfc3339()));
                        true
                    }
                    _ => false,
                };
                if changed {
                    state.insert(meta, Slot { side: Side::Known(v), at: Some(e.seq) });
                }
            }
        }
    }
    state
}

/// Backward: undo the "before" side of `events`, latest first, from `last`.
fn backward(events: &[(&Event, Effect)], mut state: State) -> State {
    for (e, eff) in events.iter().rev() {
        match eff {
            Effect::Changes(changes) => {
                for c in changes {
                    if let Some(before) = &c.before {
                        state.insert(c.key.clone(), Slot { side: before.clone(), at: Some(e.seq) });
                    }
                }
            }
            Effect::Block(_) => {
                if may_be_gate(&state) {
                    let side = Side::Unknown(reason(e, "may have armed or disarmed it"));
                    state.insert(Key::Field("metadata"), Slot { side, at: Some(e.seq) });
                }
            }
        }
    }
    state
}

/// A legacy event that may have changed values without recording it.
struct LegacyEvent {
    seq: i64,
    op: String,
    issue_id: Option<String>,
    data: Value,
}

impl LegacyEvent {
    /// Whether it deleted `target` and so dropped `id`'s edge to it: a
    /// `deleted` always may have; a purge or compaction only when it named
    /// `id` among the issues that lost an edge.
    fn deletes(&self, target: &str, id: &str) -> bool {
        let listed = |k: &str, x: &str| self.data[k].as_array().is_some_and(|a| a.iter().any(|v| v == x));
        match self.op.as_str() {
            "deleted" => self.issue_id.as_deref() == Some(target),
            "purged" | "run_compacted" => listed("ids", target) && listed("detached", id),
            _ => false,
        }
    }

    /// The `(from, to)` of a rename.
    fn rename(&self) -> Option<(&str, &str)> {
        (self.op == "prefix_renamed").then(|| Some((self.data["from"].as_str()?, self.data["to"].as_str()?)))?
    }
}

fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// The retained events before the marker that may have changed issue `id`
/// without a record.
struct Legacy<'a> {
    events: &'a [LegacyEvent],
    marker: i64,
    id: &'a str,
}

impl Legacy<'_> {
    /// Why `value` of `key`, whose evidence spans the events in the inclusive
    /// range `window`, may have been changed by one of these events without
    /// a record: the cause, or `None` when none of them could have changed
    /// it. `gate`: the issue is, or may be, a gate; `forward`: a value of the
    /// forward pass (else of the backward one).
    fn taint(&self, key: &Key, value: &Value, window: (i64, i64), gate: bool, forward: bool) -> Option<String> {
        let (lo, hi) = (window.0, window.1.min(self.marker - 1));
        if lo > hi {
            return None;
        }
        let id = self.id;
        let inside = || self.events.iter().filter(|l| l.seq >= lo && l.seq <= hi);
        match key {
            Key::Field("metadata") if gate => return Some("gate arming".into()),
            Key::Field(f) if TEXT_FIELDS.contains(f) => {
                let text = match value {
                    Value::String(s) => s.clone(),
                    Value::Null => return None,
                    other => other.to_string(),
                };
                for l in inside() {
                    if let Some((from, to)) = l.rename() {
                        let prefix = format!("{}-", if forward { from } else { to });
                        if contains_ignore_case(&text, &prefix) {
                            return Some(format!("rename-prefix at #{}", l.seq));
                        }
                    }
                }
            }
            Key::Dep(target) if !forward || !value.is_null() => {
                if let Some(l) = inside().find(|l| l.deletes(target, id)) {
                    return Some(format!("deletion of {target} at #{}", l.seq));
                }
            }
            _ => {}
        }
        None
    }
}

/// The state of `id` at `point`, rebuilt from its retained events (see the
/// [module](self) docs). An issue that did not exist then is an answer
/// (`exists: false`); one with neither a row nor events is not found; a
/// point before retained history fails with [`Error::HistoryPruned`] unless
/// the issue's retained creation shows it did not exist yet.
///
/// To rebuild many issues, or one issue at many points, load a [`History`]
/// once and use [`History::issue`] or [`History::rebuild`].
pub fn issue_as_of(conn: &Connection, id: &str, point: Point) -> Result<IssueAsOf> {
    History::load(conn)?.issue(conn, id, point)
}

impl PointView {
    /// The view of `point`.
    pub fn of(point: Point) -> PointView {
        match point {
            Point::Seq(n) => PointView { seq: Some(n), time: None },
            Point::Time(t) => PointView { seq: None, time: Some(t) },
        }
    }

    /// `#N` for a seq, else the time in RFC 3339.
    pub fn label(&self) -> String {
        match (self.seq, self.time) {
            (Some(n), _) => format!("#{n}"),
            (None, Some(t)) => t.to_rfc3339(),
            (None, None) => String::new(),
        }
    }
}

/// What every rebuild in one read shares: the log's bounds, the history
/// marker and the retained purges and run compactions, read once by
/// [`History::load`] inside the caller's read transaction.
#[derive(Clone, Debug)]
pub struct History {
    head: i64,
    floor: i64,
    floor_ts: Option<Timestamp>,
    marker: i64,
    /// Every retained `purged` and `run_compacted` event, by seq.
    removals: Vec<Event>,
}

/// One issue's retained history and final state, loaded once by
/// [`History::load_issue`] and replayable at any point by
/// [`History::rebuild`].
#[derive(Clone, Debug)]
pub struct Loaded {
    pub id: String,
    /// Its own events plus the retained removals naming it, by seq.
    pub history: Vec<Event>,
    /// Its snapshot (the final state), or `None` when it has no row.
    pub row: Option<Value>,
}

impl History {
    /// Read the shared context.
    pub fn load(conn: &Connection) -> Result<History> {
        let head = events::head(conn)?;
        let floor = events::floor(conn)?;
        let floor_ts: Option<Timestamp> =
            conn.prepare_cached("SELECT ts FROM events WHERE seq = ?1")?.query_row([floor], |r| r.get(0)).optional()?;
        let marker: i64 = meta_get(conn, HISTORY_COMPLETE_FROM)?.and_then(|v| v.parse().ok()).unwrap_or(head + 1);
        // Purges and run compactions record the issues they removed in `ids`,
        // under the run's id or none: merged into each issue's history
        // wherever they are retained (see `load_issue`).
        let mut stmt = conn.prepare_cached(
            "SELECT seq, tx, ts, actor, op, issue_id, data FROM events
             WHERE seq > ?1 AND op IN ('purged','run_compacted') ORDER BY seq",
        )?;
        let rows = stmt.query_map([floor - 1], |r| {
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
        })?;
        let removals = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(History { head, floor, floor_ts, marker, removals })
    }

    /// The newest event's seq.
    pub fn head(&self) -> i64 {
        self.head
    }

    /// The oldest retained event's seq.
    pub fn floor(&self) -> i64 {
        self.floor
    }

    /// The oldest retained event's time, if any event is retained.
    pub fn floor_ts(&self) -> Option<Timestamp> {
        self.floor_ts
    }

    /// The oldest event retention kept.
    pub fn retained(&self) -> Retained {
        Retained { seq: self.floor, ts: self.floor_ts }
    }

    /// Refuse a seq that is negative or past the newest event.
    pub fn check(&self, point: Point) -> Result<()> {
        if let Point::Seq(n) = point {
            if n < 0 {
                return Err(Error::invalid("event seq must be >= 0"));
            }
            if n > self.head {
                return Err(Error::invalid(format!("event seq {n} is past the newest event (#{})", self.head)));
            }
        }
        Ok(())
    }

    /// Whether `point` is before retained history.
    pub fn before_retention(&self, point: Point) -> bool {
        match point {
            Point::Seq(n) => n < self.floor - 1,
            Point::Time(t) => self.floor_ts.is_some_and(|f| t < f),
        }
    }

    /// Load `id`'s events, the retained removals naming it (the id may
    /// have been used again since, or that reuse removed too, so both passes
    /// see every life of the id) and its row. Not found when it has neither
    /// a row nor events.
    pub fn load_issue(&self, conn: &Connection, id: &str) -> Result<Loaded> {
        let mut history = events::history(conn, id)?;
        // The final state: the row, or the issue's deletion.
        let row = match issues::get(conn, id)? {
            Some(_) => Some(issues::snapshot(conn, id)?),
            None => None,
        };
        let own: BTreeSet<i64> = history.iter().map(|e| e.seq).collect();
        let removals: Vec<Event> = self
            .removals
            .iter()
            .filter(|e| {
                !own.contains(&e.seq) && e.data["ids"].as_array().is_some_and(|ids| ids.iter().any(|x| x == id))
            })
            .cloned()
            .collect();
        if !removals.is_empty() {
            history.extend(removals);
            history.sort_by_key(|e| e.seq);
        }
        if row.is_none() && history.is_empty() {
            return Err(Error::not_found("issue", id));
        }
        Ok(Loaded { id: id.to_string(), history, row })
    }

    /// [`issue_as_of`] over this context.
    pub fn issue(&self, conn: &Connection, id: &str, point: Point) -> Result<IssueAsOf> {
        self.check(point)?;
        let loaded = self.load_issue(conn, id)?;
        self.rebuild(conn, &loaded, point)
    }

    /// The state of `loaded` at `point` (see [`issue_as_of`]). The point is
    /// checked first, as [`History::check`] does.
    pub fn rebuild(&self, conn: &Connection, loaded: &Loaded, point: Point) -> Result<IssueAsOf> {
        self.check(point)?;
        rebuild(conn, self, loaded, point)
    }
}

fn rebuild(conn: &Connection, hist: &History, loaded: &Loaded, point: Point) -> Result<IssueAsOf> {
    let (head, floor, floor_ts, marker) = (hist.head, hist.floor, hist.floor_ts, hist.marker);
    let id = loaded.id.as_str();
    let history = &loaded.history;
    let row = &loaded.row;
    let retained_from = hist.retained();
    let view = PointView::of(point);
    let is_creation = |e: &Event| e.op == "created" || (e.op == "imported" && e.data["mode"] != json!("update"));
    let is_deletion = |e: &Event| {
        e.op == "deleted"
            || (matches!(e.op.as_str(), "purged" | "run_compacted")
                && e.data["ids"].as_array().is_some_and(|ids| ids.iter().any(|x| x == id)))
    };
    let created_by_point = history.iter().rfind(|e| is_creation(e) && point.includes(e));
    let created = created_by_point.or_else(|| history.iter().find(|e| is_creation(e))).map(EventRef::of);
    // The life the point is in: after its creation, the first deletion that
    // ends it; when that creation is not by then (pruned, so the reuse's
    // stands in), the latest deletion by then, which ended an earlier life.
    let first_after = || history.iter().find(|e| is_deletion(e) && created.as_ref().is_none_or(|c| e.seq > c.seq));
    let deleted = if created.is_none() || created_by_point.is_some() {
        first_after()
    } else {
        history.iter().rfind(|e| is_deletion(e) && point.includes(e)).or_else(first_after)
    }
    .map(EventRef::of);
    let last_event = history.iter().rfind(|e| point.includes(e)).map(|e| e.seq);
    let mut out = IssueAsOf {
        id: id.to_string(),
        point: view,
        exists: false,
        created,
        deleted,
        fields: Map::new(),
        labels: Vec::new(),
        dependencies: Vec::new(),
        unknown: Vec::new(),
        last_event,
        retained_from,
        history_complete_from: marker,
        incomplete: false,
    };

    // Before retained history: only a retained creation tells.
    if hist.before_retention(point) {
        if history.first().is_some_and(is_creation) {
            out.created = history.first().map(EventRef::of);
            out.deleted = None;
            return Ok(out);
        }
        return Err(Error::HistoryPruned { id: id.to_string(), floor, floor_ts });
    }

    let included: Vec<&Event> = history.iter().filter(|e| point.includes(e)).collect();
    let excluded: Vec<&Event> = history.iter().filter(|e| !point.includes(e)).collect();
    // The bounds of the point's windows, as seqs (see `taint`).
    let (fwd_hi, bwd_lo) = match point {
        Point::Seq(n) => (n, n),
        Point::Time(_) => (marker - 1, included.last().map_or(floor - 1, |e| e.seq)),
    };
    let legacy_from = floor.max(1);
    let has_legacy = floor < marker;

    let mut universe = Universe::default();
    if let Some(snap) = &row {
        universe.add_snapshot(snap);
    }
    for e in history {
        universe.add_event(e);
    }
    let run = |universe: &Universe| {
        let keys = universe.keys();
        fn effects<'e>(list: &[&'e Event], id: &str, universe: &Universe) -> Vec<(&'e Event, Effect)> {
            list.iter().map(|e| (*e, effect(e, id, universe))).collect()
        }
        let fwd = forward(&effects(&included, id, universe), &keys);
        let mut last: State = BTreeMap::new();
        let final_unknown = |what: &str| Slot { side: Side::Unknown(what.to_string()), at: None };
        match &row {
            Some(snap) => {
                last.insert(Key::Exists, Slot { side: Side::Known(json!(true)), at: None });
                for (key, side) in snapshot_sides(snap, universe) {
                    last.insert(key, Slot { side, at: None });
                }
            }
            None => {
                for key in &keys {
                    last.insert(key.clone(), final_unknown("deleted"));
                }
                last.insert(Key::Exists, Slot { side: Side::Known(json!(false)), at: None });
            }
        }
        let bwd = backward(&effects(&excluded, id, universe), last);
        (keys, fwd, bwd)
    };
    let (mut keys, mut fwd, mut bwd) = run(&universe);

    // History before the marker: read the retained legacy events the windows may span, once.
    let window_of = |slot: &Slot, forward: bool| -> (i64, i64) {
        if forward { (slot.at.unwrap_or(0) + 1, fwd_hi) } else { (bwd_lo + 1, slot.at.unwrap_or(head + 1) - 1) }
    };
    let spans_legacy = |(lo, hi): (i64, i64)| has_legacy && lo.max(legacy_from) <= hi.min(marker - 1);
    let mut legacy: Vec<LegacyEvent> = Vec::new();
    if has_legacy {
        let mut lowest = bwd_lo + 1;
        let mut needed = spans_legacy((bwd_lo + 1, head));
        for (state, forward) in [(&fwd, true), (&bwd, false)] {
            for slot in state.values().filter(|s| matches!(s.side, Side::Known(_))) {
                let w = window_of(slot, forward);
                if spans_legacy(w) {
                    needed = true;
                    lowest = lowest.min(w.0);
                }
            }
        }
        if needed {
            let mut stmt = conn.prepare_cached(
                "SELECT seq, op, issue_id, data FROM events
                 WHERE seq >= ?1 AND seq < ?2 AND op IN ('prefix_renamed','deleted','purged','run_compacted')
                 ORDER BY seq",
            )?;
            let rows = stmt.query_map([lowest.max(legacy_from), marker], |r| {
                let data: String = r.get(3)?;
                Ok(LegacyEvent {
                    seq: r.get(0)?,
                    op: r.get(1)?,
                    issue_id: r.get(2)?,
                    data: serde_json::from_str(&data).unwrap_or_else(|_| json!({})),
                })
            })?;
            legacy = rows.collect::<rusqlite::Result<_>>()?;
            // Issues deleted after the point, by a deletion that may have dropped an edge of this one.
            let mut more = false;
            for l in legacy.iter().filter(|l| l.seq > bwd_lo) {
                let targets: Vec<String> = match l.op.as_str() {
                    "deleted" => l.issue_id.iter().cloned().collect(),
                    "purged" | "run_compacted"
                        if l.data["detached"].as_array().is_some_and(|a| a.iter().any(|v| v == id)) =>
                    {
                        l.data["ids"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect()
                    }
                    _ => Vec::new(),
                };
                for t in targets {
                    if t != id {
                        more |= universe.deps.insert(t);
                    }
                }
            }
            if more {
                (keys, fwd, bwd) = run(&universe);
            }
        }
    }

    // Values whose evidence spans legacy history, where an unrecorded write may have changed them.
    let cause = |state: &State, key: &Key, slot: &Slot, forward: bool| -> Option<String> {
        let Side::Known(v) = &slot.side else { return None };
        let w = window_of(slot, forward);
        if !spans_legacy(w) {
            return None;
        }
        let gate = matches!(key, Key::Field("metadata")) && may_be_gate(state);
        Legacy { events: &legacy, marker, id }.taint(key, v, w, gate, forward)
    };
    let mut incomplete = has_legacy && history.iter().any(|e| e.seq < marker);
    let mut merged: BTreeMap<Key, std::result::Result<Value, String>> = BTreeMap::new();
    for key in &keys {
        let mut f = fwd[key].clone();
        let mut b = bwd[key].clone();
        for (slot, state, forward) in [(&mut f, &fwd, true), (&mut b, &bwd, false)] {
            if matches!(slot.side, Side::Known(_)) && spans_legacy(window_of(slot, forward)) {
                incomplete = true;
            }
            if let Some(c) = cause(state, key, slot, forward) {
                slot.side = Side::Unknown(format!(
                    "may have been changed without a record by an older bd before #{marker}: {c}"
                ));
            }
        }
        let value = match (&f.side, &b.side) {
            (Side::Known(x), Side::Known(y)) if same(key, x, y) => Ok(x.clone()),
            (Side::Known(x), Side::Known(_)) => {
                let a = f.at.map_or_else(|| "the point".to_string(), |s| format!("#{s}"));
                let b = b.at.map_or_else(|| "now".to_string(), |s| format!("#{s}"));
                Err(if *key == Key::Exists {
                    // Neither pass is wrong about its own events: one of the issue's lives has no retained record.
                    let (then, later) =
                        if *x == json!(true) { ("existed", "did not") } else { ("did not exist", "did") };
                    format!(
                        "created or deleted without a retained event between {a} and {b}: its events up to the point \
                         say it {then}, the later ones that it {later}"
                    )
                } else {
                    format!("changed without a recorded event between {a} and {b}")
                })
            }
            (Side::Known(x), _) | (_, Side::Known(x)) => Ok(x.clone()),
            (Side::Unknown(r), Side::Unknown(s)) => {
                let generic = |r: &str| r == "no retained record" || r == "deleted";
                Err(if !generic(r) {
                    r.clone()
                } else if !generic(s) {
                    s.clone()
                } else {
                    "no retained record".into()
                })
            }
        };
        merged.insert(key.clone(), value);
    }
    out.incomplete = incomplete;

    // Whether it existed then; when the history cannot tell, nothing is
    // reported as that moment's state: `exists` is false and listed unknown.
    out.exists = match merged.remove(&Key::Exists) {
        Some(Ok(v)) => v == json!(true),
        Some(Err(reason)) => {
            out.unknown.push(Unknown { key: Key::Exists.name(), reason });
            false
        }
        None => true,
    };
    if !out.exists {
        return Ok(out);
    }
    for (key, value) in merged {
        match value {
            Err(reason) => {
                // An edge or label of no consequence: absent on both sides as far as known.
                out.unknown.push(Unknown { key: key.name(), reason });
            }
            Ok(v) => match key {
                Key::Field(f) => {
                    out.fields.insert(f.to_string(), v);
                }
                Key::Label(l) if v == json!(true) => out.labels.push(l),
                Key::Dep(target) if !v.is_null() => out.dependencies.push(DepAsOf {
                    target,
                    dep_type: v["type"].as_str().unwrap_or_default().to_string(),
                    metadata: v["metadata"].clone(),
                }),
                _ => {}
            },
        }
    }
    Ok(out)
}

/// Whether two known values of `key` are the same.
fn same(key: &Key, a: &Value, b: &Value) -> bool {
    match key {
        Key::Field(f) => canonical(f, Some(a)) == canonical(f, Some(b)),
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_parse() {
        let now = Timestamp(10_000_000);
        assert_eq!(Point::parse("12", now).unwrap(), Point::Seq(12));
        assert_eq!(Point::parse("#12", now).unwrap(), Point::Seq(12));
        assert!(Point::parse("#-1", now).is_err());
        assert!(Point::parse("#x", now).is_err());
        assert_eq!(Point::parse("-1h", now).unwrap(), Point::Time(Timestamp(10_000_000 - 3_600_000)));
        let t = Point::parse("2026-01-15T09:00:00Z", now).unwrap();
        assert_eq!(t, Point::Time(Timestamp::parse_rfc3339("2026-01-15T09:00:00Z").unwrap()));
        assert!(Point::parse("whenever", now).is_err());
    }

    #[test]
    fn canonical_times_and_defaults() {
        assert_eq!(canonical("closed_at", Some(&json!(1000))), json!("1970-01-01T00:00:01.000Z"));
        assert_eq!(canonical("closed_at", Some(&json!("1970-01-01T00:00:01Z"))), json!("1970-01-01T00:00:01.000Z"));
        assert_eq!(canonical("ephemeral", None), json!(false));
        assert_eq!(canonical("metadata", None), json!({}));
        assert!(contains_ignore_case("see T-1", "t-"));
        assert!(!contains_ignore_case("see x", "t-"));
    }

    #[test]
    fn point_views_label_seqs_and_times() {
        assert_eq!(PointView::of(Point::Seq(7)), PointView { seq: Some(7), time: None });
        assert_eq!(PointView::of(Point::Seq(7)).label(), "#7");
        let t = Timestamp::parse_rfc3339("2026-01-15T09:00:00Z").unwrap();
        assert_eq!(PointView::of(Point::Time(t)), PointView { seq: None, time: Some(t) });
        assert_eq!(PointView::of(Point::Time(t)).label(), t.to_rfc3339());
    }

    /// One shared context answers as `issue_as_of` does, and one loaded
    /// history replays at every point as a fresh rebuild does.
    #[test]
    fn one_history_answers_as_issue_as_of_at_every_point() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::issues::DeleteOptions;
        use crate::model::{IssuePatch, NewIssue};
        use crate::store::{InitOptions, OpenOptions, Store};
        use crate::time::{Clock, ManualClock};
        use crate::{CloseOptions, Guard, IdMode};

        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(Timestamp(1_700_000_000_000)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let mut store =
            Store::init(&dir.path().join("bd.db"), InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts)
                .unwrap();
        let mut times = Vec::new();
        let mut write = |f: &mut dyn FnMut(&mut crate::store::WriteCtx<'_>) -> Result<()>| {
            clock.advance(Duration::from_secs(60));
            store.write("test", "alice", |tx| f(tx)).unwrap();
            times.push(clock.now());
        };
        let mut id = String::new();
        write(&mut |tx| {
            id = tx.create_issue(NewIssue::titled("first"))?.id;
            Ok(())
        });
        let other = id.clone();
        write(&mut |tx| {
            let patch = IssuePatch { title: Some("second".into()), ..Default::default() };
            tx.update_issue(&other, &patch, &Guard::default(), false).map(|_| ())
        });
        write(&mut |tx| tx.close_issue(&other, &CloseOptions::default()).map(|_| ()));
        write(&mut |tx| {
            tx.delete_issues(std::slice::from_ref(&other), &DeleteOptions { force: true, ..Default::default() })
                .map(|_| ())
        });

        store
            .read(|r| {
                let conn = r.conn();
                let hist = History::load(conn)?;
                let head = hist.head();
                assert!(head >= 4);
                let mut points: Vec<Point> = (0..=head).map(Point::Seq).collect();
                points.extend(times.iter().map(|t| Point::Time(*t)));
                points.push(Point::Time(times[0].minus(Duration::from_secs(1))));
                points.push(Point::Time(clock.now().plus(Duration::from_secs(3600))));
                let loaded = hist.load_issue(conn, &id)?;
                let mut titles = BTreeSet::new();
                for point in points {
                    let fresh = issue_as_of(conn, &id, point);
                    let shared = hist.issue(conn, &id, point);
                    let replayed = hist.rebuild(conn, &loaded, point);
                    match (&fresh, &shared, &replayed) {
                        (Ok(a), Ok(b), Ok(c)) => {
                            assert_eq!(a, b, "{point:?}");
                            assert_eq!(b, c, "{point:?}");
                            if let Some(t) = a.fields.get("title").and_then(Value::as_str) {
                                titles.insert(t.to_string());
                            }
                        }
                        (Err(a), Err(b), Err(c)) => {
                            assert_eq!(a.to_string(), b.to_string(), "{point:?}");
                            assert_eq!(b.to_string(), c.to_string(), "{point:?}");
                        }
                        other => panic!("{point:?}: {other:?}"),
                    }
                }
                assert_eq!(titles, BTreeSet::from(["first".to_string(), "second".to_string()]));
                // The point checks come before the lookup, as before.
                let past = hist.issue(conn, "t-nope", Point::Seq(head + 1)).unwrap_err();
                assert_eq!(
                    past.to_string(),
                    issue_as_of(conn, "t-nope", Point::Seq(head + 1)).unwrap_err().to_string()
                );
                assert!(past.to_string().contains("past the newest event"), "{past}");
                assert!(hist.rebuild(conn, &loaded, Point::Seq(-1)).is_err());
                assert_eq!(hist.issue(conn, "t-nope", Point::Seq(head)).unwrap_err().exit_code(), 3);
                assert_eq!(hist.retained(), Retained { seq: hist.floor(), ts: hist.floor_ts() });
                assert!(!hist.before_retention(Point::Seq(0)));
                Ok(())
            })
            .unwrap();
    }
}
