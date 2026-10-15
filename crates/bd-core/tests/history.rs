//! History: the payloads writes record so an issue can be rebuilt as of a
//! past moment (`asof`), that rebuild, and compaction of old closed issues,
//! whose original text the history keeps.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bd_core::asof::{self, FIELDS, IssueAsOf, Point};
use bd_core::gates::{GateKind, GateSpec, NewGate};
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use serde_json::{Value, json};
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

struct Env {
    _dir: TempDir,
    #[allow(dead_code)]
    path: PathBuf,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bd").join("bd.db");
        let clock = Arc::new(ManualClock::new(Timestamp(T0)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store = Store::init(&path, InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts).unwrap();
        Env { _dir: dir, path, store, clock }
    }

    /// One write, a second after the last.
    fn w<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.try_w(f).unwrap()
    }

    fn try_w<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        self.clock.advance(Duration::from_secs(1));
        self.store.write("test", "alice", f)
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.w(|tx| tx.create_issue(new)).id
    }

    fn update(&mut self, id: &str, patch: IssuePatch) {
        self.w(|tx| tx.update_issue(id, &patch, &Guard::default(), false));
    }

    fn close(&mut self, id: &str) {
        self.w(|tx| tx.close_issue(id, &CloseOptions::default()));
    }

    fn reopen(&mut self, id: &str) {
        self.w(|tx| tx.reopen_issue(id, Some("again")));
    }

    fn issue(&self, id: &str) -> Issue {
        self.store.read(|r| r.issue(id)).unwrap()
    }

    fn snap(&self, id: &str) -> Value {
        self.store.read(|r| issues::snapshot(r.conn(), id)).unwrap()
    }

    fn head(&self) -> i64 {
        self.store.read(|r| r.event_head()).unwrap()
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn history(&self, id: &str) -> Vec<Event> {
        self.store.read(|r| r.history(id)).unwrap()
    }

    fn events_since(&self, seq: i64) -> Vec<Event> {
        self.store.read(|r| r.events(&EventQuery { since: Some(seq), ..Default::default() })).unwrap().events
    }

    fn as_of(&self, id: &str, point: Point) -> Result<IssueAsOf> {
        self.store.read(|r| r.issue_as_of(id, point))
    }

    fn at(&self, id: &str, point: Point) -> IssueAsOf {
        self.as_of(id, point).unwrap_or_else(|e| panic!("{id} as of {point:?}: {e}"))
    }

    fn prune_before(&mut self, seq: i64) {
        self.w(|tx| tx.prune_events(&PruneOptions { before: Some(seq), ..Default::default() }));
    }

    /// Run raw SQL in a write transaction (unrecorded changes, stripped payloads).
    fn sql(&mut self, sql: &str) {
        self.store.write("sql", "alice", |tx| Ok(tx.conn().execute_batch(sql)?)).unwrap();
    }

    fn set_marker(&mut self, seq: i64) {
        self.sql(&format!("UPDATE meta SET value = '{seq}' WHERE key = 'history_complete_from'"));
    }
}

fn unknown_keys(a: &IssueAsOf) -> BTreeSet<String> {
    a.unknown.iter().map(|u| u.key.clone()).collect()
}

fn reason_of<'a>(a: &'a IssueAsOf, key: &str) -> &'a str {
    a.unknown.iter().find(|u| u.key == key).map(|u| u.reason.as_str()).unwrap_or("")
}

/// A snapshot's value of `field`, as the rebuild reports it.
fn field_of(snap: &Value, field: &str) -> Value {
    match (field, snap.get(field)) {
        ("ephemeral", None) => json!(false),
        (_, Some(v)) => v.clone(),
        (_, None) => Value::Null,
    }
}

fn deps_of(snap: &Value) -> Vec<Value> {
    snap["dependencies"].as_array().cloned().unwrap_or_default()
}

/// The differences between the rebuild `a` and the recorded `snap`: keys
/// whose rebuilt value is wrong, and (`strict`) any key left unknown.
fn differences(a: &IssueAsOf, snap: &Value, strict: bool) -> Vec<String> {
    let unknown = unknown_keys(a);
    let mut out = Vec::new();
    if strict && !unknown.is_empty() {
        out.push(format!("unknown: {:?}", a.unknown));
    }
    if strict && a.incomplete {
        out.push("incomplete".into());
    }
    if !a.exists {
        if !unknown.contains("exists") {
            out.push("exists: false".into());
        }
        return out;
    }
    for f in FIELDS {
        if unknown.contains(f) {
            continue;
        }
        let (got, want) = (a.fields.get(f).cloned().unwrap_or(Value::Null), field_of(snap, f));
        if got != want {
            out.push(format!("{f}: {got} != {want}"));
        }
    }
    let want_labels: BTreeSet<String> =
        snap["labels"].as_array().into_iter().flatten().filter_map(|l| l.as_str().map(String::from)).collect();
    let got_labels: BTreeSet<String> = a.labels.iter().cloned().collect();
    for l in want_labels.symmetric_difference(&got_labels) {
        if !unknown.contains(&format!("label:{l}")) {
            out.push(format!("label {l}"));
        }
    }
    let want: Vec<(String, Value)> = deps_of(snap)
        .into_iter()
        .map(|d| (d["target"].as_str().unwrap().to_string(), json!({ "type": d["type"], "metadata": d["metadata"] })))
        .collect();
    let got: Vec<(String, Value)> = a
        .dependencies
        .iter()
        .map(|d| (d.target.clone(), json!({ "type": d.dep_type, "metadata": d.metadata })))
        .collect();
    let targets: BTreeSet<&String> = want.iter().chain(&got).map(|(t, _)| t).collect();
    for t in targets {
        if unknown.contains(&format!("dep:{t}")) {
            continue;
        }
        let w = want.iter().find(|(x, _)| x == t);
        let g = got.iter().find(|(x, _)| x == t);
        if w != g {
            out.push(format!("dep {t}: {g:?} != {w:?}"));
        }
    }
    out
}

fn gate(kind: GateKind, blocks: &str) -> NewGate {
    NewGate {
        spec: GateSpec { await_id: (kind == GateKind::GhRun).then(|| "ci.yml".to_string()), ..GateSpec::new(kind) },
        blocks: vec![blocks.to_string()],
        title: None,
        description: String::new(),
        assignee: None,
        parent: None,
        priority: None,
        ephemeral: false,
    }
}

// ---------------------------------------------------------------- payloads

#[test]
fn reopened_records_previous_close_fields() {
    let mut env = Env::new();
    let id = env.create(NewIssue::titled("Work"));
    env.w(|tx| {
        tx.close_issue(
            &id,
            &CloseOptions { reason: Some("shipped".into()), outcome: Some(Outcome::Failed), ..Default::default() },
        )
    });
    let closed = env.issue(&id);
    let head = env.head();
    env.reopen(&id);
    let e = env.events_since(head).into_iter().find(|e| e.op == "reopened").unwrap();
    assert_eq!(
        e.data,
        json!({ "reason": "again", "previous": {
            "close_reason": "shipped", "close_outcome": "failed", "closed_at": closed.closed_at.unwrap() } })
    );
}

#[test]
fn import_update_records_previous_snapshot() {
    let mut env = Env::new();
    let id = env.create(NewIssue { labels: vec!["a".into()], ..NewIssue::titled("Before") });
    let before = env.snap(&id);
    let mut jsonl = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut jsonl, &ExportOptions::default())).unwrap();
    let jsonl = String::from_utf8(jsonl).unwrap().replace("\"Before\"", "\"After\"");
    let head = env.head();
    env.w(|tx| tx.import_jsonl(&mut jsonl.as_bytes(), &ImportOptions::default()));
    let e = env.events_since(head).into_iter().find(|e| e.op == "imported").unwrap();
    assert_eq!(e.data["mode"], "update");
    assert_eq!(e.data["previous"], before);
    assert_eq!(e.data["issue"]["title"], "After");
}

#[test]
fn gate_events_record_metadata_changes() {
    let mut env = Env::new();
    let work = env.create(NewIssue::titled("Work"));
    let g = env.w(|tx| tx.create_gate(gate(GateKind::GhRun, &work))).id;
    let before = env.issue(&g).metadata;
    let head = env.head();
    env.w(|tx| tx.escalate_gate(&g, "overdue"));
    let e = env.events_since(head).into_iter().find(|e| e.op == "gate_escalated").unwrap();
    assert_eq!(e.data["changes"]["metadata"], json!({ "old": before, "new": env.issue(&g).metadata }));
    assert_eq!(e.data["reason"], "overdue");

    for run in ["41", "42"] {
        let before = env.issue(&g).metadata;
        let head = env.head();
        env.w(|tx| tx.pin_gate_run(&g, run, None));
        let e = env.events_since(head).into_iter().find(|e| e.op == "gate_updated").unwrap();
        let after = env.issue(&g).metadata;
        assert_eq!(after["gate"]["run_id"], run);
        assert_eq!(e.data["changes"]["metadata"], json!({ "old": before, "new": after }));
    }
}

#[test]
fn gate_creation_records_arming() {
    let mut env = Env::new();
    let work = env.create(NewIssue::titled("Work"));
    let head = env.head();
    let g = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    let armed: Vec<Event> = env.events_since(head).into_iter().filter(|e| e.op == "gate_armed").collect();
    assert_eq!(armed.len(), 1);
    assert_eq!(armed[0].issue_id.as_deref(), Some(g.as_str()));
    let new = &armed[0].data["changes"]["metadata"]["new"];
    assert_eq!(new["gate"]["armed_at"], json!(armed[0].ts));
    assert!(armed[0].data["changes"]["metadata"]["old"]["gate"].get("armed_at").is_none());
    assert_eq!(*new, env.issue(&g).metadata);
}

#[test]
fn terminal_gates_never_change_arming() {
    let mut env = Env::new();
    let blocker = env.create(NewIssue::titled("Blocker"));
    let work = env.create(NewIssue { deps: vec![(DepType::Blocks, blocker.clone())], ..NewIssue::titled("Work") });
    let g = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    assert!(env.issue(&g).is_blocked, "it took on the work's prerequisite");
    // Closed while blocked, then given another blocker: nothing about arming changes.
    env.w(|tx| tx.close_issue(&g, &CloseOptions { force: true, ..Default::default() }));
    let metadata = env.issue(&g).metadata;
    let other = env.create(NewIssue::titled("Other"));
    let head = env.head();
    env.w(|tx| tx.add_dependency(&g, &other, DepType::Blocks, None));
    assert_eq!(env.issue(&g).metadata, metadata);
    let touching: Vec<String> = env
        .events_since(head)
        .into_iter()
        .filter(|e| e.issue_id.as_deref() == Some(g.as_str()) && e.op != "dep_added")
        .map(|e| e.op)
        .collect();
    assert!(touching.is_empty(), "{touching:?}");

    // A live gate re-blocked: only a `blocked` event, and armed_at goes.
    let blocker2 = env.create(NewIssue::titled("Blocker 2"));
    let work2 = env.create(NewIssue::titled("Work 2"));
    let g2 = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work2))).id;
    assert!(env.issue(&g2).metadata["gate"].get("armed_at").is_some());
    let head = env.head();
    env.w(|tx| tx.add_dependency(&g2, &blocker2, DepType::Blocks, None));
    let ops: Vec<String> = env
        .events_since(head)
        .into_iter()
        .filter(|e| e.issue_id.as_deref() == Some(g2.as_str()))
        .map(|e| e.op)
        .collect();
    assert_eq!(ops, ["dep_added", "blocked"]);
    assert!(env.issue(&g2).metadata["gate"].get("armed_at").is_none());
}

#[test]
fn deleting_records_dropped_edges_on_survivors() {
    let mut env = Env::new();
    let gone = env.create(NewIssue::titled("Gone"));
    let gone2 = env.create(NewIssue::titled("Gone too"));
    let b = env.create(NewIssue::titled("B"));
    let a = env.create(NewIssue::titled("A"));
    env.w(|tx| {
        tx.add_dependency(&b, &gone, DepType::Related, Some(json!({ "why": "x" })))?;
        tx.add_dependency(&a, &gone2, DepType::Blocks, None)?;
        tx.add_dependency(&a, &gone, DepType::Blocks, None)
    });
    let head = env.head();
    env.w(|tx| tx.delete_issues(&[gone.clone(), gone2.clone()], &DeleteOptions { force: true, ..Default::default() }));
    let events = env.events_since(head);
    // By survivor, then target: B (t-3) before A (t-4).
    assert_eq!((b.as_str(), a.as_str(), gone.as_str(), gone2.as_str()), ("t-3", "t-4", "t-1", "t-2"));
    let ops: Vec<(String, String, Value)> = events
        .iter()
        .take(5)
        .map(|e| (e.op.clone(), e.issue_id.clone().unwrap_or_default(), e.data["target"].clone()))
        .collect();
    let row = |op: &str, id: &str, target: &str| (op.to_string(), id.to_string(), json!(target));
    assert_eq!(
        ops,
        [
            row("dep_removed", &b, &gone),
            row("dep_removed", &a, &gone),
            row("dep_removed", &a, &gone2),
            ("deleted".to_string(), gone.clone(), Value::Null),
            ("deleted".to_string(), gone2.clone(), Value::Null),
        ]
    );
    assert_eq!(
        events[0].data,
        json!({ "target": gone, "type": "related", "metadata": { "why": "x" }, "dropped_by": gone })
    );
    assert_eq!(events[1].data, json!({ "target": gone, "type": "blocks", "metadata": {}, "dropped_by": gone }));
    assert_eq!(events[2].data["dropped_by"], json!(gone2));

    // A purge drops the edge of an issue outside it the same way.
    let scratch = env.create(NewIssue { ephemeral: true, ..NewIssue::titled("Scratch") });
    let keep = env.create(NewIssue::titled("Keep"));
    env.w(|tx| tx.add_dependency(&keep, &scratch, DepType::Related, None));
    env.close(&scratch);
    let head = env.head();
    env.w(|tx| tx.purge_ephemeral(None, false));
    let events = env.events_since(head);
    assert_eq!((events[0].op.as_str(), events[0].issue_id.as_deref()), ("dep_removed", Some(keep.as_str())));
    assert_eq!(events[0].data["dropped_by"], json!(scratch));
    assert_eq!(events[1].op, "purged");
    assert_eq!(events[1].data["detached"], json!([keep]));
}

#[test]
fn rename_prefix_records_rewritten_references() {
    let mut env = Env::new();
    let one = env.create(NewIssue::titled("One"));
    let two = env.create(NewIssue {
        description: "after t-1".into(),
        notes: "t-1".into(),
        metadata: Some(json!({ "see": "t-1", "note": "t-1 notes" })),
        ..NewIssue::titled("Two")
    });
    assert_eq!((one.as_str(), two.as_str()), ("t-1", "t-2"));
    let head = env.head();
    env.w(|tx| tx.rename_prefix(&RenamePrefixOptions { to: "u".into(), from: None }));
    let renamed: Vec<Event> = env.events_since(head).into_iter().filter(|e| e.op == "references_renamed").collect();
    assert_eq!(renamed.len(), 1, "{renamed:#?}");
    let e = &renamed[0];
    assert_eq!(e.issue_id.as_deref(), Some("u-2"));
    assert_eq!((e.data["from"].as_str(), e.data["to"].as_str()), (Some("t"), Some("u")));
    // Old values as event payloads keep them: a string equal to a renamed id is renamed, text is not. The notes
    // ("t-1", an id) and the metadata (`see`, an id) then read the same before and after: not recorded.
    assert_eq!(e.data["changes"], json!({ "description": { "old": "after t-1", "new": "after u-1" } }));
    // The rename did not rewrite its own record.
    assert_eq!(env.issue("u-2").description, "after u-1");
}

// ---------------------------------------------------------------- as of

/// Snapshots of `ids` after each write: (head, time, id, snapshot).
type Recorded = Vec<(i64, Timestamp, String, Value)>;

fn record(env: &Env, ids: &[&str], out: &mut Recorded) {
    let (head, now) = (env.head(), env.now());
    for id in ids {
        if env.store.read(|r| r.find_issue(id)).unwrap().is_some() {
            out.push((head, now, id.to_string(), env.snap(id)));
        }
    }
}

#[test]
fn as_of_matches_recorded_state_after_every_write() {
    let mut env = Env::new();
    let mut rec: Recorded = Vec::new();
    let other = env.create(NewIssue::titled("Other"));
    let blocker = env.create(NewIssue::titled("Blocker"));
    let x = env.create(NewIssue {
        description: "first".into(),
        labels: vec!["a".into(), "b".into()],
        deps: vec![(DepType::Related, other.clone())],
        ..NewIssue::titled("Task")
    });
    let work = env.create(NewIssue { deps: vec![(DepType::Blocks, blocker.clone())], ..NewIssue::titled("Work") });
    let g = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    let ids = [x.as_str(), g.as_str(), work.as_str()];
    let created_at = env.head();
    record(&env, &ids, &mut rec);
    let mut step = |env: &mut Env, f: &dyn Fn(&mut Env)| {
        f(env);
        record(env, &ids, &mut rec);
    };
    let tomorrow = Timestamp(T0 + 86_400_000);
    step(&mut env, &|env| {
        env.update(
            &x,
            IssuePatch {
                title: Some("Task, renamed".into()),
                description: Some("second".into()),
                design: Some("design".into()),
                acceptance_criteria: Some("accept".into()),
                notes: Some("notes".into()),
                priority: Some(1),
                issue_type: Some("bug".into()),
                external_ref: Some(Some("gh-1".into())),
                estimated_minutes: Some(Some(30)),
                due_at: Some(Some(tomorrow)),
                set_metadata: vec![("k".into(), json!({ "deep": [1, 2] }))],
                ephemeral: Some(true),
                ..Default::default()
            },
        )
    });
    step(&mut env, &|env| {
        env.update(&x, IssuePatch { ephemeral: Some(false), append_notes: Some("more".into()), ..Default::default() })
    });
    step(&mut env, &|env| {
        env.update(
            &x,
            IssuePatch { add_labels: vec!["c".into()], remove_labels: vec!["a".into()], ..Default::default() },
        )
    });
    step(&mut env, &|env| env.update(&x, IssuePatch { assignee: Some(Some("alice".into())), ..Default::default() }));
    step(&mut env, &|env| {
        env.update(&x, IssuePatch { assignee: Some(None), unset_metadata: vec!["k".into()], ..Default::default() })
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.add_dependency(&x, &blocker, DepType::Blocks, None));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.add_dependency(&x, &other, DepType::Related, Some(json!({ "why": "context" }))));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.remove_dependency(&x, &blocker));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.defer_issue(&x, Some(tomorrow)));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.undefer_issue(&x));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.defer_issue(&x, None));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.undefer_issue(&x));
    });
    step(&mut env, &|env| {
        let claim = env.w(|tx| tx.claim(&x, &ClaimOptions::default()));
        env.w(|tx| tx.heartbeat(&x, Some(claim.lease.token), None));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.release(&x, &ReleaseOptions::default()));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.claim(&x, &ClaimOptions::default()));
    });
    step(&mut env, &|env| {
        env.clock.advance(Duration::from_secs(86_400));
        env.w(|tx| tx.reclaim_expired(&ReclaimOptions::default()));
    });
    // The gate: unblocked (armed), blocked again (disarmed), unblocked again.
    step(&mut env, &|env| env.close(&blocker));
    step(&mut env, &|env| env.reopen(&blocker));
    step(&mut env, &|env| env.close(&blocker));
    step(&mut env, &|env| {
        env.w(|tx| tx.escalate_gate(&g, "overdue"));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.resolve_gate(&g, Some("approved"), false));
    });
    step(&mut env, &|env| {
        env.w(|tx| tx.close_issue(&x, &CloseOptions { reason: Some("done".into()), ..Default::default() }));
    });
    step(&mut env, &|env| env.reopen(&x));
    step(&mut env, &|env| {
        env.w(|tx| tx.close_issue(&x, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() }));
    });
    step(&mut env, &|env| {
        let rev = env.issue(&x).revision;
        env.w(|tx| tx.compact_issue(&x, "short", &Guard { if_revision: Some(rev), ..Default::default() }));
    });
    let gate_armed = env.history(&g).iter().filter(|e| e.op == "unblocked").count();
    assert_eq!(gate_armed, 2, "the gate armed twice by unblocking");

    let mut failures = Vec::new();
    for (head, _, id, snap) in &rec {
        let a = env.at(id, Point::Seq(*head));
        for d in differences(&a, snap, true) {
            failures.push(format!("{id} at #{head}: {d}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Before the issues existed.
    let before = env.at(&x, Point::Seq(created_at - 10));
    assert!(!before.exists && before.created.is_some() && before.unknown.is_empty());

    // Pruned: what is still retained is right or reported unknown, never wrong.
    let floor = rec[rec.len() / 2].0;
    env.prune_before(floor);
    let mut failures = Vec::new();
    for (head, _, id, snap) in &rec {
        match env.as_of(id, Point::Seq(*head)) {
            Ok(a) if *head >= floor - 1 => {
                for d in differences(&a, snap, false) {
                    failures.push(format!("{id} at #{head} after the prune: {d}"));
                }
            }
            Ok(a) => failures.push(format!("{id} at #{head}: answered before retention: {a:?}")),
            Err(Error::HistoryPruned { floor: f, .. }) => {
                assert_eq!(f, floor);
                assert!(*head < floor - 1, "{id} at #{head}: pruned");
            }
            Err(e) => failures.push(format!("{id} at #{head}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn as_of_time_points() {
    let mut env = Env::new();
    let mut rec: Recorded = Vec::new();
    let id = env.create(NewIssue::titled("Timed"));
    record(&env, &[&id], &mut rec);
    for n in 0..4 {
        env.update(&id, IssuePatch { notes: Some(format!("note {n}")), priority: Some(n), ..Default::default() });
        record(&env, &[&id], &mut rec);
    }
    env.close(&id);
    record(&env, &[&id], &mut rec);
    for (_, ts, id, snap) in &rec {
        let a = env.at(id, Point::Time(*ts));
        assert!(differences(&a, snap, true).is_empty(), "{:?}", differences(&a, snap, true));
        // A little later, before the next write: the same.
        let a = env.at(id, Point::Time(Timestamp(ts.millis() + 500)));
        assert!(differences(&a, snap, true).is_empty());
    }
    let parsed = Point::parse("-500ms", env.now()).unwrap();
    assert_eq!(parsed, Point::Time(Timestamp(env.now().millis() - 500)));
}

#[test]
fn as_of_before_creation_is_not_existing() {
    let mut env = Env::new();
    env.create(NewIssue::titled("Old"));
    let start = env.head();
    let t = env.now();
    let id = env.create(NewIssue::titled("New"));
    let created = env.history(&id)[0].seq;
    for point in [Point::Seq(start), Point::Time(t)] {
        let a = env.at(&id, point);
        assert!(!a.exists, "{point:?}");
        assert_eq!(a.created.as_ref().map(|c| c.seq), Some(created));
        assert!(a.fields.is_empty() && a.unknown.is_empty());
    }
    // Older events pruned, the creation kept: before retention it still did not exist.
    env.prune_before(created);
    let a = env.at(&id, Point::Seq(1));
    assert!(!a.exists);
    assert_eq!(a.created.as_ref().map(|c| c.seq), Some(created));
    assert!(matches!(env.as_of("t-1", Point::Seq(1)), Err(Error::HistoryPruned { .. })));
    assert!(matches!(env.as_of("t-404", Point::Seq(1)), Err(Error::NotFound { .. })));
    assert!(matches!(env.as_of(&id, Point::Seq(env.head() + 1)), Err(Error::Invalid(_))));
}

#[test]
fn as_of_deleted_and_purged_issues() {
    let mut env = Env::new();
    let gone = env.create(NewIssue { labels: vec!["x".into()], ..NewIssue::titled("Gone") });
    let survivor = env.create(NewIssue::titled("Survivor"));
    env.w(|tx| tx.add_dependency(&survivor, &gone, DepType::Blocks, None));
    env.update(&gone, IssuePatch { notes: Some("n".into()), ..Default::default() });
    let before = env.head();
    let snap = env.snap(&gone);
    let survivor_snap = env.snap(&survivor);
    env.w(|tx| tx.delete_issues(std::slice::from_ref(&gone), &DeleteOptions { force: true, ..Default::default() }));
    let deleted = env.history(&gone).last().unwrap().seq;

    let a = env.at(&gone, Point::Seq(before));
    assert!(differences(&a, &snap, true).is_empty(), "{:?}", differences(&a, &snap, true));
    let a = env.at(&gone, Point::Seq(env.head()));
    assert!(!a.exists && a.deleted_by_then());
    assert_eq!(a.deleted.as_ref().map(|d| d.seq), Some(deleted));
    let a = env.at(&survivor, Point::Seq(before));
    assert!(differences(&a, &survivor_snap, true).is_empty());

    // With the creations pruned, the deletion still rebuilds both.
    env.prune_before(before);
    let a = env.at(&gone, Point::Seq(before));
    assert!(differences(&a, &snap, true).is_empty(), "{:?}", differences(&a, &snap, true));
    let a = env.at(&survivor, Point::Seq(before));
    assert_eq!(a.dependencies.len(), 1, "via the dep_removed recorded on it: {a:?}");
    assert!(differences(&a, &survivor_snap, true).is_empty(), "{:?}", differences(&a, &survivor_snap, true));

    // A purged issue: no event of its own records the purge.
    let scratch = env.create(NewIssue { ephemeral: true, ..NewIssue::titled("Scratch") });
    env.close(&scratch);
    let closed = env.head();
    let snap = env.snap(&scratch);
    env.w(|tx| tx.purge_ephemeral(None, false));
    let a = env.at(&scratch, Point::Seq(closed));
    assert!(differences(&a, &snap, true).is_empty(), "{:?}", differences(&a, &snap, true));
    let a = env.at(&scratch, Point::Seq(env.head()));
    assert!(!a.exists && a.deleted_by_then());
}

#[test]
fn as_of_reports_unknown_for_old_payloads() {
    let mut env = Env::new();
    let id = env.create(NewIssue::titled("Work"));
    env.w(|tx| tx.close_issue(&id, &CloseOptions { reason: Some("first".into()), ..Default::default() }));
    let closed = env.head();
    let work = env.create(NewIssue::titled("Gated work"));
    let g = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    let gated = env.head();
    env.reopen(&id);
    env.w(|tx| tx.escalate_gate(&g, "overdue"));
    // As an older bd wrote them: a reopen without its previous close fields, an escalation without its change.
    env.sql(
        "UPDATE events SET data = json_remove(data, '$.previous') WHERE op = 'reopened';
             UPDATE events SET data = json_remove(data, '$.changes') WHERE op = 'gate_escalated';",
    );
    let seq_of = |env: &Env, id: &str, op: &str| env.history(id).iter().find(|e| e.op == op).unwrap().seq;
    let (reopened, escalated) = (seq_of(&env, &id, "reopened"), seq_of(&env, &g, "gate_escalated"));
    // What came before is pruned: only the backward pass tells.
    env.prune_before(closed + 1);
    let a = env.at(&id, Point::Seq(closed));
    assert_eq!(
        unknown_keys(&a),
        BTreeSet::from(["close_reason".to_string(), "close_outcome".into(), "closed_at".into()])
    );
    assert!(reason_of(&a, "close_reason").contains(&format!("reopened #{reopened}")), "{a:?}");
    assert_eq!(a.fields["status"], "closed");
    env.prune_before(gated + 1);
    let a = env.at(&g, Point::Seq(gated));
    assert!(reason_of(&a, "metadata").contains(&format!("gate_escalated #{escalated}")), "{a:?}");
    assert_eq!(a.fields["title"], env.issue(&g).title);
}

#[test]
fn as_of_flags_unrecorded_changes() {
    let mut env = Env::new();
    let id = env.create(NewIssue { notes: "original".into(), ..NewIssue::titled("Work") });
    let created = env.head();
    env.update(&id, IssuePatch { priority: Some(1), ..Default::default() });
    env.sql(&format!("UPDATE issues SET notes = 'x' WHERE id = '{id}'"));
    let a = env.at(&id, Point::Seq(created));
    assert!(unknown_keys(&a).contains("notes"), "{a:?}");
    assert!(reason_of(&a, "notes").starts_with("changed without a recorded event between #"), "{a:?}");
    assert!(!a.fields.contains_key("notes"));
    assert_eq!(a.fields["priority"], 2);
}

#[test]
fn as_of_after_rename_prefix() {
    let mut env = Env::new();
    let one = env.create(NewIssue::titled("One"));
    let two = env.create(NewIssue {
        description: "after t-1".into(),
        metadata: Some(json!({ "see": "t-1" })),
        deps: vec![(DepType::Blocks, one.clone())],
        ..NewIssue::titled("Two")
    });
    let before = env.head();
    let snap_before = env.snap(&two);
    env.w(|tx| tx.rename_prefix(&RenamePrefixOptions { to: "u".into(), from: None }));
    let now = env.at("u-2", Point::Seq(env.head()));
    assert!(differences(&now, &env.snap("u-2"), true).is_empty(), "{:?}", differences(&now, &env.snap("u-2"), true));
    let then = env.at("u-2", Point::Seq(before));
    assert_eq!(then.fields["description"], snap_before["description"]);
    assert_eq!(then.fields["description"], "after t-1");
    assert!(then.unknown.is_empty(), "{then:?}");
}

#[test]
fn as_of_gate_metadata_follows_arming() {
    let mut env = Env::new();
    let blocker = env.create(NewIssue::titled("Blocker"));
    let work = env.create(NewIssue { deps: vec![(DepType::Blocks, blocker.clone())], ..NewIssue::titled("Work") });
    let free = env.create(NewIssue::titled("Free work"));
    let shut = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    let open = env.w(|tx| tx.create_gate(gate(GateKind::Human, &free))).id;
    let at_create = env.at(&open, Point::Seq(env.head()));
    let armed = env.history(&open).iter().find(|e| e.op == "gate_armed").unwrap().ts;
    assert_eq!(at_create.fields["metadata"]["gate"]["armed_at"], json!(armed));

    env.close(&blocker);
    let unblocked = env.history(&shut).iter().rev().find(|e| e.op == "unblocked").unwrap().clone();
    let a = env.at(&shut, Point::Seq(unblocked.seq));
    assert_eq!(a.fields["metadata"]["gate"]["armed_at"], json!(unblocked.ts));
    env.reopen(&blocker);
    let a = env.at(&shut, Point::Seq(env.head()));
    assert!(a.fields["metadata"]["gate"].get("armed_at").is_none(), "{a:?}");
    assert_eq!(a.fields["metadata"], env.issue(&shut).metadata);
}

#[test]
fn as_of_marks_history_before_the_marker_incomplete() {
    // A rename an older bd made: its references_renamed events are missing.
    let mut env = Env::new();
    env.create(NewIssue::titled("One"));
    let two = env.create(NewIssue { description: "after t-1".into(), ..NewIssue::titled("Two") });
    env.w(|tx| tx.rename_prefix(&RenamePrefixOptions { to: "u".into(), from: None }));
    let renamed = env.head();
    env.sql("DELETE FROM events WHERE op = 'references_renamed'");
    env.set_marker(renamed + 1);
    env.update("u-2", IssuePatch { priority: Some(1), ..Default::default() });
    let created = env.history("u-2")[0].seq;
    let _ = two;
    env.prune_before(created + 1);
    let floor = env.store.read(|r| events::floor(r.conn())).unwrap();
    // Before the rename (the state before the oldest event kept): the text may have been rewritten since.
    let a = env.at("u-2", Point::Seq(floor - 1));
    assert!(a.incomplete);
    assert!(unknown_keys(&a).contains("description"), "{a:?}");
    assert!(reason_of(&a, "description").contains("older bd"), "{a:?}");
    assert!(reason_of(&a, "description").contains(&format!("rename-prefix at #{renamed}")), "{a:?}");
    assert_eq!(a.fields["priority"], 2, "untouched by the rename");
    assert_eq!(a.fields["title"], "Two", "no renamed prefix in it");
    // After it, the evidence spans no older bd's history.
    let a = env.at("u-2", Point::Seq(renamed));
    assert!(!a.incomplete && a.unknown.is_empty(), "{a:?}");
    assert_eq!(a.fields["description"], "after u-1");
    // With every event recorded in full, nothing is suspect.
    env.set_marker(1);
    let a = env.at("u-2", Point::Seq(renamed));
    assert!(!a.incomplete && !unknown_keys(&a).contains("description"), "{a:?}");

    // A gate an older bd armed at creation: no gate_armed.
    let mut env = Env::new();
    let work = env.create(NewIssue::titled("Work"));
    let g = env.w(|tx| tx.create_gate(gate(GateKind::Human, &work))).id;
    let created = env.head();
    env.sql("DELETE FROM events WHERE op = 'gate_armed'");
    env.set_marker(created + 1);
    env.update(&g, IssuePatch { priority: Some(1), ..Default::default() });
    // Just after its creation, before the arming in the same transaction; the creation pruned.
    let g_created = env.history(&g)[0].seq;
    env.prune_before(g_created + 1);
    let a = env.at(&g, Point::Seq(g_created));
    assert!(a.incomplete);
    assert!(reason_of(&a, "metadata").contains("gate arming"), "{a:?}");
    assert_eq!(a.fields["priority"], 2);

    // An edge an older bd dropped with the issue it pointed to: no dep_removed.
    let mut env = Env::new();
    let gone = env.create(NewIssue::titled("Gone"));
    let survivor = env.create(NewIssue { deps: vec![(DepType::Related, gone.clone())], ..NewIssue::titled("S") });
    let linked = env.head();
    env.w(|tx| tx.delete_issues(std::slice::from_ref(&gone), &DeleteOptions { force: true, ..Default::default() }));
    let deleted = env.head();
    env.sql("DELETE FROM events WHERE op = 'dep_removed'");
    env.set_marker(deleted + 1);
    env.update(&survivor, IssuePatch { priority: Some(1), ..Default::default() });
    // Before the deletion, the edge's record pruned: the deletion may have dropped an edge it did not record.
    env.prune_before(linked + 1);
    let floor = env.store.read(|r| events::floor(r.conn())).unwrap();
    assert_eq!(floor, deleted, "the oldest event kept is the deletion's");
    let a = env.at(&survivor, Point::Seq(floor - 1));
    assert!(a.incomplete);
    let key = format!("dep:{gone}");
    assert!(unknown_keys(&a).contains(&key), "{a:?}");
    assert!(reason_of(&a, &key).contains(&format!("deletion of {gone} at #")), "{a:?}");
    assert_eq!(a.fields["priority"], 2);
    // After it, nothing is suspect: the edge is gone.
    let a = env.at(&survivor, Point::Seq(deleted));
    assert!(a.unknown.is_empty() && a.dependencies.is_empty(), "{a:?}");
}

#[test]
fn as_of_legacy_taint_is_targeted() {
    let mut env = Env::new();
    let target = env.create(NewIssue { ephemeral: true, ..NewIssue::titled("Purged target") });
    let other_purged = env.create(NewIssue { ephemeral: true, ..NewIssue::titled("Purged too") });
    let a = env.create(NewIssue { deps: vec![(DepType::Related, target.clone())], ..NewIssue::titled("A") });
    let b = env.create(NewIssue { description: "nothing renamed here".into(), ..NewIssue::titled("B") });
    let c = env.create(NewIssue::titled("C"));
    env.close(&target);
    env.close(&other_purged);
    let before = env.head();
    env.w(|tx| tx.purge_ephemeral(None, false));
    env.w(|tx| tx.delete_issues(std::slice::from_ref(&c), &DeleteOptions::default()));
    env.sql("DELETE FROM events WHERE op = 'dep_removed'");
    let legacy_end = env.head();
    env.set_marker(legacy_end + 1);
    env.update(&b, IssuePatch { priority: Some(1), ..Default::default() });
    env.update(&a, IssuePatch { priority: Some(1), ..Default::default() });

    // B lost no edge to the purge: none of the purged ids is suspect for it, nor C, which it never pointed to.
    let ab = env.at(&b, Point::Seq(before));
    let keys = unknown_keys(&ab);
    assert!(!keys.iter().any(|k| k.starts_with("dep:")), "{ab:?}");
    assert!(ab.dependencies.is_empty());
    assert_eq!(ab.fields["description"], "nothing renamed here");
    // A did: its edge to the purged target is suspect where only the backward pass could tell, and right here,
    // where the retained creation shows it.
    let aa = env.at(&a, Point::Seq(before));
    assert_eq!(aa.dependencies.iter().map(|d| d.target.as_str()).collect::<Vec<_>>(), [target.as_str()]);
    // Its creation and the edge added with it pruned.
    let created_a = env.history(&a)[0].seq;
    env.prune_before(created_a + 2);
    let aa = env.at(&a, Point::Seq(before));
    assert!(unknown_keys(&aa).contains(&format!("dep:{target}")), "{aa:?}");
    let ab = env.at(&b, Point::Seq(before));
    assert!(!unknown_keys(&ab).contains(&format!("dep:{other_purged}")), "{ab:?}");
}

// ---------------------------------------------------------------- compaction

fn closed_with_text(env: &mut Env, title: &str) -> String {
    let id = env.create(NewIssue {
        description: "A long description of what was done and why it was done that way.".into(),
        design: "Design notes".into(),
        acceptance_criteria: "It works".into(),
        notes: "Some notes".into(),
        ..NewIssue::titled(title)
    });
    env.close(&id);
    id
}

fn guard(rev: i64) -> Guard {
    Guard { if_revision: Some(rev), ..Default::default() }
}

#[test]
fn compact_refuses_open_and_stale_and_longer_summaries() {
    let mut env = Env::new();
    let open = env.create(NewIssue { description: "text".repeat(20), ..NewIssue::titled("Open") });
    let rev = env.issue(&open).revision;
    let e = env.try_w(|tx| tx.compact_issue(&open, "short", &guard(rev))).unwrap_err();
    assert!(matches!(e, Error::Refused(_)) && e.exit_code() == 2, "{e}");
    let id = closed_with_text(&mut env, "Closed");
    let rev = env.issue(&id).revision;
    let e = env.try_w(|tx| tx.compact_issue(&id, "short", &guard(rev - 1))).unwrap_err();
    assert_eq!(e.exit_code(), 13, "{e}");
    let e = env.try_w(|tx| tx.compact_issue(&id, "  \n", &guard(rev))).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    let e = env.try_w(|tx| tx.compact_issue(&id, &"x".repeat(500), &guard(rev))).unwrap_err();
    assert!(matches!(e, Error::Refused(_)) && e.to_string().contains("not shorter"), "{e}");
    assert_eq!(env.issue(&id).revision, rev, "nothing written");
}

#[test]
fn compact_replaces_text_and_records_original() {
    let mut env = Env::new();
    let id = closed_with_text(&mut env, "Done");
    let before = env.issue(&id);
    let head = env.head();
    let out = env.w(|tx| tx.compact_issue(&id, "Did it.\n\n", &guard(before.revision)));
    assert_eq!((out.level, out.size), (1, 7));
    let original = compaction::text_size(&before) as i64;
    assert_eq!(out.original_size, original);
    let after = env.issue(&id);
    assert_eq!(
        (after.description.as_str(), after.design.as_str(), after.acceptance_criteria.as_str(), after.notes.as_str()),
        ("Did it.", "", "", "")
    );
    assert_eq!((after.title.as_str(), after.close_reason.clone()), ("Done", before.close_reason.clone()));
    assert_eq!(after.revision, before.revision + 1);
    let c = &after.metadata["compaction"];
    assert_eq!((c["level"].as_i64(), c["original_size"].as_i64()), (Some(1), Some(original)));
    assert_eq!(c["compacted_at"], json!(env.now()));
    let events = env.events_since(head);
    let compacted: Vec<&Event> = events.iter().filter(|e| e.op == "compacted").collect();
    assert_eq!(compacted.len(), 1);
    assert!(events.iter().all(|e| e.op != "updated"));
    let d = &compacted[0].data;
    assert_eq!(d["changes"]["description"]["old"], json!(before.description));
    assert_eq!(d["changes"]["notes"]["old"], json!(before.notes));
    assert_eq!(d["changes"]["metadata"]["new"], after.metadata);
    assert_eq!(
        (d["level"].as_i64(), d["original_size"].as_i64(), d["size"].as_i64()),
        (Some(1), Some(original), Some(7))
    );
}

#[test]
fn compact_again_raises_level_keeps_original_size() {
    let mut env = Env::new();
    let id = closed_with_text(&mut env, "Done");
    let original = compaction::text_size(&env.issue(&id)) as i64;
    let rev = env.issue(&id).revision;
    env.w(|tx| tx.compact_issue(&id, "Did it, in short.", &guard(rev)));
    let rev = env.issue(&id).revision;
    let out = env.w(|tx| tx.compact_issue(&id, "Did it.", &guard(rev)));
    assert_eq!((out.level, out.original_size), (2, original));
    assert_eq!(env.issue(&id).metadata["compaction"]["level"], 2);
}

#[test]
fn candidates_respect_age_ephemeral_compacted_empty_and_limit() {
    let mut env = Env::new();
    let old1 = closed_with_text(&mut env, "Old 1");
    let old2 = closed_with_text(&mut env, "Old 2");
    let old3 = closed_with_text(&mut env, "Old 3");
    let compacted = closed_with_text(&mut env, "Compacted");
    let rev = env.issue(&compacted).revision;
    env.w(|tx| tx.compact_issue(&compacted, "short", &guard(rev)));
    let empty = env.create(NewIssue::titled("Empty"));
    env.close(&empty);
    let eph = env.create(NewIssue { description: "scratch".into(), ephemeral: true, ..NewIssue::titled("Eph") });
    env.close(&eph);
    env.create(NewIssue { description: "open".into(), ..NewIssue::titled("Open") });
    env.clock.advance(Duration::from_secs(10 * 86_400));
    let recent = closed_with_text(&mut env, "Recent");

    let ids = |c: Vec<Candidate>| c.into_iter().map(|c| c.id).collect::<Vec<_>>();
    let week = Duration::from_secs(7 * 86_400);
    let all = env.store.read(|r| r.compact_candidates(week, None)).unwrap();
    assert_eq!(all[0].size, compaction::text_size(&env.issue(&old1)));
    assert_eq!(all[0].revision, env.issue(&old1).revision);
    assert_eq!(ids(all), [old1.clone(), old2.clone(), old3.clone()]);
    assert_eq!(ids(env.store.read(|r| r.compact_candidates(week, Some(2))).unwrap()), [old1.clone(), old2.clone()]);
    let any_age = ids(env.store.read(|r| r.compact_candidates(Duration::ZERO, None)).unwrap());
    assert_eq!(any_age, [old1, old2, old3, recent]);
}

#[test]
fn stats_counts() {
    let mut env = Env::new();
    let a = closed_with_text(&mut env, "A");
    let b = closed_with_text(&mut env, "B");
    let c = closed_with_text(&mut env, "C");
    env.create(NewIssue::titled("Open"));
    let size = compaction::text_size(&env.issue(&a)) as i64;
    for (id, summary) in [(&a, "Short A."), (&b, "Short B, longer.")] {
        let rev = env.issue(id).revision;
        env.w(|tx| tx.compact_issue(id, summary, &guard(rev)));
    }
    let rev = env.issue(&a).revision;
    env.w(|tx| tx.compact_issue(&a, "A.", &guard(rev)));
    let s = env.store.read(|r| r.compact_stats(Duration::ZERO)).unwrap();
    assert_eq!((s.closed, s.compacted), (3, 2));
    assert_eq!(s.by_level.into_iter().collect::<Vec<_>>(), [(1, 1), (2, 1)]);
    assert_eq!(s.original_bytes, 2 * size);
    assert_eq!(s.current_bytes, ("A.".len() + "Short B, longer.".len()) as i64);
    assert_eq!(s.saved_bytes, s.original_bytes - s.current_bytes);
    assert_eq!((s.candidates, s.candidate_bytes), (1, compaction::text_size(&env.issue(&c)) as i64));
    let s = env.store.read(|r| r.compact_stats(Duration::from_secs(86_400))).unwrap();
    assert_eq!(s.candidates, 0);
}

#[test]
fn as_of_before_compaction_shows_original() {
    let mut env = Env::new();
    let id = closed_with_text(&mut env, "Done");
    let original = env.snap(&id);
    env.clock.advance(Duration::from_secs(60));
    let rev = env.issue(&id).revision;
    env.w(|tx| tx.compact_issue(&id, "Did it.", &guard(rev)));
    let e = env.history(&id).into_iter().find(|e| e.op == "compacted").unwrap();
    let (seq, ts) = (e.seq, e.ts);
    let compacted = env.snap(&id);
    let just_before = Timestamp(ts.millis() - 1000);

    let check_original = |a: &IssueAsOf| {
        for f in ["description", "design", "acceptance_criteria", "notes", "metadata"] {
            assert_eq!(a.fields.get(f), Some(&original[f]), "{f}: {a:?}");
            assert!(!unknown_keys(a).contains(f));
        }
        assert!(a.fields["metadata"].get("compaction").is_none());
    };
    for point in [Point::Seq(seq - 1), Point::Time(just_before)] {
        let a = env.at(&id, point);
        check_original(&a);
        assert!(a.unknown.is_empty(), "{a:?}");
    }
    for point in [Point::Seq(seq), Point::Time(ts)] {
        let a = env.at(&id, point);
        assert!(differences(&a, &compacted, true).is_empty(), "{:?}", differences(&a, &compacted, true));
    }

    // Everything older than the compaction pruned: its seq minus one (the floor's) still shows the original.
    env.prune_before(seq);
    check_original(&env.at(&id, Point::Seq(seq - 1)));
    let e = env.as_of(&id, Point::Time(just_before)).unwrap_err();
    assert!(matches!(e, Error::HistoryPruned { floor, .. } if floor == seq), "{e}");
    assert_eq!((e.code(), e.exit_code()), ("history_pruned", 6));
    assert_eq!(env.at(&id, Point::Time(ts)).fields["description"], "Did it.");
    let _ = asof::FIELDS;
}
