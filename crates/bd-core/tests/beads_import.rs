//! Lossless import of beads' `bd export` format: every field of upstream's
//! `Issue`, `IssueWithCounts` and export record is mapped, kept under
//! `metadata.beads`, or dropped (and counted), and a bd export of the result
//! round-trips byte for byte.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use bd_core::transfer::{ExportOptions, FieldCounts, ImportOptions, ImportSummary};
use bd_core::*;
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const FIXTURE: &str = include_str!("fixtures/beads-export.jsonl");

/// Every JSON key of upstream's `Issue` (internal/types/types.go), of
/// `IssueWithCounts`, and of `exportIssueRecord` (cmd/bd/export.go), plus the
/// legacy `wisp` flag older exports carry.
const UPSTREAM_KEYS: &[&str] = &[
    // Issue
    "id",
    "title",
    "description",
    "design",
    "acceptance_criteria",
    "notes",
    "spec_id",
    "status",
    "priority",
    "issue_type",
    "is_blocked",
    "assignee",
    "owner",
    "estimated_minutes",
    "created_at",
    "created_by",
    "updated_at",
    "started_at",
    "closed_at",
    "close_reason",
    "closed_by_session",
    "lease_expires_at",
    "heartbeat_at",
    "lease_granted_node",
    "due_at",
    "defer_until",
    "external_ref",
    "source_system",
    "metadata",
    "compaction_level",
    "compacted_at",
    "compacted_at_commit",
    "original_size",
    "labels",
    "dependencies",
    "comments",
    "sender",
    "ephemeral",
    "no_history",
    "wisp_type",
    "storage_class",
    "pinned",
    "is_template",
    "bonded_from",
    "await_type",
    "await_id",
    "timeout",
    "waiters",
    "source_formula",
    "source_location",
    "mol_type",
    "work_type",
    "event_kind",
    "actor",
    "target",
    "payload",
    // IssueWithCounts
    "dependency_count",
    "dependent_count",
    "comment_count",
    "comments_omitted",
    "parent",
    // exportIssueRecord
    "_type",
    "wisp_plane",
    // legacy
    "wisp",
];

/// Fields that map to a column, labels, edges, comments or the gate.
const MAPPED: &[&str] = &[
    "id",
    "title",
    "description",
    "design",
    "acceptance_criteria",
    "notes",
    "status",
    "priority",
    "issue_type",
    "assignee",
    "estimated_minutes",
    "created_at",
    "created_by",
    "updated_at",
    "started_at",
    "closed_at",
    "close_reason",
    "due_at",
    "defer_until",
    "external_ref",
    "metadata",
    "labels",
    "dependencies",
    "comments",
    "ephemeral",
    "is_template",
    // Mapped when the fixture backs them: legacy `wisp` is `ephemeral`, `parent`
    // is a parent-child edge, `await_*` form `metadata.gate`.
    "wisp",
    "parent",
    "await_type",
    "await_id",
    "timeout",
    "waiters",
];

/// Fields kept as `metadata.beads.<field>` with the value unchanged.
const KEPT: &[&str] = &[
    "owner",
    "spec_id",
    "closed_by_session",
    "source_system",
    "sender",
    "compaction_level",
    "compacted_at",
    "compacted_at_commit",
    "original_size",
    "mol_type",
    "wisp_type",
    "work_type",
    "no_history",
    "storage_class",
    "pinned",
    "bonded_from",
    "source_formula",
    "source_location",
    "event_kind",
    "actor",
    "target",
    "payload",
    "wisp_plane",
];

/// Derived or node-local: dropped.
const DERIVED: &[&str] = &[
    "is_blocked",
    "revision",
    "dependency_count",
    "dependent_count",
    "comment_count",
    "comments_omitted",
    "lease_expires_at",
    "heartbeat_at",
    "lease_granted_node",
];

const TIMESTAMPS: &[&str] = &["created_at", "updated_at", "started_at", "closed_at", "due_at", "defer_until"];

struct Env {
    _dir: TempDir,
    store: Store,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bd").join("bd.db");
        let clock = Arc::new(ManualClock::new(Timestamp(1_700_000_000_000)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store = Store::init(&path, InitOptions { prefix: "bd".into(), id_mode: IdMode::Counter }, opts).unwrap();
        clock.advance(Duration::from_secs(1));
        Env { _dir: dir, store }
    }

    fn import(&mut self, input: &str) -> ImportSummary {
        let opts = ImportOptions { lenient: true, ..Default::default() };
        self.store.write("import", "me", |tx| tx.import_jsonl(&mut input.as_bytes(), &opts)).unwrap()
    }

    /// The export, one parsed line per record, header removed.
    fn export(&self) -> Vec<Value> {
        let mut buf = Vec::new();
        let opts = ExportOptions { include_ephemeral: true, ..Default::default() };
        self.store.read(|r| r.export_jsonl(&mut buf, &opts)).unwrap();
        let text = String::from_utf8(buf).unwrap();
        text.lines().skip(1).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn assert_healthy(&mut self) {
        let report = bd_core::doctor::diagnose(&mut self.store, false, true).unwrap();
        let bad: Vec<_> = report.checks.iter().filter(|c| c.severity != bd_core::doctor::Severity::Ok).collect();
        assert!(bad.is_empty(), "doctor found problems: {bad:#?}");
    }
}

fn fixture_lines() -> Vec<Map<String, Value>> {
    FIXTURE.lines().map(|l| serde_json::from_str::<Value>(l).unwrap().as_object().unwrap().clone()).collect()
}

fn counts(summary: &ImportSummary, key: &str) -> (usize, usize, usize) {
    let c: FieldCounts = summary.fields.get(key).cloned().unwrap_or_default();
    (c.mapped, c.kept, c.dropped)
}

fn instant(v: &Value) -> Timestamp {
    Timestamp::parse_rfc3339(v.as_str().unwrap()).unwrap()
}

#[test]
fn fixture_has_every_upstream_key() {
    let seen: BTreeSet<String> = fixture_lines().iter().flat_map(|l| l.keys().cloned()).collect();
    let missing: Vec<_> = UPSTREAM_KEYS.iter().filter(|k| !seen.contains(**k)).collect();
    assert!(missing.is_empty(), "fixture lacks upstream keys: {missing:?}");
    let known: BTreeSet<&str> = UPSTREAM_KEYS.iter().copied().chain(["revision"]).collect();
    for k in &seen {
        assert!(known.contains(k.as_str()) || k.starts_with("x_"), "unexpected fixture key {k}");
    }
    // The three tables partition upstream's keys (plus the marker).
    for k in UPSTREAM_KEYS.iter().filter(|k| **k != "_type") {
        let n = [MAPPED, KEPT, DERIVED].iter().filter(|t| t.contains(k)).count();
        assert_eq!(n, 1, "{k} must be in exactly one table");
    }
}

#[test]
fn every_key_is_mapped_kept_or_dropped() {
    let mut env = Env::new();
    let summary = env.import(FIXTURE);
    assert_eq!((summary.created, summary.skipped), (9, 2), "{summary:?}");
    let exported = env.export();
    let by_id: BTreeMap<&str, &Value> = exported.iter().map(|v| (v["id"].as_str().unwrap(), v)).collect();
    assert_eq!(by_id.len(), 9);
    assert!(!by_id.contains_key("bd-t1") && !by_id.contains_key("bd-p1"));

    for line in fixture_lines() {
        let id = line["id"].as_str().unwrap();
        let Some(out) = by_id.get(id) else { continue };
        let beads = out["metadata"].get("beads").and_then(Value::as_object).cloned().unwrap_or_default();
        for (k, v) in line.iter().filter(|(k, v)| k.as_str() != "_type" && !v.is_null()) {
            let k = k.as_str();
            if DERIVED.contains(&k) {
                assert!(!beads.contains_key(k), "{id}: derived {k} must not be kept");
            } else if KEPT.contains(&k) || k.starts_with("x_") {
                assert_eq!(beads.get(k), Some(v), "{id}: {k} kept in metadata.beads");
            } else if TIMESTAMPS.contains(&k) {
                assert_eq!(instant(&out[k]), instant(v), "{id}: {k}");
            } else {
                assert!(MAPPED.contains(&k), "{id}: {k} is in no table");
                assert!(!beads.contains_key(k), "{id}: mapped {k} also kept");
                match k {
                    "is_template" => assert!(v == &json!(false)),
                    "wisp" => assert_eq!(out["ephemeral"], json!(true), "{id}: legacy wisp"),
                    "parent" => {
                        let deps = out["dependencies"].as_array().unwrap();
                        assert!(
                            deps.iter().any(|d| d["type"] == "parent-child" && &d["depends_on_id"] == v),
                            "{id}: parent {v} backed by an edge"
                        );
                    }
                    "await_type" | "await_id" | "timeout" | "waiters" => {
                        assert!(out["metadata"]["gate"]["type"].is_string(), "{id}: gate formed");
                    }
                    "metadata" => {
                        for (mk, mv) in v.as_object().unwrap().iter().filter(|(mk, _)| mk.as_str() != "beads") {
                            assert_eq!(&out["metadata"][mk], mv);
                        }
                    }
                    "labels" | "comments" | "dependencies" => {
                        assert_eq!(out[k].as_array().unwrap().len(), v.as_array().unwrap().len(), "{id}: {k}");
                    }
                    "ephemeral" => assert_eq!(out[k], *v),
                    _ => assert_eq!(&out[k], v, "{id}: {k}"),
                }
            }
        }
        // Nothing appears in metadata.beads that the line did not carry.
        for k in beads.keys() {
            assert!(line.contains_key(k) || k == "origin", "{id}: metadata.beads.{k} comes from no field of the line");
        }
    }

    // Existing metadata.beads keys stay, merged with kept fields.
    let e1 = by_id["bd-e1"]["metadata"]["beads"].as_object().unwrap();
    assert_eq!(e1["origin"], "hand-written");
    assert_eq!(e1["owner"], "quang@example.com");
    assert_eq!(e1["x_custom"]["nested"][2]["deep"], true);
    assert_eq!(by_id["bd-e1"]["metadata"]["team"], "core");
    // Gate fields formed a gate.
    let gate = &by_id["bd-g1"]["metadata"]["gate"];
    assert_eq!(
        (gate["type"].as_str(), gate["await_id"].as_str(), gate["timeout"].as_str()),
        (Some("timer"), Some("soak"), Some("1h"))
    );
    assert_eq!(gate["waiters"], json!(["mayor/"]));
    assert!(by_id["bd-g1"]["metadata"].get("beads").is_none());
    // Edge metadata: string-encoded metadata parsed, thread_id kept.
    let related = by_id["bd-e1.1"]["dependencies"].as_array().unwrap().iter().find(|d| d["type"] == "related").unwrap();
    assert_eq!(related["metadata"], json!({ "weight": 3 }));
    let reply = &by_id["bd-m2"]["dependencies"][0];
    assert_eq!(reply["metadata"], json!({ "beads": { "thread_id": "bd-m1" } }));
    // Leases are granted fresh and the derived state is bd's own.
    assert_eq!(by_id["bd-e1.2"]["status"], "in_progress");
    assert_eq!(summary.leases_granted, 1);
    env.assert_healthy();
}

#[test]
fn reports_fields_mapped_kept_and_dropped() {
    let mut env = Env::new();
    let s = env.import(FIXTURE);
    // Nine issues survive; the tombstone and the proto contribute dropped.
    assert_eq!(counts(&s, "title"), (9, 0, 2));
    assert_eq!(counts(&s, "owner"), (0, 3, 2));
    assert_eq!(counts(&s, "spec_id"), (0, 1, 1));
    assert_eq!(counts(&s, "x_custom"), (0, 1, 1));
    assert_eq!(counts(&s, "is_template"), (1, 0, 1));
    assert_eq!(counts(&s, "dependency_count"), (0, 0, 3));
    assert_eq!(counts(&s, "comment_count"), (0, 0, 3));
    assert_eq!(counts(&s, "is_blocked"), (0, 0, 2));
    assert_eq!(counts(&s, "revision"), (0, 0, 1));
    assert_eq!(counts(&s, "parent"), (2, 0, 0));
    assert_eq!(counts(&s, "wisp"), (1, 0, 0));
    assert_eq!(counts(&s, "ephemeral"), (1, 0, 0));
    assert_eq!(counts(&s, "await_type"), (1, 0, 0));
    assert_eq!(counts(&s, "mol_type"), (0, 1, 0));
    assert_eq!(counts(&s, "wisp_type"), (0, 1, 0));
    assert_eq!(counts(&s, "wisp_plane"), (0, 1, 0));
    assert_eq!(counts(&s, "dependencies.thread_id"), (0, 1, 0));
    assert!(!s.fields.contains_key("_type"));
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["fields"]["owner"], json!({ "mapped": 0, "kept": 3, "dropped": 2 }));
    // Only the proto warns; kept fields and dropped counts are silent.
    assert_eq!(s.warnings.iter().filter(|w| w.contains("proto")).count(), 1);
    assert!(s.warnings.iter().all(|w| !w.contains("metadata.beads")), "{:?}", s.warnings);
}

#[test]
fn export_round_trips_and_reimport_is_unchanged() {
    let mut a = Env::new();
    a.import(FIXTURE);
    let first = a.export();
    // Re-importing the beads file changes nothing.
    let again = a.import(FIXTURE);
    assert_eq!((again.created, again.updated, again.unchanged), (0, 0, 9), "{again:?}");
    assert_eq!(a.export(), first);

    // A bd export imports into a fresh store to the same export, and adds
    // no metadata.beads of its own.
    let mut text = String::new();
    for line in &first {
        text.push_str(&line.to_string());
        text.push('\n');
    }
    let mut b = Env::new();
    let s = b.import(&text);
    assert_eq!((s.created, s.skipped), (9, 0), "{s:?}");
    assert!(s.fields.values().all(|c| c.kept == 0 && c.dropped == 0), "{:?}", s.fields);
    assert_eq!(b.export(), first);
    let (e1, e2) = (a.export(), b.export());
    for (x, y) in e1.iter().zip(&e2) {
        assert_eq!(x.to_string(), y.to_string());
    }
    b.assert_healthy();
}

#[test]
fn metadata_beads_wins_over_top_level_fields() {
    let mut env = Env::new();
    let line = r#"{"_type":"issue","id":"bd-1","title":"A","owner":"top@x","spec_id":"s","mol_type":"swarm","metadata":{"beads":{"owner":"inner@x","mol_type":"patrol"}}}
{"_type":"issue","id":"bd-2","title":"B","owner":"top@x","wisp":"yes","parent":"bd-nope","metadata":{"beads":"text"}}
"#;
    let s = env.import(line);
    assert_eq!(s.created, 2);
    let one = env.store.read(|r| r.issue("bd-1")).unwrap();
    assert_eq!(one.metadata["beads"], json!({ "owner": "inner@x", "mol_type": "patrol", "spec_id": "s" }));
    assert_eq!(counts(&s, "mol_type"), (0, 0, 1));
    assert_eq!(counts(&s, "spec_id"), (0, 1, 0));
    assert!(
        s.warnings.contains(&"bd-1: kept metadata.beads.owner, dropped top-level owner".to_string()),
        "{:?}",
        s.warnings
    );
    assert!(s.warnings.contains(&"bd-1: kept metadata.beads.mol_type, dropped top-level mol_type".to_string()));
    // A metadata.beads that is not an object is left alone and the fields are dropped.
    let two = env.store.read(|r| r.issue("bd-2")).unwrap();
    assert_eq!(two.metadata["beads"], json!("text"));
    assert_eq!(counts(&s, "owner"), (0, 0, 2));
    assert_eq!(counts(&s, "wisp"), (0, 0, 1));
    assert_eq!(counts(&s, "parent"), (0, 0, 1));
    assert!(s.warnings.iter().any(|w| w.starts_with("bd-2: metadata.beads is not an object")));
}

#[test]
fn legacy_wisp_flag_maps_to_ephemeral() {
    let mut env = Env::new();
    let s = env
        .import("{\"id\":\"bd-1\",\"title\":\"A\",\"wisp\":true}\n{\"id\":\"bd-2\",\"title\":\"B\",\"wisp\":false}\n");
    assert_eq!(counts(&s, "wisp"), (2, 0, 0));
    assert!(env.store.read(|r| r.issue("bd-1")).unwrap().ephemeral);
    let two = env.store.read(|r| r.issue("bd-2")).unwrap();
    assert!(!two.ephemeral && two.metadata.get("beads").is_none());
}

#[test]
fn gate_fields_are_kept_when_no_gate_forms() {
    let mut env = Env::new();
    let s = env.import(
        "{\"id\":\"bd-1\",\"title\":\"A\",\"await_id\":\"x\",\"waiters\":[\"w\"]}\n{\"id\":\"bd-2\",\"title\":\"B\",\"await_type\":\"timer\",\"timeout\":1000000000,\"metadata\":{\"gate\":{\"type\":\"human\"}}}\n",
    );
    let one = env.store.read(|r| r.issue("bd-1")).unwrap();
    assert_eq!(one.metadata, json!({ "beads": { "await_id": "x", "waiters": ["w"] } }));
    let two = env.store.read(|r| r.issue("bd-2")).unwrap();
    assert_eq!(two.metadata["gate"], json!({ "type": "human" }));
    assert_eq!(two.metadata["beads"], json!({ "await_type": "timer", "timeout": 1_000_000_000 }));
    assert_eq!(counts(&s, "await_type"), (0, 1, 0));
    assert_eq!(counts(&s, "await_id"), (0, 1, 0));
}
