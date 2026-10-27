//! The approval packet over real workspaces: what is selected and in which
//! order, what is left out, and every limit.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::config::IdMode;
use crate::gates::{self, GateKind, GateSpec, NewGate};
use crate::issues::CloseOptions;
use crate::model::{DepType, NewIssue};
use crate::store::{InitOptions, OpenOptions, Store, WriteCtx};
use crate::time::ManualClock;

struct Ws {
    _dir: tempfile::TempDir,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Ws {
    fn new() -> Ws {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(Timestamp(1_700_000_000_000)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store =
            Store::init(&dir.path().join("bd.db"), InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts)
                .unwrap();
        Ws { _dir: dir, store, clock }
    }

    fn write<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.clock.advance(Duration::from_secs(60));
        self.store.write("test", "alice", f).unwrap()
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.write(|tx| tx.create_issue(new)).id
    }

    fn task(&mut self, title: &str, parent: Option<&str>) -> String {
        self.create(NewIssue { parent: parent.map(String::from), ..NewIssue::titled(title) })
    }

    fn typed(&mut self, title: &str, issue_type: &str, parent: &str) -> String {
        self.create(NewIssue {
            parent: Some(parent.into()),
            issue_type: Some(issue_type.into()),
            ..NewIssue::titled(title)
        })
    }

    /// A playbook run: an epic with `metadata.playbook.role = "run"`.
    fn run(&mut self, title: &str) -> String {
        self.create(NewIssue {
            issue_type: Some("epic".into()),
            metadata: Some(json!({ "playbook": { "role": "run" } })),
            ..NewIssue::titled(title)
        })
    }

    /// `from` depends on `to`.
    fn dep(&mut self, from: &str, to: &str, dep_type: DepType) {
        let (f, t) = (from.to_string(), to.to_string());
        self.write(|tx| tx.add_dependency(&f, &t, dep_type, None));
    }

    fn gate(&mut self, held: &[&str], parent: Option<&str>, description: &str) -> String {
        let g = NewGate {
            spec: GateSpec::new(GateKind::Human),
            blocks: held.iter().map(|h| h.to_string()).collect(),
            title: None,
            description: description.into(),
            assignee: None,
            parent: parent.map(String::from),
            priority: None,
            ephemeral: false,
        };
        self.write(|tx| tx.create_gate(g)).id
    }

    fn comment(&mut self, id: &str, text: &str) {
        let id = id.to_string();
        self.write(|tx| tx.add_comment(&id, text));
    }

    /// Close `id` as an ordinary close would: refused while it has open
    /// children or live blockers.
    fn close(&mut self, id: &str) {
        let id = id.to_string();
        self.write(|tx| tx.close_issue(&id, &CloseOptions::default()));
    }

    /// Raw SQL, past every check bd makes, to damage a workspace.
    fn sql(&mut self, sql: &str, args: impl rusqlite::Params) {
        self.write(|tx| Ok(tx.conn().execute(sql, args)?));
    }

    fn edge(&mut self, from: &str, to: &str, dep_type: &str) {
        self.sql(
            "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at) VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![from, to, dep_type],
        );
    }

    fn collect_with(&self, gate: &str, limits: &Limits) -> Packet {
        self.store
            .read(|r| {
                let held = gates::view(r.conn(), gate)?.blocks;
                collect_with(r.conn(), gate, &held, limits)
            })
            .unwrap()
    }

    fn collect(&self, gate: &str) -> Packet {
        self.collect_with(gate, &Limits::default())
    }
}

fn order(p: &Packet) -> Vec<(Role, &str, Option<&str>)> {
    p.sources.iter().map(|s| (s.role, s.id.as_str(), s.under.as_deref())).collect()
}

fn source<'p>(p: &'p Packet, id: &str) -> &'p Source {
    p.sources.iter().find(|s| s.id == id).unwrap_or_else(|| panic!("{id} not in {:?}", order(p)))
}

fn has(p: &Packet, id: &str) -> bool {
    p.sources.iter().any(|s| s.id == id)
}

fn full(s: &str) -> Text {
    Text::Full(s.into())
}

fn shown(t: &Text) -> &str {
    match t {
        Text::Full(s) | Text::Truncated { text: s, .. } => s,
        Text::Omitted { .. } => "",
    }
}

fn graph_notes(p: &Packet) -> Vec<&Note> {
    p.notes.iter().filter(|n| matches!(n, Note::RecordLimit { .. } | Note::EdgeLimit { .. })).collect()
}

#[test]
fn a_playbook_gate_shows_its_steps_decisions_and_run() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let req = ws.create(NewIssue {
        parent: Some(run.clone()),
        description: "REQ".into(),
        acceptance_criteria: "ACCEPT".into(),
        ..NewIssue::titled("requirements")
    });
    let decide = ws.create(NewIssue {
        parent: Some(run.clone()),
        design: "DESIGN".into(),
        deps: vec![(DepType::Blocks, req.clone())],
        ..NewIssue::titled("decide")
    });
    let adr = ws.create(NewIssue {
        parent: Some(decide.clone()),
        issue_type: Some("decision".into()),
        design: "ADR".into(),
        ..NewIssue::titled("ADR")
    });
    let bug = ws.typed("A bug", "bug", &decide);
    let outside = ws.task("Outside the run", None);
    ws.dep(&decide, &outside, DepType::Blocks);
    let build = ws.create(NewIssue {
        parent: Some(run.clone()),
        description: "BUILD".into(),
        deps: vec![(DepType::Blocks, decide.clone())],
        ..NewIssue::titled("build")
    });
    let held_adr = ws.typed("Build ADR", "decision", &build);
    let related = ws.task("Related", None);
    ws.dep(&build, &related, DepType::Related);
    let discovered = ws.task("Discovered", None);
    ws.dep(&build, &discovered, DepType::DiscoveredFrom);
    let gate = ws.gate(&[&build], Some(&run), "GATE");
    let gate_adr = ws.typed("Gate ADR", "decision", &gate);
    let run_adr = ws.typed("Run ADR", "decision", &run);
    let later = ws.create(NewIssue {
        parent: Some(run.clone()),
        deps: vec![(DepType::Blocks, build.clone())],
        ..NewIssue::titled("later")
    });
    ws.comment(&run, "SCORE");
    ws.comment(&req, "EVIDENCE");

    let p = ws.collect(&gate);
    assert!(p.playbook);
    assert_eq!(
        order(&p),
        vec![
            (Role::Gate, gate.as_str(), None),
            (Role::Held, build.as_str(), None),
            (Role::Decision, held_adr.as_str(), Some(build.as_str())),
            (Role::Run, run.as_str(), None),
            (Role::Prerequisite, req.as_str(), None),
            (Role::Prerequisite, decide.as_str(), None),
            (Role::Decision, adr.as_str(), Some(decide.as_str())),
        ]
    );
    for excluded in [&later, &related, &discovered, &bug, &gate_adr, &run_adr, &outside] {
        assert!(!has(&p, excluded), "{excluded} is not part of the approval");
    }
    assert!(p.notes.is_empty(), "{:?}", p.notes);

    assert_eq!(source(&p, &gate).fields, vec![Field { kind: FieldKind::Description, text: full("GATE") }]);
    assert_eq!(
        source(&p, &req).fields,
        vec![
            Field { kind: FieldKind::Description, text: full("REQ") },
            Field { kind: FieldKind::AcceptanceCriteria, text: full("ACCEPT") },
        ]
    );
    assert_eq!(source(&p, &adr).fields, vec![Field { kind: FieldKind::Design, text: full("ADR") }]);
    let run_src = source(&p, &run);
    assert_eq!(run_src.title, "Run");
    assert_eq!(run_src.comments.len(), 1);
    assert_eq!((run_src.comments[0].author.as_str(), &run_src.comments[0].text), ("alice", &full("SCORE")));
    assert_eq!(source(&p, &req).comments[0].text, full("EVIDENCE"));
    assert_eq!(source(&p, &gate).status, Status::Open);
}

#[test]
fn a_decision_on_a_scheduling_path_is_still_followed() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let a = ws.task("A", Some(&run));
    let b = ws.task("B", Some(&run));
    let x = ws.task("X", Some(&run));
    let h = ws.task("H", Some(&run));
    assert!(a < b);
    let gate = ws.gate(&[&h], Some(&run), "");
    ws.dep(&gate, &a, DepType::Blocks);
    ws.dep(&gate, &b, DepType::Blocks);
    let d = ws.typed("D", "decision", &a);
    ws.dep(&b, &d, DepType::Blocks);
    ws.dep(&d, &x, DepType::Blocks);
    for id in [&x, &d, &a, &b] {
        ws.close(id);
    }
    assert!(ws.store.read(|r| gates::view(r.conn(), &gate)).unwrap().is_armed());

    let p = ws.collect(&gate);
    assert_eq!(
        order(&p),
        vec![
            (Role::Gate, gate.as_str(), None),
            (Role::Held, h.as_str(), None),
            (Role::Run, run.as_str(), None),
            (Role::Prerequisite, a.as_str(), None),
            (Role::Decision, d.as_str(), Some(a.as_str())),
            (Role::Prerequisite, b.as_str(), None),
            (Role::Prerequisite, x.as_str(), None),
        ]
    );
    assert_eq!(source(&p, &x).status, Status::Closed);
    assert!(graph_notes(&p).is_empty(), "{:?}", p.notes);
}

#[test]
fn a_gate_outside_a_run_shows_its_work_and_parent_only() {
    let mut ws = Ws::new();
    let parent = ws.create(NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled("Plain") });
    let blocker = ws.task("Blocker", Some(&parent));
    let work = ws.create(NewIssue {
        parent: Some(parent.clone()),
        deps: vec![(DepType::Blocks, blocker.clone())],
        ..NewIssue::titled("Work")
    });
    let adr = ws.typed("ADR", "decision", &work);
    let gate = ws.gate(&[&work], Some(&parent), "");
    let p = ws.collect(&gate);
    assert!(!p.playbook);
    assert_eq!(
        order(&p),
        vec![
            (Role::Gate, gate.as_str(), None),
            (Role::Held, work.as_str(), None),
            (Role::Parent, parent.as_str(), None)
        ]
    );
    assert!(!has(&p, &blocker) && !has(&p, &adr));
    assert!(p.notes.is_empty());

    // No parent at all: the gate and its work.
    let lone = ws.task("Lone", None);
    let gate = ws.gate(&[&lone], None, "");
    assert_eq!(order(&ws.collect(&gate)), vec![(Role::Gate, gate.as_str(), None), (Role::Held, lone.as_str(), None)]);
}

#[test]
fn empty_and_blank_fields_are_left_out() {
    let mut ws = Ws::new();
    let work = ws.create(NewIssue {
        description: "  \n\t ".into(),
        acceptance_criteria: String::new(),
        design: "  kept  ".into(),
        notes: "\n".into(),
        ..NewIssue::titled("Work")
    });
    let gate = ws.gate(&[&work], None, "");
    let p = ws.collect(&gate);
    assert!(source(&p, &gate).fields.is_empty());
    assert_eq!(source(&p, &work).fields, vec![Field { kind: FieldKind::Design, text: full("  kept  ") }]);
}

#[test]
fn a_long_field_is_cut_on_a_character_boundary() {
    let mut ws = Ws::new();
    let long = "€".repeat(7000); // 21,000 bytes; 16 KiB falls inside a character
    let work = ws.create(NewIssue { description: long.clone(), ..NewIssue::titled("Work") });
    let gate = ws.gate(&[&work], None, "");
    let p = ws.collect(&gate);
    let Text::Truncated { text, total_bytes } = &source(&p, &work).fields[0].text else {
        panic!("{:?}", source(&p, &work).fields)
    };
    assert_eq!(*total_bytes, 21_000);
    assert_eq!(text.len(), MAX_TEXT_BYTES / 3 * 3);
    assert!(long.starts_with(text.as_str()));
}

#[test]
fn the_source_budget_cuts_and_then_omits_later_text() {
    let mut ws = Ws::new();
    let big = "x".repeat(MAX_TEXT_BYTES);
    let mut held = Vec::new();
    for i in 0..3 {
        held.push(ws.create(NewIssue {
            description: big.clone(),
            acceptance_criteria: big.clone(),
            design: big.clone(),
            notes: big.clone(),
            ..NewIssue::titled(format!("Work {i}"))
        }));
    }
    let refs: Vec<&str> = held.iter().map(String::as_str).collect();
    let gate = ws.gate(&refs, None, "");
    let p = ws.collect(&gate);
    let texts: Vec<&Text> = p.sources.iter().flat_map(|s| s.fields.iter().map(|f| &f.text)).collect();
    assert_eq!(texts.len(), 12);
    let total: usize = texts.iter().map(|t| shown(t).len()).sum();
    assert_eq!(total, MAX_SOURCE_BYTES);
    assert!(texts[..8].iter().all(|t| matches!(t, Text::Full(_))));
    assert!(texts[8..].iter().all(|t| matches!(t, Text::Omitted { total_bytes } if *total_bytes == big.len() as u64)));

    // A smaller budget cuts the field that crosses it.
    let limits = Limits { text_bytes: 64, source_bytes: 100, ..Limits::default() };
    let p = ws.collect_with(&gate, &limits);
    let texts: Vec<&Text> = p.sources.iter().flat_map(|s| s.fields.iter().map(|f| &f.text)).collect();
    assert!(matches!(texts[0], Text::Truncated { text, total_bytes } if text.len() == 64 && *total_bytes == 16384));
    assert!(matches!(texts[1], Text::Truncated { text, .. } if text.len() == 36));
    assert!(texts[2..].iter().all(|t| matches!(t, Text::Omitted { .. })));
}

#[test]
fn only_the_newest_comments_are_shown() {
    let mut ws = Ws::new();
    let work = ws.task("Work", None);
    for i in 0..10 {
        ws.comment(&work, &format!("comment {i}"));
    }
    let long = format!("{}TAIL", "y".repeat(MAX_TEXT_BYTES));
    ws.comment(&work, &long);
    let gate = ws.gate(&[&work], None, "");
    let p = ws.collect(&gate);
    let s = source(&p, &work);
    assert_eq!(s.earlier_comments, 3);
    let texts: Vec<&str> = s.comments.iter().map(|c| shown(&c.text)).collect();
    assert_eq!(texts[..7].to_vec(), (3..10).map(|i| format!("comment {i}")).collect::<Vec<_>>());
    assert!(
        matches!(&s.comments[7].text, Text::Truncated { text, total_bytes } if text.len() == MAX_TEXT_BYTES && *total_bytes == long.len() as u64)
    );
    assert!(s.comments.windows(2).all(|w| w[0].created_at <= w[1].created_at));

    // Ten comments: eight shown, two earlier.
    let other = ws.task("Other", None);
    for i in 0..10 {
        ws.comment(&other, &format!("c{i}"));
    }
    let gate = ws.gate(&[&other], None, "");
    let s = ws.collect(&gate).sources.into_iter().find(|s| s.id == other).unwrap();
    assert_eq!((s.comments.len(), s.earlier_comments), (8, 2));
    assert_eq!(shown(&s.comments[0].text), "c2");
    assert_eq!(shown(&s.comments[7].text), "c9");
}

#[test]
fn at_most_eight_held_issues_are_included() {
    let mut ws = Ws::new();
    let held: Vec<String> = (0..9).map(|i| ws.task(&format!("Work {i}"), None)).collect();
    let refs: Vec<&str> = held.iter().map(String::as_str).collect();
    let gate = ws.gate(&refs, None, "");
    let p = ws.collect(&gate);
    assert_eq!(p.sources.iter().filter(|s| s.role == Role::Held).count(), MAX_HELD);
    assert_eq!(p.notes, vec![Note::HeldLimit { gate: gate.clone(), more: 1 }]);
}

#[test]
fn a_wide_gate_stops_at_the_edge_limit() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let h = ws.task("H", Some(&run));
    let gate = ws.gate(&[&h], Some(&run), "");
    let r = run.clone();
    let g = gate.clone();
    ws.write(move |tx| {
        for i in 0..300 {
            let s = tx.create_issue(NewIssue { parent: Some(r.clone()), ..NewIssue::titled(format!("step {i}")) })?;
            tx.add_dependency(&g, &s.id, DepType::Blocks, None)?;
        }
        Ok(())
    });
    let p = ws.collect(&gate);
    assert_eq!(graph_notes(&p), vec![&Note::EdgeLimit { at: gate.clone(), during: Walk::Prerequisites }]);
    assert!(p.sources.len() <= MAX_RECORDS);
}

#[test]
fn a_long_chain_stops_at_the_record_limit() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let h = ws.task("H", Some(&run));
    let gate = ws.gate(&[&h], Some(&run), "");
    let (r, g) = (run.clone(), gate.clone());
    ws.write(move |tx| {
        let mut prev = g;
        for i in 0..100 {
            let s = tx.create_issue(NewIssue { parent: Some(r.clone()), ..NewIssue::titled(format!("step {i}")) })?;
            tx.add_dependency(&prev, &s.id, DepType::Blocks, None)?;
            prev = s.id;
        }
        Ok(())
    });
    let p = ws.collect(&gate);
    assert_eq!(p.sources.len(), MAX_RECORDS);
    let notes = graph_notes(&p);
    assert!(matches!(notes[..], [Note::RecordLimit { during: Walk::Prerequisites, .. }]), "{notes:?}");
}

#[test]
fn each_walk_names_where_its_limit_stopped_it() {
    let mut ws = Ws::new();
    // The run lookup: a gate three levels below its run.
    let run = ws.run("Run");
    let p1 = ws.task("P1", Some(&run));
    let p2 = ws.task("P2", Some(&p1));
    let work = ws.task("Work", Some(&p2));
    let gate = ws.gate(&[&work], Some(&p2), "");
    let p = ws.collect_with(&gate, &Limits { edges: 2, ..Limits::default() });
    assert_eq!(p.notes, vec![Note::EdgeLimit { at: gate.clone(), during: Walk::Run }]);
    assert!(!p.playbook);
    assert_eq!(order(&p), vec![(Role::Gate, gate.as_str(), None), (Role::Held, work.as_str(), None)]);
    assert!(ws.collect(&gate).playbook);

    // The decision records: a step with many children.
    let run = ws.run("Run 2");
    let h = ws.task("H", Some(&run));
    for i in 0..10 {
        ws.typed(&format!("ADR {i}"), "decision", &h);
    }
    let gate = ws.gate(&[&h], Some(&run), "");
    let p = ws.collect_with(&gate, &Limits { edges: 5, ..Limits::default() });
    assert_eq!(p.notes, vec![Note::EdgeLimit { at: h.clone(), during: Walk::Decisions }]);
    assert!(p.playbook && has(&p, &run));
    assert!(!p.sources.iter().any(|s| s.role == Role::Decision));

    // Too few records for them.
    let p = ws.collect_with(&gate, &Limits { records: 4, ..Limits::default() });
    assert_eq!(p.notes, vec![Note::RecordLimit { at: h.clone(), during: Walk::Decisions }]);
    assert_eq!(p.sources.len(), 4);
    assert_eq!(p.sources.iter().filter(|s| s.role == Role::Decision).count(), 1);
}

#[test]
fn cycles_end_and_diamonds_are_shown_once() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let a = ws.task("A", Some(&run));
    let b = ws.task("B", Some(&run));
    let c = ws.task("C", Some(&run));
    let h = ws.task("H", Some(&run));
    let gate = ws.gate(&[&h], Some(&run), "");
    ws.dep(&gate, &a, DepType::Blocks);
    ws.dep(&gate, &b, DepType::Blocks);
    ws.dep(&a, &c, DepType::Blocks);
    ws.dep(&b, &c, DepType::Blocks);
    let p = ws.collect(&gate);
    assert_eq!(p.sources.iter().filter(|s| s.id == c).count(), 1);

    // A blocks cycle, which bd refuses to write.
    ws.edge(&c, &a, "blocks");
    let p = ws.collect(&gate);
    for id in [&a, &b, &c] {
        assert_eq!(p.sources.iter().filter(|s| &s.id == id).count(), 1, "{id}");
    }
    assert!(graph_notes(&p).is_empty());

    // A parent cycle.
    let p1 = ws.task("P1", None);
    let p2 = ws.task("P2", Some(&p1));
    let work = ws.task("Work", Some(&p2));
    let gate = ws.gate(&[&work], Some(&p2), "");
    ws.edge(&p1, &p2, "parent-child");
    let p = ws.collect(&gate);
    assert!(!p.playbook);
    assert_eq!(
        order(&p),
        vec![(Role::Gate, gate.as_str(), None), (Role::Held, work.as_str(), None), (Role::Parent, p2.as_str(), None)]
    );
}

#[test]
fn a_missing_held_issue_is_unavailable() {
    let mut ws = Ws::new();
    let work = ws.task("Work", None);
    let gate = ws.gate(&[&work], None, "");
    let p = ws
        .store
        .read(|r| {
            let mut held = gates::view(r.conn(), &gate)?.blocks;
            held.push(IssueRef {
                id: "t-gone".into(),
                title: "Gone".into(),
                status: Status::Open,
                priority: 2,
                issue_type: "task".into(),
                assignee: None,
            });
            collect(r.conn(), &gate, &held)
        })
        .unwrap();
    assert_eq!(p.notes, vec![Note::Unavailable { id: "t-gone".into() }]);
    assert_eq!(order(&p), vec![(Role::Gate, gate.as_str(), None), (Role::Held, work.as_str(), None)]);
}

#[test]
fn only_a_run_role_of_exactly_run_makes_a_run() {
    let mut ws = Ws::new();
    let run = ws.run("Run");
    let h = ws.task("H", Some(&run));
    let gate = ws.gate(&[&h], Some(&run), "");
    let huge = format!("run{}", "x".repeat(1 << 20));
    for role in [json!(huge), json!(1), json!({ "x": 1 }), json!(["run"])] {
        let meta = json!({ "playbook": { "role": role } }).to_string();
        ws.sql("UPDATE issues SET metadata = ?1 WHERE id = ?2", rusqlite::params![meta, run]);
        let p = ws.collect(&gate);
        assert!(!p.playbook);
        assert_eq!(source(&p, &run).role, Role::Parent);
    }
    ws.sql(r#"UPDATE issues SET metadata = '{"playbook":{"role":"run"}}' WHERE id = ?1"#, [&run]);
    assert_eq!(source(&ws.collect(&gate), &run).role, Role::Run);

    // A child whose type merely starts like one is not a decision record.
    let odd = ws.typed("Odd", "decision", &h);
    let adr = ws.typed("ADR", "decision", &h);
    ws.sql(
        "UPDATE issues SET issue_type = ?1 WHERE id = ?2",
        rusqlite::params![format!("decision{}", "x".repeat(1 << 20)), odd],
    );
    let p = ws.collect(&gate);
    assert!(!has(&p, &odd));
    assert_eq!(source(&p, &adr).under.as_deref(), Some(h.as_str()));
}

#[test]
fn a_long_id_is_kept_whole() {
    let mut ws = Ws::new();
    let id = format!("t-{}", "a".repeat(253));
    assert_eq!(id.len(), 255);
    ws.create(NewIssue { id: Some(id.clone()), description: "LONG".into(), ..NewIssue::titled("Long") });
    let gate = ws.gate(&[&id], None, "");
    let p = ws.collect(&gate);
    let s = source(&p, &id);
    assert_eq!((s.role, s.id.len()), (Role::Held, 255));
    assert_eq!(s.fields, vec![Field { kind: FieldKind::Description, text: full("LONG") }]);
}

#[test]
fn byte_prefixes_drop_a_cut_character_and_replace_bad_bytes() {
    assert_eq!(utf8_prefix("a€".as_bytes()[..3].to_vec()), "a");
    assert_eq!(utf8_prefix(b"a\xffb".to_vec()), "a\u{fffd}b");
    assert_eq!(utf8_prefix("ok".into()), "ok");
}
