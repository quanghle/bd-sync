//! Playbooks, runs, and gates at the engine level (manual clock).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bd_core::doctor;
use bd_core::gates::{self, GateKind, GatePhase, GateSpec, NewGate, Verdict};
use bd_core::playbook::{
    self, CompactOptions, DiscardOptions, Loader, Plan, Role, RunRequest, StartOptions, StepState,
};
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use serde_json::json;
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

struct Env {
    _dir: TempDir,
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
        Env { _dir: dir, store, clock }
    }

    fn plan(&self, toml: &str, vars: &[(&str, &str)]) -> Plan {
        let pb = playbook::parse_toml(toml, "test.toml", "test").unwrap();
        pb.validate().unwrap();
        let req = RunRequest {
            vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        };
        playbook::compile(&pb, &req, &Loader::default()).unwrap()
    }

    fn start(&mut self, toml: &str, vars: &[(&str, &str)]) -> String {
        let plan = self.plan(toml, vars);
        self.store.write("run", "alice", |tx| tx.start_run(&plan, &StartOptions::default())).unwrap().run.id
    }

    fn issue(&self, id: &str) -> Issue {
        self.store.read(|r| r.issue(id)).unwrap()
    }

    fn ready_ids(&self) -> Vec<String> {
        self.store.read(|r| r.ready(&ReadyQuery::default())).unwrap().into_iter().map(|i| i.id).collect()
    }

    fn close(&mut self, id: &str) -> CloseOutcome {
        self.clock.advance(Duration::from_secs(1));
        self.store.write("close", "alice", |tx| tx.close_issue(id, &CloseOptions::default())).unwrap()
    }

    fn close_failed(&mut self, id: &str) -> CloseOutcome {
        let opts = CloseOptions { outcome: Some(Outcome::Failed), reason: Some("broke".into()), ..Default::default() };
        self.store.write("close", "alice", |tx| tx.close_issue(id, &opts)).unwrap()
    }

    fn gate(&self, id: &str) -> gates::GateView {
        self.store.read(|r| gates::view(r.conn(), id)).unwrap()
    }

    fn evaluate(&self, id: &str) -> Option<Verdict> {
        let g = self.gate(id);
        self.store.read(|r| gates::evaluate_local(r.conn(), &g, r.now())).unwrap()
    }

    fn assert_healthy(&mut self) {
        let report = doctor::diagnose(&mut self.store, false, true).unwrap();
        let bad: Vec<_> = report.checks.iter().filter(|c| c.severity != doctor::Severity::Ok).collect();
        assert!(bad.is_empty(), "doctor found problems: {bad:#?}");
    }
}

const RELEASE: &str = r#"
playbook = "release"
title = "Release {{version}}"

[vars.version]
required = true
pattern = '^\d+\.\d+\.\d+$'

[[steps]]
id = "bump"
title = "Bump version to {{version}}"

[[steps]]
id = "changelog"
needs = ["bump"]

[[steps]]
id = "tag"
title = "Tag v{{version}}"
needs = ["changelog"]
"#;

#[test]
fn a_run_creates_readable_ids_and_completes_itself() {
    let mut env = Env::new();
    let run = env.start(RELEASE, &[("version", "1.2.0")]);
    assert_eq!(run, "t-1");
    let root = env.issue(&run);
    assert_eq!((root.title.as_str(), root.issue_type.as_str()), ("Release 1.2.0", "epic"));
    assert_eq!(root.metadata["playbook"]["vars"]["version"], "1.2.0");
    assert_eq!(env.issue("t-1.tag").title, "Tag v1.2.0");
    assert_eq!(env.ready_ids(), vec!["t-1.bump"], "the run itself is a container, never ready");

    env.close("t-1.bump");
    assert_eq!(env.ready_ids(), vec!["t-1.changelog"]);
    env.close("t-1.changelog");
    let last = env.close("t-1.tag");
    assert_eq!(last.completed.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["t-1"]);
    let root = env.issue(&run);
    assert_eq!((root.status, root.close_outcome), (Status::Closed, Some(Outcome::Done)));

    let status = env.store.read(|r| playbook::run_status(r.conn(), &run, r.now())).unwrap();
    assert_eq!((status.progress.total, status.progress.done), (3, 3));
    assert_eq!(status.playbook.as_deref(), Some("release"));
    let ops: Vec<String> = env.store.read(|r| r.history(&run)).unwrap().into_iter().map(|e| e.op).collect();
    assert!(ops.contains(&"run_started".to_string()) && ops.contains(&"closed".to_string()), "{ops:?}");
    env.assert_healthy();
}

#[test]
fn a_failed_step_fails_the_run_and_reopening_reopens_it() {
    let mut env = Env::new();
    let run = env.start("[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n", &[]);
    env.close_failed("t-1.a");
    let done = env.close("t-1.b");
    assert_eq!(done.completed.len(), 1);
    assert_eq!(env.issue(&run).close_outcome, Some(Outcome::Failed));

    let r = env.store.write("reopen", "alice", |tx| tx.reopen_issue("t-1.a", Some("retry"))).unwrap();
    assert_eq!(r.reopened.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec!["t-1"]);
    assert_eq!(env.issue(&run).status, Status::Open);
    env.close("t-1.a");
    assert_eq!(env.issue(&run).close_outcome, Some(Outcome::Done));
    env.assert_healthy();
}

const GATED: &str = r#"
[[steps]]
id = "build"

[[steps]]
id = "deploy"
needs = ["build"]
[steps.gate]
type = "human"
timeout = "4h"

[[steps]]
id = "cleanup"
needs = ["deploy"]
[steps.gate]
type = "timer"
timeout = "1h"
"#;

#[test]
fn gates_arm_when_their_step_could_start() {
    let mut env = Env::new();
    let run = env.start(GATED, &[]);
    assert_eq!(env.ready_ids(), vec!["t-1.build"], "gates are never ready work");
    let err = env.store.write("claim", "bob", |tx| tx.claim("t-1.gate-deploy", &ClaimOptions::default())).unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err}");

    let human = env.gate("t-1.gate-deploy");
    assert_eq!(human.phase, GatePhase::Waiting);
    assert!(human.armed_at.is_none());
    assert_eq!(human.blocks.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(), vec!["t-1.deploy"]);

    env.clock.advance(Duration::from_secs(3 * 3600));
    env.close("t-1.build");
    let armed_at = env.store.now();
    let human = env.gate("t-1.gate-deploy");
    assert_eq!((human.phase, human.armed_at), (GatePhase::Armed, Some(armed_at)));
    assert!(env.ready_ids().is_empty(), "deploy waits for its approval");
    assert!(matches!(env.evaluate("t-1.gate-deploy"), Some(Verdict::Pending(_))));

    // The 4h timeout counts from arming, not from when the run started.
    env.clock.advance(Duration::from_secs(3600));
    assert!(gates::overdue(&env.gate("t-1.gate-deploy"), env.store.now()).is_none());
    env.clock.advance(Duration::from_secs(4 * 3600));
    let reason = gates::overdue(&env.gate("t-1.gate-deploy"), env.store.now()).unwrap();
    assert!(reason.contains("still shut 4h after arming"), "{reason}");
    env.clock.advance(Duration::from_secs(600));
    let later = gates::overdue(&env.gate("t-1.gate-deploy"), env.store.now()).unwrap();
    assert_eq!(later, reason, "the reason is stable, so re-checks escalate once");
    assert!(env.store.write("esc", "bd", |tx| tx.escalate_gate("t-1.gate-deploy", &reason)).unwrap());
    assert!(!env.store.write("esc", "bd", |tx| tx.escalate_gate("t-1.gate-deploy", &reason)).unwrap(), "idempotent");
    assert_eq!(env.gate("t-1.gate-deploy").phase, GatePhase::Escalated);
    assert_eq!(env.store.read(|r| r.comments("t-1.gate-deploy")).unwrap().len(), 1);

    env.store.write("resolve", "carol", |tx| tx.resolve_gate("t-1.gate-deploy", Some("approved"), false)).unwrap();
    assert_eq!(env.ready_ids(), vec!["t-1.deploy"]);

    // The timer in front of cleanup starts only when deploy closes.
    env.clock.advance(Duration::from_secs(10 * 3600));
    assert_eq!(env.gate("t-1.gate-cleanup").phase, GatePhase::Waiting);
    env.close("t-1.deploy");
    env.clock.advance(Duration::from_secs(1800));
    assert!(matches!(env.evaluate("t-1.gate-cleanup"), Some(Verdict::Pending(d)) if d.contains("opens in 30m")));
    env.clock.advance(Duration::from_secs(1800));
    assert!(matches!(env.evaluate("t-1.gate-cleanup"), Some(Verdict::Resolve(_))));
    env.store.write("resolve", "bd", |tx| tx.resolve_gate("t-1.gate-cleanup", None, false)).unwrap();
    let closed = env.close("t-1.cleanup");
    assert_eq!(closed.completed.len(), 1, "run completes once gates and steps are closed");
    assert_eq!(env.issue(&run).status, Status::Closed);
    env.assert_healthy();
}

#[test]
fn ad_hoc_gates_inherit_prerequisites_and_issue_gates_honor_failure() {
    let mut env = Env::new();
    let prereq = env.store.write("c", "a", |tx| tx.create_issue(NewIssue::titled("Prereq"))).unwrap().id;
    let work = env
        .store
        .write("c", "a", |tx| {
            tx.create_issue(NewIssue { deps: vec![(DepType::Blocks, prereq.clone())], ..NewIssue::titled("Work") })
        })
        .unwrap()
        .id;
    let other = env.store.write("c", "a", |tx| tx.create_issue(NewIssue::titled("Upstream"))).unwrap().id;
    let mut spec = GateSpec::new(GateKind::Issue);
    spec.await_id = Some(other.clone());
    let gate = env
        .store
        .write("g", "a", |tx| {
            tx.create_gate(NewGate {
                spec,
                blocks: vec![work.clone()],
                title: None,
                description: String::new(),
                assignee: None,
                parent: None,
                priority: None,
                ephemeral: false,
            })
        })
        .unwrap();
    assert_eq!(gate.issue_type, "gate");
    assert_eq!(gate.title, format!("Wait for {other}: Work"));
    assert_eq!(env.gate(&gate.id).phase, GatePhase::Waiting, "copied the prerequisite of the work it holds");
    env.close(&prereq);
    assert_eq!(env.gate(&gate.id).phase, GatePhase::Armed);
    assert!(matches!(env.evaluate(&gate.id), Some(Verdict::Pending(_))));
    env.close_failed(&other);
    assert!(matches!(env.evaluate(&gate.id), Some(Verdict::Escalate(d)) if d.contains("failed")));
    env.store.write("reopen", "a", |tx| tx.reopen_issue(&other, None)).unwrap();
    env.close(&other);
    assert!(matches!(env.evaluate(&gate.id), Some(Verdict::Resolve(_))));
    env.assert_healthy();
}

#[test]
fn spawners_close_before_their_children_and_fan_in_waits() {
    let mut env = Env::new();
    let run = env.start(
        "[[steps]]\nid = \"spawn\"\n[[steps]]\nid = \"collect\"\nneeds = [\"spawn\"]\nwaits_for = \"all-children\"\n",
        &[],
    );
    env.store.write("claim", "agent", |tx| tx.claim("t-1.spawn", &ClaimOptions::default())).unwrap();
    for part in ["one", "two"] {
        env.store
            .write("c", "agent", |tx| {
                tx.create_issue(NewIssue { parent: Some("t-1.spawn".into()), ..NewIssue::titled(part) })
            })
            .unwrap();
    }
    env.store.write("close", "agent", |tx| tx.close_issue("t-1.spawn", &CloseOptions::default())).unwrap();
    assert!(env.issue("t-1.collect").is_blocked, "waits for the spawned children");
    assert_eq!(env.ready_ids(), vec!["t-1.spawn.1", "t-1.spawn.2"]);
    env.close("t-1.spawn.1");
    env.close("t-1.spawn.2");
    assert_eq!(env.ready_ids(), vec!["t-1.collect"]);
    assert_eq!(env.close("t-1.collect").completed.len(), 1);
    assert_eq!(env.issue(&run).status, Status::Closed);

    // Plain parents still refuse to close over open children.
    let p = env.store.write("c", "a", |tx| tx.create_issue(NewIssue::titled("P"))).unwrap().id;
    env.store
        .write("c", "a", |tx| tx.create_issue(NewIssue { parent: Some(p.clone()), ..NewIssue::titled("C") }))
        .unwrap();
    let err = env.store.write("close", "a", |tx| tx.close_issue(&p, &CloseOptions::default())).unwrap_err();
    assert!(matches!(err, Error::Refused(_)));
    env.assert_healthy();
}

#[test]
fn groups_close_when_their_steps_do() {
    let mut env = Env::new();
    env.start(
        "[[steps]]\nid = \"tests\"\n[[steps.children]]\nid = \"unit\"\n[[steps.children]]\nid = \"e2e\"\n\
         [[steps]]\nid = \"ship\"\nneeds = [\"tests\"]\n",
        &[],
    );
    assert_eq!(env.ready_ids(), vec!["t-1.tests.e2e", "t-1.tests.unit"]);
    env.close("t-1.tests.unit");
    let out = env.close("t-1.tests.e2e");
    assert_eq!(out.completed.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["t-1.tests"]);
    assert_eq!(out.unblocked.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["t-1.ship"]);
    let status = env.store.read(|r| playbook::run_status(r.conn(), "t-1", r.now())).unwrap();
    let states: Vec<(String, StepState)> = status.nodes.iter().map(|n| (n.id.clone(), n.state)).collect();
    assert_eq!(
        states,
        vec![
            ("t-1.tests".into(), StepState::Done),
            ("t-1.tests.unit".into(), StepState::Done),
            ("t-1.tests.e2e".into(), StepState::Done),
            ("t-1.ship".into(), StepState::Ready),
        ]
    );
    env.assert_healthy();
}

#[test]
fn ephemeral_runs_stay_out_of_exports_and_purge_whole() {
    let mut env = Env::new();
    let keep = env.store.write("c", "a", |tx| tx.create_issue(NewIssue::titled("Keep me"))).unwrap().id;
    let plan = {
        let pb = playbook::parse_toml("ephemeral = true\n[[steps]]\nid = \"check\"\n", "t.toml", "patrol").unwrap();
        playbook::compile(&pb, &RunRequest::default(), &Loader::default()).unwrap()
    };
    assert!(plan.ephemeral);
    let run = env.store.write("run", "a", |tx| tx.start_run(&plan, &StartOptions::default())).unwrap().run.id;
    assert!(env.issue(&run).ephemeral && env.issue(&format!("{run}.check")).ephemeral);
    env.store
        .write("dep", "a", |tx| tx.add_dependency(&keep, &format!("{run}.check"), DepType::Related, None))
        .unwrap();

    let mut buf = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut buf, &ExportOptions::default())).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains("Keep me") && !text.contains("patrol"), "{text}");
    assert!(!text.contains(".check"), "edges into ephemeral issues are left out too");

    let open = env.store.write("purge", "a", |tx| tx.purge_ephemeral(None, false)).unwrap();
    assert!(open.deleted.is_empty(), "open runs are never purged");
    env.close(&format!("{run}.check"));
    assert_eq!(env.issue(&run).status, Status::Closed);
    let too_new =
        env.store.write("purge", "a", |tx| tx.purge_ephemeral(Some(Duration::from_secs(3600)), false)).unwrap();
    assert!(too_new.deleted.is_empty());
    let purged = env.store.write("purge", "a", |tx| tx.purge_ephemeral(None, false)).unwrap();
    assert_eq!(purged.deleted, vec![run.clone(), format!("{run}.check")]);
    assert_eq!(purged.detached, vec![keep.clone()]);
    assert!(env.store.read(|r| r.find_issue(&run)).unwrap().is_none());
    let ops: Vec<String> = env
        .store
        .read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() }))
        .unwrap()
        .events
        .into_iter()
        .map(|e| e.op)
        .collect();
    assert!(ops.contains(&"purged".to_string()) && !ops.contains(&"deleted".to_string()), "one summary event");
    env.assert_healthy();
}

/// Which closed ephemeral issues a purge deletes: a candidate (closed past
/// the cutoff) goes when everything below it is a candidate too and every
/// ephemeral issue above it is one (persistent ancestors, open or not, never
/// hold it), even if a candidate ancestor itself has to stay.
#[test]
fn purge_deletes_candidates_whose_subtree_and_ephemeral_ancestors_are_candidates() {
    let mut env = Env::new();
    let mut make = |title: &str, parent: Option<&str>, ephemeral: bool| -> String {
        let new = NewIssue { parent: parent.map(String::from), ephemeral, ..NewIssue::titled(title) };
        env.store.write("c", "alice", |tx| tx.create_issue(new)).unwrap().id
    };
    // A whole closed ephemeral tree.
    let a = make("a", None, true);
    let a1 = make("a1", Some(&a), true);
    let a2 = make("a2", Some(&a1), true);
    let a1b = make("a1b", Some(&a), true);
    // A closed ephemeral run whose last step closed too recently.
    let b = make("b", None, true);
    let b1 = make("b1", Some(&b), true);
    let b2 = make("b2", Some(&b), true);
    // A persistent child holds its ephemeral parent but neither its ephemeral
    // child nor its ephemeral sibling.
    let c = make("c", None, true);
    let c1 = make("c1", Some(&c), false);
    let c1x = make("c1x", Some(&c1), true);
    let c2 = make("c2", Some(&c), true);
    // Under an open persistent parent.
    let d = make("d", None, false);
    let d1 = make("d1", Some(&d), true);
    let d1a = make("d1a", Some(&d1), true);
    // Under an open ephemeral parent, even across a persistent one.
    let e = make("e", None, true);
    let e1 = make("e1", Some(&e), true);
    let f1 = make("f1", Some(&e), false);
    let f2 = make("f2", Some(&f1), true);
    // Survivors with edges into the purge, and a spawner losing a closed child.
    let keep = make("keep", None, false);
    let cond = make("cond", None, false);
    let spawner = make("spawner", None, false);
    let spawned = make("spawned", Some(&spawner), true);
    let live = make("live", Some(&spawner), false);
    let waiter = make("waiter", None, false);
    env.store
        .write("dep", "alice", |tx| {
            tx.add_dependency(&keep, &a2, DepType::Blocks, None)?;
            tx.add_dependency(&a, &keep, DepType::Related, None)?;
            tx.add_dependency(&waiter, &spawner, DepType::WaitsFor, Some(json!({ "gate": "any-children" })))
        })
        .unwrap();
    for id in [&a2, &a1, &a1b, &a, &b1, &c1x, &c1, &c2, &c, &d1a, &d1, &e1, &f2, &f1, &spawned] {
        env.close(id);
    }
    env.store.write("dep", "alice", |tx| tx.add_dependency(&cond, &a2, DepType::ConditionalBlocks, None)).unwrap();
    assert!(env.issue(&cond).is_blocked && !env.issue(&waiter).is_blocked && env.issue(&live).status == Status::Open);
    env.clock.advance(Duration::from_secs(3600));
    env.close(&b2);
    env.close(&b);

    let mut expected = vec![a.clone(), a1.clone(), a2.clone(), a1b.clone(), c1x, c2, d1, d1a, spawned];
    expected.sort();
    let older = Some(Duration::from_secs(1800));
    let head = env.store.read(|r| r.events(&EventQuery::default())).unwrap().events.last().unwrap().seq;
    let dry = env.store.write("purge", "alice", |tx| tx.purge_ephemeral(older, true)).unwrap();
    assert_eq!((dry.deleted.clone(), dry.dry_run), (expected.clone(), true));
    assert!(dry.detached.is_empty() && env.store.read(|r| r.find_issue(&a)).unwrap().is_some());

    let out = env.store.write("purge", "alice", |tx| tx.purge_ephemeral(older, false)).unwrap();
    assert_eq!(out.deleted, expected);
    assert_eq!(out.detached, {
        let mut v = vec![keep.clone(), cond.clone()];
        v.sort();
        v
    });
    for id in &expected {
        assert!(env.store.read(|r| r.find_issue(id)).unwrap().is_none(), "{id} purged");
    }
    for id in [&b, &b1, &b2, &c, &c1, &d, &e, &e1, &f1, &f2, &keep, &cond, &spawner, &live, &waiter] {
        assert!(env.store.read(|r| r.find_issue(id)).unwrap().is_some(), "{id} kept");
    }
    assert!(!env.issue(&cond).is_blocked, "its conditional blocker is gone");
    assert!(env.issue(&waiter).is_blocked, "the spawner's only closed child is gone");

    let events = env.store.read(|r| r.events(&EventQuery { since: Some(head), ..Default::default() })).unwrap().events;
    let ops: Vec<(&str, Option<&str>)> = events.iter().map(|e| (e.op.as_str(), e.issue_id.as_deref())).collect();
    assert_eq!(ops, vec![("purged", None), ("unblocked", Some(cond.as_str())), ("blocked", Some(waiter.as_str()))]);
    let cutoff = env.store.read(|r| Ok(r.now())).unwrap().minus(Duration::from_secs(1800));
    assert_eq!(
        events[0].data,
        json!({ "cutoff": cutoff, "ids": expected, "count": expected.len(), "detached": out.detached })
    );
    env.assert_healthy();

    let again = env.store.write("purge", "alice", |tx| tx.purge_ephemeral(None, false)).unwrap();
    let mut rest = vec![b, b1, b2];
    rest.sort();
    assert_eq!(again.deleted, rest, "the run goes once its last step is old enough");
    env.assert_healthy();
}

/// What a purge deletes, decided per candidate from its whole subtree and its
/// chain of ancestors (the definition the engine computes in one pass).
fn purge_by_definition(conn: &rusqlite::Connection, cutoff: Timestamp) -> Vec<String> {
    let query = |sql: &str, arg: &dyn rusqlite::ToSql| -> Vec<String> {
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([arg], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
    };
    let candidates: BTreeSet<String> =
        query("SELECT id FROM issues WHERE ephemeral = 1 AND status = 'closed' AND closed_at <= ?1", &cutoff)
            .into_iter()
            .collect();
    let mut out = Vec::new();
    for id in &candidates {
        let below = query(
            "WITH RECURSIVE sub(id) AS (
                 SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child'
                 UNION SELECT d.issue_id FROM sub s JOIN dependencies d ON d.depends_on_id = s.id
                 WHERE d.dep_type = 'parent-child')
             SELECT id FROM sub",
            id,
        );
        let mut above = Vec::new();
        let mut cur = id.clone();
        while let Some(p) = query(
            "SELECT depends_on_id FROM dependencies WHERE issue_id = ?1 AND dep_type = 'parent-child'
             ORDER BY depends_on_id LIMIT 1",
            &cur,
        )
        .pop()
        {
            if above.contains(&p) {
                break;
            }
            above.push(p.clone());
            cur = p;
        }
        let ephemeral = |x: &String| query("SELECT id FROM issues WHERE id = ?1 AND ephemeral = 1", x).len() == 1;
        if below.iter().all(|d| candidates.contains(d)) && above.iter().all(|a| candidates.contains(a) || !ephemeral(a))
        {
            out.push(id.clone());
        }
    }
    out
}

#[test]
fn purge_matches_its_definition_on_random_forests() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut roll = |n: u64| -> u64 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % n
    };
    for round in 0..12 {
        let mut env = Env::new();
        let n = 60;
        let mut ids: Vec<String> = Vec::new();
        let mut parent: Vec<Option<usize>> = Vec::new();
        for i in 0..n {
            let p = if i == 0 || roll(4) == 0 { None } else { Some(roll(i as u64) as usize) };
            let new = NewIssue {
                parent: p.map(|p| ids[p].clone()),
                ephemeral: roll(5) != 0,
                ..NewIssue::titled(format!("n{i}"))
            };
            ids.push(env.store.write("c", "alice", |tx| tx.create_issue(new)).unwrap().id);
            parent.push(p);
        }
        // 0 open, 1 closed recently, 2 closed long ago; a parent closes after its children.
        let mut state = vec![0u8; n];
        for i in (0..n).rev() {
            let floor = (0..n).filter(|&c| parent[c] == Some(i)).map(|c| state[c]).min().unwrap_or(2);
            state[i] = roll(u64::from(floor) + 2).min(u64::from(floor)) as u8;
        }
        for phase in [2, 1] {
            for i in (0..n).rev().filter(|&i| state[i] == phase) {
                env.close(&ids[i]);
            }
            env.clock.advance(Duration::from_secs(3600));
        }
        if round % 3 == 2 {
            // Hand-made hierarchies: extra parents and cycles.
            env.store
                .write("sql", "alice", |tx| {
                    for _ in 0..6 {
                        let (a, b) = (roll(n as u64) as usize, roll(n as u64) as usize);
                        tx.conn().execute(
                            "INSERT OR IGNORE INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
                             SELECT ?1, ?2, 'parent-child', 0 WHERE ?1 <> ?2",
                            [&ids[a], &ids[b]],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
        }
        let older = Duration::from_secs(5400);
        let cutoff = env.store.read(|r| Ok(r.now())).unwrap().minus(older);
        let expected = env.store.read(|r| Ok(purge_by_definition(r.conn(), cutoff))).unwrap();
        let got = env.store.write("purge", "alice", |tx| tx.purge_ephemeral(Some(older), true)).unwrap().deleted;
        assert_eq!(got, expected, "round {round}");
        let all = env.store.read(|r| Ok(purge_by_definition(r.conn(), r.now()))).unwrap();
        let got = env.store.write("purge", "alice", |tx| tx.purge_ephemeral(None, true)).unwrap().deleted;
        assert_eq!(got, all, "round {round}");
        assert!(!all.is_empty() && all.len() < n, "round {round}: a forest with something to keep and to purge");
    }
}

#[test]
fn compact_folds_a_finished_run_and_discard_removes_one() {
    let mut env = Env::new();
    let run = env.start(GATED, &[]);
    let err = env.store.write("compact", "a", |tx| tx.compact_run(&run, &CompactOptions::default())).unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err}");
    env.close("t-1.build");
    env.store.write("resolve", "a", |tx| tx.resolve_gate("t-1.gate-deploy", Some("ok by carol"), false)).unwrap();
    env.close_failed("t-1.deploy");
    env.store.write("resolve", "a", |tx| tx.resolve_gate("t-1.gate-cleanup", None, true)).unwrap();
    env.close("t-1.cleanup");
    assert_eq!(env.issue(&run).close_outcome, Some(Outcome::Failed));

    let opts = CompactOptions { summary: Some("Shipped with a failed deploy.".into()), ..Default::default() };
    let out = env.store.write("compact", "a", |tx| tx.compact_run(&run, &opts)).unwrap();
    assert_eq!(out.removed.len(), 5);
    let root = env.issue(&run);
    assert!(root.notes.contains("Shipped with a failed deploy.") && root.notes.contains("✗ deploy"), "{}", root.notes);
    assert!(root.notes.contains("ok by carol"));
    assert!(env.store.read(|r| r.children(&run)).unwrap().is_empty());
    assert!(root.metadata["playbook"]["compacted"]["issues"] == 5);

    let other = env.start(RELEASE, &[("version", "2.0.0")]);
    env.store.write("claim", "bob", |tx| tx.claim(&format!("{other}.bump"), &ClaimOptions::default())).unwrap();
    let opts = |force: bool, take_over: bool| DiscardOptions { force, take_over, dry_run: false };
    for o in [opts(false, false), opts(true, false)] {
        let err = env.store.write("discard", "a", |tx| tx.discard_run(&other, &o)).unwrap_err();
        assert!(err.to_string().contains("held by bob"), "{err}");
    }
    let gone = env.store.write("discard", "a", |tx| tx.discard_run(&other, &opts(false, true))).unwrap();
    assert_eq!(gone.deleted.len(), 4);
    let err = env.store.write("discard", "a", |tx| tx.discard_run("t-1.cleanup", &opts(false, false)));
    assert!(err.is_err(), "only runs can be discarded");
    let compacted = env.store.write("discard", "a", |tx| tx.discard_run(&run, &opts(false, false))).unwrap();
    assert_eq!(compacted.deleted, vec![run.clone()]);
    env.assert_healthy();
}

#[test]
fn extract_round_trips_a_run() {
    let mut env = Env::new();
    let toml = "[[steps]]\nid = \"spawn\"\n\
        [[steps]]\nid = \"tests\"\nneeds = [\"spawn\"]\n[[steps.children]]\nid = \"unit\"\npriority = 1\n\
        [[steps]]\nid = \"collect\"\nneeds = [\"tests\", \"spawn\"]\nwaits_for = \"children-of(spawn)\"\n[steps.gate]\ntype = \"human\"\n";
    let run = env.start(toml, &[]);
    let pb = env.store.read(|r| playbook::extract(r.conn(), &run, Some("again"))).unwrap();
    let text = playbook::to_toml(&pb).unwrap();
    let again = playbook::parse_toml(&text, "x.toml", "again").unwrap();
    again.validate().unwrap();
    let a = env.plan(toml, &[]);
    let b = playbook::compile(&again, &RunRequest::default(), &Loader::default()).unwrap();
    let shape = |p: &Plan| {
        let mut keys: Vec<String> = p.issues.iter().map(|i| format!("{}:{:?}", i.key, i.role)).collect();
        let mut edges: Vec<String> = p.edges.iter().map(|e| format!("{}->{}:{}", e.from, e.to, e.dep_type)).collect();
        keys.sort();
        edges.sort();
        (keys, edges)
    };
    assert_eq!(shape(&a), shape(&b), "{text}");
    assert_eq!(b.issues.iter().find(|i| i.key == "tests.unit").unwrap().priority, 1);
    assert!(b.issues.iter().any(|i| i.role == Role::Gate));
}

#[test]
fn extends_and_expand_compose_playbooks_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| std::fs::write(dir.path().join(name), text).unwrap();
    write(
        "base.toml",
        "description = \"Base\"\n[vars.target]\ndefault = \"staging\"\n[[steps]]\nid = \"build\"\n[[steps]]\nid = \"deploy\"\ntitle = \"Deploy to {{target}}\"\nneeds = [\"build\"]\n",
    );
    write(
        "checks.formula.toml",
        "[vars.suite]\nrequired = true\n[[steps]]\nid = \"lint\"\n[[steps]]\nid = \"test\"\ntitle = \"Test {{suite}}\"\nneeds = [\"lint\"]\n",
    );
    write(
        "service.toml",
        "extends = \"base\"\n[vars.target]\ndefault = \"prod\"\n\
         [[steps]]\nid = \"verify\"\nneeds = [\"build\"]\nexpand = \"checks\"\nexpand_vars = { suite = \"{{target}}-smoke\" }\n\
         [[steps]]\nid = \"deploy\"\ntitle = \"Ship to {{target}}\"\nneeds = [\"verify\"]\n",
    );
    let loader = Loader::new(vec![PathBuf::from(dir.path())]);
    let pb = loader.load("service").unwrap();
    assert_eq!(pb.description, "Base");
    assert_eq!(pb.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), vec!["build", "deploy", "verify"]);
    let plan = playbook::compile(&pb, &RunRequest::default(), &loader).unwrap();
    let keys: Vec<&str> = plan.issues.iter().map(|i| i.key.as_str()).collect();
    assert_eq!(keys, vec!["build", "deploy", "verify", "verify.lint", "verify.test"]);
    assert_eq!(plan.issues[1].title, "Ship to prod");
    assert_eq!(plan.issues[4].title, "Test prod-smoke");
    let listed = loader.list();
    assert_eq!(listed.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), vec!["base", "checks", "service"]);
    assert!(listed.iter().all(|l| l.error.is_none()), "{listed:?}");

    write("loop-a.toml", "extends = \"loop-b\"\n[[steps]]\nid = \"x\"\n");
    write("loop-b.toml", "extends = \"loop-a\"\n[[steps]]\nid = \"y\"\n");
    assert!(loader.load("loop-a").unwrap_err().to_string().contains("circular extends"));
    write("self.toml", "[[steps]]\nid = \"x\"\nexpand = \"self\"\n");
    let pb = loader.load("self").unwrap();
    let err = playbook::compile(&pb, &RunRequest::default(), &loader).unwrap_err();
    assert!(err.to_string().contains("circular expand"), "{err}");
}

#[test]
fn import_maps_beads_workflow_fields() {
    let mut env = Env::new();
    let jsonl = [
        json!({"_type": "issue", "id": "t-50", "title": "Proto", "status": "open", "issue_type": "epic", "is_template": true}),
        json!({"_type": "issue", "id": "t-51", "title": "Wisp", "status": "open", "issue_type": "task", "ephemeral": true}),
        json!({"_type": "issue", "id": "t-52", "title": "Gate: gh:pr 42", "status": "open", "issue_type": "gate",
               "await_type": "gh:pr", "await_id": "42", "timeout": 1_800_000_000_000i64, "waiters": ["mayor"]}),
        json!({"_type": "issue", "id": "t-53", "title": "Merge", "status": "open", "issue_type": "task",
               "dependencies": [{"depends_on_id": "t-52", "type": "blocks"}]}),
    ]
    .iter()
    .map(|v| v.to_string())
    .collect::<Vec<_>>()
    .join("\n");
    let summary =
        env.store.write("import", "a", |tx| tx.import_jsonl(&mut jsonl.as_bytes(), &ImportOptions::default())).unwrap();
    assert_eq!((summary.created, summary.skipped), (3, 1));
    assert!(summary.warnings.iter().any(|w| w.contains("template")), "{:?}", summary.warnings);
    assert!(env.issue("t-51").ephemeral);
    let gate = env.gate("t-52");
    let spec = gate.spec.clone().unwrap();
    assert_eq!(
        (spec.kind, spec.await_id.as_deref(), spec.timeout.as_deref()),
        (GateKind::GhPr, Some("42"), Some("30m"))
    );
    assert_eq!(gate.phase, GatePhase::Armed, "imported open gates are armed from their creation time");
    assert!(env.ready_ids() == vec!["t-51"], "the gate holds t-53 and is not ready itself");
    env.assert_healthy();
}

/// Adds `levels` closed issues `{prefix}1..` below `root`, each the only child
/// of the one before (`bd update --parent` chains issues without a limit).
/// Plain SQL: checking each new edge would take quadratic time.
fn chain_below(env: &mut Env, root: &str, prefix: &str, levels: usize) {
    let issues = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO issues (id, title, status, created_at, updated_at, closed_at, close_reason)
        SELECT ?3 || k, 'Level ' || k, 'closed', ?2 + k, ?2 + k, ?2 + k, 'done' FROM n";
    let edges = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        SELECT ?3 || k, CASE k WHEN 1 THEN ?4 ELSE ?3 || (k - 1) END, 'parent-child', ?2 FROM n";
    env.store
        .write("chain", "alice", |tx| {
            tx.conn().execute(issues, (levels as i64, T0, prefix))?;
            tx.conn().execute(edges, (levels as i64, T0, prefix, root))?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn deep_hierarchies_fit_a_server_threads_stack() {
    const LEVELS: usize = 100_000;
    let mut env = Env::new();
    let mut root =
        |title: &str| env.store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled(title))).unwrap().id;
    let (deep, long) = (root("Deep"), root("Long"));
    chain_below(&mut env, &deep, "d", LEVELS);
    chain_below(&mut env, &long, "l", playbook::MAX_RUN_ISSUES);
    // bd serve runs commands on blocking threads with a 2 MiB stack.
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            let status = env.store.read(|r| playbook::run_status(r.conn(), &deep, r.now())).unwrap();
            assert_eq!(status.nodes.len(), LEVELS);
            assert!(status.nodes.iter().enumerate().all(|(i, n)| n.depth == i + 1 && n.id == format!("d{}", i + 1)));
            assert_eq!(status.progress.done, LEVELS);

            let tree = env.store.read(|r| r.dep_tree(&deep, Direction::Up, usize::MAX)).unwrap();
            assert_eq!(tree.len(), LEVELS + 1);
            assert_eq!((tree[LEVELS].depth, tree[LEVELS].id.as_str()), (LEVELS, format!("d{LEVELS}").as_str()));

            let extract = |root: &str| env.store.read(|r| playbook::extract(r.conn(), root, Some("deep")));
            let err = extract(&deep).unwrap_err().to_string();
            assert_eq!(err, format!("playbook deep: has {LEVELS} steps (at most {})", playbook::MAX_RUN_ISSUES));
            let err = extract(&long).unwrap_err().to_string();
            let first_too_deep = playbook::MAX_DEPTH + 1;
            assert_eq!(
                err,
                format!(
                    "playbook deep: step level-{first_too_deep} is nested more than {} levels deep",
                    playbook::MAX_DEPTH
                )
            );
            // As deep as a playbook may nest.
            let top = playbook::MAX_RUN_ISSUES - playbook::MAX_DEPTH;
            let pb = extract(&format!("l{top}")).unwrap();
            assert_eq!(pb.all_steps().len(), playbook::MAX_DEPTH);
            assert_eq!(pb.all_steps().last().unwrap().id, format!("level-{}", playbook::MAX_RUN_ISSUES));
            let again = playbook::parse_toml(&playbook::to_toml(&pb).unwrap(), "deep.toml", "deep").unwrap();
            again.validate().unwrap();
            assert_eq!(again.all_steps().len(), playbook::MAX_DEPTH);
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A run `{prefix}0` with `levels` open groups `{prefix}1..` below it, each
/// the only child of the one before, and an open step below the last one.
/// Plain SQL, as in [`chain_below`], then table statistics (`ANALYZE`, which
/// bd never runs but a workspace may have run anyway), which change query
/// plans. Returns the step.
fn group_chain(env: &mut Env, prefix: &str, levels: usize) -> String {
    let issues = "WITH RECURSIVE n(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO issues (id, title, issue_type, metadata, created_at, updated_at)
        SELECT ?3 || k, 'Level ' || k, 'epic',
               json_object('playbook', json_object('role', CASE k WHEN 0 THEN 'run' ELSE 'group' END)),
               ?2 + k, ?2 + k
        FROM n";
    let edges = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        SELECT ?3 || k, ?3 || (k - 1), 'parent-child', ?2 FROM n";
    env.store
        .write("chain", "alice", |tx| {
            tx.conn().execute(issues, (levels as i64, T0, prefix))?;
            tx.conn().execute(edges, (levels as i64, T0, prefix))?;
            tx.conn().execute_batch("ANALYZE")?;
            tx.create_issue(NewIssue { parent: Some(format!("{prefix}{levels}")), ..NewIssue::titled("Last step") })
        })
        .unwrap()
        .id
}

#[test]
fn closing_the_last_step_under_deep_groups_closes_them_in_linear_time() {
    const LEVELS: usize = 50_000;
    let mut env = Env::new();
    let (local, served) = (group_chain(&mut env, "a", LEVELS), group_chain(&mut env, "b", LEVELS));
    // On bd serve's 2 MiB blocking threads, once without a policy and once
    // under an agent's, which checks every group for human gates.
    let env = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            for (step, prefix, policy) in
                [(local, "a", None), (served, "b", Some(Policy { actor: "alice".into(), admin: false, human: false }))]
            {
                let started = std::time::Instant::now();
                let out = env
                    .store
                    .write("close", "alice", |tx| {
                        tx.set_policy(policy.clone());
                        tx.close_issue(&step, &CloseOptions::default())
                    })
                    .unwrap();
                let took = started.elapsed();
                // Quadratic, this took hours; linear, about a second unoptimized.
                assert!(took < Duration::from_secs(60), "closing {step} took {took:?}");
                assert_eq!(out.completed.len(), LEVELS + 1);
                assert_eq!(out.completed[0].id, format!("{prefix}{LEVELS}"));
                assert_eq!(out.completed[LEVELS].id, format!("{prefix}0"));
                let run = env.issue(&format!("{prefix}0"));
                assert_eq!((run.status, run.close_reason.as_deref()), (Status::Closed, Some("every step closed")));
            }
            env
        })
        .unwrap()
        .join()
        .unwrap();
    let mut env = env;
    env.assert_healthy();
}

/// An open chain of `levels` issues below `root`: even levels are playbook
/// groups, and level `deferred` is deferred for a day.
fn open_chain_below(env: &mut Env, root: &str, prefix: &str, levels: usize, deferred: usize) {
    let issues = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO issues (id, title, status, created_at, updated_at, defer_until, metadata)
        SELECT ?3 || k, 'Level ' || k, 'open', ?2 + k, ?2 + k, CASE k WHEN ?4 THEN ?2 + 86400000 END,
               CASE k % 2 WHEN 0 THEN '{\"playbook\":{\"role\":\"group\"}}' ELSE '{}' END FROM n";
    let edges = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        SELECT ?3 || k, CASE k WHEN 1 THEN ?4 ELSE ?3 || (k - 1) END, 'parent-child', ?2 FROM n";
    env.store
        .write("chain", "alice", |tx| {
            tx.conn().execute(issues, (levels as i64, T0, prefix, deferred as i64))?;
            tx.conn().execute(edges, (levels as i64, T0, prefix, root))?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn deep_open_chains_take_linear_time() {
    // Each group's counts used to walk its whole subtree, and each step's
    // deferral check all its ancestors: hours for this chain, not seconds.
    const LEVELS: usize = 100_000;
    const DEFERRED: usize = LEVELS / 2 + 1;
    let mut env = Env::new();
    let root = env.store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled("Deep"))).unwrap().id;
    open_chain_below(&mut env, &root, "d", LEVELS, DEFERRED);
    let started = std::time::Instant::now();
    let status = env.store.read(|r| playbook::run_status(r.conn(), &root, r.now())).unwrap();
    assert_eq!(status.nodes.len(), LEVELS);
    let p = &status.progress;
    assert_eq!((p.total, p.ready, p.blocked, p.done), (LEVELS / 2, DEFERRED / 2, LEVELS / 2 - DEFERRED / 2, 0));
    let node = |level: usize| {
        let n = &status.nodes[level - 1];
        assert_eq!((n.depth, n.id.as_str()), (level, format!("d{level}").as_str()));
        (n.state, n.detail.clone().unwrap_or_default())
    };
    assert_eq!(node(1), (StepState::Ready, String::new()));
    assert_eq!(node(2), (StepState::Open, format!("0/{} closed", (LEVELS - 2) / 2)));
    assert_eq!(node(DEFERRED - 2), (StepState::Ready, String::new()));
    assert_eq!(node(DEFERRED), (StepState::Deferred, format!("deferred by d{DEFERRED}")));
    assert_eq!(node(LEVELS - 1), (StepState::Deferred, format!("deferred by d{DEFERRED}")));
    assert_eq!(node(LEVELS), (StepState::Open, "0/0 closed".to_string()));
    // The same counts as a run's progress (`bd playbook runs`).
    let as_run = "UPDATE issues SET metadata = '{\"playbook\":{\"role\":\"run\"}}' WHERE id = ?1";
    env.store.write("mark", "alice", |tx| Ok(tx.conn().execute(as_run, [&root])?)).unwrap();
    let runs = env.store.read(|r| playbook::runs(r.conn(), &Default::default(), r.now())).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(
        (runs[0].progress.total, runs[0].progress.ready, runs[0].progress.blocked),
        (p.total, p.ready, p.blocked)
    );
    // Generous for slow CI machines; the quadratic version took hours.
    let took = started.elapsed();
    assert!(took < Duration::from_secs(60), "status and progress took {took:?}");
}

const INNER: &str = r#"
playbook = "inner"

[[steps]]
id = "a"
[[steps.children]]
id = "x"
[[steps.children]]
id = "y"

[[steps]]
id = "b"
needs = ["a"]
[steps.gate]
type = "human"
"#;

fn progress_of_runs(env: &Env, q: &playbook::RunsQuery) -> Vec<(String, [usize; 8])> {
    let runs = env.store.read(|r| playbook::runs(r.conn(), q, r.now())).unwrap();
    runs.into_iter()
        .map(|s| {
            let p = s.progress;
            (s.id, [p.total, p.done, p.failed, p.active, p.ready, p.blocked, p.gates_open, p.escalated])
        })
        .collect()
}

#[test]
fn runs_count_the_steps_of_the_runs_nested_in_them() {
    let mut env = Env::new();
    let outer = env.start(RELEASE, &[("version", "1.0.0")]);
    let start_below = |env: &mut Env, parent: &str| {
        let plan = env.plan(INNER, &[]);
        let opts = StartOptions { parent: Some(parent.into()), ..Default::default() };
        env.store.write("run", "alice", |tx| tx.start_run(&plan, &opts)).unwrap().run.id
    };
    let inner = start_below(&mut env, &format!("{outer}.bump"));
    env.close(&format!("{inner}.a.x"));
    env.store.write("claim", "bob", |tx| tx.claim(&format!("{inner}.a.y"), &ClaimOptions::default())).unwrap();
    // [total, done, failed, active, ready, blocked, gates_open, escalated]
    let all = playbook::RunsQuery::default();
    let (inner_p, outer_p) = ([3, 1, 0, 1, 0, 1, 1, 0], [6, 1, 0, 1, 1, 3, 1, 0]);
    assert_eq!(progress_of_runs(&env, &all), vec![(inner.clone(), inner_p), (outer.clone(), outer_p)]);
    // A run counts the runs inside it whether or not they are listed.
    let only_outer = playbook::RunsQuery { playbook: Some("release".into()), ..Default::default() };
    assert_eq!(progress_of_runs(&env, &only_outer), vec![(outer.clone(), outer_p)]);
    let newest = playbook::RunsQuery { limit: Some(1), ..Default::default() };
    assert_eq!(progress_of_runs(&env, &newest), vec![(inner.clone(), inner_p)]);
    let innermost = start_below(&mut env, &format!("{inner}.b"));
    let (innermost_p, inner_p, outer_p) =
        ([3, 0, 0, 0, 0, 3, 1, 0], [6, 1, 0, 1, 0, 4, 2, 0], [9, 1, 0, 1, 1, 6, 2, 0]);
    let nested = vec![(innermost.clone(), innermost_p), (inner.clone(), inner_p), (outer.clone(), outer_p)];
    assert_eq!(progress_of_runs(&env, &all), nested);

    // A damaged database: a second parent across runs, then a parent cycle.
    let other = env.start(INNER, &[]);
    let edge = "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        VALUES (?1, ?2, 'parent-child', 0)";
    let add = |env: &mut Env, child: String, parent: String| {
        env.store.write("damage", "alice", |tx| Ok(tx.conn().execute(edge, [&child, &parent])?)).unwrap();
    };
    add(&mut env, format!("{other}.a"), format!("{outer}.tag"));
    let (other_p, outer_p) = ([3, 0, 0, 0, 2, 1, 1, 0], [11, 1, 0, 1, 3, 6, 2, 0]);
    assert_eq!(
        progress_of_runs(&env, &all),
        vec![
            (other.clone(), other_p),
            (innermost.clone(), innermost_p),
            (inner.clone(), inner_p),
            (outer.clone(), outer_p)
        ]
    );
    add(&mut env, outer.clone(), format!("{innermost}.b"));
    assert_eq!(
        progress_of_runs(&env, &all),
        vec![(other, other_p), (innermost, outer_p), (inner, outer_p), (outer, outer_p)]
    );
}

/// `levels` open runs `{prefix}1..`, each the only child of the one before,
/// and below each a step `{prefix}s{k}`, closed for even `k`. Plain SQL, as
/// in [`chain_below`].
fn nested_runs(env: &mut Env, prefix: &str, levels: usize) {
    let issues = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO issues (id, title, status, created_at, updated_at, closed_at, metadata)
        SELECT ?3 || k, 'Run ' || k, 'open', ?2 + 2 * k, ?2 + 2 * k, NULL,
               '{\"playbook\":{\"role\":\"run\",\"name\":\"nest\"}}' FROM n
        UNION ALL
        SELECT ?3 || 's' || k, 'Step ' || k, CASE k % 2 WHEN 0 THEN 'closed' ELSE 'open' END,
               ?2 + 2 * k + 1, ?2 + 2 * k + 1, CASE k % 2 WHEN 0 THEN ?2 END, '{}' FROM n";
    let edges = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        SELECT ?3 || k, ?3 || (k - 1), 'parent-child', ?2 FROM n WHERE k > 1
        UNION ALL
        SELECT ?3 || 's' || k, ?3 || k, 'parent-child', ?2 FROM n";
    env.store
        .write("nest", "alice", |tx| {
            tx.conn().execute(issues, (levels as i64, T0, prefix))?;
            tx.conn().execute(edges, (levels as i64, T0, prefix))?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn deeply_nested_runs_take_linear_time() {
    // Each run walked its own subtree, which holds every run inside it.
    const LEVELS: usize = 20_000;
    let mut env = Env::new();
    nested_runs(&mut env, "r", LEVELS);
    let started = std::time::Instant::now();
    let runs = env.store.read(|r| playbook::runs(r.conn(), &Default::default(), r.now())).unwrap();
    let took = started.elapsed();
    assert_eq!(runs.len(), LEVELS);
    for (i, run) in runs.iter().enumerate() {
        // Newest first: the innermost run, with one step, comes first.
        let k = LEVELS - i;
        let steps = LEVELS - k + 1;
        let done = LEVELS / 2 - (k - 1) / 2;
        assert_eq!(run.id, format!("r{k}"));
        let p = &run.progress;
        assert_eq!((p.total, p.done, p.ready, p.blocked), (steps, done, steps - done, 0), "{}", run.id);
    }
    // Generous for slow CI machines; the quadratic version took minutes.
    assert!(took < Duration::from_secs(60), "runs took {took:?}");
}

/// A run `{prefix}0` closed with `levels` closed groups `{prefix}1..` below
/// it, each the only child of the one before, and a closed step `{prefix}-step`
/// below the last one, as a finished run leaves them. Plain SQL with table
/// statistics, as in [`group_chain`]. Returns the step.
fn closed_group_chain(env: &mut Env, prefix: &str, levels: usize) -> String {
    let issues = "WITH RECURSIVE n(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO issues (id, title, issue_type, status, metadata, created_at, updated_at, closed_at,
                            close_reason, close_outcome)
        SELECT ?3 || k, 'Level ' || k, 'epic', 'closed',
               json_object('playbook', json_object('role', CASE k WHEN 0 THEN 'run' ELSE 'group' END)),
               ?2 + k, ?2 + k, ?2 + k, 'every step closed', 'done'
        FROM n";
    let edges = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
        INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
        SELECT ?3 || k, ?3 || (k - 1), 'parent-child', ?2 FROM n";
    let step = format!("{prefix}-step");
    env.store
        .write("chain", "alice", |tx| {
            tx.conn().execute(issues, (levels as i64, T0, prefix))?;
            tx.conn().execute(edges, (levels as i64, T0, prefix))?;
            tx.conn().execute(
                "INSERT INTO issues (id, title, status, created_at, updated_at, closed_at, close_reason, close_outcome)
                 VALUES (?1, 'Last step', 'closed', ?2, ?2, ?2, 'done', 'done')",
                (&step, T0),
            )?;
            tx.conn().execute(
                "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
                 VALUES (?1, ?2, 'parent-child', ?3)",
                (&step, format!("{prefix}{levels}"), T0),
            )?;
            tx.conn().execute_batch("ANALYZE")?;
            Ok(())
        })
        .unwrap();
    step
}

#[test]
fn reopening_a_step_under_deep_closed_groups_reopens_them_in_linear_time() {
    const LEVELS: usize = 20_000;
    let mut env = Env::new();
    let (plain, held) = (closed_group_chain(&mut env, "a", LEVELS), closed_group_chain(&mut env, "b", LEVELS));
    // Halfway up the second chain, a group waits on an open issue: once it
    // reopens, it blocks everything reopened below it.
    let blocker = env.store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled("Blocker"))).unwrap().id;
    let mid = format!("b{}", LEVELS / 2);
    env.store
        .write("dep", "alice", |tx| {
            tx.conn().execute(
                "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at) VALUES (?1, ?2, 'blocks', ?3)",
                (&mid, &blocker, T0),
            )?;
            Ok(())
        })
        .unwrap();
    let env = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            for (step, prefix) in [(plain, "a"), (held, "b")] {
                let since = env.store.read(|r| r.events(&EventQuery::default())).unwrap().head;
                let started = std::time::Instant::now();
                let out = env.store.write("reopen", "alice", |tx| tx.reopen_issue(&step, None)).unwrap();
                let took = started.elapsed();
                eprintln!("reopening {step} under {LEVELS} groups took {took:?}");
                // Quadratic, this took minutes; linear, well under a second.
                assert!(took < Duration::from_secs(60), "reopening {step} took {took:?}");
                assert_eq!(out.reopened.len(), LEVELS + 1);
                assert_eq!(out.reopened[0].id, format!("{prefix}{LEVELS}"));
                assert_eq!(out.reopened[LEVELS].id, format!("{prefix}0"));
                assert!(out.reopened.iter().all(|i| i.status == Status::Open));
                let blocked: Vec<&str> = out.newly_blocked.iter().map(|i| i.id.as_str()).collect();
                let events = env
                    .store
                    .read(|r| r.events(&EventQuery { since: Some(since), ..Default::default() }))
                    .unwrap()
                    .events;
                let reopened = events.iter().filter(|e| e.op == "reopened").count();
                let blocks: Vec<&str> =
                    events.iter().filter(|e| e.op == "blocked").map(|e| e.issue_id.as_deref().unwrap()).collect();
                assert_eq!(reopened, LEVELS + 2);
                if prefix == "a" {
                    assert!(blocked.is_empty() && blocks.is_empty(), "{blocked:?}");
                } else {
                    assert_eq!(blocked, [step.as_str()]);
                    // The group itself, then down its subtree: every group
                    // reopened below it and the step.
                    assert_eq!(blocks.len(), LEVELS / 2 + 2);
                    assert_eq!((blocks[0], blocks[1]), (mid.as_str(), format!("b{}", LEVELS / 2 + 1).as_str()));
                    assert_eq!(blocks[LEVELS / 2 + 1], step);
                }
            }
            env
        })
        .unwrap()
        .join()
        .unwrap();
    let mut env = env;
    // Groups are not work; the second step waits on the blocker.
    assert_eq!(env.ready_ids(), ["a-step".to_string(), blocker]);
    env.assert_healthy();
}

#[test]
fn reopening_up_closed_groups_blocks_what_it_should_in_order() {
    let mut env = Env::new();
    let mut make = |title: &str, parent: Option<&str>, role: Option<&str>| {
        let new = NewIssue { parent: parent.map(String::from), ..NewIssue::titled(title) };
        env.store
            .write("create", "alice", |tx| {
                let id = tx.create_issue(new)?.id;
                if let Some(role) = role {
                    tx.conn().execute(
                        "UPDATE issues SET metadata = json_object('playbook', json_object('role', ?1)) WHERE id = ?2",
                        (role, &id),
                    )?;
                }
                Ok(id)
            })
            .unwrap()
    };
    // A run with a failed step and, two groups down, a step; G2 waits on an
    // open issue, D on G1 failing, W on the run's steps.
    let run = make("Run", None, Some("run"));
    let g1 = make("G1", Some(&run), Some("group"));
    let g2 = make("G2", Some(&g1), Some("group"));
    let step = make("Step", Some(&g2), None);
    let failed = make("Failed", Some(&g1), None);
    let x = make("X", None, None);
    let d = make("D", None, None);
    let w = make("W", None, None);
    // Another run three groups deep, whose step waits for the steps of the
    // top group.
    let run2 = make("Run 2", None, Some("run"));
    let h1 = make("H1", Some(&run2), Some("group"));
    let h2 = make("H2", Some(&h1), Some("group"));
    let h3 = make("H3", Some(&h2), Some("group"));
    let leaf = make("Leaf", Some(&h3), None);
    env.close_failed(&failed);
    env.close(&step);
    env.close(&leaf);
    assert_eq!((env.issue(&run).status, env.issue(&run2).status), (Status::Closed, Status::Closed));
    let edges = [(&g2, &x, DepType::Blocks), (&d, &g1, DepType::ConditionalBlocks), (&w, &run, DepType::WaitsFor)];
    for (issue, target, t) in edges.into_iter().chain([(&leaf, &h1, DepType::WaitsFor)]) {
        env.store.write("dep", "alice", |tx| tx.add_dependency(issue, target, t, None)).unwrap();
    }
    assert_eq!(env.ready_ids(), [x.clone(), d.clone(), w.clone()]);

    for (reopen, reopened, blocked, expected) in [
        (
            &step,
            vec![&g2, &g1, &run],
            vec![&step, &d, &w],
            vec![
                ("reopened", &step, json!({ "reason": null })),
                ("reopened", &g2, json!({ "reason": format!("{step} was reopened") })),
                ("blocked", &g2, json!({})),
                ("blocked", &step, json!({})),
                ("reopened", &g1, json!({ "reason": format!("{step} was reopened") })),
                ("blocked", &d, json!({})),
                ("blocked", &w, json!({})),
                ("reopened", &run, json!({ "reason": format!("{step} was reopened") })),
            ],
        ),
        (
            &leaf,
            vec![&h3, &h2, &h1, &run2],
            vec![&leaf],
            vec![
                ("reopened", &leaf, json!({ "reason": null })),
                ("reopened", &h3, json!({ "reason": format!("{leaf} was reopened") })),
                ("reopened", &h2, json!({ "reason": format!("{leaf} was reopened") })),
                // H1 has a live step again.
                ("blocked", &leaf, json!({})),
                ("reopened", &h1, json!({ "reason": format!("{leaf} was reopened") })),
                ("reopened", &run2, json!({ "reason": format!("{leaf} was reopened") })),
            ],
        ),
    ] {
        let since = env.store.read(|r| r.events(&EventQuery::default())).unwrap().head;
        let out = env.store.write("reopen", "alice", |tx| tx.reopen_issue(reopen, None)).unwrap();
        let ids = |refs: &[IssueRef]| refs.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&out.reopened), reopened.into_iter().cloned().collect::<Vec<_>>());
        assert_eq!(ids(&out.newly_blocked), blocked.into_iter().cloned().collect::<Vec<_>>());
        let events = env.store.read(|r| r.events(&EventQuery { since: Some(since), ..Default::default() })).unwrap();
        let events: Vec<_> =
            events.events.into_iter().map(|e| (e.op, e.issue_id.unwrap_or_default(), e.data)).collect();
        let expected: Vec<_> = expected.into_iter().map(|(op, id, data)| (op.to_string(), id.clone(), data)).collect();
        assert_eq!(events, expected);
    }
    // X holds G2 and its step; D, W and the leaf wait.
    assert_eq!(env.ready_ids(), [run, g1, x, run2, h1, h2, h3]);
    env.assert_healthy();
}
