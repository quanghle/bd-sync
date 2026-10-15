//! Engine-level integration tests: lifecycle, graph semantics, ready order,
//! leases, crash recovery, optimistic concurrency, events, and concurrency.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use bd_core::doctor;
use bd_core::hierarchy;
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use serde_json::json;
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

struct Env {
    _dir: TempDir,
    path: PathBuf,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Env {
    fn new() -> Env {
        Env::with_mode(IdMode::Counter)
    }

    fn with_mode(id_mode: IdMode) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bd").join("bd.db");
        let clock = Arc::new(ManualClock::new(Timestamp(T0)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store = Store::init(&path, InitOptions { prefix: "t".into(), id_mode }, opts).unwrap();
        Env { _dir: dir, path, store, clock }
    }

    fn open_another(&self) -> Store {
        let opts = OpenOptions { clock: self.clock.clone(), ..Default::default() };
        Store::open(&self.path, opts).unwrap()
    }

    fn create(&mut self, title: &str, priority: u8) -> String {
        self.create_with(NewIssue { title: title.into(), priority: Some(priority), ..Default::default() })
    }

    fn create_with(&mut self, new: NewIssue) -> String {
        self.clock.advance(Duration::from_millis(10));
        self.store.write("create", "alice", |tx| tx.create_issue(new)).unwrap().id
    }

    fn dep(&mut self, issue: &str, target: &str, t: DepType) {
        self.store.write("dep", "alice", |tx| tx.add_dependency(issue, target, t, None)).unwrap();
    }

    fn close(&mut self, id: &str) -> CloseOutcome {
        self.store.write("close", "alice", |tx| tx.close_issue(id, &CloseOptions::default())).unwrap()
    }

    fn issue(&self, id: &str) -> Issue {
        self.store.read(|r| r.issue(id)).unwrap()
    }

    fn ready_ids(&self) -> Vec<String> {
        self.ready_ids_with(&ReadyQuery::default())
    }

    fn ready_ids_with(&self, q: &ReadyQuery) -> Vec<String> {
        self.store.read(|r| r.ready(q)).unwrap().into_iter().map(|i| i.id).collect()
    }

    fn events(&self) -> Vec<Event> {
        self.store.read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() })).unwrap().events
    }

    fn assert_healthy(&mut self) {
        let report = doctor::diagnose(&mut self.store, false, true).unwrap();
        let bad: Vec<_> = report.checks.iter().filter(|c| c.severity != doctor::Severity::Ok).collect();
        assert!(bad.is_empty(), "doctor found problems: {bad:#?}");
    }
}

#[test]
fn create_assigns_ids_and_records_events() {
    let mut env = Env::new();
    let a = env.create("First", 1);
    let b = env.create("Second", 2);
    assert_eq!((a.as_str(), b.as_str()), ("t-1", "t-2"));
    let child = env.create_with(NewIssue { title: "Child".into(), parent: Some(a.clone()), ..Default::default() });
    assert_eq!(child, "t-1.1");
    let child2 = env.create_with(NewIssue { title: "Child 2".into(), parent: Some(a.clone()), ..Default::default() });
    assert_eq!(child2, "t-1.2");
    let issue = env.issue(&a);
    assert_eq!(issue.status, Status::Open);
    assert_eq!(issue.revision, 1);
    assert_eq!(issue.created_by, "alice");
    let ops: Vec<String> = env.events().into_iter().map(|e| e.op).collect();
    assert!(ops.starts_with(&["config_set".into(), "config_set".into(), "created".into(), "created".into()]));
    assert!(ops.contains(&"dep_added".to_string()));
    env.assert_healthy();
}

#[test]
fn hash_ids_use_prefix_and_adaptive_length() {
    let mut env = Env::with_mode(IdMode::Hash);
    let mut seen = HashSet::new();
    for i in 0..50 {
        let id = env.create(&format!("Issue {i}"), 2);
        assert!(id.starts_with("t-"), "{id}");
        assert_eq!(id.len(), "t-".len() + 3, "{id}");
        assert!(seen.insert(id));
    }
}

#[test]
fn validation_rejects_bad_input() {
    let mut env = Env::new();
    let err = env.store.write("c", "alice", |tx| tx.create_issue(NewIssue::titled("   "))).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)));
    let err = env
        .store
        .write("c", "alice", |tx| {
            tx.create_issue(NewIssue { title: "x".into(), priority: Some(7), ..Default::default() })
        })
        .unwrap_err();
    assert!(err.to_string().contains("priority"));
    let err = env
        .store
        .write("c", "alice", |tx| {
            tx.create_issue(NewIssue { title: "x".into(), issue_type: Some("nope".into()), ..Default::default() })
        })
        .unwrap_err();
    assert!(err.to_string().contains("unknown issue type"));
    // Nothing was written by the failed transactions.
    assert_eq!(env.store.read(|r| r.list(&ListQuery { all: true, ..Default::default() })).unwrap().len(), 0);
}

#[test]
fn blocks_edges_gate_readiness_and_release_on_close() {
    let mut env = Env::new();
    let a = env.create("Design", 1);
    let b = env.create("Implement", 1);
    let c = env.create("Test", 1);
    env.dep(&b, &a, DepType::Blocks);
    env.dep(&c, &b, DepType::Blocks);
    assert_eq!(env.ready_ids(), vec![a.clone()]);
    assert!(env.issue(&b).is_blocked && env.issue(&c).is_blocked);

    let blocked = env.store.read(|r| r.blocked(&WorkFilter::default(), None)).unwrap();
    assert_eq!(blocked.len(), 2);
    assert_eq!(blocked[0].blockers[0].id, a);

    let out = env.close(&a);
    assert_eq!(out.unblocked.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), vec![b.clone()]);
    assert_eq!(env.ready_ids(), vec![b.clone()]);
    assert!(env.issue(&c).is_blocked, "C waits on B, which is still open");

    // In-progress blockers still block.
    env.store.write("claim", "bob", |tx| tx.claim(&b, &ClaimOptions::default())).unwrap();
    assert!(env.issue(&c).is_blocked);

    // Reopen re-blocks dependents.
    let reopened = env.store.write("reopen", "alice", |tx| tx.reopen_issue(&a, Some("regression"))).unwrap();
    assert!(!reopened.already_open);
    assert!(env.issue(&b).is_blocked);
    let ops: Vec<String> = env.events().into_iter().map(|e| e.op).collect();
    assert!(ops.contains(&"unblocked".to_string()) && ops.contains(&"blocked".to_string()));
    env.assert_healthy();
}

#[test]
fn hierarchy_blocks_downward_only() {
    let mut env = Env::new();
    let gate = env.create("Gate", 0);
    let epic =
        env.create_with(NewIssue { title: "Epic".into(), issue_type: Some("epic".into()), ..Default::default() });
    let child = env.create_with(NewIssue { title: "Child".into(), parent: Some(epic.clone()), ..Default::default() });
    let grandchild =
        env.create_with(NewIssue { title: "Grandchild".into(), parent: Some(child.clone()), ..Default::default() });
    assert!(!env.issue(&epic).is_blocked, "epics are not blocked by their open children");
    env.dep(&epic, &gate, DepType::Blocks);
    assert!(env.issue(&epic).is_blocked);
    assert!(env.issue(&child).is_blocked && env.issue(&grandchild).is_blocked, "blocking flows down the hierarchy");
    assert_eq!(env.ready_ids(), vec![gate.clone()]);
    let blockers = env.store.read(|r| r.blockers(&grandchild)).unwrap();
    assert_eq!(blockers[0].kind, BlockerKind::Parent);

    env.close(&gate);
    assert!(!env.issue(&grandchild).is_blocked);
    assert_eq!(env.ready_ids(), vec![grandchild.clone()], "the epic is excluded, and the child waits on its own child");
    let with_epics = env.ready_ids_with(&ReadyQuery { include_epics: true, ..Default::default() });
    assert!(!with_epics.contains(&epic), "not blocked, but not ready either: its work is in its open child");

    // Parents cannot close over open children unless forced.
    let err = env.store.write("close", "alice", |tx| tx.close_issue(&epic, &CloseOptions::default())).unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err}");
    env.assert_healthy();
}

#[test]
fn conditional_blocks_runs_only_on_failure() {
    let mut env = Env::new();
    let build = env.create("Build", 1);
    let fix = env.create("Fix build", 1);
    let deploy = env.create("Deploy", 1);
    env.dep(&fix, &build, DepType::ConditionalBlocks);
    env.dep(&deploy, &build, DepType::Blocks);
    assert!(env.issue(&fix).is_blocked);

    // Success: the error path stays blocked, the happy path proceeds.
    env.close(&build);
    assert!(env.issue(&fix).is_blocked);
    assert!(!env.issue(&deploy).is_blocked);
    let why = env.store.read(|r| r.blockers(&fix)).unwrap();
    assert!(why[0].detail.contains("succeeded"), "{why:?}");

    // Failure: reopen and close as failed; the error path becomes ready.
    env.store.write("reopen", "alice", |tx| tx.reopen_issue(&build, None)).unwrap();
    env.store
        .write("close", "alice", |tx| {
            tx.close_issue(
                &build,
                &CloseOptions {
                    outcome: Some(Outcome::Failed),
                    reason: Some("tests red".into()),
                    ..Default::default()
                },
            )
        })
        .unwrap();
    assert!(!env.issue(&fix).is_blocked);
    assert!(env.ready_ids().contains(&fix));
    env.assert_healthy();
}

#[test]
fn waits_for_gates_follow_spawner_children() {
    let mut env = Env::new();
    let spawner = env.create("Fan out", 1);
    let c1 = env.create_with(NewIssue { title: "Part 1".into(), parent: Some(spawner.clone()), ..Default::default() });
    let c2 = env.create_with(NewIssue { title: "Part 2".into(), parent: Some(spawner.clone()), ..Default::default() });
    let all = env.create("Merge all", 1);
    let any = env.create("First result", 1);
    env.dep(&all, &spawner, DepType::WaitsFor);
    env.store
        .write("dep", "alice", |tx| {
            tx.add_dependency(&any, &spawner, DepType::WaitsFor, Some(json!({"gate": "any-children"})))
        })
        .unwrap();
    assert!(env.issue(&all).is_blocked && env.issue(&any).is_blocked);

    env.close(&c1);
    assert!(env.issue(&all).is_blocked, "all-children waits for every child");
    assert!(!env.issue(&any).is_blocked, "any-children opens after the first close");

    env.close(&c2);
    assert!(!env.issue(&all).is_blocked);

    // A new live child shuts the all-children gate again.
    env.create_with(NewIssue { title: "Part 3".into(), parent: Some(spawner.clone()), ..Default::default() });
    assert!(env.issue(&all).is_blocked);
    let err = env
        .store
        .write("dep", "alice", |tx| tx.add_dependency(&all, &c1, DepType::WaitsFor, Some(json!({"gate": "most"}))))
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)));
    env.assert_healthy();
}

#[test]
fn cycles_and_hierarchy_deadlocks_are_rejected() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 1);
    let c = env.create("C", 1);
    env.dep(&b, &a, DepType::Blocks);
    env.dep(&c, &b, DepType::Blocks);
    let err = env.store.write("dep", "alice", |tx| tx.add_dependency(&a, &c, DepType::Blocks, None)).unwrap_err();
    match err {
        Error::Cycle { path } => assert_eq!(path, vec![a.clone(), c.clone(), b.clone(), a.clone()]),
        other => panic!("expected cycle, got {other}"),
    }
    let err = env.store.write("dep", "alice", |tx| tx.add_dependency(&a, &a, DepType::Related, None)).unwrap_err();
    assert!(err.to_string().contains("itself"));
    // Informational edges may point "backwards".
    env.store.write("dep", "alice", |tx| tx.add_dependency(&a, &c, DepType::Related, None)).unwrap();

    let parent = env.create("Parent", 1);
    let kid = env.create_with(NewIssue { title: "Kid".into(), parent: Some(parent.clone()), ..Default::default() });
    let err =
        env.store.write("dep", "alice", |tx| tx.add_dependency(&kid, &parent, DepType::Blocks, None)).unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "same pair already has a parent-child edge: {err}");
    let grandkid =
        env.create_with(NewIssue { title: "Grandkid".into(), parent: Some(kid.clone()), ..Default::default() });
    let err =
        env.store.write("dep", "alice", |tx| tx.add_dependency(&grandkid, &parent, DepType::Blocks, None)).unwrap_err();
    assert!(err.to_string().contains("ancestor"), "{err}");
    let err =
        env.store.write("dep", "alice", |tx| tx.add_dependency(&parent, &grandkid, DepType::Blocks, None)).unwrap_err();
    assert!(err.to_string().contains("descendant") || matches!(err, Error::Cycle { .. }), "{err}");
    assert!(env.store.read(|r| r.cycles()).unwrap().is_empty());
    env.assert_healthy();
}

#[test]
fn ready_order_is_deterministic_per_policy() {
    let mut env = Env::new();
    let old_low = env.create("old low", 3);
    let old_high = env.create("old high", 0);
    env.clock.advance(Duration::from_secs(3 * 24 * 3600));
    let new_low = env.create("new low", 2);
    let new_high = env.create("new high", 1);
    let tie = env.create_with(NewIssue {
        id: Some("t-zz".into()),
        title: "tie".into(),
        priority: Some(1),
        ..Default::default()
    });

    let by_priority = env.ready_ids();
    assert_eq!(by_priority, vec![old_high.clone(), new_high.clone(), tie.clone(), new_low.clone(), old_low.clone()]);
    let oldest = env.ready_ids_with(&ReadyQuery { sort: SortPolicy::Oldest, ..Default::default() });
    assert_eq!(oldest, vec![old_low.clone(), old_high.clone(), new_low.clone(), new_high.clone(), tie.clone()]);
    let hybrid = env.ready_ids_with(&ReadyQuery { sort: SortPolicy::Hybrid, ..Default::default() });
    assert_eq!(hybrid, vec![new_high.clone(), tie.clone(), new_low.clone(), old_low.clone(), old_high.clone()]);
    for _ in 0..5 {
        assert_eq!(env.ready_ids_with(&ReadyQuery { sort: SortPolicy::Hybrid, ..Default::default() }), hybrid);
    }
    let limited = env.ready_ids_with(&ReadyQuery { limit: Some(2), ..Default::default() });
    assert_eq!(limited, by_priority[..2].to_vec());
    let unlimited = env.ready_ids_with(&ReadyQuery { limit: Some(usize::MAX), ..Default::default() });
    assert_eq!(unlimited, by_priority, "a limit past SQLite's integers is no limit");
}

#[test]
fn deferral_hides_issue_and_subtree_until_time() {
    let mut env = Env::new();
    let epic =
        env.create_with(NewIssue { title: "Later epic".into(), issue_type: Some("epic".into()), ..Default::default() });
    let kid = env.create_with(NewIssue { title: "Kid".into(), parent: Some(epic.clone()), ..Default::default() });
    let grandkid =
        env.create_with(NewIssue { title: "Grandkid".into(), parent: Some(kid.clone()), ..Default::default() });
    let solo = env.create("Solo", 2);
    let until = env.clock.now().plus(Duration::from_secs(3600));
    env.store.write("defer", "alice", |tx| tx.defer_issue(&epic, Some(until))).unwrap();
    env.store.write("defer", "alice", |tx| tx.defer_issue(&solo, None)).unwrap();
    assert!(env.ready_ids().is_empty(), "deferral hides the whole subtree; indefinite deferral hides solo");
    let reasons = env.store.read(|r| r.not_ready_reasons(&grandkid)).unwrap();
    assert!(reasons[0].contains(&epic), "{reasons:?}");
    let err = env.store.write("claim", "bob", |tx| tx.claim(&grandkid, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(err, Error::NotReady { .. }));

    env.clock.advance(Duration::from_secs(3601));
    assert_eq!(env.ready_ids(), vec![grandkid.clone()], "the kid waits on its own kid");
    env.store.write("undefer", "alice", |tx| tx.undefer_issue(&solo)).unwrap();
    assert!(env.ready_ids().contains(&solo));
}

#[test]
fn an_issue_with_open_children_is_not_ready_to_claim() {
    let mut env = Env::new();
    let epic_titled =
        |title: &str| NewIssue { title: title.into(), issue_type: Some("epic".into()), ..Default::default() };
    let epic = env.create_with(epic_titled("Epic"));
    let mut kids = Vec::new();
    for n in 1..=7 {
        // The second is reserved for bob.
        let assignee = (n == 2).then(|| "bob".to_string());
        let kid = NewIssue { title: format!("Kid {n}"), parent: Some(epic.clone()), assignee, ..Default::default() };
        kids.push(env.create_with(kid));
    }
    let unplanned = env.create_with(epic_titled("Not broken down yet"));
    // Whatever its type: a task with a subtask, at the head of the queue by priority.
    let task = env.create("A task with a subtask", 0);
    let subtask =
        NewIssue { title: "Subtask".into(), parent: Some(task.clone()), priority: Some(3), ..Default::default() };
    let subtask = env.create_with(subtask);
    env.store.write("claim", "agent-a", |tx| tx.claim(&kids[0], &ClaimOptions::default())).unwrap();

    let reason = "its children come first, and 7 are open (t-1.1 claimed by agent-a, t-1.2 open, assigned to bob, \
                  t-1.3 open, t-1.4 open, t-1.5 open, 2 more): claim one of them (`bd claim --next --parent t-1`)";
    assert_eq!(env.store.read(|r| r.not_ready_reasons(&epic)).unwrap(), [reason]);
    let err = env.store.write("claim", "bob", |tx| tx.claim(&epic, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(&err, Error::NotReady { reasons, .. } if reasons == &[reason]), "{err}");
    assert_eq!(err.exit_code(), 4);
    assert_eq!(env.issue(&epic).status, Status::Open, "refused: nothing changed");
    let reason =
        "its children come first, and 1 is open (t-3.1 open): claim one of them (`bd claim --next --parent t-3`)";
    let err = env.store.write("claim", "dave", |tx| tx.claim(&task, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(&err, Error::NotReady { reasons, .. } if reasons == &[reason]), "{err}");

    // The queue agrees, epics asked for or not, and so does `claim --next`.
    let ready = env.ready_ids();
    assert!(!ready.contains(&task) && ready.contains(&subtask), "{ready:?}");
    let epics =
        ReadyQuery { filter: WorkFilter { types: vec!["epic".into()], ..Default::default() }, ..Default::default() };
    assert_eq!(env.ready_ids_with(&epics), std::slice::from_ref(&unplanned));
    let all = env.ready_ids_with(&ReadyQuery { include_epics: true, ..Default::default() });
    assert!(all.contains(&unplanned) && !all.contains(&epic) && !all.contains(&task), "{all:?}");
    let next = env.store.write("claim", "carol", |tx| tx.claim_next(&epics, &ClaimOptions::default())).unwrap();
    assert_eq!(next.map(|c| c.issue.id), Some(unplanned.clone()), "an epic not broken down yet");
    assert!(env.store.write("claim", "carol", |tx| tx.claim_next(&epics, &ClaimOptions::default())).unwrap().is_none());
    // No block: the children are ready as before. The first one erin may take beats the task's P0.
    let next = env.store.write("claim", "erin", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()));
    assert_eq!(next.unwrap().map(|c| c.issue.id), Some(kids[2].clone()));

    // The counts agree with the queue, and count the task as waiting on its children (epics are no work).
    let counts = |env: &Env| {
        let stats = env.store.read(|r| r.stats()).unwrap();
        (stats.ready, stats.waiting_on_children)
    };
    assert_eq!(counts(&env), (env.ready_ids().len() as i64, 1));
    let later = env.create("Later", 2);
    env.store.write("defer", "alice", |tx| tx.defer_issue(&later, None)).unwrap();
    assert_eq!(counts(&env), (env.ready_ids().len() as i64, 1), "with something deferred too");

    // By id, --allow-blocked claims a parent anyway.
    let anyway = ClaimOptions { allow_blocked: true, ..Default::default() };
    env.store.write("claim", "bob", |tx| tx.claim(&epic, &anyway)).unwrap();
    env.store.write("release", "bob", |tx| tx.release(&epic, &ReleaseOptions::default())).unwrap();

    // Once every child is closed, a parent is ready again: wrapping it up is its own work.
    for (kid, actor) in kids.iter().zip(["agent-a", "alice", "erin", "alice", "alice", "alice", "alice"]) {
        env.store.write("close", actor, |tx| tx.close_issue(kid, &CloseOptions::default())).unwrap();
    }
    env.close(&subtask);
    assert!(env.store.read(|r| r.not_ready_reasons(&epic)).unwrap().is_empty());
    assert_eq!(env.ready_ids_with(&epics), std::slice::from_ref(&epic));
    assert!(env.ready_ids().contains(&task));
    assert_eq!(counts(&env), (env.ready_ids().len() as i64, 0));
    env.store.write("claim", "bob", |tx| tx.claim(&epic, &ClaimOptions::default())).unwrap();
    env.store.write("claim", "dave", |tx| tx.claim(&task, &ClaimOptions::default())).unwrap();
    env.assert_healthy();
}

#[test]
fn a_spawner_is_ready_before_the_work_it_spawned() {
    // A fan-out: P spawns C while it holds its claim; C needs X, X needs P, and W collects P's children.
    // `bd close` lets a spawner finish first, so the queue must offer P back once released, or nothing
    // is ever ready again.
    let mut env = Env::new();
    let p = env.create("Spawner", 2);
    let x = env.create("After the spawner", 2);
    let w = env.create("Collector", 2);
    env.store.write("claim", "bob", |tx| tx.claim(&p, &ClaimOptions::default())).unwrap();
    let c = env.create_with(NewIssue { title: "Spawned".into(), parent: Some(p.clone()), ..Default::default() });
    env.dep(&x, &p, DepType::Blocks);
    env.dep(&c, &x, DepType::Blocks);
    env.dep(&w, &p, DepType::WaitsFor);
    env.store.write("release", "bob", |tx| tx.release(&p, &ReleaseOptions::default())).unwrap();

    assert!(env.store.read(|r| r.not_ready_reasons(&p)).unwrap().is_empty());
    assert_eq!(env.ready_ids(), std::slice::from_ref(&p));
    let stats = env.store.read(|r| r.stats()).unwrap();
    assert_eq!((stats.ready, stats.waiting_on_children), (1, 0));
    for (id, actor) in [(&p, "carol"), (&x, "carol"), (&c, "dave"), (&w, "erin")] {
        let next =
            env.store.write("claim", actor, |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()));
        assert_eq!(next.unwrap().map(|c| c.issue.id).as_ref(), Some(id), "in order");
        env.store.write("close", actor, |tx| tx.close_issue(id, &CloseOptions::default())).unwrap();
    }
    env.assert_healthy();
}

#[test]
fn claims_are_atomic_idempotent_and_leased() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 2);
    env.dep(&b, &a, DepType::Blocks);

    let claim = env.store.write("claim", "bob", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    assert!(!claim.already_held);
    assert_eq!(claim.issue.status, Status::InProgress);
    assert_eq!(claim.issue.assignee.as_deref(), Some("bob"));
    assert_eq!(claim.lease.expires_at, env.clock.now().plus(Duration::from_secs(300)));
    let token = claim.lease.token;
    let claimed_event = env.events().into_iter().find(|e| e.op == "claimed").unwrap();
    assert_eq!(claimed_event.seq, token, "the fencing token is the claim event's seq");

    // A live claim is its lease's: claimed again by the same actor name, it is
    // refused (another session may hold it), unless the caller shows the token.
    let err = env.store.write("claim", "bob", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(err, Error::AlreadyClaimed { ref holder, .. } if holder == "bob"), "{err}");
    let renew = ClaimOptions { token: Some(token), ..Default::default() };
    env.clock.advance(Duration::from_secs(60));
    let again = env.store.write("claim", "bob", |tx| tx.claim(&a, &renew)).unwrap();
    assert!(again.already_held);
    assert_eq!(again.lease.token, token);
    assert_eq!(again.lease.expires_at, env.clock.now().plus(Duration::from_secs(300)), "renewed");
    let stale = ClaimOptions { token: Some(token + 100), ..Default::default() };
    let err = env.store.write("claim", "bob", |tx| tx.claim(&a, &stale)).unwrap_err();
    assert!(matches!(err, Error::LeaseLost { .. }), "{err}");

    let err = env.store.write("claim", "carol", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(err, Error::AlreadyClaimed { ref holder, .. } if holder == "bob"));
    assert_eq!(err.exit_code(), 4);

    let err = env.store.write("claim", "carol", |tx| tx.claim(&b, &ClaimOptions::default())).unwrap_err();
    assert!(matches!(err, Error::NotReady { .. }), "blocked issues are not claimable by default");
    env.store
        .write("claim", "carol", |tx| tx.claim(&b, &ClaimOptions { allow_blocked: true, ..Default::default() }))
        .unwrap();

    // Release by a non-owner needs force.
    let err = env.store.write("release", "carol", |tx| tx.release(&a, &ReleaseOptions::default())).unwrap_err();
    assert!(matches!(err, Error::NotOwner { .. }));
    let released = env.store.write("release", "bob", |tx| tx.release(&a, &ReleaseOptions::default())).unwrap();
    assert_eq!(released.status, Status::Open);
    assert_eq!(released.assignee, None);
    assert!(env.store.read(|r| r.lease(&a)).unwrap().is_none());

    let counters = env.store.read(|r| Ok(metrics::metrics(r.conn(), r.now(), None)?.counters)).unwrap();
    assert_eq!(counters.get("claim_conflicts"), Some(&2));
    assert_eq!(counters.get("lease_lost"), Some(&1));
    assert_eq!(counters.get("not_owner"), Some(&1));
    env.assert_healthy();
}

#[test]
fn claim_next_takes_queue_head_and_respects_reservations_and_pools() {
    let mut env = Env::new();
    let low = env.create("low", 3);
    let high = env.create("high", 0);
    let reserved = env.create_with(NewIssue {
        title: "for dave".into(),
        priority: Some(0),
        assignee: Some("dave".into()),
        ..Default::default()
    });
    let pooled = env.create_with(NewIssue {
        title: "pool".into(),
        priority: Some(1),
        assignee: Some("crew".into()),
        ..Default::default()
    });
    env.store.write("config", "alice", |tx| config::set(tx, "claim.pools", "crew")).unwrap();

    let next = |env: &mut Env, who: &str| {
        env.store
            .write("claim", who, |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))
            .unwrap()
            .map(|c| c.issue.id)
    };
    assert_eq!(next(&mut env, "bob"), Some(high.clone()));
    assert_eq!(next(&mut env, "bob"), Some(pooled.clone()), "pool aliases are claimable by anyone");
    assert_eq!(next(&mut env, "bob"), Some(low.clone()), "issues reserved for dave are skipped");
    assert_eq!(next(&mut env, "bob"), None);
    assert_eq!(next(&mut env, "dave"), Some(reserved.clone()));
}

#[test]
fn claim_next_near_prefers_siblings_then_the_queue() {
    let mut env = Env::new();
    let parent = env.create("Parent", 2);
    let a = env.create_with(NewIssue {
        title: "a".into(),
        priority: Some(2),
        parent: Some(parent.clone()),
        ..Default::default()
    });
    let b = env.create_with(NewIssue {
        title: "b".into(),
        priority: Some(3),
        parent: Some(parent.clone()),
        ..Default::default()
    });
    let z = env.create("Unrelated, more urgent", 0);
    let near_next = |env: &mut Env, closing: &str, q: &ReadyQuery| {
        let closing = closing.to_string();
        env.store
            .write("close", "bob", |tx| {
                let near = tx.parent(&closing)?;
                tx.close_issue(&closing, &CloseOptions::default())?;
                tx.claim_next_near(q, near.as_deref(), &ClaimOptions::default())
            })
            .unwrap()
            .map(|(c, from)| (c.issue.id, from, c.lease.token))
    };

    // Siblings first, though z has a higher priority.
    let (got, from, token) = near_next(&mut env, &a, &ReadyQuery::default()).unwrap();
    assert_eq!((got.as_str(), from), (b.as_str(), NextFrom::Siblings));
    let lease = env.store.read(|r| r.lease(&b)).unwrap().unwrap();
    assert_eq!((lease.holder.as_str(), lease.token), ("bob", token));
    assert_eq!(env.issue(&b).status, Status::InProgress);

    // Bob finishes b: the subtree has nothing ready left, so the queue
    // decides (z before the newly ready parent, by priority).
    env.store.write("close", "bob", |tx| tx.close_issue(&b, &CloseOptions::default())).unwrap();
    let c = env.create_with(NewIssue {
        title: "c".into(),
        priority: Some(4),
        parent: Some(parent.clone()),
        assignee: Some("dave".into()),
        ..Default::default()
    });
    let q = ReadyQuery::default();
    let found = env.store.write("peek", "bob", |tx| tx.next_ready(&q, Some(&parent))).unwrap();
    let (issue, from) = found.unwrap();
    assert_eq!((issue.id.as_str(), from), (z.as_str(), NextFrom::Queue), "c is reserved for dave");

    // An explicit parent filter searches only that subtree: no fallback.
    let only_parent =
        ReadyQuery { filter: WorkFilter { parent: Some(parent.clone()), ..Default::default() }, ..Default::default() };
    let found = env.store.write("peek", "bob", |tx| tx.next_ready(&only_parent, Some(&z))).unwrap();
    assert!(found.is_none(), "{found:?}");
    let found = env.store.write("peek", "dave", |tx| tx.next_ready(&only_parent, None)).unwrap();
    assert_eq!(found.map(|(i, f)| (i.id, f)), Some((c.clone(), NextFrom::Queue)));
    env.assert_healthy();
}

#[test]
fn next_ready_writes_nothing_and_close_then_claim_rolls_back_together() {
    let mut env = Env::new();
    let parent = env.create("Parent", 2);
    let a = env.create_with(NewIssue { title: "a".into(), parent: Some(parent.clone()), ..Default::default() });
    let b = env.create_with(NewIssue { title: "b".into(), parent: Some(parent.clone()), ..Default::default() });

    let head = env.store.read(|r| r.event_head()).unwrap();
    let found = env.store.write("peek", "bob", |tx| tx.next_ready(&ReadyQuery::default(), Some(&parent))).unwrap();
    assert_eq!(found.map(|(i, f)| (i.id, f)), Some((a.clone(), NextFrom::Siblings)));
    assert_eq!(env.store.read(|r| r.event_head()).unwrap(), head, "next_ready emits no events");
    assert!(env.store.read(|r| r.lease(&a)).unwrap().is_none());
    assert_eq!(env.issue(&a).status, Status::Open);

    // Close and claim in one transaction, then fail: both roll back.
    let err = env
        .store
        .write("close", "bob", |tx| {
            tx.close_issue(&a, &CloseOptions::default())?;
            let claimed = tx.claim_next_near(&ReadyQuery::default(), Some(&parent), &ClaimOptions::default())?;
            assert_eq!(
                claimed.as_ref().map(|(c, f)| (c.issue.id.as_str(), *f)),
                Some((b.as_str(), NextFrom::Siblings))
            );
            Err::<(), _>(Error::invalid("a later batch line failed"))
        })
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err}");
    assert_eq!(env.issue(&a).status, Status::Open);
    assert_eq!(env.issue(&b).status, Status::Open);
    assert!(env.issue(&b).assignee.is_none());
    assert!(env.store.read(|r| r.lease(&b)).unwrap().is_none());
    assert_eq!(env.store.read(|r| r.event_head()).unwrap(), head);
    env.assert_healthy();
}

#[test]
fn heartbeat_extends_lease_and_detects_loss() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let claim = env.store.write("claim", "bob", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    env.clock.advance(Duration::from_secs(200));
    let lease = env.store.write("hb", "bob", |tx| tx.heartbeat(&a, Some(claim.lease.token), None)).unwrap();
    assert_eq!(lease.expires_at, env.clock.now().plus(Duration::from_secs(300)));
    assert_eq!(lease.renewals, 1);

    let err = env.store.write("hb", "bob", |tx| tx.heartbeat(&a, Some(claim.lease.token + 999), None)).unwrap_err();
    assert!(matches!(err, Error::LeaseLost { .. }));
    let err = env.store.write("hb", "carol", |tx| tx.heartbeat(&a, None, None)).unwrap_err();
    assert!(matches!(err, Error::LeaseLost { .. }));
    // Heartbeats do not bump the revision or write events.
    let rev = env.issue(&a).revision;
    let before = env.events().len();
    env.store.write("hb", "bob", |tx| tx.heartbeat(&a, None, None)).unwrap();
    assert_eq!(env.issue(&a).revision, rev);
    assert_eq!(env.events().len(), before);
}

#[test]
fn crashed_worker_is_reclaimed_after_grace() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 2);
    let crashed = env.store.write("claim", "worker-1", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    env.store.write("claim", "worker-2", |tx| tx.claim(&b, &ClaimOptions::default())).unwrap();

    // worker-2 keeps heartbeating; worker-1 died right after claiming.
    for _ in 0..3 {
        env.clock.advance(Duration::from_secs(240));
        env.store.write("hb", "worker-2", |tx| tx.heartbeat(&b, None, None)).unwrap();
    }
    // worker-1's lease expired at +300s and grace is 10m: at +720s it is not yet reclaimable.
    let none = env.store.write("reclaim", "reaper", |tx| tx.reclaim_expired(&ReclaimOptions::default())).unwrap();
    assert!(none.is_empty());
    env.clock.advance(Duration::from_secs(200));
    env.store.write("hb", "worker-2", |tx| tx.heartbeat(&b, None, None)).unwrap();
    let reclaimed = env.store.write("reclaim", "reaper", |tx| tx.reclaim_expired(&ReclaimOptions::default())).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].issue_id, a);
    assert_eq!(reclaimed[0].previous_holder, "worker-1");
    let issue = env.issue(&a);
    assert_eq!((issue.status, issue.assignee.clone()), (Status::Open, None));
    assert_eq!(env.issue(&b).status, Status::InProgress);

    // The zombie learns it lost the claim; its fenced close is refused.
    let err = env.store.write("hb", "worker-1", |tx| tx.heartbeat(&a, Some(crashed.lease.token), None)).unwrap_err();
    assert!(matches!(err, Error::LeaseLost { .. }));
    let next = env
        .store
        .write("claim", "worker-3", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))
        .unwrap()
        .unwrap();
    assert_eq!(next.issue.id, a);
    let err = env
        .store
        .write("close", "worker-1", |tx| {
            tx.close_issue(&a, &CloseOptions { token: Some(crashed.lease.token), ..Default::default() })
        })
        .unwrap_err();
    assert!(matches!(err, Error::LeaseLost { .. }));
    env.store
        .write("close", "worker-3", |tx| {
            tx.close_issue(&a, &CloseOptions { token: Some(next.lease.token), ..Default::default() })
        })
        .unwrap();
    env.assert_healthy();
}

#[test]
fn claim_next_auto_reclaims_stale_leases() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    env.store.write("claim", "dead", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    env.clock.advance(Duration::from_secs(301 + 600));
    let claim = env
        .store
        .write("claim", "alive", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))
        .unwrap()
        .unwrap();
    assert_eq!(claim.issue.id, a);
    assert_eq!(claim.issue.assignee.as_deref(), Some("alive"));
    let events = env.events();
    let n = events.len();
    assert_eq!((events[n - 2].op.as_str(), events[n - 1].op.as_str()), ("reclaimed", "claimed"));
    assert_eq!(events[n - 2].tx, events[n - 1].tx, "reclaim and claim share one transaction");
}

#[test]
fn suggest_next_names_what_claim_next_would_without_writing() {
    let mut env = Env::new();
    let dead = env.create("Held by a dead claim", 0);
    let lower = env.create("Lower priority", 2);
    env.store.write("claim", "dead", |tx| tx.claim(&dead, &ClaimOptions::default())).unwrap();
    env.clock.advance(Duration::from_secs(301 + 600));
    let before = env.events().len();
    let (issue, _) = env
        .store
        .write("close", "alive", |tx| tx.suggest_next(&ReadyQuery::default(), None))
        .unwrap()
        .expect("a suggestion");
    assert_eq!(issue.id, dead, "the dead claim's issue, reclaimed first by claim_next");
    assert_eq!(issue.assignee.as_deref(), Some("dead"), "as stored: nothing was reclaimed");
    assert_eq!(env.events().len(), before, "nothing written");
    assert_eq!(env.issue(&dead).status, Status::InProgress);
    let claim = env
        .store
        .write("claim", "alive", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))
        .unwrap()
        .unwrap();
    assert_eq!(claim.issue.id, issue.id, "the issue suggested");

    // With lease.auto_reclaim off, claim_next leaves dead claims alone, and so does the suggestion.
    let urgent = env.create("Urgent", 0);
    env.store.write("claim", "dead", |tx| tx.claim(&urgent, &ClaimOptions::default())).unwrap();
    env.clock.advance(Duration::from_secs(301 + 600));
    env.store.write("config", "alice", |tx| config::set(tx, "lease.auto_reclaim", "false")).unwrap();
    let next = env.store.write("close", "alive", |tx| tx.suggest_next(&ReadyQuery::default(), None)).unwrap();
    assert_eq!(next.map(|(i, _)| i.id), Some(lower));
}

#[test]
fn optimistic_concurrency_guards() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let rev = env.issue(&a).revision;
    let patch = IssuePatch { title: Some("A2".into()), ..Default::default() };
    let out = env
        .store
        .write("update", "alice", |tx| {
            tx.update_issue(&a, &patch, &Guard { if_revision: Some(rev), ..Default::default() }, false)
        })
        .unwrap();
    assert_eq!(out.issue.revision, rev + 1);
    assert_eq!(out.changed, vec!["title".to_string()]);

    // A writer holding the stale revision loses and writes nothing.
    let stale = IssuePatch { title: Some("lost update".into()), ..Default::default() };
    let err = env
        .store
        .write("update", "bob", |tx| {
            tx.update_issue(&a, &stale, &Guard { if_revision: Some(rev), ..Default::default() }, false)
        })
        .unwrap_err();
    assert_eq!(err.exit_code(), 13);
    assert_eq!(env.issue(&a).title, "A2");

    let err = env
        .store
        .write("update", "bob", |tx| {
            tx.update_issue(&a, &stale, &Guard { if_assignee: Some(Some("bob".into())), ..Default::default() }, false)
        })
        .unwrap_err();
    assert!(matches!(err, Error::Conflict { field: "assignee", .. }));
    env.store
        .write("update", "bob", |tx| {
            tx.update_issue(&a, &patch, &Guard { if_status: Some(Status::Open), ..Default::default() }, false)
        })
        .unwrap();

    // No-op updates do not bump the revision.
    let same = env.store.write("update", "alice", |tx| tx.update_issue(&a, &patch, &Guard::default(), false)).unwrap();
    assert!(same.changed.is_empty());
    assert_eq!(same.issue.revision, rev + 1);
}

#[test]
fn update_enforces_claim_invariants() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let err = env
        .store
        .write("u", "alice", |tx| {
            tx.update_issue(
                &a,
                &IssuePatch { status: Some(Status::InProgress), ..Default::default() },
                &Guard::default(),
                false,
            )
        })
        .unwrap_err();
    assert!(err.to_string().contains("assignee"));
    let err = env
        .store
        .write("u", "alice", |tx| {
            tx.update_issue(
                &a,
                &IssuePatch { status: Some(Status::Closed), ..Default::default() },
                &Guard::default(),
                false,
            )
        })
        .unwrap_err();
    assert!(err.to_string().contains("bd close"));

    // Assign-and-start on behalf of someone grants them a lease.
    let patch =
        IssuePatch { status: Some(Status::InProgress), assignee: Some(Some("erin".into())), ..Default::default() };
    env.store.write("u", "alice", |tx| tx.update_issue(&a, &patch, &Guard::default(), false)).unwrap();
    assert_eq!(env.store.read(|r| r.lease(&a)).unwrap().unwrap().holder, "erin");

    // Taking over a live claim needs force; the lease follows the assignee.
    let take = IssuePatch { assignee: Some(Some("frank".into())), ..Default::default() };
    let err = env.store.write("u", "frank", |tx| tx.update_issue(&a, &take, &Guard::default(), false)).unwrap_err();
    assert!(matches!(err, Error::AlreadyClaimed { .. }));
    env.store.write("u", "frank", |tx| tx.update_issue(&a, &take, &Guard::default(), true)).unwrap();
    assert_eq!(env.store.read(|r| r.lease(&a)).unwrap().unwrap().holder, "frank");

    // Moving out of in_progress drops the lease.
    let park = IssuePatch { status: Some(Status::Blocked), ..Default::default() };
    env.store.write("u", "frank", |tx| tx.update_issue(&a, &park, &Guard::default(), false)).unwrap();
    assert!(env.store.read(|r| r.lease(&a)).unwrap().is_none());
    env.assert_healthy();
}

#[test]
fn labels_metadata_and_reparenting() {
    let mut env = Env::new();
    let p1 = env.create("P1", 1);
    let p2 = env.create("P2", 1);
    let a = env.create_with(NewIssue {
        title: "A".into(),
        labels: vec!["backend".into(), " api ".into(), "backend".into()],
        parent: Some(p1.clone()),
        ..Default::default()
    });
    assert_eq!(env.issue(&a).labels, vec!["api".to_string(), "backend".to_string()]);
    let patch = IssuePatch {
        add_labels: vec!["urgent".into()],
        remove_labels: vec!["api".into()],
        set_metadata: vec![("team".into(), json!("core"))],
        parent: Some(Some(p2.clone())),
        ..Default::default()
    };
    let out = env.store.write("u", "alice", |tx| tx.update_issue(&a, &patch, &Guard::default(), false)).unwrap();
    assert_eq!(out.issue.labels, vec!["backend".to_string(), "urgent".to_string()]);
    assert_eq!(out.issue.metadata["team"], "core");
    let details = env.store.read(|r| r.details(&a)).unwrap();
    assert_eq!(details.parent.as_deref(), Some(p2.as_str()));
    let q = ListQuery {
        filter: WorkFilter { labels_all: vec!["urgent".into()], ..Default::default() },
        ..Default::default()
    };
    assert_eq!(env.store.read(|r| r.list(&q)).unwrap().len(), 1);
    let q = ListQuery { filter: WorkFilter { parent: Some(p1.clone()), ..Default::default() }, ..Default::default() };
    assert!(env.store.read(|r| r.list(&q)).unwrap().is_empty());
}

const DAY: Duration = Duration::from_secs(86_400);

fn ids_of(issues: Vec<Issue>) -> Vec<String> {
    let mut ids: Vec<String> = issues.into_iter().map(|i| i.id).collect();
    ids.sort();
    ids
}

#[test]
fn list_filters_by_time_and_title() {
    let mut env = Env::new();
    let a = env.create("Plan 50% done", 2);
    let d = env.create("Later", 2);
    let deferred = IssuePatch { status: Some(Status::Deferred), ..Default::default() };
    env.store.write("u", "alice", |tx| tx.update_issue(&d, &deferred, &Guard::default(), false)).unwrap();
    env.clock.advance(DAY);
    let b = env.create_with(NewIssue {
        due_at: Some(Timestamp(T0).plus(2 * DAY)),
        priority: Some(2),
        ..NewIssue::titled("Plan 50x done")
    });
    env.clock.advance(DAY);
    let c = env.create("Ship_it", 2);
    let x = env.create("Shipxit", 2);
    env.clock.advance(DAY);
    let notes = IssuePatch { notes: Some("touched".into()), ..Default::default() };
    env.store.write("u", "alice", |tx| tx.update_issue(&a, &notes, &Guard::default(), false)).unwrap();
    env.clock.advance(DAY);
    env.close(&c);
    env.clock.advance(DAY);
    let (ia, ib, ic) = (env.issue(&a), env.issue(&b), env.issue(&c));

    let list = |env: &Env, f: WorkFilter| {
        ids_of(env.store.read(|r| r.list(&ListQuery { all: true, filter: f, ..Default::default() })).unwrap())
    };
    let sorted = |v: &[&String]| {
        let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    };
    let w = WorkFilter::default;
    // `_after` is inclusive, `_before` exclusive.
    assert_eq!(list(&env, WorkFilter { created_after: Some(ib.created_at), ..w() }), sorted(&[&b, &c, &x]));
    assert_eq!(list(&env, WorkFilter { created_before: Some(ib.created_at), ..w() }), sorted(&[&a, &d]));
    assert_eq!(
        list(&env, WorkFilter { created_after: Some(ib.created_at), created_before: Some(ic.created_at), ..w() }),
        sorted(&[&b])
    );
    assert_eq!(list(&env, WorkFilter { updated_after: Some(ia.updated_at), ..w() }), sorted(&[&a, &c]));
    assert_eq!(list(&env, WorkFilter { updated_before: Some(ia.updated_at), ..w() }), sorted(&[&b, &d, &x]));
    let closed_at = ic.closed_at.unwrap();
    assert_eq!(list(&env, WorkFilter { closed_after: Some(closed_at), ..w() }), sorted(&[&c]));
    assert!(list(&env, WorkFilter { closed_before: Some(closed_at), ..w() }).is_empty());
    assert_eq!(
        list(&env, WorkFilter { closed_before: Some(closed_at.plus(Duration::from_millis(1))), ..w() }),
        sorted(&[&c])
    );
    // Stale: open or in progress only, so neither the deferred nor the closed issue.
    assert_eq!(list(&env, WorkFilter { stale_before: Some(ia.updated_at), ..w() }), sorted(&[&b, &x]));
    let now = env.store.read(|r| Ok(r.now())).unwrap();
    assert_eq!(list(&env, WorkFilter { stale_before: Some(now), ..w() }), sorted(&[&a, &b, &x]));
    // Title: ASCII case-insensitive, `%` and `_` literal.
    let title = |t: &str| list(&env, WorkFilter { title_contains: Some(t.into()), ..w() });
    assert_eq!(title("50%"), sorted(&[&a]));
    assert_eq!(title("plan 50"), sorted(&[&a, &b]));
    assert_eq!(title("p_i"), sorted(&[&c]));
    assert_eq!(title("  "), list(&env, w()));
    assert!(title("\\").is_empty());
    // Overdue: due in the past and not closed.
    assert_eq!(list(&env, WorkFilter { overdue_at: Some(now), ..w() }), sorted(&[&b]));
    assert!(list(&env, WorkFilter { overdue_at: Some(Timestamp(T0)), ..w() }).is_empty());
    env.close(&b);
    assert!(list(&env, WorkFilter { overdue_at: Some(now), ..w() }).is_empty());
}

#[test]
fn ready_filters_by_time() {
    let mut env = Env::new();
    let old = env.create("Old", 0);
    env.clock.advance(DAY);
    let low = env.create("Low", 3);
    let high = env.create_with(NewIssue { due_at: Some(Timestamp(T0)), priority: Some(1), ..NewIssue::titled("High") });
    env.clock.advance(DAY);
    let cutoff = env.issue(&low).created_at;
    let ready = |f: WorkFilter| env.ready_ids_with(&ReadyQuery { filter: f, ..Default::default() });
    // Queue order (priority) is kept.
    assert_eq!(ready(WorkFilter { created_after: Some(cutoff), ..Default::default() }), [high.as_str(), low.as_str()]);
    assert_eq!(ready(WorkFilter { created_before: Some(cutoff), ..Default::default() }), [old.as_str()]);
    assert_eq!(ready(WorkFilter { updated_after: Some(cutoff), ..Default::default() }), [high.as_str(), low.as_str()]);
    assert_eq!(ready(WorkFilter { updated_before: Some(cutoff), ..Default::default() }), [old.as_str()]);
    let now = env.store.read(|r| Ok(r.now())).unwrap();
    assert_eq!(ready(WorkFilter { overdue_at: Some(now), ..Default::default() }), [high.as_str()]);
    assert_eq!(ready(WorkFilter { stale_before: Some(cutoff), ..Default::default() }), [old.as_str()]);
    assert_eq!(ready(WorkFilter { title_contains: Some("LOW".into()), ..Default::default() }), [low.as_str()]);
}

fn under(title: &str, parent: &str) -> NewIssue {
    NewIssue { parent: Some(parent.to_string()), ..NewIssue::titled(title) }
}

fn epic(title: &str) -> NewIssue {
    NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled(title) }
}

#[test]
fn epic_status_counts_the_subtree() {
    let mut env = Env::new();
    let e = env.create_with(epic("Epic"));
    let a = env.create_with(under("A", &e));
    let b = env.create_with(under("B", &e));
    let a1 = env.create_with(under("A1", &a));
    let a2 = env.create_with(under("A2", &a));
    let x = env.create("Outside blocker", 1);
    let empty = env.create_with(epic("Empty"));
    env.dep(&a2, &x, DepType::Blocks);
    env.store.write("claim", "bob", |tx| tx.claim(&b, &ClaimOptions::default())).unwrap();
    env.close(&a1);
    let status = |env: &Env, id: &str| env.store.read(|r| r.epic_status(id)).unwrap();
    let counts = |s: &hierarchy::EpicStatus| (s.total, s.closed, s.open, s.in_progress, s.blocked, s.percent);

    let s = status(&env, &e);
    assert_eq!((s.id.as_str(), s.title.as_str(), s.issue_type.as_str()), (e.as_str(), "Epic", "epic"));
    assert_eq!(counts(&s), (4, 1, 2, 1, 1, Some(25)));
    assert!(!s.close_eligible);
    // Any issue's subtree, not only an epic's; never eligible unless an epic.
    let sa = status(&env, &a);
    assert_eq!(counts(&sa), (2, 1, 1, 0, 1, Some(50)));
    assert!(!sa.close_eligible);
    let none = status(&env, &empty);
    assert_eq!(counts(&none), (0, 0, 0, 0, 0, None));
    assert!(!none.close_eligible, "an epic without children is not eligible");
    assert!(matches!(env.store.read(|r| r.epic_status("t-404")), Err(Error::NotFound { .. })));

    env.close(&x);
    env.close(&a2);
    env.close(&a);
    // A closed, B still in progress: 3 of 4 closed, floored.
    let s = status(&env, &e);
    assert_eq!(counts(&s), (4, 3, 0, 1, 0, Some(75)));
    assert!(!s.close_eligible);
    assert!(env.store.read(|r| r.close_eligible_epics()).unwrap().is_empty());
    // The last direct child closes: eligible, as `bd stats` says.
    env.store.write("close", "bob", |tx| tx.close_issue(&b, &CloseOptions::default())).unwrap();
    let s = status(&env, &e);
    assert_eq!(counts(&s), (4, 4, 0, 0, 0, Some(100)));
    assert!(s.close_eligible);
    assert_eq!(env.store.read(|r| r.close_eligible_epics()).unwrap(), [e.as_str()]);
    assert_eq!(env.store.read(|r| r.stats()).unwrap().closable_epics, [e.as_str()]);
    let open: Vec<String> = env.store.read(|r| r.epics(false)).unwrap().into_iter().map(|s| s.id).collect();
    assert_eq!(open, [e.as_str(), empty.as_str()]);

    env.close(&e);
    assert!(!status(&env, &e).close_eligible, "closed already");
    let open: Vec<String> = env.store.read(|r| r.epics(false)).unwrap().into_iter().map(|s| s.id).collect();
    assert_eq!(open, [empty.as_str()]);
    let all: Vec<String> = env.store.read(|r| r.epics(true)).unwrap().into_iter().map(|s| s.id).collect();
    assert_eq!(all, [e.as_str(), empty.as_str()]);
    let json = serde_json::to_value(status(&env, &e)).unwrap();
    assert_eq!(
        json,
        json!({"id": e, "title": "Epic", "status": "closed", "issue_type": "epic", "total": 4, "closed": 4,
               "open": 0, "in_progress": 0, "blocked": 0, "percent": 100, "close_eligible": false})
    );
    assert_eq!(serde_json::to_value(status(&env, &empty)).unwrap()["percent"], json!(null));
}

#[test]
fn children_direct_and_recursive() {
    let mut env = Env::new();
    let p = env.create("Parent", 2);
    let c1 = env.create_with(under("C1", &p));
    let g = env.create_with(under("Grandchild", &c1));
    let c2 = env.create_with(under("C2", &p));
    env.create("Unrelated", 2);
    env.close(&c2);
    let children = |id: &str, recursive: bool| {
        env.store.read(|r| r.child_issues(id, recursive)).unwrap().into_iter().map(|i| i.id).collect::<Vec<_>>()
    };
    // Creation order, closed ones too.
    assert_eq!(children(&p, false), [c1.as_str(), c2.as_str()]);
    assert_eq!(children(&p, true), [c1.as_str(), g.as_str(), c2.as_str()]);
    assert_eq!(children(&c1, false), [g.as_str()]);
    assert!(children(&g, true).is_empty());
    assert!(matches!(env.store.read(|r| r.child_issues("t-404", false)), Err(Error::NotFound { .. })));
}

#[test]
fn children_come_in_creation_order_after_an_import() {
    // Rows out of creation order, so rowid (import) order differs from it.
    let mut env = Env::new();
    let row = |id: &str, day: u32, parent: &str| {
        let deps = if parent.is_empty() {
            String::new()
        } else {
            format!(
                r#","dependencies":[{{"issue_id":"{id}","depends_on_id":"{parent}","type":"parent-child","created_at":"2026-01-0{day}T00:00:00Z","created_by":"alice","metadata":"{{}}"}}]"#
            )
        };
        format!(
            r#"{{"_type":"issue","id":"{id}","title":"{id}","status":"open","priority":2,"issue_type":"task","created_at":"2026-01-0{day}T00:00:00Z","updated_at":"2026-01-0{day}T00:00:00Z"{deps}}}"#
        ) + "\n"
    };
    let jsonl = [
        row("t-p", 1, ""),
        row("t-late", 5, "t-p"),
        row("t-grand", 4, "t-late"),
        row("t-mid", 3, "t-p"),
        row("t-early", 2, "t-p"),
    ]
    .concat();
    env.store.write("import", "me", |tx| tx.import_jsonl(&mut jsonl.as_bytes(), &ImportOptions::default())).unwrap();
    let children = |recursive: bool| {
        env.store.read(|r| r.child_issues("t-p", recursive)).unwrap().into_iter().map(|i| i.id).collect::<Vec<_>>()
    };
    assert_eq!(children(false), ["t-early", "t-mid", "t-late"]);
    assert_eq!(children(true), ["t-early", "t-mid", "t-grand", "t-late"]);
}

#[test]
fn stale_flags_old_work_and_expired_leases() {
    let mut env = Env::new();
    let old = env.create("Old", 2);
    let closed = env.create("Old but closed", 2);
    env.close(&closed);
    let deferred = env.create("Old but deferred", 2);
    let patch = IssuePatch { status: Some(Status::Deferred), ..Default::default() };
    env.store.write("u", "alice", |tx| tx.update_issue(&deferred, &patch, &Guard::default(), false)).unwrap();
    env.clock.advance(10 * DAY);
    let fresh = env.create("Fresh", 2);
    let claimed = env.create("Claimed", 2);
    let held = env.create("Held", 2);
    env.store.write("claim", "bob", |tx| tx.claim(&claimed, &ClaimOptions::default())).unwrap();
    // Past the 5m lease: bob's lease expired, carol's (taken later) did not.
    env.clock.advance(Duration::from_secs(240));
    env.store.write("claim", "carol", |tx| tx.claim(&held, &ClaimOptions::default())).unwrap();
    env.clock.advance(Duration::from_secs(120));
    let now = env.store.read(|r| Ok(r.now())).unwrap();
    let rows = env.store.read(|r| r.stale(7 * DAY, None)).unwrap();
    let ids: Vec<&str> = rows.iter().map(|s| s.issue.id.as_str()).collect();
    assert_eq!(ids, [old.as_str(), claimed.as_str()], "least recently updated first");
    assert!(rows[0].stale && rows[0].lease_holder.is_none() && rows[0].lease_expired_at.is_none());
    assert!(!rows[1].stale, "updated recently, but its lease expired");
    assert_eq!(rows[1].lease_holder.as_deref(), Some("bob"));
    let expired = rows[1].lease_expired_at.unwrap();
    assert!(expired <= now && expired > now.minus(Duration::from_secs(120)));
    let json = serde_json::to_value(&rows[1]).unwrap();
    assert_eq!((json["id"].as_str(), json["stale"].as_bool()), (Some(claimed.as_str()), Some(false)));
    assert_eq!(json["lease_holder"], json!("bob"));
    assert!(serde_json::to_value(&rows[0]).unwrap().get("lease_holder").is_none());

    assert_eq!(env.store.read(|r| r.stale(7 * DAY, Some(1))).unwrap().len(), 1);
    // Nothing is older than no time at all: every live issue, held or not.
    let all: Vec<String> =
        env.store.read(|r| r.stale(Duration::ZERO, None)).unwrap().into_iter().map(|s| s.issue.id).collect();
    assert_eq!(all, [old.as_str(), fresh.as_str(), claimed.as_str(), held.as_str()]);
}

#[test]
fn orphans_find_dangling_text_references() {
    let mut env = Env::new();
    let one = env.create("Parent", 2);
    assert_eq!(one, "t-1");
    let two = env.create_with(NewIssue {
        description: "see t-99, and t-1. also (t-1), t-1.5 and t-1.5.2; xt-98, t-, bd-7 and t-99 again".into(),
        design: "t-99".into(),
        ..NewIssue::titled("Second")
    });
    let three = env.create("Fix t-42 (after t-2)", 2);
    env.store.write("c", "alice", |tx| tx.add_comment(&one, "blocked on t-77, not t-3")).unwrap();
    env.store.write("c", "alice", |tx| tx.add_comment(&one, "still t-77")).unwrap();
    let found = env.store.read(|r| r.orphans("t")).unwrap();
    let json = serde_json::to_value(&found).unwrap();
    assert_eq!(
        json,
        json!([
            {"id": one, "title": "Parent", "references": [{"id": "t-77", "field": "comment"}]},
            {"id": two, "title": "Second", "references": [
                {"id": "t-99", "field": "description"}, {"id": "t-99", "field": "design"}]},
            {"id": three, "title": "Fix t-42 (after t-2)", "references": [{"id": "t-42", "field": "title"}]},
        ])
    );
    // Another prefix: only its own references.
    let bd = env.store.read(|r| r.orphans("bd")).unwrap();
    assert_eq!(bd.len(), 1);
    assert_eq!((bd[0].id.as_str(), bd[0].references[0].id.as_str()), (two.as_str(), "bd-7"));
    assert!(env.store.read(|r| r.orphans("t x")).is_err());
    assert!(env.store.read(|r| r.orphans("")).is_err());
    // Creating the issue named settles the references to it.
    for n in 4..=99 {
        env.create(&format!("Filler {n}"), 2);
    }
    let left: Vec<String> = env.store.read(|r| r.orphans("t")).unwrap().into_iter().map(|o| o.id).collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn subgraph_walks_up_and_down_and_truncates() {
    use bd_core::subgraph::EdgeSet;
    let mut env = Env::new();
    let ids: Vec<String> = (1..=12).map(|n| env.create(&format!("N{n}"), 2)).collect();
    let id = |n: usize| ids[n - 1].clone();
    // A chain 1 <- 2 <- 3, a diamond 3 <- {4, 5} <- 6, 3 a child of 12,
    // 7 a child of 2 and 11 after 1 (reached only by turning around),
    // 9 after 8 (unrelated) and 10 related to 3.
    for (issue, target, t) in [
        (2, 1, DepType::Blocks),
        (3, 2, DepType::Blocks),
        (4, 3, DepType::Blocks),
        (5, 3, DepType::Blocks),
        (6, 4, DepType::Blocks),
        (6, 5, DepType::Blocks),
        (3, 12, DepType::ParentChild),
        (7, 2, DepType::ParentChild),
        (11, 1, DepType::Blocks),
        (9, 8, DepType::Blocks),
        (10, 3, DepType::Related),
    ] {
        env.dep(&id(issue), &id(target), t);
    }
    let walk = |root: usize, edges: &EdgeSet, max: usize| env.store.read(|r| r.subgraph(Some(&id(root)), edges, max));
    let node_ids = |g: &bd_core::subgraph::Subgraph| g.nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>();
    let sorted = |ns: &[usize]| {
        let mut v: Vec<String> = ns.iter().map(|n| id(*n)).collect();
        v.sort();
        v
    };

    let g = walk(3, &EdgeSet::Default, 200).unwrap();
    assert_eq!(g.root.as_deref(), Some(id(3).as_str()));
    assert_eq!(node_ids(&g), sorted(&[1, 2, 3, 4, 5, 6, 12]), "ancestors and descendants, nothing beside");
    assert!(!g.truncated);
    let edges: Vec<(String, String, String)> =
        g.edges.iter().map(|e| (e.depends_on.clone(), e.issue.clone(), e.dep_type.to_string())).collect();
    let e = |d: usize, i: usize, t: &str| (id(d), id(i), t.to_string());
    assert_eq!(
        edges,
        [
            e(1, 2, "blocks"),
            e(12, 3, "parent-child"),
            e(2, 3, "blocks"),
            e(3, 4, "blocks"),
            e(3, 5, "blocks"),
            e(4, 6, "blocks"),
            e(5, 6, "blocks"),
        ]
    );
    let json = serde_json::to_value(&g).unwrap();
    assert_eq!(json["edges"][0], json!({"issue": id(2), "depends_on": id(1), "type": "blocks"}));
    assert_eq!(json["max_nodes"], 200);
    assert_eq!(json["nodes"][0]["status"], "open");

    // Related links only when asked for; blocks alone drops the parent.
    assert_eq!(node_ids(&walk(3, &EdgeSet::All, 200).unwrap()), sorted(&[1, 2, 3, 4, 5, 6, 10, 12]));
    let blocks = walk(3, &EdgeSet::Only(vec![DepType::Blocks]), 200).unwrap();
    assert_eq!(node_ids(&blocks), sorted(&[1, 2, 3, 4, 5, 6]));
    assert!(blocks.edges.iter().all(|e| e.dep_type == DepType::Blocks));

    // Truncated in (distance, id) order: 12 sorts before 2 at distance 1.
    let small = walk(3, &EdgeSet::Default, 2).unwrap();
    assert_eq!(node_ids(&small), sorted(&[3, 12]));
    assert!(small.truncated);
    assert_eq!(small.edges.len(), 1);
    assert_eq!(walk(3, &EdgeSet::Default, 2).unwrap().nodes, small.nodes, "deterministic");
    assert_eq!(node_ids(&walk(3, &EdgeSet::Default, 1).unwrap()), [id(3)]);
    assert!(matches!(env.store.read(|r| r.subgraph(Some("t-404"), &EdgeSet::Default, 5)), Err(Error::NotFound { .. })));

    // Every open issue: closed ones left out, truncated past the bound.
    env.close(&id(8));
    let open = env.store.read(|r| r.subgraph(None, &EdgeSet::Default, 200)).unwrap();
    assert_eq!(open.root, None);
    assert_eq!(open.nodes.len(), 11);
    assert!(!open.nodes.iter().any(|n| n.id == id(8)) && !open.truncated);
    assert!(!open.edges.iter().any(|e| e.issue == id(8) || e.depends_on == id(8)));
    let few = env.store.read(|r| r.subgraph(None, &EdgeSet::Default, 3)).unwrap();
    assert_eq!(node_ids(&few), [id(1), id(10), id(11)], "id order");
    assert!(few.truncated);
    assert_eq!(few.edges.len(), 1, "11 after 1: {:?}", few.edges);
}

#[test]
fn delete_protects_dependents_unless_forced_or_cascaded() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 1);
    let c = env.create("C", 1);
    env.dep(&b, &a, DepType::Blocks);
    env.dep(&c, &b, DepType::Blocks);
    let err = env
        .store
        .write("del", "alice", |tx| tx.delete_issues(std::slice::from_ref(&a), &DeleteOptions::default()))
        .unwrap_err();
    assert!(matches!(err, Error::Refused(_)));
    let preview = env
        .store
        .write("del", "alice", |tx| {
            tx.delete_issues(
                std::slice::from_ref(&a),
                &DeleteOptions { cascade: true, dry_run: true, ..Default::default() },
            )
        })
        .unwrap();
    assert_eq!(preview.deleted, vec![a.clone(), b.clone(), c.clone()]);
    let out = env
        .store
        .write("del", "alice", |tx| {
            tx.delete_issues(std::slice::from_ref(&a), &DeleteOptions { force: true, ..Default::default() })
        })
        .unwrap();
    assert_eq!(out.detached, vec![b.clone()]);
    assert!(!env.issue(&b).is_blocked, "dropping the edge unblocks the dependent");
    let history = env.store.read(|r| r.history(&a)).unwrap();
    assert_eq!(history.last().unwrap().op, "deleted", "history survives deletion");
    env.assert_healthy();
}

#[test]
fn comments_and_memories() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    env.store.write("c", "bob", |tx| tx.add_comment(&a, "first")).unwrap();
    env.store.write("c", "carol", |tx| tx.add_comment(&a, "second")).unwrap();
    let comments = env.store.read(|r| r.comments(&a)).unwrap();
    let pairs: Vec<(&str, &str)> = comments.iter().map(|c| (c.author.as_str(), c.text.as_str())).collect();
    assert_eq!(pairs, vec![("bob", "first"), ("carol", "second")]);
    assert_eq!(env.issue(&a).revision, 1, "comments do not bump the revision");

    let w = env.store.write("m", "bob", |tx| tx.remember(None, "Always run tests with -race flag", None)).unwrap();
    assert_eq!(w.memory.key, "always-run-tests-with-race-flag");
    assert_eq!(w.action, MemoryAction::Created);
    let w2 = env.store.write("m", "carol", |tx| tx.remember(Some(&w.memory.key), "Use -race", Some(1))).unwrap();
    assert_eq!((w2.action, w2.memory.revision, w2.memory.updated_by.as_str()), (MemoryAction::Updated, 2, "carol"));
    let err = env.store.write("m", "bob", |tx| tx.remember(Some(&w.memory.key), "stale write", Some(1))).unwrap_err();
    assert_eq!(err.exit_code(), 13);
    let err = env.store.write("m", "bob", |tx| tx.remember(Some(&w.memory.key), "create only", Some(0))).unwrap_err();
    assert!(matches!(err, Error::Conflict { .. }));
    assert_eq!(env.store.read(|r| r.memories(Some("RACE"))).unwrap().len(), 1);
    assert!(env.store.write("m", "bob", |tx| tx.forget(&w.memory.key)).unwrap().is_some());
    assert!(env.store.read(|r| r.memories(None)).unwrap().is_empty());
}

#[test]
fn comments_tail_is_chronological_and_counted() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    for n in 0..5 {
        env.clock.advance(Duration::from_millis(1));
        env.store.write("c", "bob", |tx| tx.add_comment(&a, &format!("note {n}"))).unwrap();
    }
    // Two comments in the same millisecond keep their insertion order.
    env.store.write("c", "bob", |tx| tx.add_comment(&a, "note 5")).unwrap();
    let (tail, total) = env.store.read(|r| r.comments_tail(&a, 3)).unwrap();
    let texts: Vec<&str> = tail.iter().map(|c| c.text.as_str()).collect();
    assert_eq!((texts, total), (vec!["note 3", "note 4", "note 5"], 6));
    let (none, total) = env.store.read(|r| r.comments_tail(&a, 0)).unwrap();
    assert_eq!((none.len(), total), (0, 6));
    let (all, _) = env.store.read(|r| r.comments_tail(&a, 50)).unwrap();
    assert_eq!(all, env.store.read(|r| r.comments(&a)).unwrap());
}

#[test]
fn briefs_carry_the_parent_and_leave_out_the_rest() {
    let mut env = Env::new();
    let p = env.create("Parent", 1);
    let c = env.create_with(NewIssue {
        parent: Some(p.clone()),
        labels: vec!["infra".into()],
        description: "long text".into(),
        ..NewIssue::titled("Child")
    });
    let issues = vec![env.issue(&p), env.issue(&c)];
    let briefs = env.store.read(|r| r.briefs(&issues)).unwrap();
    assert_eq!(briefs[0].parent, None);
    assert_eq!(briefs[1].parent.as_deref(), Some(p.as_str()));
    let v = serde_json::to_value(&briefs[1]).unwrap();
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, BTreeSet::from(["id", "title", "status", "priority", "issue_type", "parent", "labels"]));
    let v = serde_json::to_value(&briefs[0]).unwrap();
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, BTreeSet::from(["id", "title", "status", "priority", "issue_type"]));
}

#[test]
fn show_brief_cuts_the_description_and_names_blockers() {
    let mut env = Env::new();
    // 600 characters of two bytes each: a cut by bytes would split one.
    let description = "é".repeat(600);
    let a = env.create_with(NewIssue { description: description.clone(), ..NewIssue::titled("A") });
    let b = env.create("Blocker", 1);
    env.dep(&a, &b, DepType::Blocks);
    for n in 0..4 {
        env.clock.advance(Duration::from_millis(1));
        env.store.write("c", "bob", |tx| tx.add_comment(&a, &format!("note {n}"))).unwrap();
    }
    let s = env.store.read(|r| r.show_brief(&a, 3)).unwrap();
    assert!(s.description_truncated);
    assert_eq!(s.description, format!("{}…", "é".repeat(BRIEF_DESCRIPTION_CHARS)));
    assert_eq!(s.blockers, vec![b.clone()]);
    let texts: Vec<&str> = s.comments.iter().map(|c| c.text.as_str()).collect();
    assert_eq!((texts, s.comments_total), (vec!["note 1", "note 2", "note 3"], 4));
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["description_truncated"], json!(true));
    assert_eq!(v["blockers"], json!([b]));
    assert!(v.get("metadata").is_none() && v.get("created_at").is_none());

    // A short description is kept whole and not flagged; no blockers or
    // comments leave their keys out.
    let short =
        env.create_with(NewIssue { description: "é".repeat(BRIEF_DESCRIPTION_CHARS), ..NewIssue::titled("S") });
    let s = env.store.read(|r| r.show_brief(&short, 3)).unwrap();
    assert!(!s.description_truncated);
    assert_eq!(s.description.chars().count(), BRIEF_DESCRIPTION_CHARS);
    let v = serde_json::to_value(&s).unwrap();
    for key in ["description_truncated", "blockers", "comments"] {
        assert!(v.get(key).is_none(), "{key} should be left out");
    }
    assert_eq!(v["comments_total"], json!(0));
}

/// A recompute stops at the closed, unblocked issues below what changed:
/// closing a hierarchy bottom-up in one transaction, then blocking its root,
/// gives the flags and events of a walk through every descendant.
#[test]
fn recompute_stops_at_closed_descendants() {
    let mut env = Env::new();
    let child = |env: &mut Env, title: &str, parent: &str| {
        env.create_with(NewIssue { title: title.into(), parent: Some(parent.into()), ..Default::default() })
    };
    let x = env.create("blocker", 1);
    let r = env.create("root", 1);
    let a = child(&mut env, "a", &r);
    let b = child(&mut env, "b", &a);
    let c = child(&mut env, "c", &b);
    let d = child(&mut env, "d", &c);
    let s = child(&mut env, "closed with a live child", &r);
    let s1 = child(&mut env, "live below a closed parent", &s);
    let w = env.create("waiter", 1);
    env.dep(&w, &b, DepType::WaitsFor);
    env.dep(&a, &x, DepType::Blocks);
    let force = CloseOptions { force: true, ..Default::default() };
    env.store.write("close", "alice", |tx| tx.close_issue(&s, &force)).unwrap();
    let y = env.create("late blocker", 1);
    let since = env.events().last().unwrap().seq;

    env.store
        .write("close", "alice", |tx| {
            for id in [&x, &d, &c, &b] {
                tx.close_issue(id, &CloseOptions::default())?;
            }
            tx.add_dependency(&r, &y, DepType::Blocks, None)
        })
        .unwrap();

    let got: Vec<(String, String)> =
        env.events().into_iter().filter(|e| e.seq > since).map(|e| (e.op, e.issue_id.unwrap_or_default())).collect();
    let want: Vec<(String, String)> = [
        ("closed", &x),
        ("unblocked", &a),
        ("unblocked", &b),
        ("unblocked", &c),
        ("unblocked", &d),
        ("closed", &d),
        ("closed", &c),
        ("unblocked", &w),
        ("closed", &b),
        ("dep_added", &r),
        ("blocked", &r),
        ("blocked", &a),
    ]
    .into_iter()
    .map(|(op, id)| (op.to_string(), id.clone()))
    .collect();
    assert_eq!(got, want);
    assert!(env.issue(&a).is_blocked);
    assert!(!env.issue(&s1).is_blocked);
    assert!(!env.issue(&d).is_blocked);
    env.assert_healthy();
}

#[test]
fn events_are_gapless_transactional_and_prunable() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let head_before = env.store.read(|r| r.event_head()).unwrap();
    // A failed transaction writes nothing and burns no sequence numbers.
    let _ = env.store.write("bad", "alice", |tx| -> Result<()> {
        tx.add_comment(&a, "will roll back")?;
        Err(Error::invalid("boom"))
    });
    assert_eq!(env.store.read(|r| r.event_head()).unwrap(), head_before);
    env.store.write("c", "alice", |tx| tx.add_comment(&a, "kept")).unwrap();
    let events = env.events();
    for pair in events.windows(2) {
        assert_eq!(pair[1].seq, pair[0].seq + 1, "gapless");
    }
    // A single transaction groups its events under one tx id.
    let b = env.create("B", 1);
    env.dep(&b, &a, DepType::Blocks);
    let out = env.close(&a);
    assert_eq!(out.unblocked.len(), 1);
    let last = env.events();
    let tail: Vec<&Event> = last.iter().rev().take(2).collect();
    assert_eq!(tail[0].op, "unblocked");
    assert_eq!(tail[1].op, "closed");
    assert_eq!(tail[0].tx, tail[1].tx);

    let head = env.store.read(|r| r.event_head()).unwrap();
    let pruned = env
        .store
        .write("prune", "alice", |tx| tx.prune_events(&PruneOptions { keep: Some(3), ..Default::default() }))
        .unwrap();
    assert!(pruned.deleted > 0);
    let err = env.store.read(|r| r.events(&EventQuery { since: Some(1), ..Default::default() })).unwrap_err();
    assert!(matches!(err, Error::EventsTruncated { .. }));
    let page = env.store.read(|r| r.events(&EventQuery { since: Some(head - 1), ..Default::default() })).unwrap();
    assert_eq!(page.events.first().unwrap().seq, head);
    env.assert_healthy();
}

#[test]
fn export_import_round_trip() {
    let mut env = Env::new();
    let a = env.create_with(NewIssue { title: "A".into(), labels: vec!["x".into()], ..Default::default() });
    let b = env.create("B", 0);
    env.dep(&b, &a, DepType::Blocks);
    env.store.write("c", "bob", |tx| tx.add_comment(&a, "note")).unwrap();
    env.store.write("m", "bob", |tx| tx.remember(Some("k1"), "remember me", None)).unwrap();
    env.store.write("claim", "bob", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    let mut buf = Vec::new();
    let summary = env.store.read(|r| r.export_jsonl(&mut buf, &ExportOptions::default())).unwrap();
    assert_eq!((summary.issues, summary.dependencies, summary.comments, summary.memories), (2, 1, 1, 1));

    let mut other = Env::new();
    let result = other
        .store
        .write("import", "importer", |tx| tx.import_jsonl(&mut buf.as_slice(), &ImportOptions::default()))
        .unwrap();
    assert_eq!(
        (result.created, result.dependencies, result.comments, result.memories, result.leases_granted),
        (2, 1, 1, 1, 1)
    );
    assert!(other.issue(&b).is_blocked);
    assert_eq!(other.issue(&a).labels, vec!["x".to_string()]);
    assert_eq!(other.store.read(|r| r.lease(&a)).unwrap().unwrap().holder, "bob");
    // Re-importing is idempotent.
    let again = other
        .store
        .write("import", "importer", |tx| tx.import_jsonl(&mut buf.as_slice(), &ImportOptions::default()))
        .unwrap();
    assert_eq!((again.created, again.updated, again.unchanged, again.comments), (0, 0, 2, 0));
    other.assert_healthy();
}

#[test]
fn imports_beads_export_format() {
    let mut env = Env::new();
    let beads = r#"{"_type":"issue","id":"bd-a1","title":"Epic","status":"open","priority":1,"issue_type":"epic","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","owner":"x@y","dependency_count":0}
{"_type":"issue","id":"bd-a1.1","title":"Child","status":"closed","priority":2,"issue_type":"task","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","closed_at":"2026-01-02T00:00:00Z","close_reason":"Done","labels":["l"],"dependencies":[{"issue_id":"bd-a1.1","depends_on_id":"bd-a1","type":"parent-child","created_at":"2026-01-01T00:00:00Z","created_by":"alice","metadata":"{}"}],"comments":[{"id":"u1","issue_id":"bd-a1.1","author":"alice","text":"hi","created_at":"2026-01-01T00:00:00Z"}]}
{"_type":"issue","id":"bd-b2","title":"Hooked work","status":"hooked","assignee":"agent","priority":2,"issue_type":"task","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
{"_type":"memory","key":"dolt-phantoms","value":"Phantom DBs hide in three places"}
"#;
    let out = env
        .store
        .write("import", "me", |tx| tx.import_jsonl(&mut beads.as_bytes(), &ImportOptions::default()))
        .unwrap();
    assert_eq!((out.created, out.dependencies, out.comments, out.memories), (3, 1, 1, 1));
    let details = env.store.read(|r| r.details("bd-a1.1")).unwrap();
    assert_eq!(details.parent.as_deref(), Some("bd-a1"));
    assert_eq!(details.issue.status, Status::Closed);
    assert_eq!(env.issue("bd-b2").status, Status::InProgress);
    // beads' owner has no column: kept in metadata.beads. Derived counts are dropped.
    let epic = env.issue("bd-a1");
    assert_eq!(epic.metadata["beads"], json!({ "owner": "x@y" }));
    assert_eq!(out.fields["owner"].kept, 1);
    assert_eq!(out.fields["dependency_count"].dropped, 1);
    assert_eq!(
        env.store.read(|r| r.memory("dolt-phantoms")).unwrap().unwrap().content,
        "Phantom DBs hide in three places"
    );
    env.assert_healthy();
}

#[test]
fn doctor_detects_and_repairs_drift() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 1);
    env.dep(&b, &a, DepType::Blocks);
    env.store.write("claim", "bob", |tx| tx.claim(&a, &ClaimOptions::default())).unwrap();
    env.store.connection().execute("UPDATE issues SET is_blocked = 0 WHERE id = ?1", [&b]).unwrap();
    env.store.connection().execute("DELETE FROM leases WHERE issue_id = ?1", [&a]).unwrap();
    let report = doctor::diagnose(&mut env.store, false, false).unwrap();
    assert!(!report.ok);
    let failing: BTreeSet<&str> =
        report.checks.iter().filter(|c| c.severity == doctor::Severity::Error).map(|c| c.name).collect();
    assert_eq!(failing, BTreeSet::from(["blocked_state", "claims_have_leases"]));
    let fixed = doctor::diagnose(&mut env.store, true, false).unwrap();
    assert!(fixed.ok);
    assert!(env.issue(&b).is_blocked);
    env.assert_healthy();
}

#[test]
fn concurrent_workers_claim_each_issue_exactly_once() {
    let mut env = Env::new();
    for i in 0..60 {
        env.create(&format!("job {i}"), (i % 5) as u8);
    }
    let workers = 8;
    let barrier = Arc::new(Barrier::new(workers));
    let handles: Vec<_> = (0..workers)
        .map(|w| {
            let mut store = env.open_another();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let actor = format!("worker-{w}");
                let mut mine = Vec::new();
                while let Some(claim) = store
                    .write("claim", &actor, |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))
                    .unwrap()
                {
                    let id = claim.issue.id.clone();
                    let opts = CloseOptions { token: Some(claim.lease.token), ..Default::default() };
                    store.write("close", &actor, |tx| tx.close_issue(&id, &opts)).unwrap();
                    mine.push(id);
                }
                mine
            })
        })
        .collect();
    let mut all: Vec<String> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let total = all.len();
    all.sort();
    all.dedup();
    assert_eq!(total, 60, "every issue claimed");
    assert_eq!(all.len(), 60, "no issue claimed twice");
    let events = env.events();
    assert_eq!(events.iter().filter(|e| e.op == "claimed").count(), 60);
    for pair in events.windows(2) {
        assert_eq!(pair[1].seq, pair[0].seq + 1);
    }
    env.assert_healthy();
}

#[test]
fn snapshots_are_verified_self_contained_copies() {
    let mut env = Env::new();
    let id = env.create("Survives the restore", 1);
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("copy.db");
    env.store.snapshot(&copy).unwrap();
    env.create("After the snapshot", 2);
    let names: Vec<String> =
        std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, vec!["copy.db"], "one file, no -wal or -shm");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "only the owner may read a copy of everything: {mode:o}");
    }

    let err = env.store.snapshot(&copy).unwrap_err();
    assert_eq!(err.exit_code(), 2, "never overwrites: {err}");
    assert!(copy.is_file(), "the existing file is left alone");

    let restored = Store::open(&copy, OpenOptions::default()).unwrap();
    let titles: Vec<String> =
        restored.read(|r| r.list(&ListQuery::default())).unwrap().into_iter().map(|i| i.title).collect();
    assert_eq!(titles, vec!["Survives the restore"]);
    assert_eq!(restored.read(|r| r.issue(&id)).unwrap().priority, 1);
    assert_eq!(restored.meta("workspace_id").unwrap(), env.store.meta("workspace_id").unwrap());
}

#[test]
fn cycles_in_a_damaged_database_are_each_listed_once() {
    let mut env = Env::new();
    let edges = [
        ("c-a", "c-b", "blocks"),
        ("c-b", "c-c", "blocks"),
        ("c-c", "c-a", "blocks"),
        ("c-b", "c-d", "parent-child"),
        ("c-d", "c-b", "parent-child"),
        ("c-c", "c-e", "conditional-blocks"),
        ("c-e", "c-f", "conditional-blocks"),
        ("c-f", "c-c", "blocks"),
        ("c-g", "c-a", "blocks"),
        ("c-f", "c-g", "related"),
    ];
    // Plain SQL: adding these edges is refused. Then a chain of 200,000
    // issues, each blocking the one before and blocked by it.
    const LEVELS: i64 = 200_000;
    env.store
        .write("damage", "alice", |tx| {
            for id in ["c-a", "c-b", "c-c", "c-d", "c-e", "c-f", "c-g"] {
                tx.conn().execute(
                    "INSERT INTO issues (id, title, created_at, updated_at) VALUES (?1, ?1, ?2, ?2)",
                    (id, T0),
                )?;
            }
            for (a, b, t) in edges {
                tx.conn().execute(
                    "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at) VALUES (?1, ?2, ?3, ?4)",
                    (a, b, t, T0),
                )?;
            }
            let chain = "WITH RECURSIVE n(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
                INSERT INTO issues (id, title, created_at, updated_at)
                SELECT printf('d-%06d', k), 'Level ' || k, ?2, ?2 FROM n";
            tx.conn().execute(chain, (LEVELS, T0))?;
            let both_ways = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < ?1)
                INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
                SELECT printf('d-%06d', k), printf('d-%06d', k - 1), 'blocks', ?2 FROM n
                UNION ALL SELECT printf('d-%06d', k - 1), printf('d-%06d', k), 'blocks', ?2 FROM n";
            tx.conn().execute(both_ways, (LEVELS, T0))?;
            Ok(())
        })
        .unwrap();
    let started = std::time::Instant::now();
    let cycles = env.store.read(|r| r.cycles()).unwrap();
    let took = started.elapsed();
    let ids = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(cycles[..3], [ids(&["c-a", "c-b", "c-c"]), ids(&["c-b", "c-d"]), ids(&["c-c", "c-e", "c-f"])]);
    assert_eq!(cycles.len(), 3 + LEVELS as usize);
    for (k, cycle) in cycles[3..].iter().enumerate() {
        assert_eq!(*cycle, [format!("d-{k:06}"), format!("d-{:06}", k + 1)]);
    }
    // Each cycle cost a scan of the whole path: minutes in a debug build.
    assert!(took < Duration::from_secs(60), "dep cycles took {took:?}");
}

#[test]
fn batched_event_pages_are_the_whole_pages() {
    let mut env = Env::new();
    let a = env.create("A", 1);
    let b = env.create("B", 2);
    env.close(&a);
    env.store
        .write("create", "bob", |tx| tx.create_issue(NewIssue { title: "C".into(), ..Default::default() }))
        .unwrap();
    env.dep(&b, &a, DepType::Blocks);
    let head = env.events().last().unwrap().seq;
    let mut queries = Vec::new();
    for since in [None, Some(0), Some(2), Some(head), Some(head + 5)] {
        for limit in [None, Some(0), Some(1), Some(3), Some(100)] {
            queries.push(EventQuery { since, limit, ..Default::default() });
        }
        queries.push(EventQuery { since, issue_id: Some(a.clone()), ..Default::default() });
        queries.push(EventQuery { since, ops: vec!["created".into()], limit: Some(2), ..Default::default() });
        queries.push(EventQuery { since, actor: Some("bob".into()), ..Default::default() });
    }
    let each = |store: &Store, q: &EventQuery, batch: usize| {
        store.read(|r| {
            let mut got: Vec<Event> = Vec::new();
            let (head, floor) = r.events_each(q, batch, &mut |events| {
                assert!(!events.is_empty() && events.len() <= batch.max(1), "{} in a batch of {batch}", events.len());
                got.extend_from_slice(events);
                Ok(())
            })?;
            Ok((got, head, floor))
        })
    };
    for q in &queries {
        let page = env.store.read(|r| r.events(q)).unwrap();
        for batch in [0, 1, 2, 3, 1000] {
            let (got, head, floor) = each(&env.store, q, batch).unwrap();
            let seqs = |events: &[Event]| events.iter().map(|e| e.seq).collect::<Vec<_>>();
            assert_eq!(seqs(&got), seqs(&page.events), "{q:?} in batches of {batch}");
            assert_eq!((head, floor), (page.head, page.floor), "{q:?}");
        }
    }

    // A cursor behind retained history fails the same way.
    let opts = PruneOptions { before: Some(4), ..Default::default() };
    env.store.write("prune", "alice", |tx| tx.prune_events(&opts)).unwrap();
    let behind = EventQuery { since: Some(1), ..Default::default() };
    assert!(matches!(env.store.read(|r| r.events(&behind)), Err(Error::EventsTruncated { .. })));
    assert!(matches!(each(&env.store, &behind, 2), Err(Error::EventsTruncated { .. })));
}

#[test]
fn a_writer_past_the_busy_timeout_is_told_the_database_is_busy() {
    let mut env = Env::new();
    env.create("First", 2);
    let writer = rusqlite::Connection::open(&env.path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let opts = OpenOptions { clock: env.clock.clone(), busy_timeout: Duration::from_millis(50), ..Default::default() };
    let mut other = Store::open(&env.path, opts).unwrap();
    let e = other.write("create", "bob", |tx| tx.create_issue(NewIssue::titled("Second"))).unwrap_err();
    assert_eq!((e.code(), e.exit_code()), ("busy", 5), "{e}");
    assert!(e.to_string().starts_with("database is busy: timed out after"), "{e}");
    writer.execute_batch("COMMIT").unwrap();
}

// ---------------------------------------------------------------------------
// Renaming the issue prefix

fn rename(env: &mut Env, to: &str, from: Option<&str>) -> Result<RenamePrefixOutcome> {
    env.clock.advance(Duration::from_millis(10));
    let o = RenamePrefixOptions { to: to.into(), from: from.map(String::from) };
    env.store.write("rename-prefix", "alice", |tx| tx.rename_prefix(&o))
}

/// Every edge as (issue, depends on, type, metadata), in order.
fn edges(env: &Env) -> Vec<(String, String, String, serde_json::Value)> {
    env.store
        .read(|r| {
            let mut stmt = r.conn().prepare(
                "SELECT issue_id, depends_on_id, dep_type, metadata FROM dependencies ORDER BY issue_id, depends_on_id",
            )?;
            let rows = stmt.query_map([], |row| {
                let meta: String = row.get(3)?;
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, serde_json::from_str(&meta).unwrap()))
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap()
}

fn all_ids(env: &Env) -> Vec<String> {
    let all = ListQuery { all: true, ..Default::default() };
    let mut ids: Vec<String> = env.store.read(|r| r.list(&all)).unwrap().into_iter().map(|i| i.id).collect();
    ids.sort();
    ids
}

fn prefix(env: &Env) -> String {
    env.store.read(|r| config::prefix(r.conn())).unwrap()
}

fn head(env: &Env) -> i64 {
    env.store.read(|r| r.event_head()).unwrap()
}

#[test]
fn rename_prefix_moves_ids_edges_claims_events_and_references() {
    let mut env = Env::new();
    let parent = env.create("Parent", 1);
    let c1 = env.create_with(NewIssue { parent: Some(parent.clone()), ..NewIssue::titled("Child 1") });
    let c2 = env.create_with(NewIssue { parent: Some(parent.clone()), ..NewIssue::titled("Child 2") });
    assert_eq!((c1.as_str(), c2.as_str()), ("t-1.1", "t-1.2"));
    let two = env.create_with(NewIssue { labels: vec!["infra".into()], ..NewIssue::titled("Two") });
    let three = env.create_with(NewIssue {
        description: "After t-1.2 lands (and t-2), not t-10 or xt-1.".into(),
        ..NewIssue::titled("Three")
    });
    assert_eq!((two.as_str(), three.as_str()), ("t-2", "t-3"));
    env.store
        .write("dep", "alice", |tx| {
            tx.add_dependency(&three, &two, DepType::Blocks, Some(json!({"why": "t-2", "note": "t-1-notes"})))
        })
        .unwrap();
    env.store.write("comment", "alice", |tx| tx.add_comment(&parent, "blocked on t-2")).unwrap();
    env.store.write("remember", "alice", |tx| tx.remember(Some("plan"), "see t-1.", None)).unwrap();
    let claim = env.store.write("claim", "bob", |tx| tx.claim(&two, &ClaimOptions::default())).unwrap();

    let map = |id: &str| id.replacen("t-", "new-", 1);
    let edges_before = edges(&env);
    let blocked_before: Vec<(String, bool)> =
        all_ids(&env).into_iter().map(|id| (map(&id), env.issue(&id).is_blocked)).collect();
    let history_before: Vec<i64> = env.store.read(|r| r.history(&parent)).unwrap().iter().map(|e| e.seq).collect();
    let revision_before = env.issue(&parent).revision;
    let head_before = head(&env);

    let out = rename(&mut env, "new", None).unwrap();
    assert_eq!((out.from.as_str(), out.to.as_str()), ("t", "new"));
    assert_eq!((out.renamed, out.kept, out.claims), (5, 0, 1));
    assert_eq!(out.metadata, 1, "the edge naming t-2");
    // Issue t-3's description, the comment and the memory.
    assert_eq!(out.text, 3);
    assert_eq!(out.examples[0], ("t-1".to_string(), "new-1".to_string()));

    // One transaction, recording the new prefix and the rename.
    let appended: Vec<Event> = env.events().into_iter().filter(|e| e.seq > head_before).collect();
    assert!(appended.iter().all(|e| e.tx == appended[0].tx), "{appended:#?}");
    let ops: Vec<&str> = appended.iter().map(|e| e.op.as_str()).collect();
    assert_eq!(ops, ["references_renamed", "config_set", "prefix_renamed"]);
    // The rewritten text of the issue naming renamed ids, as old and new.
    let references = &appended[0];
    assert_eq!(references.issue_id.as_deref(), Some("new-3"));
    assert_eq!(
        references.data["changes"]["description"],
        json!({
            "old": "After t-1.2 lands (and t-2), not t-10 or xt-1.",
            "new": "After new-1.2 lands (and new-2), not t-10 or xt-1.",
        })
    );
    let summary = &appended[2];
    assert_eq!(summary.issue_id, None);
    assert_eq!((summary.data["from"].as_str(), summary.data["to"].as_str()), (Some("t"), Some("new")));
    assert_eq!(summary.data["renamed"], 5);

    // Ids: the new ones, children included, and none of the old.
    assert_eq!(all_ids(&env), ["new-1", "new-1.1", "new-1.2", "new-2", "new-3"]);
    assert!(matches!(env.store.read(|r| r.issue("t-1")), Err(Error::NotFound { .. })));
    assert_eq!(prefix(&env), "new");
    assert_eq!(env.issue("new-1").revision, revision_before, "revisions are left alone");

    // Edges (types and metadata kept, the id in the metadata renamed) and blocked flags.
    let expected: Vec<_> = edges_before
        .iter()
        .map(|(a, b, t, m)| {
            let m = if a == "t-3" { json!({"why": "new-2", "note": "t-1-notes"}) } else { m.clone() };
            (map(a), map(b), t.clone(), m)
        })
        .collect();
    assert_eq!(edges(&env), expected);
    assert!(!edges(&env).iter().any(|(a, b, _, _)| a.starts_with("t-") || b.starts_with("t-")));
    let blocked_after: Vec<(String, bool)> = all_ids(&env)
        .into_iter()
        .map(|id| {
            let b = env.issue(&id).is_blocked;
            (id, b)
        })
        .collect();
    assert_eq!(blocked_after, blocked_before);
    assert!(env.issue("new-3").is_blocked);

    // Labels, comments, memories and text.
    assert_eq!(env.issue("new-2").labels, ["infra"]);
    let comments = env.store.read(|r| r.comments("new-1")).unwrap();
    assert_eq!(comments.iter().map(|c| c.text.as_str()).collect::<Vec<_>>(), ["blocked on new-2"]);
    assert_eq!(env.store.read(|r| r.memory("plan")).unwrap().unwrap().content, "see new-1.");
    assert_eq!(env.issue("new-3").description, "After new-1.2 lands (and new-2), not t-10 or xt-1.");

    // History moved with the issue, and events' id fields were renamed.
    let history_after: Vec<Event> = env.store.read(|r| r.history("new-1")).unwrap();
    let seqs: Vec<i64> = history_after.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, history_before);
    assert!(env.store.read(|r| r.history("t-1")).unwrap().is_empty());
    let dep_added = env.events().into_iter().find(|e| e.op == "dep_added" && e.issue_id.as_deref() == Some("new-3"));
    let dep_added = dep_added.expect("the blocks edge's event");
    assert!(!dep_added.data.to_string().contains("\"t-2\""), "{}", dep_added.data);

    // The live claim goes on under the new id with the same token.
    let lease = env.store.read(|r| r.lease("new-2")).unwrap().expect("lease moved");
    assert_eq!(
        (lease.holder.as_str(), lease.token, lease.expires_at),
        ("bob", claim.lease.token, claim.lease.expires_at)
    );
    let issue = env.issue("new-2");
    assert_eq!((issue.status, issue.assignee.as_deref()), (Status::InProgress, Some("bob")));
    env.store.write("heartbeat", "bob", |tx| tx.heartbeat("new-2", Some(claim.lease.token), None)).unwrap();

    // Nothing dangles, and child ids go on where they were.
    let dangling = env
        .store
        .read(|r| Ok(r.conn().prepare("PRAGMA foreign_key_check")?.query_map([], |_| Ok(()))?.count()))
        .unwrap();
    assert_eq!(dangling, 0);
    env.assert_healthy();
    let next = env.create_with(NewIssue { parent: Some("new-1".into()), ..NewIssue::titled("Child 3") });
    assert_eq!(next, "new-1.3");
    assert!(env.create("Fresh", 2).starts_with("new-"));
}

#[test]
fn rename_prefix_rewrites_issue_gates_which_still_resolve() {
    let mut env = Env::new();
    let upstream = env.create("Upstream", 1);
    let mut gate_ids = Vec::new();
    for await_id in [upstream.clone(), format!("rig:{upstream}")] {
        // Work of its own, so neither gate waits for the other.
        let work = env.create("Work", 1);
        let mut spec = gates::GateSpec::new(gates::GateKind::Issue);
        spec.await_id = Some(await_id);
        let gate = env
            .store
            .write("gate", "alice", |tx| {
                tx.create_gate(gates::NewGate {
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
        gate_ids.push(gate.id);
    }
    rename(&mut env, "new", None).unwrap();
    let gate_ids: Vec<String> = gate_ids.iter().map(|id| id.replacen("t-", "new-", 1)).collect();
    let awaited: Vec<String> =
        gate_ids.iter().map(|id| env.issue(id).metadata["gate"]["await_id"].as_str().unwrap().to_string()).collect();
    assert_eq!(awaited, ["new-1", "rig:new-1"]);
    assert!(env.issue(&gate_ids[0]).title.starts_with("Wait for new-1"), "{}", env.issue(&gate_ids[0]).title);

    let verdicts = |env: &Env| -> Vec<Option<gates::Verdict>> {
        gate_ids
            .iter()
            .map(|id| {
                env.store.read(|r| gates::evaluate_local(r.conn(), &gates::view(r.conn(), id)?, r.now())).unwrap()
            })
            .collect()
    };
    assert!(verdicts(&env).iter().all(|v| matches!(v, Some(gates::Verdict::Pending(_)))), "{:?}", verdicts(&env));
    env.close("new-1");
    assert!(verdicts(&env).iter().all(|v| matches!(v, Some(gates::Verdict::Resolve(_)))), "{:?}", verdicts(&env));
    env.assert_healthy();
}

#[test]
fn rename_prefix_refuses_ids_that_belong_to_other_issues() {
    let mut env = Env::new();
    env.create("Mine", 1);
    env.create_with(NewIssue { id: Some("x-1".into()), ..NewIssue::titled("Theirs") });
    let head_before = head(&env);
    let err = rename(&mut env, "x", None).unwrap_err();
    assert!(matches!(&err, Error::Invalid(m) if m.contains("x-1")), "{err}");
    assert_eq!(all_ids(&env), ["t-1", "x-1"]);
    assert_eq!(prefix(&env), "t");
    assert_eq!(head(&env), head_before);
    env.assert_healthy();
}

#[test]
fn rename_prefix_to_a_longer_nested_prefix_keeps_ids_that_have_it() {
    let mut env = Env::new();
    let one = env.create_with(NewIssue { id: Some("bd-1".into()), ..NewIssue::titled("Old") });
    let seven = env.create_with(NewIssue { id: Some("bd-sync-7".into()), ..NewIssue::titled("New") });
    env.dep(&one, &seven, DepType::Blocks);
    env.create("Other", 2);
    let out = rename(&mut env, "bd-sync", Some("bd")).unwrap();
    assert_eq!((out.renamed, out.kept), (1, 1));
    assert_eq!(all_ids(&env), ["bd-sync-1", "bd-sync-7", "t-1"]);
    assert_eq!(prefix(&env), "bd-sync");
    let deps: Vec<String> =
        env.store.read(|r| graph::dependencies_of(r.conn(), "bd-sync-1")).unwrap().into_iter().map(|e| e.id).collect();
    assert_eq!(deps, ["bd-sync-7"]);
    env.assert_healthy();
}

#[test]
fn rename_prefix_to_a_shorter_nested_prefix_renames_chained_ids() {
    let mut env = Env::new();
    let q = env.create_with(NewIssue { id: Some("bd-sync-q".into()), ..NewIssue::titled("Q") });
    let qq = env.create_with(NewIssue { id: Some("bd-sync-sync-q".into()), ..NewIssue::titled("QQ") });
    env.dep(&qq, &q, DepType::Blocks);
    let out = rename(&mut env, "bd", Some("bd-sync")).unwrap();
    assert_eq!((out.renamed, out.kept), (2, 0));
    assert_eq!(all_ids(&env), ["bd-q", "bd-sync-q"]);
    assert_eq!(env.issue("bd-q").title, "Q");
    assert_eq!(env.issue("bd-sync-q").title, "QQ");
    let deps: Vec<String> =
        env.store.read(|r| graph::dependencies_of(r.conn(), "bd-sync-q")).unwrap().into_iter().map(|e| e.id).collect();
    assert_eq!(deps, ["bd-q"]);
    assert!(env.issue("bd-sync-q").is_blocked);
    env.assert_healthy();
}

#[test]
fn rename_prefix_needs_an_admin_policy() {
    let mut env = Env::new();
    env.create("One", 1);
    let o = RenamePrefixOptions { to: "new".into(), from: None };
    let policy = |admin| Policy { actor: "alice".into(), admin, human: false, max_claims: None };
    let err = env
        .store
        .write("rename-prefix", "alice", |tx| {
            tx.set_policy(Some(policy(false)));
            tx.rename_prefix(&o)
        })
        .unwrap_err();
    assert!(matches!(err, Error::Unauthorized(_)), "{err}");
    assert_eq!(all_ids(&env), ["t-1"]);
    env.store
        .write("rename-prefix", "alice", |tx| {
            tx.set_policy(Some(policy(true)));
            tx.rename_prefix(&o)
        })
        .unwrap();
    assert_eq!(all_ids(&env), ["new-1"]);
}

#[test]
fn rename_prefix_to_the_same_prefix_does_nothing() {
    let mut env = Env::new();
    env.create("One", 1);
    let head_before = head(&env);
    let out = rename(&mut env, " T- ", None).unwrap();
    assert_eq!(out, RenamePrefixOutcome { from: "t".into(), to: "t".into(), ..Default::default() });
    assert!(!out.prefix_set);
    assert_eq!(head(&env), head_before);
    assert_eq!(all_ids(&env), ["t-1"]);
    assert!(matches!(rename(&mut env, "Not valid!", None), Err(Error::Invalid(_))));
}

#[test]
fn rename_prefix_from_the_new_prefix_only_sets_issue_prefix() {
    let mut env = Env::new();
    env.create("One", 1);
    env.store.write("config", "alice", |tx| config::set(tx, "issue_prefix", "q")).unwrap();
    let head_before = head(&env);
    let out = rename(&mut env, "t", Some("t")).unwrap();
    assert_eq!((out.renamed, out.prefix_set), (0, true));
    assert_eq!(prefix(&env), "t");
    assert_eq!(all_ids(&env), ["t-1"]);
    let appended: Vec<Event> = env.events().into_iter().filter(|e| e.seq > head_before).collect();
    let ops: Vec<&str> = appended.iter().map(|e| e.op.as_str()).collect();
    assert_eq!(ops, ["config_set"]);
    // Again: now a full no-op.
    let head_before = head(&env);
    let out = rename(&mut env, "t", Some("t")).unwrap();
    assert!(!out.prefix_set);
    assert_eq!(head(&env), head_before);
}

#[test]
fn rename_prefix_rewrites_a_gate_awaiting_a_unique_partial_id() {
    let mut env = Env::new();
    let awaited = env.create_with(NewIssue { id: Some("t-ab12x".into()), ..NewIssue::titled("Upstream") });
    let work = env.create("Work", 1);
    let mut spec = gates::GateSpec::new(gates::GateKind::Issue);
    spec.await_id = Some("t-ab12".into());
    let gate = env
        .store
        .write("gate", "alice", |tx| {
            tx.create_gate(gates::NewGate {
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
    let out = rename(&mut env, "new", None).unwrap();
    assert!(out.prefix_set);
    let gate_id = gate.id.replacen("t-", "new-", 1);
    assert_eq!(env.issue(&gate_id).metadata["gate"]["await_id"], "new-ab12x");
    let verdict = |env: &Env| {
        env.store.read(|r| gates::evaluate_local(r.conn(), &gates::view(r.conn(), &gate_id)?, r.now())).unwrap()
    };
    assert!(matches!(verdict(&env), Some(gates::Verdict::Pending(_))), "{:?}", verdict(&env));
    env.close(&awaited.replacen("t-", "new-", 1));
    assert!(matches!(verdict(&env), Some(gates::Verdict::Resolve(_))), "{:?}", verdict(&env));
    env.assert_healthy();
}

fn explain(env: &Env, id: &str, opts: ExplainOptions) -> Readiness {
    env.store.read(|r| r.explain(id, opts)).unwrap()
}

fn texts(env: &Env, id: &str, reasons: &[NotReady]) -> Vec<String> {
    let now = env.clock.now();
    reasons.iter().map(|r| r.text(id, now)).collect()
}

#[test]
fn explain_names_status_claims_and_excluded_types() {
    let mut env = Env::new();
    let task = env.create("Task", 2);
    assert_eq!(
        explain(&env, &task, ExplainOptions::default()),
        Readiness { id: task.clone(), ready: true, reasons: vec![] }
    );

    // A claim: its status, and the lease while live, expired, then reclaimable (never its token).
    let claim = env.store.write("claim", "agent-a", |tx| tx.claim(&task, &ClaimOptions::default())).unwrap();
    let why = explain(&env, &task, ExplainOptions::default());
    assert!(!why.ready);
    let expires_at = claim.lease.expires_at;
    assert_eq!(
        why.reasons,
        [
            NotReady::Status { status: Status::InProgress },
            NotReady::Claimed { holder: "agent-a".into(), expires_at, live: true, reclaimable: false },
        ]
    );
    assert_eq!(
        texts(&env, &task, &why.reasons),
        ["status is in_progress".to_string(), format!("claimed by agent-a (lease expires {expires_at}, in 5m)")]
    );
    let json = serde_json::to_value(&why).unwrap();
    assert_eq!(json["reasons"][1]["kind"], "claimed");
    assert!(json["reasons"][1].get("token").is_none(), "{json}");
    // The claim path's words leave the lease out.
    assert_eq!(env.store.read(|r| r.not_ready_reasons(&task)).unwrap(), ["status is in_progress"]);
    env.clock.advance(Duration::from_secs(6 * 60));
    let why = explain(&env, &task, ExplainOptions::default());
    assert!(matches!(why.reasons[1], NotReady::Claimed { live: false, reclaimable: false, .. }));
    assert_eq!(
        texts(&env, &task, &why.reasons)[1],
        format!("claimed by agent-a (lease expired {expires_at}, reclaimable once lease.grace passes)")
    );
    env.clock.advance(Duration::from_secs(10 * 60));
    let why = explain(&env, &task, ExplainOptions::default());
    assert!(matches!(why.reasons[1], NotReady::Claimed { live: false, reclaimable: true, .. }));
    assert_eq!(
        texts(&env, &task, &why.reasons)[1],
        format!("claimed by agent-a (lease expired {expires_at}, reclaimable)")
    );

    // Closed.
    env.store
        .write("close", "agent-a", |tx| tx.close_issue(&task, &CloseOptions { take_over: true, ..Default::default() }))
        .unwrap();
    assert_eq!(explain(&env, &task, ExplainOptions::default()).reasons, [NotReady::Status { status: Status::Closed }]);

    // An epic, unless asked for.
    let epic =
        env.create_with(NewIssue { title: "Epic".into(), issue_type: Some("epic".into()), ..Default::default() });
    let why = explain(&env, &epic, ExplainOptions::default());
    assert_eq!(why.reasons, [NotReady::ExcludedType { issue_type: "epic".into() }]);
    assert_eq!(
        texts(&env, &epic, &why.reasons),
        ["epics are left out of the ready queue (--include-epics or -t epic)"]
    );
    assert_eq!(
        serde_json::to_value(&why.reasons[0]).unwrap(),
        json!({ "kind": "excluded_type", "issue_type": "epic" })
    );
    assert!(explain(&env, &epic, ExplainOptions { include_epics: true, ..Default::default() }).ready);
    assert!(
        env.store.read(|r| r.not_ready_reasons(&epic)).unwrap().is_empty(),
        "a type is no reason to refuse a claim"
    );

    // A gate, unless asked for.
    let held = env.create("Held", 2);
    let gate = env
        .store
        .write("gate", "alice", |tx| {
            tx.create_gate(gates::NewGate {
                spec: gates::GateSpec::new(gates::GateKind::Human),
                blocks: vec![held.clone()],
                title: None,
                description: String::new(),
                assignee: None,
                parent: None,
                priority: None,
                ephemeral: false,
            })
        })
        .unwrap()
        .id;
    let why = explain(&env, &gate, ExplainOptions::default());
    assert_eq!(why.reasons, [NotReady::ExcludedType { issue_type: "gate".into() }]);
    assert_eq!(
        texts(&env, &gate, &why.reasons),
        [format!("a gate: it opens through bd gate check or bd gate resolve {gate}, never as ready work")]
    );
    assert!(explain(&env, &gate, ExplainOptions { include_gates: true, ..Default::default() }).ready);
}

#[test]
fn explain_names_blockers_with_their_gates() {
    let mut env = Env::new();
    let blocker = env.create("Blocker", 2);
    let blocked = env.create("Blocked", 2);
    env.dep(&blocked, &blocker, DepType::Blocks);
    let maybe = env.create("Runs if the blocker fails", 2);
    env.dep(&maybe, &blocker, DepType::ConditionalBlocks);

    let why = explain(&env, &blocked, ExplainOptions::default());
    assert_eq!(
        why.reasons,
        [NotReady::Blocked {
            id: blocker.clone(),
            title: "Blocker".into(),
            status: Status::Open,
            via: BlockerKind::Blocks,
            detail: "blocker is open".into(),
            gate: None,
            root: None,
        }]
    );
    assert_eq!(texts(&env, &blocked, &why.reasons), [format!("blocked by {blocker} (blocker is open)")]);
    let kid = env.create_with(NewIssue { title: "Kid".into(), parent: Some(blocked.clone()), ..Default::default() });
    // The parent, blocked, is named (not its own blocker); the parent waits on its kid too.
    let why = explain(&env, &kid, ExplainOptions::default());
    assert!(
        matches!(&why.reasons[..], [NotReady::Blocked { id, via: BlockerKind::Parent, gate: None, .. }] if id == &blocked),
        "{why:?}"
    );
    assert_eq!(serde_json::to_value(&why.reasons[0]).unwrap()["via"], "parent");
    let root = RootCause { id: blocked.clone(), blockers: vec![blocker.clone()] };
    assert!(matches!(&why.reasons[..], [NotReady::Blocked { root: Some(r), .. }] if r == &root), "{why:?}");
    assert_eq!(texts(&env, &kid, &why.reasons), [format!("blocked by {blocked} (parent is blocked by {blocker})")]);
    // Further down, the parent is named and the ancestor actually blocked.
    let grandkid =
        env.create_with(NewIssue { title: "Grandkid".into(), parent: Some(kid.clone()), ..Default::default() });
    let why = explain(&env, &grandkid, ExplainOptions::default());
    assert!(
        matches!(&why.reasons[..], [NotReady::Blocked { id, via: BlockerKind::Parent, root: Some(r), .. }] if id == &kid && r == &root),
        "{why:?}"
    );
    assert_eq!(
        texts(&env, &grandkid, &why.reasons),
        [format!("blocked by {kid} (parent is blocked: ancestor {blocked} is blocked by {blocker})")]
    );
    let json = serde_json::to_value(&why.reasons[0]).unwrap();
    assert_eq!(json["root"], serde_json::json!({"id": blocked, "blockers": [blocker]}));
    let why = explain(&env, &maybe, ExplainOptions::default());
    assert!(matches!(&why.reasons[..], [NotReady::Blocked { via: BlockerKind::Conditional, gate: None, .. }]));

    // A gate issue that blocks: its kind.
    let held = env.create("Held", 2);
    let gate = env
        .store
        .write("gate", "alice", |tx| {
            tx.create_gate(gates::NewGate {
                spec: gates::GateSpec::new(gates::GateKind::Human),
                blocks: vec![held.clone()],
                title: None,
                description: String::new(),
                assignee: None,
                parent: None,
                priority: None,
                ephemeral: false,
            })
        })
        .unwrap()
        .id;
    let why = explain(&env, &held, ExplainOptions::default());
    assert!(
        matches!(&why.reasons[..], [NotReady::Blocked { id, via: BlockerKind::Blocks, gate: Some(g), .. }] if id == &gate && g == "human"),
        "{why:?}"
    );
    assert_eq!(serde_json::to_value(&why.reasons[0]).unwrap()["gate"], "human");

    // waits-for: the edge's gate, all-children when it names none.
    let spawner = env.create("Spawner", 2);
    env.create_with(NewIssue { title: "Spawned".into(), parent: Some(spawner.clone()), ..Default::default() });
    let any = env.create("Any", 2);
    let all = env.create("All", 2);
    env.store
        .write("dep", "alice", |tx| {
            tx.add_dependency(&any, &spawner, DepType::WaitsFor, Some(json!({ "gate": "any-children" })))
        })
        .unwrap();
    env.dep(&all, &spawner, DepType::WaitsFor);
    for (id, want) in [(&any, "any-children"), (&all, "all-children")] {
        let why = explain(&env, id, ExplainOptions::default());
        assert!(
            matches!(&why.reasons[..], [NotReady::Blocked { id: s, via: BlockerKind::WaitsFor, gate: Some(g), .. }] if s == &spawner && g == want),
            "{why:?}"
        );
    }
    // A spawner never waits on its children.
    assert!(explain(&env, &spawner, ExplainOptions::default()).ready);
}

#[test]
fn explain_names_deferrals_and_children() {
    let mut env = Env::new();
    let parent = env.create("Parent", 2);
    let kid = env.create_with(NewIssue { title: "Kid".into(), parent: Some(parent.clone()), ..Default::default() });
    let why = explain(&env, &parent, ExplainOptions::default());
    assert_eq!(
        why.reasons,
        [NotReady::WaitsOnChildren {
            open: 1,
            children: vec![OpenChild { id: kid.clone(), status: Status::Open, assignee: None }],
        }]
    );
    assert_eq!(
        texts(&env, &parent, &why.reasons),
        [format!(
            "its children come first, and 1 is open ({kid} open): claim one of them (`bd claim --next --parent {parent}`)"
        )]
    );
    assert_eq!(
        serde_json::to_value(&why.reasons[0]).unwrap(),
        json!({ "kind": "waits_on_children", "open": 1, "children": [{ "id": kid, "status": "open" }] })
    );

    let until = env.clock.now().plus(Duration::from_secs(3600));
    env.store.write("defer", "alice", |tx| tx.defer_issue(&parent, Some(until))).unwrap();
    let why = explain(&env, &kid, ExplainOptions::default());
    assert_eq!(why.reasons, [NotReady::Deferred { source: parent.clone(), until: Some(until) }]);
    assert_eq!(texts(&env, &kid, &why.reasons), [format!("ancestor {parent} is deferred until {until} (in 1h)")]);
    assert!(explain(&env, &kid, ExplainOptions { include_deferred: true, ..Default::default() }).ready);
    let why = explain(&env, &parent, ExplainOptions::default());
    assert!(
        matches!(&why.reasons[..], [NotReady::Deferred { source, .. }, NotReady::WaitsOnChildren { .. }] if source == &parent)
    );
    assert_eq!(texts(&env, &parent, &why.reasons[..1]), [format!("deferred until {until} (in 1h)")]);
    let solo = env.create("Solo", 2);
    env.store.write("defer", "alice", |tx| tx.defer_issue(&solo, None)).unwrap();
    let why = explain(&env, &solo, ExplainOptions::default());
    // An open-ended deferral is the status `deferred` too.
    assert_eq!(
        why.reasons,
        [NotReady::Status { status: Status::Deferred }, NotReady::Deferred { source: solo.clone(), until: None }]
    );
    assert_eq!(serde_json::to_value(&why.reasons[1]).unwrap(), json!({ "kind": "deferred", "source": solo }));
}

#[test]
fn not_ready_lists_the_open_issues_the_queue_leaves_out() {
    let mut env = Env::new();
    let blocker = env.create("Blocker", 3);
    let blocked = env.create("Blocked", 1);
    env.dep(&blocked, &blocker, DepType::Blocks);
    let parent = env.create("Parent", 0);
    let kid = env.create_with(NewIssue { title: "Kid".into(), parent: Some(parent.clone()), ..Default::default() });
    let later = env.create("Later", 2);
    env.store
        .write("defer", "alice", |tx| tx.defer_issue(&later, Some(env.clock.now().plus(Duration::from_secs(60)))))
        .unwrap();
    let epic =
        env.create_with(NewIssue { title: "Epic".into(), issue_type: Some("epic".into()), ..Default::default() });
    env.create_with(NewIssue {
        title: "Epic kid".into(),
        parent: Some(epic.clone()),
        priority: Some(4),
        ..Default::default()
    });
    let claimed = env.create("Claimed", 2);
    env.store.write("claim", "agent-a", |tx| tx.claim(&claimed, &ClaimOptions::default())).unwrap();

    let ids = |q: &ReadyQuery| -> Vec<String> {
        env.store.read(|r| r.not_ready(q)).unwrap().into_iter().map(|i| i.id).collect()
    };
    // By priority: open only, epics left out as in the queue.
    assert_eq!(ids(&ReadyQuery::default()), [parent.clone(), blocked.clone(), later.clone()]);
    assert_eq!(ids(&ReadyQuery { limit: Some(2), ..Default::default() }), [parent.clone(), blocked.clone()]);
    assert_eq!(ids(&ReadyQuery { include_deferred: true, ..Default::default() }), [parent.clone(), blocked.clone()]);
    assert_eq!(
        ids(&ReadyQuery { include_epics: true, ..Default::default() }),
        [parent.clone(), blocked.clone(), later.clone(), epic.clone()]
    );
    let under = WorkFilter { parent: Some(parent.clone()), ..Default::default() };
    assert!(ids(&ReadyQuery { filter: under, ..Default::default() }).is_empty(), "the kid is ready");
    assert!(env.ready_ids().contains(&kid) && env.ready_ids().contains(&blocker));
    env.clock.advance(Duration::from_secs(61));
    assert_eq!(ids(&ReadyQuery::default()), [parent, blocked]);
}

#[test]
fn order_keys_say_why_the_queue_is_in_its_order() {
    let mut env = Env::new();
    let id = env.create("Task", 1);
    let issue = env.issue(&id);
    let created = issue.created_at;
    let now = env.clock.now();
    assert_eq!(ready::order_key(&issue, SortPolicy::Priority, now), format!("P1, created {created}"));
    assert_eq!(ready::order_key(&issue, SortPolicy::Oldest, now), format!("created {created}"));
    assert_eq!(ready::order_key(&issue, SortPolicy::Hybrid, now), format!("recent (last 48h): P1, created {created}"));
    let later = now.plus(Duration::from_secs(49 * 3600));
    assert_eq!(ready::order_key(&issue, SortPolicy::Hybrid, later), format!("older: created {created}"));
}

fn close_as(
    env: &mut Env,
    actor: &str,
    id: &str,
    target: &str,
    kind: Replacement,
    opts: &CloseAsOptions,
) -> Result<CloseAsOutcome> {
    env.clock.advance(Duration::from_millis(10));
    env.store.write("close_as", actor, |tx| tx.close_as(id, target, kind, opts))
}

fn edges_of(env: &Env, id: &str) -> (Vec<Edge>, Vec<Edge>) {
    env.store.read(|r| Ok((r.dependencies(id)?, r.dependents(id)?))).unwrap()
}

#[test]
fn closing_as_a_duplicate_or_superseded_adds_the_edge_and_closes_in_one_transaction() {
    let mut env = Env::new();
    let canonical = env.create("Canonical", 1);
    let dup = env.create_with(NewIssue { title: "Dup".into(), labels: vec!["x".into()], ..Default::default() });
    let old = env.create("Old", 2);
    env.store.write("c", "alice", |tx| tx.add_comment(&dup, "a comment")).unwrap();
    let before_canonical = env.issue(&canonical);
    let before_edges = edges_of(&env, &canonical);

    let out =
        close_as(&mut env, "alice", &dup, &canonical, Replacement::Duplicate, &CloseAsOptions::default()).unwrap();
    assert!(!out.already);
    assert_eq!(out.dep_type, DepType::Duplicates);
    assert_eq!(out.target.id, canonical);
    assert_eq!(out.issue.status, Status::Closed);
    assert_eq!(out.issue.close_reason.as_deref(), Some(format!("duplicate of {canonical}").as_str()));
    assert_eq!(out.issue.close_outcome, Some(Outcome::Done));
    assert_eq!(out.issue.labels, vec!["x".to_string()]);
    let (down, _) = edges_of(&env, &dup);
    assert_eq!(down.len(), 1);
    assert_eq!((down[0].id.as_str(), &down[0].dep_type), (canonical.as_str(), &DepType::Duplicates));
    assert_eq!(env.store.read(|r| r.comments(&dup)).unwrap().len(), 1);

    let events = env.events();
    let added = events.iter().rev().find(|e| e.op == "dep_added").unwrap();
    let closed = events.iter().rev().find(|e| e.op == "closed").unwrap();
    assert_eq!(added.tx, closed.tx, "one transaction");
    assert_eq!(added.issue_id.as_deref(), Some(dup.as_str()));
    assert_eq!(closed.data["reason"], format!("duplicate of {canonical}"));
    assert_eq!(closed.data["outcome"], "done");

    let out =
        close_as(&mut env, "alice", &old, &canonical, Replacement::Supersede, &CloseAsOptions::default()).unwrap();
    assert_eq!(out.dep_type, DepType::Supersedes);
    assert_eq!(out.issue.close_reason.as_deref(), Some(format!("superseded by {canonical}").as_str()));
    let (down, _) = edges_of(&env, &old);
    assert_eq!((down[0].id.as_str(), &down[0].dep_type), (canonical.as_str(), &DepType::Supersedes));

    // The replacing issue is untouched: same revision, status and own edges.
    assert_eq!(env.issue(&canonical), before_canonical);
    let (down, up) = edges_of(&env, &canonical);
    assert_eq!(down, before_edges.0);
    assert_eq!(up.len(), 2, "only the two new incoming edges");
    env.assert_healthy();
}

#[test]
fn closing_as_a_duplicate_moves_nothing_else() {
    let mut env = Env::new();
    let canonical = env.create("Canonical", 1);
    let dup = env.create("Dup", 1);
    let child = env.create_with(NewIssue { title: "Child".into(), parent: Some(dup.clone()), ..Default::default() });
    let other = env.create("Other", 1);
    env.dep(&dup, &other, DepType::Related);

    let opts = CloseAsOptions::default();
    let e = close_as(&mut env, "alice", &dup, &canonical, Replacement::Duplicate, &opts).unwrap_err();
    assert!(matches!(e, Error::Refused(ref m) if m.contains("open child")), "{e}");
    assert_eq!(e.exit_code(), 2);
    assert_eq!(env.issue(&dup).status, Status::Open);
    assert_eq!(edges_of(&env, &dup).0.len(), 1, "the refused close rolled back its edge");

    let force = CloseAsOptions { force: true, ..Default::default() };
    close_as(&mut env, "alice", &dup, &canonical, Replacement::Duplicate, &force).unwrap();
    assert_eq!(env.issue(&child).status, Status::Open);
    assert_eq!(env.store.read(|r| r.details(&child)).unwrap().parent.as_deref(), Some(dup.as_str()));
    let (down, _) = edges_of(&env, &dup);
    let kinds: Vec<_> = down.iter().map(|e| (e.id.as_str(), e.dep_type.as_str())).collect();
    assert!(kinds.contains(&(other.as_str(), "related")) && kinds.contains(&(canonical.as_str(), "duplicates")));
    assert_eq!(edges_of(&env, &canonical).0.len(), 0);
    env.assert_healthy();
}

#[test]
fn closing_a_blocked_issue_as_a_duplicate_needs_force() {
    let mut env = Env::new();
    let canonical = env.create("Canonical", 1);
    let blocker = env.create("Blocker", 1);
    let dup = env.create("Dup", 1);
    env.dep(&dup, &blocker, DepType::Blocks);
    let e =
        close_as(&mut env, "alice", &dup, &canonical, Replacement::Duplicate, &CloseAsOptions::default()).unwrap_err();
    assert!(matches!(e, Error::Refused(ref m) if m.contains("blocked by")), "{e}");
    let force = CloseAsOptions { force: true, ..Default::default() };
    close_as(&mut env, "alice", &dup, &canonical, Replacement::Duplicate, &force).unwrap();
    env.assert_healthy();
}

#[test]
fn closing_as_a_duplicate_refuses_nonsense_and_writes_nothing() {
    let mut env = Env::new();
    let y = env.create("Y", 1);
    let x = env.create("X", 1);
    let z = env.create("Z", 1);
    let opts = CloseAsOptions::default();
    let head_before = head(&env);
    let refused = |env: &mut Env, id: &str, target: &str, kind: Replacement, code: i32, needle: &str| {
        let e = close_as(env, "alice", id, target, kind, &CloseAsOptions::default()).unwrap_err();
        assert_eq!(e.exit_code(), code, "{e}");
        assert!(e.to_string().contains(needle), "{e}");
    };

    refused(&mut env, &x, &x, Replacement::Duplicate, 2, "cannot be");
    refused(&mut env, &x, "t-999", Replacement::Duplicate, 3, "t-999");
    refused(&mut env, "t-999", &x, Replacement::Supersede, 3, "t-999");
    // Another type of edge between them is not replaced.
    env.dep(&x, &y, DepType::Blocks);
    refused(&mut env, &x, &y, Replacement::Duplicate, 2, "remove that edge first");
    assert_eq!(env.issue(&x).status, Status::Open);
    env.store.write("rm", "alice", |tx| tx.remove_dependency(&x, &y)).unwrap();
    // Nor one the other way: y blocked by x would be released by closing x.
    env.dep(&y, &x, DepType::Blocks);
    refused(
        &mut env,
        &x,
        &y,
        Replacement::Supersede,
        2,
        &format!("{y} already depends on {x} via blocks; remove that edge first"),
    );
    assert_eq!(env.issue(&x).status, Status::Open);
    env.store.write("rm", "alice", |tx| tx.remove_dependency(&y, &x)).unwrap();
    let head_before = head_before.max(head(&env));

    // The reverse edge of the same type.
    close_as(&mut env, "alice", &z, &x, Replacement::Duplicate, &opts).unwrap();
    let head_mid = head(&env);
    // z is closed as a duplicate of x: x cannot be a duplicate of z, and a
    // duplicate of the closed duplicate z is sent to its root.
    refused(&mut env, &x, &z, Replacement::Duplicate, 2, "already a duplicate of");
    let w = env.create("W", 1);
    let head_w = head(&env);
    refused(&mut env, &w, &z, Replacement::Duplicate, 2, &format!("mark {w} a duplicate of {x}"));
    assert_eq!(head(&env), head_w);
    assert!(head_w > head_mid && head_mid > head_before);
    // The same chain check for supersedes.
    let old = env.create("Old", 1);
    close_as(&mut env, "alice", &old, &y, Replacement::Supersede, &opts).unwrap();
    let older = env.create("Older", 1);
    refused(&mut env, &older, &old, Replacement::Supersede, 2, &format!("mark {older} superseded by {y}"));
    // A target closed as plain done is accepted, and so is a different relation to a closed duplicate.
    let done = env.create("Done", 1);
    env.close(&done);
    let late = env.create("Late", 1);
    close_as(&mut env, "alice", &late, &done, Replacement::Duplicate, &opts).unwrap();
    let other = env.create("Other", 1);
    close_as(&mut env, "alice", &other, &z, Replacement::Supersede, &opts).unwrap();
    env.assert_healthy();
}

#[test]
fn closing_an_already_closed_issue_as_a_duplicate_is_idempotent_only_with_the_edge() {
    let mut env = Env::new();
    let y = env.create("Y", 1);
    let x = env.create("X", 1);
    let plain = env.create("Plain", 1);
    env.close(&plain);
    let opts = CloseAsOptions::default();
    close_as(&mut env, "alice", &x, &y, Replacement::Duplicate, &opts).unwrap();
    let head_before = head(&env);
    let revision = env.issue(&x).revision;
    let again = close_as(&mut env, "alice", &x, &y, Replacement::Duplicate, &opts).unwrap();
    assert!(again.already);
    assert_eq!(again.issue.revision, revision);
    assert_eq!(head(&env), head_before, "no events");

    for (id, target, kind) in [(&x, &y, Replacement::Supersede), (&plain, &y, Replacement::Duplicate)] {
        let e = close_as(&mut env, "alice", id, target, kind, &opts).unwrap_err();
        assert!(matches!(e, Error::Refused(ref m) if m.contains("already closed") && m.contains("bd dep add")), "{e}");
        assert_eq!(e.exit_code(), 2);
    }
    assert_eq!(head(&env), head_before);
    assert_eq!(env.issue(&plain).close_reason, None);
    env.assert_healthy();
}

#[test]
fn closing_as_a_duplicate_checks_the_guards() {
    let mut env = Env::new();
    let y = env.create("Y", 1);
    let x = env.create("X", 1);
    let head_before = head(&env);
    let rev = env.issue(&x).revision;
    for guard in [
        Guard { if_revision: Some(rev + 1), ..Default::default() },
        Guard { if_status: Some(Status::InProgress), ..Default::default() },
        Guard { if_assignee: Some(Some("bob".into())), ..Default::default() },
    ] {
        let e = close_as(
            &mut env,
            "alice",
            &x,
            &y,
            Replacement::Duplicate,
            &CloseAsOptions { guard, ..Default::default() },
        )
        .unwrap_err();
        assert!(matches!(e, Error::Conflict { .. }), "{e}");
        assert_eq!(e.exit_code(), 13);
    }
    assert_eq!(head(&env), head_before);
    assert_eq!(env.issue(&x).status, Status::Open);
    let guard = Guard { if_revision: Some(rev), ..Default::default() };
    close_as(&mut env, "alice", &x, &y, Replacement::Duplicate, &CloseAsOptions { guard, ..Default::default() })
        .unwrap();
    env.assert_healthy();
}

#[test]
fn closing_as_a_duplicate_ends_another_actors_claim_only_with_take_over() {
    let mut env = Env::new();
    let y = env.create("Y", 1);
    let x = env.create("X", 1);
    let token = env.store.write("claim", "bob", |tx| tx.claim(&x, &ClaimOptions::default())).unwrap().lease.token;
    let head_before = head(&env);

    for (force, take_over) in [(false, false), (true, false)] {
        let opts = CloseAsOptions { force, take_over, ..Default::default() };
        let e = close_as(&mut env, "alice", &x, &y, Replacement::Duplicate, &opts).unwrap_err();
        assert!(matches!(e, Error::NotOwner { ref holder, .. } if holder.as_deref() == Some("bob")), "{e}");
        assert_eq!(e.exit_code(), 4);
    }
    assert_eq!(head(&env), head_before);
    assert_eq!(env.issue(&x).status, Status::InProgress);
    assert!(edges_of(&env, &x).0.is_empty());

    // The holder itself needs no takeover.
    let own = env.create("Own", 1);
    env.store.write("claim", "alice", |tx| tx.claim(&own, &ClaimOptions::default())).unwrap();
    close_as(&mut env, "alice", &own, &y, Replacement::Supersede, &CloseAsOptions::default()).unwrap();
    assert!(env.store.read(|r| r.lease(&own)).unwrap().is_none());

    let opts = CloseAsOptions { take_over: true, ..Default::default() };
    close_as(&mut env, "alice", &x, &y, Replacement::Duplicate, &opts).unwrap();
    let closed = env.store.read(|r| r.history(&x)).unwrap().into_iter().rev().find(|e| e.op == "closed").unwrap();
    assert_eq!(closed.data["claim_override"], json!({ "holder": "bob", "token": token }));
    assert!(env.store.read(|r| r.lease(&x)).unwrap().is_none(), "the lease ends with the claim");
    env.assert_healthy();
}
