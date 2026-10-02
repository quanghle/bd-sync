//! Engine-level integration tests: lifecycle, graph semantics, ready order,
//! leases, crash recovery, optimistic concurrency, events, and concurrency.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use bd_core::doctor;
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
    assert_eq!(env.ready_ids(), vec![child.clone(), grandchild.clone()], "epics are excluded from ready");
    let with_epics = env.ready_ids_with(&ReadyQuery { include_epics: true, ..Default::default() });
    assert!(with_epics.contains(&epic));

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
    assert_eq!(env.ready_ids(), vec![kid.clone(), grandkid.clone()]);
    env.store.write("undefer", "alice", |tx| tx.undefer_issue(&solo)).unwrap();
    assert!(env.ready_ids().contains(&solo));
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
