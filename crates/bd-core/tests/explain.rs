//! `ready::explain` cross-checked on random graphs: for every issue, its
//! reasons agree with the stored blocked flag, the flags with a from-scratch
//! computation, and "no reasons" with the ready queue (and the not-ready
//! listing with the rest of the open issues).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bd_core::gates::{GateKind, GateSpec, NewGate};
use bd_core::*;
use serde_json::json;

const T0: i64 = 1_700_000_000_000;
const ISSUES: usize = 30;
const OPS: usize = 60;

/// splitmix64: a deterministic generator, the same on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a>(&mut self, ids: &'a [String]) -> &'a str {
        &ids[self.below(ids.len())]
    }
}

/// A random workspace: a parent-child forest with epics, gates, every kind
/// of scheduling edge, closes done and failed, deferrals with and without an
/// end, claims by two actors (some blocked, some expired), and time passing.
fn random_workspace(seed: u64) -> (tempfile::TempDir, Store, Vec<String>) {
    let mut rng = Rng(seed);
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(Timestamp(T0)));
    let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
    let init = InitOptions { prefix: "x".into(), id_mode: IdMode::Counter };
    let mut store = Store::init(&dir.path().join(".bd").join("bd.db"), init, opts).unwrap();

    let mut ids: Vec<String> = Vec::new();
    for n in 0..ISSUES {
        clock.advance(Duration::from_millis(10));
        let parent = (!ids.is_empty() && rng.chance(45)).then(|| rng.pick(&ids).to_string());
        let issue_type = rng.chance(12).then(|| "epic".to_string());
        let new = NewIssue {
            title: format!("Issue {n}"),
            priority: Some(rng.below(5) as u8),
            parent,
            issue_type,
            ..Default::default()
        };
        ids.push(store.write("create", "alice", |tx| tx.create_issue(new)).unwrap().id);
    }

    for _ in 0..OPS {
        let a = rng.pick(&ids).to_string();
        let b = rng.pick(&ids).to_string();
        // Errors (cycles, hierarchy deadlocks, closed or claimed issues,
        // claims of issues that are not ready) are part of the game.
        let _ = match rng.below(9) {
            0 | 1 => store.write("dep", "alice", |tx| tx.add_dependency(&a, &b, DepType::Blocks, None).map(drop)),
            2 => {
                store.write("dep", "alice", |tx| tx.add_dependency(&a, &b, DepType::ConditionalBlocks, None).map(drop))
            }
            3 => {
                let gate = if rng.chance(50) { "any-children" } else { "all-children" };
                let meta = rng.chance(80).then(|| json!({ "gate": gate }));
                store.write("dep", "alice", |tx| tx.add_dependency(&a, &b, DepType::WaitsFor, meta).map(drop))
            }
            4 => {
                let outcome = if rng.chance(35) { Outcome::Failed } else { Outcome::Done };
                let opts = CloseOptions {
                    outcome: Some(outcome),
                    force: rng.chance(50),
                    take_over: true,
                    ..Default::default()
                };
                store.write("close", "alice", |tx| tx.close_issue(&a, &opts).map(drop))
            }
            5 => {
                let until =
                    rng.chance(60).then(|| clock.now().plus(Duration::from_secs(600 * (1 + rng.below(12) as u64))));
                store.write("defer", "alice", |tx| tx.defer_issue(&a, until).map(drop))
            }
            6 => {
                let actor = if rng.chance(50) { "agent-a" } else { "agent-b" };
                let opts = ClaimOptions { allow_blocked: rng.chance(40), ..Default::default() };
                store.write("claim", actor, |tx| tx.claim(&a, &opts).map(drop))
            }
            7 => {
                let gate = NewGate {
                    spec: if rng.chance(50) { GateSpec::new(GateKind::Human) } else { GateSpec::new(GateKind::Issue) },
                    blocks: vec![a.clone()],
                    title: None,
                    description: String::new(),
                    assignee: None,
                    parent: None,
                    priority: None,
                    ephemeral: false,
                };
                let gate = store.write("gate", "alice", |tx| tx.create_gate(gate));
                gate.map(|g| ids.push(g.id))
            }
            _ => {
                clock.advance(Duration::from_secs(60 * rng.below(90) as u64));
                Ok(())
            }
        };
    }
    (dir, store, ids)
}

/// The reasons the ready queue and the not-ready listing go by.
fn keeps_out_of_the_queue(r: &NotReady) -> bool {
    matches!(r, NotReady::Blocked { .. } | NotReady::Deferred { .. } | NotReady::WaitsOnChildren { .. })
}

#[test]
fn explanations_agree_with_the_blocked_flags_and_the_ready_queue() {
    let mut kinds = BTreeSet::new();
    let (mut ready_total, mut not_ready_total) = (0, 0);
    for seed in 1..=24u64 {
        let (_dir, store, ids) = random_workspace(seed);
        store
            .read(|r| {
                let truth = graph::full_blocked_set(r.conn())?;
                let all = ReadyQuery { limit: None, ..Default::default() };
                let ready: BTreeSet<String> = r.ready(&all)?.into_iter().map(|i| i.id).collect();
                let not_ready: BTreeSet<String> = r.not_ready(&all)?.into_iter().map(|i| i.id).collect();
                let mut explained_ready = BTreeSet::new();
                let mut explained_not_ready = BTreeSet::new();
                for id in &ids {
                    let issue = r.issue(id)?;
                    let why = r.explain(id, ExplainOptions::default())?;
                    let ctx = format!("seed {seed}, {id}: {why:?}");
                    assert_eq!(issue.is_blocked, truth.contains(id), "stored flag vs full set, {ctx}");
                    if !issue.status.is_terminal() {
                        let blocked = why.reasons.iter().any(|r| matches!(r, NotReady::Blocked { .. }));
                        assert_eq!(issue.is_blocked, blocked, "is_blocked vs explanation, {ctx}");
                    }
                    assert_eq!(why.ready, why.reasons.is_empty(), "{ctx}");
                    if why.ready {
                        explained_ready.insert(id.clone());
                    }
                    // Open, of a type the queue takes, and kept out only by its graph or deferral.
                    let open_work = issue.status == Status::Open
                        && !why.reasons.iter().any(|r| matches!(r, NotReady::ExcludedType { .. }));
                    if open_work && why.reasons.iter().any(keeps_out_of_the_queue) {
                        explained_not_ready.insert(id.clone());
                    }
                    // The claim path's words are the same reasons, minus lease and type.
                    let words = r.not_ready_reasons(id)?;
                    let expected: Vec<String> = why
                        .reasons
                        .iter()
                        .filter(|r| !matches!(r, NotReady::Claimed { .. } | NotReady::ExcludedType { .. }))
                        .map(|reason| reason.text(id, r.now()))
                        .collect();
                    assert_eq!(words, expected, "{ctx}");
                    for reason in &why.reasons {
                        kinds.insert(serde_json::to_value(reason).unwrap()["kind"].as_str().unwrap().to_string());
                    }
                }
                ready_total += ready.len();
                not_ready_total += not_ready.len();
                assert_eq!(explained_ready, ready, "seed {seed}: no reasons == the ready queue");
                assert_eq!(explained_not_ready, not_ready, "seed {seed}: the not-ready listing");
                Ok(())
            })
            .unwrap();
    }
    // The seeds reach both sides of the queue and every kind of reason.
    assert!(ready_total > 24 && not_ready_total > 24, "ready {ready_total}, not ready {not_ready_total}");
    let want = ["blocked", "claimed", "deferred", "excluded_type", "status", "waits_on_children"];
    assert_eq!(kinds, want.iter().map(|k| k.to_string()).collect(), "kinds reached");
}
