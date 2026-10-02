//! Write policies (what `bd serve` lets each access token override), at the
//! engine level: other actors' claims need an admin, human gates a person,
//! and GitHub gates may only name the workspace's allowed repositories.

use std::sync::Arc;
use std::time::Duration;

use bd_core::gates::{GateKind, GateRepos, GateSpec, NewGate};
use bd_core::playbook::{self, CompactOptions, Loader, RunRequest, StartOptions};
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use serde_json::{Value, json};
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

fn agent(actor: &str) -> Option<Policy> {
    Some(Policy { actor: actor.into(), admin: false, human: false })
}

fn admin_agent(actor: &str) -> Option<Policy> {
    Some(Policy { actor: actor.into(), admin: true, human: false })
}

fn person(actor: &str) -> Option<Policy> {
    Some(Policy { actor: actor.into(), admin: false, human: true })
}

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

    /// One write transaction as `actor`, under `policy` (`None`: unlimited, like the CLI).
    fn as_<T>(
        &mut self,
        actor: &str,
        policy: Option<Policy>,
        f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>,
    ) -> Result<T> {
        self.clock.advance(Duration::from_millis(10));
        self.store.write("test", actor, |tx| {
            tx.set_policy(policy);
            f(tx)
        })
    }

    fn create(&mut self, title: &str) -> String {
        self.as_("alice", None, |tx| tx.create_issue(NewIssue::titled(title))).unwrap().id
    }

    fn issue(&self, id: &str) -> Issue {
        self.store.read(|r| r.issue(id)).unwrap()
    }

    fn start(&mut self, toml: &str, vars: &[(&str, &str)]) -> Result<String> {
        let pb = playbook::parse_toml(toml, "test.toml", "test").unwrap();
        let req = RunRequest {
            vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        };
        let plan = playbook::compile(&pb, &req, &Loader::default()).unwrap();
        self.as_("alice", agent("alice"), |tx| tx.start_run(&plan, &StartOptions::default())).map(|s| s.run.id)
    }

    fn assert_healthy(&mut self) {
        let report = doctor::diagnose(&mut self.store, false, true).unwrap();
        let bad: Vec<_> = report.checks.iter().filter(|c| c.severity != doctor::Severity::Ok).collect();
        assert!(bad.is_empty(), "doctor found problems: {bad:#?}");
    }
}

fn denied<T: std::fmt::Debug>(r: Result<T>, needle: &str) {
    match r {
        Err(e @ Error::Unauthorized(_)) => {
            assert!(e.to_string().contains(needle), "{e}");
            assert_eq!(e.exit_code(), 7);
        }
        other => panic!("expected an access refusal mentioning {needle:?}, got {other:?}"),
    }
}

fn force_release() -> ReleaseOptions {
    ReleaseOptions { force: true, ..Default::default() }
}

fn patch(f: impl FnOnce(&mut IssuePatch)) -> IssuePatch {
    let mut p = IssuePatch::default();
    f(&mut p);
    p
}

#[test]
fn other_actors_claims_need_an_admin() {
    let mut env = Env::new();
    let ids: Vec<String> = (1..=6).map(|n| env.create(&format!("Task {n}"))).collect();
    for id in &ids[..5] {
        env.as_("bob/w1", agent("bob"), |tx| tx.claim(id, &ClaimOptions::default())).unwrap();
    }
    let held = ids[0].clone();

    // Without force the old answers stand; with it, a write token is refused.
    let e = env.as_("alice", agent("alice"), |tx| tx.release(&held, &ReleaseOptions::default())).unwrap_err();
    assert!(matches!(e, Error::NotOwner { .. }), "{e}");
    denied(env.as_("alice", agent("alice"), |tx| tx.release(&held, &force_release())), "needs an admin");
    let cas = ReleaseOptions {
        guard: Guard { if_assignee: Some(Some("bob/w1".into())), ..Default::default() },
        force: true,
        ..Default::default()
    };
    denied(env.as_("alice", agent("alice"), |tx| tx.release(&held, &cas)), "claimed by bob/w1");
    let take = patch(|p| p.assignee = Some(Some("alice".into())));
    let e = env.as_("alice", agent("alice"), |tx| tx.update_issue(&held, &take, &Guard::default(), false)).unwrap_err();
    assert!(matches!(e, Error::AlreadyClaimed { .. }), "{e}");
    denied(env.as_("alice", agent("alice"), |tx| tx.update_issue(&held, &take, &Guard::default(), true)), "admin");
    for status in [Status::Open, Status::Blocked, Status::Deferred, Status::Pinned] {
        let p = patch(|p| p.status = Some(status));
        denied(env.as_("alice", agent("alice"), |tx| tx.update_issue(&held, &p, &Guard::default(), false)), "admin");
    }
    denied(env.as_("alice", agent("alice"), |tx| tx.close_issue(&held, &CloseOptions::default())), "admin");
    let del = DeleteOptions { force: true, ..Default::default() };
    denied(env.as_("alice", agent("alice"), |tx| tx.delete_issues(std::slice::from_ref(&held), &del)), "admin");
    assert_eq!(env.issue(&held).assignee.as_deref(), Some("bob/w1"), "nothing changed");

    // Changes that leave the claim alone are fine.
    let label = patch(|p| p.add_labels = vec!["looked-at".into()]);
    env.as_("alice", agent("alice"), |tx| tx.update_issue(&held, &label, &Guard::default(), false)).unwrap();

    // The token's own actor and its sub-actors may take over each other's claims without an
    // admin, but with force like everyone: each sub-actor holds its own lease.
    env.as_("bob/w2", agent("bob"), |tx| tx.release(&ids[1], &force_release())).unwrap();
    let e = env.as_("bob", agent("bob"), |tx| tx.close_issue(&ids[2], &CloseOptions::default())).unwrap_err();
    assert!(matches!(e, Error::NotOwner { .. }), "{e}");
    let force_close = CloseOptions { force: true, ..Default::default() };
    env.as_("bob", agent("bob"), |tx| tx.close_issue(&ids[2], &force_close)).unwrap();
    // An admin may take over anyone's claim; without a policy (the CLI) anyone may: with force.
    let e = env.as_("ops", admin_agent("ops"), |tx| tx.update_issue(&held, &take, &Guard::default(), false));
    assert!(matches!(e, Err(Error::AlreadyClaimed { .. })), "{e:?}");
    env.as_("ops", admin_agent("ops"), |tx| tx.update_issue(&held, &take, &Guard::default(), true)).unwrap();
    assert_eq!(env.issue(&held).assignee.as_deref(), Some("alice"));
    let e = env.as_("carol", None, |tx| tx.release(&ids[3], &ReleaseOptions::default())).unwrap_err();
    assert!(matches!(e, Error::NotOwner { .. }), "{e}");
    env.as_("carol", None, |tx| tx.release(&ids[3], &force_release())).unwrap();

    // Reserved work nobody has claimed can be reassigned and released.
    env.as_("alice", None, |tx| {
        tx.update_issue(&ids[5], &patch(|p| p.assignee = Some(Some("bob".into()))), &Guard::default(), false)
    })
    .unwrap();
    env.as_("alice", agent("alice"), |tx| tx.release(&ids[5], &force_release())).unwrap();

    // Expired leases stay reclaimable by anyone.
    env.clock.advance(Duration::from_secs(3600));
    let reclaimed = env.as_("alice", agent("alice"), |tx| tx.reclaim_expired(&ReclaimOptions::default())).unwrap();
    let mut reclaimed: Vec<&str> = reclaimed.iter().map(|r| r.issue_id.as_str()).collect();
    reclaimed.sort();
    assert_eq!(reclaimed, vec![ids[0].as_str(), ids[4].as_str()], "bob's and the one taken over");
    env.assert_healthy();
}

fn last_event(env: &Env, op: &str, id: &str) -> Event {
    let history = env.store.read(|r| r.history(id)).unwrap();
    history.into_iter().rev().find(|e| e.op == op).unwrap_or_else(|| panic!("no {op} event on {id}"))
}

/// A claim conflict (exit 4): `id` is held by `holder`.
fn not_owner<T: std::fmt::Debug>(r: Result<T>, holder: &str) {
    match r {
        Err(e @ Error::NotOwner { .. }) => {
            assert!(e.to_string().contains(&format!("held by {holder},")), "{e}");
            assert_eq!(e.exit_code(), 4);
        }
        other => panic!("expected a refusal naming holder {holder}, got {other:?}"),
    }
}

#[test]
fn live_claims_are_their_holders_alone() {
    let mut env = Env::new();
    let ids: Vec<String> = (1..=8).map(|n| env.create(&format!("Task {n}"))).collect();
    let tokens: Vec<i64> = ids
        .iter()
        .map(|id| env.as_("ann/s1", None, |tx| tx.claim(id, &ClaimOptions::default())).unwrap().lease.token)
        .collect();
    let none = Guard::default();
    let close = CloseOptions::default();
    let force_close = CloseOptions { force: true, ..Default::default() };
    let reopen = patch(|p| p.status = Some(Status::Open));
    let take = |who: &str| patch(|p| p.assignee = Some(Some(who.to_string())));

    // Without a policy (the CLI), every other actor name is refused: another actor, the
    // holder's root actor, and a sibling sub-actor alike.
    for actor in ["bob", "ann", "ann/s2"] {
        let held = &ids[0];
        not_owner(env.as_(actor, None, |tx| tx.close_issue(held, &close)), "ann/s1");
        not_owner(env.as_(actor, None, |tx| tx.update_issue(held, &reopen, &none, false)), "ann/s1");
        let e = env.as_(actor, None, |tx| tx.update_issue(held, &take(actor), &none, false)).unwrap_err();
        assert!(matches!(e, Error::AlreadyClaimed { .. }) && e.exit_code() == 4, "{e}");
        let del = DeleteOptions::default();
        not_owner(env.as_(actor, None, |tx| tx.delete_issues(std::slice::from_ref(held), &del)), "ann/s1");
        not_owner(env.as_(actor, None, |tx| tx.release(held, &ReleaseOptions::default())), "ann/s1");
        let e = env.as_(actor, None, |tx| tx.claim(held, &ClaimOptions::default())).unwrap_err();
        assert!(matches!(e, Error::AlreadyClaimed { .. }), "{e}");
        // Even with the holder's token: it proves a grant to its holder only.
        let with_token = ClaimOptions { token: Some(tokens[0]), ..Default::default() };
        let e = env.as_(actor, None, |tx| tx.claim(held, &with_token)).unwrap_err();
        assert!(matches!(e, Error::AlreadyClaimed { .. }), "{e}");
    }
    assert_eq!(env.issue(&ids[0]).assignee.as_deref(), Some("ann/s1"), "nothing changed");
    assert_eq!(env.store.read(|r| r.lease(&ids[0])).unwrap().unwrap().token, tokens[0]);
    let label = patch(|p| p.add_labels = vec!["seen".into()]);
    env.as_("bob", None, |tx| tx.update_issue(&ids[0], &label, &none, false)).expect("leaves the claim alone");

    // With force each goes through, and its event names the claim it ended.
    let overridden = |env: &Env, op: &str, n: usize| {
        let e = last_event(env, op, &ids[n]);
        assert_eq!(e.data["claim_override"], json!({ "holder": "ann/s1", "token": tokens[n] }), "{op}: {}", e.data);
    };
    env.as_("bob", None, |tx| tx.close_issue(&ids[0], &force_close)).unwrap();
    overridden(&env, "closed", 0);
    env.as_("ann", None, |tx| tx.update_issue(&ids[1], &reopen, &none, true)).unwrap();
    overridden(&env, "updated", 1);
    env.as_("ann/s2", None, |tx| tx.update_issue(&ids[2], &take("ann/s2"), &none, true)).unwrap();
    overridden(&env, "updated", 2);
    assert_eq!(env.store.read(|r| r.lease(&ids[2])).unwrap().unwrap().holder, "ann/s2", "the lease follows");
    env.as_("bob", None, |tx| tx.release(&ids[3], &force_release())).unwrap();
    overridden(&env, "released", 3);
    let del = DeleteOptions { force: true, ..Default::default() };
    env.as_("bob", None, |tx| tx.delete_issues(std::slice::from_ref(&ids[4]), &del)).unwrap();
    overridden(&env, "deleted", 4);

    // The holder ends its own claim without force or token; a token it passes must match.
    let stale = CloseOptions { token: Some(tokens[5] + 1000), ..Default::default() };
    let e = env.as_("ann/s1", None, |tx| tx.close_issue(&ids[5], &stale)).unwrap_err();
    assert!(matches!(e, Error::LeaseLost { .. }), "{e}");
    env.as_("ann/s1", None, |tx| tx.close_issue(&ids[5], &close)).unwrap();
    assert!(last_event(&env, "closed", &ids[5]).data.get("claim_override").is_none());

    // An expired lease stays protected until `reclaim` could take it (lease.grace, 10m, past
    // its expiry); then the claim is anyone's to claim or end.
    env.clock.advance(Duration::from_secs(6 * 60));
    not_owner(env.as_("bob", None, |tx| tx.close_issue(&ids[6], &close)), "ann/s1");
    let e = env.as_("bob", None, |tx| tx.claim(&ids[6], &ClaimOptions::default())).unwrap_err();
    assert!(matches!(e, Error::AlreadyClaimed { .. }), "{e}");
    env.clock.advance(Duration::from_secs(10 * 60));
    let c = env.as_("bob", None, |tx| tx.claim(&ids[6], &ClaimOptions::default())).unwrap();
    assert_eq!((c.issue.status, c.issue.assignee.as_deref()), (Status::InProgress, Some("bob")));
    assert_eq!(c.reclaimed.as_ref().map(|r| (r.previous_holder.as_str(), r.token)), Some(("ann/s1", tokens[6])));
    assert!(c.lease.token > tokens[6] && !c.already_held);
    assert_eq!(last_event(&env, "reclaimed", &ids[6]).data["previous_holder"], "ann/s1");
    env.as_("bob", None, |tx| tx.close_issue(&ids[7], &close)).expect("a dead claim needs no force");
    assert!(last_event(&env, "closed", &ids[7]).data.get("claim_override").is_none());
    let reclaimed = env.as_("bob", None, |tx| tx.reclaim_expired(&ReclaimOptions::default())).unwrap();
    assert_eq!(reclaimed.len(), 1, "only ann/s2's claim taken over above is left: {reclaimed:?}");
    env.assert_healthy();
}

#[test]
fn a_dead_claim_is_released_by_anyone_a_live_one_by_its_holder() {
    let mut env = Env::new();
    let id = env.create("Task");
    env.as_("ann", None, |tx| tx.claim(&id, &ClaimOptions::default())).unwrap();
    not_owner(env.as_("bob", None, |tx| tx.release(&id, &ReleaseOptions::default())), "ann");
    env.clock.advance(Duration::from_secs(16 * 60));
    let released = env.as_("bob", None, |tx| tx.release(&id, &ReleaseOptions::default())).unwrap();
    assert_eq!((released.status, released.assignee), (Status::Open, None));
    let e = last_event(&env, "released", &id);
    assert_eq!((e.data["previous_holder"].as_str(), e.data.get("claim_override")), (Some("ann"), None));
    env.assert_healthy();
}

#[test]
fn imports_and_runs_need_force_to_end_live_claims() {
    let mut env = Env::new();
    let id = env.create("Claimed");
    let mut before = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut before, &ExportOptions::default())).unwrap();
    let token = env.as_("ann", None, |tx| tx.claim(&id, &ClaimOptions::default())).unwrap().lease.token;
    // An export from before the claim would put the issue back to open.
    let import = |force: bool| {
        let before = before.clone();
        move |tx: &mut WriteCtx<'_>| {
            tx.import_jsonl(&mut before.as_slice(), &ImportOptions { force, ..Default::default() })
        }
    };
    not_owner(env.as_("bob", None, import(false)), "ann");
    denied(env.as_("bob", agent("bob"), import(true)), "needs an admin");
    env.as_("ops", admin_agent("ops"), |tx| {
        import(true)(tx)?;
        tx.set_rollback_only();
        Ok(())
    })
    .expect("an admin token, with force");
    env.as_("bob", None, import(true)).unwrap();
    assert_eq!(env.issue(&id).status, Status::Open);
    assert_eq!(last_event(&env, "imported", &id).data["claim_override"], json!({ "holder": "ann", "token": token }));

    // Discarding or compacting a run deletes its claimed steps only with force (already
    // required for unfinished runs), and records each claim it ended.
    let run = env.start("[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n", &[]).unwrap();
    let step = format!("{run}.a");
    let token = env.as_("ann", None, |tx| tx.claim(&step, &ClaimOptions::default())).unwrap().lease.token;
    assert!(matches!(env.as_("bob", None, |tx| tx.discard_run(&run, false, false)), Err(Error::Refused(_))));
    let compact = CompactOptions { force: true, ..Default::default() };
    env.as_("bob", None, |tx| tx.compact_run(&run, &compact)).unwrap();
    let e = last_event(&env, "run_compacted", &run);
    assert_eq!(e.data["claim_overrides"], json!({ step.clone(): { "holder": "ann", "token": token } }), "{}", e.data);
    env.assert_healthy();
}

#[test]
fn runs_with_claimed_steps_need_an_admin_to_discard() {
    let mut env = Env::new();
    let run = env.start("[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n", &[]).unwrap();
    env.as_("bob", agent("bob"), |tx| tx.claim("t-1.a", &ClaimOptions::default())).unwrap();
    denied(env.as_("alice", agent("alice"), |tx| tx.discard_run(&run, true, true)), "claimed by bob");
    let compact = CompactOptions { force: true, ..Default::default() };
    denied(env.as_("alice", agent("alice"), |tx| tx.compact_run(&run, &compact)), "claimed by bob");
    env.as_("ops", admin_agent("ops"), |tx| tx.discard_run(&run, true, false)).unwrap();
    assert!(env.store.read(|r| r.issue(&run)).is_err(), "discarded");
}

const APPROVAL: &str = r#"
[[steps]]
id = "build"

[[steps]]
id = "deploy"
needs = ["build"]
[steps.gate]
type = "human"
[[steps.children]]
id = "upload"
[[steps.children]]
id = "notify"

[[steps]]
id = "announce"
needs = ["deploy"]
"#;

#[test]
fn human_gates_open_only_for_a_person() {
    let mut env = Env::new();
    let run = env.start(APPROVAL, &[]).unwrap();
    let gate = "t-1.gate-deploy";
    env.as_("bot", agent("bot"), |tx| tx.close_issue("t-1.build", &CloseOptions::default())).unwrap();
    let bot = || agent("bot");
    let ops = || admin_agent("ops");
    let none = Guard::default();

    // The gate itself: resolving, closing, pinning, retyping, re-specifying, deleting.
    denied(env.as_("bot", bot(), |tx| tx.resolve_gate(gate, Some("lgtm"), false)), "is a human gate");
    denied(env.as_("ops", ops(), |tx| tx.resolve_gate(gate, None, true)), "only a person can open it");
    denied(env.as_("bot", bot(), |tx| tx.close_issue(gate, &CloseOptions::default())), "open it");
    let pin = patch(|p| p.status = Some(Status::Pinned));
    denied(env.as_("bot", bot(), |tx| tx.update_issue(gate, &pin, &none, false)), "open it");
    for change in [
        patch(|p| p.issue_type = Some("task".into())),
        patch(|p| p.set_metadata = vec![("gate".into(), json!({ "type": "timer", "timeout": "1s" }))]),
        patch(|p| p.unset_metadata = vec!["gate".into()]),
        patch(|p| p.metadata = Some(json!({}))),
    ] {
        denied(env.as_("bot", bot(), |tx| tx.update_issue(gate, &change, &none, true)), "change its type or condition");
    }
    let del = DeleteOptions { force: true, ..Default::default() };
    denied(env.as_("bot", bot(), |tx| tx.delete_issues(&[gate.to_string()], &del)), "delete it");
    // Harmless edits are fine: it is still a human gate.
    let retitle = patch(|p| {
        p.title = Some("Approve the deploy".into());
        p.assignee = Some(Some("carol".into()));
        p.set_metadata = vec![("gate".into(), json!({ "type": "human", "timeout": "2h" }))];
    });
    env.as_("bot", bot(), |tx| tx.update_issue(gate, &retitle, &none, false)).unwrap();

    // The work it holds back (directly, below it, and around it) cannot get past it.
    denied(env.as_("bot", bot(), |tx| tx.remove_dependency("t-1.deploy", gate)), "remove that edge");
    let force = CloseOptions { force: true, ..Default::default() };
    for (id, why) in [
        ("t-1.deploy", "waits for human gate t-1.gate-deploy"),
        ("t-1.deploy.upload", "waits for human gate t-1.gate-deploy"),
        (run.as_str(), "holds work that waits for human gate"),
    ] {
        denied(env.as_("bot", bot(), |tx| tx.close_issue(id, &force)), why);
        denied(env.as_("bot", bot(), |tx| tx.update_issue(id, &pin, &none, false)), why);
        denied(env.as_("bot", bot(), |tx| tx.delete_issues(&[id.to_string()], &del)), why);
    }
    let detach = patch(|p| p.parent = Some(None));
    denied(env.as_("bot", bot(), |tx| tx.update_issue("t-1.deploy.upload", &detach, &none, false)), "move it");
    denied(env.as_("bot", bot(), |tx| tx.remove_dependency("t-1.deploy.upload", "t-1.deploy")), "move it out");
    denied(env.as_("bot", bot(), |tx| tx.discard_run(&run, true, true)), "delete it");
    let compact = CompactOptions { force: true, ..Default::default() };
    denied(env.as_("bot", bot(), |tx| tx.compact_run(&run, &compact)), "delete it");
    // Without force, held work is refused as before (blocked), not as an access problem.
    let e = env.as_("bot", bot(), |tx| tx.close_issue("t-1.deploy.upload", &CloseOptions::default())).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");

    // An import may not open it either, even with an admin token.
    let mut snap = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut snap, &ExportOptions::default())).unwrap();
    let opened: String = String::from_utf8(snap)
        .unwrap()
        .lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).unwrap();
            if v["id"] == gate {
                v["status"] = json!("closed");
                v["closed_at"] = json!(T0);
            }
            format!("{v}\n")
        })
        .collect();
    let import = |tx: &mut WriteCtx<'_>| tx.import_jsonl(&mut opened.as_bytes(), &ImportOptions::default());
    denied(env.as_("ops", ops(), import), "only a person");
    assert_eq!(env.issue(gate).status, Status::Open);
    // Nor move held work out from under its group by retyping the edge.
    let mut snap = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut snap, &ExportOptions::default())).unwrap();
    let line = String::from_utf8(snap)
        .unwrap()
        .lines()
        .find(|l| l.contains("\"id\":\"t-1.deploy.upload\""))
        .unwrap()
        .to_string();
    let mut upload: Value = serde_json::from_str(&line).unwrap();
    upload["dependencies"] = json!([{ "depends_on_id": "t-1.deploy", "type": "related" }]);
    let moved = upload.to_string();
    let import = |tx: &mut WriteCtx<'_>| tx.import_jsonl(&mut moved.as_bytes(), &ImportOptions::default());
    denied(env.as_("ops", ops(), import), "t-1.deploy.upload waits for human gate");
    let import = |tx: &mut WriteCtx<'_>| tx.import_jsonl(&mut moved.as_bytes(), &ImportOptions::default());
    env.as_("ops", person("ops"), |tx| {
        import(tx)?;
        tx.set_rollback_only();
        Ok(())
    })
    .expect("a person may");

    // A person resolves it; the work flows again.
    env.as_("carol", person("carol"), |tx| tx.resolve_gate(gate, Some("approved"), false)).unwrap();
    let ready: Vec<String> =
        env.store.read(|r| r.ready(&ReadyQuery::default())).unwrap().into_iter().map(|i| i.id).collect();
    assert_eq!(ready, vec!["t-1.deploy.notify", "t-1.deploy.upload"]);
    env.assert_healthy();
}

#[test]
fn people_and_the_cli_are_not_limited_by_human_gates() {
    let mut env = Env::new();
    let run = env.start(APPROVAL, &[]).unwrap();
    let force = CloseOptions { force: true, ..Default::default() };
    env.as_("carol", person("carol"), |tx| tx.close_issue("t-1.deploy.upload", &force)).unwrap();
    env.as_("alice", None, |tx| tx.remove_dependency("t-1.deploy", "t-1.gate-deploy")).unwrap();
    env.as_("alice", None, |tx| tx.close_issue("t-1.gate-deploy", &force)).unwrap();
    // Other gates stay open to agents: resolving a timer by hand is their call.
    let work = env.create("Later");
    let mut spec = GateSpec::new(GateKind::Timer);
    spec.timeout = Some("1h".into());
    let timer = env
        .as_("bot", agent("bot"), |tx| {
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
    env.as_("bot", agent("bot"), |tx| tx.resolve_gate(&timer.id, None, false)).unwrap();
    env.as_("bot", agent("bot"), |tx| tx.discard_run(&run, true, false)).unwrap();
    env.assert_healthy();
}

fn gh_gate(kind: GateKind, repo: Option<&str>, blocks: &str) -> NewGate {
    let mut spec = GateSpec::new(kind);
    spec.await_id = Some(if kind == GateKind::GhPr { "42".into() } else { "release.yml".into() });
    spec.repo = repo.map(String::from);
    NewGate {
        spec,
        blocks: vec![blocks.to_string()],
        title: None,
        description: String::new(),
        assignee: None,
        parent: None,
        priority: None,
        ephemeral: false,
    }
}

#[test]
fn github_gates_name_only_allowed_repositories() {
    let mut env = Env::new();
    let work = env.create("Ship");
    // Locally, with nothing configured, any repository (as before).
    let legacy =
        env.as_("alice", None, |tx| tx.create_gate(gh_gate(GateKind::GhPr, Some("else/where"), &work))).unwrap();
    // Through bd serve, only the workspace's own repository, whatever the role.
    for policy in [agent("bot"), admin_agent("ops"), person("carol")] {
        let e = env.as_("x", policy.clone(), |tx| tx.create_gate(gh_gate(GateKind::GhRun, Some("else/where"), &work)));
        assert!(matches!(&e, Err(Error::Refused(m)) if m.contains("own repository")), "{e:?}");
        env.as_("x", policy, |tx| tx.create_gate(gh_gate(GateKind::GhRun, None, &work))).unwrap();
    }
    // Plain creates and updates that would make a gate watch another repository.
    let raw = NewIssue {
        issue_type: Some("gate".into()),
        metadata: Some(json!({ "gate": { "type": "gh:pr", "await_id": "7", "repo": "else/where" } })),
        ..NewIssue::titled("Sneaky")
    };
    let e = env.as_("bot", agent("bot"), |tx| tx.create_issue(raw.clone())).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");
    let retarget = patch(|p| {
        p.set_metadata = vec![("gate".into(), json!({ "type": "gh:pr", "await_id": "42", "repo": "other/repo" }))]
    });
    let e = env
        .as_("bot", agent("bot"), |tx| tx.update_issue(&legacy.id, &retarget, &Guard::default(), false))
        .unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");
    // A gate that already watched a repository keeps working; editing it otherwise is fine.
    let retitle = patch(|p| p.title = Some("Wait for the PR".into()));
    env.as_("bot", agent("bot"), |tx| tx.update_issue(&legacy.id, &retitle, &Guard::default(), false)).unwrap();
    // Playbook variables cannot point a gate elsewhere either.
    let pb = "[vars.repo]\n[[steps]]\nid = \"ship\"\n[steps.gate]\ntype = \"gh:pr\"\nawait_id = \"1\"\nrepo = \"{{repo}}\"\n";
    let e = env.start(pb, &[("repo", "else/where")]).unwrap_err();
    assert!(e.to_string().contains("not allowed"), "{e}");

    // gate.repos allows more, for every caller, the CLI included.
    env.as_("ops", admin_agent("ops"), |tx| config::set(tx, "gate.repos", "org/*, ghe.example.com/team/app")).unwrap();
    for repo in ["org/app", "ORG/Other", "ghe.example.com/team/app"] {
        env.as_("bot", agent("bot"), |tx| tx.create_gate(gh_gate(GateKind::GhPr, Some(repo), &work))).unwrap();
    }
    // A host is part of the name: org/* is on gh's default host, whichever that is.
    for repo in ["else/where", "github.com/org/app", "ghe.example.com/org/app", "orga/app", "team/app"] {
        let e = env.as_("alice", None, |tx| tx.create_gate(gh_gate(GateKind::GhPr, Some(repo), &work))).unwrap_err();
        assert!(e.to_string().contains("not in gate.repos (org/*, ghe.example.com/team/app)"), "{e}");
    }
    env.start(pb, &[("repo", "org/app")]).unwrap();

    // Imports are held to it too.
    let mut snap = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut snap, &ExportOptions::default())).unwrap();
    let text = String::from_utf8(snap).unwrap().replace("\"org/app\"", "\"evil/app\"");
    let e = env.as_("ops", admin_agent("ops"), |tx| tx.import_jsonl(&mut text.as_bytes(), &ImportOptions::default()));
    assert!(matches!(&e, Err(Error::Refused(m)) if m.contains("evil/app")), "{e:?}");

    env.as_("ops", admin_agent("ops"), |tx| config::set(tx, "gate.repos", "*")).unwrap();
    env.as_("bot", agent("bot"), |tx| tx.create_gate(gh_gate(GateKind::GhPr, Some("any/where"), &work))).unwrap();
    let e = env.as_("ops", None, |tx| config::set(tx, "gate.repos", "not a repo")).unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    env.assert_healthy();
}

#[test]
fn gate_repo_allowlists_load_from_config() {
    let mut env = Env::new();
    let load = |env: &Env, served| env.store.read(|r| GateRepos::load(r.conn(), served)).unwrap();
    assert_eq!(load(&env, false), GateRepos::Any, "unset: unlimited locally");
    assert_eq!(load(&env, true), GateRepos::Only(vec![]), "unset: the workspace's own repository when served");
    env.as_("ops", None, |tx| config::set(tx, "gate.repos", "a/b,c/*")).unwrap();
    assert_eq!(load(&env, false), GateRepos::Only(vec!["a/b".into(), "c/*".into()]));
    assert_eq!(env.store.read(|r| r.config_value("gate.repos")).unwrap(), "a/b,c/*");
    let repos = load(&env, true);
    assert!(repos.allows("A/B") && repos.allows("c/d") && !repos.allows("a/c") && !repos.allows("x/c/d"));
    assert!(!repos.allows("github.com/a/b"), "with GH_HOST set elsewhere, a/b is not github.com's");
    let hosted = GateRepos::Only(vec!["github.com/a/*".into(), "ghe.example.com/b/c".into()]);
    assert!(hosted.allows("GitHub.com/a/x") && hosted.allows("ghe.example.com/b/c"));
    assert!(!hosted.allows("a/x") && !hosted.allows("b/c") && !hosted.allows("ghe.example.com/a/x"));
    let mut spec = GateSpec::new(GateKind::GhPr);
    spec.await_id = Some("1".into());
    repos.check(&spec).expect("no repo: the workspace's own");
    spec.repo = Some("e/f".into());
    assert!(repos.check(&spec).is_err());
}

fn set_role(env: &mut Env, id: &str, role: &str) {
    let p = patch(|p| p.set_metadata = vec![("playbook".into(), json!({ "role": role }))]);
    env.as_("alice", None, |tx| tx.update_issue(id, &p, &Guard::default(), false)).unwrap();
}

fn child(env: &mut Env, actor: &str, policy: Option<Policy>, parent: &str, new: NewIssue) -> String {
    let new = NewIssue { parent: Some(parent.to_string()), ..new };
    env.as_(actor, policy, |tx| tx.create_issue(new)).unwrap().id
}

fn human_gate(env: &mut Env, blocks: &str) -> String {
    let gate = NewGate {
        spec: GateSpec::new(GateKind::Human),
        blocks: vec![blocks.to_string()],
        title: None,
        description: String::new(),
        assignee: None,
        parent: None,
        priority: None,
        ephemeral: false,
    };
    env.as_("alice", None, |tx| tx.create_gate(gate)).unwrap().id
}

#[test]
fn self_closing_containers_respect_the_policy() {
    let mut env = Env::new();
    let none = Guard::default();
    // Only playbook runs mark runs and groups: no caller under a policy may.
    let plain = env.create("Plain");
    let mark = patch(|p| p.set_metadata = vec![("playbook".into(), json!({ "role": "group" }))]);
    for policy in [agent("bot"), person("carol")] {
        denied(env.as_("x", policy, |tx| tx.update_issue(&plain, &mark, &none, false)), "needs an admin access token");
    }
    // An admin may: closing one still checks claims and human gates (below).
    env.as_("ops", admin_agent("ops"), |tx| tx.update_issue(&plain, &mark, &none, false)).unwrap();

    // (a) A gate is never a self-closing container, whatever its metadata says.
    let work = env.create("Deploy");
    let gate = human_gate(&mut env, &work);
    set_role(&mut env, &gate, "group");
    let c = child(&mut env, "bot", agent("bot"), &gate, NewIssue::titled("Under the gate"));
    env.as_("bot", agent("bot"), |tx| tx.close_issue(&c, &CloseOptions::default())).unwrap();
    assert_eq!(env.issue(&gate).status, Status::Open, "still waiting for a person");
    let c = child(&mut env, "alice", None, &gate, NewIssue::titled("Under the gate, locally"));
    env.as_("alice", None, |tx| tx.close_issue(&c, &CloseOptions::default())).unwrap();
    assert_eq!(env.issue(&gate).status, Status::Open, "not even locally");
    assert!(env.issue(&work).is_blocked);

    // (b) Held work made a group (on the server's host): a pinned issue moved under it and
    // closed would close the group with its gate shut.
    set_role(&mut env, &work, "group");
    let pinned = env
        .as_("bot", agent("bot"), |tx| {
            tx.create_issue(NewIssue { status: Some(Status::Pinned), ..NewIssue::titled("Pin") })
        })
        .unwrap()
        .id;
    let under = patch(|p| p.parent = Some(Some(work.clone())));
    env.as_("bot", agent("bot"), |tx| tx.update_issue(&pinned, &under, &none, false)).unwrap();
    let r = env.as_("bot", agent("bot"), |tx| tx.close_issue(&pinned, &CloseOptions::default()));
    denied(r, "its last open step just closed");
    assert_eq!(env.issue(&work).status, Status::Open);
    env.as_("carol", person("carol"), |tx| tx.close_issue(&pinned, &CloseOptions::default())).unwrap();
    assert_eq!(env.issue(&work).status, Status::Closed, "a person may");

    // (c) A group claimed by another actor stays open, with its claim, when its last step closes.
    let claimed = env.create("Claimed group");
    set_role(&mut env, &claimed, "group");
    let steps: Vec<String> =
        (1..=2).map(|n| child(&mut env, "alice", None, &claimed, NewIssue::titled(format!("Step {n}")))).collect();
    env.as_("bob", agent("bob"), |tx| tx.claim(&claimed, &ClaimOptions { allow_blocked: true, ..Default::default() }))
        .unwrap();
    env.as_("alice", agent("alice"), |tx| tx.close_issue(&steps[0], &CloseOptions::default())).unwrap();
    env.as_("alice", agent("alice"), |tx| tx.close_issue(&steps[1], &CloseOptions::default())).unwrap();
    let group = env.issue(&claimed);
    assert_eq!((group.status, group.assignee.as_deref()), (Status::InProgress, Some("bob")));
    env.as_("bob", agent("bob"), |tx| tx.heartbeat(&claimed, None, None)).expect("bob still holds it");
    // So it does for its holder's sub-actors, an admin, and the CLI: no step close takes over a claim.
    for (actor, policy) in [("bob/w1", agent("bob")), ("ops", admin_agent("ops")), ("carol", None)] {
        env.as_("alice", None, |tx| tx.reopen_issue(&steps[1], None)).unwrap();
        env.as_(actor, policy, |tx| tx.close_issue(&steps[1], &CloseOptions::default())).unwrap();
        assert_eq!(env.issue(&claimed).status, Status::InProgress, "{actor}");
    }
    // Its holder closes it as before.
    env.as_("alice", None, |tx| tx.reopen_issue(&steps[1], None)).unwrap();
    env.as_("bob", agent("bob"), |tx| tx.close_issue(&steps[1], &CloseOptions::default())).unwrap();
    assert_eq!(env.issue(&claimed).status, Status::Closed);

    // Real runs still close themselves, and compaction still writes its bookkeeping.
    let run = env.start("[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n", &[]).unwrap();
    for step in ["a", "b"] {
        env.as_("bot", agent("bot"), |tx| tx.close_issue(&format!("{run}.{step}"), &CloseOptions::default())).unwrap();
    }
    assert_eq!(env.issue(&run).status, Status::Closed);
    env.as_("bot", agent("bot"), |tx| tx.compact_run(&run, &CompactOptions::default())).unwrap();
    assert!(env.issue(&run).metadata["playbook"]["compacted"].is_object());
    let drop_role = patch(|p| p.unset_metadata = vec!["playbook".into()]);
    denied(env.as_("bot", agent("bot"), |tx| tx.update_issue(&run, &drop_role, &none, false)), "metadata.playbook");

    // Nor may an import change it.
    let mut snap = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut snap, &ExportOptions::default())).unwrap();
    let text = String::from_utf8(snap).unwrap().replace("\"role\":\"run\"", "\"role\":\"group\"");
    let import = |tx: &mut WriteCtx<'_>| tx.import_jsonl(&mut text.as_bytes(), &ImportOptions::default());
    denied(env.as_("bot", agent("bot"), import), "metadata.playbook");
    env.as_("ops", admin_agent("ops"), |tx| {
        import(tx)?;
        tx.set_rollback_only();
        Ok(())
    })
    .expect("an admin may");
    env.assert_healthy();
}

#[test]
fn held_work_and_its_gate_stay_in_their_container() {
    let mut env = Env::new();
    let none = Guard::default();
    let epic = env
        .as_("alice", None, |tx| {
            tx.create_issue(NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled("Release") })
        })
        .unwrap()
        .id;
    let after = env.as_("alice", None, |tx| {
        tx.create_issue(NewIssue { deps: vec![(DepType::Blocks, epic.clone())], ..NewIssue::titled("Announce") })
    });
    let after = after.unwrap().id;
    let work = child(&mut env, "alice", None, &epic, NewIssue::titled("Deploy"));
    let other = child(&mut env, "alice", None, &epic, NewIssue::titled("Docs"));
    let gate = human_gate(&mut env, &work);
    assert_eq!(env.store.read(|r| r.details(&gate)).unwrap().parent.as_deref(), Some(epic.as_str()));
    let elsewhere = env.create("Elsewhere");
    let bot = || agent("bot");

    for id in [&work, &gate] {
        for to in [None, Some(elsewhere.clone())] {
            let mv = patch(|p| p.parent = Some(to.clone()));
            denied(
                env.as_("bot", bot(), |tx| tx.update_issue(id, &mv, &none, false)),
                &format!("move it out of {epic}"),
            );
        }
        denied(env.as_("bot", bot(), |tx| tx.remove_dependency(id, &epic)), "move it out of");
    }
    // Unrelated work moves freely, and held work may still be put under a parent.
    let out = patch(|p| p.parent = Some(None));
    env.as_("bot", bot(), |tx| tx.update_issue(&other, &out, &none, false)).unwrap();
    let loose = env.create("Loose");
    let loose_gate = human_gate(&mut env, &loose);
    let into = patch(|p| p.parent = Some(Some(elsewhere.clone())));
    env.as_("bot", bot(), |tx| tx.update_issue(&loose, &into, &none, false)).unwrap();
    env.as_("bot", bot(), |tx| tx.update_issue(&loose_gate, &into, &none, false)).unwrap();
    let force = CloseOptions { force: true, ..Default::default() };
    denied(env.as_("bot", bot(), |tx| tx.close_issue(&epic, &force)), "holds work that waits for human gate");
    assert!(env.issue(&after).is_blocked);

    // An import may not take them out of the epic or close it either.
    let mut snap = Vec::new();
    env.store.read(|r| r.export_jsonl(&mut snap, &ExportOptions::default())).unwrap();
    let snap = String::from_utf8(snap).unwrap();
    let edit = |id: &str, f: &dyn Fn(&mut Value)| -> String {
        snap.lines()
            .map(|l| {
                let mut v: Value = serde_json::from_str(l).unwrap();
                if v["id"] == id {
                    f(&mut v);
                }
                format!("{v}\n")
            })
            .collect()
    };
    let retype = |v: &mut Value| {
        for d in v["dependencies"].as_array_mut().unwrap() {
            if d["type"] == "parent-child" {
                d["type"] = json!("related");
            }
        }
    };
    let close = |v: &mut Value| {
        v["status"] = json!("closed");
        v["closed_at"] = json!(T0);
    };
    for text in [edit(&gate, &retype), edit(&work, &retype), edit(&epic, &close)] {
        let import = |tx: &mut WriteCtx<'_>| tx.import_jsonl(&mut text.as_bytes(), &ImportOptions::default());
        denied(env.as_("ops", admin_agent("ops"), import), "only a person");
    }
    assert!(env.issue(&after).is_blocked);

    // A person may restructure it.
    let mv = patch(|p| p.parent = Some(None));
    env.as_("carol", person("carol"), |tx| tx.update_issue(&work, &mv, &none, false)).unwrap();
    env.assert_healthy();
}

#[test]
fn gates_are_never_in_progress_so_claims_cannot_hide_as_gates() {
    let mut env = Env::new();
    let none = Guard::default();
    let task = env.create("Bob's work");
    env.as_("bob", agent("bob"), |tx| tx.claim(&task, &ClaimOptions::default())).unwrap();
    // Retyping a claim into a gate would make it look unclaimed: refused for everyone, locally too.
    let to_gate = patch(|p| p.issue_type = Some("gate".into()));
    for policy in [agent("alice"), admin_agent("ops"), None] {
        let e = env.as_("alice", policy, |tx| tx.update_issue(&task, &to_gate, &none, true)).unwrap_err();
        assert!(matches!(&e, Error::Refused(m) if m.contains("release it before making it a gate")), "{e}");
    }
    assert_eq!(env.issue(&task).assignee.as_deref(), Some("bob"));
    let work = env.create("Held");
    let gate = human_gate(&mut env, &work);
    let claim = patch(|p| {
        p.status = Some(Status::InProgress);
        p.assignee = Some(Some("alice".into()));
    });
    let e = env.as_("alice", None, |tx| tx.update_issue(&gate, &claim, &none, false)).unwrap_err();
    assert!(matches!(&e, Error::Refused(m) if m.contains("never in progress")), "{e}");

    // An import brings an in-progress gate in open, with a warning.
    let line = json!({
        "id": "t-9", "title": "Imported gate", "status": "in_progress", "assignee": "alice", "issue_type": "gate",
        "metadata": { "gate": { "type": "human" } }, "created_at": T0, "updated_at": T0,
    });
    let text = format!("{line}\n");
    let summary =
        env.as_("alice", None, |tx| tx.import_jsonl(&mut text.as_bytes(), &ImportOptions::default())).unwrap();
    assert!(summary.warnings.iter().any(|w| w.contains("never in progress")), "{:?}", summary.warnings);
    assert_eq!(env.issue("t-9").status, Status::Open);
    env.assert_healthy();
}

#[test]
fn a_gate_with_held_work_below_it_opens_only_for_a_person() {
    let mut env = Env::new();
    // A timer gate with a child that waits for a human gate is a container of held work like
    // any other: an agent may not open it (`bd gate check` reports it as an error).
    let later = env.create("Later");
    let mut spec = GateSpec::new(GateKind::Timer);
    spec.timeout = Some("1h".into());
    let timer = env
        .as_("alice", None, |tx| {
            tx.create_gate(NewGate {
                spec,
                blocks: vec![later.clone()],
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
    let held = child(&mut env, "alice", None, &timer, NewIssue::titled("Held below the timer"));
    let approval = human_gate(&mut env, &held);
    env.clock.advance(Duration::from_secs(2 * 3600));
    let r = env.as_("bot", agent("bot"), |tx| tx.resolve_gate(&timer, Some("timer elapsed"), false));
    denied(r, &format!("holds work that waits for human gate {approval}"));
    assert!(env.issue(&later).is_blocked);
    env.as_("carol", person("carol"), |tx| tx.resolve_gate(&timer, Some("timer elapsed"), false)).unwrap();
    assert!(!env.issue(&later).is_blocked);
    assert!(env.issue(&held).is_blocked, "{approval} still holds its work");
    // Nor may an agent delete such a gate.
    let other = env.create("Other");
    let mut spec = GateSpec::new(GateKind::Timer);
    spec.timeout = Some("1h".into());
    let gate = NewGate {
        spec,
        blocks: vec![other],
        title: None,
        description: String::new(),
        assignee: None,
        parent: None,
        priority: None,
        ephemeral: false,
    };
    let timer2 = env.as_("alice", None, |tx| tx.create_gate(gate)).unwrap().id;
    let mv = patch(|p| p.parent = Some(Some(timer2.clone())));
    env.as_("alice", None, |tx| tx.update_issue(&held, &mv, &Guard::default(), false)).unwrap();
    let del = DeleteOptions { force: true, ..Default::default() };
    denied(env.as_("bot", agent("bot"), |tx| tx.delete_issues(std::slice::from_ref(&timer2), &del)), "holds work");

    // Nor does making a container of held work a gate let it close or pin.
    let epic = env.create("Epic");
    let inside = child(&mut env, "alice", None, &epic, NewIssue::titled("Inside"));
    human_gate(&mut env, &inside);
    let after = env
        .as_("alice", None, |tx| {
            tx.create_issue(NewIssue { deps: vec![(DepType::Blocks, epic.clone())], ..NewIssue::titled("After") })
        })
        .unwrap()
        .id;
    let retype = patch(|p| p.issue_type = Some("gate".into()));
    env.as_("bot", agent("bot"), |tx| tx.update_issue(&epic, &retype, &Guard::default(), false)).unwrap();
    let force = CloseOptions { force: true, ..Default::default() };
    denied(env.as_("bot", agent("bot"), |tx| tx.close_issue(&epic, &force)), "holds work that waits for human gate");
    let pin = patch(|p| p.status = Some(Status::Pinned));
    denied(env.as_("bot", agent("bot"), |tx| tx.update_issue(&epic, &pin, &Guard::default(), false)), "pin it");
    assert!(env.issue(&after).is_blocked);

    // Work under a closed container is not held through it.
    let run = env.start(APPROVAL, &[]).unwrap();
    let inner = child(&mut env, "alice", None, &format!("{run}.deploy.upload"), NewIssue::titled("Inner"));
    env.as_("alice", None, |tx| tx.close_issue(&format!("{run}.deploy.upload"), &force)).unwrap();
    assert!(!env.issue(&inner).is_blocked);
    env.as_("bot", agent("bot"), |tx| tx.close_issue(&inner, &force)).unwrap();
    env.assert_healthy();
}

#[test]
fn a_failed_savepoint_undoes_only_its_own_writes() {
    let mut env = Env::new();
    let keep = env.create("Keep");
    let head = env.store.read(|r| r.event_head()).unwrap();
    let (kept, lost) = env
        .as_("alice", None, |tx| {
            let lost = tx.savepoint(|tx| {
                tx.create_issue(NewIssue::titled("Lost"))?;
                tx.close_issue(&keep, &CloseOptions::default())?;
                Err::<(), _>(Error::Refused("changed my mind".into()))
            });
            let kept = tx.savepoint(|tx| tx.create_issue(NewIssue::titled("Kept")))?;
            Ok((kept, lost))
        })
        .unwrap();
    assert!(matches!(lost, Err(Error::Refused(_))));
    assert_eq!(env.issue(&keep).status, Status::Open, "the failed step's close was undone");
    let titles: Vec<String> =
        env.store.read(|r| r.list(&ListQuery::default())).unwrap().into_iter().map(|i| i.title).collect();
    assert_eq!(titles, vec!["Keep", "Kept"]);
    let events = env.store.read(|r| r.events(&EventQuery { since: Some(head), ..Default::default() })).unwrap();
    let seqs: Vec<i64> = events.events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![head + 1], "only the kept step's event, numbered without a gap: {seqs:?}");
    assert_eq!(events.events[0].tx, head + 1, "and it starts its transaction");
    assert_eq!(events.events[0].issue_id.as_deref(), Some(kept.id.as_str()));
    env.assert_healthy();
}
