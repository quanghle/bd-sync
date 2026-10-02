//! End-to-end tests of the `bd` binary.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

/// Variables that name an agent session (and so a per-session actor).
const SESSION_ENV: [&str; 6] = [
    "BD_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "COPILOT_AGENT_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "CLAUDE_ENV_FILE",
];

struct Ws {
    dir: TempDir,
}

impl Ws {
    fn new() -> Ws {
        let ws = Ws { dir: tempfile::tempdir().unwrap() };
        ws.ok(&["init", "--prefix", "t", "--id-mode", "counter"]);
        ws
    }

    fn cmd_in(dir: &Path, actor: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bd"));
        c.current_dir(dir)
            .args(args)
            .env("BD_ACTOR", actor)
            .env("BD_LOG", "error")
            .env_remove("BD_DB")
            .env_remove("BD_REMOTE")
            .env_remove("BD_PLAYBOOK_PATH")
            .env_remove("BD_GH")
            .env("XDG_CONFIG_HOME", dir.join(".xdg"));
        for var in SESSION_ENV {
            c.env_remove(var);
        }
        c
    }

    fn run_as(&self, actor: &str, args: &[&str]) -> Output {
        Ws::cmd_in(self.dir.path(), actor, args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run_as("tester", args);
        assert!(out.status.success(), "bd {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.ok(&a)).unwrap()
    }

    fn code_as(&self, actor: &str, args: &[&str]) -> i32 {
        self.run_as(actor, args).status.code().unwrap()
    }

    fn id(&self, args: &[&str]) -> String {
        let mut a = vec!["-q"];
        a.extend_from_slice(args);
        self.ok(&a).trim().to_string()
    }
}

#[test]
fn lifecycle_with_exit_codes() {
    let ws = Ws::new();
    let a = ws.id(&["create", "Design", "-p", "1"]);
    let b = ws.id(&["create", "Build", "-p", "2", "--dep", &a]);
    assert_eq!((a.as_str(), b.as_str()), ("t-1", "t-2"));

    let ready = ws.json(&["ready"]);
    assert_eq!(ready.as_array().unwrap().len(), 1);
    assert_eq!(ready[0]["id"], "t-1");

    let claim = ws.json(&["claim", "--next"]);
    assert_eq!(claim["issue"]["id"], "t-1");
    assert_eq!(claim["issue"]["status"], "in_progress");
    let token = claim["lease"]["token"].as_i64().unwrap();

    assert_eq!(ws.code_as("other", &["claim", "t-1"]), 4, "already claimed");
    assert_eq!(ws.code_as("other", &["claim", "t-2"]), 4, "not ready");
    assert_eq!(ws.code_as("tester", &["show", "t-404"]), 3, "not found");
    assert_eq!(ws.code_as("tester", &["create", "x", "-p", "9"]), 2, "invalid priority");

    let closed = ws.json(&["close", "t-1", "--token", &token.to_string(), "-r", "done"]);
    assert_eq!(closed["unblocked"][0]["id"], "t-2");
    assert_eq!(ws.json(&["ready"])[0]["id"], "t-2");

    let rev = ws.json(&["show", "t-2"])["revision"].as_i64().unwrap();
    ws.ok(&["update", "t-2", "--title", "Build it", "--if-revision", &rev.to_string()]);
    assert_eq!(ws.code_as("tester", &["update", "t-2", "-p", "0", "--if-revision", &rev.to_string()]), 13);
    assert_eq!(ws.json(&["show", "t-2"])["title"], "Build it");

    let empty = ws.json(&["claim", "--next", "--type", "bug"]);
    assert!(empty.is_null(), "no ready bugs");
}

#[test]
fn show_list_and_short_ids() {
    let ws = Ws::new();
    let epic = ws.id(&["create", "Epic", "-t", "epic"]);
    let child = ws.id(&["create", "Child", "--parent", &epic, "-l", "ui,web"]);
    assert_eq!(child, "t-1.1");
    // Ids resolve without the prefix.
    let shown = ws.json(&["show", "1.1"]);
    assert_eq!(shown["id"], "t-1.1");
    assert_eq!(shown["parent"], "t-1");
    assert_eq!(shown["labels"], serde_json::json!(["ui", "web"]));
    let both = ws.json(&["show", "t-1", "t-1.1"]);
    assert_eq!(both.as_array().unwrap().len(), 2);
    let listed = ws.json(&["list", "--label", "ui"]);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let text = ws.ok(&["list"]);
    assert!(text.contains("t-1.1") && text.contains("-- 2 issue(s)"), "{text}");
}

#[test]
fn batch_is_atomic_with_back_references() {
    let ws = Ws::new();
    let script = ws.dir.path().join("ops.txt");
    std::fs::write(
        &script,
        "# graph\ncreate \"Parent\" -t epic\ncreate \"A\" --parent $1\ncreate \"B\" --parent $1 --dep $2\n",
    )
    .unwrap();
    let out = ws.json(&["batch", "-f", script.to_str().unwrap()]);
    assert_eq!(out["committed"], true);
    assert_eq!(out["operations"].as_array().unwrap().len(), 3);
    assert_eq!(ws.json(&["show", "t-1.2"])["is_blocked"], true);

    std::fs::write(&script, "create \"Ghost\"\nclose t-999\n").unwrap();
    assert_eq!(ws.code_as("tester", &["batch", "-f", script.to_str().unwrap()]), 3);
    assert!(ws.json(&["list", "--search", "Ghost"]).as_array().unwrap().is_empty(), "rolled back");

    std::fs::write(&script, "create \"Dry\"\n").unwrap();
    let dry = ws.json(&["batch", "--dry-run", "-f", script.to_str().unwrap()]);
    assert_eq!(dry["committed"], false);
    assert!(ws.json(&["list", "--search", "Dry"]).as_array().unwrap().is_empty());
}

#[test]
fn events_cursor_and_truncation() {
    let ws = Ws::new();
    for t in ["one", "two", "three"] {
        ws.ok(&["create", t]);
    }
    let lines = ws.ok(&["--json", "events", "--since", "0"]);
    let events: Vec<Value> = lines.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(events.len() >= 5);
    for pair in events.windows(2) {
        assert_eq!(pair[1]["seq"].as_i64().unwrap(), pair[0]["seq"].as_i64().unwrap() + 1);
    }
    let last = events.last().unwrap()["seq"].as_i64().unwrap();
    let tail = ws.ok(&["--json", "events", "--since", &(last - 1).to_string()]);
    assert_eq!(tail.lines().count(), 1);
    ws.ok(&["events", "prune", "--keep", "1"]);
    assert_eq!(ws.code_as("tester", &["events", "--since", "1"]), 6, "cursor behind retained history");
    assert!(ws.json(&["history", "t-1"]).as_array().unwrap().is_empty(), "pruned history is empty, not an error");
    assert_eq!(ws.code_as("tester", &["history", "t-404"]), 3);
}

fn seqs(lines: &str) -> Vec<(i64, String)> {
    lines
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .map(|e| (e["seq"].as_i64().unwrap(), e["op"].as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn events_wait_for_a_matching_event() {
    use std::time::{Duration, Instant};
    let ws = Ws::new();
    ws.ok(&["create", "One"]);
    let head = ws.json(&["info"])["events_head"].as_i64().unwrap().to_string();

    let started = Instant::now();
    assert_eq!(ws.ok(&["events", "--since", &head, "--wait", "400ms", "--interval-ms", "50"]), "", "nothing came");
    assert!(started.elapsed() >= Duration::from_millis(400), "{:?}", started.elapsed());

    // Events its filters skip do not end the wait; the first matching one does.
    let waiter = Ws::cmd_in(ws.dir.path(), "tester", &["--json", "events", "--since", &head])
        .args(["--wait", "60s", "--op", "closed", "--interval-ms", "50"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    ws.ok(&["create", "Two"]);
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    ws.ok(&["close", "t-1"]);
    let out = waiter.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(started.elapsed() < Duration::from_secs(30), "{:?}", started.elapsed());
    let printed = seqs(&String::from_utf8(out.stdout).unwrap());
    assert_eq!(printed.iter().map(|(_, op)| op.as_str()).collect::<Vec<_>>(), ["closed"]);

    // Events already there are printed at once, like without --wait.
    let started = Instant::now();
    let now = seqs(&ws.ok(&["--json", "events", "--since", &head, "--wait", "1h"]));
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(now, seqs(&ws.ok(&["--json", "events", "--since", &head])));

    assert_eq!(ws.code_as("tester", &["events", "--wait", "1s"]), 2, "--wait needs a cursor");
    assert_eq!(ws.code_as("tester", &["events", "--since", "1", "--wait", "1s", "--follow"]), 2);
    assert_eq!(ws.code_as("tester", &["events", "--since", "1", "--wait", "soon"]), 2);

    // A deleted issue keeps its events, as for `bd history`.
    ws.ok(&["delete", "t-2"]);
    let ops: Vec<String> =
        seqs(&ws.ok(&["--json", "events", "--issue", "t-2"])).into_iter().map(|(_, op)| op).collect();
    assert_eq!(ops.first().map(String::as_str), Some("created"));
    assert_eq!(ops.last().map(String::as_str), Some("deleted"));
    assert_eq!(ws.code_as("tester", &["events", "--issue", "t-404"]), 3, "unknown issues are still errors");
}

#[test]
fn crash_recovery_via_reclaim() {
    let ws = Ws::new();
    ws.ok(&["create", "Fragile"]);
    let out = ws.run_as("crashy", &["--json", "claim", "t-1", "--ttl", "1s"]);
    assert!(out.status.success());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Sooner than lease.grace, the claim is still live: reclaiming it is a takeover.
    let reclaimed = ws.json(&["reclaim", "--grace", "0s", "--take-over"]);
    assert_eq!(reclaimed[0]["issue_id"], "t-1");
    assert_eq!(reclaimed[0]["previous_holder"], "crashy");
    assert_eq!(ws.code_as("crashy", &["heartbeat", "t-1"]), 4, "zombie learns it lost the lease");
    let claim = ws.json(&["claim", "--next"]);
    assert_eq!(claim["issue"]["assignee"], "tester");
}

impl Ws {
    fn json_as(&self, actor: &str, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        let out = self.run_as(actor, &a);
        assert!(out.status.success(), "bd {args:?} as {actor}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// `bd batch` as `actor`, from a file holding `ops`.
    fn batch_as(&self, actor: &str, ops: &str) -> Output {
        let script = self.dir.path().join("batch.txt");
        std::fs::write(&script, ops).unwrap();
        self.run_as(actor, &["batch", "-f", script.to_str().unwrap()])
    }

    /// The `data` of the last `op` event on `id`.
    fn last_event(&self, op: &str, id: &str) -> Value {
        let history = self.json(&["history", id]);
        let e = history.as_array().unwrap().iter().rev().find(|e| e["op"] == op);
        e.unwrap_or_else(|| panic!("no {op} event on {id}: {history}"))["data"].clone()
    }
}

#[test]
fn a_live_claim_is_claimed_once_even_by_the_same_actor() {
    let ws = Ws::new();
    ws.ok(&["create", "Contended"]);
    let first = ws.json_as("ann", &["claim", "t-1"]);
    let token = first["lease"]["token"].as_i64().unwrap().to_string();
    // A second session running as the same actor is told, not handed the same lease.
    let out = ws.run_as("ann", &["claim", "t-1"]);
    assert_eq!(out.status.code(), Some(4));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already claimed by ann") && err.contains("--token"), "{err}");
    assert_eq!(ws.code_as("ann", &["claim", "t-1", "--token", "99999"]), 4, "a stale token");
    // Its holder renews it with its token: the same lease.
    let again = ws.json_as("ann", &["claim", "t-1", "--token", &token]);
    assert_eq!((again["already_held"].as_bool(), &again["lease"]["token"]), (Some(true), &first["lease"]["token"]));
    assert_eq!(ws.code_as("ann", &["claim", "--next", "--token", &token]), 2, "--token names one claim");
    assert!(ws.json_as("ann", &["claim", "--next"]).is_null(), "claim --next never returns held work");
    assert_eq!(ws.batch_as("ann", "claim t-1\n").status.code(), Some(4), "nor does a batch");
    ws.ok(&["create", "Next"]);
    // The common path is unchanged: claim, work, close by the same actor.
    let next = ws.json_as("ann", &["claim", "--next"]);
    assert_eq!(next["issue"]["id"], "t-2");
    ws.json_as("ann", &["close", "t-2", "--reason", "done"]);
    ws.json_as("ann", &["close", "t-1", "--token", &token]);
}

#[test]
fn live_claims_are_protected_from_other_actors() {
    let ws = Ws::new();
    for n in 1..=6 {
        ws.ok(&["create", &format!("Task {n}")]);
    }
    let mut tokens = vec![String::new()];
    for n in 1..=6 {
        let c = ws.json_as("ann/s1", &["claim", &format!("t-{n}")]);
        tokens.push(c["lease"]["token"].as_i64().unwrap().to_string());
    }
    // Another actor, the holder's root actor, and a sibling sub-actor are all refused (exit 4)
    // anything that ends or takes over the claim, alone or in a batch (which rolls back whole).
    // --force (open children, blockers, dependents) changes nothing.
    for actor in ["bob", "ann", "ann/s2"] {
        for args in [
            &["close", "t-1"][..],
            &["close", "t-1", "--force"],
            &["close", "t-1", "--token", &tokens[1]],
            &["update", "t-1", "--status", "open"],
            &["update", "t-1", "--assignee", actor],
            &["delete", "t-1"],
            &["delete", "t-1", "--force", "--cascade"],
            &["release", "t-1"],
            &["release", "t-1", "--if-assignee", "ann/s1"],
            &["claim", "t-1"],
        ] {
            assert_eq!(ws.code_as(actor, args), 4, "bd {args:?} as {actor}");
            let line = shlex::try_join(args.iter().copied()).unwrap();
            let out = ws.batch_as(actor, &format!("comment add t-1 \"checking in\"\n{line}\n"));
            assert_eq!(out.status.code(), Some(4), "batch {line:?} as {actor}");
        }
    }
    let out = ws.run_as("bob", &["close", "t-1"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("t-1 is held by ann/s1, not bob") && err.contains("--take-over"), "{err}");
    assert!(!err.contains("bd reclaim"), "no workaround is suggested: {err}");
    assert!(ws.json(&["comments", "t-1"]).as_array().unwrap().is_empty(), "every batch rolled back");
    let shown = ws.json(&["show", "t-1"]);
    assert_eq!((shown["status"].as_str(), shown["assignee"].as_str()), (Some("in_progress"), Some("ann/s1")));
    assert_eq!(shown["lease"]["token"].as_i64().unwrap().to_string(), tokens[1]);
    ws.json_as("bob", &["update", "t-1", "--add-label", "seen", "--notes", "looked at it"]);

    // --force never takes over: on update and release, where it once did, it is a usage error,
    // alone or in a batch.
    for args in [
        &["update", "t-3", "--assignee", "ann/s2", "--force"][..],
        &["update", "t-3", "--status", "open", "--force"],
        &["release", "t-3", "--force"],
    ] {
        let (code, err) = refusal(&ws, "ann/s2", args);
        assert!(code == 2 && err.contains("--take-over"), "bd {args:?}: {err}");
        let line = shlex::try_join(args.iter().copied()).unwrap();
        assert_eq!(ws.batch_as("ann/s2", &format!("{line}\n")).status.code(), Some(2), "batch {line:?}");
    }
    assert_eq!(ws.json(&["show", "t-3"])["assignee"], "ann/s1", "still ann/s1's");

    // With --take-over each goes through, and the event history records the claim it ended.
    ws.json_as("bob", &["close", "t-1", "--take-over", "--reason", "superseded"]);
    ws.json_as("ann", &["update", "t-2", "--status", "open", "--take-over"]);
    ws.json_as("ann/s2", &["update", "t-3", "--assignee", "ann/s2", "--take-over"]);
    ws.json_as("bob", &["release", "t-4", "--if-assignee", "ann/s1", "--take-over"]);
    let out = ws.batch_as("bob", "delete t-5 --take-over\n");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for (n, op) in [(1, "closed"), (2, "updated"), (3, "updated"), (4, "released"), (5, "deleted")] {
        let data = ws.last_event(op, &format!("t-{n}"));
        let expected = serde_json::json!({ "holder": "ann/s1", "token": tokens[n].parse::<i64>().unwrap() });
        assert_eq!(data["claim_override"], expected, "t-{n} {op}: {data}");
    }
    assert_eq!(ws.json(&["show", "t-3"])["lease"]["holder"], "ann/s2", "the lease follows the takeover");
    // The holder itself needs neither --take-over nor its token.
    ws.json_as("ann/s1", &["close", "t-6"]);
    assert!(ws.last_event("closed", "t-6").get("claim_override").is_none());
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
}

#[test]
fn dead_claims_are_anyones() {
    let ws = Ws::new();
    for n in 1..=3 {
        ws.ok(&["create", &format!("Task {n}")]);
    }
    ws.ok(&["config", "set", "lease.grace", "0s"]);
    for n in 1..=3 {
        ws.json_as("crashy", &["claim", &format!("t-{n}"), "--ttl", "1s"]);
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // A claim `bd reclaim` would take back is reclaimed by a claim, and closed or released without --take-over.
    let c = ws.json_as("tester", &["claim", "t-1"]);
    assert_eq!(
        (c["issue"]["assignee"].as_str(), c["reclaimed"]["previous_holder"].as_str()),
        (Some("tester"), Some("crashy"))
    );
    assert!(ws.ok(&["claim", "t-2"]).contains("reclaimed from crashy"));
    ws.json_as("other", &["release", "t-3"]);
    assert_eq!(ws.json(&["show", "t-3"])["status"], "open");
    assert_eq!(ws.code_as("crashy", &["heartbeat", "t-1"]), 4, "the zombie learns it lost the lease");
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
}

#[test]
fn imports_take_over_live_claims_only_with_take_over() {
    let ws = Ws::new();
    ws.ok(&["create", "Task"]);
    let before = ws.dir.path().join("before.jsonl");
    ws.ok(&["export", "-o", before.to_str().unwrap()]);
    let token = ws.json_as("ann", &["claim", "t-1"])["lease"]["token"].clone();
    // The export from before the claim would put the issue back to open.
    assert_eq!(ws.code_as("bob", &["import", before.to_str().unwrap()]), 4);
    assert_eq!(ws.json(&["show", "t-1"])["assignee"], "ann");
    ws.json_as("bob", &["import", before.to_str().unwrap(), "--take-over"]);
    assert_eq!(ws.json(&["show", "t-1"])["status"], "open");
    assert_eq!(
        ws.last_event("imported", "t-1")["claim_override"],
        serde_json::json!({ "holder": "ann", "token": token })
    );
}

/// Exit code and stderr of `bd args` as `actor`.
fn refusal(ws: &Ws, actor: &str, args: &[&str]) -> (i32, String) {
    let out = ws.run_as(actor, args);
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The incident: --force, passed to get past open children, blockers, dependents or an
/// unfinished run, used to take over the claim too. Now the claim is named first, and
/// only --take-over takes it over.
#[test]
fn force_never_takes_over_a_claim() {
    let ws = Ws::new();
    let epic = ws.id(&["create", "Epic", "-t", "epic"]);
    let child = ws.id(&["create", "Child", "--parent", &epic]);
    ws.json_as("worker", &["claim", &epic, "--allow-blocked"]);
    for args in [&["close", epic.as_str()][..], &["close", epic.as_str(), "--force"]] {
        let (code, err) = refusal(&ws, "coord", args);
        assert_eq!(code, 4, "bd {args:?}: {err}");
        assert!(err.contains(&format!("{epic} is held by worker, not coord")), "{err}");
    }
    let (code, err) = refusal(&ws, "coord", &["close", &epic, "--take-over"]);
    assert!(code == 2 && err.contains("open child"), "--take-over is not --force: {err}");
    ws.json_as("coord", &["close", &epic, "--force", "--take-over"]);
    assert_eq!(ws.last_event("closed", &epic)["claim_override"]["holder"], "worker");
    assert_eq!(ws.json(&["show", &child])["status"], "open");

    // Several ids: every claim of another actor is named before anything else happens.
    let free = ws.id(&["create", "Free"]);
    let mine = ws.id(&["create", "Worker's"]);
    let theirs = ws.id(&["create", "Other's"]);
    ws.json_as("worker", &["claim", &mine]);
    ws.json_as("other", &["claim", &theirs]);
    let (code, err) = refusal(&ws, "coord", &["close", &free, &mine, "--force"]);
    assert!(code == 4 && err.contains(&format!("{mine} is held by worker")), "{err}");
    let (code, err) = refusal(&ws, "coord", &["close", &free, &mine, &theirs]);
    assert_eq!(code, 4, "{err}");
    assert!(
        err.contains(&format!("{mine} (held by worker)")) && err.contains(&format!("{theirs} (held by other)")),
        "{err}"
    );
    assert_eq!(ws.json(&["show", &free])["status"], "open", "nothing closed");

    // Deleting past dependents (--force, --cascade) is not deleting past a claim.
    let after = ws.id(&["create", "After", "--dep", &mine]);
    for args in [&["delete", mine.as_str(), "--force"][..], &["delete", mine.as_str(), "--cascade"]] {
        let (code, err) = refusal(&ws, "coord", args);
        assert!(code == 4 && err.contains("held by worker"), "bd {args:?}: {err}");
    }
    ws.json_as("coord", &["delete", &mine, "--force", "--take-over"]);
    assert_eq!(ws.last_event("deleted", &mine)["claim_override"]["holder"], "worker");
    assert_eq!(ws.json(&["show", &after])["is_blocked"], false);

    // An unfinished run (--force) with claimed steps (--take-over), listed with their holders.
    ws.playbook("two", "[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n");
    let run = ws.json(&["playbook", "run", "two"])["run"]["id"].as_str().unwrap().to_string();
    let (a, b) = (format!("{run}.a"), format!("{run}.b"));
    ws.json_as("worker", &["claim", &a]);
    ws.json_as("other", &["claim", &b]);
    for args in
        [&["playbook", "compact", run.as_str(), "--force"][..], &["playbook", "discard", run.as_str(), "--force"]]
    {
        let (code, err) = refusal(&ws, "coord", args);
        assert_eq!(code, 4, "bd {args:?}: {err}");
        assert!(
            err.contains(&format!("{a} (held by worker)")) && err.contains(&format!("{b} (held by other)")),
            "{err}"
        );
    }
    ws.json_as("coord", &["playbook", "discard", &run, "--take-over"]);
    assert_eq!(ws.last_event("deleted", &a)["claim_override"]["holder"], "worker");
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
}

#[test]
fn reclaiming_a_live_claim_early_is_a_takeover() {
    let ws = Ws::new();
    let id = ws.id(&["create", "Slow"]);
    ws.json_as("worker", &["claim", &id, "--ttl", "1s"]);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Expired, but inside lease.grace (10m): the worker may still heartbeat.
    assert_eq!(refusal(&ws, "coord", &["close", &id]).0, 4);
    assert!(ws.json_as("coord", &["reclaim"]).as_array().unwrap().is_empty(), "the configured grace");
    let (code, err) = refusal(&ws, "coord", &["reclaim", "--grace", "0s"]);
    assert!(code == 4 && err.contains(&format!("{id} is held by worker")), "{err}");
    assert_eq!(ws.json(&["show", &id])["assignee"], "worker");
    let r = ws.json_as("coord", &["reclaim", "--grace", "0s", "--take-over"]);
    assert_eq!(r[0]["issue_id"], id.as_str());
    assert_eq!(ws.last_event("reclaimed", &id)["claim_override"]["holder"], "worker");
    assert_eq!(ws.code_as("worker", &["heartbeat", &id]), 4, "the worker learns it lost the lease");
}

#[test]
fn a_run_claimed_by_another_actor_stays_open_when_its_last_step_closes() {
    let ws = Ws::new();
    ws.playbook("two", "[[steps]]\nid = \"a\"\n[[steps]]\nid = \"b\"\n");
    let run = ws.json(&["playbook", "run", "two"])["run"]["id"].as_str().unwrap().to_string();
    let (a, b) = (format!("{run}.a"), format!("{run}.b"));
    ws.json_as("coordinator", &["claim", &run]);
    ws.json_as("worker", &["claim", &a]);
    // Discarding the run would end the worker's claim: named first, --force or not.
    for args in [&["playbook", "discard", &run][..], &["playbook", "discard", &run, "--force"]] {
        let out = ws.run_as("coordinator", args);
        assert_eq!(out.status.code(), Some(4), "bd {args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("{a} is held by worker")));
    }
    ws.json_as("worker", &["close", &a]);
    let closed = ws.json_as("worker", &["close", &b]);
    assert!(closed.get("completed").is_none(), "{closed}");
    let shown = ws.json(&["show", &run]);
    assert_eq!((shown["status"].as_str(), shown["assignee"].as_str()), (Some("in_progress"), Some("coordinator")));
    // Its holder closes it.
    ws.json_as("coordinator", &["close", &run]);
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
}

#[test]
fn memory_comments_prime_and_health() {
    let ws = Ws::new();
    ws.ok(&["create", "Task"]);
    ws.ok(&["comment", "add", "t-1", "looks", "good"]);
    assert_eq!(ws.json(&["comments", "t-1"])[0]["text"], "looks good");
    let m = ws.json(&["remember", "Prefer small PRs"]);
    assert_eq!(m["memory"]["key"], "prefer-small-prs");
    assert_eq!(ws.ok(&["recall", "prefer-small-prs"]).trim(), "Prefer small PRs");
    let prime = ws.ok(&["prime"]);
    assert!(prime.contains("## Persistent memories (1)") && prime.contains("Prefer small PRs"), "{prime}");
    assert!(prime.contains("t-1"), "ready work listed");
    ws.ok(&["forget", "prefer-small-prs"]);
    assert_eq!(ws.code_as("tester", &["forget", "prefer-small-prs"]), 3);

    let metrics = ws.ok(&["metrics"]);
    assert!(metrics.contains("bd_issues{status=\"open\"} 1") && metrics.contains("bd_events_head_seq"), "{metrics}");
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
    let info = ws.json(&["info"]);
    assert_eq!(info["journal_mode"], "wal");
}

#[test]
fn export_import_round_trip_via_cli() {
    let src = Ws::new();
    src.ok(&["create", "A", "-l", "x"]);
    src.ok(&["create", "B", "--dep", "t-1"]);
    src.ok(&["remember", "--key", "k", "value"]);
    let file = src.dir.path().join("snap.jsonl");
    src.ok(&["export", "-o", file.to_str().unwrap()]);
    let dst = Ws::new();
    let summary = dst.json(&["import", file.to_str().unwrap()]);
    assert_eq!(summary["created"], 2);
    assert_eq!(dst.json(&["show", "t-2"])["is_blocked"], true);
    assert_eq!(dst.ok(&["recall", "k"]).trim(), "value");
}

#[test]
fn prime_is_silent_outside_a_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let out = Ws::cmd_in(dir.path(), "x", &["prime"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    let out = Ws::cmd_in(dir.path(), "x", &["ready"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn directory_flag_resolves_the_workspace() {
    let ws = Ws::new();
    let elsewhere = tempfile::tempdir().unwrap();
    let dir = ws.dir.path().to_str().unwrap();
    let out = Ws::cmd_in(elsewhere.path(), "tester", &["-C", dir, "--json", "info"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let info: Value = serde_json::from_slice(&out.stdout).unwrap();
    let path = info["path"].as_str().unwrap();
    assert!(!path.starts_with(r"\\?\"), "no verbatim Windows path: {path}");
    // Compare canonical forms: macOS temp dirs live under /var -> /private/var.
    let expected = ws.dir.path().join(".bd").join("bd.db");
    assert_eq!(std::fs::canonicalize(path).unwrap(), std::fs::canonicalize(expected).unwrap());
}

#[test]
fn user_playbooks_come_from_the_config_dir() {
    let ws = Ws::new();
    let step = "[[steps]]\nid = \"a\"\n";
    let xdg = ws.dir.path().join(".xdg").join("bd").join("playbooks");
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::write(xdg.join("mine.toml"), step).unwrap();
    assert_eq!(ws.json(&["playbook", "list"])["playbooks"][0]["name"], "mine");

    // Without XDG_CONFIG_HOME: %APPDATA%\bd\playbooks on Windows, ~/.config/bd/playbooks elsewhere.
    let home = ws.dir.path().join("home");
    let (var, dir) = if cfg!(windows) {
        ("APPDATA", home.join("bd").join("playbooks"))
    } else {
        ("HOME", home.join(".config").join("bd").join("playbooks"))
    };
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("theirs.toml"), step).unwrap();
    let mut c = Ws::cmd_in(ws.dir.path(), "tester", &["--json", "playbook", "list"]);
    c.env_remove("XDG_CONFIG_HOME").env(var, &home);
    let out = c.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let listed: Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> =
        listed["playbooks"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["theirs"], "{listed}");
}

impl Ws {
    fn playbook(&self, name: &str, text: &str) {
        let dir = self.dir.path().join(".bd").join("playbooks");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), text).unwrap();
    }

    fn with_env(&self, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut c = Ws::cmd_in(self.dir.path(), "tester", args);
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }
}

/// A stand-in for the GitHub CLI: `pr view 42` reports a merged PR, any other
/// PR a closed one. A batch file on Windows (std runs those through cmd.exe
/// and escapes the arguments), a shell script elsewhere.
fn fake_gh(dir: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let gh = dir.join("fake-gh.cmd");
        std::fs::write(
            &gh,
            "@echo off\r\nif \"%~3\"==\"42\" goto merged\r\necho {\"state\":\"CLOSED\",\"title\":\"Old\"}\r\nexit /b 0\r\n:merged\r\necho {\"state\":\"MERGED\",\"title\":\"Feature\"}\r\n",
        )
        .unwrap();
        gh
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let gh = dir.join("fake-gh");
        std::fs::write(
            &gh,
            "#!/bin/sh\ncase \"$3\" in 42) echo '{\"state\":\"MERGED\",\"title\":\"Feature\"}' ;; *) echo '{\"state\":\"CLOSED\",\"title\":\"Old\"}' ;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
        gh
    }
}

const DEPLOY: &str = r#"
description = "Build, approve, deploy"
[vars.service]
required = true
[[steps]]
id = "build"
title = "Build {{service}}"
[[steps]]
id = "deploy"
title = "Deploy {{service}}"
needs = ["build"]
[steps.gate]
type = "human"
"#;

#[test]
fn playbook_runs_flow_through_ready_and_gates() {
    let ws = Ws::new();
    ws.playbook("deploy", DEPLOY);
    let listed = ws.json(&["playbook", "list"]);
    assert_eq!(listed["playbooks"][0]["name"], "deploy");
    assert_eq!(listed["playbooks"][0]["vars"], serde_json::json!(["service!"]));
    assert_eq!(ws.code_as("tester", &["playbook", "run", "deploy"]), 2, "missing required var");
    assert_eq!(ws.code_as("tester", &["playbook", "run", "nope"]), 3, "unknown playbook");

    let plan = ws.json(&["playbook", "plan", "deploy", "--var", "service=api"]);
    assert_eq!(plan["dry_run"], true);
    assert!(ws.json(&["list"]).as_array().unwrap().is_empty(), "plan writes nothing");

    let run = ws.json(&["playbook", "run", "deploy", "--var", "service=api"]);
    let id = run["run"]["id"].as_str().unwrap().to_string();
    assert_eq!(run["ready"][0]["id"], format!("{id}.build"));
    let ready = ws.json(&["ready", "--run", &id]);
    assert_eq!(ready.as_array().unwrap().len(), 1, "gates and the run itself are not work");
    assert_eq!(ws.code_as("tester", &["claim", &format!("{id}.gate-deploy")]), 2, "gates are not claimed");

    ws.ok(&["close", &format!("{id}.build")]);
    let gates = ws.json(&["gate", "list"]);
    assert_eq!(gates[0]["phase"], "armed");
    assert!(ws.ok(&["prime"]).contains("Gates needing a person"), "approvals show up in prime");
    ws.ok(&["gate", "resolve", &format!("{id}.gate-deploy"), "-r", "ship it"]);
    let closed = ws.json(&["close", &format!("{id}.deploy")]);
    assert_eq!(closed["completed"][0]["id"], id.as_str());

    let status = ws.json(&["playbook", "status", &id]);
    assert_eq!(status["progress"]["done"], 2);
    assert_eq!(status["nodes"].as_array().unwrap().len(), 3);
    let runs = ws.json(&["playbook", "runs", "--all"]);
    assert_eq!(runs[0]["playbook"], "deploy");
    assert!(ws.json(&["playbook", "runs"]).as_array().unwrap().is_empty(), "finished runs are hidden by default");

    ws.ok(&["playbook", "extract", &id, "--save", "--name", "deploy-copy"]);
    let again = ws.json(&["playbook", "run", "deploy-copy"]);
    assert_eq!(again["steps"], 2);
    assert_eq!(again["gates"], 1);
    ws.ok(&["playbook", "compact", &id]);
    assert!(ws.json(&["show", &id])["notes"].as_str().unwrap().contains("ship it"));
    assert_eq!(ws.code_as("tester", &["doctor"]), 0);
}

#[test]
fn playbook_files_are_parsed_strictly() {
    let ws = Ws::new();
    ws.playbook("typo", "[[steps]]\nid = \"a\"\n[steps.gate]\ntype = \"human\"\napprovers = [\"lead\"]\n");
    let out = ws.run_as("tester", &["playbook", "show", "typo"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("approvers") && err.contains("line 5"), "{err}");
    let listed = ws.json(&["playbook", "list"]);
    assert!(listed["playbooks"][0]["error"].as_str().unwrap().contains("approvers"));
}

#[test]
fn timer_and_github_gates_via_gate_check() {
    let ws = Ws::new();
    let work = ws.id(&["create", "Bake"]);
    // The timer counts from the gate's `armed_at`, recorded inside `gate create`'s
    // transaction; read the deadline the gate stores rather than timing the process.
    let gate = ws.id(&["gate", "create", "-t", "timer", "--timeout", "2s", "--blocks", &work]);
    let deadline =
        bd_core::Timestamp::parse_rfc3339(ws.json(&["gate", "show", &gate])["deadline"].as_str().unwrap()).unwrap();
    let checked = ws.json(&["gate", "check"]);
    if bd_core::Timestamp::now() < deadline {
        assert_eq!(checked["checked"][0]["verdict"], "pending", "{checked}");
    }
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let wait = deadline.since(bd_core::Timestamp::now()).max(0) as u64 + 50;
        std::thread::sleep(std::time::Duration::from_millis(wait));
        let checked = ws.json(&["gate", "check"]);
        if checked["checked"][0]["action"] == "opened" {
            break;
        }
        assert_eq!(checked["checked"][0]["verdict"], "pending", "{checked}");
        assert!(std::time::Instant::now() < give_up, "the timer never opened: {checked}");
    }
    assert_eq!(ws.json(&["ready"])[0]["id"], work.as_str());

    let gh = fake_gh(ws.dir.path());
    let merge = ws.id(&["create", "Merge"]);
    let revive = ws.id(&["create", "Revive"]);
    ws.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", &merge]);
    ws.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "#7", "--blocks", &revive]);
    let env = [("BD_GH", gh.to_str().unwrap())];
    let out = ws.with_env(&env, &["--json", "gate", "check", "--type", "gh"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let checked: Value = serde_json::from_slice(&out.stdout).unwrap();
    let actions: Vec<&str> =
        checked["checked"].as_array().unwrap().iter().map(|c| c["action"].as_str().unwrap()).collect();
    assert_eq!(actions, vec!["opened", "escalated"]);
    let ready: Vec<String> =
        ws.json(&["ready"]).as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_string()).collect();
    assert!(ready.contains(&merge) && !ready.contains(&revive));
    assert!(ws.ok(&["prime"]).contains("escalated: PR #7 was closed"));
    let out = ws.with_env(&[("BD_GH", "/nonexistent/gh")], &["--json", "gate", "check"]);
    let checked: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(checked["checked"][0]["action"], "error", "escalated gates are still probed");
    assert!(checked["checked"][0]["detail"].as_str().unwrap().contains("cannot run"));
    assert!(ws.ok(&["gate", "list"]).contains("escalated: PR #7"), "an error changes nothing");
}

#[test]
fn gate_check_type_local_leaves_github_gates_alone() {
    let ws = Ws::new();
    let malformed = ws.id(&["create", "Hand-made gate without a condition", "-t", "gate"]);
    let (bake, merge) = (ws.id(&["create", "Bake"]), ws.id(&["create", "Merge"]));
    let timer = ws.id(&["gate", "create", "-t", "timer", "--timeout", "1h", "--blocks", &bake]);
    ws.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", &merge]);
    let env = [("BD_GH", "/nonexistent/gh")];
    let out = ws.with_env(&env, &["--json", "gate", "check", "--type", "local"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let checked: Value = serde_json::from_slice(&out.stdout).unwrap();
    let seen: Vec<(&str, &str)> = checked["checked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["id"].as_str().unwrap(), c["action"].as_str().unwrap()))
        .collect();
    assert_eq!(seen, vec![(malformed.as_str(), "escalated"), (timer.as_str(), "unchanged")], "gh is never run");
    let out = ws.with_env(&env, &["--json", "gate", "check", "--type", "gh"]);
    let checked: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(checked["checked"].as_array().unwrap().len(), 1, "{checked}");
    assert_eq!(checked["checked"][0]["action"], "error");
}

/// A stand-in for `gh run list` that prints `runs.json` from its own
/// directory and appends its arguments to `gh-args.log`.
fn fake_gh_runs(dir: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let gh = dir.join("fake-gh-runs.cmd");
        std::fs::write(&gh, "@echo off\r\necho %*>>\"%~dp0gh-args.log\"\r\ntype \"%~dp0runs.json\"\r\n").unwrap();
        gh
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let gh = dir.join("fake-gh-runs");
        std::fs::write(
            &gh,
            "#!/bin/sh\nd=$(dirname \"$0\")\necho \"$*\" >> \"$d/gh-args.log\"\ncat \"$d/runs.json\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
        gh
    }
}

#[test]
fn gh_run_gates_filter_by_branch_and_event_and_follow_the_head() {
    let ws = Ws::new();
    let gh = fake_gh_runs(ws.dir.path());
    let env = [("BD_GH", gh.to_str().unwrap())];
    let work = ws.id(&["create", "Verify"]);
    let gate = ws.json(&[
        "gate",
        "create",
        "-t",
        "gh:run",
        "--await-id",
        "release.yml",
        "--branch",
        "v1.2.3",
        "--event",
        "push",
        "--blocks",
        &work,
    ])["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        ws.code_as("tester", &["gate", "create", "-t", "gh:pr", "--await-id", "1", "--branch", "x", "--blocks", &work]),
        2
    );

    let now = bd_core::Timestamp::now().millis();
    let at = |offset_s: i64| bd_core::Timestamp(now + offset_s * 1000).to_rfc3339();
    let run = |id: u64, created: String, branch: &str, event: &str, sha: &str, status: &str, conclusion: &str| {
        serde_json::json!({"databaseId": id, "name": "Release", "createdAt": created, "headBranch": branch,
            "event": event, "headSha": sha, "status": status, "conclusion": conclusion})
    };
    let write_runs = |runs: &[Value]| {
        std::fs::write(ws.dir.path().join("runs.json"), Value::from(runs.to_vec()).to_string()).unwrap()
    };
    let check = || {
        let out = ws.with_env(&env, &["--json", "gate", "check"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["checked"][0].clone()
    };

    // Too old, then a dry run on main, then (a little before arming, by GitHub's clock) the tag push.
    let old = run(1, at(-600), "v1.2.3", "push", "aaa", "completed", "success");
    let dry = run(2, at(-40), "main", "workflow_dispatch", "bbb", "completed", "success");
    let mut tag = run(3, at(-20), "v1.2.3", "push", "ccc", "in_progress", "");
    write_runs(&[old.clone(), dry.clone(), tag.clone()]);
    let c = check();
    assert_eq!((c["verdict"].as_str(), c["run_id"].as_str()), (Some("pending"), Some("3")), "{c}");
    let args = std::fs::read_to_string(ws.dir.path().join("gh-args.log")).unwrap();
    assert!(args.contains("--branch=v1.2.3") && args.contains("--event=push"), "{args}");

    tag["status"] = "completed".into();
    tag["conclusion"] = "failure".into();
    write_runs(&[old.clone(), dry.clone(), tag.clone()]);
    assert_eq!(check()["action"], "escalated");

    // The tag is re-created on another commit: the gate follows its new run.
    let retag = run(4, at(5), "v1.2.3", "push", "ddd", "in_progress", "");
    write_runs(&[old.clone(), dry.clone(), tag.clone(), retag.clone()]);
    let c = check();
    assert_eq!((c["run_id"].as_str(), c["previous_run_id"].as_str()), (Some("4"), Some("3")), "{c}");
    let shown = ws.json(&["gate", "show", &gate]);
    assert_eq!(
        (shown["phase"].as_str(), shown["run_id"].as_str()),
        (Some("armed"), Some("4")),
        "re-pinning drops the escalation"
    );
    assert!(ws.ok(&["show", &gate]).contains("Now watching GitHub run 4 instead of 3"));
    assert_eq!(check()["action"], "unchanged", "a pinned run on the current head stays pinned");

    let mut retag = retag;
    retag["status"] = "completed".into();
    retag["conclusion"] = "success".into();
    write_runs(&[old, dry, tag, retag]);
    assert_eq!(check()["action"], "opened");
    assert_eq!(ws.json(&["ready"])[0]["id"], work.as_str());
}

#[test]
fn ephemeral_runs_are_kept_out_of_exports_and_purged() {
    let ws = Ws::new();
    ws.playbook("patrol", "ephemeral = true\n[[steps]]\nid = \"check\"\n");
    let run = ws.json(&["playbook", "run", "patrol"]);
    let id = run["run"]["id"].as_str().unwrap().to_string();
    assert_eq!(run["ephemeral"], true);
    assert!(!ws.ok(&["export"]).contains(&id));
    assert!(ws.ok(&["export", "--include-ephemeral"]).contains(&id));
    let kept = ws.json(&["playbook", "run", "patrol", "--persistent"]);
    assert_eq!(kept["ephemeral"], false);
    ws.ok(&["close", &format!("{id}.check")]);
    let purged = ws.json(&["purge"]);
    assert_eq!(purged["deleted"].as_array().unwrap().len(), 2);
    assert_eq!(ws.code_as("tester", &["show", &id]), 3);
}

/// `bd` as user `tester` with no actor named: a terminal, or with `session`
/// set, a command of an agent session.
fn as_user(ws: &Ws, session: Option<(&str, &str)>, args: &[&str]) -> Output {
    let mut c = Ws::cmd_in(ws.dir.path(), "", args);
    c.env_remove("BD_ACTOR")
        .env_remove("BEADS_ACTOR")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "user.name")
        .env("GIT_CONFIG_VALUE_0", "tester");
    if let Some((var, id)) = session {
        c.env(var, id);
    }
    c.output().unwrap()
}

const SESSION_A: (&str, &str) = ("COPILOT_AGENT_SESSION_ID", "286f56fd-c22e-458a-93ac-dfcfb9bb2788");
const SESSION_B: (&str, &str) = ("COPILOT_AGENT_SESSION_ID", "5139d45d-1aec-41fb-a65b-5e2515a04348");

#[test]
fn concurrent_agent_sessions_act_as_distinct_sub_actors() {
    let ws = Ws::new();
    ws.ok(&["create", "Shared work"]);
    let json = |session, args: &[&str]| -> Value {
        let out = as_user(&ws, session, &[&["--json"], args].concat());
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_str(&String::from_utf8(out.stdout).unwrap()).unwrap()
    };
    assert_eq!(json(None, &["info"])["actor"], "tester", "a terminal keeps the plain user");
    assert_eq!(json(None, &["info"])["actor_source"], "default");
    let a = json(Some(SESSION_A), &["info"]);
    assert_eq!((a["actor"].as_str(), a["actor_source"].as_str()), (Some("tester/copilot-b9bb2788"), Some("session")));
    assert_eq!(json(Some(SESSION_A), &["info"])["actor"], a["actor"], "every command of a session acts the same");
    assert_eq!(json(Some(("CLAUDE_CODE_SESSION_ID", "abc-123")), &["info"])["actor"], "tester/claude-abc123");
    assert_eq!(json(Some(("BD_SESSION", "worker 1")), &["info"])["actor"], "tester/worker-1");

    let claimed = as_user(&ws, Some(SESSION_A), &["claim", "t-1"]);
    let text = String::from_utf8(claimed.stdout).unwrap();
    assert!(text.contains("Claimed t-1 as tester/copilot-b9bb2788"), "{text}");
    let held = json(None, &["show", "t-1"]);
    assert_eq!(held["assignee"], "tester/copilot-b9bb2788");

    // Another session of the same user is another actor: it cannot end the claim by name.
    for args in [&["close", "t-1"][..], &["release", "t-1"], &["update", "t-1", "--status", "open"]] {
        assert_eq!(as_user(&ws, Some(SESSION_B), args).status.code(), Some(4), "{args:?}");
        assert_eq!(as_user(&ws, None, args).status.code(), Some(4), "{args:?} from a terminal");
    }
    let refused = String::from_utf8(as_user(&ws, Some(SESSION_B), &["close", "t-1"]).stderr).unwrap();
    assert!(refused.contains("held by tester/copilot-b9bb2788, not tester/copilot-15a04348"), "{refused}");
    assert_eq!(json(None, &["show", "t-1"])["status"], "in_progress");
    // Its own session closes it; a takeover stays possible on purpose.
    assert!(as_user(&ws, Some(SESSION_A), &["close", "t-1"]).status.success());
    ws.ok(&["create", "Other work"]);
    assert!(as_user(&ws, Some(SESSION_A), &["claim", "t-2"]).status.success());
    assert!(as_user(&ws, Some(SESSION_B), &["close", "t-2", "--take-over"]).status.success());
}

#[test]
fn prime_shows_the_actor_and_warns_when_it_may_be_shared() {
    let ws = Ws::new();
    ws.ok(&["create", "Work"]);
    let prime = |session| String::from_utf8(as_user(&ws, session, &["prime"]).stdout).unwrap();
    let text = prime(Some(SESSION_A));
    assert!(text.contains("you are `tester/copilot-b9bb2788` (this agent session's own actor"), "{text}");
    assert!(!prime(None).contains('⚠'), "no claims, nothing to share");

    assert!(as_user(&ws, None, &["claim", "t-1"]).status.success());
    let text = prime(None);
    assert!(text.contains("you are `tester` (from git user.name; no agent session detected)"), "{text}");
    assert!(text.contains("⚠ `tester` is the default actor") && text.contains("BD_SESSION=<name>"), "{text}");
    let out = as_user(&ws, None, &["prime", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((v["actor_source"].as_str(), v["shared_actor_claims"].as_bool()), (Some("default"), Some(true)));
    assert!(!prime(Some(SESSION_A)).contains('⚠'), "a session's own actor holds none of them");
    // An actor named outright is the user's choice.
    assert!(!ws.ok(&["prime"]).contains('⚠'));
}

#[test]
fn session_start_hook_gives_claude_sessions_their_own_actor() {
    let ws = Ws::new();
    let env_file = ws.dir.path().join("claude-env.sh");
    let hook = |extra: &[(&str, &str)], input: &str| {
        let mut c = Ws::cmd_in(ws.dir.path(), "", &["hook", "session-start"]);
        c.env_remove("BD_ACTOR").env("CLAUDE_ENV_FILE", &env_file).stdin(std::process::Stdio::piped());
        c.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        for (k, v) in extra {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let input =
        r#"{"session_id":"8e7d0c1a-0b6f-4c55-9d3e-1f2a3b4c5d6e","hook_event_name":"SessionStart","source":"startup"}"#;
    let out = hook(&[], input);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("claude-3b4c5d6e"));
    let line = "export CLAUDE_CODE_SESSION_ID=8e7d0c1a-0b6f-4c55-9d3e-1f2a3b4c5d6e\n";
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), line);
    // Later Bash commands source the file: they act as the session's sub-actor.
    let info =
        as_user(&ws, Some(("CLAUDE_CODE_SESSION_ID", "8e7d0c1a-0b6f-4c55-9d3e-1f2a3b4c5d6e")), &["--json", "info"]);
    assert_eq!(serde_json::from_slice::<Value>(&info.stdout).unwrap()["actor"], "tester/claude-3b4c5d6e");

    // A worker started from a coordinator's shell inherits its variables, yet
    // its hook writes its own id, which then replaces the inherited one.
    let worker = r#"{"session_id":"0000-child-1111","hook_event_name":"SessionStart"}"#;
    let inherited = [("CLAUDE_CODE_SESSION_ID", "8e7d0c1a-0b6f-4c55-9d3e-1f2a3b4c5d6e"), ("BD_SESSION", "crew")];
    assert!(hook(&inherited, worker).status.success());
    let written = std::fs::read_to_string(&env_file).unwrap();
    assert_eq!(written, format!("{line}export CLAUDE_CODE_SESSION_ID=0000-child-1111\n"));
    // Bad input writes nothing and never fails the hook.
    for input in ["{}", "not json", r#"{"session_id":"x\ny"}"#] {
        assert!(hook(&[], input).status.success(), "{input}");
    }
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), written);
    // Ids are quoted for the shell that sources the file.
    assert!(hook(&[], r#"{"session_id":"a'b c"}"#).status.success());
    assert!(std::fs::read_to_string(&env_file).unwrap().ends_with("export CLAUDE_CODE_SESSION_ID='a'\\''b c'\n"));
    // Without $CLAUDE_ENV_FILE (other harnesses) it does nothing.
    let out = Ws::cmd_in(ws.dir.path(), "x", &["hook", "session-start"]).stdin(std::process::Stdio::null()).output();
    assert!(out.unwrap().status.success());
}

#[test]
fn nested_sessions_do_not_act_as_their_parent() {
    let ws = Ws::new();
    let actor = |vars: &[(&str, &str)]| {
        let mut c = Ws::cmd_in(ws.dir.path(), "", &["--json", "info"]);
        c.env_remove("BD_ACTOR")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "user.name")
            .env("GIT_CONFIG_VALUE_0", "tester");
        for (k, v) in vars {
            c.env(k, v);
        }
        let v: Value = serde_json::from_slice(&c.output().unwrap().stdout).unwrap();
        v["actor"].as_str().unwrap().to_string()
    };
    // An inherited BD_SESSION never outranks the session's own id.
    assert_eq!(
        actor(&[("BD_SESSION", "claude-parent"), ("CLAUDE_CODE_SESSION_ID", "child")]),
        "tester/claude-child.claude-parent"
    );
    assert_eq!(actor(&[("BD_SESSION", "claude-parent")]), "tester/claude-parent");
    // Codex started from a Claude Code shell keeps Claude's id and adds its own.
    let claude = actor(&[("CLAUDE_CODE_SESSION_ID", "aaaa-1111")]);
    let codex = actor(&[("CLAUDE_CODE_SESSION_ID", "aaaa-1111"), ("CODEX_THREAD_ID", "zzzz-9999")]);
    assert_eq!((claude.as_str(), codex.as_str()), ("tester/claude-aaaa1111", "tester/claude-aaaa1111.codex-zzzz9999"));
}

#[test]
fn claims_of_other_sessions_of_yours_are_listed_with_their_takeover() {
    let ws = Ws::new();
    ws.ok(&["create", "Started before /clear"]);
    ws.ok(&["create", "Someone else's"]);
    assert!(as_user(&ws, Some(SESSION_A), &["claim", "t-1"]).status.success());
    assert!(ws.run_as("bob", &["claim", "t-2"]).status.success());

    // The next session of the same user (a new id) sees it, and how to take it over.
    let prime = String::from_utf8(as_user(&ws, Some(SESSION_B), &["prime"]).stdout).unwrap();
    let take_over = "bd update t-1 --assignee tester/copilot-15a04348 --take-over";
    assert!(prime.contains("## Held by other sessions of yours (1)"), "{prime}");
    assert!(prime.contains("held by tester/copilot-b9bb2788, lease expires in "), "{prime}");
    assert!(prime.contains(take_over) && !prime.contains("t-2"), "{prime}");
    let v: Value = serde_json::from_slice(&as_user(&ws, Some(SESSION_B), &["prime", "--json"]).stdout).unwrap();
    assert_eq!(v["other_sessions_claims"][0]["issue"]["id"], "t-1");
    assert_eq!(v["other_sessions_claims"][0]["take_over"], take_over);
    assert_eq!(v["claims"].as_array().unwrap().len(), 0);
    // The plain user (a terminal, or claims from before sessions had actors) is one of them too.
    let prime = String::from_utf8(as_user(&ws, None, &["prime"]).stdout).unwrap();
    assert!(prime.contains("bd update t-1 --assignee tester --take-over"), "{prime}");

    // Exit 4 against another session of yours says so, with the takeover.
    for args in [&["heartbeat", "t-1"][..], &["close", "t-1"], &["release", "t-1"], &["claim", "t-1"]] {
        let out = as_user(&ws, Some(SESSION_B), args);
        let err = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(4), "{args:?}: {err}");
        assert!(err.contains("held by another session of yours (tester/copilot-b9bb2788"), "{args:?}: {err}");
        assert!(err.contains(take_over), "{args:?}: {err}");
    }
    // Not against another user's claim.
    let err = String::from_utf8(as_user(&ws, Some(SESSION_B), &["close", "t-2"]).stderr).unwrap();
    assert!(err.contains("pick other work") && !err.contains("session of yours"), "{err}");

    // The takeover it names works, and moves the lease.
    let mut cmd: Vec<&str> = take_over.split(' ').skip(1).collect();
    cmd.retain(|a| !a.is_empty());
    assert!(as_user(&ws, Some(SESSION_B), &cmd).status.success());
    assert!(as_user(&ws, Some(SESSION_B), &["heartbeat", "t-1"]).status.success());
    assert_eq!(as_user(&ws, Some(SESSION_A), &["heartbeat", "t-1"]).status.code(), Some(4));
}
