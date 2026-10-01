//! End-to-end tests of the `bd` binary.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

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
        c.current_dir(dir).args(args).env("BD_ACTOR", actor).env("BD_LOG", "error").env_remove("BD_DB");
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

#[test]
fn crash_recovery_via_reclaim() {
    let ws = Ws::new();
    ws.ok(&["create", "Fragile"]);
    let out = ws.run_as("crashy", &["--json", "claim", "t-1", "--ttl", "1s"]);
    assert!(out.status.success());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let reclaimed = ws.json(&["reclaim", "--grace", "0s"]);
    assert_eq!(reclaimed[0]["issue_id"], "t-1");
    assert_eq!(reclaimed[0]["previous_holder"], "crashy");
    assert_eq!(ws.code_as("crashy", &["heartbeat", "t-1"]), 4, "zombie learns it lost the lease");
    let claim = ws.json(&["claim", "--next"]);
    assert_eq!(claim["issue"]["assignee"], "tester");
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
