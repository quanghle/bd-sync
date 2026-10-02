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
        c.current_dir(dir)
            .args(args)
            .env("BD_ACTOR", actor)
            .env("BD_LOG", "error")
            .env_remove("BD_DB")
            .env_remove("BD_REMOTE")
            .env_remove("BD_PLAYBOOK_PATH")
            .env_remove("BD_GH")
            .env("XDG_CONFIG_HOME", dir.join(".xdg"));
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
