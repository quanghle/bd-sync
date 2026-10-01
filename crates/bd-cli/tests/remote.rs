//! End-to-end tests of `bd serve` and remote clients: real server and client
//! processes, each test with its own server on an ephemeral port.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

/// `bd` with a clean environment, run in `dir`.
fn bd(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bd"));
    c.current_dir(dir).env("BD_LOG", "error").env("XDG_CONFIG_HOME", dir.join(".xdg"));
    for var in [
        "BD_DB",
        "BD_REMOTE",
        "BD_TOKEN",
        "BD_ACTOR",
        "BEADS_ACTOR",
        "BD_CA_CERT",
        "BD_INSECURE_HTTP",
        "BD_SERVE_ROOT",
        "BD_PLAYBOOK_PATH",
        "BD_GH",
        "BD_TIMING",
        "BD_REMOTE_RETRY_SECS",
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
    ] {
        c.env_remove(var);
    }
    c
}

fn check(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed ({:?}): {}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A `bd serve` process over a temp root holding workspace `proj` (prefix `t`).
struct Server {
    child: Child,
    base: String,
    root: TempDir,
}

impl Server {
    fn start() -> Server {
        Server::start_with(&[])
    }

    fn start_with(extra: &[&str]) -> Server {
        Server::launch(Server::prepare(), "127.0.0.1:0", extra)
    }

    /// A server root with workspace `proj`.
    fn prepare() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        let ws = root.path().join("proj");
        std::fs::create_dir_all(&ws).unwrap();
        check(bd(&ws).args(["init", "--prefix", "t", "--id-mode", "counter"]).output().unwrap(), "init");
        root
    }

    fn launch(root: TempDir, listen: &str, extra: &[&str]) -> Server {
        Server::launch_with(root, listen, extra, |_| {})
    }

    /// Like `launch`, after `setup` adjusts the server's command (environment, stderr).
    fn launch_with(root: TempDir, listen: &str, extra: &[&str], setup: impl FnOnce(&mut Command)) -> Server {
        let mut cmd = bd(root.path());
        cmd.args(["serve", "--root"])
            .arg(root.path())
            .args(["--listen", listen])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        setup(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let base =
            line.split_whitespace().find(|w| w.starts_with("http")).unwrap_or_else(|| panic!("{line}")).to_string();
        Server { child, base, root }
    }

    fn url(&self) -> String {
        format!("{}/w/proj", self.base)
    }

    /// Create an access token on the server host; returns its secret.
    fn token(&self, name: &str, actor: &str, extra: &[&str]) -> String {
        create_token(self.root.path(), name, actor, extra)
    }

    fn client(&self, token: &str) -> Client {
        Client { dir: tempfile::tempdir().unwrap(), url: self.url(), token: token.to_string(), ca: None }
    }

    /// `bd` on the server's host, opening workspace `proj`'s database directly as `actor`.
    fn local(&self, actor: &str, args: &[&str]) -> Output {
        let db = self.root.path().join("proj").join(".bd").join("bd.db");
        bd(self.root.path()).arg("--db").arg(db).env("BD_ACTOR", actor).args(args).output().unwrap()
    }
}

fn create_token(root: &Path, name: &str, actor: &str, extra: &[&str]) -> String {
    let out = bd(root)
        .args(["serve", "token", "create", name, "--as", actor, "-q", "--root"])
        .arg(root)
        .args(extra)
        .output()
        .unwrap();
    check(out, "token create").trim().to_string()
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A client machine: its own directory, pointed at the server with BD_REMOTE/BD_TOKEN.
struct Client {
    dir: TempDir,
    url: String,
    token: String,
    ca: Option<std::path::PathBuf>,
}

impl Client {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = bd(self.dir.path());
        c.env("BD_REMOTE", &self.url).env("BD_TOKEN", &self.token).args(args);
        if let Some(ca) = &self.ca {
            c.env("BD_CA_CERT", ca);
        }
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        check(self.run(args), &format!("bd {args:?}"))
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.ok(&a)).unwrap()
    }

    fn code(&self, args: &[&str]) -> i32 {
        self.run(args).status.code().unwrap()
    }

    fn with_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut child =
            self.cmd(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }
}

/// One raw exec request.
fn post(url: &str, token: &str, body: &Value) -> (u16, Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).proxy(None).build().into();
    let mut r = agent
        .post(format!("{url}/v1/exec"))
        .header("authorization", format!("Bearer {token}"))
        .content_type("application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = r.status().as_u16();
    (status, serde_json::from_str(&r.body_mut().read_to_string().unwrap()).unwrap())
}

#[test]
fn remote_lifecycle_keeps_cli_output_and_exit_codes() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let bob = server.client(&server.token("bob-laptop", "bob", &[]));

    assert_eq!(alice.ok(&["-q", "create", "Design", "-p", "1"]).trim(), "t-1");
    assert_eq!(alice.ok(&["-q", "create", "Build", "--dep", "t-1"]).trim(), "t-2");
    let ready = bob.json(&["ready"]);
    assert_eq!(ready.as_array().unwrap().len(), 1);
    assert_eq!(ready[0]["id"], "t-1");

    let claim = alice.json(&["claim", "--next"]);
    assert_eq!(claim["issue"]["id"], "t-1");
    assert_eq!(claim["issue"]["assignee"], "alice", "the token's actor");
    let token = claim["lease"]["token"].as_i64().unwrap().to_string();

    assert_eq!(bob.code(&["claim", "t-1"]), 4, "already claimed");
    assert_eq!(bob.code(&["claim", "t-2"]), 4, "not ready");
    assert_eq!(bob.code(&["show", "t-404"]), 3, "not found");
    assert_eq!(bob.code(&["create", "x", "-p", "9"]), 2, "invalid priority");
    assert_eq!(bob.code(&["heartbeat", "t-1"]), 4, "bob holds no lease");
    let err = bob.run(&["--json", "release", "t-1"]);
    assert_eq!(err.status.code(), Some(4));
    let err: Value = serde_json::from_slice(&err.stderr).unwrap();
    assert_eq!(err["error"]["code"], "not_owner", "JSON errors keep their shape");

    alice.ok(&["heartbeat", "t-1", "--token", &token]);
    alice.ok(&["close", "t-1", "--reason", "done", "--token", &token]);
    assert_eq!(bob.json(&["ready"])[0]["id"], "t-2", "closing released the dependent");

    let prime = alice.ok(&["prime"]);
    assert!(prime.contains(&format!("Workspace `{}`", server.url())), "{prime}");
    assert!(prime.contains("you are `alice`"), "{prime}");
    let info = alice.json(&["info"]);
    assert_eq!(info["path"], server.url());
    assert_eq!(info["actor"], "alice");
}

#[test]
fn tokens_bind_actor_role_and_workspace() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let reader = server.client(&server.token("dashboard", "dash", &["--role", "read"]));
    let elsewhere = server.client(&server.token("other-ws", "carol", &["--workspace", "other"]));
    let admin = server.client(&server.token("ops", "ops", &["--role", "admin"]));

    let mut anonymous = server.client("");
    assert_eq!(anonymous.code(&["list"]), 7, "no BD_TOKEN");
    anonymous.token = "bdt_wrong".into();
    assert_eq!(anonymous.code(&["list"]), 7, "unknown token");
    assert_eq!(elsewhere.code(&["list"]), 7, "token scoped to another workspace");

    alice.ok(&["create", "Shared"]);
    assert_eq!(reader.code(&["list"]), 0);
    assert_eq!(reader.code(&["create", "nope"]), 7, "read-only token");
    assert_eq!(reader.code(&["claim", "--next"]), 7);
    // Every command classified as a read works on the query-only connection.
    alice.ok(&["comment", "add", "t-1", "note"]);
    for args in [
        &["show", "t-1"][..],
        &["list"],
        &["ready"],
        &["blocked"],
        &["leases"],
        &["comments", "t-1"],
        &["memories"],
        &["history", "t-1"],
        &["prime"],
        &["stats"],
        &["metrics"],
        &["export"],
        &["info"],
        &["version"],
        &["dep", "list", "t-1"],
        &["dep", "tree", "t-1"],
        &["dep", "cycles"],
        &["label", "list"],
        &["config", "list"],
        &["config", "get", "lease.ttl"],
        &["playbook", "list"],
        &["playbook", "runs"],
        &["gate", "list"],
        &["events"],
    ] {
        let out = reader.run(args);
        assert!(out.status.success(), "read token: bd {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    // Actors: the token's own, or a sub-actor per agent; nobody else's.
    assert_eq!(alice.code(&["--actor", "bob", "list"]), 7);
    let mut c = alice.cmd(&["--json", "create", "From an agent"]);
    let out = check(c.env("BD_ACTOR", "alice/agent-1").output().unwrap(), "create as sub-actor");
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["created_by"], "alice/agent-1");
    let out = alice.cmd(&["list"]).env("BD_ACTOR", "mallory").output().unwrap();
    assert_eq!(out.status.code(), Some(7), "BD_ACTOR is checked too");

    // Admin-only operations, directly or inside a batch.
    assert_eq!(alice.code(&["config", "set", "lease.ttl", "10m"]), 7);
    assert_eq!(alice.with_stdin(&["batch"], "config set lease.ttl 10m\n").status.code(), Some(7));
    assert_eq!(alice.code(&["doctor"]), 7);
    assert_eq!(alice.code(&["events", "prune", "--keep", "1"]), 7);
    admin.ok(&["config", "set", "lease.ttl", "10m"]);
    assert_eq!(alice.json(&["config", "get", "lease.ttl"])["value"], "10m");
    assert_eq!(admin.code(&["doctor"]), 0);

    // Revocation applies to the running server at once.
    check(
        bd(server.root.path())
            .args(["serve", "token", "revoke", "alice-laptop", "--root"])
            .arg(server.root.path())
            .output()
            .unwrap(),
        "revoke",
    );
    assert_eq!(alice.code(&["list"]), 7);
    let tokens = std::fs::read_to_string(server.root.path().join("tokens.json")).unwrap();
    assert!(!tokens.contains("bdt_"), "only hashes are stored");
}

#[test]
fn retried_writes_are_applied_once() {
    let server = Server::start();
    let secret = server.token("alice-laptop", "alice", &[]);
    let url = server.url();
    let req = json!({ "argv": ["create", "Exactly once", "-q"], "request_id": "retry-1" });
    let (status, first) = post(&url, &secret, &req);
    assert_eq!(status, 200, "{first}");
    assert_eq!((first["exit_code"].as_i64(), first["replayed"].as_bool()), (Some(0), Some(false)));
    let (status, second) = post(&url, &secret, &req);
    assert_eq!(status, 200);
    assert_eq!(second["replayed"], true);
    assert_eq!(second["stdout"], first["stdout"], "the stored response is replayed");

    let alice = server.client(&secret);
    let titles: Vec<Value> = alice.json(&["list"]).as_array().unwrap().iter().map(|i| i["title"].clone()).collect();
    assert_eq!(titles, vec![json!("Exactly once")]);

    // A failed write records nothing, so its retry runs again.
    let bad = json!({ "argv": ["close", "t-404"], "request_id": "retry-2" });
    assert_eq!(post(&url, &secret, &bad).1["exit_code"], 3);
    assert_eq!(post(&url, &secret, &bad).1["replayed"], false);

    // Another token cannot read or reuse the id.
    let other = server.token("bob-laptop", "bob", &[]);
    let (status, body) = post(&url, &other, &req);
    assert_eq!(status, 409, "{body}");

    // A retried claim gets the same claim back, not a second issue.
    let claim = json!({ "argv": ["--json", "claim", "--next"], "request_id": "claim-1" });
    let (_, first) = post(&url, &secret, &claim);
    let (_, again) = post(&url, &secret, &claim);
    assert_eq!((first["replayed"].as_bool(), again["replayed"].as_bool()), (Some(false), Some(true)));
    let parse = |r: &Value| serde_json::from_str::<Value>(r["stdout"].as_str().unwrap()).unwrap();
    let (c1, c2) = (parse(&first), parse(&again));
    assert_eq!(c1["issue"]["id"], "t-1");
    assert_eq!((&c1["issue"]["id"], &c1["lease"]["token"]), (&c2["issue"]["id"], &c2["lease"]["token"]));
    let leases = alice.json(&["leases"]);
    assert_eq!(leases.as_array().unwrap().len(), 1, "one lease, not two: {leases}");

    // Each CLI invocation is its own request.
    alice.ok(&["create", "Twice"]);
    alice.ok(&["create", "Twice"]);
    assert_eq!(alice.json(&["list"]).as_array().unwrap().len(), 3);
}

#[test]
fn concurrent_claims_from_remote_and_local_clients_are_exclusive() {
    let server = Server::start();
    let secret = server.token("workers", "pool", &[]);
    let admin = server.client(&secret);
    let script: String = (1..=24).map(|n| format!("create \"Task {n}\"\n")).collect();
    check(admin.with_stdin(&["batch"], &script), "batch");

    // Six remote clients, plus one process on the server's host that opens the database directly.
    let url = server.url();
    let db = server.root.path().join("proj").join(".bd").join("bd.db");
    let start = std::sync::Arc::new(std::sync::Barrier::new(7));
    let workers: Vec<_> = (0..7)
        .map(|w| {
            let (url, secret, db, start) = (url.clone(), secret.clone(), db.clone(), start.clone());
            std::thread::spawn(move || {
                let dir = tempfile::tempdir().unwrap();
                let run = |args: &[&str]| {
                    let mut cmd = bd(dir.path());
                    if w == 6 {
                        cmd.arg("--db").arg(&db).env("BD_ACTOR", "local-worker");
                    } else {
                        cmd.env("BD_REMOTE", &url).env("BD_TOKEN", &secret).env("BD_ACTOR", format!("pool/w{w}"));
                    }
                    check(cmd.args(args).output().unwrap(), &format!("worker {w}: bd {args:?}"))
                };
                start.wait();
                let mut done = Vec::new();
                loop {
                    let claim: Value = serde_json::from_str(&run(&["--json", "claim", "--next"])).unwrap();
                    if claim.is_null() {
                        return done;
                    }
                    let id = claim["issue"]["id"].as_str().unwrap().to_string();
                    let token = claim["lease"]["token"].as_i64().unwrap().to_string();
                    run(&["close", &id, "--token", &token]);
                    done.push(id);
                }
            })
        })
        .collect();
    let mut closed: Vec<String> = workers.into_iter().flat_map(|h| h.join().unwrap()).collect();
    closed.sort();
    let mut expected: Vec<String> = (1..=24).map(|n| format!("t-{n}")).collect();
    expected.sort();
    assert_eq!(closed, expected, "every issue claimed and closed by exactly one worker");

    let events = admin.ok(&["--json", "events", "--since", "0", "--op", "claimed"]);
    let mut claimed: Vec<String> = events
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["issue_id"].as_str().unwrap().to_string())
        .collect();
    claimed.sort();
    assert_eq!(claimed, expected, "one claimed event per issue");
}

#[test]
fn claim_races_on_one_issue_have_one_winner() {
    let server = Server::start();
    let secret = server.token("workers", "pool", &[]);
    let admin = server.client(&secret);
    admin.ok(&["create", "Contended"]);

    // Eight remote clients and one local process on the server's host claim t-1 at once.
    let (url, db) = (server.url(), server.root.path().join("proj").join(".bd").join("bd.db"));
    let start = std::sync::Arc::new(std::sync::Barrier::new(9));
    let racers: Vec<_> = (0..9)
        .map(|w| {
            let (url, secret, db, start) = (url.clone(), secret.clone(), db.clone(), start.clone());
            std::thread::spawn(move || {
                let dir = tempfile::tempdir().unwrap();
                let mut cmd = bd(dir.path());
                let actor = if w == 8 { "local-racer".to_string() } else { format!("pool/r{w}") };
                if w == 8 {
                    cmd.arg("--db").arg(&db);
                } else {
                    cmd.env("BD_REMOTE", &url).env("BD_TOKEN", &secret);
                }
                cmd.env("BD_ACTOR", &actor).args(["claim", "t-1"]);
                start.wait();
                (actor, cmd.output().unwrap().status.code())
            })
        })
        .collect();
    let results: Vec<(String, Option<i32>)> = racers.into_iter().map(|h| h.join().unwrap()).collect();
    let winners: Vec<&String> = results.iter().filter(|(_, c)| *c == Some(0)).map(|(a, _)| a).collect();
    assert_eq!(winners.len(), 1, "exactly one winner: {results:?}");
    assert!(results.iter().all(|(_, c)| *c == Some(0) || *c == Some(4)), "losers see a claim conflict: {results:?}");
    let issue = admin.json(&["show", "t-1"]);
    assert_eq!(issue["assignee"].as_str(), Some(winners[0].as_str()));
    let claims = admin.ok(&["--json", "events", "--since", "0", "--op", "claimed"]);
    assert_eq!(claims.lines().count(), 1, "one claimed event: {claims}");
}

#[test]
fn bench_remote_mode_verifies_invariants() {
    let dir = tempfile::tempdir().unwrap();
    let out = bd(dir.path())
        .args(["--json", "bench", "--mode", "remote", "--workers", "4", "--issues", "60"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_str(&check(out, "bench --mode remote")).unwrap();
    assert_eq!(report["mode"], "remote");
    assert_eq!(report["verified"], true, "{report}");
    assert!(report["edges"].as_i64().unwrap() > 0, "a dependency graph, so claim order is checked too");
    let claims: i64 = report["claims_by_worker"].as_array().unwrap().iter().map(|c| c.as_i64().unwrap()).sum();
    assert_eq!(claims, 60);

    let keep = dir.path().join("not-a-workspace.db");
    let out = bd(dir.path()).args(["bench", "--mode", "remote", "--keep"]).arg(&keep).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "--keep must name <root>/<name>/.bd/bd.db in remote mode");
}

#[test]
fn remote_command_configures_a_checkout() {
    let server = Server::start();
    let secret = server.token("alice-laptop", "alice", &[]);
    let checkout = tempfile::tempdir().unwrap();
    let sub = checkout.path().join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let run = |dir: &Path, token: Option<&str>, args: &[&str]| {
        let mut cmd = bd(dir);
        if let Some(t) = token {
            cmd.env("BD_TOKEN", t);
        }
        cmd.args(args).output().unwrap()
    };

    check(run(checkout.path(), None, &["remote", "set", &server.url()]), "remote set");
    let toml = std::fs::read_to_string(checkout.path().join(".bd/remote.toml")).unwrap();
    assert!(toml.contains(&format!("url = \"{}\"", server.url())), "{toml}");
    assert!(checkout.path().join(".bd/.gitignore").is_file());

    let out = run(&sub, None, &["--json", "remote", "show"]);
    assert_eq!(out.status.code(), Some(7), "no BD_TOKEN");
    let show: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((show["connected"].as_bool(), show["token_set"].as_bool()), (Some(false), Some(false)));

    let out = run(&sub, Some(&secret), &["--json", "remote", "show"]);
    let show: Value = serde_json::from_str(&check(out, "remote show")).unwrap();
    assert_eq!(show["connected"], true);
    assert_eq!(show["server"]["actor"], "alice");
    assert_eq!(show["url"], server.url());
    let out = run(&sub, Some("bdt_wrong"), &["remote", "show"]);
    assert_eq!(out.status.code(), Some(7), "a bad token fails the check");

    assert_eq!(check(run(&sub, Some(&secret), &["-q", "create", "From the checkout"]), "create").trim(), "t-1");

    check(run(&sub, None, &["remote", "unset"]), "remote unset");
    assert!(!checkout.path().join(".bd/remote.toml").exists());
    assert_eq!(run(&sub, Some(&secret), &["list"]).status.code(), Some(3), "no workspace any more");

    // A local workspace in the same .bd/ is not hidden by accident.
    check(run(checkout.path(), None, &["init", "--prefix", "loc"]), "init");
    assert_eq!(run(checkout.path(), None, &["remote", "set", &server.url()]).status.code(), Some(2));
    check(run(checkout.path(), None, &["remote", "set", &server.url(), "--force"]), "remote set --force");
    assert_eq!(check(run(&sub, Some(&secret), &["-q", "list"]), "list").trim(), "t-1", "remote.toml wins");
    assert_eq!(run(&sub, None, &["remote", "set", "http://bd.example.com/w/proj"]).status.code(), Some(2));
}

/// Run `cmd` with `input` on its stdin; returns its output.
fn with_input(mut cmd: Command, input: &str) -> Output {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn remote_login_saves_tokens_per_server() {
    let server = Server::start();
    let alice = server.token("alice-laptop", "alice", &[]);
    let bob = server.token("bob-proj", "bob", &["--workspace", "proj"]);
    let checkout = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let creds = config.path().join("bd").join("credentials.toml");
    let cmd = |token: Option<&str>, args: &[&str]| {
        let mut c = bd(checkout.path());
        c.env("XDG_CONFIG_HOME", config.path()).args(args);
        if let Some(t) = token {
            c.env("BD_TOKEN", t);
        }
        c
    };
    let run = |token: Option<&str>, args: &[&str]| with_input(cmd(token, args), "");
    let login = |input: &str, args: &[&str]| {
        let out = with_input(cmd(None, &[&["--json", "remote", "login"], args].concat()), input);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!text.contains(&alice) && !text.contains(&bob), "secrets are never printed: {text}");
        out
    };
    let json = |out: Output, what: &str| -> Value {
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!text.contains(&alice) && !text.contains(&bob), "secrets are never printed: {text}");
        serde_json::from_str(&check(out, what)).unwrap()
    };
    let show = || json(run(None, &["--json", "remote", "show"]), "remote show");

    check(run(None, &["remote", "set", &server.url()]), "remote set");
    let out = run(None, &["list"]);
    assert_eq!(out.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bd remote login"), "the error says how to fix it");

    // A token is checked before it is saved.
    let out = login("bdt_wrong\n", &[]);
    assert_eq!(out.status.code(), Some(7), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing was saved"));
    assert_eq!(login("", &[]).status.code(), Some(2), "no token on stdin");
    assert!(!creds.exists(), "nothing saved");

    // Logged in, commands need no BD_TOKEN.
    let v = json(login(&format!("{alice}\n"), &[]), "login");
    assert_eq!(
        (v["key"].as_str(), v["scope"].as_str(), v["actor"].as_str()),
        (Some(&*server.base), Some("server"), Some("alice"))
    );
    assert_eq!(v["path"].as_str().map(Path::new), Some(creds.as_path()));
    assert!(std::fs::read_to_string(&creds).unwrap().contains(&alice));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&creds), mode(creds.parent().unwrap())), (0o600, 0o700));
    }
    assert_eq!(check(run(None, &["-q", "create", "With a saved token"]), "create").trim(), "t-1");
    let v = show();
    assert_eq!((v["connected"].as_bool(), v["token_set"].as_bool()), (Some(true), Some(true)));
    assert_eq!((v["token_from"].as_str(), v["server"]["actor"].as_str()), (Some("credentials"), Some("alice")));
    assert_eq!(v["credentials"]["key"].as_str(), Some(&*server.base));
    assert_eq!(v["credentials"]["path"].as_str().map(Path::new), Some(creds.as_path()));

    // $BD_TOKEN takes precedence.
    assert_eq!(run(Some("bdt_wrong"), &["list"]).status.code(), Some(7));
    let v = json(run(Some(&bob), &["--json", "remote", "show"]), "remote show with BD_TOKEN");
    assert_eq!((v["token_from"].as_str(), v["server"]["actor"].as_str()), (Some("env"), Some("bob")));

    // A token saved for one workspace takes precedence over its server's.
    let v = json(login(&bob, &[&server.url(), "--workspace-only"]), "login --workspace-only");
    assert_eq!((v["key"].as_str(), v["scope"].as_str()), (Some(&*server.url()), Some("workspace")));
    assert_eq!(show()["server"]["actor"], "bob");
    let v = json(run(None, &["--json", "remote", "logout", "--workspace-only"]), "logout --workspace-only");
    assert_eq!(v["removed"], json!([server.url()]));
    assert_eq!(show()["server"]["actor"], "alice");

    // A file that cannot be read is an error naming it, unless $BD_TOKEN makes it unnecessary.
    let saved = std::fs::read_to_string(&creds).unwrap();
    std::fs::write(&creds, "not toml at all").unwrap();
    let out = run(None, &["list"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains(&*creds.to_string_lossy()));
    check(run(Some(&alice), &["list"]), "list with BD_TOKEN");
    std::fs::write(&creds, saved).unwrap();

    let v = json(run(None, &["--json", "remote", "logout"]), "logout");
    assert_eq!((v["removed"].clone(), v["file_removed"].as_bool()), (json!([server.base]), Some(true)));
    assert!(!creds.exists(), "the empty file is removed");
    assert_eq!(run(None, &["list"]).status.code(), Some(7), "logged out");
    let v = json(run(None, &["--json", "remote", "logout"]), "logout again");
    assert_eq!(v["removed"], json!([]));

    // An unreachable server fails the check; --no-verify saves the token anyway.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let down = format!("http://127.0.0.1:{port}/w/proj");
    let mut c = cmd(None, &["remote", "login", &down]);
    c.env("BD_REMOTE_RETRY_SECS", "0");
    assert_eq!(with_input(c, "bdt_offline").status.code(), Some(8));
    assert!(!creds.exists());
    let v = json(login("bdt_offline", &[&down, "--no-verify"]), "login --no-verify");
    assert_eq!((v["verified"].as_bool(), v["key"].as_str()), (Some(false), Some(&*format!("http://127.0.0.1:{port}"))));
    assert!(std::fs::read_to_string(&creds).unwrap().contains("bdt_offline"));
}

#[test]
fn remote_login_uses_the_platform_config_dir() {
    // Without XDG_CONFIG_HOME: %APPDATA%\bd on Windows, ~/.config/bd elsewhere.
    let home = tempfile::tempdir().unwrap();
    let (var, creds) = if cfg!(windows) {
        ("APPDATA", home.path().join("bd").join("credentials.toml"))
    } else {
        ("HOME", home.path().join(".config").join("bd").join("credentials.toml"))
    };
    let url = "https://bd.example.com/w/proj";
    let mut c = bd(home.path());
    c.env_remove("XDG_CONFIG_HOME").env(var, home.path()).args(["remote", "login", url, "--no-verify"]);
    check(with_input(c, "bdt_x"), "login");
    assert!(std::fs::read_to_string(&creds).unwrap().contains("[servers.\"https://bd.example.com\"]"));
    let mut c = bd(home.path());
    c.env_remove("XDG_CONFIG_HOME").env(var, home.path()).args(["remote", "logout", "https://bd.example.com"]);
    check(with_input(c, ""), "logout");
    assert!(!creds.exists());
}

#[test]
fn saved_tokens_stay_bound_to_the_ca_they_were_checked_with() {
    let dir = tempfile::tempdir().unwrap();
    let (server, ca_pem, _) = https_server(dir.path());
    let secret = server.token("alice-laptop", "alice", &[]);
    let config = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let cmd = |dir: &Path, args: &[&str]| {
        let mut c = bd(dir);
        c.env("XDG_CONFIG_HOME", config.path()).env("BD_REMOTE_RETRY_SECS", "0").args(args);
        c
    };
    let run = |c: Command| {
        let out = with_input(c, "");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!text.contains(&secret), "secrets are never printed: {text}");
        (out.status.code(), text)
    };
    // A checkout whose remote.toml names a CA of its own for the server's URL.
    let repo_with_ca = |pem: &[u8]| {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".bd")).unwrap();
        std::fs::write(repo.path().join(".bd/ca.pem"), pem).unwrap();
        std::fs::write(
            repo.path().join(".bd/remote.toml"),
            format!("url = \"{}\"\nca_cert = \"ca.pem\"\n", server.url()),
        )
        .unwrap();
        repo
    };
    let repo = repo_with_ca(&std::fs::read(&ca_pem).unwrap());

    // Saved trusting the system's CAs (which cannot check this test server, hence --no-verify)...
    let login = cmd(elsewhere.path(), &["--remote", &server.url(), "remote", "login", "--no-verify"]);
    check(with_input(login, &secret), "login --no-verify");
    // ...the token is not sent where a checkout's CA would be trusted instead: had it been, `list` would succeed.
    let (code, text) = run(cmd(repo.path(), &["list"]));
    assert_eq!(code, Some(7), "{text}");
    assert!(text.contains("is not sent") && text.contains("bd remote login"), "{text}");
    let (code, text) = run(cmd(repo.path(), &["prime"]));
    assert_eq!(code, Some(0), "hooks still succeed: {text}");
    assert!(text.contains("unavailable"), "{text}");
    let (code, text) = run(cmd(repo.path(), &["remote", "show"]));
    assert_eq!(code, Some(7), "{text}");
    assert!(text.contains("not usable") && text.contains("is not sent"), "{text}");

    // The user's own settings still apply: $BD_TOKEN, and $BD_CA_CERT.
    let mut c = cmd(repo.path(), &["-q", "create", "With BD_TOKEN"]);
    c.env("BD_TOKEN", &secret);
    assert_eq!(run(c), (Some(0), "t-1\n".to_string()));
    let mut c = cmd(elsewhere.path(), &["--remote", &server.url(), "-q", "list"]);
    c.env("BD_CA_CERT", &ca_pem);
    assert_eq!(run(c), (Some(0), "t-1\n".to_string()));

    // Logged in from the checkout, the token is checked and bound to its CA, whatever its line endings.
    let login = check(with_input(cmd(repo.path(), &["--json", "remote", "login"]), &secret), "login with the CA");
    let v: Value = serde_json::from_str(&login).unwrap();
    assert_eq!((v["verified"].as_bool(), v["actor"].as_str()), (Some(true), Some("alice")));
    assert_eq!(run(cmd(repo.path(), &["-q", "list"])), (Some(0), "t-1\n".to_string()));
    let other = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let other = other.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();

    // A process reads the CA once: replacing the checkout's ca.pem (a `git checkout`) does not change what a
    // running `events --follow` trusts, so its next polls neither skip the check nor fail.
    let mut follow = cmd(repo.path(), &["--json", "events", "--follow", "--interval-ms", "200"]);
    let mut follower = KillOnDrop::new(follow.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap());
    let (tx, rx) = std::sync::mpsc::channel::<Value>();
    let stdout = follower.child().stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
            if tx.send(serde_json::from_str(&line).unwrap()).is_err() {
                return;
            }
        }
    });
    let wait_for = |op: &str, issue: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(e) if e["op"] == op && e["issue_id"] == issue => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        false
    };
    assert!(wait_for("created", "t-1"));
    std::fs::write(repo.path().join(".bd/ca.pem"), other.pem()).unwrap();
    std::thread::sleep(Duration::from_millis(600));
    let mut c = cmd(elsewhere.path(), &["--remote", &server.url(), "-q", "update", "t-1", "--title", "Renamed"]);
    c.env("BD_TOKEN", &secret).env("BD_CA_CERT", &ca_pem);
    assert_eq!(run(c).0, Some(0));
    assert!(wait_for("updated", "t-1"), "the follower kept the CA it started with");
    drop(follower);
    std::fs::copy(&ca_pem, repo.path().join(".bd/ca.pem")).unwrap();

    let crlf = std::fs::read_to_string(&ca_pem).unwrap().replace("\r\n", "\n").replace('\n', "\r\n");
    let crlf_repo = repo_with_ca(crlf.as_bytes());
    assert_eq!(run(cmd(crlf_repo.path(), &["-q", "list"])), (Some(0), "t-1\n".to_string()));

    // ...and no longer sent trusting the system's CAs, or another CA (which would fail with 8 if it were tried).
    let (code, text) = run(cmd(elsewhere.path(), &["--remote", &server.url(), "list"]));
    assert_eq!(code, Some(7), "{text}");
    let other_repo = repo_with_ca(other.pem().as_bytes());
    let (code, text) = run(cmd(other_repo.path(), &["list"]));
    assert_eq!(code, Some(7), "{text}");
    assert!(text.contains("another CA certificate"), "{text}");
}

#[test]
fn tokens_passed_as_arguments_are_never_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let url = "https://bd.example.com/w/proj";
    for (args, why) in [
        (vec!["remote", "login", "bdt_fakesecret123"], "looks like an access token"),
        (vec!["remote", "logout", "bdt_fakesecret123"], "looks like an access token"),
        (vec!["remote", "login", url, "bdt_fakesecret123"], "never a token on the command line"),
        (vec!["remote", "logout", url, "bdt_fakesecret123"], "never a token on the command line"),
        (vec!["remote", "set", url, "bdt_fakesecret123"], "never a token on the command line"),
        (vec!["remote", "set", "bdt_fakesecret123"], "looks like an access token"),
        (vec!["remote", "set", "fakesecret123"], "not a URL"),
        (vec!["remote", "login", "fakesecret123"], "not a URL"),
        (vec!["remote", "logout", "fakesecret123"], "not a URL"),
    ] {
        for json in [false, true] {
            let mut c = bd(dir.path());
            if json {
                c.arg("--json");
            }
            c.args(&args);
            let out = with_input(c, "");
            let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            assert_eq!(out.status.code(), Some(2), "{args:?}: {text}");
            assert!(text.contains(why), "{args:?}: {text}");
            assert!(!text.contains("fakesecret"), "{args:?} echoed the argument: {text}");
            if json {
                let err: Value = serde_json::from_slice(&out.stderr).unwrap();
                assert_eq!(err["error"]["exit_code"], 2, "{text}");
            }
        }
    }
}

#[test]
fn prime_in_session_hooks_never_fails() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let checkout = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(checkout.path().join(".bd")).unwrap();
    std::fs::write(checkout.path().join(".bd/remote.toml"), format!("url = \"http://127.0.0.1:{port}/w/proj\"\n"))
        .unwrap();

    let out = bd(checkout.path()).arg("prime").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "no BD_TOKEN");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("unavailable") && text.contains("BD_TOKEN"), "{text}");

    let started = Instant::now();
    let out = bd(checkout.path()).env("BD_TOKEN", "bdt_x").arg("prime").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "server down");
    assert!(String::from_utf8_lossy(&out.stdout).contains("unavailable"));
    assert!(started.elapsed() < Duration::from_secs(15), "hooks are not held up: {:?}", started.elapsed());

    let out = bd(checkout.path())
        .env("BD_TOKEN", "bdt_x")
        .env("BD_REMOTE_RETRY_SECS", "0")
        .args(["--json", "prime"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(8), "--json keeps strict errors");
}

#[test]
fn stdin_and_files_travel_with_the_command() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let admin = server.client(&server.token("ops", "ops", &["--role", "admin"]));

    check(alice.with_stdin(&["batch"], "create \"A\" -p 1\ncreate \"B\" --dep $1\n"), "batch from stdin");
    std::fs::write(alice.dir.path().join("ops.txt"), "create \"C\"\n").unwrap();
    alice.ok(&["batch", "-f", "ops.txt"]);
    check(alice.with_stdin(&["comment", "add", "t-1", "--stdin"], "from stdin\nsecond line"), "comment --stdin");
    std::fs::write(alice.dir.path().join("note.md"), "from a file").unwrap();
    alice.ok(&["comment", "add", "t-1", "--file", "note.md"]);
    let comments = alice.json(&["comments", "t-1"]);
    assert_eq!(comments[0]["text"], "from stdin\nsecond line");
    assert_eq!(comments[1]["text"], "from a file");

    alice.ok(&["export", "-o", "snap.jsonl"]);
    let snap = std::fs::read_to_string(alice.dir.path().join("snap.jsonl")).unwrap();
    assert_eq!(snap.lines().count(), 4, "header + 3 issues: {snap}");
    assert!(!server.root.path().join("proj").join("snap.jsonl").exists(), "nothing written on the server");
    assert!(alice.ok(&["export"]).lines().count() == 4, "export to stdout");

    // A file the client did not send is never read from the server's disk.
    let (_, r) = post(&alice.url, &admin.token, &json!({ "argv": ["import", "/etc/hostname", "--dry-run"] }));
    assert_eq!(r["exit_code"], 2);
    assert!(r["stderr"].as_str().unwrap().contains("did not send"), "{r}");

    // Import (admin): from a file and from stdin, into a second workspace.
    let ws2 = server.root.path().join("copy");
    std::fs::create_dir_all(&ws2).unwrap();
    check(bd(&ws2).args(["init", "--prefix", "t"]).output().unwrap(), "init copy");
    std::fs::copy(alice.dir.path().join("snap.jsonl"), admin.dir.path().join("snap.jsonl")).unwrap();
    let copy = Client { url: format!("{}/w/copy", server.base), ..admin };
    copy.ok(&["import", "snap.jsonl", "--dry-run"]);
    check(copy.with_stdin(&["import", "-"], &snap), "import from stdin");
    assert_eq!(copy.json(&["list"]).as_array().unwrap().len(), 3);
}

#[test]
fn remote_configuration_and_refusals() {
    let server = Server::start();
    let secret = server.token("alice-laptop", "alice", &[]);
    let alice = server.client(&secret);
    alice.ok(&["create", "Via remote.toml"]);

    // A checkout with .bd/remote.toml talks to the server without BD_REMOTE.
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join(".bd")).unwrap();
    std::fs::write(repo.path().join(".bd/remote.toml"), format!("url = \"{}\"\n", server.url())).unwrap();
    std::fs::create_dir_all(repo.path().join("src/deep")).unwrap();
    let run = |dir: &Path, args: &[&str]| bd(dir).env("BD_TOKEN", &secret).args(args).output().unwrap();
    let out = check(run(&repo.path().join("src/deep"), &["--json", "list"]), "list via remote.toml");
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()[0]["title"], "Via remote.toml");
    assert_eq!(run(repo.path(), &["init"]).status.code(), Some(2), "init refused in a remote workspace");
    assert_eq!(bd(repo.path()).args(["list"]).output().unwrap().status.code(), Some(7), "token required");

    std::fs::write(repo.path().join(".bd/remote.toml"), format!("uri = \"{}\"\n", server.url())).unwrap();
    assert_eq!(run(repo.path(), &["list"]).status.code(), Some(2), "unknown keys are errors");

    // URL checks happen before anything is sent.
    let with_url = |url: &str| alice.cmd(&["list"]).env("BD_REMOTE", url).output().unwrap().status.code();
    assert_eq!(with_url("http://bd.example.com/w/proj"), Some(2), "plain HTTP off loopback");
    assert_eq!(with_url(&format!("{}/w/missing", server.base)), Some(3), "unknown workspace");
    assert_eq!(with_url(&server.base), Some(2), "no /w/<name>");
    assert_eq!(alice.cmd(&["list"]).env("BD_DB", "x.db").output().unwrap().status.code(), Some(2), "--db and --remote");

    // Commands that only make sense on the server's machine.
    for argv in [json!(["init"]), json!(["events", "--follow"]), json!(["serve", "--root", "/"]), json!(["bench"])] {
        let (status, r) = post(&alice.url, &secret, &json!({ "argv": argv }));
        assert_eq!((status, r["exit_code"].as_i64()), (200, Some(2)), "{argv}: {r}");
    }
    assert_eq!(alice.code(&["playbook", "show", "../../etc/passwd.toml"]), 2, "playbooks by name only");
    let (_, r) = post(&alice.url, &secret, &json!({ "argv": ["create"] }));
    assert_eq!(r["exit_code"], 2, "parse errors come back like local ones: {r}");
    assert!(r["stderr"].as_str().unwrap().contains("required"), "{r}");
}

#[test]
fn clients_retry_until_the_server_is_up() {
    let root = Server::prepare();
    let secret = create_token(root.path(), "alice-laptop", "alice", &[]);
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/w/proj");
    let client = Client { dir: tempfile::tempdir().unwrap(), url, token: secret, ca: None };

    let started = Instant::now();
    let out = client.cmd(&["list"]).env("BD_REMOTE_RETRY_SECS", "0").output().unwrap();
    assert_eq!(out.status.code(), Some(8), "server unreachable");
    assert!(started.elapsed() < Duration::from_secs(5), "BD_REMOTE_RETRY_SECS=0 tries once");

    let waiting =
        KillOnDrop::new(client.cmd(&["-q", "create", "Queued while down"]).stdout(Stdio::piped()).spawn().unwrap());
    std::thread::sleep(Duration::from_millis(700));
    let _server = Server::launch(root, &format!("127.0.0.1:{port}"), &[]);
    let out = waiting.wait_with_output();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "t-1");
}

/// Kills a child process when dropped, even if the test panics.
struct KillOnDrop(Option<Child>);

impl KillOnDrop {
    fn new(child: Child) -> KillOnDrop {
        KillOnDrop(Some(child))
    }

    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("running")
    }

    fn wait_with_output(mut self) -> Output {
        self.0.take().expect("running").wait_with_output().unwrap()
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn events_follow_polls_the_server() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    alice.ok(&["create", "Before"]);
    let mut follower = KillOnDrop::new(
        alice.cmd(&["--json", "events", "--follow", "--interval-ms", "200"]).stdout(Stdio::piped()).spawn().unwrap(),
    );
    let (tx, rx) = std::sync::mpsc::channel::<Value>();
    let stdout = follower.child().stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
            if tx.send(serde_json::from_str(&line).unwrap()).is_err() {
                return;
            }
        }
    });
    let wait_for = |issue: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(e) if e["op"] == "created" && e["issue_id"] == issue => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        false
    };
    assert!(wait_for("t-1"), "the first page includes recent history");
    alice.ok(&["create", "After"]);
    assert!(wait_for("t-2"), "the follower printed the new event");
}

/// An HTTPS server whose certificate a private CA signed; returns the server and the CA and key PEM files in `dir`.
fn https_server(dir: &Path) -> (Server, std::path::PathBuf, std::path::PathBuf) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap().signed_by(&key, &issuer).unwrap();
    let (ca_pem, cert_pem, key_pem) = (dir.join("ca.pem"), dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&ca_pem, ca_cert.pem()).unwrap();
    std::fs::write(&cert_pem, cert.pem()).unwrap();
    std::fs::write(&key_pem, key.serialize_pem()).unwrap();

    let server =
        Server::start_with(&["--tls-cert", cert_pem.to_str().unwrap(), "--tls-key", key_pem.to_str().unwrap()]);
    assert!(server.base.starts_with("https://"), "{}", server.base);
    (server, ca_pem, key_pem)
}

#[test]
fn https_with_a_private_ca() {
    let dir = tempfile::tempdir().unwrap();
    let (server, ca_pem, key_pem) = https_server(dir.path());
    let mut alice = server.client(&server.token("alice-laptop", "alice", &[]));

    let started = Instant::now();
    assert_eq!(alice.code(&["list"]), 8, "an untrusted certificate fails");
    assert!(started.elapsed() < Duration::from_secs(10), "certificate errors are not retried");

    alice.ca = Some(ca_pem.clone());
    alice.ok(&["create", "Over TLS"]);
    assert_eq!(alice.json(&["list"])[0]["title"], "Over TLS");

    // remote.toml can name the CA, relative to itself.
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join(".bd")).unwrap();
    std::fs::copy(&ca_pem, repo.path().join(".bd/ca.pem")).unwrap();
    std::fs::write(repo.path().join(".bd/remote.toml"), format!("url = \"{}\"\nca_cert = \"ca.pem\"\n", server.url()))
        .unwrap();
    let out = bd(repo.path()).env("BD_TOKEN", &alice.token).args(["-q", "list"]).output().unwrap();
    assert_eq!(check(out, "list via remote.toml with ca_cert").trim(), "t-1");

    // `bd remote set --ca-cert` copies the CA next to remote.toml.
    let fresh = tempfile::tempdir().unwrap();
    let out = bd(fresh.path()).args(["remote", "set", &server.url(), "--ca-cert"]).arg(&ca_pem).output().unwrap();
    check(out, "remote set --ca-cert");
    assert_eq!(std::fs::read(fresh.path().join(".bd/ca.pem")).unwrap(), std::fs::read(&ca_pem).unwrap());
    let out = bd(fresh.path()).env("BD_TOKEN", &alice.token).args(["remote", "show"]).output().unwrap();
    assert!(check(out, "remote show over TLS").contains("✓ connected"));
    let out = bd(fresh.path()).args(["remote", "set", &server.url(), "--ca-cert"]).arg(&key_pem).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "a key is not a CA certificate");
}

#[test]
fn serve_refuses_plain_http_off_loopback() {
    let root = tempfile::tempdir().unwrap();
    let out = bd(root.path()).args(["serve", "--listen", "0.0.0.0:0", "--root"]).arg(root.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unencrypted"));
    let out = bd(root.path()).args(["serve", "--listen", "127.0.0.1:0"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "--root is required");
    let out = bd(root.path()).args(["serve", "--max-body-mib", "0", "--root"]).arg(root.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "body limit out of range");
}

#[test]
fn oversized_requests_are_refused_before_their_body_is_read() {
    let server = Server::start_with(&["--max-body-mib", "1"]);
    let secret = server.token("alice-laptop", "alice", &[]);
    let addr = server.base.trim_start_matches("http://").to_string();
    let mut conn = std::net::TcpStream::connect(&addr).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    // Headers only: the server must answer without waiting for the 2 MiB it was promised.
    write!(
        conn,
        "POST /w/proj/v1/exec HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        2 << 20
    )
    .unwrap();
    let mut status = String::new();
    BufReader::new(&conn).read_line(&mut status).unwrap();
    assert!(status.starts_with("HTTP/1.1 413"), "{status}");

    let alice = server.client(&secret);
    alice.ok(&["create", "Small requests still run"]);
}

#[test]
fn server_log_is_plain_text_with_one_line_per_request() {
    let root = Server::prepare();
    let secret = create_token(root.path(), "alice-laptop", "alice", &[]);
    let log = root.path().join("server.log");
    let mut child = bd(root.path())
        .args(["serve", "--root"])
        .arg(root.path())
        .args(["--listen", "127.0.0.1:0"])
        .env_remove("BD_LOG")
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let base = line.split_whitespace().find(|w| w.starts_with("http")).unwrap().to_string();
    let server = KillOnDrop::new(child);
    let alice = Client { dir: tempfile::tempdir().unwrap(), url: format!("{base}/w/proj"), token: secret, ca: None };
    alice.ok(&["create", "Logged"]);
    drop(server);

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(!text.contains('\u{1b}'), "no terminal colors in a log file: {text:?}");
    let exec: Vec<&str> = text.lines().filter(|l| l.contains("exec")).collect();
    assert_eq!(exec.len(), 1, "{text}");
    assert!(exec[0].contains("token=alice-laptop") && exec[0].contains("exit_code=0"), "{}", exec[0]);
}

/// Poll until `done` holds, with a deadline generous enough for loaded CI machines.
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Leases that last a second and are reclaimable as soon as they expire.
fn short_leases(ws: &Path) {
    for (key, value) in [("lease.ttl", "1s"), ("lease.grace", "0s")] {
        check(bd(ws).args(["config", "set", key, value]).output().unwrap(), "config set");
    }
}

/// A stand-in for the server's GitHub CLI: `pr view 42` reports a merged PR,
/// any other PR a closed one.
fn merged_pr_gh(dir: &Path) -> std::path::PathBuf {
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

/// `(op, issue)` of the events the server wrote itself.
fn server_events(client: &Client) -> Vec<(String, String)> {
    let events = client.ok(&["--json", "events", "--since", "0"]);
    events
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|e| e["actor"] == "bd-serve")
        .map(|e| (e["op"].as_str().unwrap().to_string(), e["issue_id"].as_str().unwrap_or_default().to_string()))
        .collect()
}

fn has(events: &[(String, String)], op: &str, issue: &str) -> bool {
    events.iter().any(|(o, i)| o == op && i == issue)
}

#[test]
fn background_jobs_reclaim_leases_and_open_gates_without_clients() {
    let root = Server::prepare();
    short_leases(&root.path().join("proj"));
    let tools = tempfile::tempdir().unwrap();
    let gh = merged_pr_gh(tools.path());
    let fast = ["--reclaim-every", "100ms", "--gate-check-every", "100ms", "--gh-check-every", "100ms"];
    let server = Server::launch_with(root, "127.0.0.1:0", &fast, |c| {
        c.env("BD_GH", &gh);
    });
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    alice.ok(&["create", "Abandoned"]);
    alice.ok(&["create", "Baked"]);
    alice.ok(&["create", "Merged"]);
    alice.ok(&["claim", "t-1"]);
    alice.ok(&["gate", "create", "-t", "timer", "--timeout", "1s", "--blocks", "t-2"]);
    alice.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", "t-3"]);

    eventually("the dead worker's claim to be reclaimed", || alice.json(&["show", "t-1"])["status"] == "open");
    eventually("the timer gate to open", || alice.json(&["show", "t-4"])["status"] == "closed");
    // On Windows, workspace paths under bd serve are verbatim (\\?\C:\...), which cmd.exe,
    // and so this batch-file gh, refuses as a working directory (bd-sync-wnh).
    let github = !cfg!(windows);
    if github {
        eventually("the server's gh to open the PR gate", || alice.json(&["show", "t-5"])["status"] == "closed");
    }
    let ready: Vec<String> =
        alice.json(&["ready"]).as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_string()).collect();
    assert!(ready.contains(&"t-1".to_string()) && ready.contains(&"t-2".to_string()), "{ready:?}");

    let events = server_events(&alice);
    assert!(has(&events, "reclaimed", "t-1"), "written by the server as bd-serve: {events:?}");
    assert!(has(&events, "closed", "t-4"), "{events:?}");
    assert!(!github || has(&events, "closed", "t-5"), "{events:?}");
    assert_eq!(alice.json(&["show", "t-1"])["assignee"], Value::Null);
}

#[test]
fn background_jobs_can_be_turned_off() {
    let root = Server::prepare();
    short_leases(&root.path().join("proj"));
    let tools = tempfile::tempdir().unwrap();
    let gh = merged_pr_gh(tools.path());
    let flags = ["--reclaim-every", "0", "--gh-check-every", "off", "--gate-check-every", "100ms"];
    let server = Server::launch_with(root, "127.0.0.1:0", &flags, |c| {
        c.env("BD_GH", &gh);
    });
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    alice.ok(&["create", "Claimed"]);
    alice.ok(&["create", "Merged"]);
    alice.ok(&["create", "Baked"]);
    alice.ok(&["claim", "t-1"]);
    alice.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", "t-2"]);
    alice.ok(&["gate", "create", "-t", "timer", "--timeout", "2s", "--blocks", "t-3"]);

    eventually("the timer gate to open: gate checks are on", || alice.json(&["show", "t-5"])["status"] == "closed");
    // The lease expired a second before the timer opened, and gh checks would have run many times by now.
    assert_eq!(alice.json(&["show", "t-1"])["status"], "in_progress", "the reclaim sweep is off");
    assert_eq!(alice.json(&["show", "t-4"])["status"], "open", "GitHub checks are off, and --type local skips them");
    let events = server_events(&alice);
    assert!(has(&events, "closed", "t-5"), "{events:?}");
    assert!(events.iter().all(|(_, issue)| !["t-1", "t-2", "t-4"].contains(&issue.as_str())), "{events:?}");
}

#[test]
fn serve_validates_background_job_flags() {
    let root = tempfile::tempdir().unwrap();
    let not_a_dir = root.path().join("file");
    std::fs::write(&not_a_dir, "x").unwrap();
    let inside_a_file = not_a_dir.join("backups");
    for bad in [
        &["--reclaim-every", "soon"][..],
        &["--gate-check-every", "10ms"],
        &["--gh-check-every", "-1"],
        &["--backup-every", "1h"],
        &["--backup-keep", "3"],
        &["--backup-dir", inside_a_file.to_str().unwrap()],
    ] {
        let child = bd(root.path())
            .args(["serve", "--listen", "127.0.0.1:0", "--root"])
            .arg(root.path())
            .args(bad)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A flag that is wrongly accepted starts a server: do not wait on it forever.
        let mut child = KillOnDrop::new(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.child().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "bd serve {bad:?} started instead of refusing the flags");
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output();
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

/// Finished backups of workspace `proj`, oldest first.
fn backups_of_proj(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join("proj"))
        .map(|d| d.map(|e| e.unwrap().file_name().into_string().unwrap()).filter(|n| n.ends_with(".db")).collect())
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn background_backups_restore_and_keep_the_newest() {
    let root = Server::prepare();
    let backups = tempfile::tempdir().unwrap();
    let flags = ["--backup-dir", backups.path().to_str().unwrap(), "--backup-every", "200ms", "--backup-keep", "2"];
    let server = Server::launch(root, "127.0.0.1:0", &flags);
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    alice.ok(&["create", "Worth keeping"]);

    // Backups started after the create hold it; retention deletes all but the newest two.
    let before: std::collections::HashSet<String> = backups_of_proj(backups.path()).into_iter().collect();
    let mut seen = std::collections::BTreeSet::new();
    eventually("three new backups, then only the newest two kept", || {
        let now = backups_of_proj(backups.path());
        seen.extend(now.iter().cloned());
        seen.iter().filter(|n| !before.contains(*n)).count() >= 3 && now.len() == 2
    });
    for name in &seen {
        let stamp = name.strip_prefix("proj-").and_then(|n| n.strip_suffix("Z.db")).unwrap_or_default();
        assert!(stamp.len() == 19 && stamp.as_bytes()[8] == b'T', "proj-<UTC time>.db: {name}");
    }

    // The documented restore into a new workspace while the server runs: copy, then rename into place.
    let restored = server.root.path().join("restored");
    std::fs::create_dir_all(restored.join(".bd")).unwrap();
    let part = restored.join(".bd").join("bd.db.tmp");
    eventually("a copy of the newest backup", || {
        backups_of_proj(backups.path())
            .last()
            .is_some_and(|newest| std::fs::copy(backups.path().join("proj").join(newest), &part).is_ok())
    });
    std::fs::rename(&part, restored.join(".bd").join("bd.db")).unwrap();
    let list = check(bd(&restored).args(["--json", "list"]).output().unwrap(), "list the restored workspace");
    let titles: Vec<Value> =
        serde_json::from_str::<Value>(&list).unwrap().as_array().unwrap().iter().map(|i| i["title"].clone()).collect();
    assert_eq!(titles, vec![json!("Worth keeping")]);
    check(bd(&restored).arg("doctor").output().unwrap(), "doctor on the restored workspace");
}

/// A GitHub CLI that never answers: it notes that it started, then sleeps.
#[cfg(unix)]
fn hanging_gh(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let gh = dir.join("hanging-gh");
    std::fs::write(&gh, "#!/bin/sh\ntouch \"$(dirname \"$0\")/gh-started\"\nexec sleep 60\n").unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    gh
}

#[cfg(unix)]
#[test]
fn shutdown_stops_background_jobs_without_waiting_for_gh() {
    let root = Server::prepare();
    let tools = tempfile::tempdir().unwrap();
    let gh = hanging_gh(tools.path());
    let backups = tempfile::tempdir().unwrap();
    let log = tools.path().join("server.log");
    let flags =
        ["--gh-check-every", "100ms", "--backup-dir", backups.path().to_str().unwrap(), "--backup-every", "100ms"];
    let mut server = Server::launch_with(root, "127.0.0.1:0", &flags, |c| {
        c.env("BD_GH", &gh).env("BD_LOG", "bd::serve=info").stderr(std::fs::File::create(&log).unwrap());
    });
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    alice.ok(&["create", "Waits for GitHub"]);
    alice.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", "t-1"]);
    eventually("a gh call in progress", || tools.path().join("gh-started").exists());
    eventually("a backup", || !backups_of_proj(backups.path()).is_empty());

    let pid = server.child.id().to_string();
    check(Command::new("kill").args(["-TERM", &pid]).output().unwrap(), "kill -TERM");
    let stopping = Instant::now();
    let status = loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            break status;
        }
        assert!(stopping.elapsed() < Duration::from_secs(30), "bd serve did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
    assert!(stopping.elapsed() < Duration::from_secs(8), "the gh call is cancelled: {:?}", stopping.elapsed());
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("background jobs stopped"), "{text}");
    let leftovers: Vec<String> = std::fs::read_dir(backups.path().join("proj"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| !n.ends_with(".db"))
        .collect();
    assert!(leftovers.is_empty(), "no unfinished backup: {leftovers:?}");
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn only_human_tokens_resolve_human_gates() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let ops = server.client(&server.token("ops", "ops", &["--role", "admin"]));
    let carol = server.client(&server.token("carol-desk", "carol", &["--kind", "human"]));

    alice.ok(&["create", "Deploy"]);
    assert_eq!(alice.ok(&["-q", "gate", "create", "-t", "human", "--blocks", "t-1"]).trim(), "t-2");
    alice.ok(&["create", "Announce", "--dep", "t-1"]);

    // An agent token, even an admin one, cannot open the gate or get the work past it.
    let out = alice.run(&["--json", "gate", "resolve", "t-2", "-r", "lgtm"]);
    assert_eq!(out.status.code(), Some(7), "{}", stderr_of(&out));
    let err: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["code"], "unauthorized");
    assert!(err["error"]["message"].as_str().unwrap().contains("t-2 is a human gate"), "{err}");
    assert_eq!(ops.code(&["gate", "resolve", "t-2"]), 7, "admin agent token");
    for args in [
        &["close", "t-2"][..],
        &["close", "t-1", "--force"],
        &["update", "t-2", "--status", "pinned"],
        &["update", "t-2", "--type", "task"],
        &["update", "t-2", "--set-metadata", r#"gate={"type":"timer","timeout":"1s"}"#],
        &["dep", "rm", "t-1", "t-2"],
        &["delete", "t-2", "--force"],
        &["delete", "t-1", "--force"],
    ] {
        let out = alice.run(args);
        assert_eq!(out.status.code(), Some(7), "bd {args:?}: {}", stderr_of(&out));
    }
    let out = alice.with_stdin(&["batch"], "comment add t-2 \"looks fine\"\nclose t-2\n");
    assert_eq!(out.status.code(), Some(7), "inside a batch too: {}", stderr_of(&out));
    assert!(stderr_of(&out).contains("rolled back"), "{}", stderr_of(&out));
    assert_eq!(alice.json(&["comments", "t-2"]).as_array().unwrap().len(), 0, "the whole batch rolled back");
    assert_eq!(alice.json(&["show", "t-2"])["status"], "open");
    alice.ok(&["update", "t-2", "--assignee", "carol", "--title", "Approve the deploy"]);

    // A person's token opens it.
    carol.ok(&["gate", "resolve", "t-2", "-r", "approved"]);
    assert_eq!(alice.json(&["ready"])[0]["id"], "t-1");

    // Kinds show in the token list; on the server's own host nothing changes.
    let out =
        bd(server.root.path()).args(["--json", "serve", "token", "list", "--root"]).arg(server.root.path()).output();
    let list: Value = serde_json::from_str(&check(out.unwrap(), "token list")).unwrap();
    let kinds: Vec<(&str, &str)> =
        list.as_array().unwrap().iter().map(|t| (t["name"].as_str().unwrap(), t["kind"].as_str().unwrap())).collect();
    assert_eq!(kinds, vec![("alice-laptop", "agent"), ("ops", "agent"), ("carol-desk", "human")]);
    let out = bd(server.root.path()).args(["serve", "token", "list", "--root"]).arg(server.root.path()).output();
    assert!(check(out.unwrap(), "token list").contains("role write, kind human"));
    alice.ok(&["create", "Hotfix"]);
    alice.ok(&["gate", "create", "-t", "human", "--blocks", "t-4"]);
    check(server.local("local-ops", &["gate", "resolve", "t-5"]), "local resolve");
}

#[test]
fn tokens_without_a_kind_load_as_agent_tokens() {
    let root = Server::prepare();
    let secret = create_token(root.path(), "old-human", "dana", &["--kind", "human"]);
    // tokens.json as written before kinds existed.
    let path = root.path().join("tokens.json");
    let mut file: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    file["tokens"][0].as_object_mut().unwrap().remove("kind").expect("kind is stored");
    std::fs::write(&path, file.to_string()).unwrap();

    let server = Server::launch(root, "127.0.0.1:0", &[]);
    let dana = server.client(&secret);
    dana.ok(&["create", "Ship"]);
    dana.ok(&["gate", "create", "-t", "human", "--blocks", "t-1"]);
    assert_eq!(dana.code(&["gate", "resolve", "t-2"]), 7, "a token without a kind is an agent's");
    let out =
        bd(server.root.path()).args(["--json", "serve", "token", "list", "--root"]).arg(server.root.path()).output();
    let list: Value = serde_json::from_str(&check(out.unwrap(), "token list")).unwrap();
    assert_eq!(list[0]["kind"], "agent");
}

#[test]
fn force_takeovers_need_an_admin_token() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let bob = server.client(&server.token("bob-laptop", "bob", &[]));
    let ops = server.client(&server.token("ops", "ops", &["--role", "admin"]));
    let bob_as = |agent: &str, args: &[&str]| bob.cmd(args).env("BD_ACTOR", agent).output().unwrap();

    alice.ok(&["create", "Contended"]);
    check(bob_as("bob/w1", &["claim", "t-1"]), "bob/w1 claims");
    assert_eq!(alice.code(&["release", "t-1"]), 4, "without --force: not the owner, as before");
    assert_eq!(alice.code(&["update", "t-1", "--assignee", "alice"]), 4, "already claimed, as before");
    for args in [
        &["release", "t-1", "--force"][..],
        &["release", "t-1", "--if-assignee", "bob/w1"],
        &["update", "t-1", "--assignee", "alice", "--force"],
        &["update", "t-1", "--status", "open"],
        &["close", "t-1"],
        &["delete", "t-1"],
    ] {
        let out = alice.run(args);
        assert_eq!(out.status.code(), Some(7), "bd {args:?}: {}", stderr_of(&out));
        assert!(stderr_of(&out).contains("claimed by bob/w1"), "{}", stderr_of(&out));
    }
    assert_eq!(alice.with_stdin(&["batch"], "release t-1 --force\n").status.code(), Some(7));
    assert_eq!(alice.json(&["show", "t-1"])["assignee"], "bob/w1", "still bob's");
    alice.ok(&["comment", "add", "t-1", "how is it going?"]);

    // The token's other agents may take over its own claims.
    check(bob_as("bob/w2", &["update", "t-1", "--assignee", "bob/w2", "--force"]), "sub-actor takeover");
    // An admin token may take over anyone's.
    ops.ok(&["update", "t-1", "--assignee", "ops", "--force"]);
    assert_eq!(alice.json(&["show", "t-1"])["assignee"], "ops");
    // Locally, on the server's host, --force works as it always has.
    check(server.local("local-ops", &["release", "t-1", "--force"]), "local release --force");
    assert_eq!(alice.json(&["show", "t-1"])["status"], "open");
}

/// A stand-in for `gh pr view` that reports PR 42 merged and appends its
/// arguments to `gh-args.log` next to itself.
fn logging_fake_gh(dir: &Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let gh = dir.join("fake-gh.cmd");
        std::fs::write(
            &gh,
            "@echo off\r\necho %*>>\"%~dp0gh-args.log\"\r\necho {\"state\":\"MERGED\",\"title\":\"Feature\"}\r\n",
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
            "#!/bin/sh\necho \"$*\" >> \"$(dirname \"$0\")/gh-args.log\"\necho '{\"state\":\"MERGED\",\"title\":\"Feature\"}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
        gh
    }
}

#[test]
fn github_gates_only_watch_allowed_repositories() {
    let tools = tempfile::tempdir().unwrap();
    let gh = logging_fake_gh(tools.path());
    let server = Server::launch_with(Server::prepare(), "127.0.0.1:0", &[], |c| {
        c.env("BD_GH", &gh);
    });
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let ops = server.client(&server.token("ops", "ops", &["--role", "admin"]));
    for title in ["Own repo", "Legacy", "Allowed"] {
        alice.ok(&["create", title]);
    }

    // Through the server, a gate may not point the server's gh at another repository.
    let out = alice.run(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--repo", "evil/x", "--blocks", "t-1"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("not allowed"), "{}", stderr_of(&out));
    let raw = r#"{"gate":{"type":"gh:pr","await_id":"42","repo":"evil/x"}}"#;
    assert_eq!(alice.code(&["create", "Sneaky", "-t", "gate", "--metadata", raw]), 2);
    assert_eq!(alice.ok(&["-q", "gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", "t-1"]).trim(), "t-4");
    // A gate made on the server's host before any allowlist: still never probed through the server.
    let out = server.local(
        "local-ops",
        &["-q", "gate", "create", "-t", "gh:pr", "--await-id", "42", "--repo", "evil/x", "--blocks", "t-2"],
    );
    assert_eq!(check(out, "local gate create").trim(), "t-5");
    // Admins choose what else gates may watch.
    assert_eq!(alice.code(&["config", "set", "gate.repos", "*"]), 7);
    ops.ok(&["config", "set", "gate.repos", "org/*"]);
    alice.ok(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--repo", "org/app", "--blocks", "t-3"]);

    let checked = alice.json(&["gate", "check"]);
    let actions: Vec<(&str, &str)> = checked["checked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["id"].as_str().unwrap(), c["action"].as_str().unwrap()))
        .collect();
    assert_eq!(actions[1], ("t-5", "escalated"), "{checked}");
    assert!(checked["checked"][1]["detail"].as_str().unwrap().contains("evil/x is not in gate.repos"), "{checked}");
    let log = std::fs::read_to_string(tools.path().join("gh-args.log")).unwrap_or_default();
    assert!(!log.contains("evil"), "evil/x was never probed: {log}");
    // On Windows the server's batch-file gh cannot run in a verbatim workspace path (bd-sync-wnh).
    if !cfg!(windows) {
        assert_eq!(actions, vec![("t-4", "opened"), ("t-5", "escalated"), ("t-6", "opened")]);
        assert_eq!(log.lines().count(), 2, "{log}");
        assert!(log.contains("--repo=org/app"), "{log}");
    }
    assert!(alice.ok(&["prime"]).contains("t-5"), "a person sees why it is stuck");
}

#[test]
fn background_gate_checks_only_probe_allowed_repositories() {
    let root = Server::prepare();
    let ws = root.path().join("proj");
    let local = |args: &[&str]| check(bd(&ws).env("BD_ACTOR", "ops").args(args).output().unwrap(), "local bd");
    for title in ["Legacy", "Allowed", "Own repo"] {
        local(&["create", title]);
    }
    // Made on the server's host before the allowlist existed, then the allowlist.
    local(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--repo", "evil/x", "--blocks", "t-1"]);
    local(&["config", "set", "gate.repos", "org/*"]);
    local(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--repo", "org/app", "--blocks", "t-2"]);
    local(&["gate", "create", "-t", "gh:pr", "--await-id", "42", "--blocks", "t-3"]);

    let tools = tempfile::tempdir().unwrap();
    let gh = logging_fake_gh(tools.path());
    let flags = ["--gh-check-every", "100ms", "--gate-check-every", "off", "--reclaim-every", "off"];
    let server = Server::launch_with(root, "127.0.0.1:0", &flags, |c| {
        c.env("BD_GH", &gh);
    });
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    eventually("the server to escalate the gate on evil/x", || {
        alice.json(&["gate", "show", "t-4"])["phase"] == "escalated"
    });
    let gate = alice.json(&["gate", "show", "t-4"]);
    assert!(gate["escalation"].as_str().unwrap().contains("evil/x is not in gate.repos"), "{gate}");
    assert!(has(&server_events(&alice), "gate_escalated", "t-4"), "the server's own check");
    // On Windows the server's batch-file gh cannot run in a verbatim workspace path (bd-sync-wnh).
    if !cfg!(windows) {
        eventually("the allowed gates to be probed and open", || {
            ["t-5", "t-6"].iter().all(|g| alice.json(&["show", g])["status"] == "closed")
        });
        let log = std::fs::read_to_string(tools.path().join("gh-args.log")).unwrap();
        assert!(log.contains("--repo=org/app"), "{log}");
    }
    // Its escalation came from the allowlist, before any gh call: evil/x was never probed.
    let log = std::fs::read_to_string(tools.path().join("gh-args.log")).unwrap_or_default();
    assert!(!log.contains("evil"), "{log}");
}

#[test]
fn self_closing_containers_get_nothing_past_policies() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let bob = server.client(&server.token("bob-laptop", "bob", &[]));
    let id = |c: &Client, args: &[&str]| {
        let mut a = vec!["-q"];
        a.extend_from_slice(args);
        c.ok(&a).trim().to_string()
    };
    let group = r#"playbook={"role":"group"}"#;
    let mark_locally = |issue: &str| check(server.local("ops", &["update", issue, "--set-metadata", group]), "local");
    let work = id(&alice, &["create", "Deploy"]);
    let gate = id(&alice, &["gate", "create", "-t", "human", "--blocks", &work]);
    let theirs = id(&bob, &["create", "Bob's group"]);
    bob.ok(&["claim", &theirs]);
    // Only playbook runs mark self-closing runs and groups.
    for issue in [&gate, &work, &theirs] {
        let out = alice.run(&["update", issue, "--set-metadata", group]);
        assert_eq!(out.status.code(), Some(7), "{issue}: {}", stderr_of(&out));
        assert!(stderr_of(&out).contains("metadata.playbook"), "{}", stderr_of(&out));
    }

    // Marked anyway on the server's host: (a) a gate never closes itself.
    mark_locally(&gate);
    let under = id(&alice, &["create", "Under the gate", "--parent", &gate]);
    alice.ok(&["close", &under]);
    assert_eq!(alice.json(&["show", &gate])["status"], "open");
    // (b) Work held by the gate does not close when a pinned issue moved under it closes.
    mark_locally(&work);
    let pinned = id(&alice, &["create", "Pinned", "--pinned"]);
    alice.ok(&["update", &pinned, "--parent", &work]);
    let out = alice.run(&["close", &pinned]);
    assert_eq!(out.status.code(), Some(7), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains(&format!("{work} waits for human gate {gate}")), "{}", stderr_of(&out));
    assert_eq!(alice.json(&["show", &work])["status"], "open");
    // (c) Another actor's claimed group stays open, and claimed, when its last step closes.
    mark_locally(&theirs);
    let step = id(&alice, &["create", "Step", "--parent", &theirs]);
    alice.ok(&["close", &step]);
    let group = alice.json(&["show", &theirs]);
    assert_eq!((group["status"].as_str(), group["assignee"].as_str()), (Some("in_progress"), Some("bob")));
    bob.ok(&["heartbeat", &theirs]);
}

#[test]
fn held_work_and_human_gates_stay_in_their_container() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let carol = server.client(&server.token("carol-desk", "carol", &["--kind", "human"]));
    let id = |args: &[&str]| {
        let mut a = vec!["-q"];
        a.extend_from_slice(args);
        alice.ok(&a).trim().to_string()
    };
    let epic = id(&["create", "Release", "-t", "epic"]);
    let work = id(&["create", "Deploy", "--parent", &epic]);
    let gate = id(&["gate", "create", "-t", "human", "--blocks", &work]);
    let after = id(&["create", "Announce", "--dep", &epic]);
    for args in [
        &["update", work.as_str(), "--parent", ""][..],
        &["update", gate.as_str(), "--parent", ""],
        &["dep", "rm", work.as_str(), epic.as_str()],
        &["dep", "rm", gate.as_str(), epic.as_str()],
        &["close", epic.as_str(), "--force"],
        &["update", epic.as_str(), "--status", "pinned"],
        &["delete", epic.as_str(), "--force"],
    ] {
        let out = alice.run(args);
        assert_eq!(out.status.code(), Some(7), "bd {args:?}: {}", stderr_of(&out));
    }
    // Making the epic a gate does not change that.
    alice.ok(&["update", &epic, "--type", "gate"]);
    for args in [&["close", epic.as_str(), "--force"][..], &["update", epic.as_str(), "--status", "pinned"]] {
        let out = alice.run(args);
        assert_eq!(out.status.code(), Some(7), "bd {args:?}: {}", stderr_of(&out));
    }
    assert_eq!(alice.json(&["show", &after])["is_blocked"], true, "the epic's dependent still waits");
    carol.ok(&["update", &work, "--parent", ""]);
}

#[test]
fn claims_cannot_hide_as_gates() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let bob = server.client(&server.token("bob-laptop", "bob", &[]));
    bob.ok(&["create", "Bob's work"]);
    bob.ok(&["claim", "t-1"]);
    // Made a gate, a claim would look unclaimed to every claim check: refused, alone or in a batch.
    let out = alice.run(&["update", "t-1", "--type", "gate"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("release it before making it a gate"), "{}", stderr_of(&out));
    let takeover = "update t-1 --type gate\nupdate t-1 --assignee alice --force\nupdate t-1 --type task\n";
    let out = alice.with_stdin(&["batch"], takeover);
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    let issue = alice.json(&["show", "t-1"]);
    assert_eq!((issue["issue_type"].as_str(), issue["assignee"].as_str()), (Some("task"), Some("bob")));
    bob.ok(&["heartbeat", "t-1"]);
    // Nor can a gate be put in progress.
    alice.ok(&["create", "Held"]);
    alice.ok(&["gate", "create", "-t", "timer", "--timeout", "1h", "--blocks", "t-2"]);
    assert_eq!(alice.code(&["update", "t-3", "--status", "in_progress", "--assignee", "alice"]), 2);
}

/// Two timer gates due a second from now, one with a child that a human gate holds: returns
/// the plain timer, the one with the child, and the human gate.
fn timers_with_held_work_below_one(client: &Client) -> (String, String, String) {
    let id = |args: &[&str]| {
        let mut a = vec!["-q"];
        a.extend_from_slice(args);
        client.ok(&a).trim().to_string()
    };
    let (a, b, c) = (id(&["create", "A"]), id(&["create", "B"]), id(&["create", "C"]));
    let plain = id(&["gate", "create", "-t", "timer", "--timeout", "1s", "--blocks", &a]);
    let parent = id(&["gate", "create", "-t", "timer", "--timeout", "1s", "--blocks", &b]);
    let human = id(&["gate", "create", "-t", "human", "--blocks", &c]);
    client.ok(&["update", &c, "--parent", &parent]);
    (plain, parent, human)
}

#[test]
fn a_gate_check_opens_due_gates_beside_one_it_may_not() {
    let server = Server::start();
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let carol = server.client(&server.token("carol-desk", "carol", &["--kind", "human"]));
    let (plain, parent, human) = timers_with_held_work_below_one(&alice);
    // Opening the timer with held work below it would close a container of work a human gate
    // holds: an agent's check reports an error for that gate alone and opens the other.
    let mut entry = Value::Null;
    eventually("an agent's check to reach the timer with held work", || {
        let checked = alice.json(&["gate", "check"]);
        entry = checked["checked"].as_array().unwrap().iter().find(|c| c["id"] == parent.as_str()).cloned().unwrap();
        entry["action"] == "error"
    });
    assert!(entry["detail"].as_str().unwrap().contains(&format!("waits for human gate {human}")), "{entry}");
    assert_eq!(alice.json(&["show", &plain])["status"], "closed", "it was due first");
    assert_eq!(alice.json(&["show", &parent])["status"], "open");
    let checked = carol.json(&["gate", "check"]);
    assert_eq!((&checked["checked"][0]["id"], &checked["checked"][0]["action"]), (&json!(parent), &json!("opened")));
    assert_eq!(alice.json(&["show", &human])["status"], "open");

    // The server's own gate checks keep opening the others too.
    let flags = ["--gate-check-every", "100ms", "--gh-check-every", "off", "--reclaim-every", "off"];
    let server = Server::launch_with(Server::prepare(), "127.0.0.1:0", &flags, |_| {});
    let alice = server.client(&server.token("alice-laptop", "alice", &[]));
    let (plain, parent, human) = timers_with_held_work_below_one(&alice);
    eventually("the server to open the plain timer", || alice.json(&["show", &plain])["status"] == "closed");
    let late = alice.ok(&["-q", "create", "Later"]).trim().to_string();
    let late_gate = alice.ok(&["-q", "gate", "create", "-t", "timer", "--timeout", "1s", "--blocks", &late]);
    eventually("a later timer to open as well", || alice.json(&["show", late_gate.trim()])["status"] == "closed");
    assert_eq!(alice.json(&["show", &parent])["status"], "open");
    assert_eq!(alice.json(&["show", &human])["status"], "open");
}
