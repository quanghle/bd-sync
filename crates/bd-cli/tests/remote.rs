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
        let mut child = bd(root.path())
            .args(["serve", "--root"])
            .arg(root.path())
            .args(["--listen", listen])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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
