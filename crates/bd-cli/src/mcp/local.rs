//! Tool calls run in this process against the local workspace, as `bd
//! serve` runs a request: parsed by the CLI's grammar, executed by
//! [`crate::execute`] with output captured ([`io::capture`]).

use bd_core::{Error, Result, Store};
use clap::Parser;

use super::{Ran, Runner};
use crate::actor::Resolved;
use crate::app::App;
use crate::cli::{Cli, Global};
use crate::io::{self, Capture};

/// The most a command may print for one tool call.
pub const OUTPUT_LIMIT: usize = 4 << 20;

/// Runs tool calls in-process, as one actor, keeping the store open between
/// calls.
pub struct Local {
    global: Global,
    actor: Resolved,
    store: Option<Store>,
}

impl Local {
    /// A runner for the workspace `global` selects (`--db`, `-C`), acting as `actor`.
    pub fn new(global: Global, actor: Resolved) -> Local {
        let mut global = global;
        global.json = true;
        global.quiet = false;
        global.timing = false;
        global.remote = None;
        Local { global, actor, store: None }
    }

    /// Use `store` (the workspace's, already open) for the first call.
    pub fn set_store(&mut self, store: Option<Store>) {
        self.store = store;
    }
}

impl Runner for Local {
    fn run(&mut self, argv: &[String], _write: bool) -> Result<Ran> {
        let cli = Cli::try_parse_from(std::iter::once("bd").chain(argv.iter().map(String::as_str)))
            .map_err(|e| Error::invalid(e.to_string().lines().next().unwrap_or("invalid command line").to_string()))?;
        let mut app = App::new(self.global.clone())?;
        app.set_actor(self.actor.clone());
        if let Some(store) = self.store.take() {
            app.set_store(store);
        }
        // The policy of a token with no rights beyond the actor's own claims:
        // a model may not open human gates or take over other actors' claims.
        let (buffer, capture) = Capture::buffered(OUTPUT_LIMIT);
        let capture = Capture { token_actor: self.actor.actor.clone(), ..capture };
        let (exit_code, captured) = io::capture(capture, || crate::execute(&mut app, &cli.command));
        self.store = app.take_store();
        let stdout = String::from_utf8_lossy(buffer.borrow().output()?).into_owned();
        Ok(Ran { exit_code, stdout, stderr: String::from_utf8_lossy(&captured.stderr).into_owned() })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::actor::Source;
    use crate::mcp::{CAPABILITIES_KEY, MODERN, Server, VERSION_KEY};

    fn workspace() -> (tempfile::TempDir, Global) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join(".bd/bd.db");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        Store::init(&db, bd_core::InitOptions { prefix: "t".into(), id_mode: Default::default() }, Default::default())
            .unwrap();
        let cli = Cli::try_parse_from(["bd", "ready"]).unwrap();
        let mut global = cli.global;
        global.db = Some(db);
        (dir, global)
    }

    fn call(server: &mut Server<Local>, name: &str, arguments: Value) -> (bool, Value) {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": name, "arguments": arguments, "_meta": { VERSION_KEY: MODERN, CAPABILITIES_KEY: {} } } });
        let answer = server.handle(&request).unwrap();
        let result = &answer["result"];
        let text = result["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{answer}"));
        (result["isError"].as_bool().unwrap(), serde_json::from_str(text).unwrap())
    }

    #[test]
    fn the_coordination_loop() {
        let (_dir, global) = workspace();
        let mut server = Server::new(Local::new(global, Resolved::new("me/mcp-1", Source::Flag, "test")), false);
        let (err, a) = call(&mut server, "create", json!({ "title": "-a", "description": "--force", "priority": 1 }));
        assert!(!err, "{a}");
        assert_eq!(a["title"], "-a");
        let a = a["id"].as_str().unwrap().to_string();
        let (_, b) = call(&mut server, "create", json!({ "title": "b", "deps": [a] }));
        let b = b["id"].as_str().unwrap().to_string();

        let (_, ready) = call(&mut server, "ready", json!({ "limit": 1 }));
        assert_eq!(
            ready,
            json!({ "issues": [{ "id": a, "title": "-a", "status": "open", "priority": 1, "type": "task" }] })
        );

        let (_, claimed) = call(&mut server, "claim", json!({ "id": a }));
        let token = claimed["lease"]["token"].as_i64().unwrap();
        assert_eq!(claimed["issue"]["assignee"], "me/mcp-1");
        let (_, shown) = call(&mut server, "show", json!({ "ids": [a] }));
        assert_eq!(shown["description"], "--force");
        assert_eq!(shown["lease"]["holder"], "me/mcp-1");
        assert!(shown["lease"].get("token").is_none());
        let (err, brief) = call(&mut server, "show", json!({ "ids": [b], "brief": true }));
        assert!(!err, "{brief}");
        assert_eq!(brief["id"], b);
        assert_eq!(brief["blockers"], json!([a]));
        for key in ["design", "notes", "metadata", "created_at", "lease", "dependencies"] {
            assert!(brief.get(key).is_none(), "{key} in {brief}");
        }

        // A second claim without the token is refused, as on the command line.
        let (err, refused) = call(&mut server, "claim", json!({ "id": a }));
        assert!(err);
        assert_eq!(refused["error"]["exit_code"], 4);

        let (err, hb) = call(&mut server, "heartbeat", json!({ "id": a, "token": token }));
        assert!(!err, "{hb}");
        let (err, closed) = call(&mut server, "close", json!({ "ids": [a], "reason": "done", "token": token }));
        assert!(!err, "{closed}");
        assert_eq!(closed["unblocked"][0]["id"], b);

        let (err, bad) = call(&mut server, "close", json!({ "ids": [b] }));
        assert!(err);
        assert_eq!(bad["error"]["code"], "invalid");
        let (err, missing) = call(&mut server, "show", json!({ "ids": ["nope-1"] }));
        assert!(err);
        assert_eq!(missing["error"]["exit_code"], 3);
    }

    #[test]
    fn close_claims_the_next_issue() {
        let (_dir, global) = workspace();
        let mut server = Server::new(Local::new(global, Resolved::new("me/mcp-1", Source::Flag, "test")), false);
        let id = |server: &mut Server<Local>, args: Value| {
            call(server, "create", args).1["id"].as_str().unwrap().to_string()
        };
        let a = id(&mut server, json!({ "title": "a", "priority": 1 }));
        let b = id(&mut server, json!({ "title": "b", "priority": 2 }));
        let (_, claimed) = call(&mut server, "claim", json!({ "id": a }));
        let token = claimed["lease"]["token"].as_i64().unwrap();

        let args = json!({ "ids": [a], "reason": "done", "token": token, "claim_next": true });
        let (err, closed) = call(&mut server, "close", args.clone());
        assert!(!err, "{closed}");
        assert_eq!(closed["closed"]["issue"]["id"], a);
        assert_eq!(closed["next"]["from"], "queue");
        assert_eq!(closed["next"]["issue"]["id"], b);
        assert_eq!(closed["next"]["issue"]["assignee"], "me/mcp-1");
        let next = closed["next"]["lease"]["token"].as_i64().unwrap();
        let (err, hb) = call(&mut server, "heartbeat", json!({ "id": b, "token": next }));
        assert!(!err, "{hb}");

        // Sent again (an answer lost on the way), the close claims nothing more.
        let (err, again) = call(&mut server, "close", args);
        assert!(!err, "{again}");
        assert!(again.get("next").is_none(), "{again}");
        assert_eq!(again["next_note"], "nothing closed: not claiming");
    }

    #[test]
    fn show_says_why_an_issue_is_not_ready() {
        let (_dir, global) = workspace();
        let mut server = Server::new(Local::new(global, Resolved::new("me/mcp-1", Source::Flag, "test")), false);
        let id = |server: &mut Server<Local>, args: Value| {
            call(server, "create", args).1["id"].as_str().unwrap().to_string()
        };
        let a = id(&mut server, json!({ "title": "blocker" }));
        let b = id(&mut server, json!({ "title": "b", "deps": [a] }));
        let c = id(&mut server, json!({ "title": "c" }));
        let (err, claimed) = call(&mut server, "claim", json!({ "id": c }));
        assert!(!err, "{claimed}");
        let has = |why: &Value, check: &dyn Fn(&Value) -> bool| why["reasons"].as_array().unwrap().iter().any(check);

        let (err, shown) = call(&mut server, "show", json!({ "ids": [b, a, c], "why": true }));
        assert!(!err, "{shown}");
        assert_eq!(shown.as_array().unwrap().len(), 3, "{shown}");
        assert_eq!(shown[0]["why"]["ready"], false);
        assert!(has(&shown[0]["why"], &|r| r["kind"] == "blocked" && r["id"] == a), "{shown}");
        assert_eq!(shown[1]["why"], json!({ "ready": true }));
        assert_eq!(shown[2]["why"]["ready"], false);
        assert!(has(&shown[2]["why"], &|r| r["kind"] == "claimed" && r["holder"] == "me/mcp-1"), "{shown}");
        assert_eq!(shown[2]["lease"]["holder"], "me/mcp-1");
        assert!(shown[2]["lease"].get("token").is_none(), "{shown}");
        assert!(!shown.to_string().contains("\"token\""), "{shown}");

        let (err, brief) = call(&mut server, "show", json!({ "ids": [b], "brief": true, "why": true }));
        assert!(!err, "{brief}");
        assert_eq!(brief["id"], b);
        assert_eq!(brief["blockers"], json!([a]));
        assert_eq!(brief["why"]["ready"], false);
        assert_eq!(brief["why"]["reasons"][0]["id"], a);

        let (err, plain) = call(&mut server, "show", json!({ "ids": [a] }));
        assert!(!err, "{plain}");
        assert!(plain.get("why").is_none(), "{plain}");
    }

    /// Runs a command line through the server's own runner (for what no tool
    /// does: pinned spec issues, `supersede`), as the model's calls run.
    fn bd(server: &mut Server<Local>, argv: &[&str]) -> Value {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let ran = server.runner.run(&argv, true).unwrap();
        assert_eq!(ran.exit_code, 0, "{argv:?}: {}", ran.stderr);
        serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("{argv:?}: {e}: {}", ran.stdout))
    }

    fn id_of(created: &Value) -> String {
        created["id"].as_str().unwrap_or_else(|| panic!("{created}")).to_string()
    }

    #[test]
    fn spec_tools_end_to_end() {
        let (_dir, global) = workspace();
        let db = global.db.clone().unwrap();
        let mut server = Server::new(Local::new(global, Resolved::new("me/mcp-1", Source::Flag, "test")), false);

        // Specs off: every spec tool is refused with the CLI's own error.
        for (name, args) in [
            ("spec_list", json!({})),
            ("spec_show", json!({ "target": "checkout" })),
            ("spec_drift", json!({})),
            ("spec_none", json!({ "ids": ["t-1"], "reason": "r" })),
        ] {
            let (err, off) = call(&mut server, name, args);
            assert!(err, "{name}: {off}");
            assert_eq!(off["error"]["code"], "invalid", "{name}: {off}");
            assert_eq!(off["error"]["exit_code"], 2, "{name}: {off}");
            assert_eq!(off["error"]["message"], bd_core::specs::OFF, "{name}: {off}");
        }

        // `config set` is admin-only inside a capture: turn specs on directly.
        let mut store = Store::open(&db, Default::default()).unwrap();
        store.write("config_set", "tester", |tx| bd_core::config::set(tx, "experimental.features", "specs")).unwrap();
        drop(store);

        // In the shape `bd spec` writes: feature specs with an area, story
        // requirements with a source (closed work, linked through them).
        let design = id_of(&bd(&mut server, &["create", "--json", "--", "Design checkout"]));
        bd(&mut server, &["close", "--json", &design, "--reason", "designed"]);
        let source = format!("related:{design}");
        let spec = id_of(&bd(
            &mut server,
            &["create", "--json", "--pinned", "-t", "feature", "-l", "spec,area:checkout", "--", "Checkout"],
        ));
        let requirement = |server: &mut Server<Local>, parent: &str, title: &str| {
            id_of(&bd(
                server,
                &[
                    "create",
                    "--json",
                    "--pinned",
                    "-t",
                    "story",
                    "-l",
                    "requirement",
                    "--dep",
                    &source,
                    "--parent",
                    parent,
                    "--",
                    title,
                ],
            ))
        };
        let rule = requirement(&mut server, &spec, "Requires sign-in");
        let old = requirement(&mut server, &spec, "Guests check out");
        bd(&mut server, &["supersede", "--json", &old, "--with", &rule]);
        let sub = id_of(&bd(
            &mut server,
            &[
                "create",
                "--json",
                "--pinned",
                "-t",
                "feature",
                "-l",
                "spec,area:checkout",
                "--parent",
                &spec,
                "--",
                "Saved cards",
            ],
        ));
        requirement(&mut server, &sub, "Lists cards");

        let (err, listed) = call(&mut server, "spec_list", json!({}));
        assert!(!err, "{listed}");
        assert_eq!(listed["specs"].as_array().unwrap().len(), 2, "{listed}");
        assert_eq!(listed["specs"][0]["areas"], json!(["checkout"]), "{listed}");
        assert_eq!(listed["specs"][0]["requirements"], 1, "{listed}");

        let (err, area) = call(&mut server, "spec_show", json!({ "target": "checkout" }));
        assert!(!err, "{area}");
        assert_eq!(area["specs"].as_array().unwrap().len(), 1, "{area}");
        assert_eq!(area["specs"][0]["requirements"][0]["id"], rule, "{area}");
        assert!(!area.to_string().contains("\"history\""), "{area}");
        assert_eq!(area["specs"][0]["subspecs"][0]["spec"]["id"], sub, "{area}");
        assert!(area["specs"][0]["subspecs"][0].get("inherited").is_none(), "{area}");

        // A sub-spec shown on its own keeps what it inherits.
        let (err, shown) = call(&mut server, "spec_show", json!({ "target": sub }));
        assert!(!err, "{shown}");
        assert_eq!(shown["specs"][0]["inherited"][0]["spec"]["id"], spec, "{shown}");

        let (err, history) = call(&mut server, "spec_show", json!({ "target": spec, "history": true }));
        assert!(!err, "{history}");
        assert_eq!(history["specs"][0]["history"][0]["outcome"], "superseded", "{history}");
        assert_eq!(history["specs"][0]["history"][0]["id"], old, "{history}");

        let (err, missing) = call(&mut server, "spec_show", json!({ "target": "nope" }));
        assert!(err, "{missing}");
        assert_eq!(missing["error"]["exit_code"], 3, "{missing}");

        // Closed work linked to no spec is drift: a result, not an error.
        let (_, task) = call(&mut server, "create", json!({ "title": "Build it" }));
        let task = id_of(&task);
        let (err, closed) = call(&mut server, "close", json!({ "ids": [task], "reason": "done" }));
        assert!(!err, "{closed}");
        let (err, drift) = call(&mut server, "spec_drift", json!({}));
        assert!(!err, "{drift}");
        assert_eq!(drift["count"], 1, "{drift}");
        assert_eq!(drift["unlinked"][0]["id"], task, "{drift}");
        assert_eq!(drift["unlinked"][0]["type"], "task", "{drift}");

        let (err, none) =
            call(&mut server, "spec_none", json!({ "ids": [task], "reason": "refactor, no behavior change" }));
        assert!(!err, "{none}");
        assert_eq!(none[0]["already"], false, "{none}");
        assert!(none[0]["labels"].as_array().unwrap().contains(&json!("spec:none")), "{none}");
        let (err, shown) = call(&mut server, "show", json!({ "ids": [task] }));
        assert!(!err, "{shown}");
        assert_eq!(shown["comments"][0]["author"], "me/mcp-1", "{shown}");
        assert!(shown["comments"][0]["text"].as_str().unwrap().starts_with("No spec: "), "{shown}");

        let (err, drift) = call(&mut server, "spec_drift", json!({}));
        assert!(!err, "{drift}");
        assert_eq!(drift["count"], 0, "{drift}");
        assert!(drift.get("unlinked").is_none(), "{drift}");
        assert!(drift.get("malformed").is_none(), "{drift}");
        assert!(drift["since"].is_string(), "{drift}");

        // A spec's own issues are never marked spec:none.
        let (err, refused) = call(&mut server, "spec_none", json!({ "ids": [spec], "reason": "x" }));
        assert!(err, "{refused}");
        assert_eq!(refused["error"]["code"], "invalid", "{refused}");
        assert_eq!(refused["error"]["exit_code"], 2, "{refused}");
    }
}
