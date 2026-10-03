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
}
