//! `bd mcp`: the tool catalog over stdio, one JSON-RPC message per line,
//! for the workspace the command finds (local, or on a bd server).

use std::io::{BufRead, Read};

use bd_core::{Error, Result};
use serde_json::json;

use super::local::Local;
use super::{Ran, Runner, Server};
use crate::actor;
use crate::app::App;
use crate::auth::random_hex;
use crate::cli::{Global, McpArgs};
use crate::io;
use crate::protocol::ExecRequest;
use crate::remote;

/// Longest message a client may send.
const MAX_LINE: usize = 1 << 20;

pub fn cmd_mcp(app: &mut App, a: &McpArgs) -> Result<i32> {
    io::require_local("bd mcp")?;
    // Act as the session's actor; without one, as a sub-actor of this process's own.
    if app.g.actor.is_none() && remote::env_actor().is_none() && actor::session(&actor::env).is_none() {
        actor::set_session_flag(&format!("mcp-{}", random_hex(4)?))?;
    }
    if remote::detect(app)?.is_some() {
        let runner = Forward { global: app.g.clone() };
        return serve(Server::new(runner, a.read_only));
    }
    app.store()?;
    let actor = app.resolved_actor();
    tracing::info!(target: "bd::mcp", actor = %actor.actor, "serving MCP on stdio");
    let mut local = Local::new(app.g.clone(), actor);
    local.set_store(app.take_store());
    serve(Server::new(local, a.read_only))
}

/// Answer each line of stdin on stdout until stdin closes.
fn serve<R: Runner>(mut server: Server<R>) -> Result<i32> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        if Read::by_ref(&mut input).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line)? == 0 {
            return Ok(0);
        }
        let ended = line.last() == Some(&b'\n');
        if line.len() - usize::from(ended) > MAX_LINE {
            if !ended {
                input.skip_until(b'\n')?;
            }
            let message = format!("an MCP message is longer than {MAX_LINE} bytes");
            io::outln(
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": message } }).to_string(),
            );
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        if text.trim().is_empty() {
            continue;
        }
        if let Some(answer) = server.handle_line(text.trim()) {
            io::outln(answer);
        }
    }
}

/// Runs tool calls on the bd server of a remote workspace, each with its
/// own request id so retries apply a write once.
struct Forward {
    global: Global,
}

impl Runner for Forward {
    fn run(&mut self, argv: &[String], write: bool) -> Result<Ran> {
        // Found again for every call: a saved sign-in token is renewed when due.
        let app = App::new(self.global.clone())?;
        let remote = remote::detect(&app)?.ok_or_else(|| Error::NoWorkspace("the remote workspace is gone".into()))?;
        let mut argv = argv.to_vec();
        if let Some(a) = &self.global.actor {
            argv.insert(0, format!("--actor={a}"));
        }
        let (actor, session) = remote::identity();
        let request = ExecRequest {
            argv,
            actor,
            session,
            request_id: Some(random_hex(16)?),
            location: Some(remote.url.clone()),
            tool_call: true,
            ..Default::default()
        };
        let r = remote.exec_collected(&request, write)?;
        Ok(Ran { exit_code: r.exit_code, stdout: r.stdout, stderr: r.stderr })
    }
}
