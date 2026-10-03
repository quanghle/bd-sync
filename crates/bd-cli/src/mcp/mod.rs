//! bd's MCP server: JSON-RPC 2.0 messages in, answers out, in the stateless
//! protocol revision and the session-based one before it (see docs/mcp.md). Transports (`bd mcp` on stdio, `bd
//! serve`'s `/mcp` endpoint) hand each message to [`Server::handle`]; tool
//! calls run bd commands through a [`Runner`].

pub mod local;
mod stdio;
pub mod tools;

pub use stdio::cmd_mcp;

use serde_json::{Map, Value, json};

use bd_core::Result;

/// The protocol revision served: stateless, version in every request's `_meta`.
pub const MODERN: &str = "2026-07-28";
/// The session-based revision, for clients that start with `initialize`.
pub const LEGACY: &str = "2025-11-25";

const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";
/// How long clients may cache the tool list and discovery: the catalog only
/// changes with bd's version.
const TTL_MS: u64 = 3_600_000;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const UNSUPPORTED_VERSION: i64 = -32022;

pub const INSTRUCTIONS: &str = "bd tracks this workspace's work. Loop: `ready`, then `claim` an issue and keep the \
                                `token` it returns, work, `heartbeat` with that token during long work, and `close` \
                                with a reason (or `release` to give it back). A claim refused as held means another \
                                actor works on it: pick other work. Record follow-up work with `create` (`deps: \
                                [\"discovered-from:<id>\"]`), ordering with `dep_add`, and durable project insights \
                                with `remember`.";

/// What a command run for a tool call left.
#[derive(Debug, Default)]
pub struct Ran {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs bd command lines for tool calls: in this process, or on a bd server.
pub trait Runner {
    /// Run `argv` (without the leading `bd`); `write` if the tool may write.
    /// An error means the command could not be run at all.
    fn run(&mut self, argv: &[String], write: bool) -> Result<Ran>;
}

/// The MCP server of one workspace.
pub struct Server<R> {
    runner: R,
    /// Offer only the read-only tools (`--read-only`).
    read_only: bool,
    /// A client started a `LEGACY` session with `initialize`.
    initialized: bool,
}

impl<R: Runner> Server<R> {
    pub fn new(runner: R, read_only: bool) -> Server<R> {
        Server { runner, read_only, initialized: false }
    }

    /// Answer one JSON-RPC message (`None` for notifications and responses).
    pub fn handle(&mut self, message: &Value) -> Option<Value> {
        let Some(m) = message.as_object() else {
            return Some(error(
                Value::Null,
                INVALID_REQUEST,
                "a JSON-RPC message must be an object (batches are not supported)",
                None,
            ));
        };
        let id = m.get("id").cloned();
        if m.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error(id.unwrap_or(Value::Null), INVALID_REQUEST, "jsonrpc must be \"2.0\"", None));
        }
        let Some(method) = m.get("method").and_then(Value::as_str) else {
            if !m.contains_key("method") && (m.contains_key("result") || m.contains_key("error")) {
                // A response: the server sends no requests, so there is nothing to match it with.
                return None;
            }
            let id = id.filter(|id| id.is_string() || id.is_number()).unwrap_or(Value::Null);
            return Some(error(id, INVALID_REQUEST, "method must be a string", None));
        };
        let id = match id {
            None => return None,
            Some(id @ (Value::String(_) | Value::Number(_))) => id,
            Some(_) => return Some(error(Value::Null, INVALID_REQUEST, "id must be a string or a number", None)),
        };
        let empty = Map::new();
        let params = match m.get("params") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(p)) => p,
            Some(_) => return Some(error(id, INVALID_PARAMS, "params must be an object", None)),
        };
        Some(match self.request(method, params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message, data)) => error(id, code, &message, data),
        })
    }

    /// Answer one line of a newline-delimited stream (stdio).
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let answer = match serde_json::from_str::<Value>(line) {
            Ok(message) => self.handle(&message)?,
            Err(e) => error(Value::Null, PARSE_ERROR, &format!("invalid JSON: {e}"), None),
        };
        Some(serde_json::to_string(&answer).expect("JSON values serialize"))
    }

    fn request(&mut self, method: &str, params: &Map<String, Value>) -> std::result::Result<Value, Failure> {
        let modern = params.get("_meta").and_then(Value::as_object).is_some_and(|m| m.contains_key(VERSION_KEY));
        if modern {
            check_version(params)?;
        } else if method == "initialize" {
            return self.initialize(params);
        } else if !self.initialized && method != "ping" {
            return Err((
                INVALID_PARAMS,
                format!("_meta[{VERSION_KEY:?}] is required, or a session started with initialize"),
                None,
            ));
        }
        let result = match method {
            "server/discover" if modern => json!({
                "supportedVersions": supported(),
                "capabilities": capabilities(),
                "instructions": INSTRUCTIONS,
                "ttlMs": TTL_MS,
                "cacheScope": "public",
            }),
            "ping" => json!({}),
            "tools/list" => {
                let tools: Vec<Value> = self.offered().map(tools::Tool::describe).collect();
                if !modern {
                    return Ok(json!({ "tools": tools }));
                }
                // The list depends on the server's options (`--read-only`).
                json!({ "tools": tools, "ttlMs": TTL_MS, "cacheScope": "private" })
            }
            "tools/call" => self.call(params)?,
            _ => return Err((METHOD_NOT_FOUND, format!("method not found: {method}"), None)),
        };
        Ok(if modern { with_modern_fields(result) } else { result })
    }

    /// Start a `LEGACY` session. A client asking for another version is
    /// offered `LEGACY`, and disconnects if it cannot speak it.
    fn initialize(&mut self, params: &Map<String, Value>) -> std::result::Result<Value, Failure> {
        if !params.get("protocolVersion").is_some_and(Value::is_string) {
            return Err((INVALID_PARAMS, "protocolVersion is required".into(), None));
        }
        self.initialized = true;
        Ok(json!({
            "protocolVersion": LEGACY,
            "capabilities": capabilities(),
            "serverInfo": server_info(),
            "instructions": INSTRUCTIONS,
        }))
    }

    fn offered(&self) -> impl Iterator<Item = &'static tools::Tool> + use<R> {
        let read_only = self.read_only;
        tools::TOOLS.iter().filter(move |t| t.read_only || !read_only)
    }

    fn call(&mut self, params: &Map<String, Value>) -> std::result::Result<Value, Failure> {
        let name =
            params.get("name").and_then(Value::as_str).ok_or((INVALID_PARAMS, "name is required".into(), None))?;
        let tool = self
            .offered()
            .find(|t| t.name == name)
            .ok_or_else(|| (INVALID_PARAMS, format!("unknown tool: {name}"), None))?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(a)) => a,
            Some(_) => return Err((INVALID_PARAMS, "arguments must be an object".into(), None)),
        };
        let invocation = match tool.invoke(arguments) {
            Ok(i) => i,
            Err(message) => return Ok(tool_error("invalid", &message, 2)),
        };
        let ran = match self.runner.run(&invocation.argv, !tool.read_only) {
            Ok(ran) => ran,
            Err(e) => return Ok(tool_error(e.code(), &e.to_string(), e.exit_code())),
        };
        if ran.exit_code != 0 {
            return Ok(command_error(&ran));
        }
        Ok(match invocation.result(&ran.stdout) {
            Ok(text) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
            Err(message) => tool_error("internal", &message, 1),
        })
    }
}

/// A JSON-RPC error: code, message, data.
type Failure = (i64, String, Option<Value>);

/// A stateless request names the protocol version it speaks, and its
/// client's capabilities, in `_meta`; only `MODERN` is stateless.
fn check_version(params: &Map<String, Value>) -> std::result::Result<(), Failure> {
    let unsupported = |requested: &str| {
        Err((
            UNSUPPORTED_VERSION,
            "Unsupported protocol version".into(),
            Some(json!({ "supported": supported(), "requested": requested })),
        ))
    };
    let meta = params.get("_meta").and_then(Value::as_object);
    let version = meta.and_then(|m| m.get(VERSION_KEY)).and_then(Value::as_str).unwrap_or_default();
    if version != MODERN {
        return unsupported(version);
    }
    if !meta.is_some_and(|m| m.get(CAPABILITIES_KEY).is_some_and(Value::is_object)) {
        return Err((INVALID_PARAMS, format!("_meta[{CAPABILITIES_KEY:?}] is required"), None));
    }
    Ok(())
}

/// The protocol versions served: `LEGACY` through `initialize`.
pub fn supported() -> Vec<&'static str> {
    vec![MODERN, LEGACY]
}

fn capabilities() -> Value {
    json!({ "tools": { "listChanged": false } })
}

fn server_info() -> Value {
    json!({ "name": "bd", "version": env!("CARGO_PKG_VERSION") })
}

fn with_modern_fields(mut result: Value) -> Value {
    result["resultType"] = json!("complete");
    result["_meta"] = json!({ SERVER_INFO_KEY: server_info() });
    result
}

fn error(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut e = json!({ "code": code, "message": message });
    if let Some(data) = data {
        e["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": e })
}

/// A tool result reporting an error as the CLI's `--json` error.
fn tool_error(code: &str, message: &str, exit_code: i32) -> Value {
    let body = json!({ "error": { "code": code, "message": message, "exit_code": exit_code } });
    let text = crate::io::printable(&body.to_string()).into_owned();
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

/// The tool result of a command that failed: the JSON error it printed on
/// stderr, else its first line of stderr.
fn command_error(ran: &Ran) -> Value {
    let reported = ran.stderr.lines().find_map(|l| {
        let v: Value = serde_json::from_str(l).ok()?;
        let e = v.get("error")?;
        Some((e.get("code")?.as_str()?.to_string(), e.get("message")?.as_str()?.to_string()))
    });
    match reported {
        Some((code, message)) => tool_error(&code, &message, ran.exit_code),
        None => {
            let line = ran.stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("failed");
            tool_error("failed", line.trim_start_matches("error: "), ran.exit_code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Answers each command with the next canned result, recording the command lines.
    #[derive(Default)]
    struct Canned {
        answers: VecDeque<Ran>,
        ran: Vec<(Vec<String>, bool)>,
    }

    impl Runner for &mut Canned {
        fn run(&mut self, argv: &[String], write: bool) -> Result<Ran> {
            self.ran.push((argv.to_vec(), write));
            Ok(self.answers.pop_front().unwrap_or_default())
        }
    }

    fn modern(method: &str, params: Value) -> Value {
        let mut params = params;
        params["_meta"] = json!({ VERSION_KEY: MODERN, CAPABILITIES_KEY: {} });
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    fn without_meta(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": "a", "method": method, "params": params })
    }

    #[test]
    fn modern_discovery_and_versions() {
        let mut canned = Canned::default();
        let mut server = Server::new(&mut canned, false);
        let r = server.handle(&modern("server/discover", json!({}))).unwrap();
        assert_eq!(r["result"]["supportedVersions"], json!(["2026-07-28", "2025-11-25"]));
        assert_eq!(r["result"]["resultType"], "complete");
        assert_eq!(r["result"]["_meta"][SERVER_INFO_KEY]["name"], "bd");
        assert!(r["result"]["ttlMs"].is_u64());

        let mut old = modern("tools/list", json!({}));
        old["params"]["_meta"][VERSION_KEY] = json!("1900-01-01");
        let r = server.handle(&old).unwrap();
        assert_eq!(r["error"]["code"], UNSUPPORTED_VERSION);
        assert_eq!(r["error"]["data"]["requested"], "1900-01-01");

        let mut bare = modern("tools/list", json!({}));
        bare["params"]["_meta"].as_object_mut().unwrap().remove(CAPABILITIES_KEY);
        assert_eq!(server.handle(&bare).unwrap()["error"]["code"], INVALID_PARAMS);
        assert_eq!(
            server.handle(&without_meta("server/discover", json!({}))).unwrap()["error"]["code"],
            INVALID_PARAMS
        );
        assert_eq!(server.handle(&without_meta("tools/list", json!({}))).unwrap()["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn legacy_sessions() {
        let mut canned = Canned::default();
        let mut server = Server::new(&mut canned, false);
        // Before initialize, only ping goes without _meta.
        assert_eq!(server.handle(&without_meta("tools/list", json!({}))).unwrap()["error"]["code"], INVALID_PARAMS);
        assert_eq!(server.handle(&without_meta("ping", json!({}))).unwrap()["result"], json!({}));
        assert_eq!(server.handle(&without_meta("initialize", json!({}))).unwrap()["error"]["code"], INVALID_PARAMS);

        let r = server.handle(&without_meta("initialize", json!({ "protocolVersion": LEGACY }))).unwrap();
        assert_eq!(r["result"]["protocolVersion"], LEGACY);
        assert_eq!(r["result"]["serverInfo"]["name"], "bd");
        assert_eq!(r["result"]["instructions"], INSTRUCTIONS);
        assert_eq!(r["result"]["capabilities"], capabilities());
        assert_eq!(server.handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })), None);

        let r = server.handle(&without_meta("tools/list", json!({}))).unwrap();
        assert_eq!(r["result"].as_object().unwrap().keys().collect::<Vec<_>>(), ["tools"], "{r}");
        let r = server.handle(&without_meta("tools/call", json!({ "name": "ready" }))).unwrap();
        assert_eq!(r["result"]["isError"], false, "{r}");
        assert!(r["result"].get("resultType").is_none(), "{r}");
        assert_eq!(
            server.handle(&without_meta("server/discover", json!({}))).unwrap()["error"]["code"],
            METHOD_NOT_FOUND
        );
        // Stateless requests are still served alongside.
        assert_eq!(server.handle(&modern("ping", json!({}))).unwrap()["result"]["resultType"], "complete");
        assert_eq!(server.handle(&modern("resources/list", json!({}))).unwrap()["error"]["code"], METHOD_NOT_FOUND);

        // Another version is offered the one served.
        let mut canned = Canned::default();
        let mut server = Server::new(&mut canned, false);
        let r = server.handle(&without_meta("initialize", json!({ "protocolVersion": "2025-06-18" }))).unwrap();
        assert_eq!(r["result"]["protocolVersion"], LEGACY);
        // A stateless request cannot name the session-based revision.
        let mut stateless = modern("tools/list", json!({}));
        stateless["params"]["_meta"][VERSION_KEY] = json!(LEGACY);
        assert_eq!(server.handle(&stateless).unwrap()["error"]["code"], UNSUPPORTED_VERSION);
    }

    #[test]
    fn malformed_messages() {
        let mut canned = Canned::default();
        let mut server = Server::new(&mut canned, false);
        assert!(server.handle_line("{").unwrap().contains("-32700"));
        assert_eq!(server.handle(&json!([])).unwrap()["error"]["code"], INVALID_REQUEST);
        assert_eq!(server.handle(&json!({ "id": 1, "method": "ping" })).unwrap()["error"]["code"], INVALID_REQUEST);
        assert_eq!(server.handle(&json!({ "jsonrpc": "2.0", "id": 1, "result": {} })), None);
        assert_eq!(server.handle(&json!({ "jsonrpc": "2.0", "id": null, "error": {} })), None);
        // Neither a request nor a response: answered, so the client does not wait for ever.
        let r = server.handle(&json!({ "jsonrpc": "2.0", "id": 1 })).unwrap();
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(1), json!(INVALID_REQUEST)));
        let r = server.handle(&json!({ "jsonrpc": "2.0", "id": "x", "method": 5, "result": {} })).unwrap();
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!("x"), json!(INVALID_REQUEST)));
        let r = server.handle(&json!({ "jsonrpc": "2.0", "id": [], "method": 5 })).unwrap();
        assert_eq!(r["id"], Value::Null);
    }

    #[test]
    fn read_only_servers_offer_read_tools() {
        let mut canned = Canned::default();
        let mut server = Server::new(&mut canned, true);
        let r = server.handle(&modern("tools/list", json!({}))).unwrap();
        let names: Vec<&str> =
            r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["ready", "list", "show", "memories"]);
        assert_eq!(r["result"]["cacheScope"], "private");
        let call = modern("tools/call", json!({ "name": "close", "arguments": { "ids": ["a"], "reason": "r" } }));
        assert_eq!(server.handle(&call).unwrap()["error"]["code"], INVALID_PARAMS);
        assert!(canned.ran.is_empty());
    }

    #[test]
    fn calls_run_commands_and_report_their_errors() {
        let mut canned = Canned::default();
        canned.answers.push_back(Ran { stdout: "[]".into(), ..Default::default() });
        canned.answers.push_back(Ran {
            exit_code: 4,
            stderr: r#"{"error":{"code":"claim_conflict","exit_code":4,"message":"held by x"}}"#.into(),
            ..Default::default()
        });
        let mut server = Server::new(&mut canned, false);
        let r = server.handle(&modern("tools/call", json!({ "name": "ready" }))).unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["content"][0]["text"], "{}");
        let r = server.handle(&modern("tools/call", json!({ "name": "claim", "arguments": { "id": "a" } }))).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert_eq!(
            r["result"]["content"][0]["text"],
            r#"{"error":{"code":"claim_conflict","exit_code":4,"message":"held by x"}}"#
        );
        // Invalid arguments are the model's to fix: a tool error, and nothing runs.
        let r = server.handle(&modern("tools/call", json!({ "name": "show", "arguments": {} }))).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("ids is required"));
        let r = server.handle(&modern("tools/call", json!({ "name": "nope" }))).unwrap();
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        assert_eq!(
            canned.ran,
            [
                (vec!["ready".to_string(), "--json".into(), "--limit=11".into()], false),
                (vec!["claim".to_string(), "--json".into(), "--".into(), "a".into()], true),
            ]
        );
    }
}
