//! The tool catalog: each tool's input schema, the bd command line its
//! arguments become, and how that command's `--json` output is shaped into
//! the tool's result (see docs/mcp.md).
//!
//! Arguments never reach the command line as flags of their own: options are
//! written `--name=value` (taken as the value whatever it starts with) and
//! positional arguments follow `--`, so a title or text starting with `-` is
//! never parsed as a flag.

use serde_json::{Map, Value, json};

/// A tool's argument.
struct Param {
    name: &'static str,
    kind: Kind,
    required: bool,
    description: &'static str,
}

enum Kind {
    Str,
    /// An integer in this range.
    Int(i64, i64),
    Bool,
    /// Strings, at least and at most this many.
    List(usize, usize),
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// Some of these strings.
    EnumList(&'static [&'static str]),
}

const fn p(name: &'static str, kind: Kind, description: &'static str) -> Param {
    Param { name, kind, required: false, description }
}

const fn req(name: &'static str, kind: Kind, description: &'static str) -> Param {
    Param { name, kind, required: true, description }
}

/// How a tool's command output becomes its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// A list of issues, cut to the requested limit: summaries, and `more`.
    Summaries,
    /// Full issues, without lease tokens.
    Show,
    /// What a write returns: issues as summaries, leases as token and expiry.
    Write,
}

/// One tool of the catalog.
pub struct Tool {
    pub name: &'static str,
    description: &'static str,
    /// Reads only: offered to read tokens, and marked `readOnlyHint`.
    pub read_only: bool,
    params: &'static [Param],
    build: fn(&Args) -> Result<Vec<String>, String>,
    shape: Shape,
}

/// The command line a tool call runs, and how to shape its output.
pub struct Invocation {
    /// The command line, without the leading `bd`.
    pub argv: Vec<String>,
    shape: Shape,
    /// The number of issues asked for (`Shape::Summaries`; one more is fetched).
    limit: usize,
}

const STATUSES: &[&str] = &["open", "in_progress", "blocked", "deferred", "closed", "pinned"];
const SET_STATUSES: &[&str] = &["open", "blocked", "deferred", "pinned"];
const DEP_TYPES: &[&str] = &[
    "blocks",
    "parent-child",
    "conditional-blocks",
    "waits-for",
    "related",
    "discovered-from",
    "tracks",
    "caused-by",
    "validates",
    "supersedes",
    "duplicates",
    "replies-to",
];
const READY_LIMIT: i64 = 10;
const LIST_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 100;
const MAX_IDS: usize = 20;

/// The tools, in the order they are listed.
pub static TOOLS: &[Tool] = &[
    Tool {
        name: "ready",
        description: "Issues ready to work on (open, unblocked, not deferred) in queue order.",
        read_only: true,
        params: &[
            p("limit", Kind::Int(1, MAX_LIMIT), "Default 10"),
            p("label", Kind::List(0, MAX_IDS), "All of these"),
            p("type", Kind::Str, ""),
            p("assignee", Kind::Str, ""),
            p("unassigned", Kind::Bool, ""),
            p("parent", Kind::Str, "Under this issue"),
        ],
        build: build_ready,
        shape: Shape::Summaries,
    },
    Tool {
        name: "list",
        description: "Search and filter issues.",
        read_only: true,
        params: &[
            p("status", Kind::EnumList(STATUSES), "Default: not closed or pinned"),
            p("search", Kind::Str, "Text in title, description, notes"),
            p("label", Kind::List(0, MAX_IDS), "All of these"),
            p("label_any", Kind::List(0, MAX_IDS), "Any of these"),
            p("type", Kind::Str, ""),
            p("assignee", Kind::Str, ""),
            p("parent", Kind::Str, "Under this issue"),
            p("blocked", Kind::Bool, "Only blocked issues"),
            p("sort", Kind::Enum(&["priority", "created", "updated"]), ""),
            p("limit", Kind::Int(1, MAX_LIMIT), "Default 20"),
        ],
        build: build_list,
        shape: Shape::Summaries,
    },
    Tool {
        name: "show",
        description: "Issue details: texts, dependencies, children, blockers, comments, claim.",
        read_only: true,
        params: &[req("ids", Kind::List(1, MAX_IDS), "")],
        build: build_show,
        shape: Shape::Show,
    },
    Tool {
        name: "create",
        description: "Create an issue.",
        read_only: false,
        params: &[
            req("title", Kind::Str, ""),
            p("description", Kind::Str, "Why and what"),
            p("type", Kind::Str, "task (default), bug, feature, epic, chore"),
            p("priority", Kind::Int(0, 4), "0 critical to 4 backlog, default 2"),
            p("labels", Kind::List(0, MAX_IDS), ""),
            p("parent", Kind::Str, ""),
            p("deps", Kind::List(0, MAX_IDS), "ID (blocks) or TYPE:ID, e.g. discovered-from:ID"),
            p("assignee", Kind::Str, "Reserve for this actor"),
            p("claim", Kind::Bool, "Claim it too"),
        ],
        build: build_create,
        shape: Shape::Write,
    },
    Tool {
        name: "update",
        description: "Change fields of an issue.",
        read_only: false,
        params: &[
            req("id", Kind::Str, ""),
            p("title", Kind::Str, ""),
            p("description", Kind::Str, ""),
            p("design", Kind::Str, ""),
            p("acceptance", Kind::Str, "Acceptance criteria"),
            p("notes", Kind::Str, "Replaces notes"),
            p("append_notes", Kind::Str, "Adds a line to notes"),
            p("status", Kind::Enum(SET_STATUSES), ""),
            p("priority", Kind::Int(0, 4), ""),
            p("type", Kind::Str, ""),
            p("assignee", Kind::Str, "\"\" unassigns"),
            p("add_labels", Kind::List(0, MAX_IDS), ""),
            p("remove_labels", Kind::List(0, MAX_IDS), ""),
            p("parent", Kind::Str, "\"\" detaches"),
            p("due", Kind::Str, "2026-01-15, +2d; \"\" clears"),
            p("defer", Kind::Str, "Not ready until; \"\" clears"),
            p("if_revision", Kind::Int(0, i64::MAX), "Only at this revision"),
        ],
        build: build_update,
        shape: Shape::Write,
    },
    Tool {
        name: "claim",
        description: "Claim an issue (or the next ready one) under a lease; keep the returned token.",
        read_only: false,
        params: &[
            p("id", Kind::Str, "Issue to claim"),
            p("next", Kind::Bool, "Claim the head of the ready queue"),
            p("label", Kind::List(0, MAX_IDS), "With next: all of these"),
            p("type", Kind::Str, "With next"),
            p("parent", Kind::Str, "With next: under this issue"),
        ],
        build: build_claim,
        shape: Shape::Write,
    },
    Tool {
        name: "heartbeat",
        description: "Renew a claim's lease during long work.",
        read_only: false,
        params: &[req("id", Kind::Str, ""), req("token", Kind::Int(0, i64::MAX), "From claim")],
        build: build_heartbeat,
        shape: Shape::Write,
    },
    Tool {
        name: "close",
        description: "Close finished issues; returns the issues this unblocked.",
        read_only: false,
        params: &[
            req("ids", Kind::List(1, MAX_IDS), ""),
            req("reason", Kind::Str, "What was done"),
            p("failed", Kind::Bool, "The work failed"),
            p("token", Kind::Int(0, i64::MAX), "From claim: only while that lease is held"),
        ],
        build: build_close,
        shape: Shape::Write,
    },
    Tool {
        name: "release",
        description: "Give a claimed issue back to the queue.",
        read_only: false,
        params: &[
            req("id", Kind::Str, ""),
            p("reason", Kind::Str, ""),
            p("token", Kind::Int(0, i64::MAX), "From claim: only while that lease is held"),
        ],
        build: build_release,
        shape: Shape::Write,
    },
    Tool {
        name: "reopen",
        description: "Reopen closed issues.",
        read_only: false,
        params: &[req("ids", Kind::List(1, MAX_IDS), ""), p("reason", Kind::Str, "")],
        build: build_reopen,
        shape: Shape::Write,
    },
    Tool {
        name: "comment",
        description: "Comment on an issue: context for whoever picks it up.",
        read_only: false,
        params: &[req("id", Kind::Str, ""), req("text", Kind::Str, "")],
        build: build_comment,
        shape: Shape::Write,
    },
    Tool {
        name: "dep_add",
        description: "issue depends on depends_on (blocks: issue waits until it closes).",
        read_only: false,
        params: &[
            req("issue", Kind::Str, ""),
            req("depends_on", Kind::Str, ""),
            p("type", Kind::Enum(DEP_TYPES), "Default blocks"),
        ],
        build: build_dep_add,
        shape: Shape::Write,
    },
    Tool {
        name: "remember",
        description: "Store a durable project insight.",
        read_only: false,
        params: &[req("text", Kind::Str, ""), p("key", Kind::Str, "Replaces that memory")],
        build: build_remember,
        shape: Shape::Write,
    },
    Tool {
        name: "memories",
        description: "List or search project memories.",
        read_only: true,
        params: &[p("query", Kind::Str, "")],
        build: build_memories,
        shape: Shape::Write,
    },
];

impl Tool {
    /// The tool's entry in `tools/list`.
    pub fn describe(&self) -> Value {
        let mut properties = Map::new();
        for param in self.params {
            let mut schema = match &param.kind {
                Kind::Str => json!({ "type": "string" }),
                Kind::Int(_, i64::MAX) => json!({ "type": "integer" }),
                Kind::Int(min, max) => json!({ "type": "integer", "minimum": min, "maximum": max }),
                Kind::Bool => json!({ "type": "boolean" }),
                Kind::List(..) => json!({ "type": "array", "items": { "type": "string" } }),
                Kind::Enum(values) => json!({ "type": "string", "enum": values }),
                Kind::EnumList(values) => json!({ "type": "array", "items": { "type": "string", "enum": values } }),
            };
            if !param.description.is_empty() {
                schema["description"] = json!(param.description);
            }
            properties.insert(param.name.to_string(), schema);
        }
        let required: Vec<&str> = self.params.iter().filter(|p| p.required).map(|p| p.name).collect();
        let mut input = json!({ "type": "object", "properties": properties });
        if !required.is_empty() {
            input["required"] = json!(required);
        }
        // readOnlyHint defaults to false, destructiveHint to true.
        let annotations =
            if self.read_only { json!({ "readOnlyHint": true }) } else { json!({ "destructiveHint": false }) };
        json!({ "name": self.name, "description": self.description, "inputSchema": input, "annotations": annotations })
    }

    /// The command line for a call with `arguments`, or why they are invalid.
    pub fn invoke(&self, arguments: &Map<String, Value>) -> Result<Invocation, String> {
        let args = Args::check(self.params, arguments)?;
        let argv = (self.build)(&args)?;
        let limit = match self.shape {
            Shape::Summaries => {
                args.int("limit").unwrap_or(if self.name == "ready" { READY_LIMIT } else { LIST_LIMIT })
            }
            _ => 0,
        } as usize;
        Ok(Invocation { argv, shape: self.shape, limit })
    }
}

impl Invocation {
    /// The tool's result text for the command's `--json` output.
    pub fn result(&self, output: &str) -> Result<String, String> {
        let value: Value = if output.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(output).map_err(|e| format!("unreadable command output: {e}"))?
        };
        let shaped = match self.shape {
            Shape::Summaries => {
                let issues = match value {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                let more = issues.len() > self.limit;
                let mut out = json!({ "issues": issues.iter().take(self.limit).map(summary).collect::<Vec<_>>() });
                if more {
                    out["more"] = json!(true);
                }
                out
            }
            Shape::Show => without_lease_tokens(value),
            Shape::Write => match value {
                // `claim --next` with nothing ready.
                Value::Null => json!({ "message": "nothing matched" }),
                v => compact(v),
            },
        };
        let text = serde_json::to_string(&prune(shaped).unwrap_or_else(|| json!({}))).expect("JSON values serialize");
        Ok(crate::io::printable(&text).into_owned())
    }
}

/// Validated arguments of a call.
pub struct Args<'a>(&'a Map<String, Value>);

impl<'a> Args<'a> {
    fn check(params: &[Param], arguments: &'a Map<String, Value>) -> Result<Args<'a>, String> {
        for key in arguments.keys() {
            if !params.iter().any(|p| p.name == key) {
                return Err(format!("unknown argument {key:?}"));
            }
        }
        for param in params {
            let Some(value) = arguments.get(param.name).filter(|v| !v.is_null()) else {
                if param.required {
                    return Err(format!("{} is required", param.name));
                }
                continue;
            };
            let name = param.name;
            match &param.kind {
                Kind::Str => {
                    value.as_str().ok_or_else(|| format!("{name} must be a string"))?;
                }
                Kind::Int(min, max) => {
                    let n = value.as_i64().ok_or_else(|| format!("{name} must be an integer"))?;
                    if n < *min || n > *max {
                        return Err(format!("{name} must be between {min} and {max}"));
                    }
                }
                Kind::Bool => {
                    value.as_bool().ok_or_else(|| format!("{name} must be true or false"))?;
                }
                Kind::List(min, max) => {
                    let items = value.as_array().ok_or_else(|| format!("{name} must be an array of strings"))?;
                    if items.len() < *min || items.len() > *max {
                        return Err(format!("{name} must have {min} to {max} items"));
                    }
                    for item in items {
                        let s = item.as_str().ok_or_else(|| format!("{name} must be an array of strings"))?;
                        if s.trim().is_empty() {
                            return Err(format!("{name} must not have empty items"));
                        }
                    }
                }
                Kind::Enum(values) => {
                    let s = value.as_str().ok_or_else(|| format!("{name} must be a string"))?;
                    if !values.contains(&s) {
                        return Err(format!("{name} must be one of {}", values.join(", ")));
                    }
                }
                Kind::EnumList(values) => {
                    let items = value.as_array().ok_or_else(|| format!("{name} must be an array"))?;
                    for item in items {
                        if !item.as_str().is_some_and(|s| values.contains(&s)) {
                            return Err(format!("{name} items must be one of {}", values.join(", ")));
                        }
                    }
                }
            }
        }
        Ok(Args(arguments))
    }

    fn get(&self, name: &str) -> Option<&'a Value> {
        self.0.get(name).filter(|v| !v.is_null())
    }

    fn str(&self, name: &str) -> Option<&'a str> {
        self.get(name).and_then(Value::as_str)
    }

    fn int(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(Value::as_i64)
    }

    fn flag(&self, name: &str) -> bool {
        self.get(name).and_then(Value::as_bool).unwrap_or(false)
    }

    fn list(&self, name: &str) -> Vec<&'a str> {
        self.get(name)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }
}

/// A command line under construction: options, then `--` and positionals.
struct Line {
    options: Vec<String>,
    positionals: Vec<String>,
}

impl Line {
    fn new(command: &[&str]) -> Line {
        let mut options: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        options.push("--json".into());
        Line { options, positionals: Vec::new() }
    }

    fn opt(mut self, flag: &str, value: Option<impl ToString>) -> Line {
        if let Some(v) = value {
            self.options.push(format!("--{flag}={}", v.to_string()));
        }
        self
    }

    fn each(mut self, flag: &str, values: Vec<&str>) -> Line {
        for v in values {
            self.options.push(format!("--{flag}={v}"));
        }
        self
    }

    fn switch(mut self, flag: &str, on: bool) -> Line {
        if on {
            self.options.push(format!("--{flag}"));
        }
        self
    }

    fn arg(mut self, value: &str) -> Line {
        self.positionals.push(value.to_string());
        self
    }

    fn args(mut self, values: Vec<&str>) -> Line {
        self.positionals.extend(values.into_iter().map(String::from));
        self
    }

    fn done(self) -> Result<Vec<String>, String> {
        let mut argv = self.options;
        if !self.positionals.is_empty() {
            argv.push("--".into());
            argv.extend(self.positionals);
        }
        Ok(argv)
    }
}

fn build_ready(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["ready"])
        .opt("limit", Some(a.int("limit").unwrap_or(READY_LIMIT) + 1))
        .each("label", a.list("label"))
        .opt("type", a.str("type"))
        .opt("assignee", a.str("assignee"))
        .switch("unassigned", a.flag("unassigned"))
        .opt("parent", a.str("parent"))
        .done()
}

fn build_list(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["list"])
        .opt("limit", Some(a.int("limit").unwrap_or(LIST_LIMIT) + 1))
        .each("status", a.list("status"))
        .opt("search", a.str("search"))
        .each("label", a.list("label"))
        .each("label-any", a.list("label_any"))
        .opt("type", a.str("type"))
        .opt("assignee", a.str("assignee"))
        .opt("parent", a.str("parent"))
        .switch("blocked", a.flag("blocked"))
        .opt("sort", a.str("sort"))
        .done()
}

fn build_show(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["show"]).args(a.list("ids")).done()
}

fn build_create(a: &Args) -> Result<Vec<String>, String> {
    let title = a.str("title").unwrap_or_default();
    if title.trim().is_empty() {
        return Err("title must not be empty".into());
    }
    Line::new(&["create"])
        .opt("description", a.str("description"))
        .opt("type", a.str("type"))
        .opt("priority", a.int("priority"))
        .each("label", a.list("labels"))
        .opt("parent", a.str("parent"))
        .each("dep", a.list("deps"))
        .opt("assignee", a.str("assignee"))
        .switch("claim", a.flag("claim"))
        .arg(title)
        .done()
}

fn build_update(a: &Args) -> Result<Vec<String>, String> {
    let line = Line::new(&["update"])
        .opt("title", a.str("title"))
        .opt("description", a.str("description"))
        .opt("design", a.str("design"))
        .opt("acceptance", a.str("acceptance"))
        .opt("notes", a.str("notes"))
        .opt("append-notes", a.str("append_notes"))
        .opt("status", a.str("status"))
        .opt("priority", a.int("priority"))
        .opt("type", a.str("type"))
        .opt("assignee", a.str("assignee"))
        .each("add-label", a.list("add_labels"))
        .each("remove-label", a.list("remove_labels"))
        .opt("parent", a.str("parent"))
        .opt("due", a.str("due"))
        .opt("defer", a.str("defer"));
    if line.options.len() == 2 {
        return Err("nothing to update: give at least one field".into());
    }
    line.opt("if-revision", a.int("if_revision")).arg(a.str("id").unwrap_or_default()).done()
}

fn build_claim(a: &Args) -> Result<Vec<String>, String> {
    let next = a.flag("next");
    let filtered = ["label", "type", "parent"].iter().any(|f| a.get(f).is_some());
    match (a.str("id"), next) {
        (Some(_), true) => Err("give either id or next, not both".into()),
        (None, false) => Err("give id, or next: true".into()),
        (Some(_), false) if filtered => Err("label, type and parent apply only with next".into()),
        (Some(id), false) => Line::new(&["claim"]).arg(id).done(),
        (None, true) => Line::new(&["claim"])
            .switch("next", true)
            .each("label", a.list("label"))
            .opt("type", a.str("type"))
            .opt("parent", a.str("parent"))
            .done(),
    }
}

fn build_heartbeat(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["heartbeat"]).opt("token", a.int("token")).arg(a.str("id").unwrap_or_default()).done()
}

fn build_close(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["close"])
        .opt("reason", a.str("reason"))
        .switch("failed", a.flag("failed"))
        .opt("token", a.int("token"))
        .args(a.list("ids"))
        .done()
}

fn build_release(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["release"])
        .opt("reason", a.str("reason"))
        .opt("token", a.int("token"))
        .arg(a.str("id").unwrap_or_default())
        .done()
}

fn build_reopen(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["reopen"]).opt("reason", a.str("reason")).args(a.list("ids")).done()
}

fn build_comment(a: &Args) -> Result<Vec<String>, String> {
    let text = a.str("text").unwrap_or_default();
    if text.trim().is_empty() {
        return Err("text must not be empty".into());
    }
    Line::new(&["comment", "add"]).arg(a.str("id").unwrap_or_default()).arg(text).done()
}

fn build_dep_add(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["dep", "add"])
        .opt("type", a.str("type"))
        .arg(a.str("issue").unwrap_or_default())
        .arg(a.str("depends_on").unwrap_or_default())
        .done()
}

fn build_remember(a: &Args) -> Result<Vec<String>, String> {
    let text = a.str("text").unwrap_or_default();
    if text.trim().is_empty() {
        return Err("text must not be empty".into());
    }
    Line::new(&["remember"]).opt("key", a.str("key")).arg(text).done()
}

fn build_memories(a: &Args) -> Result<Vec<String>, String> {
    let line = Line::new(&["memories"]);
    match a.str("query").filter(|q| !q.is_empty()) {
        Some(q) => line.arg(q).done(),
        None => line.done(),
    }
}

/// Whether `v` is an issue as the CLI prints it.
fn is_issue(v: &Map<String, Value>) -> bool {
    ["id", "title", "status", "issue_type"].iter().all(|k| v.contains_key(*k))
}

/// Whether `v` is a lease as the CLI prints it.
fn is_lease(v: &Map<String, Value>) -> bool {
    ["holder", "token", "expires_at"].iter().all(|k| v.contains_key(*k))
}

/// An issue's summary.
fn summary(issue: &Value) -> Value {
    let field = |k: &str| issue.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "id": field("id"),
        "title": field("title"),
        "status": field("status"),
        "priority": field("priority"),
        "type": field("issue_type"),
        "assignee": field("assignee"),
        "labels": field("labels"),
    })
}

/// A write's output with its issues as summaries and its leases as their
/// token and expiry.
fn compact(v: Value) -> Value {
    match v {
        Value::Object(m) if is_issue(&m) => summary(&Value::Object(m)),
        Value::Object(m) if is_lease(&m) => {
            json!({ "token": m.get("token").cloned(), "expires_at": m.get("expires_at").cloned() })
        }
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, compact(v))).collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(compact).collect()),
        v => v,
    }
}

/// `show`'s output without the lease tokens: a claim's token is its
/// holder's to use, and stays out of what other models read.
fn without_lease_tokens(mut v: Value) -> Value {
    let strip = |issue: &mut Value| {
        if let Some(lease) = issue.get_mut("lease").and_then(Value::as_object_mut) {
            lease.remove("token");
        }
    };
    match &mut v {
        Value::Array(a) => a.iter_mut().for_each(strip),
        issue => strip(issue),
    }
    v
}

/// `v` without nulls, empty strings, empty arrays and empty objects, at any
/// depth; `None` if nothing is left.
fn prune(v: Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::Array(a) => {
            let a: Vec<Value> = a.into_iter().filter_map(prune).collect();
            (!a.is_empty()).then_some(Value::Array(a))
        }
        Value::Object(m) => {
            let m: Map<String, Value> = m.into_iter().filter_map(|(k, v)| prune(v).map(|v| (k, v))).collect();
            (!m.is_empty()).then_some(Value::Object(m))
        }
        v => Some(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(tool: &str, args: Value) -> Result<Invocation, String> {
        TOOLS.iter().find(|t| t.name == tool).unwrap().invoke(args.as_object().unwrap())
    }

    fn argv(tool: &str, args: Value) -> Vec<String> {
        invoke(tool, args).unwrap().argv
    }

    #[test]
    fn free_text_never_becomes_a_flag() {
        assert_eq!(
            argv("create", json!({ "title": "--take-over", "description": "-x", "labels": ["a"] })),
            ["create", "--json", "--description=-x", "--label=a", "--", "--take-over"]
        );
        assert_eq!(
            argv("comment", json!({ "id": "-f", "text": "--force" })),
            ["comment", "add", "--json", "--", "-f", "--force"]
        );
        assert_eq!(
            argv("close", json!({ "ids": ["a", "b"], "reason": "--take-over", "token": 7 })),
            ["close", "--json", "--reason=--take-over", "--token=7", "--", "a", "b"]
        );
        assert_eq!(argv("memories", json!({})), ["memories", "--json"]);
    }

    #[test]
    fn limits_fetch_one_more() {
        assert_eq!(argv("ready", json!({})), ["ready", "--json", "--limit=11"]);
        assert_eq!(
            argv("list", json!({ "limit": 5, "status": ["closed"] })),
            ["list", "--json", "--limit=6", "--status=closed"]
        );
    }

    #[test]
    fn invalid_arguments_are_refused() {
        let err = |tool, args| invoke(tool, args).err().unwrap();
        assert_eq!(err("show", json!({})), "ids is required");
        assert_eq!(err("show", json!({ "ids": [] })), "ids must have 1 to 20 items");
        assert_eq!(err("ready", json!({ "limit": 101 })), "limit must be between 1 and 100");
        assert_eq!(err("ready", json!({ "force": true })), "unknown argument \"force\"");
        assert_eq!(err("claim", json!({})), "give id, or next: true");
        assert_eq!(err("claim", json!({ "id": "a", "label": ["x"] })), "label, type and parent apply only with next");
        assert_eq!(err("update", json!({ "id": "a" })), "nothing to update: give at least one field");
        assert_eq!(err("update", json!({ "id": "a", "if_revision": 3 })), "nothing to update: give at least one field");
        assert!(err("update", json!({ "id": "a", "status": "in_progress" })).starts_with("status must be one of"));
        assert!(err("dep_add", json!({ "issue": "a", "depends_on": "b", "type": "x" })).starts_with("type must be"));
    }

    #[test]
    fn summaries_mark_a_cut_list() {
        let issue = |id: &str| {
            json!({ "id": id, "title": "t", "status": "open", "priority": 2, "issue_type": "task", "assignee": null,
                    "labels": [], "description": "long", "metadata": {} })
        };
        let inv = invoke("ready", json!({ "limit": 1 })).unwrap();
        let out = json!([issue("a"), issue("b")]).to_string();
        assert_eq!(
            inv.result(&out).unwrap(),
            r#"{"issues":[{"id":"a","priority":2,"status":"open","title":"t","type":"task"}],"more":true}"#
        );
        assert_eq!(inv.result("[]").unwrap(), "{}");
    }

    #[test]
    fn writes_shape_issues_and_leases() {
        let inv = invoke("claim", json!({ "id": "a" })).unwrap();
        let out = json!({ "already_held": false,
            "issue": { "id": "a", "title": "t", "status": "in_progress", "priority": 1, "issue_type": "bug",
                       "assignee": "me", "labels": ["x"], "notes": "" },
            "lease": { "holder": "me", "token": 9, "expires_at": "T", "issue_id": "a", "renewals": 0 } });
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"{"already_held":false,"issue":{"assignee":"me","id":"a","labels":["x"],"priority":1,"status":"in_progress","title":"t","type":"bug"},"lease":{"expires_at":"T","token":9}}"#
        );
        let next = invoke("claim", json!({ "next": true })).unwrap();
        assert_eq!(next.result("null").unwrap(), r#"{"message":"nothing matched"}"#);
    }

    #[test]
    fn show_drops_lease_tokens_and_escapes_text() {
        let inv = invoke("show", json!({ "ids": ["a"] })).unwrap();
        let out = json!({ "id": "a", "title": "\u{1b}[31mred\u{202e}", "lease": { "holder": "h", "token": 3 } });
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"{"id":"a","lease":{"holder":"h"},"title":"\u001b[31mred\u202e"}"#
        );
    }

    #[test]
    fn the_tool_list_stays_small() {
        // About 1,500 tokens at 6.4 KB; every agent connected pays this per session.
        let list = serde_json::to_string(&TOOLS.iter().map(Tool::describe).collect::<Vec<_>>()).unwrap();
        assert!(list.len() < 6656, "tools/list is {} bytes", list.len());
    }
}
