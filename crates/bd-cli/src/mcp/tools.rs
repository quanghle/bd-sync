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
    /// `bd spec list`'s specs, as `{"specs": [...]}`.
    Specs,
    /// `bd spec show`'s views, as `{"specs": [...]}`: without `history` unless
    /// asked, and without `inherited` on nested sub-specs.
    SpecViews,
    /// `bd spec drift`'s report: issues as summaries (`malformed` items as
    /// `{issue, problem, detail}`), each list cut to the limit, and `more`
    /// naming each cut list's full length.
    Drift,
    /// `bd spec changes`'s report: `changes` and `unknown` cut to the limit,
    /// and `more` naming each cut list's full length.
    Changes,
    /// `bd spec candidates`'s groups, as `{"groups": [...]}`: the groups and
    /// each group's issues cut to the limit, `count` each group's full size,
    /// and `more` the number of groups when cut.
    Candidates,
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
    /// The number of issues asked for (`Shape::Summaries`; one more is
    /// fetched), or the items kept per list (`Shape::Drift`,
    /// `Shape::Changes`, `Shape::Candidates`).
    limit: usize,
    /// The call asked for closed requirements too (`Shape::SpecViews`).
    history: bool,
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
const DRIFT_LIMIT: i64 = 20;
const CHANGES_LIMIT: i64 = 20;
const CANDIDATES_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 100;
const MAX_IDS: usize = 20;

/// The tools, in the order they are listed.
pub static TOOLS: &[Tool] = &[
    Tool {
        name: "ready",
        description: "Open, unblocked, undeferred issues in queue order.",
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
            p("status", Kind::EnumList(STATUSES), "Default: not closed/pinned"),
            p("search", Kind::Str, "In title, description, notes"),
            p("label", Kind::List(0, MAX_IDS), "All of these"),
            p("label_any", Kind::List(0, MAX_IDS), "Any of these"),
            p("type", Kind::Str, ""),
            p("assignee", Kind::Str, ""),
            p("parent", Kind::Str, "Under this issue"),
            p("blocked", Kind::Bool, "Only blocked issues"),
            p("updated_after", Kind::Str, "7d = 7 days ago"),
            p("created_after", Kind::Str, ""),
            p("overdue", Kind::Bool, ""),
            p("sort", Kind::Enum(&["priority", "created", "updated"]), ""),
            p("limit", Kind::Int(1, MAX_LIMIT), "Default 20"),
        ],
        build: build_list,
        shape: Shape::Summaries,
    },
    Tool {
        name: "show",
        description: "Issue details: texts, deps, children, blockers, comments, claim.",
        read_only: true,
        params: &[
            req("ids", Kind::List(1, MAX_IDS), ""),
            p("brief", Kind::Bool, "Key fields, last 3 comments"),
            p("why", Kind::Bool, "Readiness, and why not"),
        ],
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
        description: "Claim an issue (or the next ready one); keep the lease token.",
        read_only: false,
        params: &[
            p("id", Kind::Str, "Issue to claim"),
            p("next", Kind::Bool, "Head of the ready queue"),
            p("label", Kind::List(0, MAX_IDS), "With next: all of these"),
            p("type", Kind::Str, "With next"),
            p("parent", Kind::Str, "With next: under this issue"),
        ],
        build: build_claim,
        shape: Shape::Write,
    },
    Tool {
        name: "heartbeat",
        description: "Renew a claim's lease.",
        read_only: false,
        params: &[req("id", Kind::Str, ""), req("token", Kind::Int(0, i64::MAX), "From claim")],
        build: build_heartbeat,
        shape: Shape::Write,
    },
    Tool {
        name: "close",
        description: "Close finished issues; returns what it unblocked.",
        read_only: false,
        params: &[
            req("ids", Kind::List(1, MAX_IDS), ""),
            req("reason", Kind::Str, "What was done"),
            p("failed", Kind::Bool, "The work failed"),
            p("token", Kind::Int(0, i64::MAX), "From claim: only while held"),
            p("claim_next", Kind::Bool, "Then claim the next ready one"),
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
            p("token", Kind::Int(0, i64::MAX), "From claim: only while held"),
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
        description: "Comment for whoever picks the issue up.",
        read_only: false,
        params: &[req("id", Kind::Str, ""), req("text", Kind::Str, "")],
        build: build_comment,
        shape: Shape::Write,
    },
    Tool {
        name: "dep_add",
        description: "issue depends on depends_on (blocks: waits until it closes).",
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
    Tool {
        name: "spec_list",
        description: "Open feature specs with their areas and counts.",
        read_only: true,
        params: &[],
        build: build_spec_list,
        shape: Shape::Specs,
    },
    Tool {
        name: "spec_show",
        description: "A spec, or an area's specs: requirements, non-goals, inherited ones, sub-specs.",
        read_only: true,
        params: &[
            req("target", Kind::Str, "Spec id or area"),
            p("history", Kind::Bool, "Also closed requirements"),
            p("as_of", Kind::Str, "Event seq, date/time or -DURATION ago"),
        ],
        build: build_spec_show,
        shape: Shape::SpecViews,
    },
    Tool {
        name: "spec_drift",
        description: "Closed work linked to no spec, and specs out of order.",
        read_only: true,
        params: &[
            p("since", Kind::Str, "2026-01-15 or 30d; default: when specs turned on"),
            p("limit", Kind::Int(1, MAX_LIMIT), "Default 20, per list"),
        ],
        build: build_spec_drift,
        shape: Shape::Drift,
    },
    Tool {
        name: "spec_changes",
        description: "Requirements added, changed and removed between two times.",
        read_only: true,
        params: &[
            p("target", Kind::Str, "Spec id or area; default every spec"),
            req("since", Kind::Str, "Event seq, date/time, -DURATION or 30d"),
            p("until", Kind::Str, "Default now"),
            p("limit", Kind::Int(1, MAX_LIMIT), "Default 20"),
        ],
        build: build_spec_changes,
        shape: Shape::Changes,
    },
    Tool {
        name: "spec_candidates",
        description: "Closed work from before specs that no spec covers, grouped.",
        read_only: true,
        params: &[p("limit", Kind::Int(1, MAX_LIMIT), "Default 20: groups, and issues in each")],
        build: build_spec_candidates,
        shape: Shape::Candidates,
    },
    Tool {
        name: "spec_none",
        description: "Mark issues as touching no spec, with the reason.",
        read_only: false,
        params: &[req("ids", Kind::List(1, MAX_IDS), ""), req("reason", Kind::Str, "Why no spec")],
        build: build_spec_none,
        shape: Shape::Write,
    },
    Tool {
        name: "spec_new",
        description: "Create a spec: a pinned feature for an area.",
        read_only: false,
        params: &[
            req("area", Kind::Str, "Letters, digits, - _ . /"),
            req("title", Kind::Str, ""),
            p("parent", Kind::Str, "Parent spec: a sub-spec"),
            p("description", Kind::Str, ""),
            p("from", Kind::List(0, MAX_IDS), "Issues or runs it came from"),
        ],
        build: build_spec_new,
        shape: Shape::Write,
    },
    Tool {
        name: "spec_add",
        description: "Add a requirement or non-goal to a spec in force.",
        read_only: false,
        params: &[
            req("spec", Kind::Str, ""),
            req("sentence", Kind::Str, "One testable sentence"),
            req("from", Kind::List(1, MAX_IDS), "Issues or runs it came from"),
            p("non_goal", Kind::Bool, ""),
            p("description", Kind::Str, ""),
        ],
        build: build_spec_add,
        shape: Shape::Write,
    },
    Tool {
        name: "spec_change",
        description: "Replace a requirement by a new one, superseding it.",
        read_only: false,
        params: &[
            req("requirement", Kind::Str, ""),
            req("sentence", Kind::Str, ""),
            req("from", Kind::List(1, MAX_IDS), ""),
            p("description", Kind::Str, ""),
        ],
        build: build_spec_change,
        shape: Shape::Write,
    },
    Tool {
        name: "spec_remove",
        description: "Close a requirement that no longer holds, with the reason.",
        read_only: false,
        params: &[
            req("requirement", Kind::Str, ""),
            req("reason", Kind::Str, ""),
            p("from", Kind::List(0, MAX_IDS), ""),
        ],
        build: build_spec_remove,
        shape: Shape::Write,
    },
    Tool {
        name: "spec_link",
        description: "Link work to specs or requirements by related edges.",
        read_only: false,
        params: &[req("issue", Kind::Str, ""), req("targets", Kind::List(1, MAX_IDS), "Specs or requirements")],
        build: build_spec_link,
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
            Shape::Drift => args.int("limit").unwrap_or(DRIFT_LIMIT),
            Shape::Changes => args.int("limit").unwrap_or(CHANGES_LIMIT),
            Shape::Candidates => args.int("limit").unwrap_or(CANDIDATES_LIMIT),
            _ => 0,
        } as usize;
        let history = self.shape == Shape::SpecViews && args.flag("history");
        Ok(Invocation { argv, shape: self.shape, limit, history })
    }
}

impl Invocation {
    /// Whether a non-zero exit with output is still a result: `bd spec
    /// drift` exits 1 when it finds drift, and still prints its JSON.
    pub fn accepts_exit(&self, code: i32) -> bool {
        self.shape == Shape::Drift && code == 1
    }

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
            Shape::Specs => json!({ "specs": value }),
            Shape::SpecViews => spec_views(value, self.history),
            Shape::Drift => drift(value, self.limit),
            Shape::Changes => changes(value, self.limit),
            Shape::Candidates => candidates(value, self.limit),
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
        .switch("brief", true)
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
        .switch("brief", true)
        .opt("limit", Some(a.int("limit").unwrap_or(LIST_LIMIT) + 1))
        .each("status", a.list("status"))
        .opt("search", a.str("search"))
        .each("label", a.list("label"))
        .each("label-any", a.list("label_any"))
        .opt("type", a.str("type"))
        .opt("assignee", a.str("assignee"))
        .opt("parent", a.str("parent"))
        .switch("blocked", a.flag("blocked"))
        .opt("updated-after", a.str("updated_after"))
        .opt("created-after", a.str("created_after"))
        .switch("overdue", a.flag("overdue"))
        .opt("sort", a.str("sort"))
        .done()
}

fn build_show(a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["show"]).switch("brief", a.flag("brief")).switch("why", a.flag("why")).args(a.list("ids")).done()
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
        .switch("claim-next", a.flag("claim_next"))
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

fn build_spec_list(_a: &Args) -> Result<Vec<String>, String> {
    Line::new(&["spec", "list"]).done()
}

fn build_spec_show(a: &Args) -> Result<Vec<String>, String> {
    let target = a.str("target").unwrap_or_default();
    if target.trim().is_empty() {
        return Err("target must not be empty".into());
    }
    let as_of = a.str("as_of");
    if as_of.is_some_and(|t| t.trim().is_empty()) {
        return Err("as_of must not be empty".into());
    }
    Line::new(&["spec", "show"]).switch("history", a.flag("history")).opt("as-of", as_of).arg(target).done()
}

fn build_spec_drift(a: &Args) -> Result<Vec<String>, String> {
    // The limit is applied to the output: bd spec drift has none.
    Line::new(&["spec", "drift"]).opt("since", a.str("since")).done()
}

fn build_spec_changes(a: &Args) -> Result<Vec<String>, String> {
    // The limit is applied to the output: bd spec changes has none.
    for name in ["target", "since", "until"] {
        if a.str(name).is_some_and(|v| v.trim().is_empty()) {
            return Err(format!("{name} must not be empty"));
        }
    }
    let line = Line::new(&["spec", "changes"]).opt("since", a.str("since")).opt("until", a.str("until"));
    match a.str("target") {
        Some(target) => line.arg(target).done(),
        None => line.done(),
    }
}

fn build_spec_none(a: &Args) -> Result<Vec<String>, String> {
    let reason = a.str("reason").unwrap_or_default();
    if reason.trim().is_empty() {
        return Err("reason must not be empty".into());
    }
    Line::new(&["spec", "none"]).opt("reason", Some(reason)).args(a.list("ids")).done()
}

/// The string argument `name`, refused when blank.
fn not_blank<'a>(a: &Args<'a>, name: &str) -> Result<&'a str, String> {
    let value = a.str(name).unwrap_or_default();
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

/// The `from` ids, refused when one holds a comma: `--from` splits on commas,
/// so one item would become several ids, past the item cap.
fn from_ids<'a>(a: &Args<'a>) -> Result<Vec<&'a str>, String> {
    let ids = a.list("from");
    if ids.iter().any(|id| id.contains(',')) {
        return Err("from items must not contain ','".into());
    }
    Ok(ids)
}

fn build_spec_candidates(_a: &Args) -> Result<Vec<String>, String> {
    // The limit is applied to the output: bd spec candidates has none.
    Line::new(&["spec", "candidates"]).done()
}

fn build_spec_new(a: &Args) -> Result<Vec<String>, String> {
    let area = not_blank(a, "area")?;
    let title = not_blank(a, "title")?;
    Line::new(&["spec", "new"])
        .opt("parent", a.str("parent"))
        .opt("description", a.str("description"))
        .each("from", from_ids(a)?)
        .arg(area)
        .arg(title)
        .done()
}

fn build_spec_add(a: &Args) -> Result<Vec<String>, String> {
    let spec = not_blank(a, "spec")?;
    let sentence = not_blank(a, "sentence")?;
    Line::new(&["spec", "add"])
        .each("from", from_ids(a)?)
        .switch("non-goal", a.flag("non_goal"))
        .opt("description", a.str("description"))
        .arg(spec)
        .arg(sentence)
        .done()
}

fn build_spec_change(a: &Args) -> Result<Vec<String>, String> {
    let requirement = not_blank(a, "requirement")?;
    let sentence = not_blank(a, "sentence")?;
    Line::new(&["spec", "change"])
        .each("from", from_ids(a)?)
        .opt("description", a.str("description"))
        .arg(requirement)
        .arg(sentence)
        .done()
}

fn build_spec_remove(a: &Args) -> Result<Vec<String>, String> {
    let requirement = not_blank(a, "requirement")?;
    let reason = not_blank(a, "reason")?;
    Line::new(&["spec", "remove"]).opt("reason", Some(reason)).each("from", from_ids(a)?).arg(requirement).done()
}

fn build_spec_link(a: &Args) -> Result<Vec<String>, String> {
    let issue = not_blank(a, "issue")?;
    Line::new(&["spec", "link"]).arg(issue).args(a.list("targets")).done()
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
        "parent": field("parent"),
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

/// `bd spec show`'s views as `{"specs": [...]}`, trimmed (see `trim_view`).
fn spec_views(value: Value, history: bool) -> Value {
    let views = match value {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    json!({ "specs": views.into_iter().map(|v| trim_view(v, history, true)).collect::<Vec<_>>() })
}

/// A spec view without its `history` unless asked, and, nested (`top`
/// false), without `inherited`: a sub-spec inherits from the views above it.
fn trim_view(mut view: Value, history: bool, top: bool) -> Value {
    if let Some(m) = view.as_object_mut() {
        if !history {
            m.remove("history");
        }
        if !top {
            m.remove("inherited");
        }
        if let Some(Value::Array(subs)) = m.remove("subspecs") {
            let subs: Vec<Value> = subs.into_iter().map(|v| trim_view(v, history, false)).collect();
            m.insert("subspecs".into(), Value::Array(subs));
        }
    }
    view
}

/// How one item of a drift list is shaped.
type ItemShape = fn(&Value) -> Value;

/// `bd spec drift`'s report with its issues as summaries and each list cut to
/// `limit`; `more` names each cut list's full length. `count` stays the
/// CLI's, over the whole lists. A list an older server leaves out (such as
/// `malformed`) is empty, and pruned like any other empty list.
fn drift(value: Value, limit: usize) -> Value {
    let mut out = json!({ "since": value["since"], "count": value["count"] });
    let mut more = Map::new();
    let shaky = |i: &Value| json!({ "requirement": summary(&i["requirement"]), "source": summary(&i["source"]), "why": i["why"] });
    let orphaned = |i: &Value| json!({ "spec": summary(&i["spec"]), "parent": i["parent"] });
    let malformed =
        |i: &Value| json!({ "issue": summary(&i["issue"]), "problem": i["problem"], "detail": i["detail"] });
    let lists: [(&str, ItemShape); 6] = [
        ("unlinked", summary),
        ("shaky", shaky),
        ("bad_status", summary),
        ("orphaned", orphaned),
        ("malformed", malformed),
        ("to_link", summary),
    ];
    for (key, item) in lists {
        let items = value[key].as_array().map(Vec::as_slice).unwrap_or_default();
        if items.len() > limit {
            more.insert(key.into(), json!(items.len()));
        }
        out[key] = Value::Array(items.iter().take(limit).map(item).collect());
    }
    if !more.is_empty() {
        out["more"] = Value::Object(more);
    }
    out
}

/// `bd spec changes`'s report with `changes` and `unknown` cut to `limit`;
/// `more` names each cut list's full length.
fn changes(value: Value, limit: usize) -> Value {
    let mut out = json!({
        "since": value["since"],
        "until": value["until"],
        "specs": value["specs"],
        "incomplete": value["incomplete"],
    });
    let mut more = Map::new();
    for key in ["changes", "unknown"] {
        let items = value[key].as_array().map(Vec::as_slice).unwrap_or_default();
        if items.len() > limit {
            more.insert(key.into(), json!(items.len()));
        }
        out[key] = Value::Array(items.iter().take(limit).cloned().collect());
    }
    if !more.is_empty() {
        out["more"] = Value::Object(more);
    }
    out
}

/// `bd spec candidates`'s groups as `{"groups": [...]}`: the groups and each
/// group's issues cut to `limit`, `count` each group's full size, and `more`
/// the number of groups when they were cut.
fn candidates(value: Value, limit: usize) -> Value {
    let groups = value.as_array().map(Vec::as_slice).unwrap_or_default();
    let shaped: Vec<Value> = groups
        .iter()
        .take(limit)
        .map(|g| {
            let issues = g["issues"].as_array().map(Vec::as_slice).unwrap_or_default();
            json!({
                "key": g["key"],
                "title": g["title"],
                "count": issues.len(),
                "issues": issues.iter().take(limit).cloned().collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut out = json!({ "groups": shaped });
    if groups.len() > limit {
        out["more"] = json!({ "groups": groups.len() });
    }
    out
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
        assert_eq!(
            argv("close", json!({ "ids": ["a"], "reason": "Done", "claim_next": true })),
            ["close", "--json", "--reason=Done", "--claim-next", "--", "a"]
        );
        assert_eq!(argv("memories", json!({})), ["memories", "--json"]);
    }

    #[test]
    fn limits_fetch_one_more() {
        assert_eq!(argv("ready", json!({})), ["ready", "--json", "--brief", "--limit=11"]);
        assert_eq!(argv("list", json!({})), ["list", "--json", "--brief", "--limit=21"]);
        assert_eq!(
            argv("list", json!({ "limit": 5, "status": ["closed"] })),
            ["list", "--json", "--brief", "--limit=6", "--status=closed"]
        );
    }

    #[test]
    fn list_takes_time_filters() {
        assert_eq!(
            argv("list", json!({ "updated_after": "7d", "created_after": "2026-01-15", "overdue": true })),
            [
                "list",
                "--json",
                "--brief",
                "--limit=21",
                "--updated-after=7d",
                "--created-after=2026-01-15",
                "--overdue"
            ]
        );
        // A time that looks like a flag stays the flag's value.
        assert_eq!(
            argv("list", json!({ "updated_after": "--all", "overdue": false })),
            ["list", "--json", "--brief", "--limit=21", "--updated-after=--all"]
        );
        let err = invoke("list", json!({ "overdue": "yes" })).err().unwrap();
        assert_eq!(err, "overdue must be true or false");
        let err = invoke("list", json!({ "updated_after": 7 })).err().unwrap();
        assert!(err.starts_with("updated_after must be"), "{err}");
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
    fn show_is_brief_on_request() {
        assert_eq!(argv("show", json!({ "ids": ["a"] })), ["show", "--json", "--", "a"]);
        assert_eq!(argv("show", json!({ "ids": ["a"], "brief": false })), ["show", "--json", "--", "a"]);
        assert_eq!(argv("show", json!({ "ids": ["a"], "brief": true })), ["show", "--json", "--brief", "--", "a"]);
    }

    #[test]
    fn show_says_why_on_request() {
        assert_eq!(argv("show", json!({ "ids": ["a"], "why": true })), ["show", "--json", "--why", "--", "a"]);
        assert_eq!(argv("show", json!({ "ids": ["a"], "why": false })), ["show", "--json", "--", "a"]);
        assert_eq!(
            argv("show", json!({ "ids": ["a", "b"], "brief": true, "why": true })),
            ["show", "--json", "--brief", "--why", "--", "a", "b"]
        );
        let err = invoke("show", json!({ "ids": ["a"], "why": "yes" })).err();
        assert_eq!(err.as_deref(), Some("why must be true or false"));
    }

    #[test]
    fn summaries_keep_the_parent() {
        let inv = invoke("list", json!({})).unwrap();
        let out = json!([
            { "id": "a.1", "title": "t", "status": "open", "priority": 2, "issue_type": "task", "parent": "a" },
            { "id": "b", "title": "u", "status": "open", "priority": 1, "issue_type": "bug" },
        ]);
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"{"issues":[{"id":"a.1","parent":"a","priority":2,"status":"open","title":"t","type":"task"},{"id":"b","priority":1,"status":"open","title":"u","type":"bug"}]}"#
        );
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

    /// A `specs` entry as `bd show`, `bd claim` and `close --claim-next` print it.
    fn spec_entry() -> Value {
        json!({ "id": "s", "title": "Checkout", "status": "pinned", "areas": ["checkout"], "via": ["a"],
                "linked": [], "requirements": [{ "id": "s.1", "title": "Requires sign-in" }],
                "non_goals": [], "inherits": [] })
    }

    #[test]
    fn show_keeps_spec_context() {
        let inv = invoke("show", json!({ "ids": ["a"] })).unwrap();
        let out = json!([{ "id": "a", "title": "t", "status": "in_progress", "issue_type": "task",
                           "lease": { "holder": "h", "token": 3, "expires_at": "T" },
                           "specs": [spec_entry()], "specs_truncated": true }]);
        let shaped: Value = serde_json::from_str(&inv.result(&out.to_string()).unwrap()).unwrap();
        assert_eq!(shaped[0]["lease"], json!({ "holder": "h", "expires_at": "T" }), "the token is stripped");
        assert_eq!(
            shaped[0]["specs"],
            json!([{ "id": "s", "title": "Checkout", "status": "pinned", "areas": ["checkout"], "via": ["a"],
                     "requirements": [{ "id": "s.1", "title": "Requires sign-in" }] }]),
            "kept, without its empty lists"
        );
        assert_eq!(shaped[0]["specs_truncated"], true);
    }

    #[test]
    fn claims_keep_spec_context_whole() {
        let mut entry = spec_entry();
        entry["linked"] = json!([{ "id": "s.2", "title": "No guests", "status": "pinned", "non_goal": true }]);
        let inv = invoke("claim", json!({ "id": "a" })).unwrap();
        let out = json!({ "already_held": false,
            "issue": { "id": "a", "title": "t", "status": "in_progress", "priority": 1, "issue_type": "bug",
                       "assignee": "me", "labels": [], "notes": "" },
            "lease": { "holder": "me", "token": 9, "expires_at": "T", "issue_id": "a", "renewals": 0 },
            "specs": [entry] });
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"{"already_held":false,"issue":{"assignee":"me","id":"a","priority":1,"status":"in_progress","title":"t","type":"bug"},"lease":{"expires_at":"T","token":9},"specs":[{"areas":["checkout"],"id":"s","linked":[{"id":"s.2","non_goal":true,"status":"pinned","title":"No guests"}],"requirements":[{"id":"s.1","title":"Requires sign-in"}],"status":"pinned","title":"Checkout","via":["a"]}]}"#
        );
        // An ungoverned claim's empty list is pruned.
        let bare = json!({ "already_held": false, "issue": out["issue"], "lease": out["lease"], "specs": [] });
        let shaped: Value = serde_json::from_str(&inv.result(&bare.to_string()).unwrap()).unwrap();
        assert!(shaped.get("specs").is_none(), "{shaped}");

        let close = invoke("close", json!({ "ids": ["b"], "reason": "done", "claim_next": true })).unwrap();
        let out = json!({ "closed": out["issue"], "next": { "from": "queue", "issue": out["issue"],
                           "lease": out["lease"], "specs": [spec_entry()] } });
        let shaped: Value = serde_json::from_str(&close.result(&out.to_string()).unwrap()).unwrap();
        assert_eq!(shaped["next"]["specs"][0]["requirements"][0]["id"], "s.1", "{shaped}");
        assert_eq!(shaped["next"]["specs"][0]["areas"], json!(["checkout"]), "{shaped}");
        assert_eq!(shaped["next"]["issue"]["type"], "bug", "the issue is still summarized: {shaped}");
        assert_eq!(shaped["next"]["lease"], json!({ "token": 9, "expires_at": "T" }), "{shaped}");
    }

    #[test]
    fn spec_tools_are_listed_last_in_order() {
        let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        assert_eq!(
            names[names.len() - 11..],
            [
                "spec_list",
                "spec_show",
                "spec_drift",
                "spec_changes",
                "spec_candidates",
                "spec_none",
                "spec_new",
                "spec_add",
                "spec_change",
                "spec_remove",
                "spec_link"
            ]
        );
        let describe = |name: &str| TOOLS.iter().find(|t| t.name == name).unwrap().describe();
        for read in ["spec_list", "spec_show", "spec_drift", "spec_changes", "spec_candidates"] {
            assert_eq!(describe(read)["annotations"], json!({ "readOnlyHint": true }), "{read}");
        }
        for write in ["spec_none", "spec_new", "spec_add", "spec_change", "spec_remove", "spec_link"] {
            assert_eq!(describe(write)["annotations"], json!({ "destructiveHint": false }), "{write}");
        }
        assert_eq!(describe("spec_new")["inputSchema"]["required"], json!(["area", "title"]));
        assert_eq!(describe("spec_add")["inputSchema"]["required"], json!(["spec", "sentence", "from"]));
        assert_eq!(describe("spec_change")["inputSchema"]["required"], json!(["requirement", "sentence", "from"]));
        assert_eq!(describe("spec_remove")["inputSchema"]["required"], json!(["requirement", "reason"]));
        assert_eq!(describe("spec_link")["inputSchema"]["required"], json!(["issue", "targets"]));
        let candidates = describe("spec_candidates");
        assert_eq!(
            candidates["inputSchema"]["properties"]["limit"],
            json!({ "type": "integer", "minimum": 1, "maximum": 100,
                    "description": "Default 20: groups, and issues in each" })
        );
        assert!(candidates["inputSchema"].get("required").is_none(), "{candidates}");
        assert_eq!(describe("spec_show")["inputSchema"]["required"], json!(["target"]));
        assert_eq!(describe("spec_changes")["inputSchema"]["required"], json!(["since"]));
        assert_eq!(
            describe("spec_changes")["inputSchema"]["properties"]["limit"],
            json!({ "type": "integer", "minimum": 1, "maximum": 100, "description": "Default 20" })
        );
        assert_eq!(describe("spec_none")["inputSchema"]["required"], json!(["ids", "reason"]));
        assert_eq!(describe("spec_list")["inputSchema"], json!({ "type": "object", "properties": {} }));
    }

    #[test]
    fn spec_tool_arguments_never_become_flags() {
        assert_eq!(argv("spec_list", json!({})), ["spec", "list", "--json"]);
        assert_eq!(argv("spec_show", json!({ "target": "--history" })), ["spec", "show", "--json", "--", "--history"]);
        assert_eq!(
            argv("spec_show", json!({ "target": "checkout", "history": true })),
            ["spec", "show", "--json", "--history", "--", "checkout"]
        );
        assert_eq!(
            argv("spec_show", json!({ "target": "checkout", "history": false })),
            ["spec", "show", "--json", "--", "checkout"]
        );
        assert_eq!(argv("spec_drift", json!({})), ["spec", "drift", "--json"]);
        // The limit cuts the output; it is never passed.
        assert_eq!(
            argv("spec_drift", json!({ "since": "--all", "limit": 5 })),
            ["spec", "drift", "--json", "--since=--all"]
        );
        assert_eq!(
            argv("spec_none", json!({ "ids": ["-x", "t-1"], "reason": "--force" })),
            ["spec", "none", "--json", "--reason=--force", "--", "-x", "t-1"]
        );
        assert_eq!(
            argv("spec_show", json!({ "target": "checkout", "as_of": "-1d" })),
            ["spec", "show", "--json", "--as-of=-1d", "--", "checkout"]
        );
        assert_eq!(
            argv("spec_show", json!({ "target": "-x", "as_of": "#12", "history": true })),
            ["spec", "show", "--json", "--history", "--as-of=#12", "--", "-x"]
        );
        assert_eq!(argv("spec_changes", json!({ "since": "--all" })), ["spec", "changes", "--json", "--since=--all"]);
        // The limit cuts the output; it is never passed.
        assert_eq!(
            argv("spec_changes", json!({ "target": "--history", "since": "-1d", "until": "#9", "limit": 3 })),
            ["spec", "changes", "--json", "--since=-1d", "--until=#9", "--", "--history"]
        );

        // The limit cuts the output; it is never passed.
        assert_eq!(argv("spec_candidates", json!({})), ["spec", "candidates", "--json"]);
        assert_eq!(argv("spec_candidates", json!({ "limit": 5 })), ["spec", "candidates", "--json"]);
        assert_eq!(
            argv(
                "spec_new",
                json!({ "area": "-q", "title": "--take-over", "parent": "--force", "description": "-x",
                        "from": ["--actor=x", "t-1"] })
            ),
            [
                "spec",
                "new",
                "--json",
                "--parent=--force",
                "--description=-x",
                "--from=--actor=x",
                "--from=t-1",
                "--",
                "-q",
                "--take-over"
            ]
        );
        assert_eq!(argv("spec_new", json!({ "area": "a", "title": "T" })), ["spec", "new", "--json", "--", "a", "T"]);
        assert_eq!(
            argv(
                "spec_add",
                json!({ "spec": "-s", "sentence": "--force", "from": ["t-1"], "non_goal": true, "description": "--x" })
            ),
            ["spec", "add", "--json", "--from=t-1", "--non-goal", "--description=--x", "--", "-s", "--force"]
        );
        assert_eq!(
            argv("spec_add", json!({ "spec": "s", "sentence": "x", "from": ["t-1"], "non_goal": false })),
            ["spec", "add", "--json", "--from=t-1", "--", "s", "x"]
        );
        assert_eq!(
            argv("spec_change", json!({ "requirement": "--take-over", "sentence": "-q", "from": ["t-1", "t-2"] })),
            ["spec", "change", "--json", "--from=t-1", "--from=t-2", "--", "--take-over", "-q"]
        );
        assert_eq!(
            argv("spec_remove", json!({ "requirement": "-r", "reason": "--force", "from": ["-x"] })),
            ["spec", "remove", "--json", "--reason=--force", "--from=-x", "--", "-r"]
        );
        assert_eq!(
            argv("spec_remove", json!({ "requirement": "-r", "reason": "--force" })),
            ["spec", "remove", "--json", "--reason=--force", "--", "-r"]
        );
        assert_eq!(
            argv("spec_link", json!({ "issue": "--force", "targets": ["-q", "s-1"] })),
            ["spec", "link", "--json", "--", "--force", "-q", "s-1"]
        );
    }

    #[test]
    fn invalid_spec_arguments_are_refused() {
        let err = |tool, args| invoke(tool, args).err().unwrap();
        assert_eq!(err("spec_show", json!({})), "target is required");
        assert_eq!(err("spec_show", json!({ "target": "  " })), "target must not be empty");
        assert_eq!(err("spec_show", json!({ "target": "a", "history": "yes" })), "history must be true or false");
        assert_eq!(err("spec_show", json!({ "target": "a", "limit": 3 })), "unknown argument \"limit\"");
        assert_eq!(err("spec_list", json!({ "x": 1 })), "unknown argument \"x\"");
        assert_eq!(err("spec_none", json!({ "ids": ["a"] })), "reason is required");
        assert_eq!(err("spec_none", json!({ "ids": ["a"], "reason": " \n" })), "reason must not be empty");
        assert_eq!(err("spec_none", json!({ "ids": [], "reason": "r" })), "ids must have 1 to 20 items");
        let many: Vec<String> = (0..21).map(|i| format!("t-{i}")).collect();
        assert_eq!(err("spec_none", json!({ "ids": many, "reason": "r" })), "ids must have 1 to 20 items");
        assert_eq!(err("spec_drift", json!({ "limit": 0 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_drift", json!({ "limit": 101 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_show", json!({ "target": "a", "as_of": " " })), "as_of must not be empty");
        assert_eq!(err("spec_show", json!({ "target": "a", "as_of": 12 })), "as_of must be a string");
        assert_eq!(err("spec_changes", json!({})), "since is required");
        assert_eq!(err("spec_changes", json!({ "since": "" })), "since must not be empty");
        assert_eq!(err("spec_changes", json!({ "since": "1d", "target": " " })), "target must not be empty");
        assert_eq!(err("spec_changes", json!({ "since": "1d", "until": "\t" })), "until must not be empty");
        assert_eq!(err("spec_changes", json!({ "since": "1d", "limit": 0 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_changes", json!({ "since": "1d", "limit": 101 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_changes", json!({ "since": "1d", "history": true })), "unknown argument \"history\"");

        let comma = "from items must not contain ','";
        assert_eq!(err("spec_new", json!({ "title": "T" })), "area is required");
        assert_eq!(err("spec_new", json!({ "area": "a" })), "title is required");
        assert_eq!(err("spec_new", json!({ "area": " ", "title": "T" })), "area must not be empty");
        assert_eq!(err("spec_new", json!({ "area": "a", "title": "" })), "title must not be empty");
        assert_eq!(err("spec_new", json!({ "area": "a", "title": "\t" })), "title must not be empty");
        assert_eq!(err("spec_new", json!({ "area": "a", "title": 5 })), "title must be a string");
        assert_eq!(err("spec_new", json!({ "area": "a", "title": "T", "from": ["a,b"] })), comma);
        assert_eq!(err("spec_new", json!({ "area": "a", "title": "T", "from": many })), "from must have 0 to 20 items");
        assert_eq!(
            err("spec_new", json!({ "area": "a", "title": "T", "non_goal": true })),
            "unknown argument \"non_goal\""
        );

        let add = |extra: Value| {
            let mut args = json!({ "spec": "s", "sentence": "x", "from": ["t-1"] });
            for (k, v) in extra.as_object().unwrap() {
                args[k] = v.clone();
            }
            invoke("spec_add", args).err().unwrap()
        };
        assert_eq!(err("spec_add", json!({ "spec": "s", "sentence": "x" })), "from is required");
        assert_eq!(add(json!({ "from": [] })), "from must have 1 to 20 items");
        assert_eq!(add(json!({ "from": many })), "from must have 1 to 20 items");
        assert_eq!(add(json!({ "non_goal": "yes" })), "non_goal must be true or false");
        assert_eq!(add(json!({ "sentence": " " })), "sentence must not be empty");
        assert_eq!(add(json!({ "spec": "" })), "spec must not be empty");
        assert_eq!(add(json!({ "from": ["t-1,t-2"] })), comma);
        assert_eq!(add(json!({ "x": 1 })), "unknown argument \"x\"");

        let change = |extra: Value| {
            let mut args = json!({ "requirement": "r", "sentence": "x", "from": ["t-1"] });
            for (k, v) in extra.as_object().unwrap() {
                args[k] = v.clone();
            }
            invoke("spec_change", args).err().unwrap()
        };
        assert_eq!(change(json!({ "requirement": " " })), "requirement must not be empty");
        assert_eq!(err("spec_change", json!({ "requirement": "r", "from": ["t-1"] })), "sentence is required");
        assert_eq!(change(json!({ "sentence": " " })), "sentence must not be empty");
        assert_eq!(change(json!({ "from": [] })), "from must have 1 to 20 items");
        assert_eq!(change(json!({ "from": many })), "from must have 1 to 20 items");
        assert_eq!(change(json!({ "from": "t-1" })), "from must be an array of strings");
        assert_eq!(change(json!({ "from": ["a,b"] })), comma);
        assert_eq!(change(json!({ "x": 1 })), "unknown argument \"x\"");

        let remove = |extra: Value| {
            let mut args = json!({ "requirement": "r", "reason": "why" });
            for (k, v) in extra.as_object().unwrap() {
                args[k] = v.clone();
            }
            invoke("spec_remove", args).err().unwrap()
        };
        assert_eq!(err("spec_remove", json!({ "requirement": "r" })), "reason is required");
        assert_eq!(remove(json!({ "reason": " " })), "reason must not be empty");
        assert_eq!(remove(json!({ "reason": 3 })), "reason must be a string");
        assert_eq!(remove(json!({ "requirement": "" })), "requirement must not be empty");
        assert_eq!(remove(json!({ "from": many })), "from must have 0 to 20 items");
        assert_eq!(remove(json!({ "from": ["a,b"] })), comma);
        assert_eq!(remove(json!({ "x": 1 })), "unknown argument \"x\"");

        let link = |extra: Value| {
            let mut args = json!({ "issue": "w", "targets": ["s-1"] });
            for (k, v) in extra.as_object().unwrap() {
                args[k] = v.clone();
            }
            invoke("spec_link", args).err().unwrap()
        };
        assert_eq!(err("spec_link", json!({ "issue": "w" })), "targets is required");
        assert_eq!(link(json!({ "targets": [] })), "targets must have 1 to 20 items");
        assert_eq!(link(json!({ "targets": many })), "targets must have 1 to 20 items");
        assert_eq!(link(json!({ "issue": " " })), "issue must not be empty");
        assert_eq!(link(json!({ "issue": 7 })), "issue must be a string");
        assert_eq!(link(json!({ "targets": [""] })), "targets must not have empty items");
        assert_eq!(link(json!({ "x": 1 })), "unknown argument \"x\"");

        assert_eq!(err("spec_candidates", json!({ "limit": 0 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_candidates", json!({ "limit": 101 })), "limit must be between 1 and 100");
        assert_eq!(err("spec_candidates", json!({ "limit": "5" })), "limit must be an integer");
        assert_eq!(err("spec_candidates", json!({ "x": 1 })), "unknown argument \"x\"");
    }

    #[test]
    fn spec_candidates_cuts_groups_and_issues() {
        let brief = |id: &str, title: &str| json!({ "id": id, "title": title });
        let none = invoke("spec_candidates", json!({})).unwrap().result("[]").unwrap();
        assert_eq!(none, "{}");
        let out = json!([
            { "key": "epic:e-1", "title": "Checkout",
              "issues": [brief("a", "A\u{1b}[31m"), brief("b", "B"), brief("c", "C")] },
            { "key": "label:ui", "issues": [brief("d", "D")] },
            { "key": "ungrouped", "issues": [brief("e", "E")] },
        ])
        .to_string();
        let text = invoke("spec_candidates", json!({ "limit": 2 })).unwrap().result(&out).unwrap();
        assert!(text.contains(r#""title":"A\u001b[31m""#), "{text}");
        let shaped: Value = serde_json::from_str(&text).unwrap();
        let groups = shaped["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["key"], "epic:e-1");
        assert_eq!(groups[0]["title"], "Checkout");
        assert_eq!(groups[0]["count"], 3);
        assert_eq!(groups[0]["issues"].as_array().unwrap().len(), 2);
        assert_eq!(groups[0]["issues"][1], brief("b", "B"));
        assert_eq!(groups[1], json!({ "key": "label:ui", "count": 1, "issues": [brief("d", "D")] }));
        assert_eq!(shaped["more"], json!({ "groups": 3 }));

        let text = invoke("spec_candidates", json!({})).unwrap().result(&out).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert!(shaped.get("more").is_none(), "{text}");
        let groups = shaped["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0]["count"], 3);
        assert_eq!(groups[0]["issues"].as_array().unwrap().len(), 3);
        assert_eq!(groups[2], json!({ "key": "ungrouped", "count": 1, "issues": [brief("e", "E")] }));
    }

    #[test]
    fn spec_writes_return_summaries() {
        let issue = |id: &str, status: &str| {
            json!({ "id": id, "title": "t", "status": status, "priority": 2, "issue_type": "story",
                    "description": "long text", "labels": ["requirement"], "created_by": "me" })
        };
        let inv = invoke("spec_change", json!({ "requirement": "s.1", "sentence": "x", "from": ["w"] })).unwrap();
        let out = json!({ "requirement": issue("s.2", "pinned"), "superseded": issue("s.1", "closed"),
                          "spec": "s", "non_goal": false, "sources": ["w"] });
        let shaped: Value = serde_json::from_str(&inv.result(&out.to_string()).unwrap()).unwrap();
        let summary = |id: &str, status: &str| {
            json!({ "id": id, "title": "t", "status": status, "priority": 2, "type": "story",
                    "labels": ["requirement"] })
        };
        assert_eq!(
            shaped,
            json!({ "requirement": summary("s.2", "pinned"), "superseded": summary("s.1", "closed"),
                    "spec": "s", "non_goal": false, "sources": ["w"] })
        );

        let inv = invoke("spec_link", json!({ "issue": "w", "targets": ["s"] })).unwrap();
        let out = json!([{ "issue": "w", "target": "s", "already": false }]);
        assert_eq!(inv.result(&out.to_string()).unwrap(), r#"[{"already":false,"issue":"w","target":"s"}]"#);
    }

    #[test]
    fn spec_list_wraps_specs() {
        let inv = invoke("spec_list", json!({})).unwrap();
        assert_eq!(inv.result("[]").unwrap(), "{}");
        let out = json!([{ "id": "s-1", "title": "Checkout", "status": "pinned", "areas": ["checkout"],
            "parent": null, "closed_parent": null, "requirements": 0, "non_goals": 0, "linked": 2 }]);
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"{"specs":[{"areas":["checkout"],"id":"s-1","linked":2,"non_goals":0,"requirements":0,"status":"pinned","title":"Checkout"}]}"#
        );
    }

    #[test]
    fn spec_show_trims_history_and_nested_inherited() {
        let item = |id: &str| json!({ "id": id, "title": "r", "description": "", "sources": [] });
        let spec = |id: &str, title: &str| json!({ "id": id, "title": title, "description": "" });
        let inherited = |id: &str| json!([{ "spec": spec(id, "up"), "requirements": [item("u-1")], "non_goals": [] }]);
        let history = json!([{ "id": "h-1", "title": "old", "description": "", "sources": [],
            "outcome": "superseded", "by": "r-1", "reason": "", "closed_at": "T" }]);
        let view = json!([{
            "spec": spec("s-1", "Top\u{1b}[31m"), "requirements": [item("r-1")], "non_goals": [],
            "history": history, "errors": [], "warnings": [], "inherited": inherited("p-1"),
            "subspecs": [{ "spec": spec("s-2", "Sub"), "requirements": [item("r-2")], "non_goals": [],
                "history": history, "errors": [], "warnings": [], "inherited": inherited("s-1"), "subspecs": [] }],
        }])
        .to_string();

        let text = invoke("spec_show", json!({ "target": "s-1" })).unwrap().result(&view).unwrap();
        assert!(text.contains(r#""title":"Top\u001b[31m""#), "{text}");
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert!(!text.contains("\"history\""), "{text}");
        let top = &shaped["specs"][0];
        assert_eq!(top["inherited"][0]["spec"]["id"], "p-1");
        assert_eq!(top["subspecs"][0]["spec"]["id"], "s-2");
        assert!(top["subspecs"][0].get("inherited").is_none(), "{text}");

        let text = invoke("spec_show", json!({ "target": "s-1", "history": true })).unwrap().result(&view).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        let top = &shaped["specs"][0];
        assert_eq!(top["history"][0]["outcome"], "superseded");
        assert_eq!(top["subspecs"][0]["history"][0]["id"], "h-1");
        assert_eq!(top["inherited"][0]["spec"]["id"], "p-1");
        assert!(top["subspecs"][0].get("inherited").is_none(), "{text}");
    }

    #[test]
    fn spec_drift_cuts_each_list() {
        let issue = |id: &str, ty: &str| json!({ "id": id, "title": "t", "status": "closed", "priority": 2, "issue_type": ty, "assignee": null });
        let out = json!({
            "since": "T", "count": 6,
            "unlinked": [issue("a", "task"), issue("b", "bug")],
            "shaky": [{ "requirement": issue("r", "story"), "source": issue("w", "task"), "why": "failed" }],
            "bad_status": [],
            "orphaned": [{ "spec": issue("s", "feature"), "parent": "p" }],
            "malformed": [
                { "issue": issue("m", "epic"), "problem": "no_area", "detail": "no area:<name> label" },
                { "issue": issue("m", "epic"), "problem": "spec_type", "detail": "type epic, not feature" },
            ],
            "to_link": [],
        })
        .to_string();
        let inv = invoke("spec_drift", json!({ "limit": 1 })).unwrap();
        assert!(inv.accepts_exit(1));
        assert!(!inv.accepts_exit(2));
        assert_eq!(
            inv.result(&out).unwrap(),
            concat!(
                r#"{"count":6,"malformed":[{"detail":"no area:<name> label","issue":{"id":"m","priority":2,"status":"closed","title":"t","type":"epic"},"problem":"no_area"}],"#,
                r#""more":{"malformed":2,"unlinked":2},"orphaned":[{"parent":"p","spec":{"id":"s","priority":2,"status":"closed","title":"t","type":"feature"}}],"#,
                r#""shaky":[{"requirement":{"id":"r","priority":2,"status":"closed","title":"t","type":"story"},"source":{"id":"w","priority":2,"status":"closed","title":"t","type":"task"},"why":"failed"}],"#,
                r#""since":"T","unlinked":[{"id":"a","priority":2,"status":"closed","title":"t","type":"task"}]}"#
            )
        );
        let text = invoke("spec_drift", json!({})).unwrap().result(&out).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert!(shaped.get("more").is_none(), "{text}");
        assert_eq!(shaped["unlinked"].as_array().unwrap().len(), 2);
        assert_eq!(shaped["malformed"][1]["problem"], "spec_type");
        let none = json!({ "since": "T", "count": 0, "unlinked": [], "shaky": [], "bad_status": [], "orphaned": [], "malformed": [], "to_link": [] });
        assert_eq!(inv.result(&none.to_string()).unwrap(), r#"{"count":0,"since":"T"}"#);
        // Only spec drift has a findings exit.
        assert!(!invoke("spec_list", json!({})).unwrap().accepts_exit(1));
    }

    #[test]
    fn spec_show_keeps_the_as_of_keys() {
        let view = json!([{
            "spec": { "id": "s-1", "title": "Top", "description": "" }, "requirements": [], "non_goals": [],
            "errors": [], "warnings": [], "subspecs": [{ "spec": { "id": "s-2", "title": "Sub", "description": "" },
                "requirements": [], "non_goals": [], "errors": [], "warnings": [], "subspecs": [],
                "unknown": [{ "id": "r-9", "key": "title", "reason": "why" }] }],
            "unknown": [], "as_of": { "seq": 4, "time": "T" }, "incomplete": false,
            "retained_from": { "seq": 1, "ts": "T0" },
        }])
        .to_string();
        let text = invoke("spec_show", json!({ "target": "s-1", "as_of": "4" })).unwrap().result(&view).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        let top = &shaped["specs"][0];
        assert_eq!(top["as_of"], json!({ "seq": 4, "time": "T" }));
        assert_eq!(top["incomplete"], json!(false));
        assert_eq!(top["retained_from"], json!({ "seq": 1, "ts": "T0" }));
        // An empty unknown list is left out; a non-empty one is kept.
        assert!(top.get("unknown").is_none(), "{text}");
        assert_eq!(top["subspecs"][0]["unknown"][0]["id"], "r-9");
    }

    #[test]
    fn spec_changes_cuts_changes_and_unknown() {
        let change = |seq: i64, kind: &str| {
            json!({ "seq": seq, "at": "T", "actor": "a", "spec": "s-1", "id": format!("r-{seq}"),
                "item": "requirement", "kind": kind, "title": "t\u{1b}[31m", "sources": [] })
        };
        let unknown = |id: &str| json!({ "id": id, "key": "title", "reason": "why" });
        let out = json!({
            "since": { "seq": 3, "time": null }, "until": { "seq": null, "time": "U" },
            "specs": [{ "id": "s-1", "title": "Checkout" }],
            "changes": [change(4, "added"), change(5, "removed"), change(6, "added")],
            "unknown": [unknown("x-1")],
            "incomplete": false,
        })
        .to_string();
        let inv = invoke("spec_changes", json!({ "since": "3", "limit": 2 })).unwrap();
        assert!(!inv.accepts_exit(1));
        let text = inv.result(&out).unwrap();
        assert!(text.contains(r#""title":"t\u001b[31m""#), "{text}");
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(shaped["more"], json!({ "changes": 3 }));
        let seqs: Vec<i64> = shaped["changes"].as_array().unwrap().iter().map(|c| c["seq"].as_i64().unwrap()).collect();
        assert_eq!(seqs, [4, 5]);
        assert_eq!(shaped["unknown"], json!([unknown("x-1")]));
        assert_eq!(shaped["since"], json!({ "seq": 3 }));
        assert_eq!(shaped["until"], json!({ "time": "U" }));
        assert_eq!(shaped["specs"], json!([{ "id": "s-1", "title": "Checkout" }]));
        assert_eq!(shaped["incomplete"], json!(false));

        let text = invoke("spec_changes", json!({ "since": "3", "limit": 1 })).unwrap().result(&out).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(shaped["more"], json!({ "changes": 3 }));
        let text = invoke("spec_changes", json!({ "since": "3" })).unwrap().result(&out).unwrap();
        let shaped: Value = serde_json::from_str(&text).unwrap();
        assert!(shaped.get("more").is_none(), "{text}");
        assert_eq!(shaped["changes"].as_array().unwrap().len(), 3);

        let many: Vec<Value> = (0..3).map(|i| unknown(&format!("x-{i}"))).collect();
        let none = json!({ "since": { "seq": 3 }, "until": { "seq": 9 }, "specs": [], "changes": [],
            "unknown": many, "incomplete": true })
        .to_string();
        let text = invoke("spec_changes", json!({ "since": "3", "limit": 2 })).unwrap().result(&none).unwrap();
        assert_eq!(
            text,
            r#"{"incomplete":true,"more":{"unknown":3},"since":{"seq":3},"unknown":[{"id":"x-0","key":"title","reason":"why"},{"id":"x-1","key":"title","reason":"why"}],"until":{"seq":9}}"#
        );
    }

    #[test]
    fn spec_none_keeps_already_false() {
        let inv = invoke("spec_none", json!({ "ids": ["a"], "reason": "r" })).unwrap();
        let out = json!([{ "id": "a", "already": false, "labels": ["spec:none"], "comment_id": 7 }]);
        assert_eq!(
            inv.result(&out.to_string()).unwrap(),
            r#"[{"already":false,"comment_id":7,"id":"a","labels":["spec:none"]}]"#
        );
    }

    #[test]
    fn the_tool_list_stays_small() {
        // 10,668 bytes, about 2,500 tokens; every agent connected pays this per session.
        let list = serde_json::to_string(&TOOLS.iter().map(Tool::describe).collect::<Vec<_>>()).unwrap();
        assert!(list.len() < 10768, "tools/list is {} bytes", list.len());
    }
}
