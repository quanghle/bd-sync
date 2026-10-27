//! `bd`'s commands: the command-line grammar ([`cli`]), each command's
//! implementation, and the client of remote workspaces. [`run`] runs a
//! command line here or on a workspace's server; [`execute`] runs a command
//! here, as `bd serve` does for each request. `bd serve` itself and
//! `bd bench` belong to the binary, which hands them to this library as a
//! [`Handler`].

pub mod actor;
pub mod agents;
pub mod app;
pub mod approval_link;
pub mod backup;
pub mod batch;
pub mod cli;
pub mod commands;
pub mod credentials;
pub mod fmt;
pub mod gate_review;
pub mod gates;
pub mod gh;
pub mod github;
pub mod graph_view;
pub mod hook;
pub mod io;
pub mod keychain;
pub mod logging;
pub mod mcp;
pub mod paths;
pub mod playbooks;
pub mod protocol;
pub mod publish;
pub mod remote;
pub mod setup;
pub mod stream;
pub mod tokens;

use bd_core::{Error, Result};
use serde_json::json;

use crate::app::App;
use crate::cli::{Cli, Command, CommentCommand, EpicCommand, GateCommand, HookCommand, LabelCommand, MemoryCommand};
use crate::commands::*;

/// Run a command line: on the workspace's server when it is remote, else
/// here; returns the process exit code.
pub fn run(cli: Cli) -> i32 {
    let json = cli.global.json;
    let mut app = match App::new(cli.global.clone()) {
        Ok(app) => app,
        Err(e) => return report(&e, json),
    };
    if let Some(name) = &cli.global.session
        && let Err(e) = actor::set_session_flag(name)
    {
        return report(&e, json);
    }
    if hook::works_in_session_dir(&cli.command) {
        hook::enter_session_dir(&mut app);
        hook::take_session_id(&cli.command);
    }
    if !always_local(&cli.command) {
        match remote::detect_for(&app, &cli.command) {
            Ok(Some(r)) => return remote::run(&mut app, r, &cli),
            Ok(None) => {}
            // `bd prime` from a session hook: report the problem as context, never fail the hook.
            Err(e) if remote::is_hook(&cli) => return remote::unavailable(&cli, &e),
            Err(e) => return report(&e, json),
        }
    }
    execute(&mut app, &cli.command)
}

/// Commands that never use a remote workspace (`bd query --parse-only`
/// reads no workspace at all).
pub fn always_local(cmd: &Command) -> bool {
    matches!(cmd, Command::Query(a) if a.parse_only)
        || matches!(
            cmd,
            Command::Serve(_)
                | Command::Mcp(_)
                | Command::Remote(_)
                | Command::Backup(_)
                | Command::Hook(_)
                | Command::Setup(_)
                | Command::Version
                | Command::Completion(_)
                | Command::Bench(_)
                | Command::BenchWorker(_)
        )
}

/// Run one command and return its exit code: locally, and for each request
/// under `bd serve` (with output captured by [`io::capture`]).
pub fn execute(app: &mut App, cmd: &Command) -> i32 {
    let timing = app.g.timing
        || (!io::serving() && std::env::var("BD_TIMING").is_ok_and(|v| !matches!(v.as_str(), "" | "0" | "false")));
    let slow_ms = app.g.slow_ms;
    let name = command_name(cmd);
    let result = dispatch(app, cmd);
    let elapsed = app.started.elapsed();
    if timing {
        io::errln(format_timing(app));
    }
    let total_ms = elapsed.as_millis() as u64;
    if total_ms >= slow_ms
        && !matches!(
            cmd,
            Command::Events(_)
                | Command::Edit(_)
                | Command::Backup(_)
                | Command::Bench(_)
                | Command::BenchWorker(_)
                | Command::Serve(_)
                | Command::Mcp(_)
                | Command::Remote(_)
                | Command::Hook(_)
                | Command::Agents(cli::AgentsCommand::Approve(_) | cli::AgentsCommand::Watch(_))
                | Command::Gate(cli::GateCommand::Review(_))
        )
    {
        tracing::warn!(target: "bd::slow", command = name, total_ms, "slow command");
    }
    tracing::debug!(target: "bd::cli", command = name, total_us = elapsed.as_micros() as u64, ok = result.is_ok(), "done");
    match result {
        Ok(code) => code,
        Err(e) => {
            io::note_needs(e.needs());
            report_as(&e, app.g.json, app.known_actor())
        }
    }
}

/// The lines `report` prints for an error; `actor` is who the command ran
/// as, if it got that far.
pub fn render_error(e: &Error, json: bool, actor: Option<&actor::Resolved>) -> String {
    // A refusal at a human gate names it; bd serve may offer its approval page.
    let link = e.gate().and_then(io::approval_url);
    // A refused close or discard a person could approve may have a link of its own.
    let op = e.is_approvable().then(io::operation_link).flatten();
    if json {
        let mut error = json!({ "code": e.code(), "message": e.to_string(), "exit_code": e.exit_code() });
        if let Some(gate) = e.gate() {
            error["gate"] = json!(gate);
        }
        if let Some(url) = link {
            error["approval_url"] = json!(url);
        }
        if let Some(io::OpLink { outcome: Ok(url), .. }) = op {
            error["operation_approval_url"] = json!(url);
        }
        return format!("{}\n", json!({ "error": error }));
    }
    let mut s = format!("error: {e}\n");
    if let Some(url) = link {
        s.push_str(&format!("approve in a browser: {url}\n"));
    }
    if let Some(op) = op {
        let phrase = op.op.phrase();
        match op.outcome {
            Ok(url) => s.push_str(&format!("approve {phrase} {} in a browser: {url}\n", op.issue)),
            Err(why) => s.push_str(&format!("no browser approval link for {phrase} {}: {why}\n", op.issue)),
        }
    }
    if let Some(h) = actor.and_then(|a| other_session_hint(e, a)).or_else(|| hint(e).map(String::from)) {
        s.push_str(&format!("hint: {h}\n"));
    }
    s
}

/// Print an error on stderr and return its exit code.
pub fn report(e: &Error, json: bool) -> i32 {
    report_as(e, json, None)
}

pub fn report_as(e: &Error, json: bool, actor: Option<&actor::Resolved>) -> i32 {
    io::errln(render_error(e, json, actor).trim_end_matches('\n'));
    e.exit_code()
}

/// The hint for a claim conflict with another session of the caller's own
/// user (after /clear or a resume, or in a subagent with its own session),
/// which the caller may be continuing, or with a newer lease of the caller.
/// Only an actor bd derived has other sessions ([`actor::user_root`]).
fn other_session_hint(e: &Error, resolved: &actor::Resolved) -> Option<String> {
    let me = resolved.actor.as_str();
    if let Error::LeaseLost { id, holder: Some(h), .. } = e
        && h == me
    {
        return Some(format!(
            "you still hold {id}, under a newer lease token (named above; `bd show {id}` shows it): use that one"
        ));
    }
    let (id, holder) = match e {
        Error::NotOwner { id, holder: Some(h), .. } | Error::LeaseLost { id, holder: Some(h), .. } => (id, h),
        Error::AlreadyClaimed { id, holder } => (id, holder),
        _ => return None,
    };
    if !actor::other_session_of_user(resolved, holder) {
        return None;
    }
    Some(format!(
        "{id} is held by another session of yours ({holder}; you are {me}). If this session is continuing that work \
         (after /clear or a resume, or as the subagent it was handed to), take the claim over: `{}` (recorded in the \
         event history), then use the new lease token it prints. Otherwise another session is working on it: leave it to that session and pick other work.",
        actor::take_over_command(id, me)
    ))
}

fn hint(e: &Error) -> Option<&'static str> {
    Some(match e.unmarked() {
        Error::AlreadyClaimed { .. } => {
            "pick other work with `bd claim --next`; to renew a claim of yours, pass its lease token (`bd claim <id> --token <t>`). A claim whose holder stops heartbeating frees itself once its lease has been expired for lease.grace. Only to take it over deliberately: `bd update <id> --assignee <you> --take-over` (recorded in the event history)"
        }
        Error::NotReady { .. } => "see `bd show <id> --why` for why; `bd claim <id> --allow-blocked` overrides",
        Error::Conflict { .. } => {
            "another actor changed it first; re-read (`bd show <id> --json`) and retry with the new revision"
        }
        Error::LeaseLost { .. } => "stop working on it: the claim was released, reclaimed, or taken over",
        Error::NotOwner { .. } | Error::ClaimsHeld { .. } => {
            "only its holder ends a live claim or gives up an assignment: pick other work, or leave it to its holder (a claim whose holder stops heartbeating frees itself once its lease has been expired for lease.grace). --force does not change that; pass --take-over only to take it over deliberately (recorded in the event history)"
        }
        Error::Busy(_) => "another process holds the write lock; retry, or raise --busy-timeout-ms",
        Error::EventsTruncated { .. } => "re-baseline with `bd export` and tail from its head_seq",
        Error::HistoryPruned { .. } => "pick a later --as-of or --since; `bd events -n 1` shows what is retained",
        Error::NoWorkspace(_) => "create one with `bd init`",
        Error::Needs { .. } => {
            "only a person (or an admin) may do this: a person runs it in a terminal outside agent sessions. In a \
             remote workspace, `bd remote login --human` once saves their access token in the OS keychain, and bd \
             then uses it for such commands"
        }
        Error::Unauthorized(_) => {
            "check the access token (BD_TOKEN, or `bd remote login`), and its role, kind, workspaces and actor (`bd remote show`; `bd serve token list` on the server)"
        }
        Error::Remote(_) => {
            "`bd remote show` checks the URL, certificate and connection; the command did not take effect, so running \
             it again is safe"
        }
        Error::AnswerLost(_) => {
            "it may have taken effect: check the current state (`bd show`, `bd events`) before running it again, which \
             would apply it twice"
        }
        _ => return None,
    })
}

/// Runs the commands this library leaves to the binary linking it: `bd
/// serve` (`bd-server`) and `bd bench`, which starts servers.
pub type Handler = fn(&mut App, &Command) -> Result<i32>;

static HANDLER: std::sync::OnceLock<Handler> = std::sync::OnceLock::new();

/// Set the [`Handler`] of `bd serve` and `bd bench`, once, before [`run`].
pub fn set_handler(handler: Handler) {
    let _ = HANDLER.set(handler);
}

fn write_cmd(
    app: &mut App,
    op: &'static str,
    f: impl FnOnce(&mut bd_core::WriteCtx<'_>) -> Result<app::Out>,
) -> Result<i32> {
    let out = app.write(op, f)?;
    app.print(out);
    Ok(0)
}

pub fn dispatch(app: &mut App, cmd: &Command) -> Result<i32> {
    match cmd {
        Command::Init(a) => cmd_init(app, a).map(|_| 0),
        Command::Create(a) => write_cmd(app, "create", |tx| exec_create(tx, a)),
        Command::Quick(a) => {
            let out = app.write("create", |tx| exec_create(tx, &a.to_create()))?;
            if app.g.json {
                app.print(out);
            } else {
                for id in out.ids {
                    io::outln(id);
                }
            }
            Ok(0)
        }
        Command::Show(a) => cmd_show(app, a).map(|_| 0),
        Command::List(a) => cmd_list(app, a).map(|_| 0),
        Command::Edit(a) => cmd_edit(app, a).map(|_| 0),
        Command::Query(a) => cmd_query(app, a).map(|_| 0),
        Command::Epic(EpicCommand::Status(a)) => cmd_epic_status(app, a).map(|_| 0),
        Command::Epic(EpicCommand::CloseEligible(a)) => cmd_close_eligible(app, a).map(|_| 0),
        Command::Children(a) => cmd_children(app, a).map(|_| 0),
        Command::Stale(a) => cmd_stale(app, a).map(|_| 0),
        Command::Orphans(a) => cmd_orphans(app, a).map(|_| 0),
        Command::Spec(c) => cmd_spec(app, c),
        Command::Graph(a) => cmd_graph(app, a).map(|_| 0),
        Command::Update(a) => write_cmd(app, "update", |tx| exec_update(tx, a)),
        Command::Close(a) => write_cmd(app, "close", |tx| {
            let mut out = exec_close(tx, a).map_err(|e| approval_link::note_close(tx, a, e))?;
            let closed = std::mem::take(&mut out.close_hint);
            if let Some(hint) = unlinked_note(tx, &closed)? {
                out = out.note(hint);
            }
            Ok(out)
        }),
        Command::Duplicate(a) => write_cmd(app, "duplicate", |tx| exec_duplicate(tx, a)),
        Command::Supersede(a) => write_cmd(app, "supersede", |tx| exec_supersede(tx, a)),
        Command::Reopen(a) => write_cmd(app, "reopen", |tx| exec_reopen(tx, a)),
        Command::Defer(a) => write_cmd(app, "defer", |tx| exec_defer(tx, a)),
        Command::Undefer(a) => write_cmd(app, "undefer", |tx| exec_undefer(tx, a)),
        Command::Delete(a) => write_cmd(app, "delete", |tx| exec_delete(tx, a)),
        Command::FindDuplicates(a) => cmd_find_duplicates(app, a).map(|_| 0),
        Command::Ready(a) => cmd_ready(app, a).map(|_| 0),
        Command::Blocked(a) => cmd_blocked(app, a).map(|_| 0),
        Command::Claim(a) => write_cmd(app, "claim", |tx| exec_claim(tx, a)),
        Command::Heartbeat(a) => write_cmd(app, "heartbeat", |tx| exec_heartbeat(tx, a)),
        Command::Release(a) => write_cmd(app, "release", |tx| exec_release(tx, a)),
        Command::Reclaim(a) => cmd_reclaim(app, a).map(|_| 0),
        Command::Leases(a) => cmd_leases(app, a).map(|_| 0),
        Command::Dep(c) => cmd_dep_read(app, c).map(|_| 0),
        Command::Label(LabelCommand::List(a)) => cmd_label_list(app, a).map(|_| 0),
        Command::Label(c) => write_cmd(app, "label", |tx| exec_label(tx, c)),
        Command::Comment(CommentCommand::Add(a)) => write_cmd(app, "comment", |tx| exec_comment_add(tx, a)),
        Command::Comment(CommentCommand::List(a)) | Command::Comments(a) => cmd_comments(app, &a.id).map(|_| 0),
        Command::Memory(MemoryCommand::Add(a)) | Command::Remember(a) => {
            write_cmd(app, "remember", |tx| exec_remember(tx, a))
        }
        Command::Memory(MemoryCommand::Get(k)) | Command::Recall(k) => cmd_memory_get(app, &k.key).map(|_| 0),
        Command::Memory(MemoryCommand::List(a)) | Command::Memories(a) => {
            cmd_memory_list(app, a.query.as_deref()).map(|_| 0)
        }
        Command::Memory(MemoryCommand::Rm(k)) | Command::Forget(k) => write_cmd(app, "forget", |tx| exec_forget(tx, k)),
        Command::Events(a) => cmd_events(app, a).map(|_| 0),
        Command::History(a) => cmd_history(app, a).map(|_| 0),
        Command::Prime(a) => match cmd_prime(app, a) {
            // Hooks run `bd prime` everywhere; outside a workspace it is silent.
            Err(Error::NoWorkspace(_)) => Ok(0),
            other => other.map(|_| 0),
        },
        Command::Hook(HookCommand::SessionStart(a)) => actor::cmd_session_start(app, a),
        Command::Hook(HookCommand::SubagentStart) => actor::cmd_subagent_start(app),
        Command::Hook(HookCommand::PreToolUse) => actor::cmd_pre_tool_use(app),
        Command::Setup(a) => setup::cmd_setup(app, a),
        Command::Stats => cmd_stats(app).map(|_| 0),
        Command::Metrics(a) => cmd_metrics(app, a).map(|_| 0),
        Command::Doctor(a) => cmd_doctor(app, a),
        Command::Config(c) => cmd_config_read(app, c).map(|_| 0),
        Command::RenamePrefix(a) => write_cmd(app, "rename-prefix", |tx| exec_rename_prefix(tx, a)),
        Command::Export(a) => cmd_export(app, a).map(|_| 0),
        Command::Import(a) => cmd_import(app, a).map(|_| 0),
        Command::Backup(a) => backup::cmd_backup(app, a).map(|_| 0),
        Command::Batch(a) => batch::cmd_batch(app, a).map(|_| 0),
        Command::Playbook(c) => playbooks::cmd_playbook(app, c).map(|_| 0),
        Command::Gate(GateCommand::Review(a)) => gate_review::cmd_review(app, None, a),
        Command::Gate(c) => gates::cmd_gate(app, c).map(|_| 0),
        Command::Github(c) => github::cmd_github(app, c),
        Command::Purge(a) => playbooks::cmd_purge(app, a).map(|_| 0),
        Command::Compact(a) => cmd_issue_compact(app, a).map(|_| 0),
        Command::Agents(c) => agents::cmd_agents(app, c).map(|_| 0),
        Command::Publish(a) => publish::cmd_publish(app, a),
        Command::Bench(_) | Command::BenchWorker(_) | Command::Serve(_) => match HANDLER.get() {
            Some(handle) => handle(app, cmd),
            None => Err(Error::invalid(format!("bd {} is not part of this build", command_name(cmd)))),
        },
        Command::Mcp(a) => mcp::cmd_mcp(app, a),
        Command::Remote(c) => remote::cmd_remote(app, c),
        Command::Info => cmd_info(app).map(|_| 0),
        Command::Completion(a) => cmd_completion(a),
        Command::Version => {
            if app.g.json {
                app.print_json(
                    &json!({ "version": env!("CARGO_PKG_VERSION"), "schema_version": bd_core::SCHEMA_VERSION }),
                );
            } else {
                io::outln(format!("bd {} (schema v{})", env!("CARGO_PKG_VERSION"), bd_core::SCHEMA_VERSION));
            }
            Ok(0)
        }
    }
}

/// `bd completion <shell>`: the completion script generated from [`Cli`]'s
/// grammar. It opens no store, so it works without a workspace.
fn cmd_completion(a: &cli::CompletionArgs) -> Result<i32> {
    use clap::CommandFactory;
    let mut buf = Vec::new();
    clap_complete::generate(a.shell.generator(), &mut Cli::command(), "bd", &mut buf);
    io::with_stdout(|w| w.write_all(&buf))?;
    Ok(0)
}

pub fn command_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::Init(_) => "init",
        Command::Create(_) => "create",
        Command::Quick(_) => "q",
        Command::Show(_) => "show",
        Command::List(_) => "list",
        Command::Query(_) => "query",
        Command::Epic(_) => "epic",
        Command::Children(_) => "children",
        Command::Stale(_) => "stale",
        Command::Orphans(_) => "orphans",
        Command::Spec(_) => "spec",
        Command::Graph(_) => "graph",
        Command::Update(_) => "update",
        Command::Edit(_) => "edit",
        Command::Close(_) => "close",
        Command::Duplicate(_) => "duplicate",
        Command::Supersede(_) => "supersede",
        Command::Reopen(_) => "reopen",
        Command::Defer(_) => "defer",
        Command::Undefer(_) => "undefer",
        Command::Delete(_) => "delete",
        Command::FindDuplicates(_) => "find-duplicates",
        Command::Ready(_) => "ready",
        Command::Blocked(_) => "blocked",
        Command::Claim(_) => "claim",
        Command::Heartbeat(_) => "heartbeat",
        Command::Release(_) => "release",
        Command::Reclaim(_) => "reclaim",
        Command::Leases(_) => "leases",
        Command::Dep(_) => "dep",
        Command::Label(_) => "label",
        Command::Comment(_) | Command::Comments(_) => "comment",
        Command::Memory(_) | Command::Remember(_) | Command::Recall(_) | Command::Memories(_) | Command::Forget(_) => {
            "memory"
        }
        Command::Events(_) => "events",
        Command::History(_) => "history",
        Command::Prime(_) => "prime",
        Command::Hook(_) => "hook",
        Command::Setup(_) => "setup",
        Command::Stats => "stats",
        Command::Metrics(_) => "metrics",
        Command::Doctor(_) => "doctor",
        Command::Config(_) => "config",
        Command::RenamePrefix(_) => "rename-prefix",
        Command::Export(_) => "export",
        Command::Import(_) => "import",
        Command::Backup(_) => "backup",
        Command::Batch(_) => "batch",
        Command::Playbook(_) => "playbook",
        Command::Gate(_) => "gate",
        Command::Github(_) => "github",
        Command::Purge(_) => "purge",
        Command::Compact(_) => "compact",
        Command::Agents(_) => "agents",
        Command::Publish(_) => "publish",
        Command::Bench(_) | Command::BenchWorker(_) => "bench",
        Command::Serve(_) => "serve",
        Command::Mcp(_) => "mcp",
        Command::Remote(_) => "remote",
        Command::Info => "info",
        Command::Version => "version",
        Command::Completion(_) => "completion",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_busy_database_suggests_raising_the_busy_timeout() {
        let db = render_error(&Error::Busy("timed out after 10s waiting for the write lock".into()), false, None);
        assert!(db.starts_with("error: database is busy: timed out") && db.contains("--busy-timeout-ms"), "{db}");
        let file = render_error(&Error::Locked("another bd process is changing server.db; retry".into()), false, None);
        assert_eq!(file, "error: another bd process is changing server.db; retry\n");
        let json: serde_json::Value =
            serde_json::from_str(&render_error(&Error::Locked("x".into()), true, None)).unwrap();
        assert_eq!((&json["error"]["code"], &json["error"]["exit_code"]), (&"busy".into(), &5.into()));
    }

    #[test]
    fn a_refusal_that_needs_a_person_names_the_keychain_login() {
        let e = Error::with_needs(&[bd_core::Need::Human], "resolving a human gate needs a person's access token");
        let text = render_error(&e, false, None);
        assert!(text.contains("hint: only a person (or an admin) may do this"), "{text}");
        assert!(text.contains("`bd remote login --human`"), "{text}");
        let plain = render_error(&Error::Unauthorized("x".into()), false, None);
        assert!(!plain.contains("--human"), "{plain}");
    }

    #[test]
    fn a_refusal_at_a_human_gate_names_it_and_its_approval_link() {
        let e = || Error::with_needs(&[bd_core::Need::Human], "msg").with_gate("t-1");
        let (_, c) = io::Capture::buffered(1024);
        let c = io::Capture { approvals: Some("https://x/bd/w/p/gates/".into()), ..c };
        let ((text, json), _) = io::capture(c, || (render_error(&e(), false, None), render_error(&e(), true, None)));
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines[0], "error: msg");
        assert_eq!(lines[1], "approve in a browser: https://x/bd/w/p/gates/t-1");
        assert!(lines[2].starts_with("hint: only a person"), "{text}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["error"]["gate"], "t-1");
        assert_eq!(v["error"]["approval_url"], "https://x/bd/w/p/gates/t-1");
        assert_eq!((&v["error"]["code"], &v["error"]["exit_code"]), (&"unauthorized".into(), &7.into()));

        // Outside bd serve: the gate, no link.
        let text = render_error(&e(), false, None);
        assert!(!text.contains("approve in a browser") && !text.contains("/gates/"), "{text}");
        let v: serde_json::Value = serde_json::from_str(&render_error(&e(), true, None)).unwrap();
        assert_eq!(v["error"]["gate"], "t-1");
        assert!(v["error"].get("approval_url").is_none(), "{v}");

        // A refusal naming no gate has neither key, even under bd serve.
        let (_, c) = io::Capture::buffered(1024);
        let c = io::Capture { approvals: Some("https://x/bd/w/p/gates/".into()), ..c };
        let plain = || Error::with_needs(&[bd_core::Need::Human], "msg");
        let ((text, json), _) =
            io::capture(c, || (render_error(&plain(), false, None), render_error(&plain(), true, None)));
        assert!(!text.contains("approve in a browser"), "{text}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["error"].get("gate").is_none() && v["error"].get("approval_url").is_none(), "{v}");
    }
}

#[cfg(test)]
mod operation_link_tests {
    //! The operation approval link a refused close or discard prints under
    //! `bd serve` (`io::note_operation`, `render_error`).
    use super::*;
    use crate::approval_link::{self, LinkKey, Op, Opened, OperationRequest};
    use bd_core::gates::{GateKind, GateSpec, NewGate};
    use bd_core::{NewIssue, Queries};
    use clap::Parser;

    const KEY: [u8; 32] = [7; 32];
    const BASE: &str = "https://x/bd/w/proj/";
    /// Who runs a command: an actor, and whether its token is a person's.
    type Who<'a> = (&'a str, bool);
    const AGENT: Who = ("agent-1", false);

    struct Ws {
        _dir: tempfile::TempDir,
        db: String,
        store: bd_core::Store,
    }

    impl Ws {
        fn new() -> Ws {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(".bd").join("bd.db");
            let init = bd_core::InitOptions { prefix: "t".into(), id_mode: bd_core::IdMode::Counter };
            let store = bd_core::Store::init(&path, init, bd_core::OpenOptions::default()).unwrap();
            Ws { db: path.to_str().unwrap().to_string(), _dir: dir, store }
        }

        fn create(&mut self, new: NewIssue) -> String {
            self.store.write("setup", "alice", |tx| tx.create_issue(new)).unwrap().id
        }

        fn gate(&mut self, blocks: &str, parent: Option<&str>, approvers: Option<Vec<String>>) -> String {
            let gate = NewGate {
                spec: GateSpec { approvers, ..GateSpec::new(GateKind::Human) },
                blocks: vec![blocks.to_string()],
                title: None,
                description: String::new(),
                assignee: None,
                parent: parent.map(str::to_string),
                priority: None,
                ephemeral: false,
            };
            self.store.write("setup", "alice", |tx| tx.create_gate(gate)).unwrap().id
        }

        /// A task held by a human gate anyone human may open.
        fn held(&mut self) -> (String, String) {
            let work = self.create(NewIssue::titled("Deploy"));
            let gate = self.gate(&work, None, None);
            (work, gate)
        }

        /// A playbook run holding a human gate over its one step.
        fn run_with_gate(&mut self) -> (String, String) {
            let run = self.create(NewIssue {
                issue_type: Some("epic".into()),
                metadata: Some(json!({ "playbook": { "role": "run" } })),
                ..NewIssue::titled("Run")
            });
            let step = self.create(NewIssue { parent: Some(run.clone()), ..NewIssue::titled("Step") });
            let gate = self.gate(&step, Some(&run), None);
            (run, gate)
        }

        /// `args` as `who` (actor, a person's token) under bd serve, offering
        /// links when `links`: the exit code and stderr.
        fn run(&self, who: Who, links: bool, args: &[&str], stdin: Option<&str>) -> (i32, String) {
            let line = ["bd", "--db", &self.db, "--actor", who.0].into_iter().chain(args.iter().copied());
            let cli = Cli::try_parse_from(line).unwrap();
            let mut app = App::new(cli.global).unwrap();
            let (_, c) = io::Capture::buffered(1 << 20);
            let c = io::Capture {
                token_actor: who.0.into(),
                human: who.1,
                stdin: stdin.map(str::to_string),
                approvals: Some(format!("{BASE}gates/")),
                operation_links: links.then(|| io::OperationLinks {
                    base: BASE.into(),
                    workspace: "proj".into(),
                    key: std::sync::Arc::new(LinkKey::from_bytes(&KEY).unwrap()),
                }),
                ..c
            };
            let (code, c) = io::capture(c, || execute(&mut app, &cli.command));
            (code, String::from_utf8(c.stderr).unwrap())
        }
    }

    /// The request a link's `request=` value opens to, for `op` of `issue`.
    fn opened(url: &str, op: Op, issue: &str) -> OperationRequest {
        let prefix = format!("{BASE}{op}/{issue}?request=");
        let sealed = url.strip_prefix(&prefix).unwrap_or_else(|| panic!("{url} does not start with {prefix}"));
        let key = LinkKey::from_bytes(&KEY).unwrap();
        match approval_link::open(&key, sealed, "proj", op, issue, 0) {
            Opened::Valid(req) => *req,
            other => panic!("{other:?}"),
        }
    }

    fn op_line<'a>(stderr: &'a str, op: Op, issue: &str) -> &'a str {
        let start = format!("approve {} {issue} in a browser: ", op.phrase());
        stderr
            .lines()
            .find_map(|l| l.strip_prefix(start.as_str()))
            .unwrap_or_else(|| panic!("no operation line in {stderr}"))
    }

    fn no_op_line(stderr: &str) {
        assert!(
            !stderr.contains("in a browser: https://x/bd/w/proj/close/")
                && !stderr.contains("/discard/")
                && !stderr.contains("no browser approval link"),
            "{stderr}"
        );
    }

    #[test]
    fn a_forced_close_held_at_a_human_gate_prints_its_link() {
        let mut ws = Ws::new();
        let (work, gate) = ws.held();
        let (code, stderr) = ws.run(AGENT, true, &["close", &work, "--force", "-r", "why"], None);
        assert_eq!(code, 7, "{stderr}");
        let lines: Vec<_> = stderr.lines().collect();
        assert!(lines[0].starts_with("error: "), "{stderr}");
        assert_eq!(lines[1], format!("approve in a browser: {BASE}gates/{gate}"));
        assert!(
            lines[2].starts_with(&format!("approve the close of {work} in a browser: {BASE}close/{work}?request="))
        );
        assert!(lines[3].starts_with("hint: "), "{stderr}");
        let req = opened(op_line(&stderr, Op::Close, &work), Op::Close, &work);
        assert_eq!((req.workspace.as_str(), req.issue.as_str(), req.requester.as_str()), ("proj", &*work, "agent-1"));
        assert_eq!((req.reason.as_deref(), req.failed, req.force), (Some("why"), false, true));
        assert_eq!(req.until - req.at, approval_link::TTL);

        // The reason as given, whitespace and all; a blank one is none. --failed is carried.
        let (_, stderr) = ws.run(AGENT, true, &["close", &work, "--force", "--failed", "-r", "  why\n"], None);
        let req = opened(op_line(&stderr, Op::Close, &work), Op::Close, &work);
        assert_eq!((req.reason.as_deref(), req.failed), (Some("  why\n"), true));
        let (_, stderr) = ws.run(AGENT, true, &["close", &work, "--force", "-r", "   "], None);
        assert_eq!(opened(op_line(&stderr, Op::Close, &work), Op::Close, &work).reason, None);

        // --json carries the link.
        let (_, stderr) = ws.run(AGENT, true, &["--json", "close", &work, "--force", "-r", "why"], None);
        let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(v["error"]["gate"], json!(gate));
        let url = v["error"]["operation_approval_url"].as_str().unwrap();
        assert_eq!(opened(url, Op::Close, &work).reason.as_deref(), Some("why"));
        assert_eq!(ws.store.read(|r| r.issue(&work)).unwrap().status, bd_core::Status::Open, "nothing written");
    }

    #[test]
    fn without_links_a_refusal_prints_what_it_did_before() {
        let mut ws = Ws::new();
        let (work, _) = ws.held();
        let args = ["close", work.as_str(), "--force", "-r", "why"];
        let (with, without) = (ws.run(AGENT, true, &args, None).1, ws.run(AGENT, false, &args, None).1);
        let op = with.lines().find(|l| l.starts_with("approve the close of")).unwrap();
        assert_eq!(without, with.replace(&format!("{op}\n"), ""));
        let json = ["--json", "close", work.as_str(), "--force"];
        let v: serde_json::Value = serde_json::from_str(ws.run(AGENT, false, &json, None).1.trim()).unwrap();
        assert!(v["error"].get("operation_approval_url").is_none() && v["error"]["gate"].is_string(), "{v}");

        // Outside bd serve nothing is noted, and a marked error renders as the unmarked one.
        io::note_operation(Op::Close, "t-1", Some("why"), false, true, "agent-1", 0);
        assert_eq!(io::operation_link(), None);
        let e = || Error::with_needs(&[bd_core::Need::Human], "held").with_gate("t-1");
        assert_eq!(render_error(&e().approvable(), false, None), render_error(&e(), false, None));
        assert_eq!(render_error(&e().approvable(), true, None), render_error(&e(), true, None));
    }

    #[test]
    fn only_a_single_forced_close_or_a_discard_gets_a_link() {
        let mut ws = Ws::new();
        let (work, gate) = ws.held();
        let (other, _) = ws.held();
        // A gate held by a gate only carol may open: alice may open the first, not the second.
        let target = ws.create(NewIssue::titled("Target"));
        let gate_a = ws.gate(&target, None, None);
        ws.gate(&gate_a, None, Some(vec!["github:carol".into()]));
        let claimed = ws.create(NewIssue::titled("Claimed"));
        ws.gate(&claimed, None, None);
        let opts = bd_core::claims::ClaimOptions { allow_blocked: true, ..Default::default() };
        ws.store.write("claim", "bob", |tx| tx.claim(&claimed, &opts)).unwrap();

        let refused: [(&str, Who, Vec<&str>, i32); 6] = [
            ("take-over", AGENT, vec!["close", &work, "--force", "--take-over"], 7),
            ("two ids", AGENT, vec!["close", &work, &other, "--force"], 7),
            ("no force", AGENT, vec!["close", &work], 2),
            ("the gate itself", AGENT, vec!["close", &gate, "--force"], 7),
            ("a gate held by a gate", ("alice", true), vec!["close", &gate_a, "--force"], 7),
            ("a claim", AGENT, vec!["close", &claimed, "--force"], 7),
        ];
        for (what, who, args, exit) in refused {
            let (code, stderr) = ws.run(who, true, &args, None);
            assert_eq!(code, exit, "{what}: {stderr}");
            assert!(what != "a claim" || stderr.contains("claimed by bob"), "{stderr}");
            no_op_line(&stderr);
        }
        let (code, stderr) = ws.run(AGENT, true, &["batch"], Some(&format!("close {work} --force\n")));
        assert_eq!(code, 7, "{stderr}");
        no_op_line(&stderr);
        for id in [&work, &other, &gate, &gate_a, &claimed] {
            assert_ne!(ws.store.read(|r| r.issue(id)).unwrap().status, bd_core::Status::Closed, "{id}");
        }
    }

    #[test]
    fn a_reason_over_2000_bytes_gets_no_link_and_says_why() {
        let mut ws = Ws::new();
        let (work, _) = ws.held();
        let long = "x".repeat(approval_link::MAX_REASON + 1);
        let (_, stderr) = ws.run(AGENT, true, &["close", &work, "--force", "-r", &long], None);
        let why = format!("no browser approval link for the close of {work}: the reason is longer than 2000 bytes");
        assert!(stderr.lines().any(|l| l == why), "{stderr}");
        assert!(!stderr.contains("/close/"), "{stderr}");
        let (_, stderr) = ws.run(AGENT, true, &["--json", "close", &work, "--force", "-r", &long], None);
        let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
        assert!(v["error"].get("operation_approval_url").is_none(), "{v}");

        for fill in ["\"", "\u{1}\n\t"] {
            let reason: String = fill.chars().cycle().take(approval_link::MAX_REASON).collect();
            assert_eq!(reason.len(), approval_link::MAX_REASON);
            let (_, stderr) = ws.run(AGENT, true, &["--json", "close", &work, "--force", "-r", &reason], None);
            let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
            let url = v["error"]["operation_approval_url"].as_str().unwrap();
            assert_eq!(opened(url, Op::Close, &work).reason.as_deref(), Some(reason.as_str()));
        }
    }

    #[test]
    fn a_discard_held_at_a_human_gate_prints_its_link() {
        let mut ws = Ws::new();
        let (run, _) = ws.run_with_gate();
        let (code, stderr) = ws.run(AGENT, true, &["playbook", "discard", &run, "-r", "  cleanup "], None);
        assert_eq!(code, 7, "{stderr}");
        let req = opened(op_line(&stderr, Op::Discard, &run), Op::Discard, &run);
        assert_eq!((req.reason.as_deref(), req.failed, req.force), (Some("  cleanup "), false, false));
        let (_, stderr) = ws.run(AGENT, true, &["playbook", "discard", &run, "--force"], None);
        assert!(opened(op_line(&stderr, Op::Discard, &run), Op::Discard, &run).force);
        for flag in ["--dry-run", "--take-over"] {
            let (code, stderr) = ws.run(AGENT, true, &["playbook", "discard", &run, flag], None);
            assert_ne!(code, 0, "{flag}: {stderr}");
            no_op_line(&stderr);
        }
        assert!(ws.store.read(|r| r.issue(&run)).is_ok(), "nothing deleted");
    }

    #[test]
    fn discard_records_its_reason_in_each_deleted_event() {
        let mut ws = Ws::new();
        let run = ws.create(NewIssue {
            issue_type: Some("epic".into()),
            metadata: Some(json!({ "playbook": { "role": "run" } })),
            ..NewIssue::titled("Run")
        });
        let step = ws.create(NewIssue { parent: Some(run.clone()), ..NewIssue::titled("Step") });
        let cli = Cli::try_parse_from([
            "bd",
            "--db",
            &ws.db,
            "-q",
            "playbook",
            "discard",
            &run,
            "-r",
            "  started by mistake\n",
        ])
        .unwrap();
        let Command::Playbook(cli::PlaybookCommand::Discard(a)) = &cli.command else { panic!("{:?}", cli.command) };
        assert_eq!(a.reason.as_deref(), Some("  started by mistake\n"));
        let mut app = App::new(cli.global).unwrap();
        assert_eq!(dispatch(&mut app, &cli.command).unwrap(), 0);
        let q = bd_core::EventQuery { ops: vec!["deleted".into()], ..Default::default() };
        let events = ws.store.read(|r| r.events(&q)).unwrap().events;
        let ids: Vec<_> = events.iter().filter_map(|e| e.issue_id.clone()).collect();
        assert!(ids.contains(&run) && ids.contains(&step), "{ids:?}");
        assert!(events.iter().all(|e| e.data["reason"] == "  started by mistake\n"), "{events:?}");
    }
}
