mod app;
mod auth;
mod batch;
mod bench;
mod cli;
mod commands;
mod credentials;
mod fmt;
mod gates;
mod io;
mod jobs;
mod logging;
mod paths;
mod playbooks;
mod protocol;
mod remote;
mod serve;

use bd_core::{Error, Result};
use clap::Parser;
use serde_json::json;

use crate::app::App;
use crate::cli::{Cli, Command, CommentCommand, LabelCommand, MemoryCommand};
use crate::commands::*;

fn main() {
    let cli = Cli::parse();
    // A server logs one line per request unless BD_LOG says otherwise.
    let default_filter = if matches!(cli.command, Command::Serve(_)) { "warn,bd::serve=info" } else { "warn" };
    logging::init(cli.global.log_format, default_filter);
    std::process::exit(run(cli));
}

fn run(cli: Cli) -> i32 {
    let json = cli.global.json;
    let mut app = match App::new(cli.global.clone()) {
        Ok(app) => app,
        Err(e) => return report(&e, json),
    };
    if !always_local(&cli.command) {
        match remote::detect(&app) {
            Ok(Some(r)) => return remote::run(&mut app, r, &cli),
            Ok(None) => {}
            // `bd prime` from a session hook: report the problem as context, never fail the hook.
            Err(e) if remote::is_hook(&cli) => return remote::unavailable(&e),
            Err(e) => return report(&e, json),
        }
    }
    execute(&mut app, &cli.command)
}

/// Commands that never use a remote workspace.
fn always_local(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Serve(_) | Command::Remote(_) | Command::Version | Command::Bench(_) | Command::BenchWorker(_)
    )
}

/// Run one command and return its exit code: locally, and for each request
/// under `bd serve` (with output captured by [`io::capture`]).
fn execute(app: &mut App, cmd: &Command) -> i32 {
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
            Command::Events(_) | Command::Bench(_) | Command::BenchWorker(_) | Command::Serve(_) | Command::Remote(_)
        )
    {
        tracing::warn!(target: "bd::slow", command = name, total_ms, "slow command");
    }
    tracing::debug!(target: "bd::cli", command = name, total_us = elapsed.as_micros() as u64, ok = result.is_ok(), "done");
    match result {
        Ok(code) => code,
        Err(e) => report(&e, app.g.json),
    }
}

/// The lines `report` prints for an error.
fn render_error(e: &Error, json: bool) -> String {
    if json {
        return format!(
            "{}\n",
            json!({ "error": { "code": e.code(), "message": e.to_string(), "exit_code": e.exit_code() } })
        );
    }
    let mut s = format!("error: {e}\n");
    if let Some(h) = hint(e) {
        s.push_str(&format!("hint: {h}\n"));
    }
    s
}

/// Print an error on stderr and return its exit code.
fn report(e: &Error, json: bool) -> i32 {
    io::errln(render_error(e, json).trim_end_matches('\n'));
    e.exit_code()
}

fn hint(e: &Error) -> Option<&'static str> {
    Some(match e {
        Error::AlreadyClaimed { .. } => {
            "pick other work with `bd claim --next`; if the holder is gone, wait for `bd reclaim` or take over with `bd update <id> --assignee <you> --force`"
        }
        Error::NotReady { .. } => "see `bd show <id>` for blockers; `bd claim <id> --allow-blocked` overrides",
        Error::Conflict { .. } => {
            "another actor changed it first; re-read (`bd show <id> --json`) and retry with the new revision"
        }
        Error::LeaseLost { .. } => "stop working on it: the claim was released, reclaimed, or taken over",
        Error::NotOwner { .. } => "only the holder releases a claim; use --force for abandoned work",
        Error::Busy(_) => "another process holds the write lock; retry, or raise --busy-timeout-ms",
        Error::EventsTruncated { .. } => "re-baseline with `bd export` and tail from its head_seq",
        Error::NoWorkspace(_) => "create one with `bd init`",
        Error::Unauthorized(_) => {
            "check the access token (BD_TOKEN, or `bd remote login`), and its role, workspaces and actor (`bd remote show`; `bd serve token list` on the server)"
        }
        Error::Remote(_) => {
            "`bd remote show` checks the URL, certificate and connection; retrying is safe (a write is applied once)"
        }
        _ => return None,
    })
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

fn dispatch(app: &mut App, cmd: &Command) -> Result<i32> {
    match cmd {
        Command::Init(a) => cmd_init(app, a).map(|_| 0),
        Command::Create(a) => write_cmd(app, "create", |tx| exec_create(tx, a)),
        Command::Show(a) => cmd_show(app, a).map(|_| 0),
        Command::List(a) => cmd_list(app, a).map(|_| 0),
        Command::Update(a) => write_cmd(app, "update", |tx| exec_update(tx, a)),
        Command::Close(a) => write_cmd(app, "close", |tx| exec_close(tx, a)),
        Command::Reopen(a) => write_cmd(app, "reopen", |tx| exec_reopen(tx, a)),
        Command::Defer(a) => write_cmd(app, "defer", |tx| exec_defer(tx, a)),
        Command::Undefer(a) => write_cmd(app, "undefer", |tx| exec_undefer(tx, a)),
        Command::Delete(a) => write_cmd(app, "delete", |tx| exec_delete(tx, a)),
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
        Command::Stats => cmd_stats(app).map(|_| 0),
        Command::Metrics(a) => cmd_metrics(app, a).map(|_| 0),
        Command::Doctor(a) => cmd_doctor(app, a),
        Command::Config(c) => cmd_config_read(app, c).map(|_| 0),
        Command::Export(a) => cmd_export(app, a).map(|_| 0),
        Command::Import(a) => cmd_import(app, a).map(|_| 0),
        Command::Batch(a) => batch::cmd_batch(app, a).map(|_| 0),
        Command::Playbook(c) => playbooks::cmd_playbook(app, c).map(|_| 0),
        Command::Gate(c) => gates::cmd_gate(app, c).map(|_| 0),
        Command::Purge(a) => playbooks::cmd_purge(app, a).map(|_| 0),
        Command::Bench(a) => bench::cmd_bench(app, a).map(|_| 0),
        Command::BenchWorker(a) => bench::cmd_bench_worker(a).map(|_| 0),
        Command::Serve(a) => serve::cmd_serve(app, a).map(|_| 0),
        Command::Remote(c) => remote::cmd_remote(app, c),
        Command::Info => cmd_info(app).map(|_| 0),
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

fn command_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::Init(_) => "init",
        Command::Create(_) => "create",
        Command::Show(_) => "show",
        Command::List(_) => "list",
        Command::Update(_) => "update",
        Command::Close(_) => "close",
        Command::Reopen(_) => "reopen",
        Command::Defer(_) => "defer",
        Command::Undefer(_) => "undefer",
        Command::Delete(_) => "delete",
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
        Command::Stats => "stats",
        Command::Metrics(_) => "metrics",
        Command::Doctor(_) => "doctor",
        Command::Config(_) => "config",
        Command::Export(_) => "export",
        Command::Import(_) => "import",
        Command::Batch(_) => "batch",
        Command::Playbook(_) => "playbook",
        Command::Gate(_) => "gate",
        Command::Purge(_) => "purge",
        Command::Bench(_) | Command::BenchWorker(_) => "bench",
        Command::Serve(_) => "serve",
        Command::Remote(_) => "remote",
        Command::Info => "info",
        Command::Version => "version",
    }
}
