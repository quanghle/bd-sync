//! `bd playbook ...` and `bd purge`.
//!
//! In a remote workspace a name is looked up in the checkout's
//! `.bd/playbooks` first, then among the server's playbooks approved on this
//! machine (`.bd/approved/playbooks`, kept by `bd agents approve`:
//! [`crate::agents::approved`]), then in the client's `$BD_PLAYBOOK_PATH`
//! and user config directory; file paths are the client's. `show`, `plan`
//! and `run` always send the files they load with the command (a bundle,
//! named by `--playbook-bundle`), checked against the approvals first, and
//! the server loads it from the bundle alone: it compiles exactly the bytes
//! approved here, never its own copy. A name found nowhere here fails, saying
//! that the server's playbooks are used once approved. `list` shows all of
//! them and names the server's playbooks waiting for approval, and `extract
//! --save` writes into the checkout. `bd prime` lists them too: the client
//! sends the names and descriptions of its own and of those approved, and
//! the paths of those waiting (`--client-playbooks`), which the server lists
//! in place of its own.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bd_core::playbook::{
    self, Bundle, CompactOptions, DiscardOptions, Listed, Loader, MAX_BUNDLE_FILE_BYTES, Playbook, RunRequest,
    RunStatus, RunsQuery, StartOptions, Step, StepState,
};
use bd_core::time::parse_duration;
use bd_core::{Error, Queries, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::agents::checkout::Checkout;
use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::rel;
use crate::io;
use crate::paths::user_config_dir;
use crate::protocol::{ErrorBody, ExecRequest, ExecResponse};
use crate::remote::{self, Remote};

/// Where playbooks are looked up, in order: the workspace's `.bd/playbooks`,
/// `$BD_PLAYBOOK_PATH`, then `$XDG_CONFIG_HOME/bd/playbooks` (or
/// `~/.config/bd/playbooks`; `%APPDATA%\bd\playbooks` on Windows).
pub fn search_paths(app: &App) -> Vec<PathBuf> {
    match app.db_path() {
        Ok(db) => with_user_paths(db.parent().map(|d| d.join("playbooks"))),
        Err(_) => with_user_paths(Some(app.cwd.join(".bd").join("playbooks"))),
    }
}

/// `first`, then `$BD_PLAYBOOK_PATH` and the user config directory.
fn with_user_paths(first: Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = first.into_iter().collect();
    if let Some(extra) = std::env::var_os("BD_PLAYBOOK_PATH") {
        paths.extend(std::env::split_paths(&extra).filter(|p| !p.as_os_str().is_empty()));
    }
    if let Some(c) = user_config_dir() {
        paths.push(c.join("bd").join("playbooks"));
    }
    paths
}

/// The playbooks a command reads: the bundle named by `--playbook-bundle`
/// (sent by a remote client; under bd serve it is never read from disk), or
/// the search path.
fn loader(app: &App) -> Result<Loader> {
    let Some(file) = &app.g.playbook_bundle else { return Ok(disk_loader(search_paths(app))) };
    let bundle = Bundle::from_json(&io::read_file(file)?)?;
    // `server_first` (set by clients that predate approving the server's
    // playbooks) is ignored: the server's own copy never takes the place of
    // a bundle a client sent, which holds what was approved there.
    Loader::from_bundle(bundle)
}

/// A loader of the playbook files on `paths`: under bd serve held to them
/// ([`Loader::contained`]), so a playbook the server loads for a client
/// cannot extend or expand files elsewhere on the server.
fn disk_loader(paths: Vec<PathBuf>) -> Loader {
    let loader = Loader::new(paths);
    if io::serving() { loader.contained() } else { loader }
}

/// Under bd serve without a bundle, playbooks come from the server's own playbook path.
fn on_server(loader: &Loader) -> bool {
    io::serving() && !loader.is_bundle()
}

fn load(app: &App, loader: &Loader, reference: &str) -> Result<Playbook> {
    let r = reference.trim();
    let on_server = on_server(loader);
    if on_server && playbook::is_path_like(r) {
        // A path would name a file on the server, not the client's.
        return Err(Error::Refused(format!(
            "playbook {r:?}: bd serve runs playbooks by name from the workspace's playbook directory on the server \
             (a bd client sends the playbooks of its checkout with the command)"
        )));
    }
    loader.load_from(reference, Some(&app.cwd)).map_err(|e| match e {
        Error::NotFound { kind, id } if on_server => {
            Error::NotFound { kind, id: format!("{id} on the bd server (bd clients look in their checkout first)") }
        }
        e => e,
    })
}

fn parse_vars(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut vars = BTreeMap::new();
    for v in raw {
        let (k, val) =
            v.split_once('=').ok_or_else(|| Error::invalid(format!("--var expects NAME=VALUE, got {v:?}")))?;
        let k = k.trim();
        if vars.insert(k.to_string(), val.to_string()).is_some() {
            return Err(Error::invalid(format!("--var {k} given twice")));
        }
    }
    Ok(vars)
}

pub fn cmd_playbook(app: &mut App, cmd: &PlaybookCommand) -> Result<()> {
    match cmd {
        PlaybookCommand::List => cmd_list(app),
        PlaybookCommand::Show(a) => cmd_show(app, a),
        PlaybookCommand::Plan(a) => cmd_run(app, a, true),
        PlaybookCommand::Run(a) => cmd_run(app, a, a.dry_run),
        PlaybookCommand::Status(a) => cmd_status(app, a),
        PlaybookCommand::Runs(a) => cmd_runs(app, a),
        PlaybookCommand::Compact(a) => cmd_compact(app, a),
        PlaybookCommand::Discard(a) => cmd_discard(app, a),
        PlaybookCommand::Extract(a) => cmd_extract(app, a),
    }
}

fn cmd_list(app: &mut App) -> Result<()> {
    let loader = disk_loader(search_paths(app));
    let listed = loader.list();
    let json = json!({ "search_paths": loader.search_paths, "playbooks": listed });
    let entries: Vec<(Listed, bool)> = listed.into_iter().map(|l| (l, false)).collect();
    let searched: Vec<(PathBuf, bool)> = loader.search_paths.iter().map(|p| (p.clone(), false)).collect();
    app.print(list_out(json, &entries, &searched));
    Ok(())
}

/// What `bd playbook list` prints. Entries and searched directories marked
/// `true` are the server's playbooks approved here.
fn list_out(json: Value, entries: &[(Listed, bool)], searched: &[(PathBuf, bool)]) -> Out {
    let mut out = Out::new(json);
    if entries.is_empty() {
        out = out.line("No playbooks found. Searched:");
        for (p, from_server) in searched {
            out = out.line(format!(
                "  {}{}",
                p.display(),
                if *from_server { " (the bd server's, approved on this machine)" } else { "" }
            ));
        }
        out = out.line("Create one at .bd/playbooks/<name>.toml (see `bd playbook show <file>` to validate it).");
    }
    for (l, from_server) in entries {
        let place = if *from_server { " (the bd server's, approved here)" } else { "" };
        let mut line = format!("{:<20} {}{place}", l.name, l.path.display());
        if let Some(e) = &l.error {
            line = format!("✗ {line}\n    {}", e.replace('\n', "\n    "));
        } else {
            let vars = if l.vars.is_empty() { String::new() } else { format!("  vars: {}", l.vars.join(" ")) };
            let eph = if l.ephemeral { "  (ephemeral)" } else { "" };
            line = format!(
                "• {line}\n    {} step(s){vars}{eph}{}",
                l.steps,
                if l.description.is_empty() { String::new() } else { format!(" — {}", l.description) }
            );
        }
        if let Some(by) = &l.shadowed_by {
            line.push_str(&format!("\n    shadowed by {}", by.display()));
        }
        out = out.line(line).id(l.name.clone());
    }
    out
}

// ------------------------------------------------------------- bd prime

/// Where a playbook `bd prime` lists lives, in lookup order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Location {
    /// The workspace's `.bd/playbooks` (the checkout's, in a remote workspace).
    Checkout,
    /// The playbook path of a remote workspace's server.
    Server,
    /// A remote workspace's server's playbook, approved on the client's machine.
    Approved,
    /// `$BD_PLAYBOOK_PATH` and the user config directory.
    User,
}

/// What a client of today sends for `bd prime` (`--client-playbooks`): its
/// playbooks in lookup order (the checkout's, those approved, the user's),
/// which the server lists in place of its own, and the SHA-256 of each of
/// the server's playbook files approved on its machine, from which the
/// server names those waiting for approval there (in the same request, so
/// a session hook's prime makes one). A server that predates it reads no
/// listing from it, and lists its own; a client that predates it sends a
/// bare array of [`Summary`], read as before.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Listing {
    pub playbooks: Vec<Summary>,
    /// By path in the server's playbook directory. `None`: the client could
    /// not tell (an unusable `.bd/agents.lock`).
    #[serde(default)]
    pub approved: Option<BTreeMap<String, String>>,
}

/// What `bd prime` lists of the playbooks.
#[derive(Clone, Debug, Default)]
pub struct ForPrime {
    pub playbooks: Vec<Summary>,
    /// The server's playbooks waiting for approval on the client's machine, as it sent them.
    pub pending: Vec<crate::agents::approved::PendingPlaybook>,
}

/// A playbook as `bd prime` lists it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub name: String,
    /// The description's first line, cut short.
    #[serde(default)]
    pub description: String,
    pub location: Location,
    /// The file does not parse or validate.
    #[serde(default)]
    pub invalid: bool,
}

/// How many characters of a description `bd prime` shows.
const SUMMARY_CHARS: usize = 100;

impl Summary {
    fn of(l: &Listed, location: Location) -> Summary {
        Summary { name: l.name.clone(), description: l.description.clone(), location, invalid: l.error.is_some() }
            .tidy()
    }

    /// The description cut to one short line, and hidden characters escaped.
    /// Tidying again changes nothing (a server tidies what a client sends).
    fn tidy(self) -> Summary {
        let mut lines = self.description.trim().lines();
        let first = crate::agents::show::printable(lines.next().unwrap_or_default().trim());
        let mut description: String = first.chars().take(SUMMARY_CHARS).collect();
        if lines.next().is_some() || first.chars().count() > SUMMARY_CHARS {
            description = format!("{}…", description.trim_end());
        }
        Summary { name: crate::agents::show::printable(&self.name), description, ..self }
    }
}

/// The playbooks `bd prime` lists, in lookup order, each name once (the one
/// a command naming it loads). `client` names the listing a remote client
/// sent: of today ([`Listing`]), its playbooks, which are all it can run,
/// listed in place of the server's own, with those waiting for approval; or,
/// from a client that predates it, of its checkout's and its user's
/// playbooks, which go before and after the server's own. A listing that
/// cannot be read is left out.
pub fn for_prime(app: &App, client: Option<&Path>) -> ForPrime {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Sent {
        Listing(Listing),
        Old(Vec<Summary>),
    }
    let client: Option<Sent> = client.and_then(|file| {
        let listing = io::read_file(file).and_then(|text| {
            serde_json::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", file.display())))
        });
        listing.map_err(|e| tracing::debug!(target: "bd::cli", error = %e, "client playbooks left out")).ok()
    });
    let client = match client {
        Some(Sent::Listing(listing)) => {
            let mut seen = std::collections::HashSet::new();
            let playbooks = listing
                .playbooks
                .into_iter()
                .map(Summary::tidy)
                .filter(|s| s.location != Location::Server && seen.insert(s.name.clone()))
                .collect();
            let pending = listing.approved.map(|a| pending_against(app, &a)).unwrap_or_default();
            return ForPrime { playbooks, pending };
        }
        Some(Sent::Old(old)) => Some(old),
        None => None,
    };
    let paths = search_paths(app);
    let remote = client.is_some() || io::serving();
    let own = disk_loader(paths.clone()).list().into_iter().map(|l| {
        let location = if remote {
            Location::Server
        } else if l.path.parent() == paths.first().map(PathBuf::as_path) {
            Location::Checkout
        } else {
            Location::User
        };
        Summary::of(&l, location)
    });
    let (before, after): (Vec<Summary>, Vec<Summary>) =
        client.unwrap_or_default().into_iter().partition(|s| s.location != Location::User);
    let before = before.into_iter().map(|s| Summary { location: Location::Checkout, ..s.tidy() });
    let after = after.into_iter().map(Summary::tidy);
    let mut seen = std::collections::HashSet::new();
    let playbooks = before.chain(own).chain(after).filter(|s| seen.insert(s.name.clone())).collect();
    ForPrime { playbooks, pending: Vec::new() }
}

/// The workspace's playbooks a client that approved those of `approved`
/// (path to SHA-256) has yet to approve: none if they cannot be read.
fn pending_against(app: &App, approved: &BTreeMap<String, String>) -> Vec<crate::agents::approved::PendingPlaybook> {
    use crate::agents::approved::{PendingPlaybook, PlaybookChange};
    let set = crate::agents::playbooks_dir(app).and_then(|dir| bd_core::agents::PlaybookSet::load(&dir));
    let set = match set {
        Ok(set) => set,
        Err(e) => {
            tracing::debug!(target: "bd::cli", error = %e, "playbooks waiting for approval unknown");
            return Vec::new();
        }
    };
    set.files
        .into_iter()
        .filter_map(|(path, file)| match approved.get(&path) {
            None => Some(PendingPlaybook { path, change: PlaybookChange::New }),
            Some(sha) if *sha != file.sha256 => Some(PendingPlaybook { path, change: PlaybookChange::Changed }),
            Some(_) => None,
        })
        .collect()
}

fn step_lines(steps: &[Arc<Step>], depth: usize, out: &mut Vec<String>) {
    for s in steps {
        let mut notes = Vec::new();
        if !s.needs.is_empty() {
            notes.push(format!("needs {}", s.needs.join(", ")));
        }
        if let Some(w) = &s.waits_for {
            notes.push(format!("waits for {}", w.as_spec()));
        }
        if let Some(c) = &s.condition {
            notes.push(format!("if {c}"));
        }
        if let Some(l) = &s.repeat {
            let over = match &l.over {
                playbook::LoopOver::Count(c) => format!("count {c}"),
                playbook::LoopOver::Range(r) => format!("range {r}"),
                playbook::LoopOver::Items(i) => format!("items {}", i.join(", ")),
                playbook::LoopOver::Over(o) => format!("over {o}"),
            };
            notes.push(format!("loop {} = {over}{}", l.var, if l.sequential { ", one at a time" } else { "" }));
        }
        if let Some(e) = &s.expand {
            notes.push(format!("expands {e}"));
        }
        if let Some(g) = &s.gate {
            let mut gate = format!("gate {}", g.kind);
            if let Some(a) = &g.await_id {
                gate.push_str(&format!(" {a}"));
            }
            if let Some(b) = &g.branch {
                gate.push_str(&format!(" on {b}"));
            }
            if let Some(e) = &g.event {
                gate.push_str(&format!(" for {e}"));
            }
            if let Some(t) = &g.timeout {
                gate.push_str(&format!(" ({t})"));
            }
            notes.push(gate);
        }
        let kind = match &s.issue_type {
            Some(t) => format!(" [{t}]"),
            None if s.is_group() => " [group]".into(),
            None => String::new(),
        };
        let notes = if notes.is_empty() { String::new() } else { format!("  · {}", notes.join(" · ")) };
        out.push(format!("{}{}{kind} — {}{notes}", "  ".repeat(depth + 1), s.id, s.title));
        step_lines(&s.children, depth + 1, out);
    }
}

fn cmd_show(app: &mut App, a: &PlaybookRefArgs) -> Result<()> {
    let loader = loader(app)?;
    let pb = load(app, &loader, &a.playbook)?;
    let server = on_server(&loader);
    let mut text = vec![format!(
        "{}{}{}",
        pb.name,
        if pb.description.is_empty() { String::new() } else { format!(" — {}", pb.description) },
        pb.source
            .as_ref()
            .map(|p| format!("  ({}{})", p.display(), if server { " on the server" } else { "" }))
            .unwrap_or_default()
    )];
    let mut facts = Vec::new();
    if pb.is_ephemeral() {
        facts.push("ephemeral runs".to_string());
    }
    if !pb.extends.is_empty() {
        facts.push(format!("extends {}", pb.extends.join(", ")));
    }
    if let Some(t) = &pb.title {
        facts.push(format!("run title \"{t}\""));
    }
    if !facts.is_empty() {
        text.push(format!("  {}", facts.join(" · ")));
    }
    if !pb.vars.is_empty() {
        text.push("Vars:".into());
        for (k, v) in &pb.vars {
            let mut d = Vec::new();
            if v.required {
                d.push("required".to_string());
            }
            if let Some(def) = &v.default {
                d.push(format!("default {def:?}"));
            }
            if !v.choices.is_empty() {
                d.push(format!("one of {}", v.choices.join(", ")));
            }
            if let Some(p) = &v.pattern {
                d.push(format!("matches {p}"));
            }
            if v.kind != playbook::VarKind::String {
                d.push(format!("{:?}", v.kind).to_lowercase());
            }
            let desc = if v.description.is_empty() { String::new() } else { format!(" — {}", v.description) };
            text.push(format!("  {k} ({}){desc}", d.join(", ")));
        }
    }
    text.push("Steps:".into());
    step_lines(&pb.steps, 0, &mut text);
    let mut json = json!({ "source": pb.source, "playbook": pb });
    if server {
        json["server"] = json!(true);
    }
    let out = Out::new(json).lines(text).id(pb.name.clone());
    app.print(out);
    Ok(())
}

fn status_lines(s: &RunStatus) -> Vec<String> {
    let p = &s.progress;
    let mut parts = vec![format!("{}/{} done", p.done, p.total)];
    for (n, what) in [(p.failed, "failed"), (p.active, "active"), (p.ready, "ready"), (p.blocked, "blocked")] {
        if n > 0 {
            parts.push(format!("{n} {what}"));
        }
    }
    if p.gates_open > 0 {
        parts.push(format!(
            "{} gate(s) shut{}",
            p.gates_open,
            if p.escalated > 0 { format!(", {} escalated", p.escalated) } else { String::new() }
        ));
    }
    let run = &s.run;
    let head_state = match (run.status, run.close_outcome) {
        (bd_core::Status::Closed, Some(bd_core::Outcome::Failed)) => "✗",
        (bd_core::Status::Closed, _) => "✓",
        _ => "▸",
    };
    let mut lines = vec![format!(
        "{head_state} {} {}{} · {}",
        run.id,
        run.title,
        s.playbook.as_ref().map(|p| format!(" · playbook {p}")).unwrap_or_default(),
        parts.join(", ")
    )];
    let width = s.nodes.iter().map(|n| n.id.len() + bd_core::graph::indent(n.depth).len()).max().unwrap_or(0);
    for n in &s.nodes {
        let indent = bd_core::graph::indent(n.depth);
        let pad = width.saturating_sub(n.id.len() + indent.len());
        let mut line = format!("{indent}{} {}{} {}", n.state.icon(), n.id, " ".repeat(pad), n.title);
        let mut detail = Vec::new();
        if let Some(a) = n.assignee.as_ref().filter(|_| n.state != StepState::Active) {
            detail.push(format!("@{a}"));
        }
        if let Some(d) = &n.detail {
            detail.push(d.clone());
        }
        let state = serde_json::to_value(n.state).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        line.push_str(&format!("  [{state}]"));
        if !detail.is_empty() {
            line.push_str(&format!(" {}", detail.join(" · ")));
        }
        lines.push(line);
    }
    lines
}

fn cmd_run(app: &mut App, a: &RunArgs, dry_run: bool) -> Result<()> {
    let loader = loader(app)?;
    let pb = load(app, &loader, &a.playbook)?;
    let req = RunRequest {
        vars: parse_vars(&a.vars)?,
        ephemeral: if a.ephemeral {
            Some(true)
        } else if a.persistent {
            Some(false)
        } else {
            None
        },
        assignee: a.assignee.clone().filter(|s| !s.trim().is_empty()),
        title: a.title.clone().filter(|s| !s.trim().is_empty()),
        // The workspace's, also under bd serve: `{{experimental.<name>}}`.
        features: app.read(|r| bd_core::config::experimental(r.conn()))?,
    };
    let plan = playbook::compile(&pb, &req, &loader)?;
    let (started, status) = app.write("playbook.run", |tx| {
        let opts = StartOptions {
            parent: a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?,
            after: a.after.iter().filter(|x| !x.trim().is_empty()).map(|x| tx.resolve_id(x)).collect::<Result<_>>()?,
        };
        let started = tx.start_run(&plan, &opts)?;
        let status = playbook::run_status(tx.conn(), &started.run.id, tx.now())?;
        if dry_run {
            tx.set_rollback_only();
        }
        Ok((started, status))
    })?;
    let run = &started.run;
    let kind = if started.ephemeral { "ephemeral run" } else { "run" };
    let gates = if started.gates > 0 { format!(", {} gate(s)", started.gates) } else { String::new() };
    let mut out = if dry_run {
        Out::new(json!({ "dry_run": true, "plan": plan, "run": run.id, "status": status }))
            .line(format!(
                "Plan: {} would start {kind} {} \"{}\" ({} step(s){gates})",
                pb.name, run.id, run.title, started.steps
            ))
            .lines(status_lines(&status).into_iter().skip(1))
            .line("Dry run: nothing was written.".to_string())
    } else {
        Out::new(&started)
            .line(format!("✓ Started {kind} {}: {} ({}, {} step(s){gates})", run.id, run.title, pb.name, started.steps))
    };
    if !dry_run {
        if started.ready.is_empty() {
            out = out.line("  nothing is ready yet (the run waits on --after issues)");
        }
        for r in &started.ready {
            out = out.line(format!("  ready: {} {}", r.id, r.title));
        }
        out = out.line(format!("  progress: bd playbook status {}", run.id));
    }
    app.print(out.id(run.id.clone()));
    Ok(())
}

fn cmd_status(app: &mut App, a: &IdArg) -> Result<()> {
    let status = app.read(|r| playbook::run_status(r.conn(), &r.resolve_id(&a.id)?, r.now()))?;
    let ids: Vec<String> = status.nodes.iter().map(|n| n.id.clone()).collect();
    let out = Out::new(&status).lines(status_lines(&status));
    app.print(Out { ids, ..out });
    Ok(())
}

fn cmd_runs(app: &mut App, a: &RunsArgs) -> Result<()> {
    let q = RunsQuery { include_closed: a.all, playbook: a.playbook.clone(), limit: (a.limit > 0).then_some(a.limit) };
    let (runs, now) = app.read(|r| Ok((playbook::runs(r.conn(), &q, r.now())?, r.now())))?;
    let mut out = Out::new(&runs);
    if runs.is_empty() {
        out = out.line(if a.all { "No runs" } else { "No open runs (--all includes finished ones)" });
    }
    for r in &runs {
        let icon = match (r.status, r.outcome) {
            (bd_core::Status::Closed, Some(bd_core::Outcome::Failed)) => "✗",
            (bd_core::Status::Closed, _) => "✓",
            _ => "▸",
        };
        let p = &r.progress;
        let mut extra = Vec::new();
        for (n, what) in [(p.active, "active"), (p.ready, "ready"), (p.failed, "failed")] {
            if n > 0 {
                extra.push(format!("{n} {what}"));
            }
        }
        if p.gates_open > 0 {
            extra.push(format!("{} gate(s) shut", p.gates_open));
        }
        if r.ephemeral {
            extra.push("ephemeral".into());
        }
        out = out
            .line(format!(
                "{icon} {} {} [{}] {}/{} done{} · started {}",
                r.id,
                r.title,
                r.playbook.as_deref().unwrap_or("?"),
                p.done,
                p.total,
                if extra.is_empty() { String::new() } else { format!(" ({})", extra.join(", ")) },
                rel(r.created_at, now)
            ))
            .id(r.id.clone());
    }
    app.print(out);
    Ok(())
}

fn cmd_compact(app: &mut App, a: &CompactArgs) -> Result<()> {
    let opts =
        CompactOptions { summary: a.summary.clone(), force: a.force, take_over: a.take_over, dry_run: a.dry_run };
    let r = app.write("playbook.compact", |tx| {
        let id = tx.resolve_id(&a.id)?;
        tx.compact_run(&id, &opts)
    })?;
    let mut out = Out::new(&r);
    if r.dry_run {
        out = out
            .line(format!(
                "Would remove {} issue(s) from {} and append this digest to its notes:",
                r.removed.len(),
                r.run.id
            ))
            .line(String::new())
            .lines(r.digest.lines().map(String::from));
    } else {
        out = out.line(format!(
            "✓ Compacted {}: {} issue(s) folded into its notes (kept for good)",
            r.run.id,
            r.removed.len()
        ));
    }
    app.print(out.id(r.run.id.clone()));
    Ok(())
}

fn cmd_discard(app: &mut App, a: &DiscardArgs) -> Result<()> {
    let r = app.write("playbook.discard", |tx| {
        let id = tx.resolve_id(&a.id)?;
        tx.discard_run(&id, &DiscardOptions { force: a.force, take_over: a.take_over, dry_run: a.dry_run })
    })?;
    let verb = if r.dry_run { "Would discard" } else { "✓ Discarded" };
    let mut out = Out::new(&r).line(format!("{verb} {} issue(s): {}", r.deleted.len(), r.deleted.join(", ")));
    if !r.detached.is_empty() {
        out = out.line(format!("  edges dropped from: {}", r.detached.join(", ")));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    app.print(out);
    Ok(())
}

fn cmd_extract(app: &mut App, a: &ExtractArgs) -> Result<()> {
    if a.save {
        io::require_local("playbook extract --save")?;
    }
    let pb = app.read(|r| playbook::extract(r.conn(), &r.resolve_id(&a.id)?, a.name.as_deref()))?;
    let text = playbook::to_toml(&pb)?;
    too_large_to_send(app, &text);
    let target = match (&a.output, a.save) {
        // Under bd serve the client writes the file, relative to its own directory.
        (Some(p), _) if io::serving() => Some(p.clone()),
        (Some(p), _) => Some(if p.is_relative() { app.cwd.join(p) } else { p.clone() }),
        (None, true) => {
            let dir = search_paths(app).into_iter().next().ok_or_else(|| Error::invalid("no playbook directory"))?;
            Some(dir.join(format!("{}.toml", pb.name)))
        }
        (None, false) => None,
    };
    match target {
        None => {
            if app.g.json {
                app.print_json(&json!({ "playbook": pb, "toml": text }));
            } else {
                io::out(&text);
            }
        }
        Some(path) => {
            if io::serving() {
                // The client checked --force against its own file before sending.
                io::send_file(&path, |w| Ok(w.write_all(text.as_bytes())?))?;
            } else {
                write_playbook(&path, &text, a.force)?;
            }
            app.print(wrote(&path, &pb));
        }
    }
    Ok(())
}

/// A playbook this large runs where it is a file, but a bd client cannot send
/// it to a server: say so where it is made.
fn too_large_to_send(app: &App, text: &str) {
    if text.len() > MAX_BUNDLE_FILE_BYTES && !app.g.json {
        io::errln(format!(
            "note: this playbook is {} KiB, more than the {} KiB a bd client sends to a server in one file: run it \
             locally, or from the server's playbook directory",
            text.len() >> 10,
            MAX_BUNDLE_FILE_BYTES >> 10
        ));
    }
}

fn write_playbook(path: &Path, text: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::Refused(format!("{} exists; pass --force to overwrite", path.display())));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

fn wrote(path: &Path, pb: &Playbook) -> Out {
    Out::new(json!({ "path": path, "playbook": pb.name, "steps": pb.all_steps().len() }))
        .line(format!("✓ Wrote playbook {} to {} ({} step(s))", pb.name, path.display(), pb.all_steps().len()))
        .line(format!("  run it with: bd playbook run {}", pb.name))
        .id(path.display().to_string())
}

pub fn cmd_purge(app: &mut App, a: &PurgeArgs) -> Result<()> {
    let older = a.older_than.as_deref().map(parse_duration).transpose()?;
    let r = app.write("purge", |tx| tx.purge_ephemeral(older, a.dry_run))?;
    let verb = if r.dry_run { "Would purge" } else { "✓ Purged" };
    let mut out = Out::new(&r);
    out = if r.deleted.is_empty() {
        out.line("Nothing to purge (no closed ephemeral issues past the cutoff)")
    } else {
        out.line(format!("{verb} {} closed ephemeral issue(s)", r.deleted.len()))
    };
    if !r.detached.is_empty() {
        out = out.line(format!("  edges dropped from: {}", r.detached.join(", ")));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    app.print(out);
    Ok(())
}

// ------------------------------------------------------------ remote clients

/// Where a client puts the bundle among a request's files.
const BUNDLE_FILE: &str = "playbooks.bundle.json";
/// Names the bundle on the command line.
const BUNDLE_FLAG: &str = "--playbook-bundle";

/// A remote workspace's checkout `.bd` directory: the one holding
/// `remote.toml`, else the nearest one.
pub(crate) fn checkout_bd(app: &App) -> Result<Option<PathBuf>> {
    Ok(match remote::configured(app)?.map(|c| c.source) {
        Some(remote::Source::File(file)) => file.parent().map(Path::to_path_buf),
        _ => app.cwd.ancestors().map(|d| d.join(".bd")).find(|d| d.is_dir()),
    })
}

/// A remote workspace's checkout playbooks: `.bd/playbooks` next to
/// `remote.toml`, else in the nearest `.bd` directory.
fn checkout_playbooks(app: &App) -> Result<PathBuf> {
    Ok(checkout_bd(app)?.unwrap_or_else(|| app.cwd.join(".bd")).join("playbooks"))
}

/// Runs the `bd playbook` commands a remote workspace's client handles
/// itself: `list` (the checkout's playbooks, the server's, then the user's
/// own) and `extract --save` (into the checkout). `None`: the server runs it.
pub fn client_command(app: &App, remote: &Remote, cmd: &PlaybookCommand) -> Result<Option<i32>> {
    match cmd {
        PlaybookCommand::List => client_list(app, remote).map(Some),
        PlaybookCommand::Extract(a) if a.save => client_extract(app, remote, a).map(Some),
        _ => Ok(None),
    }
}

/// The directory of the server's playbooks approved on this machine, in a
/// remote workspace's checkout ([`crate::agents::approved`]).
fn approved_playbooks(app: &App) -> Result<Option<Checkout>> {
    Ok(checkout_bd(app)?.map(Checkout::new))
}

/// Where a remote workspace's client looks a playbook up: the checkout's
/// `.bd/playbooks`, the server's approved here, then the user's own.
fn client_paths(app: &App) -> Result<(PathBuf, Option<Checkout>, Vec<PathBuf>)> {
    let checkout = checkout_playbooks(app)?;
    let approved = approved_playbooks(app)?;
    let mut paths = vec![checkout.clone()];
    paths.extend(approved.as_ref().map(Checkout::approved_playbooks));
    paths.extend(with_user_paths(None));
    Ok((checkout, approved, paths))
}

/// `show`, `plan` and `run`: send the files of the playbook named, found on
/// the client (the checkout's, those approved here, the user's own), with
/// the command (a bundle), checked against the approvals. A name found
/// nowhere here is an error: the server's playbooks are used only once
/// approved on this machine.
pub fn attach_bundle(app: &App, cmd: &Command, request: &mut ExecRequest) -> Result<()> {
    let Command::Playbook(
        PlaybookCommand::Show(PlaybookRefArgs { playbook: reference })
        | PlaybookCommand::Plan(RunArgs { playbook: reference, .. })
        | PlaybookCommand::Run(RunArgs { playbook: reference, .. }),
    ) = cmd
    else {
        return Ok(());
    };
    if let Some(file) = &app.g.playbook_bundle {
        // A bundle named on the command line travels like any input file, but
        // never asks for the server's copy in place of what it holds.
        let text = io::read_file(file)?;
        if Bundle::from_json(&text)?.server_first {
            return Err(Error::invalid(format!(
                "{}: a playbook bundle asking for the bd server's copy first (server_first): the server's \
                 playbooks are used here only once approved on this machine (`bd agents approve`)",
                file.display()
            )));
        }
        request.files.insert(file.to_string_lossy().into_owned(), text);
        return Ok(());
    }
    // The checkout's playbooks and file paths come first, then the server's
    // approved here, then the user's own ($BD_PLAYBOOK_PATH, the config
    // directory). Inside a playbook found here, references resolve on the
    // whole client path, as locally.
    let (_, approved, paths) = client_paths(app)?;
    let loader = Loader::new(paths);
    let r = reference.trim();
    match loader.locate(r, Some(&app.cwd)) {
        Ok(_) => {}
        Err(Error::NotFound { .. }) if !playbook::is_path_like(r) => {
            return Err(Error::not_found(
                "playbook",
                format!(
                    "{r} (looked up in this checkout's .bd/playbooks, among the bd server's playbooks approved on \
                     this machine, and in the user's own; a playbook the server serves is used here only once a \
                     person approves it: `bd agents status` lists those waiting, and `bd agents approve` in a \
                     terminal approves them)"
                ),
            ));
        }
        Err(e) => return Err(e),
    }
    let bundle = loader.bundle(reference, Some(&app.cwd))?;
    if let Some(approved) = &approved {
        crate::agents::approved::verify_bundle(approved, &bundle)?;
    }
    let bundle = bundle.to_json()?;
    request.files.insert(BUNDLE_FILE.to_string(), bundle);
    request.argv.splice(0..0, [BUNDLE_FLAG.to_string(), BUNDLE_FILE.to_string()]);
    Ok(())
}

/// Where a client puts its playbook listing for `bd prime` among a request's files.
const LISTING_FILE: &str = "prime.playbooks.json";
/// Names the listing on the command line.
const LISTING_FLAG: &str = "--client-playbooks";

/// `bd prime`: send the names and descriptions of the checkout's playbooks,
/// the server's approved here and the user's own, and what is approved
/// here ([`Listing`]), which the server lists in place of its own, naming
/// its playbooks waiting for approval here. Never fails, and makes no
/// request of its own.
pub fn attach_listing(app: &App, cmd: &Command, request: &mut ExecRequest) {
    if !matches!(cmd, Command::Prime(_)) {
        return;
    }
    if let Some(file) = &app.g.client_playbooks {
        // A listing named on the command line travels like any input file.
        if let Ok(text) = io::read_file(file) {
            request.files.insert(file.to_string_lossy().into_owned(), text);
        }
        return;
    }
    let Ok((checkout, approved, paths)) = client_paths(app) else { return };
    let approved_dir = approved.as_ref().map(Checkout::approved_playbooks);
    let playbooks: Vec<Summary> = Loader::new(paths)
        .list()
        .into_iter()
        .filter(|l| l.shadowed_by.is_none())
        .map(|l| {
            let location = match l.path.parent() {
                Some(dir) if dir == checkout => Location::Checkout,
                Some(dir) if Some(dir) == approved_dir.as_deref() => Location::Approved,
                _ => Location::User,
            };
            Summary::of(&l, location)
        })
        .collect();
    let approved = match &approved {
        Some(c) => c.read_lock().ok().map(|lock| lock.playbooks.into_iter().map(|(p, a)| (p, a.sha256)).collect()),
        None => Some(BTreeMap::new()),
    };
    let listing = Listing { playbooks, approved };
    let Ok(listing) = serde_json::to_string(&listing) else { return };
    request.files.insert(LISTING_FILE.to_string(), listing);
    request.argv.splice(0..0, [LISTING_FLAG.to_string(), LISTING_FILE.to_string()]);
}

/// The server's playbooks waiting for approval in `checkout` (none: in a
/// directory without one, where nothing is approved); `None` if the server
/// does not serve them. Changes nothing.
fn pending_here(
    app: &App,
    remote: &Remote,
    checkout: Option<&Checkout>,
) -> Result<Option<Vec<crate::agents::approved::PendingPlaybook>>> {
    let nowhere;
    let checkout = match checkout {
        Some(c) => c,
        None => {
            nowhere = Checkout::new(app.cwd.join(".bd"));
            &nowhere
        }
    };
    let lock_wait = std::time::Duration::from_millis(app.g.busy_timeout_ms);
    let opts = crate::agents::sync::Options { apply: false, force: false, review: false, lock_wait };
    Ok(crate::agents::sync_playbooks(app, Some(remote), checkout, opts)?.map(|o| o.report.pending))
}

/// A read the client composes (in JSON) rather than the user's command line.
pub(crate) fn server_read(app: &App, remote: &Remote, mut argv: Vec<String>) -> Result<ExecResponse> {
    if let Some(actor) = &app.g.actor {
        argv.splice(0..0, ["--actor".to_string(), actor.clone()]);
    }
    let (actor, session) = remote::identity();
    let request = ExecRequest { argv, actor, session, location: Some(remote.url.clone()), ..Default::default() };
    remote.exec(&request)
}

/// Print the error of a read the client composed, in the user's format; returns its exit code.
fn relay_failure(app: &App, response: &ExecResponse) -> i32 {
    match response.stderr.lines().find_map(|l| serde_json::from_str::<ErrorBody>(l).ok()) {
        Some(body) if !app.g.json => io::errln(format!("error: {}", body.error.message)),
        _ => io::errln(response.stderr.trim_end()),
    }
    response.exit_code
}

/// `list` in a remote workspace: the checkout's playbooks, the server's
/// approved here, then the user's own, as a command naming one finds them;
/// and the server's waiting for approval here.
fn client_list(app: &App, remote: &Remote) -> Result<i32> {
    let (_, approved, paths) = client_paths(app)?;
    let approved_dir = approved.as_ref().map(Checkout::approved_playbooks);
    let pending = pending_here(app, remote, approved.as_ref())?;
    let entries: Vec<(Listed, bool)> = Loader::new(paths.clone())
        .list()
        .into_iter()
        .map(|l| {
            let from_server = l.path.parent().is_some_and(|d| Some(d) == approved_dir.as_deref());
            (l, from_server)
        })
        .collect();
    let playbooks: Vec<Value> = entries
        .iter()
        .map(|(l, approved)| {
            let mut v = json!(l);
            if *approved {
                v["server"] = json!(true);
                v["approved"] = json!(true);
            }
            v
        })
        .collect();
    let searched: Vec<(PathBuf, bool)> =
        paths.iter().map(|p| (p.clone(), Some(p.as_path()) == approved_dir.as_deref())).collect();
    let json = json!({
        "search_paths": paths,
        "server": { "url": remote.url, "pending": pending },
        "playbooks": playbooks,
    });
    let mut out = list_out(json, &entries, &searched);
    match pending.as_deref() {
        Some([]) | None => {}
        Some(pending) => {
            out = out.line(crate::agents::show::printable(&format!(
                "Waiting for approval on this machine (the bd server's, not usable here until approved with `bd \
                 agents approve` in a terminal): {}",
                crate::agents::approved::pending_list(pending)
            )));
        }
    }
    if pending.is_none() {
        out = out.line(
            "note: the bd server does not serve its playbooks for approval (it predates it); upgrade it to use them \
             here",
        );
    }
    app.print(out);
    Ok(0)
}

/// `extract --save` in a remote workspace: the server extracts, the client
/// writes the file into its checkout's playbook directory.
fn client_extract(app: &App, remote: &Remote, a: &ExtractArgs) -> Result<i32> {
    let mut argv: Vec<String> = vec!["--json".into(), "playbook".into(), "extract".into()];
    if let Some(name) = &a.name {
        argv.extend(["--name".into(), name.clone()]);
    }
    argv.extend(["--".into(), a.id.clone()]);
    let response = server_read(app, remote, argv)?;
    if response.exit_code != 0 {
        return Ok(relay_failure(app, &response));
    }
    let unexpected =
        |e: &dyn std::fmt::Display| Error::Remote(format!("{}: unexpected extract output: {e}", remote.url));
    let extracted: Value = serde_json::from_str(&response.stdout).map_err(|e| unexpected(&e))?;
    let text = extracted["toml"].as_str().ok_or_else(|| unexpected(&"no toml"))?;
    // Parsing checks the playbook, and its name before it becomes a file name here.
    let pb = playbook::parse_toml(text, "the extracted playbook", "extracted")?;
    let path = checkout_playbooks(app)?.join(format!("{}.toml", pb.name));
    write_playbook(&path, text, a.force)?;
    too_large_to_send(app, text);
    app.print(wrote(&path, &pb));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn the_bundle_flag_parses() {
        assert!(Cli::try_parse_from(["bd", BUNDLE_FLAG, BUNDLE_FILE, "playbook", "list"]).is_ok());
        assert!(Cli::try_parse_from(["bd", LISTING_FLAG, LISTING_FILE, "prime", "--hook", "copilot"]).is_ok());
    }

    #[test]
    fn prime_summaries_are_one_short_line_and_tidy_once() {
        let summary = |description: &str| {
            Summary {
                name: "x\u{1b}".into(),
                description: description.into(),
                location: Location::User,
                invalid: false,
            }
            .tidy()
        };
        let short = summary("  Ship it\n\nThe details.");
        assert_eq!((short.name.as_str(), short.description.as_str()), ("x\\u{1b}", "Ship it…"));
        assert_eq!(summary(&format!("{} y", "a".repeat(99))).description, format!("{}…", "a".repeat(99)));
        assert_eq!(summary("Turns \u{1b}[31mred").description, "Turns \\u{1b}[31mred");
        for d in ["Ship it\nmore", &"b".repeat(300), &format!("{}\u{202e}", "c".repeat(98)), ""] {
            let once = summary(d);
            let twice = once.clone().tidy();
            assert_eq!((&once.name, &once.description), (&twice.name, &twice.description), "{d:?}");
        }
    }
}
