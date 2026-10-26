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
//!
//! A workspace may set `playbooks.source = server`
//! ([`bd_core::config::PlaybooksSource`]): then its clients ignore the
//! checkout's `.bd/playbooks`, and a name resolves among the server's
//! playbooks approved here, then the user's own for names the server does
//! not serve (one it serves, never approved here, is not found), for the
//! names its playbooks extend or expand too. A client asks the server's
//! setting only where it changes the answer (`lookup`: some name resolved
//! in the checkout or on the user's paths), `list` only when the checkout
//! holds playbooks or a user playbook has a name the server serves
//! unapproved, and `bd prime` is decided on the server, which reads its
//! own. A server that cannot say (it predates the key, the read fails)
//! leaves it off; in server mode a failed read of the server's playbook
//! list stops the command. It is a policy for honest clients,
//! not a boundary: the server compiles whatever bundle a client sends.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bd_core::config::PlaybooksSource;
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
    let mut json = json!({ "search_paths": loader.search_paths, "playbooks": listed });
    // The workspace's setting, for a remote workspace's clients (none without a workspace).
    if let Ok(source) = app.read(|r| bd_core::config::playbooks_source(r.conn())) {
        json["source"] = json!(source.as_str());
    }
    let entries: Vec<(Listed, Mark)> = listed.into_iter().map(|l| (l, Mark::Own)).collect();
    let searched: Vec<(PathBuf, bool)> = loader.search_paths.iter().map(|p| (p.clone(), false)).collect();
    app.print(list_out(json, &entries, &searched));
    Ok(())
}

/// Where an entry of `bd playbook list` comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mark {
    /// The workspace's or the user's own.
    Own,
    /// The server's, approved here.
    Approved,
    /// The checkout's, ignored with `playbooks.source = server`.
    Ignored,
    /// The user's own of a name the server serves and this machine has not
    /// approved, not used with `playbooks.source = server`.
    Unavailable,
}

/// What `bd playbook list` prints. Searched directories marked `true` are
/// the server's playbooks approved here.
fn list_out(json: Value, entries: &[(Listed, Mark)], searched: &[(PathBuf, bool)]) -> Out {
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
    for (l, mark) in entries {
        let place = match mark {
            Mark::Own => "",
            Mark::Approved => " (the bd server's, approved here)",
            Mark::Ignored => " (ignored: playbooks.source = server)",
            Mark::Unavailable => " (waiting for approval: the bd server serves this name)",
        };
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
    /// With `playbooks.source = server`: how many of the client's checkout
    /// playbooks (by name) are ignored, left out of `playbooks`.
    pub ignored: usize,
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
/// listed in place of the server's own, with those waiting for approval
/// (with `source` [`PlaybooksSource::Server`], the workspace's setting,
/// leaving out its checkout's, counted, and its user's of a name the server
/// serves); or, from a client that predates it, of its checkout's and its
/// user's playbooks, which go before and after the server's own. A listing
/// that cannot be read is left out.
pub fn for_prime(app: &App, client: Option<&Path>, source: PlaybooksSource) -> ForPrime {
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
            let server_only = source == PlaybooksSource::Server;
            let set = if listing.approved.is_some() || server_only { served_set(app) } else { None };
            let served = |name: &str| set.as_ref().is_some_and(|s| served_name(s.files.keys(), name));
            let mut seen = std::collections::HashSet::new();
            let mut ignored = std::collections::BTreeSet::new();
            let playbooks = listing
                .playbooks
                .into_iter()
                .map(Summary::tidy)
                .filter(|s| match s.location {
                    Location::Server => false,
                    Location::Checkout if server_only => {
                        ignored.insert(s.name.clone());
                        false
                    }
                    // Not found by name: the server's of that name waits for approval.
                    Location::User if server_only && served(&s.name) => false,
                    _ => seen.insert(s.name.clone()),
                })
                .collect();
            let pending = match (listing.approved, &set) {
                (Some(a), Some(set)) => pending_against(set, &a),
                _ => Vec::new(),
            };
            return ForPrime { playbooks, pending, ignored: ignored.len() };
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
    ForPrime { playbooks, pending: Vec::new(), ignored: 0 }
}

/// The playbooks the workspace serves its clients: `None` if they cannot be read.
fn served_set(app: &App) -> Option<bd_core::agents::PlaybookSet> {
    let set = crate::agents::playbooks_dir(app).and_then(|dir| bd_core::agents::PlaybookSet::load(&dir));
    set.map_err(|e| tracing::debug!(target: "bd::cli", error = %e, "the playbooks served unknown")).ok()
}

/// The playbooks of `set` a client that approved those of `approved` (path
/// to SHA-256) has yet to approve.
fn pending_against(
    set: &bd_core::agents::PlaybookSet,
    approved: &BTreeMap<String, String>,
) -> Vec<crate::agents::approved::PendingPlaybook> {
    use crate::agents::approved::{PendingPlaybook, PlaybookChange};
    set.files
        .iter()
        .filter_map(|(path, file)| match approved.get(path) {
            None => Some(PendingPlaybook { path: path.clone(), change: PlaybookChange::New }),
            Some(sha) if *sha != file.sha256 => {
                Some(PendingPlaybook { path: path.clone(), change: PlaybookChange::Changed })
            }
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

/// `s` as lines of text; a node in `links` (gate id to its approval link)
/// gets the link in its detail, and its line escaped to one line.
fn status_lines(s: &RunStatus, links: &BTreeMap<String, String>) -> Vec<String> {
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
        let link = links.get(&n.id);
        if let Some(url) = link {
            detail.push(format!("approve in a browser: {url}"));
        }
        let state = serde_json::to_value(n.state).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        line.push_str(&format!("  [{state}]"));
        if !detail.is_empty() {
            line.push_str(&format!(" {}", detail.join(" · ")));
        }
        lines.push(if link.is_some() { crate::agents::show::printable(&line) } else { line });
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
            .lines(status_lines(&status, &BTreeMap::new()).into_iter().skip(1))
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
    let (status, links) = app.read(|r| {
        let status = playbook::run_status(r.conn(), &r.resolve_id(&a.id)?, r.now())?;
        let mut links = BTreeMap::new();
        for n in &status.nodes {
            if n.issue_type == "gate" && matches!(n.state, StepState::Armed | StepState::Escalated) {
                let view = bd_core::gates::view(r.conn(), &n.id)?;
                if let Some(url) = crate::gates::approval_url_of(&view) {
                    links.insert(n.id.clone(), url);
                }
            }
        }
        Ok((status, links))
    })?;
    let ids: Vec<String> = status.nodes.iter().map(|n| n.id.clone()).collect();
    let mut json = serde_json::to_value(&status)?;
    if let Some(nodes) = json.get_mut("nodes").and_then(Value::as_array_mut) {
        for node in nodes {
            let url = node.get("id").and_then(Value::as_str).and_then(|id| links.get(id)).cloned();
            if let (Some(url), Some(o)) = (url, node.as_object_mut()) {
                o.insert("approval_url".into(), url.into());
            }
        }
    }
    let out = Out::new(json).lines(status_lines(&status, &links));
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
/// the client (the checkout's, those approved here, the user's own; with
/// `playbooks.source = server` not the checkout's: `lookup`), with the
/// command (a bundle), checked against the approvals. A name found nowhere
/// here is an error: the server's playbooks are used only once approved on
/// this machine.
pub fn attach_bundle(app: &App, remote: &Remote, cmd: &Command, request: &mut ExecRequest) -> Result<()> {
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
    // whole client path, as locally. With `playbooks.source = server`, every
    // name (on the command line, or in `extends`/`expand`) skips the
    // checkout's; a file path named on the command line is the client's.
    let (checkout, approved, paths) = client_paths(app)?;
    let approved_dir = approved.as_ref().map(Checkout::approved_playbooks);
    let full = Loader::new(paths.clone());
    let r = reference.trim();
    let cwd = Some(app.cwd.as_path());
    let top = match full.locate(r, cwd) {
        Ok(top) => top,
        Err(Error::NotFound { .. }) if !playbook::is_path_like(r) => return Err(name_not_found(r, false)),
        Err(e) => return Err(e),
    };
    let built = full.bundle(reference, cwd);
    let bundle = if playbook::is_path_like(r) {
        built?
    } else {
        // Where each name resolved (the command line's alone if the bundle
        // could not be built): only one outside the approved asks the server.
        let targets: Vec<PathBuf> = match &built {
            Ok(b) => by_name(b).map(|(_, target)| target.to_path_buf()).collect(),
            Err(_) => vec![top],
        };
        let mut places: Vec<Place> = targets.iter().map(|t| place(t, &checkout, approved_dir.as_deref())).collect();
        // A bundle that failed may have failed on a checkout copy server mode would skip: ask then too.
        if built.is_err() && holds_playbooks(&checkout) {
            places.push(Place::Checkout);
        }
        match lookup(&places, || client_source(app, remote)) {
            Lookup::Everywhere => built?,
            Lookup::ServerOnly => {
                let rest = Loader::new(paths.into_iter().filter(|p| *p != checkout).collect());
                let rebuilt = match rest.locate(r, cwd) {
                    Ok(_) => rest.bundle(reference, cwd),
                    Err(Error::NotFound { .. }) => Err(name_not_found(r, true)),
                    Err(e) => Err(e),
                };
                // The checkout's copies skipped: those of the names this lookup resolved; if it
                // failed, those of the command line's and of the names the whole path resolved.
                let skipped = match &rebuilt {
                    Ok(b) => checkout_copies(&checkout, by_name(b).map(|(name, _)| name)),
                    Err(_) => checkout_copies(
                        &checkout,
                        std::iter::once(r).chain(built.iter().flat_map(|b| by_name(b).map(|(name, _)| name))),
                    ),
                };
                for path in &skipped {
                    warn_ignored(path);
                }
                let bundle = rebuilt?;
                refuse_served_unapproved(app, remote, &bundle, approved_dir.as_deref())?;
                bundle
            }
        }
    };
    if let Some(approved) = &approved {
        crate::agents::approved::verify_bundle(approved, &bundle)?;
    }
    let bundle = bundle.to_json()?;
    request.files.insert(BUNDLE_FILE.to_string(), bundle);
    request.argv.splice(0..0, [BUNDLE_FLAG.to_string(), BUNDLE_FILE.to_string()]);
    Ok(())
}

/// Whether `dir` holds a playbook file.
fn holds_playbooks(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.filter_map(|e| e.ok()).any(|e| playbook::name_of(&e.path()).is_some() && e.path().is_file())
    })
}

/// Where a name resolved on a remote client's lookup path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// The checkout's `.bd/playbooks`.
    Checkout,
    /// The server's playbooks approved here.
    Approved,
    /// `$BD_PLAYBOOK_PATH` and the user config directory.
    User,
}

fn place(path: &Path, checkout: &Path, approved: Option<&Path>) -> Place {
    match path.parent() {
        Some(dir) if dir == checkout => Place::Checkout,
        Some(dir) if Some(dir) == approved => Place::Approved,
        _ => Place::User,
    }
}

/// How a remote client looks playbook names up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lookup {
    /// On the whole client path, the checkout's first.
    Everywhere,
    /// `playbooks.source = server`: among the server's approved here, then
    /// the user's own for names the server does not serve; the checkout's
    /// copies of the names it looks up are skipped (and warned about).
    ServerOnly,
}

/// The lookup of a playbook whose names (the command line's and those of
/// its `extends` and `expand`) resolved at `places` on the client's whole
/// path. The workspace's setting (`source`, a request to the server) is
/// asked only where it changes the answer: some name resolved in the
/// checkout (skipped) or on the user's paths (not used for a name the
/// server serves). All among the approved, the answer is the same either
/// way.
fn lookup(places: &[Place], source: impl FnOnce() -> PlaybooksSource) -> Lookup {
    if places.iter().all(|p| *p == Place::Approved) {
        return Lookup::Everywhere;
    }
    match source() {
        PlaybooksSource::Server => Lookup::ServerOnly,
        PlaybooksSource::Checkout => Lookup::Everywhere,
    }
}

/// A name found nowhere on the client: `server_only`, with
/// `playbooks.source = server`, where the checkout was skipped.
fn name_not_found(name: &str, server_only: bool) -> Error {
    let looked = if server_only {
        "among the bd server's playbooks approved on this machine and in the user's own (playbooks.source = \
         server: this checkout's .bd/playbooks are not used)"
    } else {
        "in this checkout's .bd/playbooks, among the bd server's playbooks approved on this machine, and in the \
         user's own"
    };
    Error::not_found(
        "playbook",
        format!(
            "{name} (looked up {looked}; a playbook the server serves is used here only once a person approves it: \
             `bd agents status` lists those waiting, and `bd agents approve` in a terminal approves them)"
        ),
    )
}

/// The workspace's `playbooks.source`, asked of the server (one read): the
/// default, `checkout`, when it cannot tell (a server that predates the
/// key, a failed read or an answer that does not parse): this read fails
/// open, unlike the manifest read of server mode ([`manifest_unread`]).
fn client_source(app: &App, remote: &Remote) -> PlaybooksSource {
    let argv = ["--json", "config", "get", "--", PlaybooksSource::KEY].map(String::from).to_vec();
    match server_read(app, remote, argv) {
        Ok(response) => source_answer(&response),
        Err(e) => {
            tracing::debug!(target: "bd::cli", error = %e, "playbooks.source unknown: checkout");
            PlaybooksSource::Checkout
        }
    }
}

/// The server's answer to `config get playbooks.source --json`, parsed
/// strictly: `server` only from a successful answer that is exactly
/// `{"key": "playbooks.source", "value": "server"}`; anything else is
/// `checkout`.
fn source_answer(response: &ExecResponse) -> PlaybooksSource {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Answer {
        key: String,
        value: String,
    }
    if response.exit_code != 0 {
        return PlaybooksSource::Checkout;
    }
    match serde_json::from_str::<Answer>(&response.stdout) {
        Ok(a) if a.key == PlaybooksSource::KEY && a.value == PlaybooksSource::Server.as_str() => {
            PlaybooksSource::Server
        }
        _ => PlaybooksSource::Checkout,
    }
}

/// With `playbooks.source = server`, one warning that the checkout's copy at `path` is ignored.
fn warn_ignored(path: &Path) {
    io::errln(ignored_warning(path));
}

/// The warning of [`warn_ignored`], escaped: the path is a file name of the checkout's.
fn ignored_warning(path: &Path) -> String {
    crate::agents::show::printable(&format!(
        "warning: ignoring {} (playbooks.source = server: playbooks come from the bd server, approved on this \
         machine; `bd publish` brings the checkout's to the server)",
        path.display()
    ))
}

/// The references a bundle resolved by name, not by path (on the command
/// line, `""`, or in a file), with the file each names.
fn by_name(bundle: &Bundle) -> impl Iterator<Item = (&str, &Path)> {
    bundle
        .refs
        .values()
        .flat_map(|refs| refs.iter())
        .filter(|(reference, _)| !playbook::is_path_like(reference.trim()))
        .map(|(reference, target)| (reference.trim(), Path::new(target.as_str())))
}

/// The checkout's copies (files in `checkout`, its `.bd/playbooks`) of the
/// playbooks `names`, found as the client's lookup finds them (each extension
/// in order, without parsing, so a copy that does not load is found too),
/// sorted, each once.
fn checkout_copies<'a>(checkout: &Path, names: impl IntoIterator<Item = &'a str>) -> Vec<PathBuf> {
    let only = Loader::new(vec![checkout.to_path_buf()]);
    let mut copies: Vec<PathBuf> = names.into_iter().filter_map(|n| only.locate(n, None).ok()).collect();
    copies.sort();
    copies.dedup();
    copies
}

/// The names a bundle resolved outside the approved playbooks directory
/// (`approved`): by name, not by path, from the command line or a file.
fn names_outside<'a>(bundle: &'a Bundle, approved: Option<&Path>) -> Vec<&'a str> {
    let mut names: Vec<&str> =
        by_name(bundle).filter(|(_, target)| target.parent() != approved).map(|(name, _)| name).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether one of the server's playbook files (`paths`, in its playbook
/// directory) is the playbook `name` finds: a top-level file of that name,
/// compared ignoring ASCII case (`CHANGE` and `change.toml`), as file
/// systems that ignore case would find it.
fn served_name<'a>(mut paths: impl Iterator<Item = &'a String>, name: &str) -> bool {
    paths.any(|path| {
        !path.contains('/') && playbook::name_of(Path::new(path)).is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}

/// Whether the server's `manifest` serves a playbook named `name`.
fn serves(manifest: &bd_core::agents::PlaybooksManifest, name: &str) -> bool {
    served_name(manifest.files.keys(), name)
}

/// A failed read of the server's playbook manifest with `playbooks.source
/// = server`: the command stops (fails closed), saying why, with an exit
/// code of the failure's kind.
fn manifest_unread(e: Error) -> Error {
    let message = format!(
        "playbooks.source = server: the bd server's list of its playbooks could not be read, so a name it may serve \
         is not taken from the user's own playbooks: {e}"
    );
    match e {
        Error::Unauthorized(_) => Error::Unauthorized(message),
        Error::Remote(_) | Error::AnswerLost(_) => Error::Remote(message),
        Error::Busy(_) => Error::Busy(message),
        Error::Locked(_) => Error::Locked(message),
        _ => Error::Refused(message),
    }
}

/// With `playbooks.source = server`: a name the bundle took from the user's
/// own that the server serves (not approved here, or it would have been
/// found among those approved) is not found. Asks the server's manifest
/// only when the bundle names something outside the approved playbooks.
fn refuse_served_unapproved(app: &App, remote: &Remote, bundle: &Bundle, approved: Option<&Path>) -> Result<()> {
    let names = names_outside(bundle, approved);
    if names.is_empty() {
        return Ok(());
    }
    let Some(manifest) = crate::agents::served_playbooks(app, remote).map_err(manifest_unread)? else {
        return Ok(());
    };
    match names.into_iter().find(|n| serves(&manifest, n)) {
        None => Ok(()),
        Some(name) => Err(Error::not_found(
            "playbook",
            format!(
                "{name} (playbooks.source = server: the bd server serves a playbook of this name, not approved on \
                 this machine, so no other copy is used; a playbook the server serves is used here only once a \
                 person approves it: `bd agents status` lists those waiting, and `bd agents approve` in a terminal \
                 approves them)"
            ),
        )),
    }
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
    // Shadowed ones too, in lookup order: the server keeps the first of each
    // name it lists (with `playbooks.source = server` it leaves the
    // checkout's out, and what they shadowed is listed).
    let playbooks: Vec<Summary> = Loader::new(paths)
        .list()
        .into_iter()
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
/// and the server's waiting for approval here. With `playbooks.source =
/// server` (asked only when the checkout holds playbooks), the checkout's
/// come last, marked ignored, shadowing nothing.
fn client_list(app: &App, remote: &Remote) -> Result<i32> {
    let (checkout, approved, paths) = client_paths(app)?;
    let approved_dir = approved.as_ref().map(Checkout::approved_playbooks);
    let pending = pending_here(app, remote, approved.as_ref())?;
    let all = Loader::new(paths.clone()).list();
    let in_checkout = |l: &Listed| l.path.parent() == Some(checkout.as_path());
    let in_approved = |l: &Listed| l.path.parent().is_some_and(|d| Some(d) == approved_dir.as_deref());
    // The server's playbooks never approved here: with `playbooks.source =
    // server` no other copy of their names is used.
    let unapproved: Vec<&String> = pending
        .iter()
        .flatten()
        .filter(|p| p.change == crate::agents::approved::PlaybookChange::New)
        .map(|p| &p.path)
        .collect();
    let blocked = |l: &Listed| !in_checkout(l) && !in_approved(l) && served_name(unapproved.iter().copied(), &l.name);
    // Asked only where the answer changes what is listed.
    let source = all.iter().any(|l| in_checkout(l) || blocked(l)).then(|| client_source(app, remote));
    let server_only = source == Some(PlaybooksSource::Server);
    let mark = |l: Listed| {
        let mark = if in_approved(&l) {
            Mark::Approved
        } else if server_only && blocked(&l) {
            Mark::Unavailable
        } else {
            Mark::Own
        };
        (l, mark)
    };
    let entries: Vec<(Listed, Mark)> = if server_only {
        let rest: Vec<PathBuf> = paths.iter().filter(|p| **p != checkout).cloned().collect();
        let ignored = all.into_iter().filter(in_checkout).map(|l| (l, Mark::Ignored));
        Loader::new(rest).list().into_iter().map(mark).chain(ignored).collect()
    } else {
        all.into_iter().map(mark).collect()
    };
    let playbooks: Vec<Value> = entries
        .iter()
        .map(|(l, mark)| {
            let mut v = json!(l);
            match mark {
                Mark::Own => {}
                Mark::Approved => {
                    v["server"] = json!(true);
                    v["approved"] = json!(true);
                }
                Mark::Ignored => v["ignored"] = json!(true),
                Mark::Unavailable => v["unavailable"] = json!(true),
            }
            v
        })
        .collect();
    let searched: Vec<(PathBuf, bool)> =
        paths.iter().map(|p| (p.clone(), Some(p.as_path()) == approved_dir.as_deref())).collect();
    let mut json = json!({
        "search_paths": paths,
        "server": { "url": remote.url, "pending": pending },
        "playbooks": playbooks,
    });
    if let Some(source) = source {
        json["source"] = json!(source.as_str());
    }
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
    fn only_a_linked_gate_node_gains_its_approval_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bd").join("bd.db");
        let init = bd_core::InitOptions { prefix: "t".into(), id_mode: bd_core::IdMode::Counter };
        let mut store = bd_core::Store::init(&path, init, bd_core::OpenOptions::default()).unwrap();
        let run = store
            .write("setup", "alice", |tx| {
                let id = tx.create_issue(bd_core::NewIssue::titled("Run"))?.id;
                Ok(bd_core::issues::get(tx.conn(), &id)?.unwrap())
            })
            .unwrap();
        let node = |id: &str, title: &str, issue_type: &str, state: StepState| bd_core::playbook::StatusNode {
            depth: 1,
            id: id.into(),
            title: title.into(),
            role: None,
            issue_type: issue_type.into(),
            status: bd_core::Status::Open,
            state,
            assignee: None,
            detail: Some("human".into()),
        };
        let status = RunStatus {
            run,
            playbook: Some("change".into()),
            progress: Default::default(),
            nodes: vec![
                node("t-2", "Approve\nforged line", "gate", StepState::Armed),
                node("t-3", "Other\ngate", "gate", StepState::Escalated),
                node("t-4", "Step", "task", StepState::Ready),
            ],
        };
        let plain = status_lines(&status, &BTreeMap::new());
        let links = BTreeMap::from([("t-2".to_string(), "https://x/bd/w/p/gates/t-2".to_string())]);
        let linked = status_lines(&status, &links);
        assert_eq!(plain.len(), linked.len());
        assert_eq!(plain[0], linked[0]);
        assert_eq!(plain[2..], linked[2..], "other nodes are unchanged");
        assert!(linked[1].ends_with(" · approve in a browser: https://x/bd/w/p/gates/t-2"), "{}", linked[1]);
        assert!(linked[1].contains("Approve\\u{a}forged line"), "{}", linked[1]);
        assert!(!linked[1].contains('\n'));
        assert!(plain[1].contains("Approve\nforged line"), "unlinked lines print as before");
    }

    #[test]
    fn the_bundle_flag_parses() {
        assert!(Cli::try_parse_from(["bd", BUNDLE_FLAG, BUNDLE_FILE, "playbook", "list"]).is_ok());
        assert!(Cli::try_parse_from(["bd", LISTING_FLAG, LISTING_FILE, "prime", "--hook", "copilot"]).is_ok());
    }

    #[test]
    fn the_server_setting_is_asked_only_where_it_changes_the_lookup() {
        use Place::{Approved, Checkout, User};
        use PlaybooksSource::{Checkout as Off, Server as On};
        // Every name among the approved (or none by name): never asked.
        for source in [Off, On] {
            for places in [&[][..], &[Approved], &[Approved, Approved]] {
                let asked = std::cell::Cell::new(false);
                let l = lookup(places, || {
                    asked.set(true);
                    source
                });
                assert_eq!((l, asked.get()), (Lookup::Everywhere, false), "{places:?} {source:?}");
            }
        }
        // Any name elsewhere, the command line's or one an approved playbook
        // extends or expands: asked once.
        for places in [&[Checkout][..], &[User], &[Approved, Checkout], &[Approved, User], &[User, Checkout]] {
            let asked = &std::cell::Cell::new(0);
            let ask = |source| {
                move || {
                    asked.set(asked.get() + 1);
                    source
                }
            };
            assert_eq!(lookup(places, ask(Off)), Lookup::Everywhere, "off: as before");
            assert_eq!(lookup(places, ask(On)), Lookup::ServerOnly, "{places:?}");
            assert_eq!(asked.get(), 2, "asked once each");
        }
        let (checkout, approved) = (Path::new("/c/.bd/playbooks"), Path::new("/c/.bd/approved/playbooks"));
        assert_eq!(place(&checkout.join("x.toml"), checkout, Some(approved)), Place::Checkout);
        assert_eq!(place(&approved.join("x.toml"), checkout, Some(approved)), Place::Approved);
        assert_eq!(place(Path::new("/home/u/.config/bd/playbooks/x.toml"), checkout, Some(approved)), Place::User);
        assert_eq!(place(&approved.join("x.toml"), checkout, None), Place::User);
    }

    #[test]
    fn the_servers_setting_is_read_strictly_and_anything_else_is_off() {
        let answer = |exit_code: i32, stdout: &str| {
            source_answer(&ExecResponse { exit_code, stdout: stdout.into(), ..Default::default() })
        };
        let on = json!({ "key": "playbooks.source", "value": "server" }).to_string();
        assert_eq!(answer(0, &on), PlaybooksSource::Server);
        assert_eq!(answer(0, &format!("{on}\n")), PlaybooksSource::Server);
        for (code, stdout) in [
            (0, json!({ "key": "playbooks.source", "value": "checkout" }).to_string()),
            // An older server: the key is unknown.
            (3, String::new()),
            (1, on.clone()),
            (0, json!({ "key": "playbooks.source", "value": "Server" }).to_string()),
            (0, json!({ "key": "playbooks.source", "value": " server" }).to_string()),
            (0, json!({ "key": "other", "value": "server" }).to_string()),
            (0, json!({ "key": "playbooks.source", "value": "server", "extra": 1 }).to_string()),
            (0, json!({ "key": "playbooks.source", "value": true }).to_string()),
            (0, json!(["server"]).to_string()),
            (0, "server".into()),
            (0, String::new()),
        ] {
            assert_eq!(answer(code, &stdout), PlaybooksSource::Checkout, "{code} {stdout}");
        }
    }

    #[test]
    fn names_resolved_outside_the_approved_are_checked_against_what_the_server_serves() {
        let approved = Path::new("/c/.bd/approved/playbooks");
        let mut b = Bundle::default();
        let mut add = |from: &str, reference: &str, to: &str| {
            b.refs.entry(from.into()).or_default().insert(reference.into(), to.into());
        };
        add("", "change", "/home/u/bd/playbooks/change.toml");
        add("/home/u/bd/playbooks/change.toml", "base", "/c/.bd/approved/playbooks/base.toml");
        add("/home/u/bd/playbooks/change.toml", "./part.toml", "/home/u/bd/playbooks/part.toml");
        add("/c/.bd/approved/playbooks/base.toml", " review ", "/home/u/bd/playbooks/review.toml");
        assert_eq!(names_outside(&b, Some(approved)), ["change", "review"], "by name, outside the approved");
        assert_eq!(names_outside(&b, None), ["base", "change", "review"]);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("parts")).unwrap();
        std::fs::write(dir.path().join("change.toml"), "[[steps]]\nid = \"a\"\n").unwrap();
        std::fs::write(dir.path().join("parts/review.toml"), "[[steps]]\nid = \"a\"\n").unwrap();
        let manifest = bd_core::agents::PlaybookSet::load(dir.path()).unwrap().manifest();
        assert!(serves(&manifest, "change"));
        assert!(serves(&manifest, "CHANGE") && serves(&manifest, "Change"), "case aside");
        assert!(!serves(&manifest, "review"), "a name finds top-level files only");
        assert!(!serves(&manifest, "chan") && !serves(&manifest, "change.toml"));
        let paths = ["Deploy.formula.json".to_string(), "x/deploy.toml".to_string()];
        assert!(served_name(paths.iter(), "deploy") && !served_name(paths[1..].iter(), "deploy"));
    }

    #[test]
    fn a_manifest_that_cannot_be_read_fails_closed_saying_why() {
        for (e, code) in [
            (Error::Remote("unreachable".into()), 8),
            (Error::AnswerLost("lost".into()), 8),
            (Error::Unauthorized("no".into()), 7),
            (Error::invalid("bad answer"), 2),
        ] {
            let e = manifest_unread(e);
            assert_eq!(e.exit_code(), code, "{e}");
            assert!(e.to_string().contains("the bd server's list of its playbooks could not be read"), "{e}");
        }
    }

    #[test]
    fn the_ignored_copy_warning_is_escaped() {
        let w = ignored_warning(Path::new(".bd/playbooks/x\u{1b}[2J\u{202e}.toml"));
        assert!(
            w.starts_with("warning: ignoring .bd/playbooks/x\\u{1b}[2J\\u{202e}.toml (playbooks.source = server"),
            "{w}"
        );
        assert!(!w.chars().any(|c| c.is_control() || c == '\u{202e}'), "{w}");
    }

    #[test]
    fn the_checkout_copies_of_the_names_looked_up_are_each_named_once() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        std::fs::write(dir.join("review.toml"), "[[steps]]\nid = \"review\"\n").unwrap();
        // A copy that does not load is found all the same.
        std::fs::write(dir.join("base.toml"), "[[steps]]\nbogus = 1\n").unwrap();
        std::fs::write(dir.join("unused.toml"), "[[steps]]\nid = \"unused\"\n").unwrap();
        assert_eq!(
            checkout_copies(dir, ["review", "base", "review", "absent"]),
            vec![dir.join("base.toml"), dir.join("review.toml")]
        );
        assert!(checkout_copies(dir, std::iter::empty()).is_empty());
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
