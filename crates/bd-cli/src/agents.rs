//! `bd agents ...`: the skills and MCP server definitions a workspace serves
//! to agent harnesses ([`bd_core::agents`]), and the checkouts that use them.
//!
//! `manifest` and `fetch` read the workspace's own `.bd/agents`, next to its
//! database (under bd serve, `<root>/<ws>/.bd/agents` on the server); in a
//! remote workspace they run on the server, as any read does.
//!
//! `status`, `pull`, `approve` and `watch` work on a checkout, on the machine that
//! holds it: the directory holding the `.bd` that configures a remote
//! workspace (next to `remote.toml`, else the nearest `.bd`), or the local
//! workspace's `.bd`. In a remote workspace the client reads the server's
//! sets (`agents manifest`, then `agents fetch` for a set whose contents it
//! needs, a read token being enough) and checks them before use; a local
//! workspace reads its own `.bd/agents`. bd serve refuses these commands.
//!
//! # Which harnesses
//!
//! Those named with `--harness`; else the harnesses of the running agent
//! session, from their session id variables (`$CLAUDE_CODE_SESSION_ID`,
//! `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`; a session inside another
//! sets several, and gets each); else those `.bd/agents.lock` records
//! (`approve`, which refuses agent sessions, goes from `--harness` to the lock). Each
//! harness's set goes to its own places only ([`Harness::skills_dest`],
//! [`Harness::mcp_dest`]): a copilot pull leaves the claude and codex ones alone.
//!
//! # What a pull does
//!
//! `.bd/agents.lock` ([`lock`]) records each skill file and MCP server entry
//! bd wrote or adopted. A pull makes the checkout hold the server's set:
//!
//! - It writes the server's skill files (each at once, through a temp file;
//!   executable ones get their executable bits on Unix, and so does a file
//!   adopted or kept with the server's text but without them), restores
//!   the ones bd wrote that were deleted, and deletes those the server
//!   removed, with the directories that leaves empty below the skills
//!   directory, before it writes anything: a file the server renamed only
//!   in case is written under its new name where the file system ignores
//!   case, and a file can become a directory of the same name, or the other
//!   way round.
//! - A file or entry bd did not record that already matches the server's
//!   is adopted: recorded, not written (a fresh clone of committed files).
//!   One that differs is a conflict, reported and left alone.
//! - A file or entry bd wrote that was edited here is kept: reported as
//!   edited, or as a conflict when the server changed or removed it (a
//!   change of a file's executable bit alone is applied to the edited file).
//!   `--force` replaces or removes such edits; it never touches what bd did
//!   not write.
//! - It never follows a symlink at or below a skill's directory (the skills
//!   directory and its parents may be symlinks), nor writes an MCP file
//!   that is a symlink: those are conflicts.
//! - New and changed MCP definitions are never written: they wait for the
//!   user's approval (`bd agents approve`), even with `--force`, as a stdio
//!   definition is a command the client runs. Removals of entries bd wrote
//!   apply at once, and so does writing an approved definition back where
//!   it was deleted. The MCP file keeps everything else ([`mcp_file`]).
//! - It lists the environment variables the MCP definitions read (in
//!   effect or waiting) that are unset here: names only, as MCP servers
//!   authenticate on the client and bd never handles their credentials.
//!
//! `status` reports what a pull would do and changes nothing. `approve`
//! ([`approve`]) shows each new or changed MCP definition waiting (all, or
//! those named; rendered by [`show`], never printed as the server sent it,
//! long values cut short unless `--full`), asks y/N on the terminal, and
//! writes those approved as
//! they were shown, recording them in the lock; it never replaces an entry
//! bd did not write (a conflict), nor one changed here since it was shown.
//! It refuses to run inside an agent session or without a terminal on
//! stdin. Changes to a
//! checkout are serialized by its mutex ([`checkout`]). When nothing
//! changed, either command makes one request of the server (the manifests);
//! a set is fetched whole only when files are to be written or MCP changes
//! shown.
//!
//! `bd hook session-start` pulls for the harness starting a session, within
//! a few seconds, and tells the session what changed and what waits for
//! approval ([`hook`]). `bd agents watch` pulls each time the workspace's
//! sets change, until interrupted, printing each pull's report ([`watch`]).
//!
//! # Output
//!
//! Text output has a line per finding and harness (`claude: skills updated:
//! deploy, triage`), or `<harness>: up to date`. With `--json`, both print
//! (and `watch`, for each pull, on one line):
//!
//! ```json
//! {
//!   "applied": true,
//!   "checkout": "/home/me/proj",
//!   "harnesses": {
//!     "claude": {
//!       "server_revision": "<sha256>",
//!       "applied_revision": "<sha256>",
//!       "skills": {
//!         "changed": {"deploy": "updated", "triage": "added"},
//!         "added": [{"skill": "triage", "path": ".claude/skills/triage/SKILL.md"}],
//!         "updated": [{"skill": "deploy", "path": ".claude/skills/deploy/SKILL.md"}],
//!         "restored": [], "replaced": [], "removed": [], "adopted": [], "edited": [],
//!         "conflicts": [{"skill": "lint", "path": ".claude/skills/lint/SKILL.md", "reason": "..."}],
//!         "left": []
//!       },
//!       "mcp": {
//!         "file": ".mcp.json",
//!         "pending": [
//!           {"name": "github", "change": "changed", "fields": ["args"], "edited": false},
//!           {"name": "linear", "change": "new", "fields": [], "edited": false}
//!         ],
//!         "removed": ["old"], "restored": [], "replaced": [], "adopted": [], "edited": [],
//!         "conflicts": [{"name": null, "reason": ".mcp.json: not valid JSON (...); ..."}]
//!       },
//!       "unset_env": ["GITHUB_TOKEN"]
//!     }
//!   }
//! }
//! ```
//!
//! `applied` is `true` for a pull (the changes listed were made) and
//! `false` for status (they would be). Per harness:
//!
//! - `server_revision` is the revision of the server's set;
//!   `applied_revision` the one the checkout last pulled (`null`: never).
//! - `skills`: `changed` maps each skill with files written or removed to
//!   `added` (new here), `updated`, `removed` (gone from the server),
//!   `restored` (deleted files written again) or `replaced` (`--force`);
//!   the other lists name each file (`skill`, checkout-relative `path`):
//!   `updated` also lists files whose executable bit alone was set or
//!   cleared, `adopted` were already the server's, `edited` are local edits kept,
//!   `conflicts` are in the way (`path` is what is in the way: the file, or
//!   a directory or symlink above it), `left` stay where the server removed
//!   something.
//! - `mcp`: `pending` entries wait for approval, `new` or `changed` (with
//!   the top-level `fields` that differ from the definition approved
//!   before, and whether the entry was `edited` here since); `removed`,
//!   `restored`, `replaced`, `adopted` and `edited` name entries;
//!   `conflicts` name an entry, or `null` for the whole file.
//! - `unset_env`: the variables the MCP definitions read that are unset or
//!   empty here.
//!
//! `approve` shows each entry and its prompt on stderr; then its text
//! output has a line per outcome and harness (`claude: approved github:
//! written to .mcp.json`, `claude: declined linear: still waiting for
//! approval`), the conflicts, and how to load what was approved. With
//! `--json`, once the answers are in, it prints:
//!
//! ```json
//! {
//!   "checkout": "/home/me/proj",
//!   "harnesses": {
//!     "claude": {
//!       "file": ".mcp.json",
//!       "approved": ["github"],
//!       "declined": ["linear"],
//!       "skipped": [{"name": "docs", "reason": "its entry in .mcp.json or .bd/agents.lock changed since it was shown; ..."}],
//!       "conflicts": [{"name": "mine", "reason": "in .mcp.json, differs from the server's and was not written by bd; ..."}]
//!     }
//!   }
//! }
//! ```
//!
//! `approved` entries were written and recorded; `declined` ones still
//! wait; `skipped` are those not asked about (a name given that waits for
//! nothing: up to date, removed, a conflict) or not written (changed here
//! since they were shown, or in an MCP file bd does not write); `conflicts`
//! are as in `status`.
//!
//! # Exit codes
//!
//! 0 when the command did its work: MCP changes waiting for approval,
//! conflicts and local edits are findings, not failures, and so are
//! declined and skipped approvals. 2: no harness to work on, no checkout,
//! or an unusable `.bd/agents.lock`; for `approve`, also inside an agent
//! session, without a terminal on stdin (with entries to ask about), or a
//! name that is neither served nor recorded; 3: no workspace;
//! 5: another bd process kept the checkout's mutex past `--busy-timeout-ms`;
//! 7: the access token was refused; 8: the server was unreachable or sent
//! an answer that fails its checks (nothing was written). `watch` runs until
//! interrupted (exit 0); once running, only a refused token ends it (7),
//! and other failures are reported and tried again.

pub mod approve;
pub mod checkout;
pub mod hook;
pub mod lock;
pub mod mcp_file;
pub mod show;
pub mod sync;
pub mod watch;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use bd_core::agents::{AGENTS_DIR, AgentSet, Harness, Manifest};
use bd_core::{Error, Result};

use crate::actor;
use crate::app::{App, Out};
use crate::cli::{AgentsCommand, AgentsFetchArgs, AgentsManifestArgs};
use crate::io;
use crate::playbooks;
use crate::remote::{self, Remote};
use checkout::Checkout;
use sync::{HarnessReport, Options, PendingChange, Report, SkillChange, Source};

/// The workspace's agents directory, next to its database.
pub fn agents_dir(app: &App) -> Result<PathBuf> {
    let db = app.db_path()?;
    Ok(db.parent().map_or_else(|| PathBuf::from(AGENTS_DIR), |d| d.join(AGENTS_DIR)))
}

pub fn cmd_agents(app: &mut App, cmd: &AgentsCommand) -> Result<()> {
    match cmd {
        AgentsCommand::Manifest(a) => cmd_manifest(app, a),
        AgentsCommand::Fetch(a) => cmd_fetch(app, a),
        AgentsCommand::Status(a) => cmd_sync(app, None, &a.harnesses, false, false),
        AgentsCommand::Pull(a) => cmd_sync(app, None, &a.harnesses, true, a.force),
        AgentsCommand::Approve(a) => approve::cmd_approve(app, None, a),
        AgentsCommand::Watch(a) => watch::cmd_watch(app, None, a),
    }
}

/// Runs `status`, `pull` and `approve` in a remote workspace, where the client reads
/// the server's sets itself. `None`: the server runs the command.
pub fn client_command(app: &App, remote: &Remote, cmd: &AgentsCommand) -> Result<Option<i32>> {
    match cmd {
        AgentsCommand::Status(a) => cmd_sync(app, Some(remote), &a.harnesses, false, false).map(|()| Some(0)),
        AgentsCommand::Pull(a) => cmd_sync(app, Some(remote), &a.harnesses, true, a.force).map(|()| Some(0)),
        AgentsCommand::Approve(a) => approve::cmd_approve(app, Some(remote), a).map(|()| Some(0)),
        AgentsCommand::Watch(a) => watch::cmd_watch(app, Some(remote), a).map(|()| Some(0)),
        AgentsCommand::Manifest(_) | AgentsCommand::Fetch(_) => Ok(None),
    }
}

/// With `--json`, `{"<harness>": <Manifest>, ...}` for each harness asked for.
fn cmd_manifest(app: &mut App, a: &AgentsManifestArgs) -> Result<()> {
    let dir = agents_dir(app)?;
    let harnesses = if a.harnesses.is_empty() { Harness::ALL.to_vec() } else { a.harnesses.clone() };
    let mut manifests = BTreeMap::new();
    for h in harnesses {
        manifests.insert(h, AgentSet::load(&dir, h)?.manifest());
    }
    let mut out = Out::new(&manifests);
    for (h, m) in &manifests {
        out = out.id(format!("{h} {}", m.revision)).lines(manifest_lines(m));
    }
    app.print(out);
    Ok(())
}

fn manifest_lines(m: &Manifest) -> Vec<String> {
    let h = m.harness;
    if m.is_empty() {
        return vec![format!("{h}: nothing served")];
    }
    let revision = m.revision.get(..12).unwrap_or(&m.revision);
    let mut lines =
        vec![format!("{h}: revision {revision} (clients place it in {}/ and {})", h.skills_dest(), h.mcp_dest())];
    for (name, files) in &m.skills {
        let n = files.len();
        lines.push(format!("  skill {name} ({n} file{})", if n == 1 { "" } else { "s" }));
    }
    for name in m.mcp_servers.keys() {
        lines.push(format!("  MCP server {name}"));
    }
    lines
}

/// Always JSON, on one line: an [`AgentSet`].
fn cmd_fetch(app: &mut App, a: &AgentsFetchArgs) -> Result<()> {
    let set = AgentSet::load(&agents_dir(app)?, a.harness)?;
    io::outln(serde_json::to_string(&set)?);
    Ok(())
}

fn cmd_sync(app: &App, remote: Option<&Remote>, requested: &[Harness], apply: bool, force: bool) -> Result<()> {
    io::require_local(if apply { "bd agents pull" } else { "bd agents status" })?;
    let checkout = find_checkout(app, remote.is_some())?;
    let harnesses = harnesses(requested, &checkout)?;
    let opts = Options { apply, force, lock_wait: Duration::from_millis(app.g.busy_timeout_ms) };
    let report = sync_checkout(app, remote, &checkout, &harnesses, opts)?;
    app.print(render(&report));
    Ok(())
}

/// Compare `checkout` with the workspace's sets for `harnesses` and, with
/// `opts.apply`, bring it up to date (see the [module docs](self)): from
/// the server of a remote workspace (whose settings bound the time it
/// takes: a session hook passes [`Remote::quick`]), else from the local
/// workspace's own `.bd/agents`.
pub fn sync_checkout(
    app: &App,
    remote: Option<&Remote>,
    checkout: &Checkout,
    harnesses: &[Harness],
    opts: Options,
) -> Result<Report> {
    match remote {
        Some(remote) => sync::run(checkout, &mut RemoteSource { app, remote }, harnesses, opts),
        None => {
            let mut source = LocalSource { dir: agents_dir(app)?, loaded: BTreeMap::new() };
            sync::run(checkout, &mut source, harnesses, opts)
        }
    }
}

/// The checkout `status` and `pull` work on: in a `remote` workspace, the
/// directory holding the `.bd` that configures it (next to `remote.toml`,
/// else the nearest `.bd`); in a local one, the directory holding the
/// workspace's `.bd`.
pub fn find_checkout(app: &App, remote: bool) -> Result<Checkout> {
    let bd = if remote {
        playbooks::checkout_bd(app)?.ok_or_else(|| {
            Error::invalid(format!(
                "no .bd directory in {} or above it: agent assets go into a checkout, found by its .bd directory \
                 (`bd remote set <url>` at the checkout's root makes one)",
                app.cwd.display()
            ))
        })?
    } else {
        let db = app.db_path()?;
        match db.parent() {
            Some(dir) if dir.file_name().is_some_and(|n| n == ".bd") => dir.to_path_buf(),
            _ => {
                return Err(Error::invalid(format!(
                    "{}: agent assets go into the checkout holding the workspace's .bd directory, and this database \
                     is not in one",
                    db.display()
                )));
            }
        }
    };
    Ok(Checkout::new(bd))
}

/// The harnesses to work on: those asked for; else the running agent
/// session's; else those `.bd/agents.lock` records.
pub fn harnesses(requested: &[Harness], checkout: &Checkout) -> Result<Vec<Harness>> {
    let mut chosen: Vec<Harness> = requested.to_vec();
    if chosen.is_empty() {
        chosen = session_harnesses();
    }
    if chosen.is_empty() {
        chosen = checkout.read_lock()?.harnesses.into_keys().collect();
    }
    if chosen.is_empty() {
        return Err(Error::invalid(
            "no agent harness to work on: pass --harness claude, codex or copilot (no agent session's id is set, \
             and .bd/agents.lock records none)",
        ));
    }
    chosen.sort();
    chosen.dedup();
    Ok(chosen)
}

/// The harnesses whose agent session runs this command, from the session
/// id variables they set ([`actor::HARNESSES`]): several in a session
/// started from another one's shell.
pub fn session_harnesses() -> Vec<Harness> {
    actor::HARNESSES
        .iter()
        .filter(|(_, vars)| vars.iter().any(|v| actor::env(v).is_some()))
        .filter_map(|(prefix, _)| prefix.parse().ok())
        .collect()
}

/// A local workspace's own sets.
struct LocalSource {
    dir: PathBuf,
    /// The sets read for their manifests, kept for a fetch.
    loaded: BTreeMap<Harness, AgentSet>,
}

impl Source for LocalSource {
    fn manifests(&mut self, harnesses: &[Harness]) -> Result<BTreeMap<Harness, Manifest>> {
        let mut manifests = BTreeMap::new();
        for &h in harnesses {
            let set = AgentSet::load(&self.dir, h)?;
            manifests.insert(h, set.manifest());
            self.loaded.insert(h, set);
        }
        Ok(manifests)
    }

    fn fetch(&mut self, harness: Harness) -> Result<AgentSet> {
        match self.loaded.remove(&harness) {
            Some(set) => Ok(set),
            None => AgentSet::load(&self.dir, harness),
        }
    }
}

/// A remote workspace's sets, read from its server and checked here.
struct RemoteSource<'a> {
    app: &'a App,
    remote: &'a Remote,
}

impl RemoteSource<'_> {
    fn read(&self, argv: &[&str]) -> Result<String> {
        let response = playbooks::server_read(self.app, self.remote, argv.iter().map(|a| a.to_string()).collect())?;
        if response.exit_code != 0 {
            return Err(remote::response_error(&response, &self.remote.url));
        }
        Ok(response.stdout)
    }

    fn unusable(&self, what: &str, e: &dyn std::fmt::Display) -> Error {
        Error::Remote(format!("{}: the server's {what} is unusable, so nothing was written: {e}", self.remote.url))
    }
}

impl Source for RemoteSource<'_> {
    fn manifests(&mut self, harnesses: &[Harness]) -> Result<BTreeMap<Harness, Manifest>> {
        let list = harnesses.iter().map(|h| h.name()).collect::<Vec<_>>().join(",");
        let stdout = self.read(&["--json", "agents", "manifest", "--harness", &list])?;
        let manifests: BTreeMap<Harness, Manifest> =
            serde_json::from_str(&stdout).map_err(|e| self.unusable("agents manifest", &e))?;
        let asked: Vec<Harness> = harnesses.to_vec();
        if manifests.len() != asked.len() || asked.iter().any(|h| !manifests.contains_key(h)) {
            let sent: Vec<&str> = manifests.keys().map(|h| h.name()).collect();
            return Err(
                self.unusable("agents manifest", &format!("manifests for {} instead of {list}", sent.join(",")))
            );
        }
        for (h, m) in &manifests {
            if m.harness != *h {
                return Err(self.unusable("agents manifest", &format!("a {} manifest as the {h} one", m.harness)));
            }
            m.check().map_err(|e| self.unusable(&format!("{h} manifest"), &e))?;
        }
        Ok(manifests)
    }

    fn fetch(&mut self, harness: Harness) -> Result<AgentSet> {
        let what = format!("{harness} set");
        let stdout = self.read(&["agents", "fetch", "--harness", harness.name()])?;
        let set: AgentSet = serde_json::from_str(&stdout).map_err(|e| self.unusable(&what, &e))?;
        if set.harness != harness {
            return Err(self.unusable(&what, &format!("a {} set instead", set.harness)));
        }
        set.check().map_err(|e| self.unusable(&what, &e))?;
        Ok(set)
    }
}

/// What `status` and `pull` print: a line per finding and harness.
fn render(report: &Report) -> Out {
    let mut out = Out::new(report);
    for (h, r) in &report.harnesses {
        out = out.lines(harness_lines(*h, r, report.applied));
    }
    out
}

fn harness_lines(h: Harness, r: &HarnessReport, applied: bool) -> Vec<String> {
    let (s, m) = (&r.skills, &r.mcp);
    let mut lines = Vec::new();
    let mut parts = Vec::new();
    for (change, done, todo) in [
        (SkillChange::Added, "added", "to add"),
        (SkillChange::Updated, "updated", "to update"),
        (SkillChange::Removed, "removed", "to remove"),
        (SkillChange::Restored, "restored", "to restore"),
        (SkillChange::Replaced, "replaced over local edits", "to replace over local edits"),
    ] {
        let names: Vec<&str> = s.changed.iter().filter(|(_, c)| **c == change).map(|(n, _)| n.as_str()).collect();
        if !names.is_empty() {
            parts.push(format!("{}: {}", if applied { done } else { todo }, names.join(", ")));
        }
    }
    if !parts.is_empty() {
        lines.push(format!("{h}: skills {}", parts.join("; ")));
    }
    if !s.edited.is_empty() {
        let paths: Vec<&str> = s.edited.iter().map(|f| f.path.as_str()).collect();
        lines.push(format!("{h}: local edits kept: {}", paths.join(", ")));
    }
    for c in &s.conflicts {
        lines.push(format!("{h}: conflict: {}: {}", c.path, c.reason));
    }
    for c in &s.left {
        lines.push(format!("{h}: left in place: {}: {}", c.path, c.reason));
    }
    if !m.pending.is_empty() {
        let entries: Vec<String> = m
            .pending
            .iter()
            .map(|p| {
                let mut notes: Vec<String> = p.fields.iter().map(|f| show::field(f)).collect();
                if p.edited {
                    notes.push("edited here".into());
                }
                let change = match p.change {
                    PendingChange::New => "new",
                    PendingChange::Changed => "changed",
                };
                let name = show::field(&p.name);
                match notes.is_empty() {
                    true => format!("{name} {change}"),
                    false => format!("{name} {change} ({})", notes.join(", ")),
                }
            })
            .collect();
        lines.push(format!(
            "{h}: MCP {}: not applied; review and approve with `bd agents approve` in a terminal",
            entries.join(", ")
        ));
    }
    for (names, done, todo) in [
        (&m.removed, "removed from", "to remove from"),
        (&m.restored, "restored in", "to restore in"),
        (&m.replaced, "replaced over local edits in", "to replace over local edits in"),
    ] {
        if !names.is_empty() {
            lines.push(format!("{h}: MCP {} {}: {}", if applied { done } else { todo }, m.file, names.join(", ")));
        }
    }
    if !m.edited.is_empty() {
        lines.push(format!("{h}: MCP local edits kept in {}: {}", m.file, m.edited.join(", ")));
    }
    for c in &m.conflicts {
        match &c.name {
            Some(name) => lines.push(format!("{h}: conflict: {} {name}: {}", m.file, c.reason)),
            None => lines.push(format!("{h}: conflict: {}", c.reason)),
        }
    }
    if lines.is_empty() {
        lines.push(if r.server_revision == AgentSet::empty(h).revision {
            format!("{h}: nothing served")
        } else if applied {
            format!("{h}: up to date")
        } else {
            format!("{h}: up to date (revision {})", r.server_revision.get(..12).unwrap_or_default())
        });
    }
    if !r.unset_env.is_empty() {
        lines.push(format!("{h}: unset environment variables the MCP servers read: {}", r.unset_env.join(", ")));
    }
    // Names and paths are checked, and reasons are bd's own, but they may quote what a file or server holds.
    lines.iter().map(|l| show::printable(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{McpConflict, Pending};

    #[test]
    fn status_text_escapes_what_a_server_or_file_could_put_in_it() {
        let mut r = HarnessReport { server_revision: "r".repeat(64), ..Default::default() };
        r.mcp.file = ".mcp.json".into();
        r.mcp.pending.push(Pending {
            name: "github".into(),
            change: PendingChange::Changed,
            fields: vec!["a\nclaude: up to date\n".into(), "\u{1b}[2K\u{202e}".into(), "args".into()],
            edited: true,
            approved: None,
            server: None,
            local: None,
        });
        let reason = "not valid JSON (\u{1b}]0;title\u{7} at line 1)".to_string();
        r.mcp.conflicts.push(McpConflict { name: None, reason, foreign: false });
        let lines = harness_lines(Harness::Claude, &r, false);
        assert_eq!(
            lines,
            [
                r#"claude: MCP github changed ("a\nclaude: up to date\n", "\u{1b}[2K\u{202e}", args, edited here): not applied; review and approve with `bd agents approve` in a terminal"#,
                r"claude: conflict: not valid JSON (\u{1b}]0;title\u{7} at line 1)",
            ]
        );
        for line in &lines {
            assert!(!line.contains(|c: char| c.is_control()), "{line:?}");
        }
    }
}
