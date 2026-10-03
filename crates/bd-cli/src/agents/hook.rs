//! The agent assets part of `bd hook session-start`: at the start of each
//! agent session, bring the checkout's skills up to date and say what the
//! session needs to know, in a few lines of context.
//!
//! It is a pull ([`super::sync`]) for the harness running the hook (or the
//! session's, or those `.bd/agents.lock` records): skill files and MCP
//! entries the server removed go, and those deleted here are restored as
//! approved (none of which adds anything that runs), while new and changed
//! skills and MCP definitions are only reported, for the user to approve
//! with `bd agents approve` in a separate terminal. It never approves,
//! prompts or reads the terminal.
//!
//! It says nothing when nothing changed, outside a checkout, and when no
//! harness is known. A problem (the server unreachable or stalling, the
//! token missing or refused, the checkout's mutex busy, an answer that
//! fails its checks) is one line of context, never a failed hook.
//!
//! The whole hook gets [`HOOK_BUDGET`] from the start of its process:
//! reading its input (at most [`crate::hook::INPUT_WAIT`]), then the server
//! (all its requests, retries included, against one deadline, even when it
//! accepts the connection and never answers), then another bd process
//! changing the checkout, each from what is left ([`budgets`]), with small
//! floors so a slow start still leaves time to try. Files are written only
//! once the server's answers are in and checked, under the checkout's
//! mutex, so running out of time leaves nothing half written.
//!
//! Every line goes through [`show::printable`]: names are checked where
//! they are read, but reasons may quote what a server or a file holds.

use std::time::{Duration, Instant};

use bd_core::Result;
use bd_core::agents::{Harness, under};

use super::show;
use super::sync::{HarnessReport, Options, PendingChange, Report, SkillChange};
use crate::app::App;
use crate::remote;

/// The time the whole hook takes at most, from the start of its process
/// (beyond the floors below, and the local writes of a pull).
pub const HOOK_BUDGET: Duration = Duration::from_secs(5);
/// The longest wait for another bd process changing the same checkout.
const MAX_LOCK_WAIT: Duration = Duration::from_secs(1);
/// What the server and the mutex wait get however little is left.
const MIN_SERVER: Duration = Duration::from_secs(1);
const MIN_LOCK_WAIT: Duration = Duration::from_millis(200);

/// What is left of [`HOOK_BUDGET`] for the server, never less than its
/// floor: `bd prime` in a session hook bounds its request with it.
pub fn server_budget(app: &App) -> Duration {
    (app.started + HOOK_BUDGET).saturating_duration_since(Instant::now()).max(MIN_SERVER)
}

/// The server's time, and the wait for the checkout's mutex, out of `left`
/// of [`HOOK_BUDGET`]: a fifth for the mutex (one second at most), the rest
/// for the server; never less than the floors.
fn budgets(left: Duration) -> (Duration, Duration) {
    let lock = (left / 5).clamp(MIN_LOCK_WAIT, MAX_LOCK_WAIT);
    let server = left.saturating_sub(lock).max(MIN_SERVER);
    (server, left.saturating_sub(server).clamp(MIN_LOCK_WAIT, lock))
}

/// The lines of context for an agent session that `harness` (`None`: the
/// session's, else the lock's) starts in this checkout.
pub fn session_start(app: &App, harness: Option<Harness>) -> Vec<String> {
    match check(app, harness) {
        Ok(lines) => lines,
        Err(e) => {
            vec![show::cap_line(show::printable(&format!("bd: agent skills and MCP definitions not checked: {e}")))]
        }
    }
}

fn check(app: &App, requested: Option<Harness>) -> Result<Vec<String>> {
    let remote = remote::configured(app)?.is_some();
    let Ok(checkout) = super::find_checkout(app, remote) else { return Ok(Vec::new()) };
    let mut harnesses = match requested {
        Some(h) => vec![h],
        None => match super::session_harnesses() {
            session if !session.is_empty() => session,
            _ => checkout.read_lock()?.harnesses.into_keys().collect(),
        },
    };
    if harnesses.is_empty() {
        return Ok(Vec::new());
    }
    harnesses.sort();
    harnesses.dedup();
    let deadline = app.started + HOOK_BUDGET;
    let (server, lock_wait) = budgets(deadline.saturating_duration_since(Instant::now()));
    let remote = if remote { remote::detect(app)?.map(|r| r.quick().within(server)) } else { None };
    let skills_dir = |h: Harness| under(&checkout.root, h.skills_dest());
    let absent: Vec<Harness> = harnesses.iter().copied().filter(|&h| !skills_dir(h).exists()).collect();
    let opts = Options { apply: true, force: false, review: false, lock_wait };
    let report = super::sync_checkout(app, remote.as_ref(), &checkout, &harnesses, opts)?;
    let source = if remote.is_some() { Source::Server } else { Source::Workspace };
    Ok(lines(&report, source, |h| absent.contains(&h) && skills_dir(h).is_dir()))
}

#[derive(Clone, Copy)]
enum Source {
    Server,
    Workspace,
}

impl Source {
    fn from(self) -> &'static str {
        match self {
            Source::Server => "from the bd server",
            Source::Workspace => "from the workspace's .bd/agents",
        }
    }

    fn on(self) -> &'static str {
        match self {
            Source::Server => "on the bd server",
            Source::Workspace => "in the workspace's .bd/agents",
        }
    }
}

/// What to tell the session about `report`; `created` says whether this
/// pull created a harness's skills directory.
fn lines(report: &Report, source: Source, created: impl Fn(Harness) -> bool) -> Vec<String> {
    let several = report.harnesses.len() > 1;
    let mut lines = Vec::new();
    for (&h, r) in &report.harnesses {
        let tag = if several { format!("{h} ") } else { String::new() };
        lines.extend(harness_lines(h, r, &tag, source, created(h)));
    }
    lines.iter().map(|l| show::printable(l)).collect()
}

fn harness_lines(h: Harness, r: &HarnessReport, tag: &str, source: Source, created: bool) -> Vec<String> {
    let (s, m) = (&r.skills, &r.mcp);
    let mut lines = Vec::new();
    if !s.changed.is_empty() {
        let skills: Vec<String> = s.changed.iter().map(|(name, c)| format!("{name} ({})", skill_change(*c))).collect();
        lines.push(format!("bd: {tag}agent skills updated {}: {}.", source.from(), skills.join(", ")));
        lines.extend(skills_reload(h, created));
    }
    let applied: Vec<String> = (m.removed.iter().map(|n| (n, "removed")))
        .chain(m.restored.iter().map(|n| (n, "restored")))
        .map(|(name, what)| format!("{} ({what})", show::field(name)))
        .collect();
    if !applied.is_empty() {
        lines.push(format!(
            "bd: {tag}MCP server definitions applied to {}: {}. {}",
            m.file,
            applied.join(", "),
            mcp_reload(h)
        ));
    }
    if !s.pending.is_empty() {
        let skills: Vec<String> = s.pending.iter().map(|(name, p)| format!("{name} ({})", p.summary())).collect();
        lines.push(format!(
            "bd: {tag}agent skills changed {} and not applied: {}. Ask the user to review them and run `bd agents \
             approve` in a separate terminal.",
            source.on(),
            skills.join(", ")
        ));
    }
    if !m.pending.is_empty() {
        let entries: Vec<String> = m
            .pending
            .iter()
            .map(|p| {
                let mut what = match p.change {
                    PendingChange::New => "new".to_string(),
                    PendingChange::Changed if p.fields.is_empty() => "changed".to_string(),
                    PendingChange::Changed => {
                        let fields: Vec<String> = p.fields.iter().map(|f| show::field(f)).collect();
                        format!("changed: {}", fields.join(", "))
                    }
                };
                if p.edited {
                    what.push_str("; edited here");
                }
                format!("{} ({what})", show::field(&p.name))
            })
            .collect();
        lines.push(format!(
            "bd: {tag}MCP server definitions changed {} and not applied: {}. Ask the user to review them and run `bd \
             agents approve` in a separate terminal.",
            source.on(),
            entries.join(", ")
        ));
    }
    let conflicts = s.conflicts.len() + m.conflicts.len();
    if conflicts > 0 {
        let (n, them) = if conflicts == 1 { ("conflict", "it") } else { ("conflicts", "them") };
        lines.push(format!(
            "bd: {tag}{conflicts} agent asset {n} (files or MCP entries in the way, left as they are): `bd agents \
             status` lists {them}."
        ));
    }
    if (!applied.is_empty() || !m.pending.is_empty()) && !r.unset_env.is_empty() {
        lines.push(format!(
            "bd: {tag}environment variables the MCP servers read are unset: {}.",
            r.unset_env.join(", ")
        ));
    }
    lines
}

fn skill_change(c: SkillChange) -> &'static str {
    match c {
        SkillChange::Added => "added",
        SkillChange::Updated => "updated",
        SkillChange::Removed => "removed",
        SkillChange::Restored => "restored",
        SkillChange::Replaced => "replaced",
    }
}

/// How the session gets skills changed at its start. None of the three
/// harnesses lists them on its first turn (checked with Claude Code
/// 2.1.287, Codex 0.155.1 and Copilot CLI 1.0.91); Codex picks them up by
/// itself.
fn skills_reload(h: Harness, created: bool) -> Option<String> {
    match h {
        Harness::Copilot => Some(
            "bd: Copilot CLI read its skills before this hook ran: ask the user to run `/skills reload` to use these \
             in this session."
                .into(),
        ),
        Harness::Claude if created => Some(
            "bd: Claude Code watches .claude/skills only when it exists at session start: ask the user to run \
             `/reload-skills` to use these in this session."
                .into(),
        ),
        Harness::Claude => {
            Some("bd: if these skills are not available yet, ask the user to run `/reload-skills`.".into())
        }
        Harness::Codex => None,
    }
}

fn mcp_reload(h: Harness) -> &'static str {
    match h {
        Harness::Copilot => "Ask the user to run `/mcp reload` to apply the change.",
        Harness::Claude => "Ask the user to restart Claude Code to apply the change.",
        Harness::Codex => "Ask the user to restart Codex to apply the change.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::sync::{Conflict, McpConflict, Pending, PendingFile, PendingFileChange, PendingSkill};

    #[test]
    fn the_server_and_the_mutex_share_what_is_left_of_the_hooks_time() {
        let ms = Duration::from_millis;
        assert_eq!(budgets(HOOK_BUDGET), (ms(4000), ms(1000)), "a hook that started at once");
        // Its input took the longest it waits.
        let left = HOOK_BUDGET - crate::hook::INPUT_WAIT;
        let (server, lock) = budgets(left);
        assert_eq!((server, lock), (ms(2400), ms(600)));
        for left in [HOOK_BUDGET, left, ms(1500), ms(1240), MIN_SERVER + MIN_LOCK_WAIT] {
            let (server, lock) = budgets(left);
            assert!(server + lock <= left && server >= MIN_SERVER && lock >= MIN_LOCK_WAIT, "{left:?}");
        }
        // Nothing left: the floors, so the hook still tries.
        for left in [ms(1000), ms(0)] {
            assert_eq!(budgets(left), (MIN_SERVER, MIN_LOCK_WAIT), "{left:?}");
        }
    }

    fn report(harnesses: Vec<(Harness, HarnessReport)>) -> Report {
        Report { applied: true, checkout: Default::default(), harnesses: harnesses.into_iter().collect() }
    }

    #[test]
    fn nothing_changed_says_nothing() {
        let mut r = HarnessReport { unset_env: vec!["GITHUB_TOKEN".into()], ..Default::default() };
        r.mcp.adopted.push("github".into());
        r.mcp.edited.push("mine".into());
        assert!(lines(&report(vec![(Harness::Claude, r)]), Source::Server, |_| true).is_empty());
    }

    #[test]
    fn changes_are_named_with_what_to_do_per_harness() {
        let mut r = HarnessReport { unset_env: vec!["LINEAR_KEY".into()], ..Default::default() };
        r.skills.changed.insert("deploy".into(), SkillChange::Updated);
        r.skills.changed.insert("triage".into(), SkillChange::Added);
        r.mcp.file = ".github/mcp.json".into();
        r.mcp.removed.push("old".into());
        r.mcp.pending.push(Pending {
            name: "github".into(),
            change: PendingChange::Changed,
            fields: vec!["args".into(), "env".into()],
            edited: true,
            approved: None,
            server: None,
            local: None,
        });
        r.mcp.pending.push(Pending {
            name: "linear".into(),
            change: PendingChange::New,
            fields: vec![],
            edited: false,
            approved: None,
            server: None,
            local: None,
        });
        r.skills.conflicts.push(Conflict { skill: "x".into(), path: "p".into(), reason: "r".into() });
        let files = vec![PendingFile::example("lint", "SKILL.md", PendingFileChange::New, false, false)];
        r.skills.pending.insert("lint".into(), PendingSkill { change: PendingChange::New, files });
        let files = vec![
            PendingFile::example("release", "SKILL.md", PendingFileChange::Changed, false, true),
            PendingFile::example("release", "run.sh", PendingFileChange::Executable, true, false),
        ];
        r.skills.pending.insert("release".into(), PendingSkill { change: PendingChange::Changed, files });
        assert_eq!(
            lines(&report(vec![(Harness::Copilot, r)]), Source::Server, |_| false),
            [
                "bd: agent skills updated from the bd server: deploy (updated), triage (added).",
                "bd: Copilot CLI read its skills before this hook ran: ask the user to run `/skills reload` to use \
                 these in this session.",
                "bd: MCP server definitions applied to .github/mcp.json: old (removed). Ask the user to run `/mcp \
                 reload` to apply the change.",
                "bd: agent skills changed on the bd server and not applied: lint (new), release (changed: SKILL.md, \
                 run.sh made executable; edited here). Ask the user to review them and run `bd agents approve` in a \
                 separate terminal.",
                "bd: MCP server definitions changed on the bd server and not applied: github (changed: args, env; \
                 edited here), linear (new). Ask the user to review them and run `bd agents approve` in a separate \
                 terminal.",
                "bd: 1 agent asset conflict (files or MCP entries in the way, left as they are): `bd agents status` \
                 lists it.",
                "bd: environment variables the MCP servers read are unset: LINEAR_KEY.",
            ]
        );

        let skills = |h: Harness| {
            let mut r = HarnessReport::default();
            r.skills.changed.insert("deploy".into(), SkillChange::Removed);
            (h, r)
        };
        let several = report(vec![skills(Harness::Claude), skills(Harness::Codex)]);
        assert_eq!(
            lines(&several, Source::Workspace, |h| h == Harness::Claude),
            [
                "bd: claude agent skills updated from the workspace's .bd/agents: deploy (removed).",
                "bd: Claude Code watches .claude/skills only when it exists at session start: ask the user to run \
                 `/reload-skills` to use these in this session.",
                "bd: codex agent skills updated from the workspace's .bd/agents: deploy (removed).",
            ]
        );
    }

    #[test]
    fn lines_escape_what_a_server_or_file_could_put_in_them() {
        let mut r = HarnessReport::default();
        r.mcp.file = ".mcp.json".into();
        r.mcp.pending.push(Pending {
            name: "github".into(),
            change: PendingChange::Changed,
            fields: vec!["a\nbd: all clear\u{1b}[2K".into()],
            edited: false,
            approved: None,
            server: None,
            local: None,
        });
        r.mcp.conflicts.push(McpConflict { name: None, reason: "\u{202e}".into(), foreign: false });
        let lines = lines(&report(vec![(Harness::Claude, r)]), Source::Server, |_| false);
        assert!(lines[0].contains(r#"github (changed: "a\nbd: all clear\u{1b}[2K")"#), "{lines:?}");
        for line in &lines {
            assert!(!line.contains(|c: char| c.is_control()), "{line:?}");
        }
    }
}
