//! `bd prime`: workflow context for agent sessions.

use std::collections::BTreeMap;

use bd_core::{ListQuery, Queries, ReadyQuery, Result, Status};
use serde_json::json;

use crate::app::App;
use crate::cli::*;
use crate::fmt::rel;
use crate::io;

pub fn cmd_prime(app: &mut App, a: &PrimeArgs) -> Result<()> {
    let me = app.resolved_actor();
    let actor = me.actor.clone();
    let workspace = app.workspace_label()?;
    let (mine, others, ready, stats, memories, ttl, now, prefix, attention) = app.read(|r| {
        let claimed = r.list(&ListQuery { statuses: vec![Status::InProgress], ..Default::default() })?;
        let leases: BTreeMap<String, bd_core::Lease> =
            r.leases()?.into_iter().map(|l| (l.lease.issue_id.clone(), l.lease)).collect();
        let with_lease = |i: bd_core::Issue| {
            let l = leases.get(&i.id).cloned();
            (i, l)
        };
        // Claims of this user's other sessions: ones this session may be continuing.
        let (mine, others): (Vec<_>, Vec<_>) = claimed
            .into_iter()
            .filter(|i| {
                i.assignee.as_deref().is_some_and(|a| a == actor || crate::actor::other_session_of_user(&me, a))
            })
            .map(with_lease)
            .partition(|(i, _)| i.assignee.as_deref() == Some(actor.as_str()));
        let ready = r.ready(&ReadyQuery { limit: Some(a.ready.max(1)), ..Default::default() })?;
        // Gates a person has to act on: armed approvals and escalations.
        let attention: Vec<bd_core::gates::GateView> = bd_core::gates::list(r.conn(), false)?
            .into_iter()
            .filter(|g| {
                g.phase == bd_core::gates::GatePhase::Escalated
                    || (g.phase == bd_core::gates::GatePhase::Armed
                        && g.spec.as_ref().is_some_and(|s| s.kind == bd_core::gates::GateKind::Human))
            })
            .collect();
        Ok((
            mine,
            others,
            ready,
            r.stats()?,
            r.memories(None)?,
            r.config_value("lease.ttl")?,
            r.now(),
            r.config_value("issue_prefix")?,
            attention,
        ))
    })?;
    let experimental: Vec<(&str, &str)> = {
        let on = app.read(|r| bd_core::config::experimental(r.conn()))?;
        bd_core::config::EXPERIMENTAL.iter().filter(|(name, _)| on.contains(*name)).copied().collect()
    };
    let specs = app.read(spec_state)?;
    let shown_memories: Vec<&bd_core::Memory> =
        if a.max_memories > 0 { memories.iter().take(a.max_memories).collect() } else { memories.iter().collect() };
    let playbooks = crate::playbooks::for_prime(app, app.g.client_playbooks.as_deref());
    let shown_playbooks =
        &playbooks[..if a.max_playbooks > 0 { a.max_playbooks.min(playbooks.len()) } else { playbooks.len() }];
    if app.g.json && a.hook.is_none() {
        app.print_json(&json!({
            "workspace": workspace,
            "prefix": prefix,
            "actor": actor,
            "actor_source": me.source,
            "actor_from": me.from,
            "shared_actor_claims": shared_actor_warning(&me, mine.len()).is_some(),
            "lease_ttl": ttl,
            "claims": mine.iter().map(|(i, l)| json!({ "issue": i, "lease": l })).collect::<Vec<_>>(),
            "other_sessions_claims": others
                .iter()
                .map(|(i, l)| json!({ "issue": i, "lease": l, "take_over": crate::actor::take_over_command(&i.id, &actor) }))
                .collect::<Vec<_>>(),
            "ready": ready,
            "ready_total": stats.ready,
            "stats": stats,
            "gates_needing_attention": attention,
            "memories": shown_memories,
            "playbooks": shown_playbooks,
            "playbooks_total": playbooks.len(),
            "experimental": experimental.iter().map(|(name, about)| json!({ "name": name, "description": about })).collect::<Vec<_>>(),
            "specs": specs.json(),
        }));
        return Ok(());
    }
    let mut o = Vec::new();
    o.push("# bd workflow context".to_string());
    let whence = match me.source {
        crate::actor::Source::Session => format!("this agent session's own actor: {}", me.from),
        crate::actor::Source::Default => format!("from {}; no agent session detected", me.from),
        _ => format!("from {}", me.from),
    };
    o.push(format!("Workspace `{workspace}` (prefix `{prefix}`); you are `{actor}` ({whence})."));
    if let Some(w) = shared_actor_warning(&me, mine.len()) {
        o.push(String::new());
        o.push(w);
    }
    o.push(String::new());
    o.push("## Core loop".into());
    o.extend(core_loop(&ttl));
    if !experimental.is_empty() {
        o.push(String::new());
        o.push("## Experimental features on in this workspace".into());
        for (name, about) in &experimental {
            o.push(format!("- `{name}`: {about}"));
        }
    }
    o.extend(specs.lines());
    o.push(String::new());
    o.push(format!(
        "## Status: {} ready · {} waiting on children · {} in progress · {} blocked · {} deferred · {} open total",
        stats.ready,
        stats.waiting_on_children,
        stats.by_status.get("in_progress").copied().unwrap_or(0),
        stats.blocked,
        stats.deferred,
        stats.by_status.get("open").copied().unwrap_or(0)
    ));
    if !mine.is_empty() {
        o.push(String::new());
        o.push(format!("## Your claims ({})", mine.len()));
        for (i, l) in &mine {
            let lease = l
                .as_ref()
                .map(|l| format!(" (token {}, lease expires {})", l.token, rel(l.expires_at, now)))
                .unwrap_or_default();
            o.push(format!("- {} [P{}] {}{lease}", i.id, i.priority, i.title));
        }
    }
    if !others.is_empty() {
        o.push(String::new());
        o.push(format!("## Held by other sessions of yours ({})", others.len()));
        o.push(
            "Claims of your user's other actors: an earlier session (before /clear or a resume), a parent or \
             subagent with its own session, or a concurrent one. Take one over only if this session is continuing \
             that work, then use the new lease token it prints; otherwise leave it to its session."
                .into(),
        );
        for (i, l) in &others {
            let lease = l.as_ref().map(|l| format!(", lease expires {}", rel(l.expires_at, now))).unwrap_or_default();
            o.push(format!(
                "- {} [P{}] {} (held by {}{lease}): `{}`",
                i.id,
                i.priority,
                i.title,
                i.assignee.as_deref().unwrap_or_default(),
                crate::actor::take_over_command(&i.id, &actor)
            ));
        }
    }
    o.push(String::new());
    o.push(format!("## Ready work (top {} of {})", ready.len(), stats.ready));
    if ready.is_empty() {
        o.push("- (none)".into());
    }
    for i in &ready {
        o.push(format!("- {} [P{}] [{}] {}", i.id, i.priority, i.issue_type, i.title));
    }
    if !attention.is_empty() {
        o.push(String::new());
        o.push(format!("## Gates needing a person ({})", attention.len()));
        for g in &attention {
            let what = match (&g.escalation, g.phase) {
                (Some(reason), bd_core::gates::GatePhase::Escalated) => format!("escalated: {reason}"),
                _ => "awaiting approval".to_string(),
            };
            let holds: Vec<&str> = g.blocks.iter().map(|b| b.id.as_str()).collect();
            o.push(format!(
                "- {} {} — {what} (holds {}); open with `bd gate resolve {}`",
                g.id,
                g.title,
                holds.join(", "),
                g.id
            ));
        }
    }
    if !playbooks.is_empty() {
        o.push(String::new());
        let shown = if shown_playbooks.len() < playbooks.len() {
            format!("showing {} of {}", shown_playbooks.len(), playbooks.len())
        } else {
            playbooks.len().to_string()
        };
        o.push(format!("## Playbooks ({shown})"));
        o.push(
            "When work matches one, `bd playbook show <name>` gives its steps and vars and `bd playbook run <name> \
             --var k=v` starts it."
                .into(),
        );
        for p in shown_playbooks {
            let mut line = format!("- {}", p.name);
            if p.invalid {
                line.push_str(" — invalid: `bd playbook list` shows why");
            } else if !p.description.is_empty() {
                line.push_str(&format!(" — {}", p.description));
            }
            line.push_str(match p.location {
                crate::playbooks::Location::Checkout => "",
                crate::playbooks::Location::Server => " (on the server)",
                crate::playbooks::Location::User => " (user's own)",
            });
            o.push(line);
        }
        if shown_playbooks.len() < playbooks.len() {
            o.push(format!("- … {} more: `bd playbook list`", playbooks.len() - shown_playbooks.len()));
        }
    }
    if !memories.is_empty() {
        o.push(String::new());
        let shown = if shown_memories.len() < memories.len() {
            format!("showing {} of {}", shown_memories.len(), memories.len())
        } else {
            memories.len().to_string()
        };
        o.push(format!("## Persistent memories ({shown})"));
        o.push("Update with `bd remember --key <key> \"...\"`, search with `bd memories <q>`, remove with `bd forget <key>`.".into());
        for m in shown_memories {
            o.push(String::new());
            o.push(format!("### {}", m.key));
            o.push(m.content.clone());
        }
    }
    match a.hook {
        Some(h) => crate::hook::print_context(Some(h), crate::hook::Event::SessionStart, &o.join("\n")),
        None => o.iter().for_each(io::outln),
    }
    Ok(())
}

/// What `bd prime` says about feature specs: counts only, cheap enough for
/// a session hook.
struct SpecState {
    on: bool,
    open: usize,
    since: Option<bd_core::Timestamp>,
    unlinked: usize,
    to_link: usize,
}

fn spec_state(r: &bd_core::ReadCtx<'_>) -> Result<SpecState> {
    use bd_core::specs;
    let on = specs::is_on(r.conn())?;
    let open = specs::open_count(r.conn())?;
    if !on {
        return Ok(SpecState { on, open, since: None, unlinked: 0, to_link: 0 });
    }
    let since = specs::since(r.conn())?;
    let (unlinked, to_link) = specs::unlinked_since(r.conn(), since)?;
    Ok(SpecState { on, open, since, unlinked: unlinked.len(), to_link: to_link.len() })
}

impl SpecState {
    fn json(&self) -> serde_json::Value {
        if self.on {
            json!({ "on": true, "since": self.since, "open": self.open, "unlinked": self.unlinked, "to_link": self.to_link })
        } else {
            json!({ "on": false, "open": self.open })
        }
    }

    /// The "## Feature specs" section with specs on; with them off, a
    /// warning when open specs are left; else nothing.
    fn lines(&self) -> Vec<String> {
        if !self.on {
            if self.open == 0 {
                return Vec::new();
            }
            return vec![
                String::new(),
                format!(
                    "Feature specs are off, but {}: re-enable them (bd config set experimental.features \
                     specs) or retire them",
                    if self.open == 1 {
                        "1 open spec exists".to_string()
                    } else {
                        format!("{} open specs exist", self.open)
                    }
                ),
            ];
        }
        let since = match self.since {
            Some(t) => format!("since {}", &t.to_rfc3339()[..10]),
            None => "since (unset: `bd config set experimental.specs.since <time>`)".to_string(),
        };
        vec![
            String::new(),
            "## Feature specs".into(),
            format!(
                "{} open spec{} · {} unlinked · {} to link {since}",
                self.open,
                if self.open == 1 { "" } else { "s" },
                self.unlinked,
                self.to_link
            ),
            "- Link each change to its spec or requirement (`bd dep add <id> <spec or requirement> --type related`) \
             or mark it `bd spec none <id> -r '<why>'`; keep requirements current (add, `bd supersede <old> --with <new>`, close with a reason)."
                .into(),
            "- See `bd spec list`, `bd spec show <spec>`, `bd spec drift`.".into(),
        ]
    }
}

/// The lines of `bd prime`'s "## Core loop" section. Every `bd ...` command
/// they name in backticks parses (see the tests), and they stay few: prime is
/// injected into every agent session and again after compaction.
fn core_loop(ttl: &str) -> Vec<String> {
    vec![
        "- `bd ready` lists unblocked work in queue order (priority, then age); `--brief` on `bd ready`, `bd list` \
         and `bd show <id>` keeps output small."
            .into(),
        format!("- `bd claim --next` atomically takes the head of the queue with a {ttl} lease; `bd claim <id>` takes a specific issue."),
        "- `bd heartbeat <id> --token <t>` renews the lease while you work; a lost lease means stop.".into(),
        "- `bd close <id> --reason \"...\"` finishes (`--failed` if it failed; `--claim-next` also claims the next ready issue); `bd release <id>` gives it back."
            .into(),
        "- A live claim is its holder's: claiming it again (even as your own actor, from another session) or \
         closing, releasing or reassigning another actor's fails with exit 4, `--force` or not. `--take-over` \
         takes it over and is recorded; use it only on purpose."
            .into(),
        "- Not ready, or not where you expected? `bd ready --explain` and `bd show <id> --why` say why. Search with \
         `bd query 'status = open AND label = x AND updated > 7d'`."
            .into(),
        "- `bd create \"title\" --dep <id>` records discovered work (`bd q \"title\"` prints only the id); \
         `bd dep add <issue> <depends-on>` orders it."
            .into(),
        "- Close repeats with `bd duplicate <id> --of <other>` and replaced work with `bd supersede <id> --with <newer>`, \
         not by hand."
            .into(),
        "- `bd comment add <id> \"...\"` leaves context; `bd remember \"insight\"` stores durable memory shown here."
            .into(),
        "- `--json` on any command gives machine output; `--if-revision N` makes an update compare-and-set (exit 13 on conflict).".into(),
        "- `bd playbook run <name> --var k=v` starts repeatable multi-step work (`bd playbook list`); `bd playbook status <run>` shows its steps; gates in front of steps are listed by `bd gate list`.".into(),
    ]
}

/// `bd prime`'s warning when this session may share its actor, and so its
/// claims, with another: the actor is the plain default (no `--actor`,
/// `$BD_ACTOR` or agent session) and holds claims.
fn shared_actor_warning(me: &crate::actor::Resolved, claims: usize) -> Option<String> {
    if me.source != crate::actor::Source::Default || claims == 0 {
        return None;
    }
    let actor = &me.actor;
    Some(format!(
        "⚠ `{actor}` is the default actor, shared by every session of this user that has no session of its own, and \
         it holds {claims} claim{} (below) that may be another session's. If this is an agent session, give it its \
         own actor before claiming or closing anything: run each of its bd commands with `{}=<name>` (acting as \
         `{actor}/<name>`) or `--actor '{actor}/<name>'`. Leave claims you did not take to their holder.",
        if claims == 1 { "" } else { "s" },
        crate::actor::SESSION_VAR,
    ))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// The `bd ...` commands in backticks in `text`, placeholders (`<id>`)
    /// filled in, as argument vectors.
    fn commands_in(text: &str) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        for (i, span) in text.split('`').enumerate() {
            if i % 2 == 0 || !span.starts_with("bd ") {
                continue;
            }
            // A lease token is a number; every other placeholder an id or a name.
            let filled = span.replace("<t>", "1").replace(['<', '>'], "");
            out.push(shlex::split(&filled).unwrap_or_else(|| panic!("unbalanced quotes in {span:?}")));
        }
        out
    }

    #[test]
    fn every_core_loop_command_parses() {
        let lines = core_loop("5m");
        let argvs = commands_in(&lines.join("\n"));
        assert!(argvs.len() >= 15, "{argvs:?}");
        for argv in argvs {
            if let Err(e) = Cli::try_parse_from(&argv) {
                panic!("{argv:?} does not parse:\n{e}");
            }
        }
        // The flags named on their own apply to the commands they are named with.
        for argv in [
            &["bd", "ready", "--brief"][..],
            &["bd", "list", "--brief"],
            &["bd", "show", "x", "--brief"],
            &["bd", "close", "x", "--failed"],
            &["bd", "close", "x", "--claim-next"],
            &["bd", "update", "x", "--if-revision", "3", "--status", "open"],
            &["bd", "--json", "ready"],
        ] {
            Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }

    #[test]
    fn the_skills_working_efficiently_commands_parse() {
        for skill in [
            include_str!("../../../../.agents/skills/bd/SKILL.md"),
            include_str!("../../../../plugins/bd/skills/bd/SKILL.md"),
        ] {
            let section = skill.split("## Working efficiently").nth(1).expect("a Working efficiently section");
            let section = section.split("\n## ").next().unwrap();
            let argvs = commands_in(section);
            assert!(argvs.len() >= 10, "{argvs:?}");
            for argv in argvs {
                Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?} does not parse:\n{e}"));
            }
        }
    }

    #[test]
    fn the_feature_specs_commands_parse() {
        let on = SpecState { on: true, open: 2, since: Some(bd_core::Timestamp(0)), unlinked: 1, to_link: 3 };
        let lines = on.lines().join("\n");
        assert!(lines.contains("## Feature specs\n2 open specs · 1 unlinked · 3 to link since 1970-01-01"), "{lines}");
        let argvs = commands_in(&lines.replace("<spec or requirement>", "<spec>"));
        assert!(argvs.len() >= 5, "{argvs:?}");
        for argv in argvs {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?} does not parse:\n{e}"));
        }
        let off = SpecState { on: false, open: 1, since: None, unlinked: 0, to_link: 0 };
        assert_eq!(
            off.lines()[1],
            "Feature specs are off, but 1 open spec exists: re-enable them (bd config set experimental.features specs) \
             or retire them"
        );
        assert!(SpecState { open: 0, ..off }.lines().is_empty());
    }

    #[test]
    fn the_core_loop_stays_compact() {
        let lines = core_loop("5m");
        assert!(lines.len() <= 12, "{} lines", lines.len());
        let bytes: usize = lines.iter().map(String::len).sum();
        assert!(bytes <= 2000, "{bytes} bytes");
    }
}
