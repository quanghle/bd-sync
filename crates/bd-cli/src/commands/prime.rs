//! `bd prime`: workflow context for agent sessions.

use std::collections::BTreeMap;

use bd_core::{ListQuery, Queries, ReadyQuery, Result, Status};
use serde_json::json;

use crate::agents::show::printable;
use crate::app::App;
use crate::cli::*;
use crate::fmt::rel;
use crate::io;

/// The least text of a memory a shortened context keeps, before its `…`.
const SUMMARY_MIN_BYTES: usize = 80;
/// Under the summaries of a shortened context's memories.
const MEMORY_NOTE: &str = "Shortened to fit a session's context: `bd memory get <key>` prints one whole.";
/// The last line of a context whose fixed text alone passes the budget.
const CUT_NOTE: &str = "… cut to fit a session's context: `bd prime` prints all of it.";

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
    let source = app.read(|r| bd_core::config::playbooks_source(r.conn()))?;
    let crate::playbooks::ForPrime { playbooks, pending: pending_playbooks, ignored: ignored_playbooks } =
        crate::playbooks::for_prime(app, app.g.client_playbooks.as_deref(), source);
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
            "gates_needing_attention": attention
                .iter()
                .map(|g| {
                    let mut v = serde_json::to_value(g).unwrap_or(serde_json::Value::Null);
                    if let (Some(url), Some(o)) = (crate::gates::approval_url_of(g), v.as_object_mut()) {
                        o.insert("approval_url".into(), url.into());
                    }
                    v
                })
                .collect::<Vec<_>>(),
            "memories": shown_memories,
            "playbooks": shown_playbooks,
            "playbooks_total": playbooks.len(),
            "playbooks_pending": pending_playbooks,
            "playbooks_ignored": ignored_playbooks,
            "experimental": experimental.iter().map(|(name, about)| json!({ "name": name, "description": about })).collect::<Vec<_>>(),
            "specs": specs.json(),
        }));
        return Ok(());
    }
    let whence = match me.source {
        crate::actor::Source::Session => format!("this agent session's own actor: {}", me.from),
        crate::actor::Source::Default => format!("from {}; no agent session detected", me.from),
        _ => format!("from {}", me.from),
    };
    let mut head = vec![
        "# bd workflow context".to_string(),
        format!("Workspace `{workspace}` (prefix `{prefix}`); you are `{actor}` ({whence})."),
    ];
    if let Some(w) = shared_actor_warning(&me, mine.len()) {
        head.push(String::new());
        head.push(w);
    }
    head.push(String::new());
    head.push(format!(
        "## Status: {} ready · {} waiting on children · {} in progress · {} blocked · {} deferred · {} open total",
        stats.ready,
        stats.waiting_on_children,
        stats.by_status.get("in_progress").copied().unwrap_or(0),
        stats.blocked,
        stats.deferred,
        stats.by_status.get("open").copied().unwrap_or(0)
    ));
    let claims = (!mine.is_empty()).then(|| {
        let items = mine
            .iter()
            .map(|(i, l)| {
                let lease = l
                    .as_ref()
                    .map(|l| format!(" (token {}, lease expires {})", l.token, rel(l.expires_at, now)))
                    .unwrap_or_default();
                format!("- {} [P{}] {}{lease}", i.id, i.priority, i.title)
            })
            .collect();
        List { more: Some("bd prime"), ..List::new(|s, t| counted("Your claims", s, t), mine.len(), items) }
    });
    let held = (!others.is_empty()).then(|| {
        let items = others
            .iter()
            .map(|(i, l)| {
                let lease =
                    l.as_ref().map(|l| format!(", lease expires {}", rel(l.expires_at, now))).unwrap_or_default();
                format!(
                    "- {} [P{}] {} (held by {}{lease}): `{}`",
                    i.id,
                    i.priority,
                    i.title,
                    i.assignee.as_deref().unwrap_or_default(),
                    crate::actor::take_over_command(&i.id, &actor)
                )
            })
            .collect();
        List {
            intro: vec![
                "Claims of your user's other actors: an earlier session (before /clear or a resume), a parent or \
                 subagent with its own session, or a concurrent one. Take one over only if this session is \
                 continuing that work, then use the new lease token it prints; otherwise leave it to its session."
                    .into(),
            ],
            more: Some("bd prime"),
            ..List::new(|s, t| counted("Held by other sessions of yours", s, t), others.len(), items)
        }
    });
    let ready_list = {
        let items = ready.iter().map(|i| format!("- {} [P{}] [{}] {}", i.id, i.priority, i.issue_type, i.title));
        let total = usize::try_from(stats.ready).unwrap_or_default();
        List {
            intro: if ready.is_empty() { vec!["- (none)".into()] } else { Vec::new() },
            ..List::new(|s, t| format!("## Ready work (top {s} of {t})"), total, items.collect())
        }
    };
    let gates = (!attention.is_empty()).then(|| {
        let items = attention
            .iter()
            .map(|g| {
                let what = match (&g.escalation, g.phase) {
                    (Some(reason), bd_core::gates::GatePhase::Escalated) => format!("escalated: {reason}"),
                    _ => "awaiting approval".to_string(),
                };
                let holds: Vec<&str> = g.blocks.iter().map(|b| b.id.as_str()).collect();
                let mut line = format!(
                    "- {} {} — {what} (holds {}); open with `bd gate resolve {}`",
                    g.id,
                    g.title,
                    holds.join(", "),
                    g.id
                );
                if let Some(url) = crate::gates::approval_url_of(g) {
                    line.push_str(&format!("; or approve in a browser: {url}"));
                }
                printable(&line)
            })
            .collect();
        List {
            intro: vec![
                "Only a person opens a human gate: hand the person its approval link (where shown) or ask them to \
                 run `bd gate review` in a terminal of their own."
                    .into(),
            ],
            more: Some("bd prime"),
            ..List::new(|s, t| counted("Gates needing a person", s, t), attention.len(), items)
        }
    });
    let mut reference = vec![String::new(), "## Core loop".to_string()];
    reference.extend(core_loop(&ttl));
    if !experimental.is_empty() {
        reference.push(String::new());
        reference.push("## Experimental features on in this workspace".into());
        for (name, about) in &experimental {
            reference.push(format!("- `{name}`: {about}"));
        }
    }
    reference.extend(specs.lines());
    let playbooks_list = (!playbooks.is_empty() || !pending_playbooks.is_empty() || ignored_playbooks > 0).then(|| {
        let items = shown_playbooks
            .iter()
            .map(|p| {
                let mut line = format!("- {}", p.name);
                if p.invalid {
                    line.push_str(" — invalid: `bd playbook list` shows why");
                } else if !p.description.is_empty() {
                    line.push_str(&format!(" — {}", p.description));
                }
                line.push_str(match p.location {
                    crate::playbooks::Location::Checkout => "",
                    crate::playbooks::Location::Server => " (on the server)",
                    crate::playbooks::Location::Approved => " (the server's, approved here)",
                    crate::playbooks::Location::User => " (user's own)",
                });
                line
            })
            .collect();
        let mut foot = Vec::new();
        if !pending_playbooks.is_empty() {
            // Paths the client sent, checked as playbook paths; escaped all the same.
            foot.push(printable(&format!(
                "Waiting for approval on this machine: {}. The server's playbooks are used here only once a person \
                 approves them (a changed one keeps its approved version meanwhile): ask the user to review them and \
                 run `bd agents approve` in a separate terminal.",
                crate::agents::approved::pending_list(&pending_playbooks)
            )));
        }
        if ignored_playbooks > 0 {
            foot.push(format!(
                "{ignored_playbooks} playbook(s) in this checkout's .bd/playbooks ignored (playbooks.source = server: \
                 playbooks come from the bd server, approved on this machine): `bd publish` brings them to the server."
            ));
        }
        List {
            intro: vec![
                "When work matches one, `bd playbook show <name>` gives its steps and vars and `bd playbook run <name> \
                 --var k=v` starts it."
                    .into(),
            ],
            more: Some("bd playbook list"),
            foot,
            ..List::new(|s, t| counted("Playbooks", s, t), playbooks.len(), items)
        }
    });
    let memories_list = (!memories.is_empty()).then(|| {
        let items = shown_memories.iter().map(|m| format!("\n### {}\n{}", m.key, m.content)).collect();
        List {
            intro: vec![
                "Update with `bd remember --key <key> \"...\"`, search with `bd memories <q>`, remove with `bd forget <key>`."
                    .into(),
            ],
            more: Some("bd memories"),
            ..List::new(|s, t| counted("Persistent memories", s, t), memories.len(), items)
        }
    });
    let context = Context {
        head,
        claims,
        held,
        ready: Some(ready_list),
        gates,
        reference,
        playbooks: playbooks_list,
        memories: memories_list,
    };
    match a.hook {
        Some(h) => {
            let whole: Vec<(&str, &str)> =
                shown_memories.iter().map(|m| (m.key.as_str(), m.content.as_str())).collect();
            let text = context.escaped().within(crate::hook::CONTEXT_BYTES, &whole);
            crate::hook::print_context(Some(h), crate::hook::Event::SessionStart, &text);
        }
        None => context.lines().iter().for_each(io::outln),
    }
    Ok(())
}

/// One section of `bd prime` that can be shown in part: its heading, computed
/// from what it shows, so a count stays true after a cut, then `intro`, the
/// `items`, a line naming the command that prints what was left out, and `foot`.
struct List {
    heading: fn(usize, usize) -> String,
    total: usize,
    intro: Vec<String>,
    items: Vec<String>,
    more: Option<&'static str>,
    foot: Vec<String>,
    /// The bytes `items` adds to the text, kept so sizing a list never walks them.
    item_bytes: usize,
}

impl List {
    fn new(heading: fn(usize, usize) -> String, total: usize, items: Vec<String>) -> List {
        let mut list =
            List { heading, total, intro: Vec::new(), items: Vec::new(), more: None, foot: Vec::new(), item_bytes: 0 };
        list.set_items(items);
        list
    }

    fn set_items(&mut self, items: Vec<String>) {
        self.item_bytes = items.iter().map(|i| i.len() + 1).sum();
        self.items = items;
    }

    fn more_line(&self) -> Option<String> {
        let left_out = self.total.checked_sub(self.items.len()).filter(|n| *n > 0)?;
        self.more.map(|command| format!("- … {left_out} more: `{command}`"))
    }

    fn lines(&self) -> Vec<String> {
        let mut out = vec![String::new(), (self.heading)(self.items.len(), self.total)];
        out.extend_from_slice(&self.intro);
        out.extend_from_slice(&self.items);
        out.extend(self.more_line());
        out.extend_from_slice(&self.foot);
        out
    }

    /// What [`List::lines`] adds to the text, each line with its newline.
    fn bytes(&self) -> usize {
        let fixed: usize = self.intro.iter().chain(&self.foot).map(|l| l.len() + 1).sum();
        let more = self.more_line().map_or(0, |l| l.len() + 1);
        1 + (self.heading)(self.items.len(), self.total).len() + 1 + fixed + self.item_bytes + more
    }

    fn pop(&mut self) {
        if let Some(item) = self.items.pop() {
            self.item_bytes -= item.len() + 1;
        }
    }
}

/// A section's heading: its total, or what it shows of that total.
fn counted(name: &str, shown: usize, total: usize) -> String {
    if shown == total { format!("## {name} ({total})") } else { format!("## {name} (showing {shown} of {total})") }
}

/// What `bd prime` prints, in print order: what this session holds and can do
/// next before reference text, as a harness that cuts a long context keeps its
/// head. A list is `None` where its section is left out.
struct Context {
    head: Vec<String>,
    claims: Option<List>,
    held: Option<List>,
    ready: Option<List>,
    gates: Option<List>,
    reference: Vec<String>,
    playbooks: Option<List>,
    memories: Option<List>,
}

impl Context {
    fn lines(&self) -> Vec<String> {
        let state = [&self.claims, &self.held, &self.ready, &self.gates];
        let tail = [&self.playbooks, &self.memories];
        self.head
            .iter()
            .cloned()
            .chain(state.into_iter().flatten().flat_map(List::lines))
            .chain(self.reference.iter().cloned())
            .chain(tail.into_iter().flatten().flat_map(List::lines))
            .collect()
    }

    fn text(&self) -> String {
        self.lines().join("\n")
    }

    /// The length of [`Context::text`], exactly.
    fn bytes(&self) -> usize {
        let fixed: usize = self.head.iter().chain(&self.reference).map(|l| l.len() + 1).sum();
        let lists = [&self.claims, &self.held, &self.ready, &self.gates, &self.playbooks, &self.memories];
        let lists: usize = lists.into_iter().flatten().map(List::bytes).sum();
        (fixed + lists).saturating_sub(1)
    }

    /// This context as stdout prints it: every line goes through an escaper
    /// that can multiply its length, so a budget is measured after it. Headings
    /// and more-lines are left, built from names and counts alone.
    fn escaped(mut self) -> Context {
        let rewrite = |lines: &mut Vec<String>| lines.iter_mut().for_each(|line| *line = as_printed(line));
        rewrite(&mut self.head);
        rewrite(&mut self.reference);
        let lists = [
            &mut self.claims,
            &mut self.held,
            &mut self.ready,
            &mut self.gates,
            &mut self.playbooks,
            &mut self.memories,
        ];
        for list in lists.into_iter().flatten() {
            rewrite(&mut list.intro);
            rewrite(&mut list.foot);
            let items = list.items.iter().map(|item| as_printed(item)).collect();
            list.set_items(items);
        }
        self
    }

    /// The text a session hook prints: [`Context::text`] when it fits
    /// `budget`, else shortened to fit. `memories` are the shown memories'
    /// keys and text, which the fit summarizes.
    fn within(mut self, budget: usize, memories: &[(&str, &str)]) -> String {
        self.fit(budget, memories);
        backstop(self.text(), budget)
    }

    /// Shorten what is over `budget`: memories become one line each, then the
    /// list with the most bytes loses its last line, a tie going to the later
    /// section and the session's own claims going last. Over budget after
    /// this, every list is empty: what is left is fixed text.
    fn fit(&mut self, budget: usize, memories: &[(&str, &str)]) {
        if self.bytes() <= budget {
            return;
        }
        if let Some(list) = &mut self.memories {
            list.intro.push(MEMORY_NOTE.into());
        }
        let room = budget.saturating_sub(self.bytes() - self.memories.as_ref().map_or(0, |l| l.item_bytes));
        if let Some(list) = &mut self.memories {
            list.set_items(summaries(memories, room));
        }
        while self.bytes() > budget {
            let lists = [&mut self.held, &mut self.ready, &mut self.gates, &mut self.playbooks, &mut self.memories];
            let longest = lists.into_iter().flatten().filter(|l| !l.items.is_empty()).max_by_key(|l| l.item_bytes);
            let Some(list) = longest.or(self.claims.as_mut().filter(|l| !l.items.is_empty())) else {
                break;
            };
            list.pop();
        }
    }
}

/// `text` as stdout prints it. Printed with its newline, as a carriage return
/// before one stays where any other is escaped.
fn as_printed(text: &str) -> String {
    let mut printed = io::printable(&format!("{text}\n")).into_owned();
    printed.pop();
    printed
}

/// One line for each memory, which together take about `room` bytes: each
/// gets an even share of what the earlier ones left, so what a short memory
/// does not use goes to the next. The floor of text in [`summary`] can pass
/// `room`.
fn summaries(memories: &[(&str, &str)], room: usize) -> Vec<String> {
    let mut left = room;
    let mut out = Vec::with_capacity(memories.len());
    for (i, (key, text)) in memories.iter().enumerate() {
        let line = summary(key, text, left / (memories.len() - i));
        left = left.saturating_sub(line.len() + 1);
        out.push(line);
    }
    out
}

/// A memory as one line of `share` bytes at most with its newline, or longer
/// to keep [`SUMMARY_MIN_BYTES`] of its text. The text is escaped before it
/// is cut, as escaping can multiply its length: a cut can end inside an
/// escape, which is visible text, and never inside a character.
fn summary(key: &str, text: &str, share: usize) -> String {
    let text = printable(&text.split_whitespace().collect::<Vec<_>>().join(" "));
    let prefix = printable(&format!("- {key}: "));
    let room = share.saturating_sub(prefix.len() + 1);
    let keep = room.saturating_sub("…".len()).max(SUMMARY_MIN_BYTES);
    if text.len() <= keep + "…".len() {
        return prefix + &text;
    }
    format!("{prefix}{}…", &text[..text.floor_char_boundary(keep)])
}

/// `text` within `budget` whatever it holds: over it, cut at a line end and
/// closed with [`CUT_NOTE`]. A line longer than all the room is cut inside, on
/// a character boundary, as a cut at a line end would leave little but the
/// title. [`Context::fit`] has emptied every list by now, so this cuts fixed
/// text only, never half of a lease token or a link.
fn backstop(text: String, budget: usize) -> String {
    if text.len() <= budget {
        return text;
    }
    let room = budget.saturating_sub(CUT_NOTE.len() + 1);
    let mut kept = String::new();
    for line in text.split('\n') {
        if kept.len() + line.len() + 1 > room {
            if line.len() > room {
                kept.push_str(&line[..line.floor_char_boundary(room - kept.len())]);
            }
            break;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept.truncate(kept.trim_end().len());
    if !kept.is_empty() {
        kept.push('\n');
    }
    kept + CUT_NOTE
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
    let (unlinked, to_link) = specs::unlinked_counts(r.conn(), since)?;
    Ok(SpecState { on, open, since, unlinked, to_link })
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
            "- Link each change to its spec or requirement (`bd spec link <id> <spec or requirement>`) or mark it \
             `bd spec none <id> -r '<why>'`; keep requirements current (`bd spec add <spec> --from <id> -- '<sentence>'`, \
             `bd spec change <req> --from <id> -- '<sentence>'`, `bd spec remove <req> -r '<why>'`)."
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
    use crate::hook::CONTEXT_BYTES;

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

    /// A list with every optional part, showing `items` of `total`.
    fn list(total: usize, items: &[&str]) -> List {
        List {
            intro: vec!["intro".into()],
            more: Some("bd prime"),
            foot: vec!["foot".into()],
            ..List::new(|s, t| counted("Sample", s, t), total, items.iter().map(|i| i.to_string()).collect())
        }
    }

    #[test]
    fn a_list_prints_what_it_shows_and_counts_what_it_leaves_out() {
        assert_eq!(
            list(3, &["- a", "\n### b\nc"]).lines(),
            ["", "## Sample (showing 2 of 3)", "intro", "- a", "\n### b\nc", "- … 1 more: `bd prime`", "foot"]
        );
        assert_eq!(list(1, &["- a"]).lines(), ["", "## Sample (1)", "intro", "- a", "foot"]);
        let no_command = List { more: None, ..list(3, &["- a"]) };
        assert!(!no_command.lines().iter().any(|l| l.contains("more")), "{:?}", no_command.lines());
    }

    #[test]
    fn bytes_is_the_length_of_the_text() {
        for present in 0..1u32 << 6 {
            let part = |bit: u32, items: &[&str]| (present & 1 << bit != 0).then(|| list(3, items));
            let mut context = Context {
                head: vec!["# title".into(), String::new(), "## Status: é".into()],
                claims: part(0, &["- claim"]),
                held: part(1, &["- held", "- held too"]),
                ready: part(2, &[]),
                gates: part(3, &["- a gate …"]),
                reference: vec![String::new(), "## Core loop".into()],
                playbooks: part(4, &["- a", "- b", "- c"]),
                memories: part(5, &["\n### key\nline\nline"]),
            };
            assert_eq!(context.bytes(), context.text().len(), "{present:b}");
            // Still exact as a list loses its lines, its more-line appearing.
            if let Some(playbooks) = &mut context.playbooks {
                playbooks.pop();
                assert_eq!(context.bytes(), context.text().len(), "{present:b}");
            }
        }
        let empty = Context {
            head: Vec::new(),
            claims: None,
            held: None,
            ready: None,
            gates: None,
            reference: Vec::new(),
            playbooks: None,
            memories: None,
        };
        assert_eq!((empty.bytes(), empty.text().len()), (0, 0));
    }

    /// `count` lines of `size` bytes, told apart by a number at their start.
    fn lines_of(count: usize, size: usize) -> Vec<String> {
        (0..count).map(|n| format!("- {n:<width$}", width = size - 2)).collect()
    }

    /// The fixed text of a context, with no list.
    fn bare() -> Context {
        Context {
            head: vec!["# title".into(), String::new(), "## Status: 1 ready".into()],
            claims: None,
            held: None,
            ready: None,
            gates: None,
            reference: vec![String::new(), "## Core loop".into(), "- `bd ready` lists work".into()],
            playbooks: None,
            memories: None,
        }
    }

    fn part(heading: fn(usize, usize) -> String, more: Option<&'static str>, items: Vec<String>) -> Option<List> {
        Some(List { more, ..List::new(heading, items.len(), items) })
    }

    // The lists as `cmd_prime` builds them.
    fn claims(items: Vec<String>) -> Option<List> {
        part(|s, t| counted("Your claims", s, t), Some("bd prime"), items)
    }

    fn held(items: Vec<String>) -> Option<List> {
        part(|s, t| counted("Held by other sessions of yours", s, t), Some("bd prime"), items)
    }

    fn ready(items: Vec<String>) -> Option<List> {
        part(|s, t| format!("## Ready work (top {s} of {t})"), None, items)
    }

    fn gates(items: Vec<String>) -> Option<List> {
        part(|s, t| counted("Gates needing a person", s, t), Some("bd prime"), items)
    }

    fn playbooks(items: Vec<String>) -> Option<List> {
        part(|s, t| counted("Playbooks", s, t), Some("bd playbook list"), items)
    }

    fn memories(items: Vec<String>) -> Option<List> {
        part(|s, t| counted("Persistent memories", s, t), Some("bd memories"), items)
    }

    /// Memories as `cmd_prime` prints them whole.
    fn whole(pairs: &[(&str, &str)]) -> Option<List> {
        memories(pairs.iter().map(|(key, text)| format!("\n### {key}\n{text}")).collect())
    }

    /// How many items each list shows, in print order.
    fn shown(context: &Context) -> [usize; 6] {
        [&context.claims, &context.held, &context.ready, &context.gates, &context.playbooks, &context.memories]
            .map(|list| list.as_ref().map_or(0, |l| l.items.len()))
    }

    /// `context` with every list cut to nothing.
    fn popped(mut context: Context) -> Context {
        let lists = [
            &mut context.claims,
            &mut context.held,
            &mut context.ready,
            &mut context.gates,
            &mut context.playbooks,
            &mut context.memories,
        ];
        for list in lists.into_iter().flatten() {
            while !list.items.is_empty() {
                list.pop();
            }
        }
        context
    }

    #[test]
    fn a_text_that_fits_is_left_alone() {
        let build = |text: &str| Context { ready: ready(lines_of(3, 20)), memories: whole(&[("key", text)]), ..bare() };
        let room = CONTEXT_BYTES - build("").bytes();

        let text = "x".repeat(room);
        let context = build(&text);
        let printed = context.text();
        assert_eq!(printed.len(), CONTEXT_BYTES);
        assert_eq!(context.within(CONTEXT_BYTES, &[("key", &text)]), printed);

        let text = "x".repeat(room + 1);
        let cut = build(&text).within(CONTEXT_BYTES, &[("key", &text)]);
        assert!(cut.len() <= CONTEXT_BYTES, "{}", cut.len());
        assert!(cut.contains(MEMORY_NOTE), "{cut}");
    }

    #[test]
    fn any_mix_of_sizes_stays_within_the_budget() {
        // Multi-byte text, so that a cut can land inside a character.
        let sized = |count: usize, size: usize| -> Vec<String> {
            (0..count).map(|n| format!("- {n} {}", "é…".repeat(size / 5))).collect()
        };
        let memory_sets = [(0, 0), (1, 1), (10, 100), (1000, 100), (30, 5000), (10, 64 * 1024)];
        for count in [0, 1, 10, 1000] {
            for size in [1, 100, 5000] {
                for (memory_count, memory_size) in memory_sets {
                    let text = "é… x\n".repeat(memory_size / 8);
                    let keys: Vec<String> = (0..memory_count).map(|n| format!("key-{n}")).collect();
                    let pairs: Vec<(&str, &str)> = keys.iter().map(|k| (k.as_str(), text.as_str())).collect();
                    for (huge_foot, huge_head) in [(false, false), (true, false), (false, true)] {
                        let build = || {
                            let mut context = Context {
                                claims: claims(sized(count, size)),
                                held: held(sized(count / 10, size)),
                                ready: ready(sized(count, size / 10)),
                                gates: gates(sized(count, size)),
                                playbooks: playbooks(sized(1, size)),
                                memories: (!pairs.is_empty()).then(|| whole(&pairs)).flatten(),
                                ..bare()
                            };
                            if let (true, Some(list)) = (huge_foot, &mut context.playbooks) {
                                list.foot.push("f".repeat(3 * CONTEXT_BYTES));
                            }
                            if huge_head {
                                context.head.push(format!("x{}", "é".repeat(3 * CONTEXT_BYTES)));
                            }
                            context
                        };
                        let case = (count, size, memory_count, memory_size, huge_foot, huge_head);
                        let mut fitted = build();
                        fitted.fit(CONTEXT_BYTES, &pairs);
                        assert_eq!(fitted.bytes(), fitted.text().len(), "{case:?}");
                        let printed = build().within(CONTEXT_BYTES, &pairs);
                        assert!(printed.len() <= CONTEXT_BYTES, "{case:?}: {}", printed.len());
                    }
                }
            }
        }
    }

    #[test]
    fn memories_share_the_room_and_pass_on_their_surplus() {
        let long = "x".repeat(1000);
        let pairs = [("a", long.as_str()), ("b", "short"), ("c", long.as_str())];

        // 600 bytes in three is 200 a line with its newline; the second uses
        // 11 and the third gets the 189 it left.
        let lines = summaries(&pairs, 600);
        assert_eq!(lines.iter().map(String::len).collect::<Vec<_>>(), [199, 10, 388]);
        assert_eq!(lines[0], format!("- a: {}…", "x".repeat(191)));
        assert_eq!(lines[1], "- b: short");
        assert_eq!(lines[2], format!("- c: {}…", "x".repeat(380)));

        // In a context, they take what the rest leaves and no more.
        let printed = Context { memories: whole(&pairs), ..bare() }.within(1000, &pairs);
        assert_eq!(printed.len(), 1000, "{printed}");
        assert!(printed.contains(&format!("{MEMORY_NOTE}\n- a: x")), "{printed}");
        assert!(printed.contains("\n- b: short\n- c: x"), "{printed}");
        assert!(printed.ends_with('…'), "{printed}");
    }

    #[test]
    fn a_summary_keeps_its_floor_of_text() {
        let floor = "x".repeat(SUMMARY_MIN_BYTES);
        assert_eq!(summary("k", &"x".repeat(200), 0), format!("- k: {floor}…"));
        // A `…` in place of the last three bytes would save nothing.
        let whole = "x".repeat(SUMMARY_MIN_BYTES + 3);
        assert_eq!(summary("k", &whole, 0), format!("- k: {whole}"));
        assert_eq!(summary("k", &"x".repeat(SUMMARY_MIN_BYTES + 4), 0), format!("- k: {floor}…"));
        // With no room to share, each still has its floor.
        let long = "x".repeat(200);
        let lines = summaries(&[("k", &long), ("l", &long), ("m", &long)], 30);
        assert!(lines.iter().all(|l| l.len() == "- k: ".len() + SUMMARY_MIN_BYTES + "…".len()), "{lines:?}");
    }

    #[test]
    fn the_list_with_the_most_bytes_loses_its_last_line() {
        let build = || Context {
            claims: claims(lines_of(9, 100)),
            held: held(lines_of(2, 100)),
            ready: ready(lines_of(5, 100)),
            gates: gates(lines_of(3, 100)),
            playbooks: playbooks(lines_of(2, 100)),
            ..bare()
        };
        let mut context = build();
        let budget = context.bytes() - 1;
        context.fit(budget, &[]);
        assert_eq!(shown(&context), [9, 2, 4, 3, 2, 0]);
        assert_eq!(context.ready.as_ref().unwrap().items, lines_of(4, 100));

        // Cutting on, the lists come level instead of one being emptied.
        let mut context = build();
        let budget = context.bytes() - 450;
        context.fit(budget, &[]);
        assert_eq!(shown(&context), [9, 2, 2, 1, 1, 0]);
    }

    #[test]
    fn ties_cut_the_later_section() {
        // Lines of one size in every list, once the memories are at their floor.
        let text = "x".repeat(500);
        let pairs = [("k", text.as_str()), ("m", text.as_str())];
        let build = || Context {
            held: held(lines_of(2, 88)),
            ready: ready(lines_of(2, 88)),
            gates: gates(lines_of(2, 88)),
            playbooks: playbooks(lines_of(2, 88)),
            memories: whole(&pairs),
            ..bare()
        };
        let summarized = memories(summaries(&pairs, 0)).map(|l| List { intro: vec![MEMORY_NOTE.into()], ..l });
        let one_over = Context { memories: summarized, ..build() }.bytes() - 1;
        let mut context = build();
        context.fit(one_over, &pairs);
        assert_eq!(shown(&context), [0, 2, 2, 2, 2, 1]);

        // Memories first, then the section before them.
        let mut context = Context { memories: None, ..build() };
        let budget = context.bytes() - 1;
        context.fit(budget, &[]);
        assert_eq!(shown(&context), [0, 2, 2, 2, 1, 0]);
    }

    #[test]
    fn claims_go_last() {
        let build = || Context {
            claims: claims(lines_of(3, 500)),
            held: held(lines_of(1, 100)),
            ready: ready(lines_of(1, 100)),
            gates: gates(lines_of(1, 100)),
            playbooks: playbooks(lines_of(1, 100)),
            ..bare()
        };
        let room = Context { claims: claims(lines_of(3, 500)), ..popped(build()) }.bytes();

        let mut context = build();
        context.fit(room, &[]);
        assert_eq!(shown(&context), [3, 0, 0, 0, 0, 0]);

        let mut context = build();
        context.fit(room - 1, &[]);
        assert_eq!(shown(&context), [2, 0, 0, 0, 0, 0]);
        assert_eq!(context.claims.as_ref().unwrap().items, lines_of(2, 500));
    }

    /// Three lines of 300 bytes in every list, and six memories.
    fn crowded(memory_text: &str) -> (Context, [(&str, &str); 6]) {
        let pairs = ["key-a", "key-b", "key-c", "key-d", "key-e", "key-f"].map(|key| (key, memory_text));
        let context = Context {
            claims: claims(lines_of(3, 300)),
            held: held(lines_of(3, 300)),
            ready: ready(lines_of(3, 300)),
            gates: gates(lines_of(3, 300)),
            playbooks: playbooks(lines_of(3, 300)),
            memories: whole(&pairs),
            ..bare()
        };
        (context, pairs)
    }

    fn more_lines(text: &str) -> Vec<&str> {
        text.lines().filter(|l| l.starts_with("- … ")).collect()
    }

    #[test]
    fn a_shortened_list_counts_and_names_a_command() {
        let text = "x".repeat(300);

        // Every list but the claims is cut, each saying so.
        let (context, pairs) = crowded(&text);
        let printed = context.within(3000, &pairs);
        assert!(printed.len() <= 3000, "{printed}");
        for heading in [
            "## Your claims (3)\n",
            "## Held by other sessions of yours (showing 1 of 3)\n",
            "## Ready work (top 1 of 3)\n",
            "## Gates needing a person (showing 1 of 3)\n",
            "## Playbooks (showing 1 of 3)\n",
            "## Persistent memories (showing 4 of 6)\n",
        ] {
            assert!(printed.contains(heading), "{heading} in {printed}");
        }
        assert_eq!(
            more_lines(&printed),
            [
                "- … 2 more: `bd prime`",
                "- … 2 more: `bd prime`",
                "- … 2 more: `bd playbook list`",
                "- … 2 more: `bd memories`",
            ]
        );
        assert!(printed.contains(MEMORY_NOTE), "{printed}");

        // With all of them empty, the claims go too, and a ready list of none
        // still says how many there are.
        let (context, pairs) = crowded(&text);
        let printed = context.within(1000, &pairs);
        assert!(printed.len() <= 1000, "{printed}");
        for heading in [
            "## Your claims (showing 1 of 3)\n",
            "## Held by other sessions of yours (showing 0 of 3)\n",
            "## Ready work (top 0 of 3)\n",
            "## Gates needing a person (showing 0 of 3)\n",
            "## Playbooks (showing 0 of 3)\n",
            "## Persistent memories (showing 0 of 6)\n",
        ] {
            assert!(printed.contains(heading), "{heading} in {printed}");
        }
        assert_eq!(
            more_lines(&printed),
            [
                "- … 2 more: `bd prime`",
                "- … 3 more: `bd prime`",
                "- … 3 more: `bd prime`",
                "- … 3 more: `bd playbook list`",
                "- … 6 more: `bd memories`",
            ]
        );
        assert!(!printed.contains("(none)"), "{printed}");
    }

    #[test]
    fn every_command_a_shortened_context_names_parses() {
        let text = "x".repeat(300);
        let (context, pairs) = crowded(&text);
        let printed = context.within(3000, &pairs);
        let argvs = commands_in(&format!("{printed}\n{CUT_NOTE}\n{MEMORY_NOTE}"));
        let named: Vec<String> = argvs.iter().map(|argv| argv.join(" ")).collect();
        for command in ["bd prime", "bd memory get key", "bd memories", "bd playbook list"] {
            assert!(named.iter().any(|n| n == command), "{command} in {named:?}");
        }
        for argv in argvs {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?} does not parse:\n{e}"));
        }
    }

    #[test]
    fn fixed_and_foot_lines_survive_the_fit() {
        let pairs = [("key", "text")];
        let build = || {
            let mut context = Context {
                claims: claims(lines_of(3, 100)),
                held: held(lines_of(3, 100)),
                ready: ready(lines_of(3, 100)),
                gates: gates(lines_of(3, 100)),
                playbooks: playbooks(lines_of(3, 100)),
                memories: whole(&pairs),
                ..bare()
            };
            context.head.push("⚠ a warning".into());
            context.reference.extend(["## Experimental features on".to_string(), "## Feature specs".to_string()]);
            if let Some(list) = &mut context.playbooks {
                list.foot = vec!["Waiting for approval".into(), "1 playbook(s) ignored".into()];
            }
            context
        };
        let mut emptied = popped(build());
        if let Some(list) = &mut emptied.memories {
            list.intro.push(MEMORY_NOTE.into());
        }
        let budget = emptied.bytes();

        let mut context = build();
        context.fit(budget, &pairs);
        assert_eq!(shown(&context), [0; 6]);
        let printed = context.text();
        assert_eq!(printed.len(), budget, "{printed}");
        assert_eq!(backstop(printed.clone(), budget), printed);
        let lines: Vec<&str> = printed.lines().collect();
        for fixed in [
            "⚠ a warning",
            "## Status: 1 ready",
            "## Core loop",
            "- `bd ready` lists work",
            "## Experimental features on",
            "## Feature specs",
            "Waiting for approval",
            "1 playbook(s) ignored",
        ] {
            assert!(lines.contains(&fixed), "{fixed} in {printed}");
        }
    }

    #[test]
    fn the_backstop_cuts_at_a_line_end() {
        let text = format!("# title\n\na line\n\nanother line{}", "\nand one more".repeat(20));
        assert_eq!(backstop(text.clone(), text.len()), text);

        // A line not fitting goes whole, with the blank line above it.
        let budget = CUT_NOTE.len() + 1 + "# title\n\na line\n\nano".len();
        assert_eq!(backstop(text.clone(), budget), format!("# title\n\na line\n{CUT_NOTE}"));

        // One fitting to the byte stays.
        let budget = CUT_NOTE.len() + 1 + "# title\n\na line\n\nanother line\n".len();
        let cut = backstop(text.clone(), budget);
        assert_eq!(cut, format!("# title\n\na line\n\nanother line\n{CUT_NOTE}"));
        assert!(cut.len() <= budget);
    }

    #[test]
    fn the_backstop_cuts_one_long_line_on_a_char_boundary() {
        let label = "é".repeat(CONTEXT_BYTES);
        let text = format!("# title\nWorkspace `{label}`\n## Status");
        for budget in [CONTEXT_BYTES, CONTEXT_BYTES + 1] {
            let cut = backstop(text.clone(), budget);
            assert!((budget - 1..=budget).contains(&cut.len()), "{budget}: {}", cut.len());
            let (kept, note) = cut.rsplit_once('\n').unwrap();
            assert_eq!(note, CUT_NOTE);
            assert!(kept.starts_with("# title\nWorkspace `éé") && kept.ends_with('é'), "{kept}");
        }
        // On the first line, nothing comes before the cut.
        let cut = backstop(label.clone(), CONTEXT_BYTES);
        assert!(cut.starts_with('é') && cut.ends_with(CUT_NOTE) && cut.len() <= CONTEXT_BYTES, "{cut}");
        assert_eq!(cut.lines().count(), 2);
    }

    #[test]
    fn a_summary_stays_on_one_line_and_escapes_hidden_characters() {
        assert_eq!(summary("key", "one\ntwo\t three\r\n\n\u{1b}[2K", 1000), "- key: one two three \\u{1b}[2K");
        assert_eq!(summary("k\u{1b}\n", "x", 1000), "- k\\u{1b}\\u{a}: x");

        // Byte 80 of each falls inside a character, so the cut comes before it.
        let line = summary("k", &format!("x{}", "é".repeat(100)), 0);
        assert_eq!(line, format!("- k: x{}…", "é".repeat(39)));
        let line = summary("k", &format!("x{}", "…".repeat(100)), 0);
        assert_eq!(line, format!("- k: x{}…", "…".repeat(26)));
        assert!(!line.contains('\n'));

        // Escapes count, and a cut inside one leaves visible text.
        let line = summary("k", &"\u{1b}".repeat(100), 0);
        assert!(line.len() <= "- k: ".len() + SUMMARY_MIN_BYTES + "…".len(), "{line}");
        assert!(line.ends_with('…') && !line.contains('\u{1b}'), "{line}");
    }

    #[test]
    fn escaped_is_what_stdout_prints() {
        let part = || {
            Some(List {
                intro: vec!["intro \u{1b}".into()],
                foot: vec!["foot \u{202e}".into()],
                ..List::new(|s, t| counted("Sample", s, t), 2, vec!["\n### key\none\r\ntwo\u{1b}\rthree".into()])
            })
        };
        let build = || Context {
            head: vec!["# title \u{1b}\r".into(), String::new()],
            claims: part(),
            held: part(),
            ready: part(),
            gates: part(),
            reference: vec![String::new(), "## Core loop \u{1b}".into()],
            playbooks: part(),
            memories: part(),
        };
        let context = build().escaped();
        let text = context.text();
        assert_eq!(context.bytes(), text.len());
        assert_eq!(format!("{text}\n"), io::printable(&format!("{}\n", build().text())), "as one stream");
        assert_eq!(text.matches("\\u001b").count(), 2 + 2 * 6, "{text}");
        assert_eq!(text.matches("\\u202e").count(), 6, "{text}");
        assert!(!text.contains(['\u{1b}', '\u{202e}']), "{text}");
        assert!(text.starts_with("# title \\u001b\r\n"), "the carriage return of a line end stays: {text}");
        assert!(text.contains("\n### key\none\r\ntwo\\u001b\\u000dthree\n"), "{text}");
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
            include_str!("../../../../.bd/source/agents/codex/skills/bd/SKILL.md"),
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
