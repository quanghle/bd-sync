//! Query plans under the planner's statistics.
//!
//! SQLite plans each statement from the statistics `ANALYZE` (which `PRAGMA
//! optimize` runs) recorded, and those can be far from the data: a young
//! workspace records them while it holds an issue or two, and a long-lived
//! connection (`bd serve`'s) keeps what it opened with. Believing a table
//! holds a row, SQLite happily scans all of it: per lookup, where a walk over
//! a deep hierarchy (recomputing blocked flags, closing nested groups,
//! descendants, a deferred subtree) turns quadratic; and per command, where a
//! follower's poll for the events past its cursor reads the whole log. So bd
//! records no statistics, and drops any a database has when it opens it (see
//! `store.rs`), and the walks fix their plans besides.
//!
//! These tests run the operations that walk the graph, and single commands,
//! while recording every statement they prepare, then have SQLite plan each
//! one: no statement may scan a table inside a loop (a correlated subquery, a
//! recursive step, the inner side of a join), and only the few in
//! [`WHOLE_TABLE`], which scan by design, may scan one at all. The walks'
//! statements must plan so under stale statistics too; every statement must
//! plan so in a workspace as bd leaves it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bd_core::gates::{self, GateKind, GateSpec, NewGate};
use bd_core::subgraph::EdgeSet;
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use bd_core::{asof, comments, config, events, hierarchy, metrics, playbook, requests, spec_context, specs};
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use rusqlite::{Connection, StatementStatus};
use serde_json::json;
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

/// Statements that scan a table by design, once per command (every row, or
/// rows in order until they have enough), and that table: they may scan it
/// as their outermost loop, never inside another.
const WHOLE_TABLE: &[(&str, &str)] = &[
    // list, ready and blocked (`QueryParts`), with their filters
    ("FROM issues i WHERE 1=1", "issues"),
    // the blocked flags from scratch (`doctor`, imports), and cycles
    ("WITH RECURSIVE direct(id) AS", "issues"),
    ("SELECT id, is_blocked FROM issues ORDER BY id", "issues"),
    ("SELECT issue_id, depends_on_id FROM dependencies WHERE dep_type IN", "dependencies"),
    // stats: issues by status, blocked, closable epics, label counts
    ("SELECT status, COUNT(*) FROM issues GROUP BY status", "issues"),
    ("SELECT COUNT(*) FROM issues WHERE is_blocked = 1 AND status NOT IN", "issues"),
    ("FROM issues e WHERE e.issue_type = 'epic'", "issues"),
    ("SELECT label, COUNT(*) FROM labels", "labels"),
    // metrics: lead and cycle times of the issues closed, and queue waits of
    // those started, in the last 30 days
    ("FROM issues WHERE status = 'closed' AND", "issues"),
    ("FROM issues WHERE started_at IS NOT NULL AND", "issues"),
    // purge candidates
    ("SELECT id FROM issues WHERE ephemeral = 1", "issues"),
    // gates: every open one (`bd gate list` and checks), those a policy protects
    ("FROM issues i WHERE i.issue_type = 'gate'", "issues"),
    // playbook runs
    ("WHERE json_extract(i.metadata, '$.playbook.role') = 'run'", "issues"),
    // an id prefix past the case-variant cap, or holding a NUL or too long to walk (bd-sync-wfr):
    // the ids in order, up to a few matches
    ("SELECT id FROM issues WHERE id LIKE ?1", "issues"),
    // request records, oldest first: up to a batch (pruned hourly)
    ("SELECT rowid FROM requests WHERE created_at < ?1 ORDER BY rowid LIMIT", "requests"),
    // leases (and reclaim's expired ones), memories, config and counters
    ("FROM leases", "leases"),
    ("FROM memories", "memories"),
    ("SELECT key, value FROM config ORDER BY key", "config"),
    ("SELECT name, value FROM counters WHERE name NOT IN", "counters"),
    // the newest events (of some ops or actors), read back from the end of
    // the log until the page is full; and the oldest one `prune --keep` keeps
    ("FROM events WHERE 1=1 ORDER BY seq DESC LIMIT", "events"),
    ("FROM events WHERE 1=1 AND op IN", "events"),
    ("FROM events WHERE 1=1 AND actor = ?", "events"),
    ("SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET", "events"),
    // rename-prefix: the rows that may name a renamed id, read once each
    ("FROM issues WHERE instr(metadata", "issues"),
    ("FROM dependencies WHERE instr(metadata", "dependencies"),
    ("FROM comments WHERE instr(text", "comments"),
    ("FROM events WHERE instr(data", "events"),
    // orphans: the issues whose text mentions the prefix, read once
    ("FROM issues WHERE instr(title", "issues"),
    // bd github: the issues linked to one repository, once per run
    ("FROM issues i WHERE i.external_ref >= ?1 AND i.external_ref < ?2", "issues"),
];

static STATEMENTS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
/// The statements SQLite prepared again, and how many times.
static PREPARED_AGAIN: Mutex<BTreeMap<String, i32>> = Mutex::new(BTreeMap::new());
static RECORDING: Mutex<()> = Mutex::new(());

fn record(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(stmt, sql) = event {
        // Foreign key actions run as `-- TRIGGER ...` programs of their statement.
        if !sql.starts_with("--") {
            STATEMENTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(sql.to_string());
            let again = stmt.get_status(StatementStatus::RePrepare);
            if again > 0 {
                let mut prepared = PREPARED_AGAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let n = prepared.entry(sql.to_string()).or_default();
                *n = (*n).max(again);
            }
        }
    }
}

/// The statements `work` prepares in a new workspace, and those of them
/// SQLite prepared again, with how many times.
fn recorded(work: fn(&mut Ws)) -> (BTreeSet<String>, BTreeMap<String, i32>) {
    let _one_at_a_time = RECORDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    STATEMENTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    PREPARED_AGAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    let mut ws = Ws::new();
    ws.store.connection().trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(record));
    work(&mut ws);
    ws.store.connection().trace_v2(TraceEventCodes::empty(), None);
    (
        std::mem::take(&mut *STATEMENTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())),
        std::mem::take(&mut *PREPARED_AGAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())),
    )
}

/// The statements `work` prepares in a new workspace.
fn statements_of(work: fn(&mut Ws)) -> BTreeSet<String> {
    recorded(work).0
}

struct Ws {
    _dir: TempDir,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Ws {
    fn new() -> Ws {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(Timestamp(T0)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let path = dir.path().join(".bd").join("bd.db");
        let store = Store::init(&path, InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts).unwrap();
        Ws { _dir: dir, store, clock }
    }

    fn write<T>(&mut self, actor: &str, policy: Option<Policy>, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.clock.advance(Duration::from_millis(10));
        self.store
            .write("plans", actor, |tx| {
                tx.set_policy(policy);
                f(tx)
            })
            .unwrap()
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.write("alice", None, |tx| tx.create_issue(new)).id
    }

    fn sql(&mut self, sql: &str) {
        self.store.write("sql", "alice", |tx| Ok(tx.conn().execute_batch(sql)?)).unwrap();
    }

    /// Close the database, as a command does when it exits, and open it again.
    fn reopen(self) -> Ws {
        let Ws { _dir, store, clock } = self;
        let path = store.path().to_path_buf();
        drop(store);
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        Ws { _dir, store: Store::open(&path, opts).unwrap(), clock }
    }

    /// Whether the database holds planner statistics.
    fn analyzed(&self) -> bool {
        let sql = "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'sqlite_stat%'";
        self.store.connection().query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap() > 0
    }
}

fn agent() -> Option<Policy> {
    Some(Policy { actor: "bot".into(), admin: false, human: false, max_claims: None, oidc_approver: None })
}

fn person() -> Option<Policy> {
    Some(Policy { actor: "carol".into(), admin: false, human: true, max_claims: None, oidc_approver: None })
}

fn child(title: &str, parent: &str) -> NewIssue {
    NewIssue { parent: Some(parent.to_string()), ..NewIssue::titled(title) }
}

fn container(title: &str, role: &str, parent: Option<&str>) -> NewIssue {
    NewIssue {
        issue_type: Some("epic".into()),
        metadata: Some(json!({ "playbook": { "role": role } })),
        parent: parent.map(String::from),
        ..NewIssue::titled(title)
    }
}

/// The operations that walk the graph, on a small hierarchy with every kind
/// of edge, a human gate and a deferred step: what they prepare is recorded.
fn walk_the_graph(ws: &mut Ws) {
    let run = ws.create(container("Run", "run", None));
    let group = ws.create(container("Group", "group", Some(&run)));
    let inner = ws.create(container("Inner group", "group", Some(&group)));
    let first = ws.create(child("First", &inner));
    let second = ws.create(child("Second", &group));
    let later = ws.create(NewIssue { defer_until: Some(Timestamp(T0 + 86_400_000)), ..child("Later", &run) });
    let blocker = ws.create(NewIssue::titled("Blocker"));
    let fallback = ws.create(NewIssue::titled("Fallback"));
    let after = ws.create(NewIssue::titled("After the group"));
    let gate = ws.write("alice", None, |tx| {
        tx.add_dependency(&second, &blocker, DepType::Blocks, None)?;
        tx.add_dependency(&fallback, &first, DepType::ConditionalBlocks, None)?;
        tx.add_dependency(&after, &group, DepType::WaitsFor, Some(json!({ "gate": "any-children" })))?;
        tx.create_gate(NewGate {
            spec: GateSpec::new(GateKind::Human),
            blocks: vec![first.clone()],
            title: None,
            description: String::new(),
            assignee: None,
            parent: None,
            priority: None,
            ephemeral: false,
        })
    });
    let gate = gate.id;

    let reads = |ws: &Ws| {
        ws.store
            .read(|r| {
                for id in [&run, &group, &inner, &first, &second, &later, &after, &gate] {
                    r.details(id)?;
                    r.not_ready_reasons(id)?;
                    r.explain(id, ExplainOptions::default())?;
                    r.depths(std::slice::from_ref(id))?;
                    r.dep_tree(id, Direction::Down, usize::MAX)?;
                    r.dep_tree(id, Direction::Up, usize::MAX)?;
                    issues::descendants(r.conn(), id)?;
                    hierarchy::epic_status(r.conn(), id)?;
                    r.child_issues(id, false)?;
                    r.child_issues(id, true)?;
                    r.subgraph(Some(id), &EdgeSet::All, 50)?;
                    spec_context::governing(r.conn(), id)?;
                    spec_context::covered(r.conn(), id)?;
                }
                let below = WorkFilter { parent: Some(run.clone()), ..Default::default() };
                r.ready(&ReadyQuery::default())?;
                r.ready(&ReadyQuery { filter: below.clone(), ..Default::default() })?;
                r.ready(&ReadyQuery { include_epics: true, ..Default::default() })?;
                r.ready(&ReadyQuery { filter: below.clone(), include_epics: true, ..Default::default() })?;
                r.list(&ListQuery { filter: below.clone(), ..Default::default() })?;
                r.blocked(&below, None)?;
                r.not_ready(&ReadyQuery::default())?;
                r.not_ready(&ReadyQuery {
                    filter: below.clone(),
                    include_epics: true,
                    limit: Some(5),
                    ..Default::default()
                })?;
                playbook::run_status(r.conn(), &run, r.now())?;
                playbook::runs(r.conn(), &Default::default(), r.now())?;
                playbook::extract(r.conn(), &run, Some("plans"))?;
                graph::full_blocked_set(r.conn())?;
                r.stats()?;
                r.export_jsonl(&mut Vec::new(), &ExportOptions::default())?;
                Ok(())
            })
            .unwrap();
    };
    reads(ws);
    // An import under a policy first notes what the open human gates hold.
    let mut jsonl = Vec::new();
    ws.store.read(|r| r.export_jsonl(&mut jsonl, &ExportOptions::default())).unwrap();
    ws.write("bot", agent(), |tx| tx.import_jsonl(&mut jsonl.as_slice(), &ImportOptions::default()));

    // An agent works through the run: each close recomputes what it freed,
    // and the last one closes the groups above it, checking human gates.
    ws.write("alice", None, |tx| tx.close_issue(&blocker, &CloseOptions::default()));
    ws.write("bot", agent(), |tx| tx.close_issue(&second, &CloseOptions::default()));
    ws.write("carol", person(), |tx| tx.resolve_gate(&gate, Some("approved"), false, None));
    let claim = ws.write("bot", agent(), |tx| tx.claim(&first, &ClaimOptions::default()));
    ws.write("bot", agent(), |tx| tx.heartbeat(&first, Some(claim.lease.token), None));
    ws.write("bot", agent(), |tx| {
        tx.close_issue(&first, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() })
    });
    reads(ws);
    // Reopening the step reopens the groups closed above it, each recompute
    // leaving out the subtree reopened before.
    let reopened = ws.write("bot", agent(), |tx| tx.reopen_issue(&first, Some("again"), false)).reopened;
    assert_eq!(reopened.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), [inner.as_str(), group.as_str()]);
    ws.write("bot", agent(), |tx| {
        let patch = IssuePatch { parent: Some(Some(run.clone())), ..Default::default() };
        tx.update_issue(&second, &patch, &Guard::default(), false)
    });
    ws.write("alice", None, |tx| tx.remove_dependency(&after, &group));
    ws.write("alice", None, |tx| tx.defer_issue(&group, Some(Timestamp(T0 + 86_400_000))));
    reads(ws);

    // Scratch work under a persistent issue purged, then the run deleted with everything under it.
    let scratch = ws.create(NewIssue { ephemeral: true, ..child("Scratch", &after) });
    let scratch_step = ws.create(NewIssue { ephemeral: true, ..child("Scratch step", &scratch) });
    ws.write("alice", None, |tx| tx.close_issue(&scratch_step, &CloseOptions::default()));
    ws.write("alice", None, |tx| tx.close_issue(&scratch, &CloseOptions::default()));
    ws.write("alice", None, |tx| tx.purge_ephemeral(None, false));
    // Closing as a duplicate, and again as the idempotent no-op.
    let twin = ws.create(NewIssue::titled("Twin"));
    let close_as = |tx: &mut WriteCtx<'_>| {
        tx.close_as(&twin, &after, Replacement::Duplicate, &CloseAsOptions { force: true, ..Default::default() })
    };
    ws.write("alice", None, close_as);
    ws.write("alice", None, close_as);
    ws.write("alice", None, |tx| tx.delete_issues(std::slice::from_ref(&fallback), &DeleteOptions::default()));
    ws.write("alice", None, |tx| {
        tx.delete_issues(
            std::slice::from_ref(&run),
            &DeleteOptions { cascade: true, force: true, ..Default::default() },
        )
    });
}

/// What single commands run, outside the walks: event pages and the polls of
/// followers, pruning, the counts `bd prime` and `bd stats` print, claims and
/// leases, reclaim, memories, comments, request records, gates and config.
fn run_the_commands(ws: &mut Ws) {
    let work = ws.create(NewIssue { labels: vec!["infra".into()], ..NewIssue::titled("Work") });
    let other = ws.create(NewIssue::titled("Other"));
    ws.create(NewIssue { assignee: Some("bob".into()), ..NewIssue::titled("Bob's") });
    // A feature spec with a requirement linked to the work, and specs turned on.
    let spec = ws.create(NewIssue {
        status: Some(Status::Pinned),
        labels: vec!["spec".into(), "area:x".into()],
        ..NewIssue::titled("Spec")
    });
    let rule = ws.create(NewIssue {
        status: Some(Status::Pinned),
        labels: vec!["requirement".into()],
        deps: vec![(DepType::Related, work.clone())],
        ..child("Rule", &spec)
    });
    // A feature epic whose child is linked to the spec: the spec context walks down to it.
    let feature = ws.create(NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled("Feature") });
    ws.create(NewIssue { deps: vec![(DepType::Related, spec.clone())], ..child("Part", &feature) });
    ws.write("alice", None, |tx| config::set(tx, "experimental.features", "specs"));
    // The spec writes (`bd spec new/add/change/remove/link`): built from the
    // operations planned elsewhere, run here so a statement added to them is planned too.
    let from = |title: &str, id: &str| spec_edit::Sentence {
        title: title.into(),
        from: vec![id.into()],
        ..Default::default()
    };
    let top = ws.write("alice", None, |tx| tx.spec_new("x", &from("Top", &work), None)).spec.id;
    ws.write("alice", None, |tx| tx.spec_new("x", &from("Sub", &other), Some(&top)));
    let top_rule = ws.write("alice", None, |tx| tx.spec_add(&top, &from("Rule", &work), false)).requirement.id;
    let goal = ws.write("alice", None, |tx| tx.spec_add(&top, &from("Goal", &work), true)).requirement.id;
    let new_rule = ws.write("alice", None, |tx| tx.spec_change(&top_rule, &from("New rule", &other))).requirement.id;
    ws.write("alice", None, |tx| tx.spec_remove(&goal, "obsolete", std::slice::from_ref(&other)));
    ws.write("alice", None, |tx| tx.spec_link(&work, &[top.clone(), spec.clone()]));
    // A requirement of the hand-made spec superseded by one under `top`, which supersedes it: the
    // shape check walks from spec to spec.
    let moved = ws.create(NewIssue {
        status: Some(Status::Pinned),
        labels: vec!["requirement".into()],
        deps: vec![(DepType::Related, work.clone())],
        ..child("Moved rule", &spec)
    });
    ws.write("alice", None, |tx| tx.close_as(&moved, &new_rule, Replacement::Supersede, &CloseAsOptions::default()));
    ws.write("alice", None, |tx| tx.add_dependency(&spec, &top, DepType::Supersedes, None));
    ws.write("alice", None, |tx| config::set(tx, "events.retain_rows", "100"));
    // Enough events for the automatic prune to run.
    for n in 0..520 {
        ws.write("alice", None, |tx| tx.add_comment(&other, &format!("note {n}")));
    }

    let commands = |ws: &Ws| {
        ws.store
            .read(|r| {
                let head = r.event_head()?;
                for since in [None, Some(head.saturating_sub(10)), Some(head)] {
                    for limit in [None, Some(1), Some(50)] {
                        let page = EventQuery { since, limit, ..Default::default() };
                        r.events(&page)?;
                        r.events(&EventQuery { issue_id: Some(work.clone()), ..page.clone() })?;
                        r.events(&EventQuery { ops: vec!["claimed".into(), "closed".into()], ..page.clone() })?;
                        r.events(&EventQuery { actor: Some("bot".into()), ..page.clone() })?;
                    }
                }
                r.history(&work)?;
                events::floor(r.conn())?;
                r.stats()?;
                metrics::metrics(r.conn(), r.now(), None)?;
                r.leases()?;
                r.lease(&work)?;
                r.memories(None)?;
                r.memories(Some("deploy"))?;
                r.memory("deploy-notes")?;
                r.comments(&other)?;
                comments::count(r.conn(), &other)?;
                r.comments_tail(&other, 3)?;
                r.show_brief(&work, 3)?;
                r.briefs(&[r.issue(&work)?, r.issue(&other)?])?;
                for id in [&work, &other] {
                    r.explain(id, ExplainOptions::default())?;
                    r.explain(id, ExplainOptions { include_deferred: true, include_epics: true, include_gates: true })?;
                }
                r.not_ready(&ReadyQuery { limit: Some(5), ..Default::default() })?;
                r.not_ready(&ReadyQuery {
                    filter: WorkFilter { assignee: Some("bot".into()), ..Default::default() },
                    include_deferred: true,
                    ..Default::default()
                })?;
                r.config_entries()?;
                r.config_value("lease.ttl")?;
                r.label_counts()?;
                r.find_issue(&work)?;
                // An id prefix: ambiguous here.
                assert!(r.resolve_id("t-").is_err());
                gates::list(r.conn(), false)?;
                gates::list(r.conn(), true)?;
                requests::get(r.conn(), "req-1")?;
                let mine = WorkFilter { assignee: Some("bot".into()), ..Default::default() };
                r.ready(&ReadyQuery { filter: mine.clone(), ..Default::default() })?;
                r.list(&ListQuery { filter: mine, statuses: vec![Status::InProgress], ..Default::default() })?;
                // Bound limits and patterns, which must not make SQLite prepare a statement again.
                r.ready(&ReadyQuery { sort: SortPolicy::Hybrid, limit: Some(5), ..Default::default() })?;
                r.list(&ListQuery { limit: Some(10), search: Some("wor".into()), ..Default::default() })?;
                r.blocked(&WorkFilter::default(), Some(10))?;
                // Every time and title filter: plain conditions on the same statements.
                let now = r.now();
                let timed = WorkFilter {
                    created_after: Some(Timestamp(0)),
                    created_before: Some(now),
                    updated_after: Some(Timestamp(0)),
                    updated_before: Some(now),
                    overdue_at: Some(now),
                    stale_before: Some(now),
                    title_contains: Some("50%".into()),
                    ..Default::default()
                };
                r.ready(&ReadyQuery { filter: timed.clone(), ..Default::default() })?;
                let closed = WorkFilter { closed_after: Some(Timestamp(0)), closed_before: Some(now), ..timed };
                r.list(&ListQuery { all: true, filter: closed, ..Default::default() })?;
                // A query naming every field: conditions on the same statement, with
                // label and parent as lookups by key per issue, spec and area as one
                // uncorrelated subquery each (index lookups from its CTEs).
                let expr = format!(
                    "status = open AND priority <= 2 AND type ~ task AND NOT assignee = none \
                     AND (label = infra OR label ~ inf OR label = none) \
                     AND (title ~ wor OR description ~ x OR notes = '') AND id = t-* \
                     AND (parent = {work} OR parent = none OR parent != t-99) \
                     AND (external_ref = none OR external_ref ~ gh: OR external_ref = 'gh:o/r#1') \
                     AND created > 7d AND updated != 2026-01-15 AND closed = none \
                     AND (due < +3d OR defer >= 2026-01-01) AND pinned = false AND ephemeral = no \
                     AND (spec = {spec} OR spec != none OR area = x OR area != y)"
                );
                for sort in [ListSort::Priority, ListSort::Id] {
                    r.query(&QueryRequest { expr: expr.clone(), sort, reverse: false, limit: Some(10) })?;
                }
                // Hierarchy views: epics, those ready to close, stale work, orphans.
                r.epics(true)?;
                r.epics(false)?;
                r.close_eligible_epics()?;
                r.stale(Duration::from_secs(86_400), None)?;
                r.stale(Duration::ZERO, Some(5))?;
                r.orphans("t")?;
                // Feature specs: the tree, the listing, drift, candidates and the counts prime and doctor take.
                specs::show(r.conn(), "x")?;
                specs::show(r.conn(), &spec)?;
                specs::list(r.conn())?;
                specs::drift(r.conn(), Some(Timestamp(0)))?;
                specs::malformed(r.conn())?;
                specs::unlinked_counts(r.conn(), Some(Timestamp(0)))?;
                specs::candidates(r.conn(), None)?;
                specs::candidates(r.conn(), specs::since(r.conn())?)?;
                specs::open_count(r.conn())?;
                // The specs governing an issue, and whether a link covers it (`bd show`, `bd claim`, `bd close`).
                for id in [&work, &spec, &rule, &other, &feature] {
                    spec_context::governing(r.conn(), id)?;
                    spec_context::covered(r.conn(), id)?;
                }
                // Graph export of the open issues: the list statement, then edges per issue.
                r.subgraph(None, &EdgeSet::Default, 10)?;
                r.events_each(&EventQuery { limit: Some(5), ..Default::default() }, 2, &mut |_| Ok(()))?;
                let after = EventQuery { since: Some(head.saturating_sub(10)), limit: Some(7), ..Default::default() };
                r.events_each(&after, 3, &mut |_| Ok(()))?;
                Ok(())
            })
            .unwrap();
    };
    commands(ws);

    let claim = ws.write("bot", agent(), |tx| tx.claim(&work, &ClaimOptions::default()));
    ws.write("bot", agent(), |tx| tx.heartbeat(&work, Some(claim.lease.token), None));
    commands(ws);
    let next = ws.write("bot", agent(), |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()));
    let next = next.expect("ready work").issue.id;
    ws.write("bot", agent(), |tx| tx.release(&next, &ReleaseOptions::default()));
    let epics =
        ReadyQuery { filter: WorkFilter { types: vec!["epic".into()], ..Default::default() }, ..Default::default() };
    ws.write("bot", agent(), |tx| tx.claim_next(&epics, &ClaimOptions::default()));
    // Close a child and claim the next one near its parent, as `bd close
    // --claim-next` does; then look without claiming, as --suggest-next does.
    let family = ws.create(NewIssue::titled("Family"));
    let first = ws.create(child("First", &family));
    ws.create(child("Second", &family));
    ws.write("bot", agent(), |tx| {
        let near = tx.parent(&first)?;
        tx.close_issue(&first, &CloseOptions::default())?;
        tx.claim_next_near(&ReadyQuery::default(), near.as_deref(), &ClaimOptions::default())
    });
    ws.write("bot", agent(), |tx| tx.next_ready(&ReadyQuery::default(), Some(&family)));
    ws.write("bot", agent(), |tx| tx.suggest_next(&ReadyQuery::default(), Some(&family)));
    ws.write("bot", agent(), |tx| tx.claim(&other, &ClaimOptions::default()));
    ws.clock.advance(Duration::from_secs(3600));
    ws.write("bd-serve", None, |tx| tx.reclaim_expired(&ReclaimOptions { dry_run: true, ..Default::default() }));
    ws.write("bd-serve", None, |tx| tx.reclaim_expired(&ReclaimOptions::default()));
    ws.write("alice", None, |tx| tx.remember(Some("deploy-notes"), "Deploys go through CI", None));
    ws.write("alice", None, |tx| tx.forget("deploy-notes"));
    let timer = GateSpec { timeout: Some("1m".into()), ..GateSpec::new(GateKind::Timer) };
    let gate = ws.write("alice", None, |tx| {
        tx.create_gate(NewGate {
            spec: timer,
            blocks: vec![other.clone()],
            title: None,
            description: String::new(),
            assignee: None,
            parent: None,
            priority: None,
            ephemeral: false,
        })
    });
    ws.store
        .read(|r| {
            for g in gates::list(r.conn(), false)? {
                gates::evaluate_local(r.conn(), &g, r.now())?;
            }
            Ok(())
        })
        .unwrap();
    ws.write("bd-serve", None, |tx| tx.escalate_gate(&gate.id, "overdue"));
    ws.write("bd-serve", None, |tx| tx.resolve_gate(&gate.id, Some("timer passed"), false, None));
    ws.write("alice", None, |tx| {
        tx.record_request("req-1", "token-1", "close")?;
        tx.close_issue(&work, &CloseOptions { take_over: true, ..Default::default() })?;
        tx.save_request_response("req-1", "{}")
    });
    ws.write("bd-serve", None, |tx| tx.prune_requests(Timestamp(T0 + 86_400_000), 10));
    github_sync(ws);
    let head = ws.store.read(|r| r.event_head()).unwrap();
    ws.write("alice", None, |tx| tx.prune_events(&PruneOptions { before: Some(head - 20), ..Default::default() }));
    ws.write("alice", None, |tx| tx.prune_events(&PruneOptions { keep: Some(10), ..Default::default() }));
    ws.write("alice", None, |tx| {
        tx.prune_events(&PruneOptions { older_than: Some(Duration::from_secs(60)), ..Default::default() })
    });
    commands(ws);
    history_and_compaction(ws, &work);
    spec_history(ws, &spec);
}

/// `bd spec show --as-of` and `bd spec changes`: the events after a seq (a
/// rowid range) and after a time (`idx_events_ts`), with the rebuilds they
/// lead to, over a history an older bd wrote (left by
/// [`history_and_compaction`]).
fn spec_history(ws: &mut Ws, spec: &str) {
    // A time inside the retained history, then a requirement added and closed after it.
    let t = ws.clock.now();
    let later = ws.create(NewIssue {
        status: Some(Status::Pinned),
        labels: vec!["requirement".into()],
        ..child("Later rule", spec)
    });
    ws.write("alice", None, |tx| tx.close_issue(&later, &CloseOptions::default()));
    let now = ws.clock.now();
    ws.store
        .read(|r| {
            let head = r.event_head()?;
            // Errors (a point before what is retained) are ignored: the statements are what is checked.
            for point in [asof::Point::Seq(head - 3), asof::Point::Time(now.minus(Duration::from_secs(60)))] {
                let _ = specs::history::show_as_of(r.conn(), spec, point);
            }
            let _ = specs::history::show_as_of(r.conn(), "x", asof::Point::Seq(head));
            let _ = specs::history::changes(r.conn(), None, asof::Point::Seq(head - 10), asof::Point::Time(now));
            let _ = specs::history::changes(r.conn(), Some(spec), asof::Point::Time(t), asof::Point::Seq(head));
            Ok(())
        })
        .unwrap();
}

/// Issues as of past points (live, deleted, purged; before and after a prune;
/// across history an older bd wrote), a deletion dropping a survivor's edge,
/// and compaction: candidates, stats and a compaction.
fn history_and_compaction(ws: &mut Ws, work: &str) {
    let gone = ws.create(NewIssue::titled("Gone"));
    let survivor = ws.create(NewIssue {
        description: format!("Follows {work}, at length so that a summary is shorter"),
        deps: vec![(DepType::Related, gone.clone())],
        ..NewIssue::titled("Survivor")
    });
    let scratch = ws.create(NewIssue { ephemeral: true, ..NewIssue::titled("Scratch") });
    ws.write("alice", None, |tx| tx.close_issue(&scratch, &CloseOptions::default()));
    let mid = ws.store.read(|r| r.event_head()).unwrap();
    let t_mid = ws.clock.now();
    ws.write("alice", None, |tx| {
        tx.delete_issues(std::slice::from_ref(&gone), &DeleteOptions { force: true, ..Default::default() })
    });
    ws.write("alice", None, |tx| tx.purge_ephemeral(None, false));
    ws.write("alice", None, |tx| tx.close_issue(&survivor, &CloseOptions::default()));
    let revision = ws.store.read(|r| r.issue(&survivor)).unwrap().revision;
    let guard = Guard { if_revision: Some(revision), ..Default::default() };
    ws.write("alice", None, |tx| tx.compact_issue(&survivor, "Followed it", &guard));
    let reads = |ws: &Ws| {
        ws.store
            .read(|r| {
                for id in [&survivor, &gone, &scratch, &work.to_string()] {
                    for point in [asof::Point::Seq(mid), asof::Point::Time(t_mid), asof::Point::Seq(r.event_head()?)] {
                        // Points before what is retained fail; the statements are what is checked.
                        let _ = r.issue_as_of(id, point);
                    }
                }
                r.compact_candidates(Duration::ZERO, None)?;
                r.compact_candidates(Duration::from_secs(86_400), Some(5))?;
                r.compact_stats(Duration::ZERO)?;
                Ok(())
            })
            .unwrap();
    };
    reads(ws);
    ws.write("alice", None, |tx| tx.prune_events(&PruneOptions { before: Some(mid), ..Default::default() }));
    reads(ws);
    // History an older bd wrote: everything so far.
    let head = ws.store.read(|r| r.event_head()).unwrap();
    ws.sql(&format!("UPDATE meta SET value = '{}' WHERE key = 'history_complete_from'", head + 1));
    reads(ws);
}

/// `bd github`: a GitHub issue created in bd, a marker resolved, the linked
/// issues listed, and an apply that pulls a change and imports a comment.
fn github_sync(ws: &mut Ws) {
    use bd_core::github::{self, GithubComment, GithubIssue, IssueApply, Stamp, SyncConfig};
    let cfg = SyncConfig::default();
    let issue = |n: u64, title: &str, body: &str| GithubIssue {
        number: n,
        node_id: String::new(),
        title: title.into(),
        body: body.into(),
        open: true,
        state_reason: None,
        labels: vec!["bug".into()],
        assignees: vec![],
        updated_at: Timestamp(T0),
        html_url: String::new(),
        comments: 0,
        pull_request: false,
        author: Some("bd-bot".into()),
    };
    let gh = issue(7, "From GitHub", "");
    let created = ws.write("sync", None, |tx| tx.github_create("acme/app", &gh, None, &cfg)).0;
    let mine = ws.create(NewIssue::titled("Mine"));
    ws.store
        .read(|r| {
            github::linked(r.conn(), "acme/app")?;
            github::resolve_markers(r.conn(), &[issue(8, "Mine", &github::marker(&mine))], Some("bd-bot"))?;
            Ok(())
        })
        .unwrap();
    let local = ws.store.read(|r| r.issue(&created.id)).unwrap();
    let mut changed = gh.clone();
    changed.title = "Renamed".into();
    changed.open = false;
    let comment = GithubComment {
        id: 1,
        user: "octo".into(),
        body: "hi".into(),
        created_at: Timestamp(T0),
        updated_at: Timestamp(T0),
        html_url: String::new(),
    };
    let apply = IssueApply {
        id: created.id.clone(),
        expected_revision: local.revision,
        repo: "acme/app".into(),
        number: 7,
        pull: Some(github::pull_changes(&local, github::Link::of(&local).as_ref(), &changed, &cfg)),
        import: vec![comment],
        adopt: vec![],
        pushed_comments: vec![],
        github_seen: changed.clone(),
        github_after: changed,
        own_github_at: None,
        local_before: local,
        stamp: Stamp::BOTH,
        comment_count: 1,
        set_external_ref: true,
    };
    ws.write("sync", None, |tx| tx.github_apply(&apply, &cfg));
}

/// The commands, then renaming the prefix: every issue, edge, comment,
/// lease and event moves. Kept out of [`no_statement_is_prepared_again`]:
/// the rename's `PRAGMA defer_foreign_keys` expires the connection's cached
/// statements (SQLite does so for every flag pragma), so those it runs
/// next are prepared again, once, by design.
fn run_the_commands_and_rename(ws: &mut Ws) {
    run_the_commands(ws);
    ws.write("alice", None, |tx| tx.rename_prefix(&RenamePrefixOptions { to: "u".into(), from: None }));
}

/// Statistics a workspace's first commands left when bd still ran `PRAGMA
/// optimize` as each command exited (or that `ANALYZE` run by hand leaves):
/// it analyzes a table the first time it is used, the issues with one issue
/// in them and the edges with one edge, and again only once it is ten times
/// larger. A long-lived connection (`bd serve`'s, or one import of many
/// issues) keeps the statistics it opened with.
const YOUNG: &str = "INSERT INTO issues (id, title, created_at, updated_at) VALUES ('p', 'Parent', 0, 0);
    ANALYZE;
    INSERT INTO issues (id, title, created_at, updated_at) VALUES ('c', 'Child', 0, 0);
    INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at) VALUES ('c', 'p', 'parent-child', 0);
    ANALYZE dependencies;";

/// Statistics of a long chain of open work, recorded before anything was
/// blocked, deferred or closed.
const GROWN: &str = "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < 2000)
    INSERT INTO issues (id, title, created_at, updated_at) SELECT 'c' || k, 'Level ' || k, k, k FROM n;
    WITH RECURSIVE n(k) AS (SELECT 2 UNION ALL SELECT k + 1 FROM n WHERE k < 2000)
    INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
    SELECT 'c' || k, 'c' || (k - 1), 'parent-child', 0 FROM n;
    ANALYZE;";

/// `EXPLAIN QUERY PLAN` rows: (id, parent, detail).
fn plan(conn: &Connection, sql: &str) -> Vec<(i64, i64, String)> {
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    // Parameters stay unbound: plans do not depend on their values.
    let mut rows = stmt.raw_query();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        out.push((row.get(0).unwrap(), row.get(1).unwrap(), row.get(3).unwrap()));
    }
    out
}

/// Aliases of the tables a statement reads, by name.
fn tables(sql: &str) -> BTreeMap<String, String> {
    let re = regex_lite::Regex::new(concat!(
        r"(?i)\b(?:FROM|JOIN)\s+(issues|dependencies|labels|comments|leases|events|memories|requests|config|counters|meta|child_counters)\b",
        r"(?:\s+(?:AS\s+)?([A-Za-z_]\w*))?",
    ))
    .unwrap();
    const KEYWORDS: &[&str] = &[
        "WHERE", "JOIN", "ON", "ORDER", "GROUP", "LIMIT", "CROSS", "LEFT", "INNER", "INDEXED", "NOT", "USING", "UNION",
    ];
    let mut out = BTreeMap::new();
    for c in re.captures_iter(sql) {
        let table = c[1].to_ascii_lowercase();
        out.insert(table.clone(), table.clone());
        if let Some(alias) = c.get(2).map(|m| m.as_str())
            && !KEYWORDS.iter().any(|k| k.eq_ignore_ascii_case(alias))
        {
            out.insert(alias.to_string(), table);
        }
    }
    out
}

/// What is wrong with `sql`'s plan: each table it scans where it may not.
fn scans(conn: &Connection, sql: &str) -> Vec<String> {
    let rows = plan(conn, sql);
    let tables = tables(sql);
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail = |id: i64| rows.iter().find(|r| r.0 == id).map(|r| r.2.as_str()).unwrap_or("");
    let parent = |id: i64| rows.iter().find(|r| r.0 == id).map(|r| r.1).unwrap_or(0);
    let is_loop = |d: &str| d.starts_with("SCAN ") || d.starts_with("SEARCH ");
    let mut bad = Vec::new();
    for (id, up, d) in &rows {
        if d.contains("AUTOMATIC") {
            bad.push(d.clone());
            continue;
        }
        let Some(name) = d.strip_prefix("SCAN ").and_then(|s| s.split(' ').next()) else { continue };
        let Some(table) = tables.get(name) else {
            continue; // a CTE or subquery
        };
        let whole_table = WHOLE_TABLE.iter().any(|(w, t)| t == table && flat.contains(w));
        // Inside a loop: the inner side of a join, a correlated subquery or a
        // recursive step, run once per row of something else.
        let inner = rows.iter().any(|r| r.1 == *up && r.0 < *id && is_loop(&r.2));
        let mut nested = false;
        let mut at = *up;
        while at != 0 {
            let a = detail(at);
            nested |= a.starts_with("CORRELATED") || a == "RECURSIVE STEP";
            // A subquery that is not correlated runs once, wherever it is listed.
            let once = a.starts_with("LIST SUBQUERY") || a.starts_with("SCALAR SUBQUERY");
            nested |= !once && rows.iter().any(|r| r.1 == parent(at) && r.0 < at && is_loop(&r.2));
            at = parent(at);
        }
        if inner || nested || !whole_table {
            bad.push(d.clone());
        }
    }
    bad
}

/// Each statement of `statements` that scans a table where it may not in
/// `ws`, with its plan.
fn failures(name: &str, ws: &Ws, statements: &BTreeSet<String>) -> Vec<String> {
    let conn = ws.store.connection();
    let mut out = Vec::new();
    for sql in statements {
        let bad = scans(conn, sql);
        if !bad.is_empty() {
            let plan: Vec<String> = plan(conn, sql).into_iter().map(|r| r.2).collect();
            out.push(format!("{name}: {sql}\n  scans: {bad:?}\n  plan: {plan:#?}"));
        }
    }
    out
}

#[test]
fn graph_walks_plan_index_lookups_under_stale_statistics() {
    let statements = statements_of(walk_the_graph);
    assert!(statements.len() > 50, "{} statements", statements.len());

    let mut failures = Vec::new();
    for (name, setup) in [("young", YOUNG), ("grown", GROWN), ("never analyzed", "")] {
        let mut stale = Ws::new();
        stale.sql(setup);
        assert_eq!(stale.analyzed(), !setup.is_empty(), "{name}");
        failures.extend(self::failures(name, &stale, &statements));
    }
    assert!(failures.is_empty(), "{} statements scan a table:\n\n{}", failures.len(), failures.join("\n\n"));
}

/// A young workspace as bd leaves it: a few commands, each opening the
/// database and closing it as it exits.
fn used_by_commands() -> Ws {
    let mut ws = Ws::new().reopen();
    for title in ["First", "Second", "Third"] {
        let id = ws.create(NewIssue::titled(title));
        ws.store
            .read(|r| {
                r.ready(&ReadyQuery::default())?;
                r.list(&ListQuery::default())?;
                r.events(&EventQuery { since: Some(0), ..Default::default() })?;
                r.history(&id)?;
                r.stats()?;
                Ok(())
            })
            .unwrap();
        ws = ws.reopen();
    }
    ws
}

/// A young workspace whose tables were analyzed (by `ANALYZE` run by hand, or
/// an older bd's `PRAGMA optimize`), then opened by bd.
fn analyzed_then_opened() -> Ws {
    let mut ws = Ws::new();
    ws.create(NewIssue::titled("First"));
    ws.sql(YOUNG);
    assert!(ws.analyzed());
    ws.reopen()
}

#[test]
fn every_statement_plans_index_lookups_in_workspaces_as_bd_leaves_them() {
    let mut statements = statements_of(walk_the_graph);
    let commands = statements_of(run_the_commands_and_rename);
    assert!(commands.len() > 50, "{} statements", commands.len());
    // The history's rarer statements ran: an older bd's history, a quiet deletion, dropped edges, arming.
    for needle in [
        "op IN ('prefix_renamed','deleted','purged','run_compacted')",
        "op IN ('purged','run_compacted') ORDER BY seq",
        "FROM dependencies INDEXED BY idx_deps_target WHERE depends_on_id = ?1",
        "SELECT metadata FROM issues WHERE id = ?1",
        "SELECT ts FROM events WHERE seq = ?1",
        // Spec history: the events after a time through their index, after a seq by rowid.
        "FROM events INDEXED BY idx_events_ts WHERE ts > ?1 AND ts <= ?2",
        "FROM events WHERE seq > ?1 AND seq <= ?2 AND op IN",
        // Feature specs: closed and open work by status through the ready index, labels by label, edges by end.
        "i.status = 'closed' AND i.closed_at >= ?1",
        "i.status IN ('open','in_progress','blocked','deferred','pinned') AND i.created_at >= ?1",
        "SELECT issue_id FROM labels WHERE label = ?1",
        "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = ?2",
        "WHERE lb.label = ?1 AND i.status <> 'closed'",
        "FROM events WHERE issue_id = ?1 AND op = 'reopened'",
        "dep_type IN (?2, ?3)",
        // Spec context: related edges by either end and children by parent, each under a bound LIMIT; labels by issue;
        // a spec's children (its requirements and non-goals) under a bound LIMIT on the edges, then issues by id.
        "WHERE issue_id = ?1 AND dep_type = 'related'",
        "WHERE depends_on_id = ?1 AND dep_type = 'related'",
        "SELECT label FROM labels WHERE issue_id = ?1 ORDER BY label",
        "dep_type = 'parent-child'\n             ORDER BY issue_id LIMIT ?2",
        "ORDER BY issue_id LIMIT ?2) d\n         CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = d.issue_id",
        // bd query's spec and area: the covering links, from a spec's parts, an area's specs, or every part.
        "i.id IN (WITH RECURSIVE sp(id) AS (SELECT s.issue_id FROM labels s WHERE s.issue_id = ?",
        "WHERE a.label = 'area:' || ?",
        "parts(id) AS (SELECT issue_id FROM labels WHERE label IN ('spec', 'requirement', 'non-goal'))",
        // Id prefixes: seeking the primary key over their case variants.
        "SELECT 1 FROM issues WHERE id >= ?1 AND id < ?2 LIMIT 1",
        "SELECT id FROM issues WHERE id >= ?1 AND id < ?2 ORDER BY id LIMIT 6",
    ] {
        assert!(commands.iter().any(|s| s.contains(needle)), "no statement with {needle:?} ran");
    }
    statements.extend(commands);

    let mut failures = Vec::new();
    for (name, ws) in [
        ("used by commands", used_by_commands()),
        ("analyzed, then opened", analyzed_then_opened()),
        ("new", Ws::new()),
    ] {
        if ws.analyzed() {
            failures.push(format!("{name}: holds planner statistics"));
        }
        failures.extend(self::failures(name, &ws, &statements));
    }
    assert!(failures.is_empty(), "{} failures:\n\n{}", failures.len(), failures.join("\n\n"));
}

/// bd's connections keep the query planner stability guarantee (see
/// `Store`): without it, SQLite (built with STAT4) plans with some bound
/// values, such as a LIMIT's or a LIKE pattern, and so prepares a statement
/// again each time one is bound, and each run of a cached statement pays its
/// planning.
#[test]
fn no_statement_is_prepared_again() {
    let mut again = BTreeMap::new();
    for work in [walk_the_graph as fn(&mut Ws), run_the_commands] {
        again.extend(recorded(work).1);
    }
    assert!(again.is_empty(), "{} statements prepared again: {again:#?}", again.len());
}

#[test]
fn opening_never_waits_to_drop_statistics() {
    let mut ws = Ws::new();
    ws.create(NewIssue::titled("First"));
    ws.sql(YOUNG);
    let path = ws.store.path().to_path_buf();
    // Another process is writing: opening leaves the statistics for later rather than wait for it.
    let writer = rusqlite::Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    let opts = OpenOptions { clock: ws.clock.clone(), busy_timeout: Duration::from_secs(5), ..Default::default() };
    let busy = Store::open(&path, opts.clone()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "waited {:?}", started.elapsed());
    let held = Ws { _dir: tempfile::tempdir().unwrap(), store: busy, clock: ws.clock.clone() };
    assert!(held.analyzed(), "left for later");
    // The busy handler is back: a write waits for the writer, as it always did.
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        writer.execute_batch("COMMIT").unwrap();
    });
    let mut held = held;
    held.create(NewIssue::titled("Second"));
    release.join().unwrap();
    // Free again, the next open drops them.
    assert!(!ws.reopen().analyzed());
}

/// `bd stale` reads only live issues, through the ready index, and each one's
/// lease by its key.
#[test]
fn stale_searches_the_ready_index_and_leases_by_key() {
    let statements = statements_of(run_the_commands);
    let sql = statements.iter().find(|s| s.contains("le.holder, le.expires_at")).expect("bd stale's statement");
    for ws in [used_by_commands(), Ws::new()] {
        let details: Vec<String> = plan(ws.store.connection(), sql).into_iter().map(|r| r.2).collect();
        assert!(
            details.iter().any(|d| d.starts_with("SEARCH i USING INDEX idx_issues_ready (status=?)")),
            "{details:#?}"
        );
        assert!(details.iter().any(|d| d == "SEARCH le USING PRIMARY KEY (issue_id=?) LEFT-JOIN"), "{details:#?}");
    }
}
