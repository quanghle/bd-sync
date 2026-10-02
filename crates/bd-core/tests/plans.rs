//! Query plans under stale planner statistics.
//!
//! SQLite plans each statement from the statistics `ANALYZE` (which `PRAGMA
//! optimize` runs) recorded, and those can be far from the data: a young
//! workspace records them while it holds an issue or two, and `bd serve`'s
//! pooled connections keep theirs. Believing a table holds a row, SQLite
//! happily scans all of it per lookup, and a walk over a deep hierarchy
//! (recomputing blocked flags, closing nested groups, descendants, a
//! deferred subtree) turns quadratic. This test runs the operations that walk
//! the graph while recording every statement they prepare, then has SQLite
//! plan each one under stale statistics and without any: no statement may
//! scan a table inside a loop (a correlated subquery, a recursive step, the
//! inner side of a join), and only the few in [`WHOLE_TABLE`], which read
//! every issue by design, may scan one at all.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bd_core::gates::{GateKind, GateSpec, NewGate};
use bd_core::playbook;
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::*;
use rusqlite::Connection;
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use serde_json::json;
use tempfile::TempDir;

const T0: i64 = 1_700_000_000_000;

/// Statements that read every issue (or edge) by design, once per command:
/// they may scan a table as their outermost loop, never inside another.
const WHOLE_TABLE: &[&str] = &[
    // list, ready and blocked (`QueryParts`), with their filters
    "WHERE 1=1",
    // the blocked flags from scratch (`doctor`, imports), and cycles
    "WITH RECURSIVE direct(id) AS",
    "SELECT id, is_blocked FROM issues ORDER BY id",
    "SELECT issue_id, depends_on_id FROM dependencies WHERE dep_type IN",
    // stats
    "SELECT COUNT(*) FROM issues",
    "SELECT status, COUNT(*) FROM issues GROUP BY status",
    "FROM issues e WHERE e.issue_type = 'epic'",
    // purge candidates
    "SELECT id FROM issues WHERE ephemeral = 1",
    // the open gates a policy protects
    "FROM issues i WHERE i.issue_type = 'gate'",
    // playbook runs
    "WHERE json_extract(i.metadata, '$.playbook.role') = 'run'",
    // leases and memories
    "FROM leases",
    "FROM memories",
];

static STATEMENTS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn record(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(_, sql) = event {
        // Foreign key actions run as `-- TRIGGER ...` programs of their statement.
        if !sql.starts_with("--") {
            STATEMENTS.lock().unwrap().insert(sql.to_string());
        }
    }
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
}

fn agent() -> Option<Policy> {
    Some(Policy { actor: "bot".into(), admin: false, human: false })
}

fn person() -> Option<Policy> {
    Some(Policy { actor: "carol".into(), admin: false, human: true })
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
                    r.depths(std::slice::from_ref(id))?;
                    r.dep_tree(id, Direction::Down, usize::MAX)?;
                    r.dep_tree(id, Direction::Up, usize::MAX)?;
                    issues::descendants(r.conn(), id)?;
                }
                let below = WorkFilter { parent: Some(run.clone()), ..Default::default() };
                r.ready(&ReadyQuery::default())?;
                r.ready(&ReadyQuery { filter: below.clone(), ..Default::default() })?;
                r.list(&ListQuery { filter: below.clone(), ..Default::default() })?;
                r.blocked(&below, None)?;
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
    ws.write("carol", person(), |tx| tx.resolve_gate(&gate, Some("approved"), false));
    let claim = ws.write("bot", agent(), |tx| tx.claim(&first, &ClaimOptions::default()));
    ws.write("bot", agent(), |tx| tx.heartbeat(&first, Some(claim.lease.token), None));
    ws.write("bot", agent(), |tx| {
        tx.close_issue(&first, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() })
    });
    reads(ws);
    ws.write("bot", agent(), |tx| tx.reopen_issue(&first, Some("again")));
    ws.write("bot", agent(), |tx| {
        let patch = IssuePatch { parent: Some(Some(run.clone())), ..Default::default() };
        tx.update_issue(&second, &patch, &Guard::default(), false)
    });
    ws.write("alice", None, |tx| tx.remove_dependency(&after, &group));
    ws.write("alice", None, |tx| tx.defer_issue(&group, Some(Timestamp(T0 + 86_400_000))));
    reads(ws);

    // Scratch work purged, then the run deleted with everything under it.
    let scratch = ws.create(NewIssue { ephemeral: true, ..NewIssue::titled("Scratch") });
    let scratch_step = ws.create(NewIssue { ephemeral: true, ..child("Scratch step", &scratch) });
    ws.write("alice", None, |tx| tx.close_issue(&scratch_step, &CloseOptions::default()));
    ws.write("alice", None, |tx| tx.close_issue(&scratch, &CloseOptions::default()));
    ws.write("alice", None, |tx| tx.purge_ephemeral(None, false));
    ws.write("alice", None, |tx| tx.delete_issues(std::slice::from_ref(&fallback), &DeleteOptions::default()));
    ws.write("alice", None, |tx| {
        tx.delete_issues(
            std::slice::from_ref(&run),
            &DeleteOptions { cascade: true, force: true, ..Default::default() },
        )
    });
}

/// Statistics as a workspace's first commands leave them: `PRAGMA optimize`,
/// run as each command exits, analyzes a table the first time it is used,
/// the issues with one issue in them and the edges with one edge, and again
/// only once it is ten times larger. A long-lived connection (`bd serve`'s,
/// or one import of many issues) keeps the statistics it opened with.
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
        r"(?i)\b(?:FROM|JOIN)\s+(issues|dependencies|labels|comments|leases|events|memories|requests)\b",
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
        if let Some(alias) = c.get(2).map(|m| m.as_str()) {
            if !KEYWORDS.iter().any(|k| k.eq_ignore_ascii_case(alias)) {
                out.insert(alias.to_string(), table);
            }
        }
    }
    out
}

/// What is wrong with `sql`'s plan: each table it scans where it may not.
fn scans(conn: &Connection, sql: &str) -> Vec<String> {
    let rows = plan(conn, sql);
    let tables = tables(sql);
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let whole_table = WHOLE_TABLE.iter().any(|w| flat.contains(w));
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
        if !tables.contains_key(name) {
            continue; // a CTE or subquery
        }
        // Inside a loop: the inner side of a join, a correlated subquery or a
        // recursive step, run once per row of something else.
        let inner = rows.iter().any(|r| r.1 == *up && r.0 < *id && is_loop(&r.2));
        let mut nested = false;
        let mut at = *up;
        while at != 0 {
            let a = detail(at);
            nested |= a.starts_with("CORRELATED") || a == "RECURSIVE STEP";
            nested |= rows.iter().any(|r| r.1 == parent(at) && r.0 < at && is_loop(&r.2));
            at = parent(at);
        }
        if inner || nested || !whole_table {
            bad.push(d.clone());
        }
    }
    bad
}

#[test]
fn graph_walks_plan_index_lookups_under_stale_statistics() {
    let mut ws = Ws::new();
    ws.store.connection().trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(record));
    walk_the_graph(&mut ws);
    ws.store.connection().trace_v2(TraceEventCodes::empty(), None);
    let statements = std::mem::take(&mut *STATEMENTS.lock().unwrap());
    assert!(statements.len() > 50, "{} statements", statements.len());

    let mut failures = Vec::new();
    for (name, setup) in [("young", YOUNG), ("grown", GROWN), ("never analyzed", "")] {
        let mut stale = Ws::new();
        stale.sql(setup);
        let conn = stale.store.connection();
        let analyzed: i64 =
            conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'sqlite_stat1'", [], |r| r.get(0)).unwrap();
        assert_eq!(analyzed, i64::from(!setup.is_empty()), "{name}");
        for sql in &statements {
            let bad = scans(conn, sql);
            if !bad.is_empty() {
                let plan: Vec<String> = plan(conn, sql).into_iter().map(|r| r.2).collect();
                failures.push(format!("{name}: {sql}\n  scans: {bad:?}\n  plan: {plan:#?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} statements scan a table:\n\n{}", failures.len(), failures.join("\n\n"));
}
