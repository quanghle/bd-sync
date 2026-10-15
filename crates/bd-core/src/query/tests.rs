//! Parser, Display, compile and limit tests, plus seeded fuzz and property
//! tests (an xorshift generator written here: no test-only crates).

use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveDate;
use rusqlite::params_from_iter;
use rusqlite::types::Value as SqlValue;

use super::*;
use crate::config::IdMode;
use crate::issues::CloseOptions;
use crate::model::{NewIssue, Status};
use crate::store::{InitOptions, OpenOptions, Store};
use crate::time::{Clock, ManualClock, Timestamp, local_day};

// ---- helpers ----------------------------------------------------------------

fn cmp(field: Field, op: Op, value: Option<&str>) -> Expr {
    let value = value.map_or(Value::None, |v| Value::Text(v.to_string()));
    Expr::Cmp(Comparison { field, op, value, column: 0 })
}

fn title(v: &str) -> Expr {
    cmp(Field::Title, Op::Eq, Some(v))
}

fn not(e: Expr) -> Expr {
    Expr::Not(Box::new(e))
}

fn err(src: &str) -> ParseError {
    parse(src).expect_err(src)
}

/// The 1-based column of the first `needle` in `src`.
fn col(src: &str, needle: &str) -> usize {
    src[..src.find(needle).expect(needle)].chars().count() + 1
}

fn jan(day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 1, day).unwrap()
}

struct Seeded {
    _dir: tempfile::TempDir,
    store: Store,
    now: Timestamp,
}

fn store_with(ids: &[&str]) -> (tempfile::TempDir, Store, Arc<ManualClock>) {
    let dir = tempfile::tempdir().unwrap();
    let day1 = local_day(jan(15), "").unwrap().0;
    let clock = Arc::new(ManualClock::new(day1.plus(Duration::from_secs(3600))));
    let mut store = Store::init(
        &dir.path().join("bd.db"),
        InitOptions { prefix: "t".into(), id_mode: IdMode::Counter },
        OpenOptions { clock: clock.clone(), ..Default::default() },
    )
    .unwrap();
    for id in ids {
        store
            .write("create", "alice", |tx| {
                tx.create_issue(NewIssue { id: Some(id.to_string()), ..NewIssue::titled(*id) })
            })
            .unwrap();
    }
    (dir, store, clock)
}

/// t-1 (epic, label urgent) is t-2's parent; t-2 has a hostile title, bob,
/// label `a%b` and a past due date; t-3 is closed. t-10 (ephemeral, due
/// later) and t-11 (pinned) are created a day later, and prefix-match `t-1`.
fn seeded() -> Seeded {
    let (dir, mut store, clock) = store_with(&[]);
    let day1 = clock.now();
    store
        .write("seed", "alice", |tx| {
            tx.create_issue(NewIssue {
                id: Some("t-1".into()),
                issue_type: Some("epic".into()),
                labels: vec!["urgent".into()],
                ..NewIssue::titled("Parent epic")
            })?;
            tx.create_issue(NewIssue {
                id: Some("t-2".into()),
                parent: Some("t-1".into()),
                assignee: Some("bob".into()),
                labels: vec!["a%b".into()],
                due_at: Some(day1.minus(Duration::from_secs(86_400))),
                ..NewIssue::titled("x' OR 1=1 --")
            })?;
            tx.create_issue(NewIssue {
                id: Some("t-3".into()),
                assignee: Some("alice".into()),
                priority: Some(0),
                description: "say \"hi\"; -- \\ *".into(),
                notes: "Notes with [brackets] and ?".into(),
                ..NewIssue::titled("50% done_now")
            })?;
            tx.close_issue("t-3", &CloseOptions { reason: Some("done".into()), ..Default::default() })
        })
        .unwrap();
    clock.set(local_day(jan(16), "").unwrap().0.plus(Duration::from_secs(7200)));
    let now = clock.now();
    store
        .write("seed", "alice", |tx| {
            tx.create_issue(NewIssue {
                id: Some("t-10".into()),
                ephemeral: true,
                due_at: Some(now.plus(Duration::from_secs(86_400))),
                ..NewIssue::titled("ten")
            })?;
            tx.create_issue(NewIssue {
                id: Some("t-11".into()),
                status: Some(Status::Pinned),
                ..NewIssue::titled("eleven")
            })
        })
        .unwrap();
    Seeded { _dir: dir, store, now }
}

impl Seeded {
    /// Compile `e` and run it in `bd query`'s statement shape.
    fn run(&self, e: &Expr) -> Result<Vec<String>, CompileError> {
        let (frag, params) = compile(self.store.connection(), e, self.now)?;
        assert_eq!(frag.matches('?').count(), params.len(), "placeholders of {frag}");
        Ok(run_sql(&self.store, &frag, params))
    }

    fn ids(&self, src: &str) -> Vec<String> {
        let e = parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
        self.run(&e).unwrap_or_else(|e| panic!("{src}: {e}"))
    }
}

fn run_sql(store: &Store, frag: &str, mut params: Vec<SqlValue>) -> Vec<String> {
    let sql = format!("SELECT i.id FROM issues i WHERE 1=1 AND ({frag}) ORDER BY i.priority, i.id LIMIT ?");
    params.push(SqlValue::Integer(1000));
    let conn = store.connection();
    let mut stmt = conn.prepare(&sql).unwrap_or_else(|e| panic!("{e}: {sql}"));
    let mut ids: Vec<String> = stmt
        .query_map(params_from_iter(params), |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap_or_else(|e| panic!("{e}: {sql}"));
    ids.sort();
    ids
}

// ---- parsing ----------------------------------------------------------------

#[test]
fn precedence_not_and_or() {
    let e = parse("title = x OR notes = y AND NOT type = z").unwrap();
    assert_eq!(
        e,
        Expr::Or(vec![
            title("x"),
            Expr::And(vec![cmp(Field::Notes, Op::Eq, Some("y")), not(cmp(Field::Type, Op::Eq, Some("z")))]),
        ])
    );
    // Chains flatten; parenthesized groups stay nodes of their own.
    assert_eq!(
        parse("title = a AND title = b AND title = c").unwrap(),
        Expr::And(vec![title("a"), title("b"), title("c")])
    );
    assert_eq!(
        parse("(title = a AND title = b) AND title = c").unwrap(),
        Expr::And(vec![Expr::And(vec![title("a"), title("b")]), title("c")])
    );
    assert_eq!(parse("((title = a))").unwrap(), title("a"));
    assert_eq!(parse("NOT NOT title = a").unwrap(), not(not(title("a"))));
}

#[test]
fn quoting_keywords_and_none() {
    assert_eq!(
        parse(r#"title = 'it\'s' AND notes = "say \"hi\" \\ x""#).unwrap(),
        Expr::And(vec![title("it's"), cmp(Field::Notes, Op::Eq, Some(r#"say "hi" \ x"#))])
    );
    assert_eq!(parse(r#"title = "it's""#).unwrap(), title("it's"));
    assert_eq!(parse("title=x").unwrap(), title("x"));
    assert_eq!(
        parse("TITLE = x and not Notes = y Or type = z").unwrap().to_string(),
        r#"title = "x" AND NOT notes = "y" OR type = "z""#
    );
    // A keyword in value position is a value.
    assert_eq!(parse("title = AND AND title = or").unwrap(), Expr::And(vec![title("AND"), title("or")]));
    assert_eq!(parse("assignee = none").unwrap(), cmp(Field::Assignee, Op::Eq, None));
    assert_eq!(parse("assignee != NONE").unwrap(), cmp(Field::Assignee, Op::Ne, None));
    assert_eq!(parse("assignee = 'none'").unwrap(), cmp(Field::Assignee, Op::Eq, Some("none")));
    assert_eq!(parse("label = none").unwrap(), cmp(Field::Label, Op::Eq, None));
    // Comparisons keep their value's column.
    let Expr::Cmp(c) = parse("  title  =  'x'").unwrap() else { panic!() };
    assert_eq!(c.column, 13);
}

#[test]
fn values_are_normalized() {
    assert_eq!(parse("status = done").unwrap(), cmp(Field::Status, Op::Eq, Some("closed")));
    assert_eq!(parse("status = In-Progress").unwrap(), cmp(Field::Status, Op::Eq, Some("in_progress")));
    assert_eq!(parse("priority <= P1").unwrap(), cmp(Field::Priority, Op::Le, Some("1")));
    assert_eq!(parse("pinned = yes").unwrap(), cmp(Field::Pinned, Op::Eq, Some("true")));
    assert_eq!(parse("ephemeral = 0").unwrap(), cmp(Field::Ephemeral, Op::Eq, Some("false")));
    assert_eq!(parse("type = BUG").unwrap(), cmp(Field::Type, Op::Eq, Some("bug")));
    assert_eq!(parse("created > 7d").unwrap(), cmp(Field::Created, Op::Gt, Some("7d")));
    assert_eq!(parse("due = 2026-01-15").unwrap(), cmp(Field::Due, Op::Eq, Some("2026-01-15")));
}

#[test]
fn display_is_canonical_with_minimal_parentheses() {
    let shown = |src: &str| {
        let e = parse(src).unwrap();
        let text = e.to_string();
        assert_eq!(parse(&text).unwrap(), e, "{src} -> {text}");
        assert_eq!(e.nesting(), parse(&text).unwrap().nesting());
        text
    };
    assert_eq!(shown("status = open AND priority <= 1"), r#"status = "open" AND priority <= "1""#);
    assert_eq!(
        shown("NOT (title = x OR notes = y) AND type = z"),
        r#"NOT (title = "x" OR notes = "y") AND type = "z""#
    );
    assert_eq!(shown("(title = x AND notes = y)"), r#"title = "x" AND notes = "y""#);
    assert_eq!(shown("(title = x AND notes = y) AND type = z"), r#"(title = "x" AND notes = "y") AND type = "z""#);
    assert_eq!(shown("(title = x OR notes = y) OR type = z"), r#"(title = "x" OR notes = "y") OR type = "z""#);
    assert_eq!(shown("title = x OR (notes = y AND type = z)"), r#"title = "x" OR notes = "y" AND type = "z""#);
    assert_eq!(shown("(title = x OR notes = y) AND type = z"), r#"(title = "x" OR notes = "y") AND type = "z""#);
    assert_eq!(shown("NOT (title = x)"), r#"NOT title = "x""#);
    assert_eq!(shown("NOT (NOT (title = x AND notes = y))"), r#"NOT NOT (title = "x" AND notes = "y")"#);
    assert_eq!(shown(r#"title = 'a"b\\c' AND assignee = none"#), r#"title = "a\"b\\c" AND assignee = none"#);
    assert_eq!(parse("NOT (title = x OR notes = y)").unwrap().nesting(), 2);
    assert_eq!(parse("NOT NOT NOT title = x").unwrap().nesting(), 3);
    assert_eq!(parse("(((title = x AND notes = y)))").unwrap().nesting(), 0);
}

#[test]
fn serializes_as_a_json_tree() {
    let e = parse("status = open AND NOT (assignee = none OR priority < 2)").unwrap();
    assert_eq!(
        serde_json::to_value(&e).unwrap(),
        serde_json::json!({"and": [
            {"field": "status", "op": "=", "value": "open"},
            {"not": {"or": [
                {"field": "assignee", "op": "=", "value": null},
                {"field": "priority", "op": "<", "value": "2"},
            ]}},
        ]})
    );
}

#[test]
fn errors_name_their_column() {
    let cases: &[(&str, usize, &str)] = &[
        ("", 1, "empty query"),
        ("   ", 1, "empty query"),
        ("foo = x", 1, "unknown field \"foo\" (fields: status, priority"),
        ("title = x AND bogus = y", 15, "unknown field"),
        ("title", 6, "expected an operator"),
        ("title x", 7, "expected an operator"),
        ("title =", 8, "expected a value after title ="),
        ("title = )", 9, "expected a value"),
        ("title = (", 9, "expected a value"),
        ("(title = x", 11, "missing ')' for the '(' at column 1"),
        ("(title = x notes = y)", 12, "expected AND, OR or ')'"),
        ("title = x)", 10, "unmatched ')'"),
        ("title = x notes = y", 11, "expected AND, OR or the end"),
        ("title = x AND", 14, "expected a comparison"),
        ("AND title = x", 1, "expected a comparison"),
        ("= x", 1, "expected a field, NOT or '('"),
        ("'title' = x", 1, "expected a field"),
        ("title = 'abc", 9, "unterminated string"),
        ("title = \"a\\nb\"", 11, "invalid escape"),
        ("title ! x", 7, "'!' must be followed by '='"),
        ("priority ~ 1", 10, "priority takes =, !=, <, <=, > or >=, not ~"),
        ("status < open", 8, "status takes = or !=, not <"),
        ("title > x", 7, "title takes =, != or ~, not >"),
        ("parent ~ t-1", 8, "parent takes = or !="),
        ("status = nope", 10, "unknown status \"nope\""),
        ("priority = 9", 12, "invalid priority \"9\""),
        ("priority = P5", 12, "invalid priority"),
        ("pinned = maybe", 10, "pinned takes true or false"),
        ("created = 7d", 11, "takes a date (YYYY-MM-DD"),
        ("created < 7x", 11, "invalid time \"7x\""),
        ("due = 2026-02-30", 7, "takes a date"),
        ("title = none", 9, "title is never none"),
        ("due < none", 7, "none takes = or !="),
        ("label ~ none", 9, "none takes = or !="),
    ];
    for &(src, column, message) in cases {
        let e = err(src);
        assert_eq!(e.column, column, "{src}: {e}");
        assert!(e.message.contains(message), "{src}: {e}");
    }
}

#[test]
fn query_errors_draw_a_caret() {
    let e = parse_query("title = x AND\tbogus = y").unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert_eq!(
        e.to_string(),
        "query: column 15: unknown field \"bogus\" (fields: status, priority, type, assignee, label, title, description, notes, id, parent, created, updated, closed, due, defer, pinned, ephemeral)\n  title = x AND bogus = y\n                ^"
    );
}

// ---- limits -----------------------------------------------------------------

#[test]
fn nesting_counts_every_not_and_parenthesis() {
    let s = seeded();
    let deepest = format!("{}status = open", "NOT ".repeat(32));
    let e = parse(&deepest).unwrap();
    assert_eq!(e.nesting(), MAX_DEPTH);
    assert_eq!(s.run(&e).unwrap(), s.ids("status = open"));

    let e = err(&format!("{}status = open", "NOT ".repeat(33)));
    assert_eq!((e.column, e.message.as_str()), (129, "nesting deeper than 32 (each NOT and each parenthesis counts)"));
    let long = format!("{}status = open", "NOT ".repeat(1000));
    assert!(long.len() <= MAX_BYTES);
    assert_eq!(err(&long).column, 129);

    let parens = |n: usize| format!("{}status = open{}", "(".repeat(n), ")".repeat(n));
    assert_eq!(s.run(&parse(&parens(32)).unwrap()).unwrap(), s.ids("status = open"));
    let e = err(&parens(33));
    assert_eq!(e.column, 33);
    assert!(e.message.starts_with("nesting deeper than 32"));

    let mixed = format!("{}NOT status = open{}", "NOT (".repeat(16), ")".repeat(16));
    assert_eq!(err(&mixed).column, 81);
    // Parentheses around a single NOT add no node: the canonical text drops them.
    let fits = format!("{}NOT status = open{}", "NOT (".repeat(15), ")".repeat(15));
    let e = parse(&fits).unwrap();
    assert_eq!((e.nesting(), e.to_string()), (16, format!("{}status = \"open\"", "NOT ".repeat(16))));
}

#[test]
fn comparisons_and_length_are_bounded() {
    let chain = |n: usize| vec!["title = x"; n].join(" AND ");
    assert_eq!(parse(&chain(128)).unwrap().comparisons(), 128);
    let e = err(&chain(129));
    assert_eq!((e.column, e.message.as_str()), (128 * "title = x AND ".len() + 1, "more than 128 comparisons"));

    let exact = format!("title = {}", "x".repeat(MAX_BYTES - 8));
    assert_eq!(exact.len(), MAX_BYTES);
    assert!(parse(&exact).is_ok());
    let e = err(&format!("{exact}x"));
    assert_eq!((e.column, e.message.as_str()), (4097, "query longer than 4096 bytes"));
    // A character that straddles the limit is the one reported.
    let wide = format!("title = {}", "é".repeat(2045));
    assert_eq!(wide.len(), 4098);
    assert_eq!(err(&wide).column, 8 + 2045);
}

#[test]
fn canonical_text_longer_than_the_limit_round_trips() {
    let s = seeded();
    // Accepted queries whose canonical text outgrows MAX_BYTES: escapes
    // doubling a value, normalized values, tight keywords gaining spaces.
    let backslashes = format!("title={}", "\\".repeat(MAX_BYTES - 6));
    let chain = |term: &str, sep: &str| {
        let mut src = String::new();
        for n in 0..MAX_COMPARISONS {
            let next = if n == 0 { term.to_string() } else { format!("{sep}{term}") };
            if src.len() + next.len() > MAX_BYTES {
                break;
            }
            src.push_str(&next);
        }
        src
    };
    let wip = chain("status=wip", " OR ");
    let mixed = chain(&format!("title='{}'", "\"".repeat(25)), "AND NOT ");
    let pinned = chain("NOT(pinned=0)", "OR ");
    for src in [backslashes, wip, mixed, pinned] {
        assert!(src.len() <= MAX_BYTES, "{}", src.len());
        let e = parse(&src).unwrap_or_else(|err| panic!("{src}: {err}"));
        let text = e.to_string();
        assert!(text.len() <= 2 * src.len() + 14 * e.comparisons(), "{} from {}", text.len(), src.len());
        assert!(text.len() <= MAX_CANONICAL_BYTES);
        check_valid(&s, &e);
    }
    // Over MAX_BYTES, only the canonical text itself: not the same query respaced.
    let e = parse(&format!("title={}", "\\".repeat(MAX_BYTES - 6))).unwrap();
    let text = e.to_string();
    assert!(text.len() > MAX_BYTES);
    let e = err(&format!(" {text}"));
    assert_eq!(e.message, "query longer than 4096 bytes");
    assert!(err(&"x".repeat(MAX_CANONICAL_BYTES + 1)).message.starts_with("query longer"));
}

// ---- compile and semantics --------------------------------------------------

const ALL: [&str; 5] = ["t-1", "t-10", "t-11", "t-2", "t-3"];

fn ids(xs: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = xs.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

#[test]
fn values_match_only_literally() {
    let s = seeded();
    let cases: &[(&str, &[&str])] = &[
        (r#"title = "x' OR 1=1 --""#, &["t-2"]),
        (r#"title ~ "' OR 1=1""#, &["t-2"]),
        (r#"title = "' OR 1=1 --""#, &[]),
        (r#"title ~ "OR 1=1 --' OR '1'='1""#, &[]),
        ("title ~ '%'", &["t-3"]),
        ("title ~ '_'", &["t-3"]),
        ("title ~ '%_'", &[]),
        ("title ~ DONE", &["t-3"]),
        (r#"description ~ "\\""#, &["t-3"]),
        (r#"description ~ '"hi";'"#, &["t-3"]),
        ("description ~ ';--'", &[]),
        ("notes ~ '[brackets]'", &["t-3"]),
        ("notes ~ '?'", &["t-3"]),
        ("id = '*'", &ALL),
        ("id = 't-1*'", &["t-1", "t-10", "t-11"]),
        ("id = 't-?'", &[]),
        ("id = 't-[1]'", &[]),
        ("id = 't-1'", &["t-1"]),
        ("id = 't-'", &[]),
        ("id ~ '-1'", &["t-1", "t-10", "t-11"]),
        ("label = 'a%b'", &["t-2"]),
        ("label = 'a_b'", &[]),
        ("label ~ '%'", &["t-2"]),
        ("label ~ URG", &["t-1"]),
        ("assignee ~ '%'", &[]),
    ];
    for &(src, want) in cases {
        assert_eq!(s.ids(src), ids(want), "{src}");
    }
    for value in ["x' OR 1=1 --", "a%b", ";--", "\"hi\"", "t-1*"] {
        let e = parse(&format!("title = '{}' OR label ~ '{0}' OR id = '{0}'", value.replace('\'', "\\'"))).unwrap();
        let (sql, params) = compile(s.store.connection(), &e, s.now).unwrap();
        assert!(!sql.contains(value), "{value} in {sql}");
        assert_eq!(params.len(), 3);
    }
}

#[test]
fn absent_fields_compare_false_and_ne_is_not_eq() {
    let s = seeded();
    let cases: &[(&str, &[&str])] = &[
        ("assignee = bob", &["t-2"]),
        ("assignee != bob", &["t-1", "t-10", "t-11", "t-3"]),
        ("NOT assignee = bob", &["t-1", "t-10", "t-11", "t-3"]),
        ("assignee = none", &["t-1", "t-10", "t-11"]),
        ("assignee != none", &["t-2", "t-3"]),
        ("due < now", &["t-2"]),
        ("NOT due < now", &["t-1", "t-10", "t-11", "t-3"]),
        ("due > now", &["t-10"]),
        ("due < +2d", &["t-10", "t-2"]),
        ("due = none", &["t-1", "t-11", "t-3"]),
        ("label = none", &["t-10", "t-11", "t-3"]),
        ("label != none", &["t-1", "t-2"]),
        ("label != urgent", &["t-10", "t-11", "t-2", "t-3"]),
        ("created = 2026-01-15", &["t-1", "t-2", "t-3"]),
        ("created = 2026-01-16", &["t-10", "t-11"]),
        ("created != 2026-01-15", &["t-10", "t-11"]),
        ("created > 7d", &ALL),
        ("created < 1d", &["t-1", "t-2", "t-3"]),
        ("updated >= 2026-01-16", &["t-10", "t-11"]),
        ("closed = 2026-01-15", &["t-3"]),
        ("closed != 2026-01-15", &["t-1", "t-10", "t-11", "t-2"]),
        ("closed = none", &["t-1", "t-10", "t-11", "t-2"]),
        ("defer = none", &ALL),
        ("defer > 1d", &[]),
        ("NOT defer > 1d", &ALL),
        ("status = closed", &["t-3"]),
        ("status = pinned", &["t-11"]),
        ("pinned = true", &["t-11"]),
        ("pinned = no", &["t-1", "t-10", "t-2", "t-3"]),
        ("ephemeral = yes", &["t-10"]),
        ("priority <= 0", &["t-3"]),
        ("priority > 0 AND priority != 2", &[]),
        ("type = EPIC", &["t-1"]),
        ("type ~ PIC OR status = closed", &["t-1", "t-3"]),
    ];
    for &(src, want) in cases {
        assert_eq!(s.ids(src), ids(want), "{src}");
    }
}

#[test]
fn parent_resolves_like_the_parent_flag() {
    let s = seeded();
    // An exact id wins over the t-10/t-11 prefix matches; a bare number
    // takes the prefix.
    assert_eq!(s.ids("parent = t-1"), ids(&["t-2"]));
    assert_eq!(s.ids("parent = 1"), ids(&["t-2"]));
    assert_eq!(s.ids("parent = t-99"), ids(&[]));
    assert_eq!(s.ids("NOT parent = t-99"), ids(&ALL));
    assert_eq!(s.ids("parent != t-99"), ids(&ALL));
    assert_eq!(s.ids("parent = none"), ids(&["t-1", "t-10", "t-11", "t-3"]));
    assert_eq!(s.ids("parent != none"), ids(&["t-2"]));
    assert_eq!(s.ids("parent = t-2"), ids(&[]));

    let (_dir, store, clock) = store_with(&["t-10", "t-11"]);
    let src = "title = x OR parent = t-1";
    let e = parse(src).unwrap();
    match compile(store.connection(), &e, clock.now()) {
        Err(CompileError::Query(q)) => {
            assert_eq!(q.column, col(src, "t-1"));
            assert!(q.message.contains("ambiguous id \"t-1\""), "{}", q.message);
        }
        other => panic!("{other:?}"),
    }
}

// ---- fuzz and property tests ------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

const SOUP: &[&str] = &[
    "NOT",
    "not",
    "AND",
    "and",
    "OR",
    "Or",
    "(",
    ")",
    "=",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "~",
    "!",
    "status",
    "priority",
    "type",
    "assignee",
    "label",
    "title",
    "description",
    "notes",
    "id",
    "parent",
    "created",
    "updated",
    "closed",
    "due",
    "defer",
    "pinned",
    "ephemeral",
    "Status",
    "foo",
    "none",
    "open",
    "done",
    "P1",
    "1",
    "9",
    "true",
    "maybe",
    "7d",
    "+3d",
    "2026-01-15",
    "t-1",
    "t-*",
    "t",
    "*",
    "'",
    "\"",
    "\\",
    "'x'",
    "\"y\"",
    "'it\\'s'",
    "\"a\\qb\"",
    "%_",
    "x' OR 1=1 --",
    ";--",
    "é",
    "日本",
    "\t",
    "\u{202e}",
];

const TRICKY: &[&str] = &[
    "'",
    "\"",
    ";--",
    "%_\\*",
    "x' OR 1=1 --",
    "none",
    "NONE",
    "AND",
    "(",
    "\\",
    "é ü",
    "a b",
    "",
    "50%",
    "bob",
    "urgent",
];

/// Values `parent` resolves without ambiguity in the seeded store: none,
/// existing ids, a prefix-less id, an unknown id, and strings that
/// prefix-match no id.
const PARENT_VALUES: &[Option<&str>] = &[
    None,
    Some("t-1"),
    Some("t-2"),
    Some("1"),
    Some("t-99"),
    Some("'"),
    Some(";--"),
    Some("%_\\*"),
    Some("x' OR 1=1 --"),
];

fn soup(rng: &mut Rng) -> String {
    match rng.below(20) {
        0 => {
            let bytes: Vec<u8> = (0..rng.below(40)).map(|_| rng.next() as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        1 => (0..rng.below(20)).filter_map(|_| char::from_u32(rng.next() as u32 % 0x11_0000)).collect(),
        2 => format!("{}{}", rng.pick(&["NOT ", "(", "NOT (", "NOT("]).repeat(rng.below(40)), random_comparisons(rng)),
        3..=9 => random_comparisons(rng),
        _ => {
            let n = rng.below(25);
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(rng.pick(SOUP));
                s.push_str(rng.pick(&[" ", " ", " ", ""]));
            }
            s
        }
    }
}

/// Comparisons joined by AND/OR with random NOTs and parentheses, then
/// mutated a little: mostly valid, sometimes not.
fn random_comparisons(rng: &mut Rng) -> String {
    let mut words: Vec<String> = Vec::new();
    for n in 0..1 + rng.below(6) {
        if n > 0 {
            words.push(rng.pick(&["AND", "OR", "and", "or"]).to_string());
        }
        if rng.below(4) == 0 {
            words.push("NOT".into());
        }
        let open = rng.below(5) == 0;
        if open {
            words.push("(".into());
        }
        words.push(gen_cmp(rng).to_string());
        if open {
            words.push(")".into());
        }
    }
    match rng.below(6) {
        0 if !words.is_empty() => {
            let at = rng.below(words.len());
            words.remove(at);
        }
        1 => {
            let at = rng.below(words.len() + 1);
            words.insert(at, rng.pick(SOUP).to_string());
        }
        _ => {}
    }
    words.join(" ")
}

fn gen_cmp(rng: &mut Rng) -> Expr {
    let field = *rng.pick(&Field::ALL);
    let op = *rng.pick(field.ops());
    let eq = matches!(op, Op::Eq | Op::Ne);
    let text = |v: &str| Some(v.to_string());
    let value: Option<String> = match field {
        Field::Status => text(rng.pick(&Status::ALL).as_str()),
        Field::Priority => text(rng.pick(&["0", "1", "2", "3", "4"])),
        Field::Type => text(&rng.pick(&[TRICKY, &["task", "bug", "epic"]].concat()).to_ascii_lowercase()),
        Field::Assignee | Field::Label if eq && rng.below(4) == 0 => None,
        Field::Id => text(rng.pick(&[TRICKY, &["t-*", "t-1", "*", "t-[1]*", "?*", "t-1?"]].concat())),
        Field::Parent => rng.pick(PARENT_VALUES).map(str::to_string),
        f if f.is_time() && eq => {
            if f.takes_none() && rng.below(3) == 0 {
                None
            } else {
                text(rng.pick(&["2026-01-15", "2025-12-31", " 2026-01-16 "]))
            }
        }
        f if f.is_time() => {
            text(rng.pick(&["7d", "+3d", "-1h", "now", "2026-01-15", "2026-01-15T09:00:00Z", "tomorrow", "1w"]))
        }
        Field::Pinned | Field::Ephemeral => text(rng.pick(&["true", "false"])),
        _ => text(rng.pick(TRICKY)),
    };
    let value = value.map_or(Value::None, Value::Text);
    Expr::Cmp(Comparison { field, op, value, column: 0 })
}

/// A random expression with `leaves` comparisons whose nesting is at most
/// `depth`, of the shapes the parser produces (AND/OR of two or more).
fn gen_tree(rng: &mut Rng, leaves: usize, depth: usize) -> Expr {
    if leaves == 1 {
        if depth >= 1 && rng.below(4) == 0 {
            return not(gen_tree(rng, 1, depth - 1));
        }
        return gen_cmp(rng);
    }
    let chain = |terms: Vec<Expr>, rng: &mut Rng| if rng.below(2) == 0 { Expr::And(terms) } else { Expr::Or(terms) };
    if depth == 0 {
        let terms = (0..leaves).map(|_| gen_cmp(rng)).collect();
        return chain(terms, rng);
    }
    if depth >= 2 && rng.below(6) == 0 {
        return not(gen_tree(rng, leaves, depth - 2));
    }
    let k = 2 + rng.below(leaves.min(5) - 1);
    let mut parts = vec![1; k];
    for _ in 0..leaves - k {
        let at = rng.below(k);
        parts[at] += 1;
    }
    let terms = parts.into_iter().map(|n| gen_tree(rng, n, depth - 1)).collect();
    chain(terms, rng)
}

/// Wrap a comparison on a deepest path in NOT: the nesting grows by one.
fn deepen(e: &mut Expr) {
    fn walk(e: &mut Expr, want: usize) {
        // A childless stand-in for `e`, to ask `wrapped` while a child is borrowed.
        let parent = match e {
            Expr::Cmp(_) => {
                let leaf = std::mem::replace(e, Expr::And(vec![]));
                *e = not(leaf);
                return;
            }
            Expr::Not(_) => not(Expr::And(vec![])),
            Expr::And(_) => Expr::And(vec![]),
            Expr::Or(_) => Expr::Or(vec![]),
        };
        let wrap = |x: &Expr| usize::from(wrapped(&parent, x));
        match e {
            Expr::Not(x) => {
                let inner = want - 1 - wrap(x);
                walk(x, inner)
            }
            Expr::And(xs) | Expr::Or(xs) => {
                let x = xs.iter_mut().find(|x| wrap(x) + x.nesting() == want).expect("a child on the deepest path");
                let inner = want - wrap(x);
                walk(x, inner)
            }
            Expr::Cmp(_) => unreachable!(),
        }
    }
    let target = e.nesting();
    walk(e, target);
}

/// A random expression with exactly `MAX_COMPARISONS` comparisons and
/// nesting exactly `MAX_DEPTH`.
fn gen_at_limit(rng: &mut Rng) -> Expr {
    let depth = rng.below(MAX_DEPTH);
    let mut e = gen_tree(rng, MAX_COMPARISONS, depth);
    while e.nesting() < MAX_DEPTH {
        let need = MAX_DEPTH - e.nesting();
        let cost = if matches!(e, Expr::And(_) | Expr::Or(_)) { 2 } else { 1 };
        if cost <= need && rng.below(2) == 0 {
            e = not(e);
        } else {
            deepen(&mut e);
        }
    }
    e
}

/// Round-trip `e` through its text, compile it (it must compile) and run it.
fn check_valid(s: &Seeded, e: &Expr) {
    let text = e.to_string();
    let back = parse(&text).unwrap_or_else(|err| panic!("{text}: {err}"));
    assert_eq!(&back, e, "{text}");
    s.run(e).unwrap_or_else(|err| panic!("{text}: {err}"));
}

#[test]
fn fuzzed_input_never_panics_and_every_parse_compiles_and_runs() {
    let s = seeded();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut parsed = 0;
    for _ in 0..10_000 {
        let src = soup(&mut rng);
        match parse(&src) {
            Err(e) => assert!(e.column >= 1 && e.column <= src.chars().count() + 1, "{src:?}: {e}"),
            Ok(e) => {
                parsed += 1;
                assert!(e.nesting() <= MAX_DEPTH, "{src:?}");
                assert!(e.comparisons() <= MAX_COMPARISONS, "{src:?}");
                let text = e.to_string();
                assert_eq!(parse(&text).unwrap_or_else(|err| panic!("{src:?} -> {text}: {err}")), e, "{src:?}");
                match s.run(&e) {
                    Ok(_) => {}
                    Err(CompileError::Query(q)) => {
                        assert!(q.message.contains("ambiguous id"), "{src:?}: {q}");
                        assert!(q.column >= 1 && q.column <= src.chars().count(), "{src:?}: {q}");
                    }
                    Err(CompileError::Db(err)) => panic!("{src:?}: {err}"),
                }
            }
        }
    }
    assert!(parsed > 1_000, "the fuzzer should reach the compiler often: {parsed}");
}

#[test]
fn random_expressions_round_trip_compile_and_run() {
    let s = seeded();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..2_000 {
        let leaves = 1 + rng.below(8);
        let depth = rng.below(5);
        let e = gen_tree(&mut rng, leaves, depth);
        assert!(e.nesting() <= depth);
        check_valid(&s, &e);
        let (sql, params) = compile(s.store.connection(), &e, s.now).unwrap();
        let count: i64 = s
            .store
            .connection()
            .query_row(&format!("SELECT COUNT(*) FROM issues i WHERE 1=1 AND ({sql})"), params_from_iter(params), |r| {
                r.get(0)
            })
            .unwrap();
        assert!((0..=5).contains(&count));
    }
}

#[test]
fn not_is_the_exact_complement() {
    let s = seeded();
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..300 {
        let leaves = 1 + rng.below(4);
        let e = gen_tree(&mut rng, leaves, 3);
        let yes = s.run(&e).unwrap();
        let no = s.run(&not(e.clone())).unwrap();
        let mut both: Vec<String> = yes.iter().chain(no.iter()).cloned().collect();
        both.sort();
        assert_eq!(both, ids(&ALL), "{e}");
    }
}

#[test]
fn the_worst_cases_at_the_limits_compile_and_run() {
    let s = seeded();
    let heavy = [
        r#"label ~ "%_""#,
        "parent != none",
        "created = 2026-01-15",
        "assignee != bob",
        "description ~ x",
        "closed != 2026-01-15",
        "parent != t-1",
    ];
    let terms: Vec<&str> = (0..MAX_COMPARISONS).map(|n| heavy[n % heavy.len()]).collect();
    // 15 levels of `NOT (term AND ...)`, then NOT NOT on each remaining
    // term of one AND chain: 32 levels, every one a node of the AST.
    let outer: String = terms[..15].iter().map(|t| format!("NOT ({t} AND ")).collect();
    let inner: Vec<String> = terms[15..].iter().map(|t| format!("NOT NOT {t}")).collect();
    let nested = format!("{outer}{}{}", inner.join(" AND "), ")".repeat(15));
    // 32 NOTs on the deepest term of the left-deep chain.
    let left = format!("{}{}", "NOT ".repeat(32), terms.join(" AND "));
    for src in [nested, left] {
        assert!(src.len() <= MAX_BYTES, "{}", src.len());
        let e = parse(&src).unwrap();
        assert_eq!((e.nesting(), e.comparisons()), (MAX_DEPTH, MAX_COMPARISONS));
        check_valid(&s, &e);
    }

    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..300 {
        let e = gen_at_limit(&mut rng);
        assert_eq!((e.nesting(), e.comparisons()), (MAX_DEPTH, MAX_COMPARISONS), "{e}");
        check_valid(&s, &e);
    }
}
