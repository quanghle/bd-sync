//! An [`Expr`] as one parameterized SQL condition over issues aliased `i`.

use std::fmt;

use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;

use super::parse::day;
use super::{Comparison, Expr, Field, Op, ParseError, Value};
use crate::error::Error;
use crate::filter::like_escape;
use crate::issues::lookup_id;
use crate::time::{Timestamp, local_day, parse_filter_time};

/// Why an [`Expr`] did not compile.
#[derive(Debug)]
pub enum CompileError {
    /// A value the store decides on: an ambiguous `parent` id, at the
    /// comparison's value column (or a value no parser would let through).
    Query(ParseError),
    /// The database failed while resolving a value.
    Db(Error),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::Query(e) => write!(f, "{e}"),
            CompileError::Db(e) => write!(f, "{e}"),
        }
    }
}

/// Compile `e` into a condition over issues aliased `i` and its parameters,
/// in order. Every value is bound, never written into the SQL; every
/// comparison yields 0 or 1, so `NOT` is an exact complement. `now` anchors
/// relative times (`created > 7d`: within the last 7 days).
pub fn compile(conn: &Connection, e: &Expr, now: Timestamp) -> Result<(String, Vec<SqlValue>), CompileError> {
    let mut c = Compiler { conn, now, sql: String::new(), params: Vec::new() };
    c.expr(e)?;
    Ok((c.sql, c.params))
}

struct Compiler<'a> {
    conn: &'a Connection,
    now: Timestamp,
    sql: String,
    params: Vec<SqlValue>,
}

fn invalid(c: &Comparison, msg: impl Into<String>) -> CompileError {
    CompileError::Query(ParseError::new(c.column, msg))
}

fn contains_pattern(v: &str) -> SqlValue {
    SqlValue::Text(format!("%{}%", like_escape(v)))
}

/// `pattern` with `*` kept as GLOB's wildcard and every other GLOB
/// metacharacter (`?`, `[`, `]`) matched literally.
fn glob_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 4);
    for c in pattern.chars() {
        match c {
            '?' => out.push_str("[?]"),
            '[' => out.push_str("[[]"),
            ']' => out.push_str("[]]"),
            c => out.push(c),
        }
    }
    out
}

/// `COALESCE((sql),0)`: a comparison on a column that may be NULL yields 0
/// for an absent value instead of NULL.
fn maybe_null(sql: String, nullable: bool) -> String {
    if nullable { format!("COALESCE(({sql}),0)") } else { sql }
}

impl Compiler<'_> {
    fn expr(&mut self, e: &Expr) -> Result<(), CompileError> {
        match e {
            Expr::And(xs) | Expr::Or(xs) => {
                let sep = if matches!(e, Expr::And(_)) { " AND " } else { " OR " };
                self.sql.push('(');
                for (n, x) in xs.iter().enumerate() {
                    if n > 0 {
                        self.sql.push_str(sep);
                    }
                    self.expr(x)?;
                }
                self.sql.push(')');
            }
            Expr::Not(x) => {
                self.sql.push_str("NOT (");
                self.expr(x)?;
                self.sql.push(')');
            }
            Expr::Cmp(c) if c.op == Op::Ne => {
                self.sql.push_str("NOT (");
                self.comparison(c, Op::Eq)?;
                self.sql.push(')');
            }
            Expr::Cmp(c) => self.comparison(c, c.op)?,
        }
        Ok(())
    }

    /// `c` compared by `op` (never `Ne`: that is `NOT` of `Eq`).
    fn comparison(&mut self, c: &Comparison, op: Op) -> Result<(), CompileError> {
        let bad = || invalid(c, format!("{} does not take {} {}", c.field, op, value_text(&c.value)));
        if !c.field.ops().contains(&c.op) {
            return Err(bad());
        }
        let (sql, params): (String, Vec<SqlValue>) = match (c.field, &c.value) {
            (Field::Status, Value::Text(v)) => ("i.status = ?".into(), vec![SqlValue::Text(v.clone())]),
            (Field::Priority, Value::Text(v)) => {
                let p: i64 = v.trim().parse().map_err(|_| bad())?;
                (format!("i.priority {} ?", op.symbol()), vec![SqlValue::Integer(p)])
            }
            (Field::Type, Value::Text(v)) => text_column("i.issue_type", false, op, v),
            (Field::Title, Value::Text(v)) => text_column("i.title", false, op, v),
            (Field::Description, Value::Text(v)) => text_column("i.description", false, op, v),
            (Field::Notes, Value::Text(v)) => text_column("i.notes", false, op, v),
            (Field::Assignee, Value::Text(v)) => text_column("i.assignee", true, op, v),
            (Field::Assignee, Value::None) => ("i.assignee IS NULL".into(), vec![]),
            (Field::Label, Value::None) => {
                ("NOT EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id)".into(), vec![])
            }
            (Field::Label, Value::Text(v)) if op == Op::Contains => (
                "EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id AND l.label LIKE ? ESCAPE '\\')".into(),
                vec![contains_pattern(v)],
            ),
            (Field::Label, Value::Text(v)) => (
                "EXISTS (SELECT 1 FROM labels l WHERE l.issue_id = i.id AND l.label = ?)".into(),
                vec![SqlValue::Text(v.clone())],
            ),
            (Field::Id, Value::Text(v)) if op == Op::Eq && v.contains('*') => {
                ("i.id GLOB ?".into(), vec![SqlValue::Text(glob_pattern(v))])
            }
            (Field::Id, Value::Text(v)) => text_column("i.id", false, op, v),
            (Field::Parent, Value::None) => (
                "NOT EXISTS (SELECT 1 FROM dependencies d WHERE d.issue_id = i.id AND d.dep_type = 'parent-child')"
                    .into(),
                vec![],
            ),
            (Field::Parent, Value::Text(v)) => {
                // An id that resolves to nothing stays as written: no parent
                // id equals it, so the comparison matches no issue.
                let parent = match lookup_id(self.conn, v) {
                    Ok(found) => found.unwrap_or_else(|| v.clone()),
                    Err(Error::Invalid(msg)) => return Err(invalid(c, msg)),
                    Err(e) => return Err(CompileError::Db(e)),
                };
                (
                    "EXISTS (SELECT 1 FROM dependencies d WHERE d.issue_id = i.id AND d.dep_type = 'parent-child' \
                     AND d.depends_on_id = ?)"
                        .into(),
                    vec![SqlValue::Text(parent)],
                )
            }
            (f, value) if f.is_time() => {
                let (col, nullable) = match f {
                    Field::Created => ("i.created_at", false),
                    Field::Updated => ("i.updated_at", false),
                    Field::Closed => ("i.closed_at", true),
                    Field::Due => ("i.due_at", true),
                    _ => ("i.defer_until", true),
                };
                match (value, op) {
                    (Value::None, Op::Eq) => (format!("{col} IS NULL"), vec![]),
                    (Value::None, _) => return Err(bad()),
                    (Value::Text(v), Op::Eq) => {
                        let date = day(v).ok_or_else(bad)?;
                        let (start, end) = local_day(date, v).map_err(|e| invalid(c, e.to_string()))?;
                        (
                            maybe_null(format!("{col} >= ? AND {col} < ?"), nullable),
                            vec![SqlValue::Integer(start.millis()), SqlValue::Integer(end.millis())],
                        )
                    }
                    (Value::Text(v), _) => {
                        let t = parse_filter_time(v, self.now).map_err(|e| invalid(c, e.to_string()))?;
                        (maybe_null(format!("{col} {} ?", op.symbol()), nullable), vec![SqlValue::Integer(t.millis())])
                    }
                }
            }
            (Field::Pinned, Value::Text(v)) => {
                let sql = match v.as_str() {
                    "true" => "i.status = 'pinned'",
                    "false" => "i.status <> 'pinned'",
                    _ => return Err(bad()),
                };
                (sql.into(), vec![])
            }
            (Field::Ephemeral, Value::Text(v)) => {
                let sql = match v.as_str() {
                    "true" => "i.ephemeral = 1",
                    "false" => "i.ephemeral = 0",
                    _ => return Err(bad()),
                };
                (sql.into(), vec![])
            }
            _ => return Err(bad()),
        };
        self.sql.push_str(&sql);
        self.params.extend(params);
        Ok(())
    }
}

fn value_text(v: &Value) -> String {
    match v {
        Value::None => "none".into(),
        Value::Text(t) => format!("{t:?}"),
    }
}

/// `=` (exact) or `~` (ASCII case-insensitive substring) on a text column.
fn text_column(col: &str, nullable: bool, op: Op, v: &str) -> (String, Vec<SqlValue>) {
    if op == Op::Contains {
        (maybe_null(format!("{col} LIKE ? ESCAPE '\\'"), nullable), vec![contains_pattern(v)])
    } else {
        (maybe_null(format!("{col} = ?"), nullable), vec![SqlValue::Text(v.to_string())])
    }
}
