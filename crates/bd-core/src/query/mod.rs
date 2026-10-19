//! `bd query`: a small expression language over issues.
//!
//! ```text
//! expr  := and { OR and }
//! and   := unary { AND unary }
//! unary := NOT unary | '(' expr ')' | FIELD OP VALUE
//! ```
//!
//! [`parse`] turns the text into a typed [`Expr`] whose comparisons keep the
//! column of their value; every comparison is checked against its field
//! (operators, value forms, `none`) while parsing, so errors point at the
//! token. [`compile`] turns an [`Expr`] into one SQL condition over issues
//! aliased `i`: every value is a bound parameter, never part of the SQL text,
//! and every comparison yields 0 or 1 (an absent field compares false, except
//! with `= none`), so `!=` and `NOT` are exact complements.
//!
//! The limits ([`MAX_BYTES`], [`MAX_DEPTH`], [`MAX_COMPARISONS`]) bound the
//! parser's recursion and the size and height of the compiled SQL; canonical
//! text, which can be longer than the query it came from, is accepted up to
//! [`MAX_CANONICAL_BYTES`].

mod compile;
mod lex;
mod parse;
#[cfg(test)]
mod tests;

use std::fmt;

use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Serialize, Serializer};

use crate::error::Error;
use crate::error::Result;

pub use compile::{CompileError, compile};
pub use parse::parse;

/// The longest query accepted, in bytes. With [`MAX_COMPARISONS`] it bounds
/// the work of lexing and parsing, and the SQL text compiled from it.
pub const MAX_BYTES: usize = 4096;

/// The longest canonical text ([`Expr`]'s `Display`) accepted: a query
/// longer than [`MAX_BYTES`] parses only if it is exactly the canonical text
/// of what it parses to, so `parse(&e.to_string()) == e` holds for every
/// accepted `e` (the round trip `bd query --parse-only` promises).
///
/// The canonical text of an accepted query is at most 2 × [`MAX_BYTES`] +
/// 14 × [`MAX_COMPARISONS`] bytes, below this: each byte of the source
/// becomes at most two (a value's `"` and `\` are escaped, a tight `AND`,
/// `OR` or `NOT` gains spaces; parentheses are only ever dropped), and each
/// comparison gains at most 14 more (spaces around its operator, the quotes,
/// and a normalized value longer than the one written: `wip` is
/// `"in_progress"`, `0` is `"false"`). Nesting and comparisons are those of
/// the source, so the SQL bounds of [`MAX_DEPTH`] hold unchanged.
pub const MAX_CANONICAL_BYTES: usize = 2 * MAX_BYTES + 16 * MAX_COMPARISONS;

/// The deepest nesting accepted: every `NOT` and every `(` adds one level
/// for what it encloses (`NOT (a)` is 2, `NOT NOT NOT a` is 3). The parser
/// checks it at the token that crosses it, which bounds its own recursion
/// (and so its stack) and the NOT nodes on any path of the compiled SQL.
///
/// Height of the compiled SQL: SQLite parses a k-term `AND`/`OR` chain as a
/// left-deep tree of height k-1, and there are at most 127 binary AND/OR
/// nodes in all ([`MAX_COMPARISONS`] - 1). A path also crosses at most 32
/// `NOT` nodes, one more for a `!=`, and about 8 inside the heaviest
/// comparison: `spec`/`area`'s `IN (WITH RECURSIVE ...)` subquery (the `IN`,
/// its compound `UNION` selects, and a recursive join's `ON ... AND ...`),
/// ahead of the others (COALESCE, EXISTS, the subquery's AND, LIKE/ESCAPE, a
/// date range); the statement's `WHERE 1=1 AND (...)` adds about 3. That is
/// about 170 at most, against SQLITE_MAX_EXPR_DEPTH = 1000 in the bundled
/// SQLite (whose parser stack grows on demand). Parameters number at most 2
/// per comparison (256; `spec` and `area` bind 1), far below
/// SQLITE_MAX_VARIABLE_NUMBER. The at-limit tests compile and run the worst
/// cases.
pub const MAX_DEPTH: usize = 32;

/// The most comparisons in one query. It bounds the AND/OR chains (loops in
/// the parser, flat chains in the SQL) and the parameters bound.
pub const MAX_COMPARISONS: usize = 128;

/// A field a comparison reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
    Status,
    Priority,
    Type,
    Assignee,
    Label,
    Title,
    Description,
    Notes,
    Id,
    Parent,
    ExternalRef,
    Created,
    Updated,
    Closed,
    Due,
    Defer,
    Pinned,
    Ephemeral,
    /// The feature spec whose links cover the issue (experimental specs).
    Spec,
    /// The area of a feature spec whose links cover the issue.
    Area,
}

impl Field {
    pub const ALL: [Field; 20] = [
        Field::Status,
        Field::Priority,
        Field::Type,
        Field::Assignee,
        Field::Label,
        Field::Title,
        Field::Description,
        Field::Notes,
        Field::Id,
        Field::Parent,
        Field::ExternalRef,
        Field::Created,
        Field::Updated,
        Field::Closed,
        Field::Due,
        Field::Defer,
        Field::Pinned,
        Field::Ephemeral,
        Field::Spec,
        Field::Area,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Field::Status => "status",
            Field::Priority => "priority",
            Field::Type => "type",
            Field::Assignee => "assignee",
            Field::Label => "label",
            Field::Title => "title",
            Field::Description => "description",
            Field::Notes => "notes",
            Field::Id => "id",
            Field::Parent => "parent",
            Field::ExternalRef => "external_ref",
            Field::Created => "created",
            Field::Updated => "updated",
            Field::Closed => "closed",
            Field::Due => "due",
            Field::Defer => "defer",
            Field::Pinned => "pinned",
            Field::Ephemeral => "ephemeral",
            Field::Spec => "spec",
            Field::Area => "area",
        }
    }

    /// The field named `s`, ignoring ASCII case.
    pub fn parse(s: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name().eq_ignore_ascii_case(s))
    }

    /// Every field name, for error messages.
    pub fn names() -> String {
        Field::ALL.map(Field::name).join(", ")
    }

    /// The operators this field takes.
    pub fn ops(self) -> &'static [Op] {
        use Op::*;
        match self {
            Field::Status | Field::Parent | Field::Pinned | Field::Ephemeral | Field::Spec | Field::Area => &[Eq, Ne],
            Field::Priority => &[Eq, Ne, Lt, Le, Gt, Ge],
            Field::Created | Field::Updated | Field::Closed | Field::Due | Field::Defer => &[Eq, Ne, Lt, Le, Gt, Ge],
            Field::Type
            | Field::Assignee
            | Field::Label
            | Field::Title
            | Field::Description
            | Field::Notes
            | Field::Id
            | Field::ExternalRef => &[Eq, Ne, Contains],
        }
    }

    /// Whether `= none` / `!= none` apply (the field can be absent).
    pub fn takes_none(self) -> bool {
        matches!(
            self,
            Field::Assignee
                | Field::Label
                | Field::Parent
                | Field::Spec
                | Field::ExternalRef
                | Field::Closed
                | Field::Due
                | Field::Defer
        )
    }

    pub fn is_time(self) -> bool {
        matches!(self, Field::Created | Field::Updated | Field::Closed | Field::Due | Field::Defer)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// `~`: ASCII case-insensitive substring.
    Contains,
}

impl Op {
    pub const ALL: [Op; 7] = [Op::Eq, Op::Ne, Op::Lt, Op::Le, Op::Gt, Op::Ge, Op::Contains];

    pub fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Contains => "~",
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

/// A comparison's value: the bare word `none` (absent), or text, normalized
/// for its field (a canonical status, a priority digit, `true`/`false`, a
/// lowercase type; anything else as written).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    None,
    Text(String),
}

/// `field op value`. `column` is the 1-based character column of the value
/// in the source; equality ignores it.
#[derive(Clone, Debug)]
pub struct Comparison {
    pub field: Field,
    pub op: Op,
    pub value: Value,
    pub column: usize,
}

impl PartialEq for Comparison {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.op == other.op && self.value == other.value
    }
}

impl Eq for Comparison {}

impl Serialize for Comparison {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Comparison", 3)?;
        st.serialize_field("field", self.field.name())?;
        st.serialize_field("op", self.op.symbol())?;
        match &self.value {
            Value::None => st.serialize_field("value", &None::<String>)?,
            Value::Text(v) => st.serialize_field("value", v)?,
        }
        st.end()
    }
}

/// A parsed query. `And`/`Or` hold two or more terms: a chain at one level
/// is one node, and a parenthesized group stays a node of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Cmp(Comparison),
}

impl Serialize for Expr {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Expr::And(xs) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("and", xs)?;
                m.end()
            }
            Expr::Or(xs) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("or", xs)?;
                m.end()
            }
            Expr::Not(x) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("not", x)?;
                m.end()
            }
            Expr::Cmp(c) => c.serialize(s),
        }
    }
}

/// Whether the canonical text wraps `child` in parentheses under `parent`:
/// only where the grouping needs them, so each one matches a parenthesis the
/// parser required in the source.
fn wrapped(parent: &Expr, child: &Expr) -> bool {
    matches!(
        (parent, child),
        (Expr::Not(_), Expr::And(_) | Expr::Or(_))
            | (Expr::And(_), Expr::And(_) | Expr::Or(_))
            | (Expr::Or(_), Expr::Or(_))
    )
}

impl Expr {
    /// The nesting depth of the canonical text ([`fmt::Display`]), counted as
    /// the parser counts it: one per `NOT` and one per parenthesis.
    pub fn nesting(&self) -> usize {
        let child = |x: &Expr| usize::from(wrapped(self, x)) + x.nesting();
        match self {
            Expr::Cmp(_) => 0,
            Expr::Not(x) => 1 + child(x),
            Expr::And(xs) | Expr::Or(xs) => xs.iter().map(child).max().unwrap_or(0),
        }
    }

    /// How many comparisons the expression holds.
    pub fn comparisons(&self) -> usize {
        match self {
            Expr::Cmp(_) => 1,
            Expr::Not(x) => x.comparisons(),
            Expr::And(xs) | Expr::Or(xs) => xs.iter().map(Expr::comparisons).sum(),
        }
    }

    fn fmt_child(&self, child: &Expr, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if wrapped(self, child) { write!(f, "({child})") } else { write!(f, "{child}") }
    }
}

/// Canonical text: keywords upper case, values quoted (`none` bare), and
/// parentheses only where the grouping needs them, so it never nests deeper
/// than the source it was parsed from, and parses back to the same `Expr`.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Cmp(c) => write!(f, "{c}"),
            Expr::Not(x) => {
                f.write_str("NOT ")?;
                self.fmt_child(x, f)
            }
            Expr::And(xs) | Expr::Or(xs) => {
                let sep = if matches!(self, Expr::And(_)) { " AND " } else { " OR " };
                for (n, x) in xs.iter().enumerate() {
                    if n > 0 {
                        f.write_str(sep)?;
                    }
                    self.fmt_child(x, f)?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.field, self.op)?;
        match &self.value {
            Value::None => f.write_str("none"),
            Value::Text(v) => {
                f.write_str("\"")?;
                for c in v.chars() {
                    if matches!(c, '"' | '\\') {
                        f.write_str("\\")?;
                    }
                    write!(f, "{c}")?;
                }
                f.write_str("\"")
            }
        }
    }
}

/// A query error at a 1-based character column of the source (one past the
/// end for "expected more").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub column: usize,
    pub message: String,
}

impl ParseError {
    pub(crate) fn new(column: usize, message: impl Into<String>) -> Self {
        ParseError { column, message: message.into() }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "column {}: {}", self.column, self.message)
    }
}

/// The error for `msg` at `column` of `src` (exit code 2): the message, then
/// the query and a caret under the column.
pub fn query_error(src: &str, column: usize, msg: &str) -> Error {
    // Whitespace shown as spaces keeps the caret under its column.
    let shown: String = src.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).collect();
    let caret = format!("{}^", " ".repeat(column.saturating_sub(1)));
    Error::invalid(format!("query: column {column}: {msg}\n  {shown}\n  {caret}"))
}

/// [`parse`], with its error as [`query_error`].
pub fn parse_query(src: &str) -> Result<Expr> {
    parse(src).map_err(|e| query_error(src, e.column, &e.message))
}
