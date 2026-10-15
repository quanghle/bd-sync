//! Recursive descent over the tokens, with the limits checked at the token
//! that crosses them, and each comparison checked against its field.

use chrono::NaiveDate;

use super::lex::{Tok, Token, lex};
use super::{Comparison, Expr, Field, MAX_BYTES, MAX_COMPARISONS, MAX_DEPTH, Op, ParseError, Value};
use crate::model::Status;
use crate::time::{Timestamp, local_day, parse_filter_time};

/// Parse a query. Errors carry the 1-based character column of the token at
/// fault (one past the end when more was expected).
pub fn parse(src: &str) -> Result<Expr, ParseError> {
    if src.len() > MAX_BYTES {
        // The first character that does not fit in MAX_BYTES.
        let mut column = 1;
        for (n, (at, c)) in src.char_indices().enumerate() {
            if at + c.len_utf8() > MAX_BYTES {
                column = n + 1;
                break;
            }
        }
        return Err(ParseError::new(column, format!("query longer than {MAX_BYTES} bytes")));
    }
    let toks = lex(src)?;
    let end = src.chars().count() + 1;
    if toks.is_empty() {
        return Err(ParseError::new(1, "empty query"));
    }
    let mut p = Parser { toks, pos: 0, depth: 0, comparisons: 0, end };
    let e = p.or()?;
    match p.toks.get(p.pos) {
        None => Ok(e),
        Some(Token { tok: Tok::RParen, col }) => Err(ParseError::new(*col, "unmatched ')'")),
        Some(t) => Err(ParseError::new(t.col, format!("expected AND, OR or the end, found {}", describe(&t.tok)))),
    }
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
    depth: usize,
    comparisons: usize,
    /// The column one past the last character.
    end: usize,
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::LParen => "'('".into(),
        Tok::RParen => "')'".into(),
        Tok::Op(op) => format!("'{op}'"),
        Tok::Word(w) => format!("{w:?}"),
        Tok::Quoted(q) => format!("the string {q:?}"),
    }
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn at_keyword(&self, kw: &str) -> Option<usize> {
        match self.peek() {
            Some(Token { tok: Tok::Word(w), col }) if w.eq_ignore_ascii_case(kw) => Some(*col),
            _ => None,
        }
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut terms = vec![self.and()?];
        while self.at_keyword("OR").is_some() {
            self.pos += 1;
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 { terms.remove(0) } else { Expr::Or(terms) })
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut terms = vec![self.unary()?];
        while self.at_keyword("AND").is_some() {
            self.pos += 1;
            terms.push(self.unary()?);
        }
        Ok(if terms.len() == 1 { terms.remove(0) } else { Expr::And(terms) })
    }

    /// One more level of nesting, opened by the token at `col`.
    fn enter(&mut self, col: usize) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError::new(
                col,
                format!("nesting deeper than {MAX_DEPTH} (each NOT and each parenthesis counts)"),
            ));
        }
        self.pos += 1;
        Ok(())
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if let Some(col) = self.at_keyword("NOT") {
            self.enter(col)?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        if let Some(Token { tok: Tok::LParen, col }) = self.peek() {
            let open = *col;
            self.enter(open)?;
            let inner = self.or()?;
            match self.peek() {
                Some(Token { tok: Tok::RParen, .. }) => self.pos += 1,
                Some(t) => {
                    return Err(ParseError::new(
                        t.col,
                        format!("expected AND, OR or ')' (for the '(' at column {open}), found {}", describe(&t.tok)),
                    ));
                }
                None => return Err(ParseError::new(self.end, format!("missing ')' for the '(' at column {open}"))),
            }
            self.depth -= 1;
            return Ok(inner);
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Expr, ParseError> {
        let Some(t) = self.peek().cloned() else {
            return Err(ParseError::new(self.end, "expected a comparison such as status = open"));
        };
        let Tok::Word(name) = &t.tok else {
            return Err(ParseError::new(t.col, format!("expected a field, NOT or '(', found {}", describe(&t.tok))));
        };
        if name.eq_ignore_ascii_case("AND") || name.eq_ignore_ascii_case("OR") {
            return Err(ParseError::new(t.col, format!("expected a comparison such as status = open, found {name}")));
        }
        self.comparisons += 1;
        if self.comparisons > MAX_COMPARISONS {
            return Err(ParseError::new(t.col, format!("more than {MAX_COMPARISONS} comparisons")));
        }
        let field = Field::parse(name)
            .ok_or_else(|| ParseError::new(t.col, format!("unknown field {name:?} (fields: {})", Field::names())))?;
        self.pos += 1;

        let op = match self.peek() {
            Some(Token { tok: Tok::Op(op), col }) => {
                if !field.ops().contains(op) {
                    return Err(ParseError::new(*col, format!("{field} takes {}, not {op}", op_list(field.ops()))));
                }
                *op
            }
            other => {
                let col = other.map_or(self.end, |t| t.col);
                return Err(ParseError::new(
                    col,
                    format!("expected an operator (=, !=, <, <=, >, >=, ~) after {field}"),
                ));
            }
        };
        self.pos += 1;

        let (raw, col) = match self.peek() {
            Some(Token { tok: Tok::Word(w), col }) if w.eq_ignore_ascii_case("none") => (None, *col),
            Some(Token { tok: Tok::Word(w) | Tok::Quoted(w), col }) => (Some(w.clone()), *col),
            other => {
                let col = other.map_or(self.end, |t| t.col);
                return Err(ParseError::new(col, format!("expected a value after {field} {op}")));
            }
        };
        self.pos += 1;
        let value = check_value(field, op, raw).map_err(|m| ParseError::new(col, m))?;
        Ok(Expr::Cmp(Comparison { field, op, value, column: col }))
    }
}

fn op_list(ops: &[Op]) -> String {
    let names: Vec<&str> = ops.iter().map(|o| o.symbol()).collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => names.join(""),
    }
}

/// A `YYYY-MM-DD` date that has a local midnight, for `=`/`!=` on a time.
pub(super) fn day(v: &str) -> Option<NaiveDate> {
    let date = NaiveDate::parse_from_str(v.trim(), "%Y-%m-%d").ok()?;
    local_day(date, v).ok().map(|_| date)
}

/// The value of a comparison of `field` by `op`, normalized (`raw` is
/// `None` for the bare word `none`), or why it does not fit.
fn check_value(field: Field, op: Op, raw: Option<String>) -> Result<Value, String> {
    let Some(v) = raw else {
        if !field.takes_none() {
            return Err(format!(
                "{field} is never none (none is for assignee, label, parent, closed, due and defer; quote it to mean the word)"
            ));
        }
        if !matches!(op, Op::Eq | Op::Ne) {
            return Err(format!("none takes = or !=, not {op}"));
        }
        return Ok(Value::None);
    };
    let text = match field {
        Field::Status => Status::parse(&v)
            .map_err(|_| format!("unknown status {v:?} (valid: open, in_progress, blocked, deferred, closed, pinned)"))?
            .as_str()
            .to_string(),
        Field::Priority => {
            let t = v.trim();
            let digits = t.strip_prefix(['p', 'P']).unwrap_or(t);
            match digits {
                "0" | "1" | "2" | "3" | "4" => digits.to_string(),
                _ => return Err(format!("invalid priority {v:?} (0-4 or P0-P4)")),
            }
        }
        Field::Type => v.to_ascii_lowercase(),
        Field::Pinned | Field::Ephemeral => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => "true".to_string(),
            "false" | "no" | "0" => "false".to_string(),
            _ => return Err(format!("{field} takes true or false (or yes/no, 1/0), not {v:?}")),
        },
        f if f.is_time() => {
            if matches!(op, Op::Eq | Op::Ne) {
                if day(&v).is_none() {
                    return Err(format!(
                        "{field} {op} takes a date (YYYY-MM-DD, that local day){}; use <, <=, > or >= for times",
                        if field.takes_none() { " or none" } else { "" }
                    ));
                }
            } else {
                parse_filter_time(&v, Timestamp(0)).map_err(|e| e.to_string())?;
            }
            v
        }
        _ => v,
    };
    Ok(Value::Text(text))
}
