//! `{{var}}` templates and compile-time step conditions.
//!
//! Templates replace `{{ name }}` with a variable's value; `\{{` is a literal
//! `{{`. Referencing an undeclared variable is an error, never an empty string.
//!
//! Conditions decide, when a run starts, whether a step exists:
//!
//! ```text
//! cond    := or
//! or      := and ("||" and)*
//! and     := unary ("&&" unary)*
//! unary   := "!" unary | "(" or ")" | compare
//! compare := value (("==" | "!=") value)?
//! value   := {{var}} | 'text' | "text" | bare-word
//! ```
//!
//! A lone value is tested for truthiness: empty, `false`, `0`, `no` and `off`
//! (any case) are false. This is a superset of beads' step conditions
//! (`{{var}}`, `!{{var}}`, `{{var}} == value`, `{{var}} != value`).

use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, PartialEq, Eq)]
enum Seg {
    Lit(String),
    Var(String),
}

fn segments(text: &str) -> Result<Vec<Seg>, String> {
    let mut segs = Vec::new();
    let mut lit = String::new();
    let mut rest = text;
    while let Some(pos) = rest.find("{{") {
        if pos > 0 && rest.as_bytes()[pos - 1] == b'\\' {
            lit.push_str(&rest[..pos - 1]);
            lit.push_str("{{");
            rest = &rest[pos + 2..];
            continue;
        }
        lit.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let end = after.find("}}").ok_or_else(|| format!("unclosed `{{{{` in {text:?}"))?;
        let name = after[..end].trim();
        if !is_ident(name) {
            return Err(format!("invalid variable reference `{{{{{}}}}}` in {text:?}", &after[..end]));
        }
        if !lit.is_empty() {
            segs.push(Seg::Lit(std::mem::take(&mut lit)));
        }
        segs.push(Seg::Var(name.to_string()));
        rest = &after[end + 2..];
    }
    lit.push_str(rest);
    if !lit.is_empty() {
        segs.push(Seg::Lit(lit));
    }
    Ok(segs)
}

/// Variable names referenced by a template (syntax errors included).
pub(crate) fn refs(text: &str) -> Result<BTreeSet<String>, String> {
    Ok(segments(text)?
        .into_iter()
        .filter_map(|s| match s {
            Seg::Var(v) => Some(v),
            Seg::Lit(_) => None,
        })
        .collect())
}

/// Substitute every `{{var}}`; unknown variables are errors.
pub(crate) fn render(text: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    if !text.contains("{{") {
        return Ok(text.to_string());
    }
    let mut out = String::with_capacity(text.len());
    for seg in segments(text)? {
        match seg {
            Seg::Lit(l) => out.push_str(&l),
            Seg::Var(v) => match vars.get(&v) {
                Some(value) => out.push_str(value),
                None => return Err(format!("unknown variable `{v}` in {text:?}")),
            },
        }
    }
    Ok(out)
}

pub(crate) fn truthy(v: &str) -> bool {
    let t = v.trim();
    !(t.is_empty() || ["false", "0", "no", "off"].iter().any(|f| t.eq_ignore_ascii_case(f)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    Not,
    And,
    Or,
    Eq,
    Ne,
    Var(String),
    Text(String),
}

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '&' if next == Some('&') => {
                toks.push(Tok::And);
                i += 2;
            }
            '|' if next == Some('|') => {
                toks.push(Tok::Or);
                i += 2;
            }
            '=' if next == Some('=') => {
                toks.push(Tok::Eq);
                i += 2;
            }
            '!' if next == Some('=') => {
                toks.push(Tok::Ne);
                i += 2;
            }
            '!' => {
                toks.push(Tok::Not);
                i += 1;
            }
            '{' if next == Some('{') => {
                let mut j = i + 2;
                let mut name = String::new();
                while j + 1 < chars.len() && !(chars[j] == '}' && chars[j + 1] == '}') {
                    name.push(chars[j]);
                    j += 1;
                }
                if j + 1 >= chars.len() {
                    return Err(format!("unclosed `{{{{` in condition {src:?}"));
                }
                let name = name.trim().to_string();
                if !is_ident(&name) {
                    return Err(format!("invalid variable `{name}` in condition {src:?}"));
                }
                toks.push(Tok::Var(name));
                i = j + 2;
            }
            '\'' | '"' => {
                let mut j = i + 1;
                let mut s = String::new();
                while j < chars.len() && chars[j] != c {
                    s.push(chars[j]);
                    j += 1;
                }
                if j >= chars.len() {
                    return Err(format!("unterminated string in condition {src:?}"));
                }
                toks.push(Tok::Text(s));
                i = j + 1;
            }
            _ => {
                let mut s = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || "()!=&|'\"".contains(c) {
                        break;
                    }
                    s.push(c);
                    i += 1;
                }
                if s.is_empty() {
                    return Err(format!("unexpected `{c}` in condition {src:?}"));
                }
                toks.push(Tok::Text(s));
            }
        }
    }
    Ok(toks)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Val {
    Var(String),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Truthy(Val),
    Cmp(Val, bool, Val),
}

/// A parsed step condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Condition {
    expr: Expr,
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    src: &'a str,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn err(&self, what: &str) -> String {
        format!("{what} in condition {:?}", self.src)
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            left = Expr::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            left = Expr::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::Not) => {
                self.pos += 1;
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err(self.err("missing `)`"));
                }
                self.pos += 1;
                Ok(e)
            }
            _ => self.compare(),
        }
    }

    fn value(&mut self) -> Result<Val, String> {
        let v = match self.peek() {
            Some(Tok::Var(v)) => Val::Var(v.clone()),
            Some(Tok::Text(t)) => Val::Text(t.clone()),
            Some(other) => return Err(self.err(&format!("unexpected {other:?}"))),
            None => return Err(self.err("unexpected end")),
        };
        self.pos += 1;
        Ok(v)
    }

    fn compare(&mut self) -> Result<Expr, String> {
        let left = self.value()?;
        match self.peek() {
            Some(Tok::Eq) | Some(Tok::Ne) => {
                let eq = self.peek() == Some(&Tok::Eq);
                self.pos += 1;
                let right = self.value()?;
                Ok(Expr::Cmp(left, eq, right))
            }
            _ => Ok(Expr::Truthy(left)),
        }
    }
}

impl Condition {
    pub(crate) fn parse(src: &str) -> Result<Condition, String> {
        let toks = tokenize(src)?;
        if toks.is_empty() {
            return Err("empty condition".into());
        }
        let mut p = Parser { toks: &toks, pos: 0, src };
        let expr = p.or()?;
        if p.pos != toks.len() {
            return Err(p.err("trailing input"));
        }
        Ok(Condition { expr })
    }

    /// Variables the condition reads.
    pub(crate) fn vars(&self) -> BTreeSet<String> {
        fn val(v: &Val, out: &mut BTreeSet<String>) {
            if let Val::Var(name) = v {
                out.insert(name.clone());
            }
        }
        fn walk(e: &Expr, out: &mut BTreeSet<String>) {
            match e {
                Expr::Or(a, b) | Expr::And(a, b) => {
                    walk(a, out);
                    walk(b, out);
                }
                Expr::Not(a) => walk(a, out),
                Expr::Truthy(v) => val(v, out),
                Expr::Cmp(a, _, b) => {
                    val(a, out);
                    val(b, out);
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&self.expr, &mut out);
        out
    }

    pub(crate) fn eval(&self, vars: &BTreeMap<String, String>) -> Result<bool, String> {
        fn val<'a>(v: &'a Val, vars: &'a BTreeMap<String, String>) -> Result<&'a str, String> {
            match v {
                Val::Text(t) => Ok(t),
                Val::Var(name) => {
                    vars.get(name).map(String::as_str).ok_or_else(|| format!("unknown variable `{name}`"))
                }
            }
        }
        fn eval(e: &Expr, vars: &BTreeMap<String, String>) -> Result<bool, String> {
            Ok(match e {
                Expr::Or(a, b) => eval(a, vars)? || eval(b, vars)?,
                Expr::And(a, b) => eval(a, vars)? && eval(b, vars)?,
                Expr::Not(a) => !eval(a, vars)?,
                Expr::Truthy(v) => truthy(val(v, vars)?),
                Expr::Cmp(a, eq, b) => (val(a, vars)? == val(b, vars)?) == *eq,
            })
        }
        eval(&self.expr, vars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn rendering() {
        let v = vars(&[("version", "1.2.0"), ("env", "prod")]);
        assert_eq!(render("Release {{version}} to {{ env }}", &v).unwrap(), "Release 1.2.0 to prod");
        assert_eq!(render(r"literal \{{version}}", &v).unwrap(), "literal {{version}}");
        assert!(render("{{nope}}", &v).unwrap_err().contains("unknown variable `nope`"));
        assert!(render("{{version", &v).is_err());
        assert!(render("{{bad name}}", &v).is_err());
        assert_eq!(refs("{{a}}-{{b}}-{{a}}").unwrap().into_iter().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn beads_condition_forms() {
        let v = vars(&[("env", "production"), ("dry", "false"), ("name", "")]);
        let check = |src: &str| Condition::parse(src).unwrap().eval(&v).unwrap();
        assert!(check("{{env}}"));
        assert!(!check("{{dry}}"));
        assert!(check("!{{dry}}"));
        assert!(!check("{{name}}"));
        assert!(check("{{env}} == production"));
        assert!(check("{{env}} == 'production'"));
        assert!(check("{{env}} != staging"));
    }

    #[test]
    fn boolean_conditions() {
        let v = vars(&[("env", "production"), ("canary", "yes"), ("region", "eu")]);
        let check = |src: &str| Condition::parse(src).unwrap().eval(&v).unwrap();
        assert!(check("{{env}} == production && {{canary}}"));
        assert!(!check("{{env}} == staging || !{{canary}}"));
        assert!(check("({{region}} == us || {{region}} == eu) && !({{env}} == staging)"));
        let c = Condition::parse("{{env}} == x || {{other}}").unwrap();
        assert_eq!(c.vars().into_iter().collect::<Vec<_>>(), vec!["env", "other"]);
        assert!(c.eval(&v).unwrap_err().contains("other"));
        for bad in ["", "{{env}} ==", "({{env}}", "{{env}} == a b", "'open"] {
            assert!(Condition::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }
}
