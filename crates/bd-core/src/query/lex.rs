//! Tokens of a query, each with its 1-based character column.

use super::{Op, ParseError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Tok {
    LParen,
    RParen,
    Op(Op),
    /// A run of characters other than whitespace and `()=!<>~"'`: a field,
    /// a keyword or a value, as its position decides.
    Word(String),
    /// A quoted string, escapes resolved: always a value.
    Quoted(String),
}

#[derive(Clone, Debug)]
pub(super) struct Token {
    pub tok: Tok,
    pub col: usize,
}

fn special(c: char) -> bool {
    c.is_whitespace() || matches!(c, '(' | ')' | '=' | '!' | '<' | '>' | '~' | '"' | '\'')
}

pub(super) fn lex(src: &str) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<char> = src.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let col = i + 1;
        let next = chars.get(i + 1).copied();
        let (tok, len) = match c {
            c if c.is_whitespace() => {
                i += 1;
                continue;
            }
            '(' => (Tok::LParen, 1),
            ')' => (Tok::RParen, 1),
            '=' => (Tok::Op(Op::Eq), 1),
            '~' => (Tok::Op(Op::Contains), 1),
            '!' if next == Some('=') => (Tok::Op(Op::Ne), 2),
            '!' => return Err(ParseError::new(col, "'!' must be followed by '=' (!=)")),
            '<' if next == Some('=') => (Tok::Op(Op::Le), 2),
            '<' => (Tok::Op(Op::Lt), 1),
            '>' if next == Some('=') => (Tok::Op(Op::Ge), 2),
            '>' => (Tok::Op(Op::Gt), 1),
            '"' | '\'' => {
                let mut text = String::new();
                let mut j = i + 1;
                loop {
                    match chars.get(j) {
                        None => return Err(ParseError::new(col, format!("unterminated string (missing closing {c})"))),
                        Some(&q) if q == c => break,
                        Some('\\') => match chars.get(j + 1) {
                            Some(&e @ ('\\' | '\'' | '"')) => {
                                text.push(e);
                                j += 2;
                            }
                            _ => {
                                return Err(ParseError::new(
                                    j + 1,
                                    "invalid escape (only \\\\, \\' and \\\" are escapes)",
                                ));
                            }
                        },
                        Some(&other) => {
                            text.push(other);
                            j += 1;
                        }
                    }
                }
                (Tok::Quoted(text), j + 1 - i)
            }
            _ => {
                let len = chars[i..].iter().position(|&c| special(c)).unwrap_or(chars.len() - i);
                (Tok::Word(chars[i..i + len].iter().collect()), len)
            }
        };
        toks.push(Token { tok, col });
        i += len;
    }
    Ok(toks)
}
