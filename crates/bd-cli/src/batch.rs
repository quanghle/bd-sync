//! `bd batch`: many write operations in one transaction.
//!
//! Each non-empty line is a bd subcommand with the same flags as on the
//! command line (`create "Title" -p 1 --dep $1`). `$N` expands to the primary
//! id produced by operation N (1-based, counting operations, not lines);
//! `$$` is a literal `$`. Lines starting with `#` are comments. Any failure
//! rolls back every operation.

use std::cell::Cell;
use std::io::Read;

use bd_core::{Error, Result, WriteCtx};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::commands::*;

#[derive(Parser, Debug)]
#[command(name = "batch", no_binary_name = true, disable_help_flag = true, disable_version_flag = true)]
struct Line {
    #[command(subcommand)]
    op: Op,
}

#[derive(Subcommand, Debug)]
enum Op {
    Create(CreateArgs),
    Update(UpdateArgs),
    Close(CloseArgs),
    Reopen(ReopenArgs),
    Defer(DeferArgs),
    Undefer(IdArg),
    Delete(DeleteArgs),
    #[command(subcommand)]
    Dep(DepCommand),
    #[command(subcommand)]
    Label(LabelCommand),
    #[command(subcommand)]
    Comment(CommentCommand),
    Claim(ClaimArgs),
    #[command(alias = "unclaim")]
    Release(ReleaseArgs),
    #[command(alias = "hb")]
    Heartbeat(HeartbeatArgs),
    Remember(MemoryAddArgs),
    Forget(KeyArg),
    #[command(subcommand)]
    Config(ConfigCommand),
}

fn run(tx: &mut WriteCtx<'_>, op: &Op) -> Result<Out> {
    match op {
        Op::Create(a) => exec_create(tx, a),
        Op::Update(a) => exec_update(tx, a),
        Op::Close(a) => exec_close(tx, a),
        Op::Reopen(a) => exec_reopen(tx, a),
        Op::Defer(a) => exec_defer(tx, a),
        Op::Undefer(a) => exec_undefer(tx, a),
        Op::Delete(a) => exec_delete(tx, a),
        Op::Dep(c) => exec_dep(tx, c),
        Op::Label(c) => exec_label(tx, c),
        Op::Comment(CommentCommand::Add(a)) => exec_comment_add(tx, a),
        Op::Comment(CommentCommand::List(_)) => Err(Error::invalid("`comment list` is read-only")),
        Op::Claim(a) => exec_claim(tx, a),
        Op::Release(a) => exec_release(tx, a),
        Op::Heartbeat(a) => exec_heartbeat(tx, a),
        Op::Remember(a) => exec_remember(tx, a),
        Op::Forget(a) => exec_forget(tx, a),
        Op::Config(c) => exec_config(tx, c),
    }
}

/// Expand `$N` back-references and `$$` escapes in one token.
fn substitute(token: &str, produced: &[Option<String>]) -> Result<String> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'$') {
            chars.next();
            out.push('$');
            continue;
        }
        let mut digits = String::new();
        while let Some(d) = chars.peek().filter(|d| d.is_ascii_digit()) {
            digits.push(*d);
            chars.next();
        }
        if digits.is_empty() {
            out.push('$');
            continue;
        }
        let n: usize = digits.parse().map_err(|_| Error::invalid(format!("bad reference ${digits}")))?;
        match produced.get(n.wrapping_sub(1)) {
            Some(Some(id)) => out.push_str(id),
            Some(None) => return Err(Error::invalid(format!("${n}: operation {n} produced no id"))),
            None => return Err(Error::invalid(format!("${n}: no earlier operation {n}"))),
        }
    }
    Ok(out)
}

pub fn cmd_batch(app: &mut App, a: &BatchArgs) -> Result<()> {
    let input = match &a.file {
        Some(f) => std::fs::read_to_string(f).map_err(|e| Error::invalid(format!("{}: {e}", f.display())))?,
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        }
    };
    let mut ops: Vec<(usize, Vec<String>)> = Vec::new();
    for (n, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = shlex::split(line).ok_or_else(|| Error::invalid(format!("line {}: unbalanced quotes", n + 1)))?;
        ops.push((n + 1, tokens));
    }
    if ops.is_empty() {
        return Err(Error::invalid("batch is empty"));
    }
    let dry = a.dry_run;
    let failed_at = Cell::new(0usize);
    let result = app.write("batch", |tx| {
        let mut produced: Vec<Option<String>> = Vec::with_capacity(ops.len());
        let mut results: Vec<Value> = Vec::with_capacity(ops.len());
        let mut text = Vec::new();
        for (i, (lineno, tokens)) in ops.iter().enumerate() {
            failed_at.set(*lineno);
            let tokens = tokens.iter().map(|t| substitute(t, &produced)).collect::<Result<Vec<_>>>()?;
            let parsed = Line::try_parse_from(&tokens).map_err(|e| {
                let msg = e.to_string();
                Error::invalid(format!(
                    "line {lineno}: {}",
                    msg.lines().next().unwrap_or("parse error").trim_start_matches("error: ")
                ))
            })?;
            let out = run(tx, &parsed.op)?;
            produced.push(out.ids.first().cloned());
            text.extend(out.text.iter().map(|l| format!("[{}] {l}", i + 1)));
            results
                .push(json!({ "op": i + 1, "line": lineno, "command": tokens[0], "ids": out.ids, "result": out.json }));
        }
        if dry {
            tx.set_rollback_only();
        }
        Ok((results, text))
    });
    let (results, text) = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bd batch: line {} failed; rolled back all {} operation(s)", failed_at.get(), ops.len());
            return Err(e);
        }
    };
    let ids: Vec<String> = results
        .iter()
        .filter_map(|r| r["ids"].as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).map(String::from))
        .collect();
    let summary = if dry {
        format!("Dry run: {} operation(s) succeeded and were rolled back", results.len())
    } else {
        format!("✓ Committed {} operation(s) in one transaction", results.len())
    };
    let out = Out::new(json!({ "committed": !dry, "operations": results })).lines(text).line(summary);
    app.print(Out { ids, ..out });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution() {
        let produced = vec![Some("t-1".to_string()), None];
        assert_eq!(substitute("$1", &produced).unwrap(), "t-1");
        assert_eq!(substitute("blocks:$1", &produced).unwrap(), "blocks:t-1");
        assert_eq!(substitute("costs $$5", &produced).unwrap(), "costs $5");
        assert_eq!(substitute("a$b", &produced).unwrap(), "a$b");
        assert!(substitute("$2", &produced).is_err());
        assert!(substitute("$3", &produced).is_err());
    }
}
