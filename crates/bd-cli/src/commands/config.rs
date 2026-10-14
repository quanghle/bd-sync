//! `bd config`.

use bd_core::config;
use bd_core::{Error, Queries, RenamePrefixOptions, Result, WriteCtx};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::io;

pub fn exec_config(tx: &mut WriteCtx<'_>, cmd: &ConfigCommand) -> Result<Out> {
    match cmd {
        ConfigCommand::Set(a) => {
            io::require_admin("config set")?;
            config::set(tx, a.key.trim(), &a.value)?;
            let value = config::get_or_default(tx.conn(), a.key.trim())?;
            Ok(Out::new(json!({ "key": a.key.trim(), "value": value })).line(format!("✓ {} = {value}", a.key.trim())))
        }
        ConfigCommand::Unset(a) => {
            io::require_admin("config unset")?;
            let removed = config::unset(tx, a.key.trim())?;
            Ok(Out::new(json!({ "key": a.key.trim(), "removed": removed })).line(if removed {
                format!("✓ Unset {}", a.key.trim())
            } else {
                format!("= {} was not set", a.key.trim())
            }))
        }
        _ => Err(Error::invalid("only `config set` and `config unset` change data")),
    }
}

/// `bd rename-prefix`: admin-only, never in a batch; `--dry-run` runs it
/// whole, then rolls back.
pub fn exec_rename_prefix(tx: &mut WriteCtx<'_>, a: &RenamePrefixArgs) -> Result<Out> {
    io::require_admin("rename-prefix")?;
    let o = tx.rename_prefix(&RenamePrefixOptions { to: a.prefix.clone(), from: a.from.clone() })?;
    if a.dry_run {
        tx.set_rollback_only();
    }
    let mut json = serde_json::to_value(&o)?;
    json["dry_run"] = json!(a.dry_run);
    let out = Out::new(json).id(o.to.clone());
    if o.from == o.to {
        let mut out = out.line(format!("= nothing to rename: the ids already have the prefix {}-", o.to));
        if o.prefix_set && !a.dry_run {
            out = out.line(format!("  issue_prefix = {}", o.to));
        }
        return Ok(out);
    }
    let references = o.metadata + o.events + o.text;
    let claims = match o.claims {
        0 => String::new(),
        n => format!("; {n} live claim{} moved: holders use the new ids", plural(n)),
    };
    let kept = match o.kept {
        0 => String::new(),
        n => format!(", {n} already {}- kept", o.to),
    };
    let head = if a.dry_run { "= Dry run: would rename" } else { "✓ Renamed" };
    let mut out = out.line(format!(
        "{head} {} issue{} from {}- to {}-{kept} ({references} reference{} rewritten{claims})",
        o.renamed,
        plural(o.renamed),
        o.from,
        o.to,
        plural(references)
    ));
    if !a.dry_run {
        out = out.line(format!("  issue_prefix = {}", o.to));
    }
    Ok(out)
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub fn cmd_config_read(app: &mut App, cmd: &ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Get(k) => {
            let v = app.read(|r| r.config_value(k.key.trim()))?;
            if app.g.json {
                app.print_json(&json!({ "key": k.key.trim(), "value": v }));
            } else {
                io::outln(v);
            }
        }
        ConfigCommand::List => {
            let entries = app.read(|r| r.config_entries())?;
            let mut out = Out::new(&entries);
            for e in &entries {
                let note = if e.is_default { "  (default)" } else { "" };
                out = out.line(format!("{:<22} = {:<10}{note}", e.key, e.value)).id(e.key.clone());
            }
            app.print(out);
        }
        _ => {
            let out = app.write("config", |tx| exec_config(tx, cmd))?;
            app.print(out);
        }
    }
    Ok(())
}
