//! `bd config`.

use bd_core::config;
use bd_core::{Error, Queries, Result, WriteCtx};
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
