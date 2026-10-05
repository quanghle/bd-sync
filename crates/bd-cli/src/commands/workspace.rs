//! `bd init`, `bd info` and the `.bd/.gitignore` they keep.

use std::io::Write;
use std::path::Path;

use bd_core::config::IdMode;
use bd_core::{Error, InitOptions, Queries, Result, Store};
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::io;

fn default_prefix(dir: &Path) -> String {
    let name = dir.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut p = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            p.push(c);
        } else if !p.ends_with('-') && !p.is_empty() {
            p.push('-');
        }
    }
    let p: String = p.trim_matches('-').chars().take(16).collect();
    let p = p.trim_end_matches('-').to_string();
    if p.is_empty() { "bd".into() } else { p }
}

/// The `.bd/.gitignore` pattern for `agents.lock` (what `bd agents pull` placed in a checkout), its mutex and temp files.
pub const AGENTS_LOCK_IGNORE: &str = "agents.lock*";
const AGENTS_LOCK_LINES: &str = "# What `bd agents pull` placed in this checkout is local state.\nagents.lock*\n";

/// `.bd/.gitignore`: the database and its WAL files, and `agents.lock`, are local state. Left alone if it exists.
pub fn write_bd_gitignore(dir: &Path) -> Result<()> {
    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        std::fs::write(
            &gitignore,
            format!(
                "# SQLite database and WAL files are local state.\n# Share issues with `bd export -o .bd/issues.jsonl`.\nbd.db\nbd.db-wal\nbd.db-shm\n{AGENTS_LOCK_LINES}"
            ),
        )?;
    }
    Ok(())
}

/// Make `.bd/.gitignore` (in `dir`) list `agents.lock`: write it if it is missing, else append the pattern if it lacks it.
pub fn ignore_agents_lock(dir: &Path) -> Result<()> {
    let gitignore = dir.join(".gitignore");
    let text = match std::fs::read_to_string(&gitignore) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return write_bd_gitignore(dir),
        Err(e) => return Err(Error::invalid(format!("{}: {e}", gitignore.display()))),
    };
    if text.lines().any(|l| l.trim() == AGENTS_LOCK_IGNORE) {
        return Ok(());
    }
    let separator = if text.is_empty() || text.ends_with('\n') { "" } else { "\n" };
    let mut file = std::fs::OpenOptions::new().append(true).open(&gitignore)?;
    file.write_all(format!("{separator}{AGENTS_LOCK_LINES}").as_bytes())?;
    Ok(())
}

pub fn cmd_init(app: &mut App, a: &InitArgs) -> Result<()> {
    io::require_local("bd init")?;
    let path = match &app.g.db {
        Some(p) if p.is_absolute() => p.clone(),
        Some(p) => app.cwd.join(p),
        None => app.cwd.join(".bd").join("bd.db"),
    };
    let prefix = match &a.prefix {
        Some(p) => p.trim().trim_end_matches('-').to_ascii_lowercase(),
        None => default_prefix(&app.cwd),
    };
    let id_mode = match a.id_mode {
        IdModeArg::Hash => IdMode::Hash,
        IdModeArg::Counter => IdMode::Counter,
    };
    let store = Store::init(&path, InitOptions { prefix: prefix.clone(), id_mode }, app.open_options())?;
    if let Some(dir) = path.parent()
        && dir.file_name().is_some_and(|n| n == ".bd")
    {
        write_bd_gitignore(dir)?;
    }
    app.set_store(store);
    let out = Out::new(json!({ "path": path, "prefix": prefix, "id_mode": id_mode.as_str() }))
        .line(format!("✓ Initialized bd workspace at {}", path.display()))
        .line(format!("  prefix: {prefix}   ids: {}   journal: WAL", id_mode.as_str()))
        .line("  next: bd create \"First task\" -p 1   then: bd ready".to_string())
        .id(path.display().to_string());
    app.print(out);
    Ok(())
}

pub fn cmd_info(app: &mut App) -> Result<()> {
    let me = app.resolved_actor();
    let actor = me.actor.clone();
    let workspace = app.workspace_label()?;
    let store = app.store()?;
    let workspace_id = store.meta("workspace_id")?;
    let created = store.meta("created_at")?;
    let (prefix, mode, durability, stats, head, sqlite_version, journal) = store.read(|r| {
        Ok((
            r.config_value("issue_prefix")?,
            r.config_value("id.mode")?,
            r.config_value("durability")?,
            r.stats()?,
            r.event_head()?,
            r.conn().query_row("SELECT sqlite_version()", [], |row| row.get::<_, String>(0))?,
            r.conn().query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?,
        ))
    })?;
    let mut info = json!({
        "path": workspace,
        "workspace_id": workspace_id,
        "created_at": created,
        "prefix": prefix,
        "id_mode": mode,
        "schema_version": bd_core::SCHEMA_VERSION,
        "sqlite_version": sqlite_version,
        "journal_mode": journal,
        "durability": durability,
        "actor": actor,
        "actor_source": me.source,
        "issues": stats.total,
        "events_head": head,
        "version": env!("CARGO_PKG_VERSION"),
    });
    // Under bd serve: what the client's access token may do, so that a refusal can be told apart.
    let token = io::request_token();
    info["token"] = token.clone().unwrap_or(Value::Null);
    let mut out = Out::new(&info)
        .line(format!("workspace   {workspace}"))
        .line(format!("prefix      {prefix} ({mode} ids)"))
        .line(format!(
            "storage     SQLite {sqlite_version}, journal {journal}, durability {durability}, schema v{}",
            bd_core::SCHEMA_VERSION
        ))
        .line(format!("actor       {actor} (from {})", me.from));
    if token.is_some() {
        out = out.line(format!("access      {}", crate::tokens::access_line(&info["token"])));
    }
    let out = out
        .line(format!("issues      {} ({} ready)   events head {head}", stats.total, stats.ready))
        .line(format!("bd          {}", env!("CARGO_PKG_VERSION")));
    app.print(out);
    Ok(())
}

pub fn format_timing(app: &App) -> String {
    let total = app.started.elapsed();
    let mut s = format!("timing: total {:.3}ms", total.as_secs_f64() * 1e3);
    if !app.open_time.is_zero() {
        s.push_str(&format!(", open {:.3}ms", app.open_time.as_secs_f64() * 1e3));
    }
    for t in &app.tx {
        s.push_str(&format!(
            ", tx[{}] lock {}µs exec {}µs commit {}µs ({} events, {} busy retries)",
            t.op, t.lock_wait_us, t.exec_us, t.commit_us, t.events, t.busy_retries
        ));
    }
    s
}
