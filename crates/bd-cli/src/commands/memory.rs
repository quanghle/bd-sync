//! Project memories: remember, forget, memories.

use bd_core::{Error, MemoryAction, Queries, Result, WriteCtx};

use crate::app::{App, Out};
use crate::cli::*;
use crate::io;

pub fn exec_remember(tx: &mut WriteCtx<'_>, a: &MemoryAddArgs) -> Result<Out> {
    let content = a.content.join(" ");
    let w = tx.remember(a.key.as_deref(), &content, a.if_revision)?;
    let verb = match w.action {
        MemoryAction::Created => "✓ Remembered",
        MemoryAction::Updated => "✓ Updated",
        MemoryAction::Unchanged => "= Unchanged",
    };
    let preview: String = w.memory.content.replace('\n', " ").chars().take(80).collect();
    Ok(Out::new(&w)
        .line(format!("{verb} [{}] (revision {}): {preview}", w.memory.key, w.memory.revision))
        .id(w.memory.key.clone()))
}

pub fn exec_forget(tx: &mut WriteCtx<'_>, a: &KeyArg) -> Result<Out> {
    match tx.forget(a.key.trim())? {
        Some(m) => Ok(Out::new(&m).line(format!("✓ Forgot [{}]", m.key)).id(m.key.clone())),
        None => Err(Error::not_found("memory", a.key.trim())),
    }
}

pub fn cmd_memory_get(app: &mut App, key: &str) -> Result<()> {
    let m = app.read(|r| r.memory(key.trim()))?.ok_or_else(|| Error::not_found("memory", key.trim()))?;
    if app.g.json {
        app.print_json(&m);
    } else {
        io::outln(&m.content);
    }
    Ok(())
}

pub fn cmd_memory_list(app: &mut App, query: Option<&str>) -> Result<()> {
    let list = app.read(|r| r.memories(query))?;
    let mut out = Out::default();
    out = out.line(match query {
        Some(q) => format!("Memories matching {q:?} ({}):", list.len()),
        None => format!("Memories ({}):", list.len()),
    });
    for m in &list {
        let preview: String = m.content.replace('\n', " ").chars().take(120).collect();
        out = out.line(format!("  {}", m.key)).line(format!("    {preview}")).id(m.key.clone());
    }
    app.print(out.items(list));
    Ok(())
}
