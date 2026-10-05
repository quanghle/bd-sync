//! Command implementations.
//!
//! Mutations are `exec_*` functions over a [`WriteCtx`] so that `bd batch`
//! can run any sequence of them inside one transaction.

mod claims;
mod config;
mod events;
mod health;
mod issues;
mod links;
mod memory;
mod prime;
mod transfer;
mod workspace;

pub use claims::*;
pub use config::*;
pub use events::*;
pub use health::*;
pub use issues::*;
pub use links::*;
pub use memory::*;
pub use prime::*;
pub use transfer::*;
pub use workspace::*;

use bd_core::time::parse_when;
use bd_core::{DepType, Error, Guard, Queries, Result, Status, Timestamp, WorkFilter};
use serde_json::Value;

use crate::cli::*;

pub fn filter_from<Q: Queries + ?Sized>(q: &Q, f: &FilterArgs) -> Result<WorkFilter> {
    let norm = |v: &[String]| v.iter().map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
    Ok(WorkFilter {
        assignee: f.assignee.clone(),
        unassigned: f.unassigned,
        types: norm(&f.types),
        exclude_types: norm(&f.exclude_types),
        priority: f.priority,
        max_priority: f.max_priority,
        labels_all: f.labels.clone(),
        labels_any: f.labels_any.clone(),
        exclude_labels: f.exclude_labels.clone(),
        parent: f.parent.as_deref().map(|p| q.resolve_id(p)).transpose()?,
        ids: Vec::new(),
    })
}

pub fn guard_from(g: &GuardArgs) -> Result<Guard> {
    Ok(Guard {
        if_revision: g.if_revision,
        if_status: g.if_status.as_deref().map(Status::parse).transpose()?,
        if_assignee: g.if_assignee.as_ref().map(|a| {
            let a = a.trim();
            (!a.is_empty()).then(|| a.to_string())
        }),
    })
}

fn json_object(s: &str, what: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(s).map_err(|e| Error::invalid(format!("{what}: invalid JSON: {e}")))?;
    if !v.is_object() {
        return Err(Error::invalid(format!("{what} must be a JSON object")));
    }
    Ok(v)
}

fn key_value(s: &str) -> Result<(String, Value)> {
    let (k, v) = s.split_once('=').ok_or_else(|| Error::invalid(format!("expected KEY=VALUE, got {s:?}")))?;
    if k.trim().is_empty() {
        return Err(Error::invalid(format!("empty metadata key in {s:?}")));
    }
    let value = serde_json::from_str(v).unwrap_or_else(|_| Value::String(v.to_string()));
    Ok((k.trim().to_string(), value))
}

fn clearable(v: &Option<String>) -> Option<Option<String>> {
    v.as_ref().map(|s| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    })
}

fn clearable_time(v: &Option<String>, now: Timestamp) -> Result<Option<Option<Timestamp>>> {
    match v {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(Some(None)),
        Some(s) => Ok(Some(Some(parse_when(s, now)?))),
    }
}

fn dep_spec<Q: Queries + ?Sized>(q: &Q, s: &str) -> Result<(DepType, String)> {
    let s = s.trim();
    if let Some((t, id)) = s.split_once(':')
        && !id.is_empty()
        && let Ok(dep_type) = DepType::parse(t)
    {
        return Ok((dep_type, q.resolve_id(id)?));
    }
    Ok((DepType::Blocks, q.resolve_id(s)?))
}

fn one_or_many<T: serde::Serialize>(items: &[T]) -> Value {
    if items.len() == 1 {
        serde_json::to_value(&items[0]).unwrap_or(Value::Null)
    } else {
        serde_json::to_value(items).unwrap_or(Value::Null)
    }
}
