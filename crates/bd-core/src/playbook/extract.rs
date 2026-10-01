//! `extract`: write a playbook from an existing epic and its subtree.
//!
//! Children become steps (grandchildren become nested steps), `blocks` edges
//! inside the subtree become `needs`, `waits-for` edges become `waits_for`, and
//! gate issues become the `[steps.gate]` of the steps they hold back. Edges to
//! issues outside the subtree are dropped, and so are notes and run-specific
//! metadata. Steps of a playbook run keep their original step ids.

use std::collections::{BTreeMap, HashMap};

use rusqlite::Connection;
use serde_json::{Map, Value};

use super::compile::Role;
use super::model::{Playbook, Step, StepGate, WaitsFor, valid_name, valid_step_id};
use super::run::role_of;
use crate::error::{Error, Result};
use crate::gates;
use crate::graph;
use crate::issues::{self, ISSUE_COLUMNS, issue_from_row};
use crate::model::{DepType, GATE_TYPE, Issue};

fn slug(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= max {
            break;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// TOML has no null: drop null values (and null array elements) from metadata.
fn without_nulls(map: Map<String, Value>) -> Map<String, Value> {
    fn clean(v: Value) -> Option<Value> {
        match v {
            Value::Null => None,
            Value::Array(items) => Some(Value::Array(items.into_iter().filter_map(clean).collect())),
            Value::Object(m) => Some(Value::Object(without_nulls(m))),
            other => Some(other),
        }
    }
    map.into_iter().filter_map(|(k, v)| clean(v).map(|v| (k, v))).collect()
}

fn children_in_order(conn: &Connection, id: &str) -> Result<Vec<Issue>> {
    let sql = format!(
        "SELECT {ISSUE_COLUMNS} FROM issues i JOIN dependencies d ON d.issue_id = i.id
         WHERE d.depends_on_id = ?1 AND d.dep_type = 'parent-child' ORDER BY i.created_at, i.rowid"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([id], issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Build a playbook from `root`'s subtree. `name` defaults to a slug of its title.
pub fn extract(conn: &Connection, root: &str, name: Option<&str>) -> Result<Playbook> {
    let epic = issues::require(conn, root)?;
    let name = match name {
        Some(n) => n.trim().to_string(),
        None => epic
            .metadata
            .pointer("/playbook/name")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(|| slug(&epic.title, 48)),
    };
    if !valid_name(&name) {
        return Err(Error::invalid(format!("invalid playbook name {name:?}; pass --name")));
    }
    // Collect the subtree in pre-order, grouped by parent (None = the epic).
    fn collect(
        conn: &Connection,
        id: &str,
        parent: Option<String>,
        by_parent: &mut HashMap<Option<String>, Vec<Issue>>,
        all: &mut Vec<Issue>,
    ) -> Result<()> {
        for kid in children_in_order(conn, id)? {
            let kid_id = kid.id.clone();
            by_parent.entry(parent.clone()).or_default().push(kid.clone());
            all.push(kid);
            collect(conn, &kid_id, Some(kid_id.clone()), by_parent, all)?;
        }
        Ok(())
    }
    let mut by_parent: HashMap<Option<String>, Vec<Issue>> = HashMap::new();
    let mut all: Vec<Issue> = Vec::new();
    collect(conn, root, None, &mut by_parent, &mut all)?;

    let mut step_ids: HashMap<String, String> = HashMap::new();
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut assign = |issue: &Issue| {
        let preferred = issue
            .metadata
            .pointer("/playbook/key")
            .and_then(Value::as_str)
            .and_then(|k| k.rsplit('.').next())
            .map(String::from)
            .filter(|s| valid_step_id(s))
            .unwrap_or_else(|| {
                let s = slug(&issue.title, 40);
                if s.starts_with(|c: char| c.is_ascii_alphabetic()) {
                    s
                } else {
                    format!("step-{s}").trim_end_matches('-').to_string()
                }
            });
        let n = used.entry(preferred.clone()).or_insert(0);
        *n += 1;
        let id = if *n == 1 { preferred } else { format!("{preferred}-{n}") };
        step_ids.insert(issue.id.clone(), id);
    };
    for i in all.iter().filter(|i| i.issue_type != GATE_TYPE) {
        assign(i);
    }

    // Gates attach to the work they hold back.
    let mut gates_for: HashMap<String, StepGate> = HashMap::new();
    for g in all.iter().filter(|i| i.issue_type == GATE_TYPE) {
        let Ok(spec) = gates::spec_of(g) else { continue };
        let view = gates::view_of(conn, g)?;
        for held in view.blocks.iter().filter(|b| step_ids.contains_key(&b.id)) {
            gates_for.entry(held.id.clone()).or_insert_with(|| StepGate {
                kind: spec.kind,
                await_id: spec.await_id.clone(),
                timeout: spec.timeout.clone(),
                repo: spec.repo.clone(),
                title: None,
                description: g.description.clone(),
                assignee: g.assignee.clone(),
            });
        }
    }

    fn build(
        conn: &Connection,
        parent: Option<String>,
        by_parent: &HashMap<Option<String>, Vec<Issue>>,
        step_ids: &HashMap<String, String>,
        gates_for: &HashMap<String, StepGate>,
    ) -> Result<Vec<Step>> {
        let mut out = Vec::new();
        for issue in by_parent.get(&parent).into_iter().flatten() {
            if issue.issue_type == GATE_TYPE {
                continue;
            }
            let sid = step_ids[&issue.id].clone();
            let mut step = Step::titled(&sid, &issue.title);
            step.description = issue.description.clone();
            step.design = issue.design.clone();
            step.acceptance_criteria = issue.acceptance_criteria.clone();
            let children = build(conn, Some(issue.id.clone()), by_parent, step_ids, gates_for)?;
            let is_group = !children.is_empty() || matches!(role_of(issue), Some(Role::Group));
            if !is_group && issue.issue_type != "task" {
                step.issue_type = Some(issue.issue_type.clone());
            }
            if issue.priority != 2 {
                step.priority = Some(issue.priority);
            }
            step.labels = issue.labels.clone();
            step.estimate = issue.estimated_minutes;
            let mut meta: Map<String, Value> = issue.metadata.as_object().cloned().unwrap_or_default();
            for k in ["playbook", "gate", "beads"] {
                meta.remove(k);
            }
            step.metadata = without_nulls(meta);
            for e in graph::dependencies_of(conn, &issue.id)? {
                let Some(target) = step_ids.get(&e.id) else { continue };
                match e.dep_type {
                    DepType::Blocks => {
                        if !step.needs.contains(target) {
                            step.needs.push(target.clone());
                        }
                    }
                    DepType::WaitsFor => {
                        let gate = e.metadata.get("gate").and_then(Value::as_str).unwrap_or("all-children");
                        step.waits_for = Some(WaitsFor { gate: gate.into(), spawner: Some(target.clone()) });
                        let also = matches!(e.metadata.get("also_blocks"), Some(Value::Bool(true)));
                        if also && !step.needs.contains(target) {
                            step.needs.push(target.clone());
                        }
                    }
                    _ => {}
                }
            }
            step.gate = gates_for.get(&issue.id).cloned();
            step.children = if is_group { children } else { Vec::new() };
            out.push(step);
        }
        Ok(out)
    }
    let steps = build(conn, None, &by_parent, &step_ids, &gates_for)?;
    if steps.is_empty() {
        return Err(Error::invalid(format!("{root} has no children to turn into steps")));
    }
    let pb = Playbook {
        name,
        description: epic.description.clone(),
        version: None,
        title: None,
        priority: (epic.priority != 2).then_some(epic.priority),
        labels: Vec::new(),
        ephemeral: None,
        extends: Vec::new(),
        vars: BTreeMap::new(),
        steps,
        source: None,
    };
    pb.validate()?;
    Ok(pb)
}
