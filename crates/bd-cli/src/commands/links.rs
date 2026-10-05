//! Dependencies, labels and comments.

use std::collections::BTreeMap;

use bd_core::{DepChange, DepType, Direction, Error, Guard, IssuePatch, Queries, Result, WriteCtx};
use serde_json::json;

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt;
use crate::io::read_input;

use super::json_object;

pub fn exec_dep(tx: &mut WriteCtx<'_>, cmd: &DepCommand) -> Result<Out> {
    match cmd {
        DepCommand::Add(a) => {
            let issue = tx.resolve_id(&a.issue)?;
            let target = tx.resolve_id(&a.depends_on)?;
            let dep_type = DepType::parse(&a.dep_type)?;
            let mut metadata = a.metadata.as_deref().map(|m| json_object(m, "--metadata")).transpose()?;
            if let Some(gate) = &a.gate {
                if dep_type != DepType::WaitsFor {
                    return Err(Error::invalid("--gate only applies to waits-for edges"));
                }
                metadata.get_or_insert_with(|| json!({}))["gate"] = json!(gate);
            }
            let change = tx.add_dependency(&issue, &target, dep_type.clone(), metadata)?;
            let blocked = tx.issue(&issue)?.is_blocked;
            let text = match change {
                DepChange::Added => format!("✓ {issue} depends on {target} ({dep_type})"),
                DepChange::MetadataUpdated => format!("✓ Updated metadata of {issue} -> {target}"),
                DepChange::Unchanged => format!("= {issue} already depends on {target} ({dep_type})"),
            };
            let mut out = Out::new(json!({ "issue": issue, "depends_on": target, "type": dep_type, "change": change, "is_blocked": blocked }))
                .line(text)
                .id(issue.clone());
            if blocked {
                out = out.line(format!("  {issue} is blocked"));
            }
            Ok(out)
        }
        DepCommand::Rm(a) => {
            let issue = tx.resolve_id(&a.issue)?;
            let target = tx.resolve_id(&a.depends_on)?;
            match tx.remove_dependency(&issue, &target)? {
                Some(edge) => Ok(Out::new(json!({ "removed": true, "edge": edge }))
                    .line(format!("✓ Removed {} edge {issue} -> {target}", edge.dep_type))
                    .id(issue)),
                None => {
                    Ok(Out::new(json!({ "removed": false })).line(format!("= no edge between {issue} and {target}")))
                }
            }
        }
        _ => Err(Error::invalid("only `dep add` and `dep rm` change data")),
    }
}

pub fn exec_label(tx: &mut WriteCtx<'_>, cmd: &LabelCommand) -> Result<Out> {
    let (a, add) = match cmd {
        LabelCommand::Add(a) => (a, true),
        LabelCommand::Rm(a) => (a, false),
        LabelCommand::List(_) => return Err(Error::invalid("`label list` is read-only")),
    };
    let id = tx.resolve_id(&a.id)?;
    let patch = if add {
        IssuePatch { add_labels: a.labels.clone(), ..Default::default() }
    } else {
        IssuePatch { remove_labels: a.labels.clone(), ..Default::default() }
    };
    let out = tx.update_issue(&id, &patch, &Guard::default(), false)?;
    let labels = if out.issue.labels.is_empty() { "(none)".to_string() } else { out.issue.labels.join(", ") };
    Ok(Out::new(&out.issue).line(format!("✓ {id} labels: {labels}")).id(id))
}

pub fn exec_comment_add(tx: &mut WriteCtx<'_>, a: &CommentAddArgs) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let text = if a.stdin {
        read_input("-")?
    } else if let Some(f) = &a.file {
        read_input(&f.to_string_lossy())?
    } else {
        a.text.join(" ")
    };
    let c = tx.add_comment(&id, &text)?;
    Ok(Out::new(&c).line(format!("✓ Comment #{} on {id}", c.id)).id(c.id.to_string()))
}

pub fn cmd_dep_read(app: &mut App, cmd: &DepCommand) -> Result<()> {
    match cmd {
        DepCommand::List(a) => {
            let (down, up) = app.read(|r| {
                let id = r.resolve_id(&a.id)?;
                let t = a.dep_type.as_deref().map(DepType::parse).transpose()?;
                let keep = |e: &bd_core::Edge| t.as_ref().is_none_or(|t| &e.dep_type == t);
                let down: Vec<_> = if a.direction != DirectionArg::Up {
                    r.dependencies(&id)?.into_iter().filter(keep).collect()
                } else {
                    vec![]
                };
                let up: Vec<_> = if a.direction != DirectionArg::Down {
                    r.dependents(&id)?.into_iter().filter(keep).collect()
                } else {
                    vec![]
                };
                Ok((down, up))
            })?;
            let mut out = Out::new(json!({ "dependencies": down, "dependents": up }));
            if !down.is_empty() {
                out = out.line("Depends on:");
                for e in &down {
                    out = out
                        .line(format!("  [{}] {} {} {}", e.dep_type, e.status.icon(), e.id, e.title))
                        .id(e.id.clone());
                }
            }
            if !up.is_empty() {
                out = out.line("Dependents:");
                for e in &up {
                    out = out
                        .line(format!("  [{}] {} {} {}", e.dep_type, e.status.icon(), e.id, e.title))
                        .id(e.id.clone());
                }
            }
            if down.is_empty() && up.is_empty() {
                out = out.line("No dependencies");
            }
            app.print(out);
        }
        DepCommand::Tree(a) => {
            let trees = app.read(|r| {
                let id = r.resolve_id(&a.id)?;
                let mut trees = Vec::new();
                if a.direction != DirectionArg::Up {
                    trees.push(("down", r.dep_tree(&id, Direction::Down, a.max_depth)?));
                }
                if a.direction != DirectionArg::Down {
                    trees.push(("up", r.dep_tree(&id, Direction::Up, a.max_depth)?));
                }
                Ok(trees)
            })?;
            let json: BTreeMap<&str, &Vec<bd_core::TreeNode>> = trees.iter().map(|(k, v)| (*k, v)).collect();
            let mut out = Out::new(&json);
            for (dir, nodes) in &trees {
                if trees.len() > 1 {
                    out = out.line(if *dir == "down" { "Depends on:" } else { "Depended on by:" });
                }
                for n in nodes {
                    out = out.line(fmt::tree_line(n)).id(n.id.clone());
                }
            }
            app.print(out);
        }
        DepCommand::Cycles => {
            let cycles = app.read(|r| r.cycles())?;
            let mut out = Out::new(&cycles);
            if cycles.is_empty() {
                out = out.line("No cycles");
            }
            for c in &cycles {
                out = out.line(format!("⟳ {} -> {}", c.join(" -> "), c[0]));
            }
            app.print(out);
        }
        DepCommand::Add(_) | DepCommand::Rm(_) => {
            let out = app.write("dep", |tx| exec_dep(tx, cmd))?;
            app.print(out);
        }
    }
    Ok(())
}

pub fn cmd_label_list(app: &mut App, a: &LabelListArgs) -> Result<()> {
    match &a.id {
        Some(raw) => {
            let issue = app.read(|r| r.issue(&r.resolve_id(raw)?))?;
            let out = Out::new(&issue.labels).lines(issue.labels.iter().cloned());
            app.print(Out { ids: issue.labels.clone(), ..out });
        }
        None => {
            let counts = app.read(|r| r.label_counts())?;
            let json: BTreeMap<&str, i64> = counts.iter().map(|(l, n)| (l.as_str(), *n)).collect();
            let mut out = Out::new(&json);
            for (l, n) in &counts {
                out = out.line(format!("{l} ({n})")).id(l.clone());
            }
            if counts.is_empty() {
                out = out.line("No labels");
            }
            app.print(out);
        }
    }
    Ok(())
}

pub fn cmd_comments(app: &mut App, id: &str) -> Result<()> {
    let (id, comments) = app.read(|r| {
        let id = r.resolve_id(id)?;
        let c = r.comments(&id)?;
        Ok((id, c))
    })?;
    let mut out = Out::default();
    if comments.is_empty() {
        out = out.line(format!("No comments on {id}"));
    }
    for c in &comments {
        out = out.line(format!("[{}] {} #{}", c.author, c.created_at, c.id)).id(c.id.to_string());
        for line in c.text.lines() {
            out = out.line(format!("  {line}"));
        }
    }
    app.print(out.items(comments));
    Ok(())
}
