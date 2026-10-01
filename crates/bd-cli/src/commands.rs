//! Command implementations.
//!
//! Mutations are `exec_*` functions over a [`WriteCtx`] so that `bd batch`
//! can run any sequence of them inside one transaction.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use bd_core::config::{self, IdMode};
use bd_core::doctor::{self, Severity};
use bd_core::metrics::{self, Metrics};
use bd_core::time::{parse_duration, parse_when};
use bd_core::transfer::{ExportOptions, ImportOptions};
use bd_core::{
    Claim, ClaimOptions, CloseOptions, DeleteOptions, DepChange, DepType, Direction, Error, EventQuery, Guard,
    InitOptions, IssuePatch, ListQuery, ListSort, MemoryAction, NewIssue, Outcome, PruneOptions, Queries, ReadyQuery,
    ReclaimOptions, ReleaseOptions, Result, SortPolicy, Status, Store, Timestamp, WorkFilter, WriteCtx,
};
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::*;
use crate::fmt::{self, rel};

// ---------------------------------------------------------------- helpers

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
    if let Some((t, id)) = s.split_once(':') {
        if !id.is_empty() {
            if let Ok(dep_type) = DepType::parse(t) {
                return Ok((dep_type, q.resolve_id(id)?));
            }
        }
    }
    Ok((DepType::Blocks, q.resolve_id(s)?))
}

fn read_input(path: &str) -> Result<String> {
    let mut s = String::new();
    if path == "-" {
        std::io::stdin().read_to_string(&mut s)?;
    } else {
        s = std::fs::read_to_string(path).map_err(|e| Error::invalid(format!("{path}: {e}")))?;
    }
    Ok(s)
}

fn one_or_many<T: serde::Serialize>(items: &[T]) -> Value {
    if items.len() == 1 {
        serde_json::to_value(&items[0]).unwrap_or(Value::Null)
    } else {
        serde_json::to_value(items).unwrap_or(Value::Null)
    }
}

// --------------------------------------------------------------- mutations

pub fn exec_create(tx: &mut WriteCtx<'_>, a: &CreateArgs) -> Result<Out> {
    let now = tx.now();
    let parent = a.parent.as_deref().map(|p| tx.resolve_id(p)).transpose()?;
    let deps = a.deps.iter().filter(|d| !d.trim().is_empty()).map(|d| dep_spec(tx, d)).collect::<Result<Vec<_>>>()?;
    let new = NewIssue {
        id: a.id.clone(),
        title: a.title.join(" "),
        description: a.description.clone().unwrap_or_default(),
        design: a.design.clone().unwrap_or_default(),
        acceptance_criteria: a.acceptance.clone().unwrap_or_default(),
        notes: a.notes.clone().unwrap_or_default(),
        issue_type: a.issue_type.clone(),
        priority: a.priority,
        status: a.pinned.then_some(Status::Pinned),
        assignee: a.assignee.clone(),
        labels: a.labels.clone(),
        parent,
        deps,
        external_ref: a.external_ref.clone(),
        estimated_minutes: a.estimate,
        due_at: a.due.as_deref().map(|s| parse_when(s, now)).transpose()?,
        defer_until: a.defer.as_deref().map(|s| parse_when(s, now)).transpose()?,
        metadata: a.metadata.as_deref().map(|m| json_object(m, "--metadata")).transpose()?,
    };
    let issue = tx.create_issue(new)?;
    let mut out = if a.claim {
        let claim = tx.claim(&issue.id, &ClaimOptions::default())?;
        claim_out(&claim, now).line(String::new())
    } else {
        Out::new(&issue)
    };
    out.text.insert(0, format!("✓ Created {}: {}", issue.id, issue.title));
    if issue.is_blocked {
        let blockers: Vec<String> = tx.blockers(&issue.id)?.into_iter().map(|b| b.id).collect();
        out.text.insert(1, format!("  blocked by: {}", blockers.join(", ")));
    }
    out.text.retain(|l| !l.is_empty());
    Ok(out.id(issue.id))
}

pub fn exec_update(tx: &mut WriteCtx<'_>, a: &UpdateArgs) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let now = tx.now();
    let patch = IssuePatch {
        title: a.title.clone(),
        description: a.description.clone(),
        design: a.design.clone(),
        acceptance_criteria: a.acceptance.clone(),
        notes: a.notes.clone(),
        append_notes: a.append_notes.clone(),
        status: a.status.as_deref().map(Status::parse).transpose()?,
        priority: a.priority,
        issue_type: a.issue_type.clone(),
        assignee: clearable(&a.assignee),
        external_ref: clearable(&a.external_ref),
        estimated_minutes: match &a.estimate {
            None => None,
            Some(s) if s.trim().is_empty() => Some(None),
            Some(s) => Some(Some(
                s.trim().parse::<i64>().map_err(|_| Error::invalid(format!("invalid estimate {s:?} (minutes)")))?,
            )),
        },
        due_at: clearable_time(&a.due, now)?,
        defer_until: clearable_time(&a.defer, now)?,
        metadata: a.metadata.as_deref().map(|m| json_object(m, "--metadata")).transpose()?,
        set_metadata: a.set_metadata.iter().map(|s| key_value(s)).collect::<Result<_>>()?,
        unset_metadata: a.unset_metadata.clone(),
        add_labels: a.add_labels.clone(),
        remove_labels: a.remove_labels.clone(),
        set_labels: a.set_labels.clone(),
        parent: match &a.parent {
            None => None,
            Some(p) if p.trim().is_empty() => Some(None),
            Some(p) => Some(Some(tx.resolve_id(p)?)),
        },
    };
    if patch.is_empty() {
        return Err(Error::invalid("nothing to update: pass at least one field flag"));
    }
    let out = tx.update_issue(&id, &patch, &guard_from(&a.guard)?, a.force)?;
    let text = if out.changed.is_empty() {
        format!("= {id} unchanged (revision {})", out.issue.revision)
    } else {
        format!("✓ Updated {id}: {} (revision {})", out.changed.join(", "), out.issue.revision)
    };
    Ok(Out::new(&out).line(text).id(id))
}

pub fn exec_close(tx: &mut WriteCtx<'_>, a: &CloseArgs) -> Result<Out> {
    let opts = CloseOptions {
        reason: a.reason.clone(),
        outcome: Some(if a.failed { Outcome::Failed } else { Outcome::Done }),
        force: a.force,
        guard: guard_from(&a.guard)?,
        token: a.token,
    };
    let mut ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    // Deepest first, so children listed alongside their parent close before it.
    let mut keyed = Vec::new();
    for id in ids.drain(..) {
        keyed.push((std::cmp::Reverse(tx.depth(&id)?), id));
    }
    keyed.sort();
    keyed.dedup();
    let mut results = Vec::new();
    let mut out = Out::new(Value::Null);
    for (_, id) in keyed {
        let r = tx.close_issue(&id, &opts)?;
        if r.already_closed {
            out = out.line(format!("= {id} already closed"));
        } else {
            let outcome = if a.failed { " (failed)" } else { "" };
            out = out.line(format!("✓ Closed {id}{outcome}: {}", r.issue.title));
        }
        for u in &r.unblocked {
            out = out.line(format!("  ↳ unblocked {} [P{}] {}", u.id, u.priority, u.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = one_or_many(&results);
    Ok(out)
}

pub fn exec_reopen(tx: &mut WriteCtx<'_>, a: &ReopenArgs) -> Result<Out> {
    let mut results = Vec::new();
    let mut out = Out::new(Value::Null);
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let r = tx.reopen_issue(&id, a.reason.as_deref())?;
        out = out.line(if r.already_open {
            format!("= {id} is not closed")
        } else {
            format!("✓ Reopened {id}: {}", r.issue.title)
        });
        for b in &r.newly_blocked {
            out = out.line(format!("  ↳ blocks again {} {}", b.id, b.title));
        }
        out = out.id(id);
        results.push(r);
    }
    out.json = one_or_many(&results);
    Ok(out)
}

pub fn exec_defer(tx: &mut WriteCtx<'_>, a: &DeferArgs) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let now = tx.now();
    let until = a.until.as_deref().map(|s| parse_when(s, now)).transpose()?;
    let out = tx.defer_issue(&id, until)?;
    let text = match until {
        Some(t) => format!("❄ Deferred {id} until {t} ({})", rel(t, now)),
        None => format!("❄ Deferred {id} indefinitely (bd undefer {id} to resume)"),
    };
    Ok(Out::new(&out).line(text).id(id))
}

pub fn exec_undefer(tx: &mut WriteCtx<'_>, a: &IdArg) -> Result<Out> {
    let id = tx.resolve_id(&a.id)?;
    let out = tx.undefer_issue(&id)?;
    let text = if out.changed.is_empty() { format!("= {id} was not deferred") } else { format!("✓ Undeferred {id}") };
    Ok(Out::new(&out).line(text).id(id))
}

pub fn exec_delete(tx: &mut WriteCtx<'_>, a: &DeleteArgs) -> Result<Out> {
    let ids = a.ids.iter().map(|raw| tx.resolve_id(raw)).collect::<Result<Vec<_>>>()?;
    let opts = DeleteOptions { cascade: a.cascade, force: a.force, dry_run: a.dry_run };
    let r = tx.delete_issues(&ids, &opts)?;
    let verb = if r.dry_run { "Would delete" } else { "✓ Deleted" };
    let mut out = Out::new(&r).line(format!("{verb} {} issue(s): {}", r.deleted.len(), r.deleted.join(", ")));
    if !r.detached.is_empty() {
        out = out.line(format!(
            "  {} edges from: {}",
            if r.dry_run { "would drop" } else { "dropped" },
            r.detached.join(", ")
        ));
    }
    for id in &r.deleted {
        out = out.id(id.clone());
    }
    Ok(out)
}

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

fn claim_out(c: &Claim, now: Timestamp) -> Out {
    let verb = if c.already_held { "Already holding" } else { "Claimed" };
    Out::new(c)
        .line(format!("✓ {verb} {}: {}", c.issue.id, c.issue.title))
        .line(format!(
            "  lease token {}, expires {} (renew: bd heartbeat {} --token {})",
            c.lease.token,
            rel(c.lease.expires_at, now),
            c.issue.id,
            c.lease.token
        ))
        .id(c.issue.id.clone())
}

pub fn exec_claim(tx: &mut WriteCtx<'_>, a: &ClaimArgs) -> Result<Out> {
    let now = tx.now();
    let ttl = a.ttl.as_deref().map(parse_duration).transpose()?;
    if a.next {
        let filter = filter_from(tx, &a.filter)?;
        let include_epics = filter.types.iter().any(|t| t == "epic");
        let q = ReadyQuery {
            filter,
            sort: SortPolicy::parse(&a.sort)?,
            limit: Some(1),
            include_deferred: false,
            include_epics,
        };
        match tx.claim_next(&q, &ClaimOptions { ttl, ..Default::default() })? {
            Some(c) => Ok(claim_out(&c, now)),
            None => Ok(Out::new(Value::Null).line("No ready work to claim")),
        }
    } else {
        let id = tx.resolve_id(a.id.as_deref().unwrap_or_default())?;
        let opts = ClaimOptions {
            ttl,
            allow_blocked: a.allow_blocked,
            guard: Guard { if_revision: a.if_revision, ..Default::default() },
        };
        Ok(claim_out(&tx.claim(&id, &opts)?, now))
    }
}

pub fn exec_heartbeat(tx: &mut WriteCtx<'_>, a: &HeartbeatArgs) -> Result<Out> {
    let now = tx.now();
    let ttl = a.ttl.as_deref().map(parse_duration).transpose()?;
    let mut leases = Vec::new();
    let mut out = Out::new(Value::Null);
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let lease = tx.heartbeat(&id, a.token, ttl)?;
        out = out
            .line(format!("♥ {id} lease renewed, expires {} (token {})", rel(lease.expires_at, now), lease.token))
            .id(id);
        leases.push(lease);
    }
    out.json = one_or_many(&leases);
    Ok(out)
}

pub fn exec_release(tx: &mut WriteCtx<'_>, a: &ReleaseArgs) -> Result<Out> {
    let opts = ReleaseOptions {
        reason: a.reason.clone(),
        force: a.force || a.if_assignee.is_some(),
        guard: Guard { if_assignee: a.if_assignee.as_ref().map(|x| Some(x.trim().to_string())), ..Default::default() },
        token: a.token,
    };
    let mut issues = Vec::new();
    let mut out = Out::new(Value::Null);
    for raw in &a.ids {
        let id = tx.resolve_id(raw)?;
        let issue = tx.release(&id, &opts)?;
        out = out.line(format!("✓ Released {id} (now {})", issue.status)).id(id);
        issues.push(issue);
    }
    out.json = one_or_many(&issues);
    Ok(out)
}

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

pub fn exec_config(tx: &mut WriteCtx<'_>, cmd: &ConfigCommand) -> Result<Out> {
    match cmd {
        ConfigCommand::Set(a) => {
            config::set(tx, a.key.trim(), &a.value)?;
            let value = config::get_or_default(tx.conn(), a.key.trim())?;
            Ok(Out::new(json!({ "key": a.key.trim(), "value": value })).line(format!("✓ {} = {value}", a.key.trim())))
        }
        ConfigCommand::Unset(a) => {
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

// ------------------------------------------------------------- top level

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

pub fn cmd_init(app: &mut App, a: &InitArgs) -> Result<()> {
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
    if let Some(dir) = path.parent() {
        if dir.file_name().is_some_and(|n| n == ".bd") {
            let gitignore = dir.join(".gitignore");
            if !gitignore.exists() {
                std::fs::write(
                    &gitignore,
                    "# SQLite database and WAL files are local state.\n# Share issues with `bd export -o .bd/issues.jsonl`.\nbd.db\nbd.db-wal\nbd.db-shm\n",
                )?;
            }
        }
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

pub fn cmd_show(app: &mut App, a: &ShowArgs) -> Result<()> {
    let (all, now) = app.read(|r| {
        let all = a.ids.iter().map(|raw| r.details(&r.resolve_id(raw)?)).collect::<Result<Vec<_>>>()?;
        Ok((all, r.now()))
    })?;
    if app.g.json {
        app.print_json(&one_or_many(&all));
    } else if app.g.quiet {
        all.iter().for_each(|d| println!("{}", d.issue.id));
    } else {
        for (n, d) in all.iter().enumerate() {
            if n > 0 {
                println!();
            }
            fmt::details(d, now).iter().for_each(|l| println!("{l}"));
        }
    }
    Ok(())
}

pub fn cmd_list(app: &mut App, a: &ListArgs) -> Result<()> {
    let (issues, now) = app.read(|r| {
        let q = ListQuery {
            filter: filter_from(r, &a.filter)?,
            statuses: a.status.iter().map(|s| Status::parse(s)).collect::<Result<_>>()?,
            all: a.all,
            blocked_only: a.blocked,
            search: a.search.clone(),
            sort: ListSort::parse(&a.sort)?,
            reverse: a.reverse,
            limit: (a.limit > 0).then_some(a.limit),
        };
        Ok((r.list(&q)?, r.now()))
    })?;
    let n = issues.len();
    let out = Out::new(&issues).lines(issues.iter().map(|i| fmt::issue_line(i, now))).line(if n == 0 {
        "No issues".to_string()
    } else {
        format!("-- {n} issue(s)")
    });
    let ids: Vec<String> = issues.iter().map(|i| i.id.clone()).collect();
    app.print(Out { ids, ..out });
    Ok(())
}

pub fn cmd_ready(app: &mut App, a: &ReadyArgs) -> Result<()> {
    let (issues, stats, now) = app.read(|r| {
        let filter = filter_from(r, &a.filter)?;
        let include_epics = a.include_epics || filter.types.iter().any(|t| t == "epic");
        let q = ReadyQuery {
            filter,
            sort: SortPolicy::parse(&a.sort)?,
            limit: (a.limit > 0).then_some(a.limit),
            include_deferred: a.include_deferred,
            include_epics,
        };
        Ok((r.ready(&q)?, r.stats()?, r.now()))
    })?;
    let mut out = Out::new(&issues);
    if issues.is_empty() {
        out = out.line(format!(
            "No ready work ({} blocked, {} in progress, {} deferred)",
            stats.blocked,
            stats.by_status.get("in_progress").copied().unwrap_or(0),
            stats.deferred
        ));
    } else {
        out = out.line(format!("Ready work ({} shown, queue order):", issues.len()));
        for (n, i) in issues.iter().enumerate() {
            out = out.line(format!("{:>3}. {}", n + 1, fmt::issue_line(i, now)));
        }
    }
    out.ids = issues.iter().map(|i| i.id.clone()).collect();
    app.print(out);
    Ok(())
}

pub fn cmd_blocked(app: &mut App, a: &BlockedArgs) -> Result<()> {
    let (blocked, now) = app.read(|r| {
        let f = filter_from(r, &a.filter)?;
        Ok((r.blocked(&f, (a.limit > 0).then_some(a.limit))?, r.now()))
    })?;
    let mut out = Out::new(&blocked);
    if blocked.is_empty() {
        out = out.line("Nothing is blocked");
    }
    for b in &blocked {
        out = out.line(fmt::issue_line(&b.issue, now));
        for x in &b.blockers {
            out = out.line(format!("    ← {} {}: {}", x.id, x.title, x.detail));
        }
        out = out.id(b.issue.id.clone());
    }
    app.print(out);
    Ok(())
}

pub fn cmd_leases(app: &mut App, a: &LeasesArgs) -> Result<()> {
    let (mut leases, now) = app.read(|r| Ok((r.leases()?, r.now())))?;
    if a.expired {
        leases.retain(|l| l.expired);
    }
    let mut out = Out::new(&leases);
    if leases.is_empty() {
        out = out.line("No leases");
    }
    for l in &leases {
        out = out
            .line(format!("◐ {} {} — {}", l.lease.issue_id, l.title, fmt::lease_text(&l.lease, now)))
            .id(l.lease.issue_id.clone());
    }
    app.print(out);
    Ok(())
}

pub fn cmd_reclaim(app: &mut App, a: &ReclaimArgs) -> Result<()> {
    let grace = a.grace.as_deref().map(parse_duration).transpose()?;
    let (reclaimed, now) = app.write("reclaim", |tx| {
        let ids = a.ids.iter().map(|i| tx.resolve_id(i)).collect::<Result<Vec<_>>>()?;
        let opts = ReclaimOptions {
            grace,
            filter: WorkFilter {
                assignee: a.assignee.clone(),
                labels_all: a.labels.clone(),
                ids,
                ..Default::default()
            },
            dry_run: a.dry_run,
        };
        Ok((tx.reclaim_expired(&opts)?, tx.now()))
    })?;
    let verb = if a.dry_run { "would reclaim" } else { "↺ Reclaimed" };
    let mut out = Out::new(&reclaimed);
    if reclaimed.is_empty() {
        out = out.line("No stale leases past the grace window");
    }
    for r in &reclaimed {
        out = out
            .line(format!(
                "{verb} {} from {} (lease expired {}, token {})",
                r.issue_id,
                r.previous_holder,
                rel(r.expired_at, now),
                r.token
            ))
            .id(r.issue_id.clone());
    }
    app.print(out);
    Ok(())
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
    let mut out = Out::new(&comments);
    if comments.is_empty() {
        out = out.line(format!("No comments on {id}"));
    }
    for c in &comments {
        out = out.line(format!("[{}] {} #{}", c.author, c.created_at, c.id)).id(c.id.to_string());
        for line in c.text.lines() {
            out = out.line(format!("  {line}"));
        }
    }
    app.print(out);
    Ok(())
}

pub fn cmd_memory_get(app: &mut App, key: &str) -> Result<()> {
    let m = app.read(|r| r.memory(key.trim()))?.ok_or_else(|| Error::not_found("memory", key.trim()))?;
    if app.g.json {
        app.print_json(&m);
    } else {
        println!("{}", m.content);
    }
    Ok(())
}

pub fn cmd_memory_list(app: &mut App, query: Option<&str>) -> Result<()> {
    let list = app.read(|r| r.memories(query))?;
    let mut out = Out::new(&list);
    out = out.line(match query {
        Some(q) => format!("Memories matching {q:?} ({}):", list.len()),
        None => format!("Memories ({}):", list.len()),
    });
    for m in &list {
        let preview: String = m.content.replace('\n', " ").chars().take(120).collect();
        out = out.line(format!("  {}", m.key)).line(format!("    {preview}")).id(m.key.clone());
    }
    app.print(out);
    Ok(())
}

pub fn cmd_events(app: &mut App, a: &EventsArgs) -> Result<()> {
    if let Some(EventsAction::Prune(p)) = &a.action {
        let opts = PruneOptions {
            before: p.before,
            older_than: p.older_than.as_deref().map(parse_duration).transpose()?,
            keep: p.keep,
        };
        let r = app.write("events.prune", |tx| tx.prune_events(&opts))?;
        let out = Out::new(&r).line(format!("✓ Pruned {} event(s); retained seq {}..={}", r.deleted, r.floor, r.head));
        app.print(out);
        return Ok(());
    }
    let issue = match &a.issue {
        Some(raw) => Some(app.read(|r| r.resolve_id(raw))?),
        None => None,
    };
    let mut q =
        EventQuery { since: a.since, limit: a.limit, issue_id: issue, ops: a.ops.clone(), actor: a.by_actor.clone() };
    let print = |app: &App, events: &[bd_core::Event]| {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        for e in events {
            let line = if app.g.json { serde_json::to_string(e).unwrap_or_default() } else { fmt::event_line(e) };
            let _ = writeln!(lock, "{line}");
        }
        let _ = lock.flush();
    };
    let page = app.read(|r| r.events(&q))?;
    print(app, &page.events);
    if !a.follow {
        return Ok(());
    }
    let mut cursor = page.events.last().map(|e| e.seq).unwrap_or(page.head.max(a.since.unwrap_or(0)));
    q.limit = Some(1000);
    loop {
        std::thread::sleep(Duration::from_millis(a.interval_ms.max(10)));
        q.since = Some(cursor);
        let page = app.read(|r| r.events(&q))?;
        if let Some(last) = page.events.last() {
            cursor = last.seq;
        } else {
            cursor = cursor.max(page.head);
        }
        print(app, &page.events);
    }
}

pub fn cmd_history(app: &mut App, a: &HistoryArgs) -> Result<()> {
    let (id, exists, events) = app.read(|r| {
        // Deleted issues keep their history, so an unknown id is looked up verbatim.
        let (id, exists) = match r.resolve_id(&a.id) {
            Ok(id) => (id, true),
            Err(Error::NotFound { .. }) => (a.id.trim().to_string(), false),
            Err(e) => return Err(e),
        };
        let events = r.history(&id)?;
        Ok((id, exists, events))
    })?;
    if events.is_empty() && !exists {
        return Err(Error::not_found("issue", id));
    }
    let mut out = Out::new(&events);
    out = if events.is_empty() {
        out.line(format!("No retained history for {id} (events were pruned)"))
    } else {
        out.line(format!("History of {id} ({} events):", events.len()))
    };
    for e in &events {
        out = out.line(fmt::event_line(e)).id(e.seq.to_string());
    }
    app.print(out);
    Ok(())
}

pub fn cmd_prime(app: &mut App, a: &PrimeArgs) -> Result<()> {
    let actor = app.actor();
    let path = app.db_path()?;
    let (mine, ready, stats, memories, ttl, now, prefix) = app.read(|r| {
        let mine = r.list(&ListQuery {
            filter: WorkFilter { assignee: Some(actor.clone()), ..Default::default() },
            statuses: vec![Status::InProgress],
            ..Default::default()
        })?;
        let leases: BTreeMap<String, bd_core::Lease> =
            r.leases()?.into_iter().map(|l| (l.lease.issue_id.clone(), l.lease)).collect();
        let mine: Vec<(bd_core::Issue, Option<bd_core::Lease>)> = mine
            .into_iter()
            .map(|i| {
                let l = leases.get(&i.id).cloned();
                (i, l)
            })
            .collect();
        let ready = r.ready(&ReadyQuery { limit: Some(a.ready.max(1)), ..Default::default() })?;
        Ok((
            mine,
            ready,
            r.stats()?,
            r.memories(None)?,
            r.config_value("lease.ttl")?,
            r.now(),
            r.config_value("issue_prefix")?,
        ))
    })?;
    let shown_memories: Vec<&bd_core::Memory> =
        if a.max_memories > 0 { memories.iter().take(a.max_memories).collect() } else { memories.iter().collect() };
    if app.g.json {
        app.print_json(&json!({
            "workspace": path,
            "prefix": prefix,
            "actor": actor,
            "lease_ttl": ttl,
            "claims": mine.iter().map(|(i, l)| json!({ "issue": i, "lease": l })).collect::<Vec<_>>(),
            "ready": ready,
            "ready_total": stats.ready,
            "stats": stats,
            "memories": shown_memories,
        }));
        return Ok(());
    }
    let mut o = Vec::new();
    o.push("# bd workflow context".to_string());
    o.push(format!("Workspace `{}` (prefix `{prefix}`); you are `{actor}`.", path.display()));
    o.push(String::new());
    o.push("## Core loop".into());
    o.push("- `bd ready` lists unblocked work in queue order (priority, then age).".into());
    o.push(format!("- `bd claim --next` atomically takes the head of the queue with a {ttl} lease; `bd claim <id>` takes a specific issue."));
    o.push("- `bd heartbeat <id> --token <t>` renews the lease while you work; a lost lease means stop.".into());
    o.push(
        "- `bd close <id> --reason \"...\"` finishes (add `--failed` when it failed); `bd release <id>` gives it back."
            .into(),
    );
    o.push(
        "- `bd create \"title\" --dep <id>` records discovered work; `bd dep add <issue> <depends-on>` orders it."
            .into(),
    );
    o.push(
        "- `bd comment add <id> \"...\"` leaves context; `bd remember \"insight\"` stores durable memory shown here."
            .into(),
    );
    o.push("- `--json` on any command gives machine output; `--if-revision N` makes an update compare-and-set (exit 13 on conflict).".into());
    o.push(String::new());
    o.push(format!(
        "## Status: {} ready · {} in progress · {} blocked · {} deferred · {} open total",
        stats.ready,
        stats.by_status.get("in_progress").copied().unwrap_or(0),
        stats.blocked,
        stats.deferred,
        stats.by_status.get("open").copied().unwrap_or(0)
    ));
    if !mine.is_empty() {
        o.push(String::new());
        o.push(format!("## Your claims ({})", mine.len()));
        for (i, l) in &mine {
            let lease = l
                .as_ref()
                .map(|l| format!(" (token {}, lease expires {})", l.token, rel(l.expires_at, now)))
                .unwrap_or_default();
            o.push(format!("- {} [P{}] {}{lease}", i.id, i.priority, i.title));
        }
    }
    o.push(String::new());
    o.push(format!("## Ready work (top {} of {})", ready.len(), stats.ready));
    if ready.is_empty() {
        o.push("- (none)".into());
    }
    for i in &ready {
        o.push(format!("- {} [P{}] [{}] {}", i.id, i.priority, i.issue_type, i.title));
    }
    if !memories.is_empty() {
        o.push(String::new());
        let shown = if shown_memories.len() < memories.len() {
            format!("showing {} of {}", shown_memories.len(), memories.len())
        } else {
            memories.len().to_string()
        };
        o.push(format!("## Persistent memories ({shown})"));
        o.push("Update with `bd remember --key <key> \"...\"`, search with `bd memories <q>`, remove with `bd forget <key>`.".into());
        for m in shown_memories {
            o.push(String::new());
            o.push(format!("### {}", m.key));
            o.push(m.content.clone());
        }
    }
    o.iter().for_each(|l| println!("{l}"));
    Ok(())
}

pub fn cmd_stats(app: &mut App) -> Result<()> {
    let stats = app.read(|r| r.stats())?;
    let mut out = Out::new(&stats).line(format!("Issues: {} total", stats.total));
    for (s, n) in &stats.by_status {
        out = out.line(format!("  {:<12} {n}", s));
    }
    out = out
        .line(format!("Ready: {}   Blocked: {}   Deferred: {}", stats.ready, stats.blocked, stats.deferred))
        .line(format!("Leases: {} active, {} expired", stats.leases_active, stats.leases_expired));
    if !stats.closable_epics.is_empty() {
        out = out.line(format!("Epics ready to close: {}", stats.closable_epics.join(", ")));
    }
    app.print(out);
    Ok(())
}

fn prom_line(o: &mut String, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
    if labels.is_empty() {
        o.push_str(&format!("{name} {value}\n"));
    } else {
        let l: Vec<String> =
            labels.iter().map(|(k, v)| format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))).collect();
        o.push_str(&format!("{name}{{{}}} {value}\n", l.join(",")));
    }
}

fn prom_header(o: &mut String, name: &str, kind: &str, help: &str) {
    o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
}

pub fn prometheus(m: &Metrics) -> String {
    let mut o = String::new();
    prom_header(&mut o, "bd_issues", "gauge", "Issues by status");
    for (s, n) in &m.stats.by_status {
        prom_line(&mut o, "bd_issues", &[("status", s)], n);
    }
    prom_header(&mut o, "bd_ready_issues", "gauge", "Ready issues by priority");
    for (p, n) in &m.ready_by_priority {
        prom_line(&mut o, "bd_ready_issues", &[("priority", p)], n);
    }
    for (name, help, v) in [
        ("bd_blocked_issues", "Live issues held back by dependencies", m.stats.blocked),
        ("bd_deferred_issues", "Live issues hidden by a deferral", m.stats.deferred),
        ("bd_leases_active", "Live claim leases", m.leases.active),
        ("bd_leases_expired", "Leases past expiry", m.leases.expired),
        ("bd_leases_expiring_soon", "Leases expiring within 60s", m.leases.expiring_soon),
        ("bd_leases_reclaimable", "Leases expired past the grace window", m.leases.reclaimable),
        ("bd_events_head_seq", "Highest event sequence number", m.events_head),
        ("bd_events_retained", "Events retained in the log", m.events_retained),
        ("bd_db_size_bytes", "Main database size", m.db.size_bytes),
    ] {
        prom_header(&mut o, name, "gauge", help);
        prom_line(&mut o, name, &[], v);
    }
    if let Some(age) = m.leases.oldest_heartbeat_age_ms {
        prom_header(&mut o, "bd_lease_oldest_heartbeat_age_seconds", "gauge", "Age of the stalest heartbeat");
        prom_line(&mut o, "bd_lease_oldest_heartbeat_age_seconds", &[], age as f64 / 1000.0);
    }
    if let Some(w) = m.db.wal_bytes {
        prom_header(&mut o, "bd_db_wal_bytes", "gauge", "WAL file size");
        prom_line(&mut o, "bd_db_wal_bytes", &[], w);
    }
    prom_header(&mut o, "bd_events_total", "counter", "Retained events by op");
    for (op, n) in &m.ops_total {
        prom_line(&mut o, "bd_events_total", &[("op", op)], n);
    }
    prom_header(&mut o, "bd_events_24h", "gauge", "Events by op in the last 24h");
    for (op, n) in &m.ops_24h {
        prom_line(&mut o, "bd_events_24h", &[("op", op)], n);
    }
    prom_header(&mut o, "bd_counter_total", "counter", "Durable counters (contention, reclaims, slow writes)");
    for (k, n) in &m.counters {
        prom_line(&mut o, "bd_counter_total", &[("name", k)], n);
    }
    for (name, help, p) in [
        ("bd_lead_time_seconds", "created -> closed, last 30 days", &m.lead_time),
        ("bd_cycle_time_seconds", "started -> closed, last 30 days", &m.cycle_time),
        ("bd_queue_wait_seconds", "created -> started, last 30 days", &m.queue_wait),
    ] {
        prom_header(&mut o, name, "summary", help);
        for (q, v) in [("0.5", p.p50_ms), ("0.9", p.p90_ms), ("0.99", p.p99_ms)] {
            if let Some(v) = v {
                prom_line(&mut o, name, &[("quantile", q)], v as f64 / 1000.0);
            }
        }
        prom_line(&mut o, &format!("{name}_count"), &[], p.count);
    }
    o
}

pub fn cmd_metrics(app: &mut App, a: &MetricsArgs) -> Result<()> {
    let path = app.db_path()?;
    let m = app.read(|r| metrics::metrics(r.conn(), r.now(), Some(&path)))?;
    if app.g.json || a.format == MetricsFormat::Json {
        app.print_json(&m);
    } else {
        print!("{}", prometheus(&m));
    }
    Ok(())
}

pub fn cmd_doctor(app: &mut App, a: &DoctorArgs) -> Result<i32> {
    let report = doctor::diagnose(app.store()?, a.fix, a.full)?;
    if app.g.json {
        app.print_json(&report);
    } else {
        for c in &report.checks {
            let icon = match (c.severity, c.fixed) {
                (_, true) => "✓ fixed",
                (Severity::Ok, _) => "✓",
                (Severity::Warn, _) => "!",
                (Severity::Error, _) => "✗",
            };
            println!("{icon} {:<20} {}", c.name, c.detail);
        }
        println!("{}", if report.ok { "healthy" } else { "problems found (run `bd doctor --fix`)" });
    }
    Ok(if report.ok { 0 } else { 1 })
}

pub fn cmd_config_read(app: &mut App, cmd: &ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Get(k) => {
            let v = app.read(|r| r.config_value(k.key.trim()))?;
            if app.g.json {
                app.print_json(&json!({ "key": k.key.trim(), "value": v }));
            } else {
                println!("{v}");
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

pub fn cmd_export(app: &mut App, a: &ExportArgs) -> Result<()> {
    let opts = ExportOptions { include_memories: !a.no_memories, include_closed: !a.open_only };
    let summary = match &a.output {
        Some(path) => {
            let tmp = path.with_extension("jsonl.tmp");
            let file = std::fs::File::create(&tmp)?;
            let mut w = std::io::BufWriter::new(file);
            let s = app.read(|r| r.export_jsonl(&mut w, &opts))?;
            w.flush()?;
            drop(w);
            std::fs::rename(&tmp, path)?;
            s
        }
        None => {
            let stdout = std::io::stdout();
            let mut w = std::io::BufWriter::new(stdout.lock());
            let s = app.read(|r| r.export_jsonl(&mut w, &opts))?;
            w.flush()?;
            s
        }
    };
    if a.output.is_some() {
        let out = Out::new(&summary).line(format!(
            "✓ Exported {} issues, {} dependencies, {} comments, {} memories (event head {})",
            summary.issues, summary.dependencies, summary.comments, summary.memories, summary.head_seq
        ));
        app.print(out);
    }
    Ok(())
}

pub fn cmd_import(app: &mut App, a: &ImportArgs) -> Result<()> {
    let data = read_input(&a.file)?;
    let opts = ImportOptions { lenient: a.lenient };
    let dry = a.dry_run;
    let summary = app.write("import", |tx| {
        let s = tx.import_jsonl(&mut BufReader::new(data.as_bytes()), &opts)?;
        if dry {
            tx.set_rollback_only();
        }
        Ok(s)
    })?;
    let prefix = if dry { "Dry run: would import" } else { "✓ Imported" };
    let mut out = Out::new(&summary).line(format!(
        "{prefix} {} new, {} updated, {} unchanged issues; {} dependencies, {} comments, {} memories, {} leases",
        summary.created,
        summary.updated,
        summary.unchanged,
        summary.dependencies,
        summary.comments,
        summary.memories,
        summary.leases_granted
    ));
    for w in &summary.warnings {
        out = out.line(format!("  ! {w}"));
    }
    app.print(out);
    Ok(())
}

pub fn cmd_info(app: &mut App) -> Result<()> {
    let actor = app.actor();
    let path = app.db_path()?;
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
    let info = json!({
        "path": path,
        "workspace_id": workspace_id,
        "created_at": created,
        "prefix": prefix,
        "id_mode": mode,
        "schema_version": bd_core::SCHEMA_VERSION,
        "sqlite_version": sqlite_version,
        "journal_mode": journal,
        "durability": durability,
        "actor": actor,
        "issues": stats.total,
        "events_head": head,
        "version": env!("CARGO_PKG_VERSION"),
    });
    let out = Out::new(&info)
        .line(format!("workspace   {}", path.display()))
        .line(format!("prefix      {prefix} ({mode} ids)"))
        .line(format!(
            "storage     SQLite {sqlite_version}, journal {journal}, durability {durability}, schema v{}",
            bd_core::SCHEMA_VERSION
        ))
        .line(format!("actor       {actor}"))
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
