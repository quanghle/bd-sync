//! JSON Lines export/import.
//!
//! Export writes one consistent snapshot: a header (with the event `head_seq`
//! at snapshot time, so a mirror can tail events from exactly there), then
//! issues sorted by id with their labels, outgoing dependencies and comments,
//! then memories sorted by key. Leases are node-local and never exported.
//!
//! Import upserts by id in one transaction and also accepts beads'
//! `bd export` format (`_type` issue/memory lines, `value` for memory
//! content, string-encoded edge metadata).

use std::collections::BTreeSet;
use std::io::{BufRead, Write};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::claims;
use crate::comments;
use crate::config;
use crate::error::{Error, Result};
use crate::events;
use crate::gates::GateKind;
use crate::graph;
use crate::ids;
use crate::issues;
use crate::memory;
use crate::model::{DepType, GATE_TYPE, Issue, ListQuery, Outcome, Status, empty_object};
use crate::store::WriteCtx;
use crate::time::{Timestamp, format_duration_ms};

pub const FORMAT: &str = "bd-jsonl";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub include_memories: bool,
    pub include_closed: bool,
    /// Ephemeral issues (scratch runs) are left out unless asked for, along
    /// with edges that point at them.
    pub include_ephemeral: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions { include_memories: true, include_closed: true, include_ephemeral: false }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExportSummary {
    pub issues: usize,
    pub dependencies: usize,
    pub comments: usize,
    pub memories: usize,
    pub head_seq: i64,
}

/// Write a snapshot. Call inside [`crate::Store::read`] for consistency.
pub fn export(conn: &Connection, now: Timestamp, out: &mut dyn Write, opts: &ExportOptions) -> Result<ExportSummary> {
    let head_seq = events::head(conn)?;
    let mut summary = ExportSummary { head_seq, ..Default::default() };
    let header = json!({
        "_type": "header",
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "prefix": config::prefix(conn)?,
        "head_seq": head_seq,
        "exported_at": now,
    });
    writeln!(out, "{header}")?;
    let q = ListQuery { all: opts.include_closed, sort: crate::model::ListSort::Id, ..Default::default() };
    for issue in issues::list(conn, &q)? {
        if issue.ephemeral && !opts.include_ephemeral {
            continue;
        }
        let mut v = serde_json::to_value(&issue)?;
        let obj = v.as_object_mut().expect("issue serializes to an object");
        obj.remove("is_blocked");
        obj.remove("revision");
        let deps: Vec<Value> = {
            let mut stmt = conn.prepare_cached(
                "SELECT d.depends_on_id, d.dep_type, d.metadata, d.created_at, d.created_by
                 FROM dependencies d JOIN issues t ON t.id = d.depends_on_id
                 WHERE d.issue_id = ?1 AND (?2 OR t.ephemeral = 0) ORDER BY d.depends_on_id",
            )?;
            let rows = stmt.query_map(params![issue.id, opts.include_ephemeral], |r| {
                let metadata: String = r.get(2)?;
                Ok(json!({
                    "depends_on_id": r.get::<_, String>(0)?,
                    "type": r.get::<_, String>(1)?,
                    "metadata": serde_json::from_str::<Value>(&metadata).unwrap_or_else(|_| empty_object()),
                    "created_at": r.get::<_, Timestamp>(3)?,
                    "created_by": r.get::<_, String>(4)?,
                }))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let comments: Vec<Value> = comments::list(conn, &issue.id)?
            .into_iter()
            .map(|c| json!({ "author": c.author, "text": c.text, "created_at": c.created_at }))
            .collect();
        summary.issues += 1;
        summary.dependencies += deps.len();
        summary.comments += comments.len();
        obj.insert("_type".into(), json!("issue"));
        obj.insert("dependencies".into(), Value::Array(deps));
        obj.insert("comments".into(), Value::Array(comments));
        writeln!(out, "{v}")?;
    }
    if opts.include_memories {
        for m in memory::list(conn, None)? {
            let mut v = serde_json::to_value(&m)?;
            let obj = v.as_object_mut().expect("memory serializes to an object");
            obj.remove("revision");
            obj.insert("_type".into(), json!("memory"));
            writeln!(out, "{v}")?;
            summary.memories += 1;
        }
    }
    Ok(summary)
}

#[derive(Clone, Debug, Default)]
pub struct ImportOptions {
    /// Accept unknown issue types as-is and map unknown statuses to `open`.
    pub lenient: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ImportSummary {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub dependencies: usize,
    pub comments: usize,
    pub memories: usize,
    pub leases_granted: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

#[derive(Deserialize)]
struct InIssue {
    id: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    design: String,
    #[serde(default, alias = "acceptance")]
    acceptance_criteria: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    priority: Option<i64>,
    #[serde(default, alias = "type")]
    issue_type: Option<String>,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    external_ref: Option<String>,
    #[serde(default)]
    estimated_minutes: Option<i64>,
    #[serde(default)]
    metadata: Option<Value>,
    created_at: Option<Timestamp>,
    #[serde(default)]
    updated_at: Option<Timestamp>,
    #[serde(default)]
    started_at: Option<Timestamp>,
    #[serde(default)]
    closed_at: Option<Timestamp>,
    #[serde(default)]
    close_reason: Option<String>,
    #[serde(default)]
    close_outcome: Option<String>,
    #[serde(default)]
    due_at: Option<Timestamp>,
    #[serde(default)]
    defer_until: Option<Timestamp>,
    #[serde(default)]
    labels: Option<Vec<String>>,
    #[serde(default)]
    dependencies: Option<Vec<InDep>>,
    #[serde(default)]
    comments: Option<Vec<InComment>>,
    #[serde(default)]
    ephemeral: bool,
    // beads workflow fields: protos are skipped (playbooks replace them),
    // gate conditions move to `metadata.gate`, molecule kinds to `metadata.beads`.
    #[serde(default)]
    is_template: bool,
    #[serde(default)]
    await_type: Option<String>,
    #[serde(default)]
    await_id: Option<String>,
    /// Go `time.Duration`: nanoseconds.
    #[serde(default)]
    timeout: Option<i64>,
    #[serde(default)]
    waiters: Option<Vec<String>>,
    #[serde(default)]
    mol_type: Option<String>,
    #[serde(default)]
    wisp_type: Option<String>,
}

#[derive(Deserialize)]
struct InDep {
    depends_on_id: String,
    #[serde(rename = "type", alias = "dep_type", default = "default_dep_type")]
    dep_type: String,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    created_at: Option<Timestamp>,
    #[serde(default)]
    created_by: Option<String>,
}

fn default_dep_type() -> String {
    "blocks".into()
}

#[derive(Deserialize)]
struct InComment {
    #[serde(default)]
    author: String,
    #[serde(alias = "body")]
    text: String,
    created_at: Option<Timestamp>,
}

#[derive(Deserialize)]
struct InMemory {
    key: String,
    #[serde(alias = "value")]
    content: String,
    #[serde(default)]
    created_at: Option<Timestamp>,
    #[serde(default)]
    updated_at: Option<Timestamp>,
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    updated_by: Option<String>,
}

/// A parsed issue line with its embedded edges and comments.
type ImportedIssue = (Issue, Vec<InDep>, Vec<InComment>);

fn object_metadata(v: Option<Value>) -> Value {
    match v {
        Some(Value::Object(m)) => Value::Object(m),
        Some(Value::String(s)) => {
            serde_json::from_str::<Value>(&s).ok().filter(Value::is_object).unwrap_or_else(empty_object)
        }
        _ => empty_object(),
    }
}

fn same_content(a: &Issue, b: &Issue) -> bool {
    let strip = |i: &Issue| {
        let mut i = i.clone();
        i.is_blocked = false;
        i.revision = 0;
        i
    };
    strip(a) == strip(b)
}

impl WriteCtx<'_> {
    /// Import a JSONL stream in this transaction (all or nothing).
    pub fn import_jsonl(&mut self, input: &mut dyn BufRead, opts: &ImportOptions) -> Result<ImportSummary> {
        let holds = self.human_holds()?;
        let mut summary = ImportSummary::default();
        let mut issues_in: Vec<ImportedIssue> = Vec::new();
        let mut memories_in: Vec<InMemory> = Vec::new();
        let now = self.now();
        let actor = self.actor().to_string();

        for (n, line) in input.lines().enumerate() {
            let line = line?;
            let lineno = n + 1;
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line).map_err(|e| Error::invalid(format!("line {lineno}: {e}")))?;
            let kind = v.get("_type").and_then(Value::as_str).unwrap_or("issue").to_string();
            match kind.as_str() {
                "header" => continue,
                "memory" => {
                    let m: InMemory =
                        serde_json::from_value(v).map_err(|e| Error::invalid(format!("line {lineno}: {e}")))?;
                    memories_in.push(m);
                }
                "issue" => {
                    let raw: InIssue =
                        serde_json::from_value(v).map_err(|e| Error::invalid(format!("line {lineno}: {e}")))?;
                    match self.convert_issue(raw, opts, &actor, now, &mut summary, lineno)? {
                        Some(entry) => issues_in.push(entry),
                        None => summary.skipped += 1,
                    }
                }
                other => {
                    summary.warnings.push(format!("line {lineno}: skipped unknown record type {other:?}"));
                    summary.skipped += 1;
                }
            }
        }

        let mut touched: BTreeSet<String> = BTreeSet::new();
        for (issue, _, _) in &issues_in {
            if !touched.insert(issue.id.clone()) {
                return Err(Error::invalid(format!("issue {} appears more than once", issue.id)));
            }
            ids::validate_explicit_id(&issue.id)?;
            match issues::get(self.conn(), &issue.id)? {
                Some(existing) if same_content(&existing, issue) => summary.unchanged += 1,
                Some(existing) => {
                    self.check_playbook_import(&existing, &issue.metadata)?;
                    self.check_gate_repo(&issue.issue_type, &issue.metadata, Some(&existing))?;
                    self.write_imported_issue(issue, true)?;
                    summary.updated += 1;
                }
                None => {
                    self.check_gate_repo(&issue.issue_type, &issue.metadata, None)?;
                    self.write_imported_issue(issue, false)?;
                    summary.created += 1;
                }
            }
        }

        for (issue, deps, _) in &issues_in {
            for d in deps {
                let dep_type = match DepType::parse(&d.dep_type) {
                    Ok(t) => t,
                    Err(e) => {
                        summary.warnings.push(format!("{}: skipped edge to {}: {e}", issue.id, d.depends_on_id));
                        continue;
                    }
                };
                if d.depends_on_id == issue.id || !ids::exists(self.conn(), &d.depends_on_id)? {
                    summary
                        .warnings
                        .push(format!("{}: skipped edge to missing/invalid target {}", issue.id, d.depends_on_id));
                    continue;
                }
                if dep_type == DepType::ParentChild {
                    if let Some(p) = graph::parent_of(self.conn(), &issue.id)? {
                        if p != d.depends_on_id {
                            summary.warnings.push(format!(
                                "{}: kept parent {p}, skipped second parent {}",
                                issue.id, d.depends_on_id
                            ));
                            continue;
                        }
                    }
                }
                let metadata = object_metadata(d.metadata.clone());
                let existing = graph::load_edge(self.conn(), &issue.id, &d.depends_on_id)?;
                if existing.as_ref().is_some_and(|e| e.dep_type == dep_type && e.metadata == metadata) {
                    continue;
                }
                self.conn()
                    .prepare_cached(
                        "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at, created_by, metadata)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(issue_id, depends_on_id) DO UPDATE SET dep_type = excluded.dep_type,
                             metadata = excluded.metadata",
                    )?
                    .execute(params![
                        issue.id,
                        d.depends_on_id,
                        dep_type,
                        d.created_at.unwrap_or(now),
                        d.created_by.clone().unwrap_or_else(|| actor.clone()),
                        metadata.to_string(),
                    ])?;
                self.emit(
                    "dep_added",
                    Some(&issue.id),
                    json!({ "target": d.depends_on_id, "type": dep_type, "metadata": metadata, "import": true }),
                )?;
                summary.dependencies += 1;
            }
        }
        let cycles = graph::find_cycles(self.conn())?;
        if let Some(c) = cycles.first() {
            return Err(Error::Cycle { path: c.clone() });
        }

        for (issue, _, comments_in) in &issues_in {
            for c in comments_in {
                let created_at = c.created_at.unwrap_or(now);
                let author = if c.author.trim().is_empty() { actor.as_str() } else { c.author.as_str() };
                let dup: bool = self
                    .conn()
                    .prepare_cached(
                        "SELECT 1 FROM comments WHERE issue_id = ?1 AND author = ?2 AND text = ?3 AND created_at = ?4",
                    )?
                    .exists(params![issue.id, author, c.text, created_at])?;
                if dup || c.text.trim().is_empty() {
                    continue;
                }
                self.conn()
                    .prepare_cached(
                        "INSERT INTO comments (issue_id, author, text, created_at) VALUES (?1, ?2, ?3, ?4)",
                    )?
                    .execute(params![issue.id, author, c.text, created_at])?;
                let cid = self.conn().last_insert_rowid();
                self.emit("commented", Some(&issue.id), json!({ "comment_id": cid, "text": c.text, "import": true }))?;
                summary.comments += 1;
            }
        }

        for m in memories_in {
            let key = memory::validate_key(&m.key)?;
            let existing = memory::get(self.conn(), &key)?;
            if existing.as_ref().is_some_and(|e| e.content == m.content) {
                continue;
            }
            self.conn()
                .prepare_cached(
                    "INSERT INTO memories (key, content, created_at, updated_at, created_by, updated_by, revision)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)
                     ON CONFLICT(key) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at,
                         updated_by = excluded.updated_by, revision = memories.revision + 1",
                )?
                .execute(params![
                    key,
                    m.content,
                    m.created_at.unwrap_or(now),
                    m.updated_at.or(m.created_at).unwrap_or(now),
                    m.created_by.clone().unwrap_or_else(|| actor.clone()),
                    m.updated_by.or(m.created_by).unwrap_or_else(|| actor.clone()),
                ])?;
            self.emit("memory_set", None, json!({ "key": key, "content": m.content, "import": true }))?;
            summary.memories += 1;
        }

        // Claims arrive without leases (leases are node-local): grant fresh
        // ones so an abandoned imported claim is eventually reclaimed.
        let ttl = config::lease_ttl(self.conn())?;
        for (issue, _, _) in &issues_in {
            if issue.status == Status::InProgress && claims::get_lease(self.conn(), &issue.id)?.is_none() {
                let holder = issue.assignee.clone().expect("in_progress has assignee");
                let seq = self.emit("lease_granted", Some(&issue.id), json!({ "reason": "import" }))?;
                claims::upsert_lease(self.conn(), &issue.id, &holder, seq, now, ttl)?;
                summary.leases_granted += 1;
            }
        }
        graph::recompute_all(self)?;
        if let Some(holds) = &holds {
            self.check_human_holds(holds)?;
        }
        Ok(summary)
    }

    fn convert_issue(
        &mut self,
        raw: InIssue,
        opts: &ImportOptions,
        actor: &str,
        now: Timestamp,
        summary: &mut ImportSummary,
        lineno: usize,
    ) -> Result<Option<ImportedIssue>> {
        let raw_status = raw.status.clone().unwrap_or_else(|| "open".into());
        if raw.is_template {
            summary.warnings.push(format!("{}: skipped beads template (proto); playbooks replace protos", raw.id));
            return Ok(None);
        }
        let mut status = match raw_status.as_str() {
            "tombstone" => return Ok(None),
            "hooked" => Status::InProgress,
            s => match Status::parse(s) {
                Ok(st) => st,
                Err(e) if !opts.lenient => return Err(Error::invalid(format!("line {lineno}: {e} (use --lenient)"))),
                Err(_) => {
                    summary.warnings.push(format!("{}: unknown status {s:?} imported as open", raw.id));
                    Status::Open
                }
            },
        };
        let issue_type = raw.issue_type.clone().unwrap_or_else(|| "task".into());
        let issue_type = match issues::validate_type(self.conn(), &issue_type) {
            Ok(t) => t,
            Err(e) if !opts.lenient => return Err(Error::invalid(format!("line {lineno}: {e} (use --lenient)"))),
            Err(_) => {
                summary.warnings.push(format!("{}: kept unknown issue type {issue_type:?}", raw.id));
                issue_type.trim().to_ascii_lowercase()
            }
        };
        let priority = raw.priority.unwrap_or(2);
        if !(0..=4).contains(&priority) {
            return Err(Error::invalid(format!("line {lineno}: priority must be 0-4 (got {priority})")));
        }
        let assignee = raw.assignee.clone().filter(|a| !a.trim().is_empty());
        if status == Status::InProgress && assignee.is_none() {
            summary.warnings.push(format!("{}: in_progress without assignee imported as open", raw.id));
            status = Status::Open;
        }
        if status == Status::InProgress && issue_type == GATE_TYPE {
            summary.warnings.push(format!("{}: a gate is never in progress; imported as open", raw.id));
            status = Status::Open;
        }
        let created_at = raw.created_at.unwrap_or(now);
        let updated_at = raw.updated_at.unwrap_or(created_at);
        let closed_at = if status == Status::Closed { Some(raw.closed_at.unwrap_or(updated_at)) } else { None };
        let close_outcome = match raw.close_outcome.as_deref() {
            Some(o) if status == Status::Closed => Some(Outcome::parse(o)?),
            _ if status == Status::Closed => Some(Outcome::Done),
            _ => None,
        };
        let title = match issues::validate_title(&raw.title) {
            Ok(t) => t,
            Err(_) if opts.lenient && !raw.title.trim().is_empty() => {
                raw.title.trim().chars().take(crate::model::MAX_TITLE_CHARS).collect()
            }
            Err(e) => return Err(Error::invalid(format!("line {lineno}: {e}"))),
        };
        let mut labels = issues::normalize_labels(&raw.labels.clone().unwrap_or_default())?;
        labels.sort();
        let mut metadata = object_metadata(raw.metadata);
        if let Some(kind) = raw.await_type.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
            let mut gate = Map::new();
            let kind = GateKind::parse(kind).map(|k| k.as_str().to_string()).unwrap_or_else(|_| kind.to_string());
            gate.insert("type".into(), json!(kind));
            if let Some(id) = raw.await_id.as_deref().filter(|s| !s.trim().is_empty()) {
                gate.insert("await_id".into(), json!(id));
            }
            if let Some(ns) = raw.timeout.filter(|ns| *ns > 0) {
                gate.insert("timeout".into(), json!(format_duration_ms((ns / 1_000_000).max(1))));
            }
            if let Some(w) = raw.waiters.as_ref().filter(|w| !w.is_empty()) {
                gate.insert("waiters".into(), json!(w));
            }
            if let Some(obj) = metadata.as_object_mut() {
                obj.entry("gate").or_insert(Value::Object(gate));
            }
        }
        let beads: Map<String, Value> = [("mol_type", &raw.mol_type), ("wisp_type", &raw.wisp_type)]
            .into_iter()
            .filter_map(|(k, v)| v.as_ref().filter(|s| !s.is_empty()).map(|s| (k.to_string(), json!(s))))
            .collect();
        if !beads.is_empty() {
            if let Some(obj) = metadata.as_object_mut() {
                obj.entry("beads").or_insert(Value::Object(beads));
            }
        }
        let issue = Issue {
            id: raw.id.trim().to_string(),
            title,
            description: raw.description,
            design: raw.design,
            acceptance_criteria: raw.acceptance_criteria,
            notes: raw.notes,
            status,
            priority: priority as u8,
            issue_type,
            assignee,
            created_by: raw.created_by.unwrap_or_else(|| actor.to_string()),
            external_ref: raw.external_ref.filter(|s| !s.trim().is_empty()),
            estimated_minutes: raw.estimated_minutes.filter(|m| *m >= 0),
            metadata,
            created_at,
            updated_at,
            started_at: raw.started_at,
            closed_at,
            close_reason: if status == Status::Closed { raw.close_reason.filter(|r| !r.is_empty()) } else { None },
            close_outcome,
            due_at: raw.due_at,
            defer_until: raw.defer_until,
            ephemeral: raw.ephemeral,
            is_blocked: false,
            revision: 0,
            labels,
        };
        Ok(Some((issue, raw.dependencies.unwrap_or_default(), raw.comments.unwrap_or_default())))
    }

    fn write_imported_issue(&mut self, issue: &Issue, exists: bool) -> Result<()> {
        let conn = self.conn();
        if exists {
            conn.prepare_cached(
                "UPDATE issues SET title = ?2, description = ?3, design = ?4, acceptance_criteria = ?5, notes = ?6,
                    status = ?7, priority = ?8, issue_type = ?9, assignee = ?10, created_by = ?11, external_ref = ?12,
                    estimated_minutes = ?13, metadata = ?14, created_at = ?15, updated_at = ?16, started_at = ?17,
                    closed_at = ?18, close_reason = ?19, close_outcome = ?20, due_at = ?21, defer_until = ?22,
                    ephemeral = ?23, revision = revision + 1
                 WHERE id = ?1",
            )?
        } else {
            conn.prepare_cached(
                "INSERT INTO issues (id, title, description, design, acceptance_criteria, notes, status, priority,
                    issue_type, assignee, created_by, external_ref, estimated_minutes, metadata, created_at, updated_at,
                    started_at, closed_at, close_reason, close_outcome, due_at, defer_until, ephemeral, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                    ?21, ?22, ?23, 1)",
            )?
        }
        .execute(params![
            issue.id,
            issue.title,
            issue.description,
            issue.design,
            issue.acceptance_criteria,
            issue.notes,
            issue.status,
            issue.priority,
            issue.issue_type,
            issue.assignee,
            issue.created_by,
            issue.external_ref,
            issue.estimated_minutes,
            issue.metadata.to_string(),
            issue.created_at,
            issue.updated_at,
            issue.started_at,
            issue.closed_at,
            issue.close_reason,
            issue.close_outcome,
            issue.due_at,
            issue.defer_until,
            issue.ephemeral as i64,
        ])?;
        conn.prepare_cached("DELETE FROM labels WHERE issue_id = ?1")?.execute([&issue.id])?;
        for l in &issue.labels {
            conn.prepare_cached("INSERT INTO labels (issue_id, label) VALUES (?1, ?2)")?.execute([&issue.id, l])?;
        }
        if exists && issue.status != Status::InProgress {
            claims::delete_lease(conn, &issue.id)?;
        } else if exists {
            let holder_ok = claims::get_lease(conn, &issue.id)?
                .is_some_and(|l| Some(l.holder.as_str()) == issue.assignee.as_deref());
            if !holder_ok {
                claims::delete_lease(conn, &issue.id)?;
            }
        }
        let snapshot = issues::snapshot(self.conn(), &issue.id)?;
        let mode = if exists { "update" } else { "create" };
        self.emit("imported", Some(&issue.id), json!({ "mode": mode, "issue": snapshot }))?;
        Ok(())
    }
}
