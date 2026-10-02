//! Human-readable rendering.

use bd_core::time::format_duration_ms;
use bd_core::{Event, Issue, IssueDetails, IssueRef, Lease, Status, Timestamp, TreeNode};
use serde_json::Value;

pub fn rel(t: Timestamp, now: Timestamp) -> String {
    let d = t.since(now);
    if d >= 0 { format!("in {}", format_duration_ms(d)) } else { format!("{} ago", format_duration_ms(-d)) }
}

pub fn issue_line(i: &Issue, now: Timestamp) -> String {
    let mut s = format!("{} {} [P{}] [{}] {}", i.status.icon(), i.id, i.priority, i.issue_type, i.title);
    if let Some(a) = &i.assignee {
        s.push_str(&format!(" @{a}"));
    }
    if i.is_blocked && !i.status.is_terminal() {
        s.push_str(" (blocked)");
    }
    if let Some(d) = i.defer_until.filter(|d| *d > now) {
        s.push_str(&format!(" (deferred until {}, {})", d, rel(d, now)));
    }
    if i.ephemeral {
        s.push_str(" (ephemeral)");
    }
    if !i.labels.is_empty() {
        s.push_str(&format!(" {{{}}}", i.labels.join(", ")));
    }
    s
}

pub fn ref_line(r: &IssueRef) -> String {
    let mut s = format!("{} {} [P{}] [{}] {}", r.status.icon(), r.id, r.priority, r.issue_type, r.title);
    if let Some(a) = &r.assignee {
        s.push_str(&format!(" @{a}"));
    }
    s
}

pub fn lease_text(l: &Lease, now: Timestamp) -> String {
    let state = if l.is_expired(now) {
        format!("EXPIRED {}", rel(l.expires_at, now))
    } else {
        format!("expires {}", rel(l.expires_at, now))
    };
    format!(
        "held by {} (token {}), {}, last heartbeat {}, renewals {}",
        l.holder,
        l.token,
        state,
        rel(l.heartbeat_at, now),
        l.renewals
    )
}

fn block(title: &str, body: &str, out: &mut Vec<String>) {
    if body.trim().is_empty() {
        return;
    }
    out.push(String::new());
    out.push(format!("{title}:"));
    for line in body.lines() {
        out.push(format!("  {line}"));
    }
}

pub fn details(d: &IssueDetails, now: Timestamp) -> Vec<String> {
    let i = &d.issue;
    let mut out = vec![format!("{} {} · {}", i.status.icon(), i.id, i.title)];
    let mut status = i.status.to_string();
    if i.is_blocked && !i.status.is_terminal() {
        status.push_str(" (blocked)");
    }
    out.push(format!(
        "  status: {status}   priority: P{}   type: {}   revision: {}",
        i.priority, i.issue_type, i.revision
    ));
    out.push(format!("  created: {} by {}   updated: {}", i.created_at, i.created_by, rel(i.updated_at, now)));
    if let Some(a) = &i.assignee {
        out.push(format!("  assignee: {a}"));
    }
    if let Some(t) = i.started_at {
        out.push(format!("  started: {t} ({})", rel(t, now)));
    }
    if let Some(t) = i.closed_at {
        let outcome = i.close_outcome.map(|o| o.to_string()).unwrap_or_else(|| "done".into());
        let reason = i.close_reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default();
        out.push(format!("  closed: {t} ({outcome}){reason}"));
    }
    if let Some(t) = i.due_at {
        out.push(format!("  due: {t} ({})", rel(t, now)));
    }
    if let Some(t) = i.defer_until {
        out.push(format!("  deferred until: {t} ({})", rel(t, now)));
    }
    if i.ephemeral {
        out.push("  ephemeral: left out of exports, deleted by `bd purge` once closed".into());
    }
    if let Some(src) = d.deferred_by.as_ref().filter(|s| **s != i.id) {
        out.push(format!("  hidden from ready: ancestor {src} is deferred"));
    }
    if !i.labels.is_empty() {
        out.push(format!("  labels: {}", i.labels.join(", ")));
    }
    if let Some(r) = &i.external_ref {
        out.push(format!("  external: {r}"));
    }
    if let Some(m) = i.estimated_minutes {
        out.push(format!("  estimate: {m}m"));
    }
    if i.metadata.as_object().is_some_and(|m| !m.is_empty()) {
        out.push(format!("  metadata: {}", i.metadata));
    }
    if let Some(p) = &d.parent {
        out.push(format!("  parent: {p}"));
    }
    if let Some(l) = &d.lease {
        out.push(format!("  lease: {}", lease_text(l, now)));
    }
    block("Description", &i.description, &mut out);
    block("Design", &i.design, &mut out);
    block("Acceptance criteria", &i.acceptance_criteria, &mut out);
    block("Notes", &i.notes, &mut out);
    if !d.blockers.is_empty() {
        out.push(String::new());
        out.push("Blocked by:".into());
        for b in &d.blockers {
            out.push(format!(
                "  - {} {} ({}): {}",
                b.id,
                b.title,
                serde_json::to_value(b.kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
                b.detail
            ));
        }
    }
    if !d.dependencies.is_empty() {
        out.push(String::new());
        out.push("Depends on:".into());
        for e in &d.dependencies {
            out.push(format!("  - [{}] {} {} {}", e.dep_type, e.status.icon(), e.id, e.title));
        }
    }
    if !d.dependents.is_empty() {
        out.push(String::new());
        out.push("Dependents:".into());
        for e in &d.dependents {
            out.push(format!("  - [{}] {} {} {}", e.dep_type, e.status.icon(), e.id, e.title));
        }
    }
    if !d.children.is_empty() {
        let done = d.children.iter().filter(|c| c.status == Status::Closed).count();
        out.push(String::new());
        out.push(format!("Children ({done}/{} closed):", d.children.len()));
        for c in &d.children {
            out.push(format!("  {}", ref_line(c)));
        }
    }
    if !d.comments.is_empty() {
        out.push(String::new());
        out.push(format!("Comments ({}):", d.comments.len()));
        for c in &d.comments {
            out.push(format!("  [{}] {}", c.author, c.created_at));
            for line in c.text.lines() {
                out.push(format!("    {line}"));
            }
        }
    }
    out
}

pub fn tree_line(n: &TreeNode) -> String {
    let indent = bd_core::graph::indent(n.depth);
    let via = n.via.as_ref().map(|v| format!("[{v}] ")).unwrap_or_default();
    let blocked = if n.is_blocked && !n.status.is_terminal() { " (blocked)" } else { "" };
    let repeated = if n.repeated { " (see above)" } else { "" };
    format!("{indent}{via}{} {} [P{}] {}{blocked}{repeated}", n.status.icon(), n.id, n.priority, n.title)
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn truncate(text: &str, max: usize) -> String {
    let one_line = text.replace('\n', " ");
    if one_line.chars().count() <= max {
        one_line
    } else {
        format!("{}…", one_line.chars().take(max).collect::<String>())
    }
}

pub fn event_summary(e: &Event) -> String {
    let d = &e.data;
    match e.op.as_str() {
        "created" => truncate(&s(&d["issue"], "title"), 60),
        "updated" => {
            let mut parts = Vec::new();
            if let Some(changes) = d.get("changes").and_then(Value::as_object) {
                for (k, v) in changes {
                    match k.as_str() {
                        "status" | "assignee" | "priority" | "issue_type" | "parent" => {
                            parts.push(format!("{k}: {} -> {}", v["old"], v["new"]));
                        }
                        "labels" => parts.push(format!("labels +{} -{}", v["added"], v["removed"])),
                        _ => parts.push(k.clone()),
                    }
                }
            }
            parts.join(", ")
        }
        "claimed" => format!("lease until {}", s(d, "expires_at")),
        "released" => {
            let reason = s(d, "reason");
            let forced = if d["forced"] == Value::Bool(true) { " (forced)" } else { "" };
            format!(
                "from {}{forced}{}",
                s(d, "previous_holder"),
                if reason.is_empty() { String::new() } else { format!(": {reason}") }
            )
        }
        "reclaimed" => format!("from {} (lease expired {})", s(d, "previous_holder"), s(d, "expired_at")),
        "closed" => {
            let reason = s(d, "reason");
            format!(
                "{}{}",
                s(d, "outcome"),
                if reason.is_empty() { String::new() } else { format!(": {}", truncate(&reason, 60)) }
            )
        }
        "reopened" => s(d, "reason"),
        "dep_added" | "dep_removed" | "dep_updated" => format!("{} -> {}", s(d, "type"), s(d, "target")),
        "commented" => truncate(&s(d, "text"), 60),
        "memory_set" | "memory_deleted" => s(d, "key"),
        "config_set" => format!("{} = {}", s(d, "key"), s(d, "value")),
        "config_unset" => s(d, "key"),
        "deleted" => truncate(&s(&d["issue"], "title"), 60),
        "imported" => s(d, "mode"),
        "pruned" => format!("deleted {} below seq {}", s(d, "deleted"), s(d, "before")),
        "lease_granted" => s(d, "reason"),
        "run_started" => format!("playbook {} ({} issues)", s(d, "playbook"), s(d, "issues")),
        "run_compacted" | "purged" => format!("removed {} issue(s)", s(d, "count")),
        "gate_escalated" => truncate(&s(d, "reason"), 80),
        "gate_updated" => format!("watching run {}", s(d, "run_id")),
        "agents_changed" => {
            let short = |k: &str| s(d, k).chars().take(12).collect::<String>();
            format!("{} set: revision {} (was {})", s(d, "harness"), short("revision"), short("previous"))
        }
        _ => {
            if d.as_object().is_some_and(|m| m.is_empty()) {
                String::new()
            } else {
                truncate(&d.to_string(), 80)
            }
        }
    }
}

pub fn event_line(e: &Event) -> String {
    let issue = e.issue_id.as_deref().unwrap_or("-");
    let summary = event_summary(e);
    let mut line = format!("#{} {} {} {} {}", e.seq, e.ts, e.actor, e.op, issue);
    if !summary.is_empty() {
        line.push_str("  ");
        line.push_str(&summary);
    }
    line
}
