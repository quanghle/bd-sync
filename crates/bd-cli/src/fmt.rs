//! Human-readable rendering.

use bd_core::asof::IssueAsOf;
use bd_core::time::format_duration_ms;
use bd_core::{
    Comment, Event, Issue, IssueBrief, IssueDetails, IssueRef, Lease, NotReady, Readiness, ShowBrief, Status,
    Timestamp, TreeNode,
};
use serde_json::Value;
use std::collections::HashMap;

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

/// A brief issue on one line: `<id> P<n> <type> <status>[ @<assignee>][
/// parent:<id>][ [l1,l2]] — <title>`, the title last as it may hold anything.
pub fn brief_line(b: &IssueBrief) -> String {
    let mut s = format!("{} P{} {} {}", b.id, b.priority, b.issue_type, b.status);
    if let Some(a) = &b.assignee {
        s.push_str(&format!(" @{a}"));
    }
    if let Some(p) = &b.parent {
        s.push_str(&format!(" parent:{p}"));
    }
    if !b.labels.is_empty() {
        s.push_str(&format!(" [{}]", b.labels.join(",")));
    }
    s.push_str(" — ");
    s.push_str(&b.title);
    s
}

/// One reason an issue is not ready, as `- <text>` under `indent`, with the
/// gate on a line of its own when the reason names one.
pub fn reason_lines(r: &NotReady, id: &str, now: Timestamp, indent: &str, out: &mut Vec<String>) {
    out.push(format!("{indent}- {}", r.text(id, now)));
    if let NotReady::Blocked { gate: Some(g), .. } = r {
        out.push(format!("{indent}  gate: {g}"));
    }
}

/// `bd show --why`: `Ready: yes`, or `Not ready:` and each reason below it,
/// under `indent`.
pub fn why_lines(w: &Readiness, now: Timestamp, indent: &str) -> Vec<String> {
    if w.ready {
        return vec![format!("{indent}Ready: yes")];
    }
    let mut out = vec![format!("{indent}Not ready:")];
    let below = format!("{indent}  ");
    for r in &w.reasons {
        reason_lines(r, &w.id, now, &below, &mut out);
    }
    out
}

/// `bd show --brief`: the brief line, open blockers, the cut description and
/// the last comments, then `why` (`--why`).
pub fn show_brief(b: &ShowBrief, why: Option<&Readiness>, now: Timestamp) -> Vec<String> {
    let mut out = vec![brief_line(&b.brief)];
    if !b.blockers.is_empty() {
        out.push(format!("  blocked by: {}", b.blockers.join(", ")));
    }
    block("Description", &b.description, &mut out);
    if b.comments_total > 0 {
        out.push(String::new());
        out.push(comments_heading(b.comments.len(), b.comments_total));
        for c in &b.comments {
            comment_lines(&c.author, c.created_at, &c.text, &mut out);
        }
    }
    if let Some(w) = why {
        out.push(String::new());
        out.extend(why_lines(w, now, ""));
    }
    out
}

fn comments_heading(shown: usize, total: i64) -> String {
    if shown as i64 == total { format!("Comments ({shown}):") } else { format!("Comments ({shown} of {total}):") }
}

fn comment_lines(author: &str, at: Timestamp, text: &str, out: &mut Vec<String>) {
    out.push(format!("  [{author}] {at}"));
    for line in text.lines() {
        out.push(format!("    {line}"));
    }
}

/// Orders `issues` so each one listed with its parent (`parents[n]` is the
/// parent of `issues[n]`) follows that parent, paired with its depth below the
/// nearest unlisted ancestor. Siblings keep their order in `issues`; an empty
/// `parents` leaves every issue at depth 0.
pub fn nest<'a>(issues: &'a [Issue], parents: &[Option<String>]) -> Vec<(usize, &'a Issue)> {
    let pos: HashMap<&str, usize> = issues.iter().enumerate().map(|(n, i)| (i.id.as_str(), n)).collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); issues.len()];
    let mut roots = Vec::new();
    for n in 0..issues.len() {
        match parents.get(n).and_then(|p| p.as_deref()).and_then(|p| pos.get(p)) {
            Some(&p) if p != n => children[p].push(n),
            _ => roots.push(n),
        }
    }
    let mut out = Vec::with_capacity(issues.len());
    let mut seen = vec![false; issues.len()];
    let mut stack: Vec<(usize, usize)> = roots.iter().rev().map(|&n| (0, n)).collect();
    while let Some((depth, n)) = stack.pop() {
        if std::mem::replace(&mut seen[n], true) {
            continue;
        }
        out.push((depth, &issues[n]));
        stack.extend(children[n].iter().rev().map(|&c| (depth + 1, c)));
    }
    // Parent links form a forest, but never drop an issue if they did not.
    out.extend((0..issues.len()).filter(|&n| !seen[n]).map(|n| (0, &issues[n])));
    out
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

/// Titled blocks of text, each left out when empty (as in `bd show`).
pub fn text_blocks(blocks: &[(&str, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for (title, body) in blocks {
        block(title, body, &mut out);
    }
    out
}

/// `bd show`, with `comments_total` the issue's comments in all (more than
/// `d.comments` holds under `--comments-tail`) and `why` its readiness
/// (`--why`), after the status lines.
pub fn details(d: &IssueDetails, now: Timestamp, comments_total: usize, why: Option<&Readiness>) -> Vec<String> {
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
    if let Some(c) = i.metadata.get("compaction").filter(|c| c.is_object()) {
        out.push(format!(
            "  compacted: level {} at {} (original {} bytes; `bd history {} --diff` shows it)",
            c["level"],
            s(c, "compacted_at"),
            c["original_size"],
            i.id
        ));
    }
    if let Some(p) = &d.parent {
        out.push(format!("  parent: {p}"));
    }
    if let Some(l) = &d.lease {
        out.push(format!("  lease: {}", lease_text(l, now)));
    }
    if let Some(w) = why {
        out.extend(why_lines(w, now, "  "));
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
    if comments_total > 0 {
        out.push(String::new());
        out.push(comments_heading(d.comments.len(), comments_total as i64));
        for Comment { author, created_at, text, .. } in &d.comments {
            comment_lines(author, *created_at, text, &mut out);
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
        "gate_armed" => "armed".into(),
        "compacted" => format!("level {}: {} -> {} bytes", s(d, "level"), s(d, "original_size"), s(d, "size")),
        "references_renamed" => format!("references {}- -> {}-", s(d, "from"), s(d, "to")),
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

/// A value of a changed field, on one line: a string as it is, anything else as compact JSON.
fn plain(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        other => other.to_string(),
    }
}

/// Fields `bd history --diff` shows as line diffs.
const TEXT_FIELDS: [&str; 4] = ["description", "design", "acceptance_criteria", "notes"];

/// The field changes an event records (`data.changes`), indented under its
/// line: text as a line diff, labels as `+a -b`, others as `old -> new`.
pub fn event_diff(e: &Event) -> Vec<String> {
    let mut out = Vec::new();
    let Some(changes) = e.data.get("changes").and_then(Value::as_object) else { return out };
    for (k, v) in changes {
        if k == "labels" {
            let names = |side: &str, sign: char| -> Vec<String> {
                v.get(side)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|l| format!("{sign}{}", plain(l)))
                    .collect()
            };
            let mut all = names("added", '+');
            all.extend(names("removed", '-'));
            out.push(format!("    labels: {}", all.join(" ")));
        } else if TEXT_FIELDS.contains(&k.as_str()) {
            out.push(format!("    {k}:"));
            let (old, new) = (v.get("old").map(plain).unwrap_or_default(), v.get("new").map(plain).unwrap_or_default());
            out.extend(line_diff(&old, &new).into_iter().map(|l| format!("      {l}")));
        } else {
            let side = |key: &str| v.get(key).map(plain).unwrap_or_else(|| "null".into());
            out.push(format!("    {k}: {} -> {}", side("old"), side("new")));
        }
    }
    out
}

/// Above this many cells (old lines times new lines), [`line_diff`] gives up
/// on a minimal diff: the whole old text is removed and the new one added.
const MAX_DIFF_CELLS: usize = 2_000_000;

/// The lines of `old` and `new` that differ: removed ones as `-line`, added
/// ones as `+line`, and the unchanged lines between them as ` line`. Lines
/// common to both ends are left out; nothing when the texts are the same.
pub fn line_diff(old: &str, new: &str) -> Vec<String> {
    let a: Vec<&str> = if old.is_empty() { Vec::new() } else { old.lines().collect() };
    let b: Vec<&str> = if new.is_empty() { Vec::new() } else { new.lines().collect() };
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..].iter().rev().zip(b[head..].iter().rev()).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let mut out = Vec::new();
    if a.len().saturating_mul(b.len()) > MAX_DIFF_CELLS {
        out.extend(a.iter().map(|l| format!("-{l}")));
        out.extend(b.iter().map(|l| format!("+{l}")));
        return out;
    }
    // Longest common subsequence, from the ends: lcs[i][j] for a[i..] and b[j..].
    let width = b.len() + 1;
    let mut lcs = vec![0u32; (a.len() + 1) * width];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i * width + j] = if a[i] == b[j] {
                lcs[(i + 1) * width + j + 1] + 1
            } else {
                lcs[(i + 1) * width + j].max(lcs[i * width + j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            out.push(format!(" {}", a[i]));
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || lcs[(i + 1) * width + j] >= lcs[i * width + j + 1]) {
            // Removals before additions.
            out.push(format!("-{}", a[i]));
            i += 1;
        } else {
            out.push(format!("+{}", b[j]));
            j += 1;
        }
    }
    out
}

/// `bd show --as-of`: the rebuilt issue, and what could not be rebuilt.
pub fn as_of(d: &IssueAsOf) -> Vec<String> {
    let point = match (d.point.seq, d.point.time) {
        (Some(n), _) => format!("#{n}"),
        (None, Some(t)) => t.to_string(),
        (None, None) => String::new(),
    };
    let last = d.last_event.map(|n| format!("last change #{n}")).unwrap_or_else(|| "no change retained".into());
    let mut out = vec![format!("{} as of {point} ({last})", d.id)];
    if !d.exists {
        let line = match (&d.deleted, &d.created) {
            _ if d.existence_unknown() => "  may or may not have existed (see below); no values shown".to_string(),
            (Some(x), _) if d.deleted_by_then() => format!("  deleted at #{} ({})", x.seq, x.ts),
            (_, Some(c)) => format!("  did not exist yet (created #{} at {})", c.seq, c.ts),
            _ => "  did not exist".to_string(),
        };
        out.push(line);
    } else {
        let f = |k: &str| d.fields.get(k);
        let text = |k: &str| f(k).map(plain).unwrap_or_else(|| "?".into());
        out.push(format!("  title: {}", text("title")));
        out.push(format!(
            "  status: {}   priority: {}   type: {}",
            text("status"),
            f("priority").map(|p| format!("P{p}")).unwrap_or_else(|| "?".into()),
            text("issue_type")
        ));
        let optional: [(&str, &str); 6] = [
            ("assignee", "assignee"),
            ("external_ref", "external"),
            ("estimated_minutes", "estimate (minutes)"),
            ("due_at", "due"),
            ("defer_until", "deferred until"),
            ("closed_at", "closed"),
        ];
        for (key, label) in optional {
            if let Some(v) = f(key).filter(|v| !v.is_null()) {
                let mut line = format!("  {label}: {}", plain(v));
                if key == "closed_at" {
                    line.push_str(&format!(" ({})", f("close_outcome").map(plain).unwrap_or_else(|| "?".into())));
                    if let Some(r) = f("close_reason").filter(|r| !r.is_null()) {
                        line.push_str(&format!(": {}", plain(r)));
                    }
                }
                out.push(line);
            }
        }
        if f("ephemeral") == Some(&Value::Bool(true)) {
            out.push("  ephemeral".into());
        }
        if !d.labels.is_empty() {
            out.push(format!("  labels: {}", d.labels.join(", ")));
        }
        if let Some(m) = f("metadata").filter(|m| m.as_object().is_some_and(|m| !m.is_empty())) {
            out.push(format!("  metadata: {m}"));
        }
        out.extend(text_blocks(&[
            ("Description", &f("description").map(plain).unwrap_or_default()),
            ("Design", &f("design").map(plain).unwrap_or_default()),
            ("Acceptance criteria", &f("acceptance_criteria").map(plain).unwrap_or_default()),
            ("Notes", &f("notes").map(plain).unwrap_or_default()),
        ]));
        if !d.dependencies.is_empty() {
            out.push(String::new());
            out.push("Depends on:".into());
            for e in &d.dependencies {
                out.push(format!("  - [{}] {}", e.dep_type, e.target));
            }
        }
    }
    if d.incomplete || !d.unknown.is_empty() {
        out.push(String::new());
    }
    if d.incomplete {
        out.push(format!(
            "! events before #{} were recorded by an older bd, which did not record every change; values it could \
             not confirm are listed as unknown",
            d.history_complete_from
        ));
    }
    for u in &d.unknown {
        out.push(format!("! {}: not recorded ({})", u.key, u.reason.replace('\n', " ")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_diff_inserts_deletes_and_changes() {
        assert!(line_diff("a\nb", "a\nb").is_empty());
        assert_eq!(line_diff("a\nc", "a\nb\nc"), ["+b"]);
        assert_eq!(line_diff("a\nb\nc", "a\nc"), ["-b"]);
        assert_eq!(line_diff("a\nb\nc", "a\nx\nc"), ["-b", "+x"]);
        assert_eq!(line_diff("a\nb\nc\nd", "a\nx\nc\ny"), ["-b", "+x", " c", "-d", "+y"]);
        assert_eq!(line_diff("", "new\ntext"), ["+new", "+text"]);
        assert_eq!(line_diff("old", ""), ["-old"]);
    }

    #[test]
    fn line_diff_falls_back_on_large_texts() {
        let old: Vec<String> = (0..1500).map(|n| format!("old {n}")).collect();
        let new: Vec<String> = (0..1500).map(|n| format!("new {n}")).collect();
        let diff = line_diff(&old.join("\n"), &new.join("\n"));
        assert_eq!(diff.len(), 3000);
        assert!(diff[..1500].iter().all(|l| l.starts_with("-old")));
        assert!(diff[1500..].iter().all(|l| l.starts_with("+new")));
    }

    #[test]
    fn event_diffs_and_summaries() {
        let e = Event {
            seq: 9,
            tx: 9,
            ts: Timestamp(0),
            actor: "a".into(),
            op: "compacted".into(),
            issue_id: Some("t-1".into()),
            data: serde_json::json!({
                "level": 1, "original_size": 40, "size": 5,
                "changes": {
                    "description": { "old": "long\ntext", "new": "short" },
                    "priority": { "old": 2, "new": 1 },
                    "labels": { "added": ["x"], "removed": ["y"] },
                    "metadata": { "old": {}, "new": { "compaction": { "level": 1 } } },
                },
            }),
        };
        assert_eq!(event_summary(&e), "level 1: 40 -> 5 bytes");
        let diff = event_diff(&e);
        assert!(diff.contains(&"    description:".to_string()), "{diff:?}");
        assert!(diff.contains(&"      -long".to_string()) && diff.contains(&"      +short".to_string()), "{diff:?}");
        assert!(diff.contains(&"    priority: 2 -> 1".to_string()), "{diff:?}");
        assert!(diff.contains(&"    labels: +x -y".to_string()), "{diff:?}");
        assert!(diff.contains(&r#"    metadata: {} -> {"compaction":{"level":1}}"#.to_string()), "{diff:?}");
    }

    #[test]
    fn as_of_unknown_existence_shows_no_values() {
        use bd_core::asof::{PointView, Retained, Unknown};
        let mut d = IssueAsOf {
            id: "t-1".into(),
            point: PointView { seq: Some(3), time: None },
            exists: false,
            created: None,
            deleted: None,
            fields: Default::default(),
            labels: vec![],
            dependencies: vec![],
            unknown: vec![Unknown {
                key: "exists".into(),
                reason: "created or deleted without a retained event".into(),
            }],
            last_event: Some(1),
            retained_from: Retained { seq: 1, ts: None },
            history_complete_from: 1,
            incomplete: false,
        };
        let out = as_of(&d);
        assert_eq!(out[1], "  may or may not have existed (see below); no values shown");
        assert!(out.iter().any(|l| l.starts_with("! exists: ")), "{out:?}");
        d.unknown.clear();
        assert_eq!(as_of(&d)[1], "  did not exist");
    }
}
