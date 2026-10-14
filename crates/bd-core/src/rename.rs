//! Renaming the issue prefix: `bd rename-prefix <new> [--from <old>]`.
//!
//! Every existing issue whose id starts with `<from>-` becomes
//! `<to>-<rest>`, in one write transaction, and `issue_prefix` becomes
//! `<to>`. Only the prefix is replaced, so a dotted child id `old-abc.1`
//! becomes `new-abc.1` along with its parent. When `<to>` itself starts with
//! `<from>-` (`bd` → `bd-sync`), ids already starting with `<to>-` are kept
//! rather than prefixed twice.
//!
//! What moves: the issue row, both ends of its dependency edges (type and
//! edge metadata kept), its labels, comments, lease (holder, token and
//! expiry unchanged, so a live claim goes on under the new id), child
//! counter and the `issue_id` of its events. Revisions and `updated_at` are
//! left alone: the id change alone already fails any guard naming the old id.
//!
//! Ordering: SQLite checks primary and unique keys row by row, and foreign
//! keys are deferred to commit, so the renames must never pass through a
//! state where two issues share an id. A new id that already belongs to an
//! issue *not* being renamed refuses the whole rename. Any other collision
//! would be with an issue that is renamed too: `to-<rest>` equal to some
//! `from-<rest2>` with `rest != rest2`, so the two ids differ in length by
//! `|to| - |from|`. Renaming in order of id length (longest first when `to`
//! is longer than `from`, shortest first when it is shorter) moves the
//! clashing id out of the way before its name is taken.
//!
//! References are rewritten after the moves:
//!
//! * JSON (issue and edge metadata, event payloads): a string is replaced
//!   only when it exactly equals a renamed id (`rewrite_json`). A gate's
//!   `metadata.gate.await_id`, plain or in its `<rig>:<id>` form, is also
//!   rewritten when its id part is a renamed id or a unique partial of one,
//!   judged against the ids that existed before the rename
//!   (`rewrite_await_id`).
//! * Free text (issue text fields, comments, memories, but not event
//!   payloads, which stay as recorded): a whole token naming a renamed id,
//!   or a renamed id followed by `.` and more (`rewrite_text`). A token is
//!   a maximal run of `[A-Za-z0-9_.-]` not preceded by such a character,
//!   with trailing `.`, `-` and `_` trimmed, so `see t-1.` and `(t-1)` are
//!   rewritten while `xt-1`, or `t-10` when no such issue exists, are not.

use std::collections::HashMap;

use rusqlite::params;
use serde::Serialize;
use serde_json::{Value, json};

use crate::config;
use crate::error::{Error, Result};
use crate::ids;
use crate::store::WriteCtx;

/// What [`WriteCtx::rename_prefix`] renames.
#[derive(Clone, Debug, Default)]
pub struct RenamePrefixOptions {
    /// The new prefix, normalized like `config set issue_prefix`.
    pub to: String,
    /// The prefix of the ids to rename, matched exactly; `None` for the
    /// current `issue_prefix`.
    pub from: Option<String>,
}

/// What a rename did (or, rolled back, would do).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RenamePrefixOutcome {
    pub from: String,
    pub to: String,
    /// Issues renamed.
    pub renamed: usize,
    /// Ids starting with `<from>-` left alone because they already start
    /// with `<to>-` (when `to` extends `from`).
    pub kept: usize,
    /// Live claims (leases) moved with their issues.
    pub claims: usize,
    /// Issues and edges whose metadata named a renamed id.
    pub metadata: usize,
    /// Events whose payload named a renamed id (moved by `issue_id` or not).
    pub events: usize,
    /// Issues, comments and memories whose text named a renamed id.
    pub text: usize,
    /// Whether this call changed `issue_prefix`.
    pub prefix_set: bool,
    /// The first few renames, old id then new, in id order.
    pub examples: Vec<(String, String)>,
}

/// How many renames [`RenamePrefixOutcome::examples`] lists.
const EXAMPLES: usize = 5;
/// How many conflicting ids a refusal names.
const NAMED_CONFLICTS: usize = 5;

impl WriteCtx<'_> {
    /// Rename every issue whose id starts with `<from>-` to `<to>-<rest>`
    /// and make `to` the `issue_prefix` (see the [module](self) docs).
    /// All or nothing: a new id that belongs to an issue not renamed, or
    /// one that is not a valid id, refuses the whole rename. Needs an admin
    /// [`Policy`](crate::Policy) when one is set.
    pub fn rename_prefix(&mut self, o: &RenamePrefixOptions) -> Result<RenamePrefixOutcome> {
        if self.policy().is_some_and(|p| !p.admin) {
            return Err(Error::Unauthorized("rename-prefix needs an admin access token".into()));
        }
        let to = config::normalize_prefix(&o.to)?;
        let from = match &o.from {
            Some(f) => {
                let f = f.trim().trim_end_matches('-');
                if f.is_empty() {
                    return Err(Error::invalid("--from needs a prefix"));
                }
                ids::validate_explicit_id(f)
                    .map_err(|_| Error::invalid(format!("invalid prefix {f:?} (letters, digits, '-', '_', '.')")))?;
                f.to_string()
            }
            None => config::prefix(self.conn())?,
        };
        let mut out = RenamePrefixOutcome { from: from.clone(), to: to.clone(), ..Default::default() };
        if from == to {
            // Nothing to rename; only point `issue_prefix` at the ids' prefix
            // when it is another one (a `config_set` event, no `prefix_renamed`).
            if config::prefix(self.conn())? != to {
                config::set(self, "issue_prefix", &to)?;
                out.prefix_set = true;
            }
            return Ok(out);
        }
        let (old_dash, to_dash) = (format!("{from}-"), format!("{to}-"));

        // Every id starting with `<from>-` sorts in [`<from>-`, `<from>.`):
        // '.' follows '-', so this is a seek on the primary key, not a scan.
        let mut olds: Vec<String> = {
            let mut stmt =
                self.conn().prepare_cached("SELECT id FROM issues WHERE id >= ?1 AND id < ?2 ORDER BY id")?;
            let rows = stmt.query_map(params![old_dash, format!("{from}.")], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        olds.retain(|id| id.starts_with(&old_dash));
        // Every `<from>-` id before the rename, kept ones included, sorted:
        // what a gate's partial `await_id` resolved against.
        let before_ids = olds.clone();
        if to.starts_with(&old_dash) {
            // `bd` → `bd-sync`: `bd-sync-7` already has the new prefix.
            let before = olds.len();
            olds.retain(|id| !id.starts_with(&to_dash));
            out.kept = before - olds.len();
        }
        let map: HashMap<String, String> =
            olds.iter().map(|old| (old.clone(), format!("{to_dash}{}", &old[old_dash.len()..]))).collect();
        let mut conflicts = Vec::new();
        for old in &olds {
            let new = &map[old];
            ids::validate_explicit_id(new)
                .map_err(|_| Error::invalid(format!("cannot rename {old}: {new:?} would not be a valid issue id")))?;
            if !map.contains_key(new) && ids::exists(self.conn(), new)? {
                conflicts.push(new.as_str());
            }
        }
        if !conflicts.is_empty() {
            let named = conflicts.iter().take(NAMED_CONFLICTS).copied().collect::<Vec<_>>().join(", ");
            let more = conflicts.len().saturating_sub(NAMED_CONFLICTS);
            let more = if more > 0 { format!(" and {more} more") } else { String::new() };
            return Err(Error::invalid(format!(
                "cannot rename {from}- to {to}-: {} already belong{} to other issues ({named}{more}); nothing was renamed",
                if conflicts.len() == 1 { "1 new id".to_string() } else { format!("{} new ids", conflicts.len()) },
                if conflicts.len() == 1 { "s" } else { "" },
            )));
        }
        out.renamed = olds.len();
        out.examples = olds.iter().take(EXAMPLES).map(|old| (old.clone(), map[old].clone())).collect();

        if !olds.is_empty() {
            // Parent and child rows move one statement at a time; the foreign
            // keys are checked at commit (SQLite resets this pragma then).
            self.conn().execute_batch("PRAGMA defer_foreign_keys = ON")?;
            // No transient primary-key collision: a target that is an existing
            // id not being renamed was refused above, so a target `<to>-<r>`
            // can only equal a renamed `<from>-<r2>`, whose length differs from
            // the target's source by |to| - |from| (both are |from-| plus a
            // rest of the same length as the target's). Longest first when
            // `to` is longer, shortest first when shorter, so that id has
            // already moved away when its name is taken. With equal lengths
            // no target is a renamed id at all (`<to>-` differs from `<from>-`).
            if to.len() > from.len() {
                olds.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
            } else {
                olds.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
            }
            for old in &olds {
                out.claims += self.move_issue(old, &map[old])?;
            }
            self.rewrite_references(&from, &to, &old_dash, &before_ids, &map, &mut out)?;
        }

        out.prefix_set = config::prefix(self.conn())? != to;
        config::set(self, "issue_prefix", &to)?;
        self.emit(
            "prefix_renamed",
            None,
            json!({
                "from": out.from,
                "to": out.to,
                "renamed": out.renamed,
                "kept": out.kept,
                "claims": out.claims,
                "metadata": out.metadata,
                "events": out.events,
                "text": out.text,
            }),
        )?;
        Ok(out)
    }

    /// Move one issue's rows from `old` to `new`, every statement by an
    /// indexed key. Revisions, `updated_at` and leases' tokens and expiries
    /// stay as they are. Returns the leases moved (0 or 1).
    fn move_issue(&self, old: &str, new: &str) -> Result<usize> {
        const MOVES: &[&str] = &[
            "UPDATE issues SET id = ?2 WHERE id = ?1",
            "UPDATE dependencies SET issue_id = ?2 WHERE issue_id = ?1",
            "UPDATE dependencies SET depends_on_id = ?2 WHERE depends_on_id = ?1",
            "UPDATE labels SET issue_id = ?2 WHERE issue_id = ?1",
            "UPDATE comments SET issue_id = ?2 WHERE issue_id = ?1",
            "UPDATE child_counters SET parent_id = ?2 WHERE parent_id = ?1",
            "UPDATE events SET issue_id = ?2 WHERE issue_id = ?1",
        ];
        let conn = self.conn();
        for sql in MOVES {
            conn.prepare_cached(sql)?.execute(params![old, new])?;
        }
        Ok(conn.prepare_cached("UPDATE leases SET issue_id = ?2 WHERE issue_id = ?1")?.execute(params![old, new])?)
    }

    /// Rewrite references to renamed ids (old ids, the keys of `map`) after
    /// the moves: JSON strings in issue and edge metadata and event payloads,
    /// and whole tokens in issue text, comments and memories. Rows are
    /// prefiltered by containing `<from>-` and written only when changed.
    fn rewrite_references(
        &self,
        from: &str,
        to: &str,
        old_dash: &str,
        before: &[String],
        map: &HashMap<String, String>,
        out: &mut RenamePrefixOutcome,
    ) -> Result<()> {
        let conn = self.conn();
        let rewrite_meta = |raw: &str, gate: bool| -> Option<String> {
            let mut v: Value = serde_json::from_str(raw).ok()?;
            // From the original value, never from `rewrite_json`'s output.
            let await_id = if gate {
                v.pointer("/gate/await_id")
                    .and_then(Value::as_str)
                    .and_then(|s| rewrite_await_id(s, old_dash, before, map))
            } else {
                None
            };
            let mut changed = rewrite_json(&mut v, map);
            if let Some(new) = await_id
                && let Some(slot) = v.pointer_mut("/gate/await_id")
            {
                *slot = Value::String(new);
                changed = true;
            }
            if changed { serde_json::to_string(&v).ok() } else { None }
        };

        // Issues: metadata and the text fields.
        type IssueText = (String, [String; 5], Option<String>, String);
        let issues: Vec<IssueText> = {
            let mut stmt = conn.prepare_cached(
                "SELECT id, title, description, design, acceptance_criteria, notes, close_reason, metadata FROM issues
                 WHERE instr(metadata, ?1) > 0 OR instr(title, ?1) > 0 OR instr(description, ?1) > 0
                    OR instr(design, ?1) > 0 OR instr(acceptance_criteria, ?1) > 0 OR instr(notes, ?1) > 0
                    OR instr(close_reason, ?1) > 0",
            )?;
            let rows = stmt.query_map([old_dash], |r| {
                Ok((r.get(0)?, [r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?], r.get(6)?, r.get(7)?))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, mut fields, mut close_reason, metadata) in issues {
            let mut text_changed = false;
            for f in fields.iter_mut() {
                if let Some(new) = rewrite_text(f, from, to, map) {
                    *f = new;
                    text_changed = true;
                }
            }
            if let Some(new) = close_reason.as_deref().and_then(|c| rewrite_text(c, from, to, map)) {
                close_reason = Some(new);
                text_changed = true;
            }
            let new_meta = rewrite_meta(&metadata, true);
            if !text_changed && new_meta.is_none() {
                continue;
            }
            out.text += usize::from(text_changed);
            out.metadata += usize::from(new_meta.is_some());
            let [title, description, design, acceptance_criteria, notes] = fields;
            conn.prepare_cached(
                "UPDATE issues SET title = ?2, description = ?3, design = ?4, acceptance_criteria = ?5, notes = ?6,
                        close_reason = ?7, metadata = ?8
                 WHERE id = ?1",
            )?
            .execute(params![
                id,
                title,
                description,
                design,
                acceptance_criteria,
                notes,
                close_reason,
                new_meta.unwrap_or(metadata)
            ])?;
        }

        // Edge metadata.
        let edges: Vec<(String, String, String)> = {
            let mut stmt = conn.prepare_cached(
                "SELECT issue_id, depends_on_id, metadata FROM dependencies WHERE instr(metadata, ?1) > 0",
            )?;
            let rows = stmt.query_map([old_dash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (issue_id, depends_on_id, metadata) in edges {
            if let Some(new) = rewrite_meta(&metadata, false) {
                conn.prepare_cached(
                    "UPDATE dependencies SET metadata = ?3 WHERE issue_id = ?1 AND depends_on_id = ?2",
                )?
                .execute(params![issue_id, depends_on_id, new])?;
                out.metadata += 1;
            }
        }

        // Comments and memories: free text (memories keep their revision).
        let comments: Vec<(i64, String)> = {
            let mut stmt = conn.prepare_cached("SELECT id, text FROM comments WHERE instr(text, ?1) > 0")?;
            let rows = stmt.query_map([old_dash], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, text) in comments {
            if let Some(new) = rewrite_text(&text, from, to, map) {
                conn.prepare_cached("UPDATE comments SET text = ?2 WHERE id = ?1")?.execute(params![id, new])?;
                out.text += 1;
            }
        }
        let memories: Vec<(String, String)> = {
            let mut stmt = conn.prepare_cached("SELECT key, content FROM memories WHERE instr(content, ?1) > 0")?;
            let rows = stmt.query_map([old_dash], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (key, content) in memories {
            if let Some(new) = rewrite_text(&content, from, to, map) {
                conn.prepare_cached("UPDATE memories SET content = ?2 WHERE key = ?1")?.execute(params![key, new])?;
                out.text += 1;
            }
        }

        // Event payloads: exact JSON strings only, the text stays as recorded.
        let events: Vec<(i64, String)> = {
            let mut stmt = conn.prepare_cached("SELECT seq, data FROM events WHERE instr(data, ?1) > 0")?;
            let rows = stmt.query_map([old_dash], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (seq, data) in events {
            if let Some(new) = rewrite_meta(&data, false) {
                conn.prepare_cached("UPDATE events SET data = ?2 WHERE seq = ?1")?.execute(params![seq, new])?;
                out.events += 1;
            }
        }
        Ok(())
    }
}

/// A character that may appear in an issue id (and so continues a token).
fn is_id_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')
}

/// Replace every JSON string exactly equal to a key of `map` with its value,
/// at any depth. Returns whether anything changed.
pub(crate) fn rewrite_json(v: &mut Value, map: &HashMap<String, String>) -> bool {
    match v {
        Value::String(s) => match map.get(s.as_str()) {
            Some(new) => {
                *s = new.clone();
                true
            }
            None => false,
        },
        Value::Array(items) => items.iter_mut().fold(false, |changed, i| rewrite_json(i, map) | changed),
        Value::Object(fields) => fields.values_mut().fold(false, |changed, f| rewrite_json(f, map) | changed),
        _ => false,
    }
}

/// The new value of a gate's `metadata.gate.await_id` (`original`), plain
/// or in beads' cross-rig form `<rig>:<id>`, when its id part is a renamed
/// id (a key of `map`) or a unique partial of one: it starts with
/// `old_dash` and exactly one id of `before` (every `<from>-` id that
/// existed before the rename, sorted) starts with it, and that one is
/// renamed, ignoring ASCII case as `issues::resolve_id` does. `None` when
/// nothing changes (no match, an ambiguous partial, or
/// a kept id).
pub(crate) fn rewrite_await_id(
    original: &str,
    old_dash: &str,
    before: &[String],
    map: &HashMap<String, String>,
) -> Option<String> {
    let (rig, id) = match original.rsplit_once(':') {
        Some((rig, id)) => (Some(rig), id.trim()),
        None => (None, original.trim()),
    };
    let new = match map.get(id) {
        Some(new) => new,
        // Matched ignoring ASCII case, as `issues::resolve_id`'s LIKE does.
        None if starts_with_ignore_case(id, old_dash) => {
            let mut matches = before.iter().filter(|b| starts_with_ignore_case(b, id));
            let (Some(only), None) = (matches.next(), matches.next()) else { return None };
            map.get(only)?
        }
        None => return None,
    };
    Some(match rig {
        Some(rig) => format!("{rig}:{new}"),
        None => new.clone(),
    })
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Rewrite whole-token references to renamed ids in free text, replacing
/// the leading `<from>-` of each with `<to>-`. A token is rewritten when it
/// (trailing `.`, `-`, `_` trimmed), or its part before some `.`, is a key
/// of `map`. Returns the new text only if something changed.
pub(crate) fn rewrite_text(text: &str, from: &str, to: &str, map: &HashMap<String, String>) -> Option<String> {
    let needle = format!("{from}-");
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut copied = 0; // bytes of `text` already in `out`
    let mut at = 0;
    while let Some(off) = text[at..].find(&needle) {
        let start = at + off;
        if start > 0 && is_id_char(bytes[start - 1]) {
            at = start + 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_id_char(bytes[end]) {
            end += 1;
        }
        // Id characters are ASCII, so these are char boundaries.
        let candidate = text[start..end].trim_end_matches(['.', '-', '_']);
        let named = map.contains_key(candidate)
            || candidate.match_indices('.').any(|(dot, _)| map.contains_key(&candidate[..dot]));
        if named {
            out.push_str(&text[copied..start]);
            out.push_str(to);
            out.push('-');
            copied = start + needle.len();
        }
        at = end;
    }
    if copied == 0 {
        return None;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::normalize_prefix;
    use serde_json::json;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn t_map() -> HashMap<String, String> {
        map(&[("t-1", "new-1"), ("t-2", "new-2"), ("t-1.2", "new-1.2")])
    }

    fn text(s: &str, m: &HashMap<String, String>) -> Option<String> {
        rewrite_text(s, "t", "new", m)
    }

    #[test]
    fn rewrite_text_whole_tokens() {
        let m = t_map();
        assert_eq!(text("see t-1.", &m).as_deref(), Some("see new-1."));
        assert_eq!(text("t-1.2", &m).as_deref(), Some("new-1.2"));
        assert_eq!(text("(t-2)", &m).as_deref(), Some("(new-2)"));
        assert_eq!(text("t-1, t-2 and t-1-", &m).as_deref(), Some("new-1, new-2 and new-1-"));
        assert_eq!(text("blocked on t-2", &m).as_deref(), Some("blocked on new-2"));
        assert_eq!(text("ünïcode t-1 ✓", &m).as_deref(), Some("ünïcode new-1 ✓"));
        // Only the parent exists: a dotted child reference still follows it.
        let parent_only = map(&[("t-1", "new-1")]);
        assert_eq!(text("t-1.2", &parent_only).as_deref(), Some("new-1.2"));
        assert_eq!(text("t-1.2.3 done", &parent_only).as_deref(), Some("new-1.2.3 done"));
    }

    #[test]
    fn rewrite_text_leaves_look_alikes() {
        let m = t_map();
        assert_eq!(text("xt-1", &m), None);
        assert_eq!(text("t-10", &m), None);
        assert_eq!(text("bd-sync", &m), None);
        assert_eq!(text("t-1x and _t-2", &m), None);
        assert_eq!(text("", &m), None);
        assert_eq!(text("t-", &m), None);
        // Nested prefixes: a kept `bd-sync-7` is not in the map.
        let nested = map(&[("bd-1", "bd-sync-1")]);
        assert_eq!(rewrite_text("bd-sync-7 bd-1", "bd", "bd-sync", &nested).as_deref(), Some("bd-sync-7 bd-sync-1"));
    }

    #[test]
    fn rewrite_json_exact_strings_at_any_depth() {
        let m = t_map();
        let mut v = json!({
            "target": "t-2",
            "list": ["t-1", "t-1-notes", {"deep": ["t-1.2", 3, null]}],
            "note": "see t-1",
            "n": 1,
        });
        assert!(rewrite_json(&mut v, &m));
        assert_eq!(
            v,
            json!({
                "target": "new-2",
                "list": ["new-1", "t-1-notes", {"deep": ["new-1.2", 3, null]}],
                "note": "see t-1",
                "n": 1,
            })
        );
        let mut unchanged = json!({"a": "t-1-notes", "b": ["x-1", true]});
        let before = unchanged.clone();
        assert!(!rewrite_json(&mut unchanged, &m));
        assert_eq!(unchanged, before);
    }

    #[test]
    fn rewrite_await_id_cross_rig_form() {
        let m = t_map();
        let mut before: Vec<String> = m.keys().cloned().collect();
        before.sort();
        let r = |s: &str| rewrite_await_id(s, "t-", &before, &m);
        assert_eq!(r("rig:t-1").as_deref(), Some("rig:new-1"));
        assert_eq!(r("t-1").as_deref(), Some("new-1"));
        assert_eq!(r("rig:t-9"), None);
        assert_eq!(r("x-1"), None);
    }

    #[test]
    fn rewrite_await_id_unique_partial() {
        let m = map(&[("t-abc", "new-abc")]);
        let before = vec!["t-abc".to_string()];
        assert_eq!(rewrite_await_id("t-ab", "t-", &before, &m).as_deref(), Some("new-abc"));
        assert_eq!(rewrite_await_id("rig:t-ab", "t-", &before, &m).as_deref(), Some("rig:new-abc"));
        assert_eq!(rewrite_await_id("T-AB", "t-", &before, &m).as_deref(), Some("new-abc"));
        // Already ambiguous before the rename: left as it is.
        let m2 = map(&[("t-abc", "new-abc"), ("t-abd", "new-abd")]);
        let before2 = vec!["t-abc".to_string(), "t-abd".to_string()];
        assert_eq!(rewrite_await_id("t-ab", "t-", &before2, &m2), None);
        assert_eq!(rewrite_await_id("rig:t-ab", "t-", &before2, &m2), None);
        // A unique partial of a kept id stays.
        let before3 = vec!["t-abc".to_string()];
        assert_eq!(rewrite_await_id("t-ab", "t-", &before3, &HashMap::new()), None);
        // bd-sync -> bd: the exact id wins over a partial reading.
        let m4 = map(&[("bd-sync-qz", "bd-qz"), ("bd-sync-sync-q", "bd-sync-q")]);
        let before4 = vec!["bd-sync-qz".to_string(), "bd-sync-sync-q".to_string()];
        assert_eq!(rewrite_await_id("bd-sync-sync-q", "bd-sync-", &before4, &m4).as_deref(), Some("bd-sync-q"));
        // The whole metadata: the gate's await_id once, from its original value.
        let mut meta = json!({"gate": {"type": "issue", "await_id": "t-ab"}});
        let new = rewrite_await_id(meta["gate"]["await_id"].as_str().unwrap(), "t-", &before, &m);
        assert!(!rewrite_json(&mut meta, &m));
        assert_eq!(new.as_deref(), Some("new-abc"));
    }

    #[test]
    fn normalize_prefix_like_config_set() {
        assert_eq!(normalize_prefix("  New- ").unwrap(), "new");
        assert_eq!(normalize_prefix("bd-sync--").unwrap(), "bd-sync");
        assert!(normalize_prefix("-").is_err());
        assert!(normalize_prefix("a b").is_err());
        assert!(normalize_prefix("_x").is_err());
    }
}
