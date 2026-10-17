//! Two-way sync between GitHub Issues and bd issues: the pure engine behind
//! `bd github status|pull|push|sync`. The CLI fetches from GitHub (through
//! `gh`), plans with the functions here, makes its GitHub writes, then
//! applies everything in one write transaction, each issue through one
//! [`WriteCtx::github_apply`] (or [`WriteCtx::github_create`] for a GitHub
//! issue new to bd), in its own savepoint.
//!
//! **Linking.** A linked bd issue has `external_ref = gh:<repo>#<n>` (the
//! repo lowercased, `host/owner/name` off the default host) and a [`Link`]
//! in `metadata.github`, written once per issue per run, merged onto the
//! Link as stored in the transaction.
//!
//! **Per-side hashes and stamps.** Each side is projected to [`Fields`]
//! (title, body, state and outcome, representable labels, priority,
//! assignee) and hashed; the Link keeps each side's hash from the last time
//! that side was synced, beside three baselines (GitHub's first assignee,
//! bd's assignee and priority). A side whose hash differs changed. A side is
//! re-stamped only when this run synced it ([`Stamp`]): a change the
//! command's direction does not carry is [`Decision::Deferred`] and never
//! stamped, so a pull never marks a pending bd edit as synced, nor a push a
//! pending GitHub edit.
//!
//! **Decisions.** One side changed: it wins in a direction that carries it.
//! Both changed (or never synced): converged sides are unchanged; otherwise
//! `--prefer` decides, and without it the fields are a conflict, left alone.
//! `newer` compares [`edit_times`], which leave out bd github's own writes:
//! the Link records when it last wrote bd (`own_local_at`) and the GitHub
//! times of its own PATCHes and comment POSTs (`own_github_at`), and a side's
//! real edit time seen while it was not stamped (`*_edit_at`).
//!
//! **Preservation.** Writes are field-wise and keep what the other side
//! cannot represent ([`pull_changes`], [`push_body`]): labels by add and
//! remove over representable values; priority only from a priority label;
//! the assignee cleared only when the mapped one was dropped; a PATCH holds
//! only the differing fields, merges `labels`, and sends `assignees` only to
//! replace or remove the first.
//!
//! **Outcomes.** A change of close outcome between two closed states is
//! applied on bd by reopening and closing again (so the open-children,
//! blocker and claim checks, events and recompute all apply), and on GitHub
//! by reopening and closing with the new `state_reason`.
//!
//! **Comments** are apart from the field decision: fetched when GitHub's
//! count differs from `comment_count`, imported in every pulling direction
//! (deduped by GitHub id in the Link's `comments` map), pushed with
//! `--comments` ending with a comment marker `<!-- bd:<id>#c<cid> -->`. A
//! fetched comment carrying the marker of a comment of the same issue is
//! adopted (mapped, never imported or posted again) in every direction, so
//! a run that crashed after posting duplicates nothing. A push-only run
//! records the stored count plus what it adopted and posted, never GitHub's,
//! so comments it did not import still differ for the next pull.
//!
//! **Issue markers.** An issue bd creates on GitHub ends with
//! `<!-- bd:<id> -->`; a listed GitHub issue whose body ends with the marker
//! of an existing, unlinked bd issue is linked to it rather than created.
//!
//! **Pull part.** [`WriteCtx::github_apply`] runs the pull changes in a
//! nested savepoint with the plan's revision guard and never a takeover or
//! `force`; any refusal there rolls back the pull part alone, and comment
//! imports and push results are still recorded.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::comments;
use crate::config;
use crate::error::{Error, Result};
use crate::issues::{self, CloseOptions};
use crate::model::{Comment, GATE_TYPE, Guard, Issue, IssuePatch, NewIssue, Outcome, Status};
use crate::store::WriteCtx;
use crate::time::Timestamp;

/// A GitHub issue as the REST API returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GithubIssue {
    pub number: u64,
    pub node_id: String,
    pub title: String,
    pub body: String,
    pub open: bool,
    pub state_reason: Option<String>,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub updated_at: Timestamp,
    pub html_url: String,
    pub comments: u64,
    pub pull_request: bool,
    /// Who opened it (`user.login`): an issue marker counts only from bd's own account.
    pub author: Option<String>,
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn bad(what: &str, why: &str) -> Error {
    Error::invalid(format!("GitHub returned an unexpected {what}: {why}"))
}

impl GithubIssue {
    /// Strict on `number`, `title`, `state` and `updated_at`; a null body is empty.
    pub fn from_json(v: &Value) -> Result<GithubIssue> {
        let number = v.get("number").and_then(Value::as_u64).ok_or_else(|| bad("issue", "no number"))?;
        let title = str_of(v, "title").ok_or_else(|| bad("issue", "no title"))?.to_string();
        let open = match str_of(v, "state") {
            Some("open") => true,
            Some("closed") => false,
            _ => return Err(bad("issue", "no state")),
        };
        let updated_at =
            Timestamp::parse_rfc3339(str_of(v, "updated_at").ok_or_else(|| bad("issue", "no updated_at"))?)?;
        let names = |key: &str, field: &str| -> Vec<String> {
            v.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().or_else(|| str_of(x, field)).map(String::from))
                .collect()
        };
        let mut assignees = names("assignees", "login");
        if assignees.is_empty()
            && let Some(a) = v.get("assignee").and_then(|a| str_of(a, "login"))
        {
            assignees.push(a.to_string());
        }
        Ok(GithubIssue {
            number,
            node_id: str_of(v, "node_id").unwrap_or_default().to_string(),
            title,
            body: str_of(v, "body").unwrap_or_default().to_string(),
            open,
            state_reason: str_of(v, "state_reason").map(String::from),
            labels: names("labels", "name"),
            assignees,
            updated_at,
            html_url: str_of(v, "html_url").unwrap_or_default().to_string(),
            comments: v.get("comments").and_then(Value::as_u64).unwrap_or(0),
            pull_request: v.get("pull_request").is_some_and(|p| !p.is_null()),
            author: v.get("user").and_then(|u| str_of(u, "login")).map(String::from),
        })
    }

    /// Closed as not planned: bd's outcome `failed`.
    pub fn failed(&self) -> bool {
        !self.open && self.state_reason.as_deref() == Some("not_planned")
    }
}

/// A comment on a GitHub issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GithubComment {
    pub id: i64,
    pub user: String,
    pub body: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub html_url: String,
}

impl GithubComment {
    pub fn from_json(v: &Value) -> Result<GithubComment> {
        let id = v.get("id").and_then(Value::as_i64).ok_or_else(|| bad("comment", "no id"))?;
        let created_at =
            Timestamp::parse_rfc3339(str_of(v, "created_at").ok_or_else(|| bad("comment", "no created_at"))?)?;
        let updated_at = str_of(v, "updated_at").map(Timestamp::parse_rfc3339).transpose()?.unwrap_or(created_at);
        Ok(GithubComment {
            id,
            user: v.get("user").and_then(|u| str_of(u, "login")).unwrap_or("ghost").to_string(),
            body: str_of(v, "body").unwrap_or_default().to_string(),
            created_at,
            updated_at,
            html_url: str_of(v, "html_url").unwrap_or_default().to_string(),
        })
    }
}

/// The workspace's `github.*` mapping config.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncConfig {
    /// `github.assignees`: (GitHub login, bd actor).
    pub assignees: Vec<(String, String)>,
    /// `github.priority_labels`: labels `<prefix>0..4` set the priority.
    pub priority_prefix: Option<String>,
}

impl SyncConfig {
    pub fn load(conn: &Connection) -> Result<SyncConfig> {
        let assignees = config::parse_assignees(&config::get_or_default(conn, "github.assignees")?)?;
        let prefix = config::get_or_default(conn, "github.priority_labels")?;
        Ok(SyncConfig { assignees, priority_prefix: Some(prefix).filter(|p| !p.is_empty()) })
    }

    /// The bd actor a GitHub login maps to (logins compare without case).
    pub fn actor_for(&self, login: &str) -> Option<&str> {
        self.assignees.iter().find(|(l, _)| l.eq_ignore_ascii_case(login)).map(|(_, a)| a.as_str())
    }

    /// The GitHub login a bd actor maps to.
    pub fn login_for(&self, actor: &str) -> Option<&str> {
        self.assignees.iter().find(|(_, a)| a == actor).map(|(l, _)| l.as_str())
    }

    fn priority_of(&self, label: &str) -> Option<u8> {
        self.priority_prefix.as_deref().and_then(|p| priority_of_label(label, p))
    }

    /// The lowest-numbered priority label among `labels`.
    fn priority_in(&self, labels: &[String]) -> Option<u8> {
        labels.iter().filter_map(|l| self.priority_of(l)).min()
    }

    /// Whether both sides can hold label `l`.
    pub fn representable(&self, l: &str) -> bool {
        github_label_ok(l) && self.bd_label_ok(l)
    }

    /// Whether bd can hold label `l` as a label: a valid bd label that is
    /// not a priority label.
    pub fn bd_label_ok(&self, l: &str) -> bool {
        issues::normalize_labels(&[l.to_string()]).is_ok_and(|v| v.len() == 1 && v[0] == l)
            && self.priority_of(l).is_none()
    }
}

/// `<prefix><0..4>`, the prefix without case.
pub fn priority_of_label(label: &str, prefix: &str) -> Option<u8> {
    let head = label.get(..prefix.len())?;
    let rest = label.get(prefix.len()..)?;
    if !head.eq_ignore_ascii_case(prefix) || rest.len() != 1 {
        return None;
    }
    rest.parse::<u8>().ok().filter(|p| *p <= 4)
}

/// GitHub refuses label names over 50 characters.
pub fn github_label_ok(l: &str) -> bool {
    !l.trim().is_empty() && l.chars().count() <= 50
}

/// CRLF as LF, trailing whitespace trimmed, a final issue-marker line removed.
pub fn normalize_body(body: &str) -> String {
    let text = body.replace("\r\n", "\n");
    let text = text.trim_end();
    if marker_of(text).is_some() {
        let cut = text.rfind('\n').map(|i| &text[..i]).unwrap_or("");
        return cut.trim_end().to_string();
    }
    text.to_string()
}

fn sorted_set(labels: impl IntoIterator<Item = String>) -> Vec<String> {
    labels.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// A side's comparable projection, used for change detection only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fields {
    pub title: String,
    pub body: String,
    pub open: bool,
    pub failed: bool,
    pub labels: Vec<String>,
    pub priority: Option<u8>,
    pub assignee: Option<String>,
}

impl Fields {
    pub fn of_github(gh: &GithubIssue, cfg: &SyncConfig) -> Fields {
        Fields {
            title: gh.title.clone(),
            body: normalize_body(&gh.body),
            open: gh.open,
            failed: gh.failed(),
            labels: sorted_set(gh.labels.iter().filter(|l| cfg.representable(l)).cloned()),
            priority: cfg.priority_in(&gh.labels),
            assignee: gh.assignees.first().map(|a| a.to_ascii_lowercase()),
        }
    }

    pub fn of_local(issue: &Issue, cfg: &SyncConfig) -> Fields {
        let open = issue.status != Status::Closed;
        Fields {
            title: issue.title.clone(),
            body: normalize_body(&issue.description),
            open,
            failed: !open && issue.close_outcome == Some(Outcome::Failed),
            labels: sorted_set(issue.labels.iter().filter(|l| cfg.representable(l)).cloned()),
            priority: cfg.priority_prefix.as_ref().map(|_| issue.priority),
            assignee: issue.assignee.clone(),
        }
    }

    pub fn hash(&self) -> String {
        let canonical = crate::agents::canonical_json(&serde_json::to_value(self).expect("fields serialize"));
        crate::agents::sha256_hex(format!("v1{canonical}").as_bytes())
    }
}

/// Which sides a write re-stamps (hash and baselines).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stamp {
    pub github: bool,
    pub local: bool,
}

impl Stamp {
    pub const BOTH: Stamp = Stamp { github: true, local: true };
    pub const NONE: Stamp = Stamp { github: false, local: false };
}

/// `metadata.github` of a linked bd issue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub repo: String,
    pub number: u64,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub updated_at: Option<Timestamp>,
    #[serde(default)]
    pub github_hash: Option<String>,
    #[serde(default)]
    pub local_hash: Option<String>,
    /// GitHub's first assignee (lowercased) when the GitHub side was last stamped.
    #[serde(default)]
    pub assignee: Option<String>,
    /// GitHub's priority label then.
    #[serde(default)]
    pub github_priority: Option<u8>,
    /// bd's assignee and priority when the bd side was last stamped.
    #[serde(default)]
    pub local_assignee: Option<String>,
    #[serde(default)]
    pub local_priority: Option<u8>,
    /// GitHub comment id -> bd comment id.
    #[serde(default)]
    pub comments: BTreeMap<String, i64>,
    #[serde(default)]
    pub comment_count: Option<u64>,
    #[serde(default)]
    pub own_local_at: Option<Timestamp>,
    #[serde(default)]
    pub own_github_at: Option<Timestamp>,
    #[serde(default)]
    pub local_edit_at: Option<Timestamp>,
    #[serde(default)]
    pub github_edit_at: Option<Timestamp>,
}

impl Link {
    pub fn new(repo: &str, number: u64) -> Link {
        Link { repo: repo.to_string(), number, ..Default::default() }
    }

    /// The Link stored in `issue`'s metadata, if any.
    pub fn of(issue: &Issue) -> Option<Link> {
        issue.metadata.get("github").and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn stamp_github(&mut self, gh: &GithubIssue, cfg: &SyncConfig) {
        self.github_hash = Some(Fields::of_github(gh, cfg).hash());
        self.assignee = gh.assignees.first().map(|a| a.to_ascii_lowercase());
        self.github_priority = cfg.priority_in(&gh.labels);
        self.github_edit_at = None;
    }

    pub fn stamp_local(&mut self, local: &Issue, cfg: &SyncConfig) {
        self.local_hash = Some(Fields::of_local(local, cfg).hash());
        self.local_assignee = local.assignee.clone();
        self.local_priority = Some(local.priority);
        self.local_edit_at = None;
    }

    pub fn touch(&mut self, gh: &GithubIssue) {
        self.node_id = gh.node_id.clone();
        self.url = gh.html_url.clone();
        self.updated_at = Some(gh.updated_at);
    }

    /// Whether `other` holds the same sync state: every field but the ones
    /// GitHub moves on its own (node_id, url, updated_at) and the edit times.
    pub fn same_sync_state(&self, other: &Link) -> bool {
        self.repo == other.repo
            && self.number == other.number
            && self.github_hash == other.github_hash
            && self.local_hash == other.local_hash
            && self.assignee == other.assignee
            && self.github_priority == other.github_priority
            && self.local_assignee == other.local_assignee
            && self.local_priority == other.local_priority
            && self.comments == other.comments
            && self.comment_count == other.comment_count
    }

    fn mapped(&self) -> BTreeSet<i64> {
        self.comments.values().copied().collect()
    }

    /// For each side not stamped by this write, note its observed edit time
    /// when it is later than bd github's own last write to that side.
    pub fn note_edit_times(&mut self, local_before: &Issue, gh_seen: &GithubIssue, stamp: Stamp) {
        if !stamp.local && self.own_local_at.is_none_or(|own| local_before.updated_at > own) {
            self.local_edit_at = Some(local_before.updated_at);
        }
        if !stamp.github && self.own_github_at.is_none_or(|own| gh_seen.updated_at > own) {
            self.github_edit_at = Some(gh_seen.updated_at);
        }
    }

    fn changed(&self, local: &Issue, gh: &GithubIssue, cfg: &SyncConfig) -> (bool, bool) {
        (
            self.local_hash.as_deref() != Some(Fields::of_local(local, cfg).hash().as_str()),
            self.github_hash.as_deref() != Some(Fields::of_github(gh, cfg).hash().as_str()),
        )
    }
}

/// Each side's last edit time, leaving out bd github's own writes: (bd, GitHub).
pub fn edit_times(local: &Issue, link: Option<&Link>, gh: &GithubIssue) -> (Timestamp, Timestamp) {
    let l = match link.and_then(|k| k.own_local_at) {
        Some(own) if local.updated_at <= own => link.and_then(|k| k.local_edit_at).unwrap_or(local.updated_at),
        _ => local.updated_at,
    };
    let g = match link.and_then(|k| k.own_github_at) {
        Some(own) if gh.updated_at <= own => link.and_then(|k| k.github_edit_at).unwrap_or(gh.updated_at),
        _ => gh.updated_at,
    };
    (l, g)
}

/// A change of the bd assignee from GitHub.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssigneeChange {
    #[default]
    Keep,
    Set(String),
    Clear,
}

/// What a pull changes on the bd issue: only fields where the sides differ.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PullChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub add_labels: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remove_labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    pub assignee: AssigneeChange,
    /// (open, failed) of GitHub when it differs from bd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<(bool, bool)>,
}

impl PullChanges {
    pub fn is_empty(&self) -> bool {
        self.fields().is_empty()
    }

    /// The names of the fields it changes.
    pub fn fields(&self) -> Vec<&'static str> {
        let mut f = Vec::new();
        if self.title.is_some() {
            f.push("title");
        }
        if self.description.is_some() {
            f.push("description");
        }
        if !self.add_labels.is_empty() || !self.remove_labels.is_empty() {
            f.push("labels");
        }
        if self.priority.is_some() {
            f.push("priority");
        }
        if self.assignee != AssigneeChange::Keep {
            f.push("assignee");
        }
        if self.state.is_some() {
            f.push("status");
        }
        f
    }
}

fn representable_labels(labels: &[String], cfg: &SyncConfig) -> BTreeSet<String> {
    labels.iter().filter(|l| cfg.representable(l)).cloned().collect()
}

/// The field-wise changes a pull makes to `local` from `gh`.
pub fn pull_changes(local: &Issue, link: Option<&Link>, gh: &GithubIssue, cfg: &SyncConfig) -> PullChanges {
    let mut c = PullChanges::default();
    if gh.title != local.title {
        c.title = Some(gh.title.clone());
    }
    let body = normalize_body(&gh.body);
    if body != normalize_body(&local.description) {
        c.description = Some(body);
    }
    let (g, l) = (representable_labels(&gh.labels, cfg), representable_labels(&local.labels, cfg));
    c.add_labels = g.difference(&l).cloned().collect();
    c.remove_labels = l.difference(&g).cloned().collect();
    if let Some(p) = cfg.priority_in(&gh.labels).filter(|p| *p != local.priority) {
        c.priority = Some(p);
    }
    let first = gh.assignees.first().map(|a| a.to_ascii_lowercase());
    let baseline = link.and_then(|k| k.assignee.clone());
    if first != baseline {
        match first.as_deref().and_then(|f| cfg.actor_for(f)) {
            Some(actor) if local.assignee.as_deref() != Some(actor) => c.assignee = AssigneeChange::Set(actor.into()),
            Some(_) => {}
            None => {
                let was = baseline.as_deref().and_then(|b| cfg.actor_for(b));
                if local.assignee.is_some() && local.assignee.as_deref() == was {
                    c.assignee = AssigneeChange::Clear;
                }
            }
        }
    }
    let (open, failed) = (local.status != Status::Closed, local.close_outcome == Some(Outcome::Failed));
    if gh.open != open || (!gh.open && gh.failed() != failed) {
        c.state = Some((gh.open, gh.failed()));
    }
    c
}

/// Whether pushing `local` changes GitHub's close outcome while both are
/// closed. GitHub applies a `state_reason` only with a change of `state`, so
/// the caller first reopens the issue (`{"state":"open"}`), then sends the
/// [`push_body`], which closes it again with the new reason.
pub fn outcome_change(local: &Issue, gh: &GithubIssue) -> bool {
    local.status == Status::Closed && !gh.open && (local.close_outcome == Some(Outcome::Failed)) != gh.failed()
}

fn reason_of(local: &Issue) -> &'static str {
    if local.close_outcome == Some(Outcome::Failed) { "not_planned" } else { "completed" }
}

/// The PATCH body that brings `gh` to `local`: only the differing fields,
/// keeping what bd cannot represent. Empty when nothing differs.
pub fn push_body(local: &Issue, link: Option<&Link>, gh: &GithubIssue, cfg: &SyncConfig) -> Map<String, Value> {
    let mut body = Map::new();
    if local.title != gh.title {
        body.insert("title".into(), json!(local.title));
    }
    let desc = normalize_body(&local.description);
    if desc != normalize_body(&gh.body) {
        let text = match marker_of(&gh.body) {
            Some(id) if desc.is_empty() => marker(&id),
            Some(id) => format!("{desc}\n\n{}", marker(&id)),
            None => desc,
        };
        body.insert("body".into(), json!(text));
    }
    let open = local.status != Status::Closed;
    if open != gh.open || outcome_change(local, gh) {
        if open {
            body.insert("state".into(), json!("open"));
        } else {
            body.insert("state".into(), json!("closed"));
            body.insert("state_reason".into(), json!(reason_of(local)));
        }
    }

    // Labels: GitHub's list, minus the representable ones bd lacks, plus
    // bd's representable ones GitHub lacks; then the priority label.
    let local_set = representable_labels(&local.labels, cfg);
    let mut labels: Vec<String> =
        gh.labels.iter().filter(|l| !cfg.representable(l) || local_set.contains(*l)).cloned().collect();
    for l in &local_set {
        if !labels.iter().any(|x| x == l) {
            labels.push(l.clone());
        }
    }
    if let Some(prefix) = &cfg.priority_prefix {
        let p = local.priority;
        let theirs = cfg.priority_in(&gh.labels);
        let had_label = theirs.is_some();
        if theirs != Some(p) && (had_label || link.and_then(|k| k.local_priority) != Some(p)) {
            labels.retain(|l| cfg.priority_of(l).is_none_or(|n| n > p));
            labels.push(format!("{prefix}{p}"));
        }
    }
    let before: BTreeSet<&String> = gh.labels.iter().collect();
    let after: BTreeSet<&String> = labels.iter().collect();
    if before != after {
        body.insert("labels".into(), json!(labels));
    }

    // Assignees: replace the first with a different mapped login, or remove
    // the first when bd unassigned the actor it mapped to.
    let first = gh.assignees.first();
    let rest: Vec<String> = gh.assignees.iter().skip(1).cloned().collect();
    match local.assignee.as_deref() {
        Some(actor) => {
            if let Some(login) = cfg.login_for(actor)
                && first.is_none_or(|f| !f.eq_ignore_ascii_case(login))
            {
                let mut list = vec![login.to_string()];
                for r in &rest {
                    if !list.iter().any(|x| x.eq_ignore_ascii_case(r)) {
                        list.push(r.clone());
                    }
                }
                body.insert("assignees".into(), json!(list));
            }
        }
        None => {
            if let Some(f) = first
                && let Some(was) = cfg.actor_for(f)
                && link.and_then(|k| k.local_assignee.as_deref()) == Some(was)
            {
                body.insert("assignees".into(), json!(rest));
            }
        }
    }
    body
}

/// The fields of a PATCH (`sent`) that GitHub's answer `after` still does
/// not reflect: changes GitHub dropped (an assignee or label without push
/// access, say). The bd side is not stamped while any remain.
pub fn unapplied(
    sent: &Map<String, Value>,
    local: &Issue,
    link: Option<&Link>,
    after: &GithubIssue,
    cfg: &SyncConfig,
) -> Vec<String> {
    let again = push_body(local, link, after, cfg);
    sent.keys().filter(|k| *k != "state_reason" && again.contains_key(*k)).cloned().collect()
}

/// The POST body creating `local` on GitHub, ending with its issue marker.
pub fn create_body(local: &Issue, cfg: &SyncConfig) -> Map<String, Value> {
    let desc = normalize_body(&local.description);
    let text = if desc.is_empty() { marker(&local.id) } else { format!("{desc}\n\n{}", marker(&local.id)) };
    let mut labels: Vec<String> = representable_labels(&local.labels, cfg).into_iter().collect();
    if let Some(prefix) = &cfg.priority_prefix {
        labels.push(format!("{prefix}{}", local.priority));
    }
    let mut body = Map::new();
    body.insert("title".into(), json!(local.title));
    body.insert("body".into(), json!(text));
    body.insert("labels".into(), json!(labels));
    if let Some(login) = local.assignee.as_deref().and_then(|a| cfg.login_for(a)) {
        body.insert("assignees".into(), json!([login]));
    }
    body
}

/// The PATCH closing a just-created issue whose bd issue is closed.
pub fn close_body(local: &Issue) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("state".into(), json!("closed"));
    body.insert("state_reason".into(), json!(reason_of(local)));
    body
}

/// `gh:<repo>#<n>`.
pub fn external_ref(repo: &str, number: u64) -> String {
    format!("gh:{}#{number}", repo.to_ascii_lowercase())
}

/// The repo and number of a `gh:<repo>#<n>` reference.
pub fn parse_external_ref(r: &str) -> Option<(String, u64)> {
    let (repo, n) = r.strip_prefix("gh:")?.rsplit_once('#')?;
    Some((repo.to_string(), n.parse().ok()?))
}

/// The issue marker ending a GitHub issue bd created: `<!-- bd:<id> -->`.
pub fn marker(id: &str) -> String {
    format!("<!-- bd:{id} -->")
}

fn final_marker(body: &str) -> Option<String> {
    let text = body.replace("\r\n", "\n");
    let last = text.trim_end().rsplit('\n').next()?.trim();
    let inner = last.strip_prefix("<!-- bd:")?.strip_suffix("-->")?.trim();
    let ok =
        !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '#'));
    ok.then(|| inner.to_string())
}

/// The bd id named by a final issue-marker line (never a comment marker).
pub fn marker_of(body: &str) -> Option<String> {
    final_marker(body).filter(|m| !m.contains('#'))
}

/// The comment marker of a bd comment posted to GitHub: `<!-- bd:<id>#c<cid> -->`.
pub fn comment_marker(issue_id: &str, comment_id: i64) -> String {
    format!("<!-- bd:{issue_id}#c{comment_id} -->")
}

/// The bd issue and comment named by a final comment-marker line.
pub fn comment_marker_of(body: &str) -> Option<(String, i64)> {
    let m = final_marker(body)?;
    let (id, c) = m.split_once("#c")?;
    Some((id.to_string(), c.parse().ok()?)).filter(|(id, _)| !id.is_empty() && !id.contains('#'))
}

/// The text of a bd comment posted to GitHub.
pub fn push_comment_body(c: &Comment) -> String {
    format!("{}\n\n— {} via bd ({})\n\n{}", c.text, c.author, c.created_at, comment_marker(&c.issue_id, c.id))
}

fn import_text(c: &GithubComment) -> String {
    format!("GitHub comment by @{} at {} ({}):\n\n{}", c.user, c.created_at, c.html_url, c.body.trim_end())
}

/// The bd issues linked to issues of `repo` (by `external_ref`), labels included.
pub fn linked(conn: &Connection, repo: &str) -> Result<Vec<Issue>> {
    let repo = repo.to_ascii_lowercase();
    let sql = format!(
        "SELECT {} FROM issues i WHERE i.external_ref >= ?1 AND i.external_ref < ?2 ORDER BY i.id",
        issues::ISSUE_COLUMNS
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([format!("gh:{repo}#"), format!("gh:{repo}$")], issues::issue_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// What the issue marker of a listed, unlinked GitHub issue names.
#[derive(Clone, Debug, PartialEq)]
pub enum MarkerMatch {
    /// No marker, or one naming no existing issue: new to bd.
    None,
    /// An existing, unlinked, syncable bd issue, with its comments.
    Link { id: String, issue: Box<Issue>, comments: Vec<Comment> },
    /// A marker that cannot link: the issue is reported as an error.
    Error(String),
}

/// Resolve the issue markers of `unlinked` GitHub issues, one result each.
/// Only a marker on an issue opened by `self_login` (the account bd writes
/// as) counts: anyone else's is ignored, so it neither links nor collides.
pub fn resolve_markers(
    conn: &Connection,
    unlinked: &[GithubIssue],
    self_login: Option<&str>,
) -> Result<Vec<MarkerMatch>> {
    let own = |g: &GithubIssue| match (g.author.as_deref(), self_login) {
        (Some(a), Some(s)) => a.eq_ignore_ascii_case(s),
        _ => false,
    };
    let markers: Vec<Option<String>> =
        unlinked.iter().map(|g| if own(g) { marker_of(&g.body) } else { None }).collect();
    let mut out = Vec::new();
    for (g, m) in unlinked.iter().zip(&markers) {
        let Some(id) = m else {
            out.push(MarkerMatch::None);
            continue;
        };
        let shared = markers.iter().filter(|x| x.as_deref() == Some(id.as_str())).count() > 1;
        let Some(issue) = issues::get(conn, id)? else {
            out.push(MarkerMatch::None);
            continue;
        };
        out.push(if shared {
            MarkerMatch::Error(format!("#{} and another GitHub issue both name {id} in their bd marker", g.number))
        } else if let Some(r) = &issue.external_ref {
            MarkerMatch::Error(format!("#{}'s marker names {id}, which is already linked to {r}", g.number))
        } else if issue.issue_type == GATE_TYPE || issue.ephemeral {
            MarkerMatch::Error(format!(
                "#{}'s marker names {id}, a gate or ephemeral issue, which is never synced",
                g.number
            ))
        } else {
            let comments = comments::list(conn, id)?;
            MarkerMatch::Link { id: id.clone(), issue: Box::new(issue), comments }
        });
    }
    Ok(out)
}

/// Who wins when both sides changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefer {
    Local,
    Github,
    Newer,
}

/// What a command carries: GitHub to bd, bd to GitHub, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Pull,
    Push,
    Both,
}

impl Direction {
    pub fn pulls(self) -> bool {
        self != Direction::Push
    }

    pub fn pushes(self) -> bool {
        self != Direction::Pull
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Pull => "pull",
            Direction::Push => "push",
            Direction::Both => "sync",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Local,
    Github,
}

/// The field decision for one linked issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Unchanged,
    /// A one-sided change the command's direction does not carry.
    Deferred {
        side: Side,
        why: String,
    },
    Pull,
    Push,
    Conflict {
        local_hash: String,
        github_hash: String,
    },
    Skip(String),
}

impl Decision {
    /// The sides a write may re-stamp (a Push's only once its PATCH succeeded).
    pub fn planned_stamp(&self) -> Stamp {
        match self {
            Decision::Unchanged | Decision::Pull | Decision::Push => Stamp::BOTH,
            _ => Stamp::NONE,
        }
    }
}

fn deferred(side: Side) -> Decision {
    let why = match side {
        Side::Local => "local change; run push",
        Side::Github => "GitHub change; run pull",
    };
    Decision::Deferred { side, why: why.into() }
}

/// Whether a pull carrying GitHub's change would overwrite the assignee or
/// priority bd changed since the link (every field, with no stamped link).
fn pull_overwrites_local(local: &Issue, link: Option<&Link>, gh: &GithubIssue, cfg: &SyncConfig) -> bool {
    let k = link.filter(|k| k.local_hash.is_some());
    let c = pull_changes(local, link, gh, cfg);
    let assignee_changed = k.is_none_or(|k| local.assignee.as_deref() != k.local_assignee.as_deref());
    let priority_changed = k.is_none_or(|k| Some(local.priority) != k.local_priority);
    (c.assignee != AssigneeChange::Keep && assignee_changed) || (c.priority.is_some() && priority_changed)
}

/// Whether a push carrying bd's change would overwrite the assignee or
/// priority GitHub changed since the link (every field, with no stamped link).
fn push_overwrites_github(local: &Issue, link: Option<&Link>, gh: &GithubIssue, cfg: &SyncConfig) -> bool {
    let k = link.filter(|k| k.github_hash.is_some());
    let body = push_body(local, link, gh, cfg);
    let first = gh.assignees.first().map(|a| a.to_ascii_lowercase());
    let theirs = cfg.priority_in(&gh.labels);
    let assignee_changed = k.is_none_or(|k| first != k.assignee);
    let priority_changed = k.is_none_or(|k| theirs != k.github_priority);
    let pushes_priority = body.get("labels").and_then(Value::as_array).is_some_and(|labels| {
        let labels: Vec<String> = labels.iter().filter_map(|l| l.as_str().map(String::from)).collect();
        cfg.priority_in(&labels) != theirs
    });
    (body.contains_key("assignees") && assignee_changed) || (pushes_priority && priority_changed)
}

/// Decide what to do with the fields of `local`, linked (or about to be)
/// to `gh`.
pub fn decide(
    local: &Issue,
    link: Option<&Link>,
    gh: &GithubIssue,
    cfg: &SyncConfig,
    dir: Direction,
    prefer: Option<Prefer>,
) -> Decision {
    if local.issue_type == GATE_TYPE || local.ephemeral {
        return Decision::Skip("gates and ephemeral issues are never synced".into());
    }
    let pull_empty = || pull_changes(local, link, gh, cfg).is_empty();
    let push_empty = || push_body(local, link, gh, cfg).is_empty();
    let conflict = || Decision::Conflict {
        local_hash: Fields::of_local(local, cfg).hash(),
        github_hash: Fields::of_github(gh, cfg).hash(),
    };
    // A side without a stamped hash (never synced, or left unstamped) changed.
    let (local_changed, github_changed) = match link {
        Some(k) => k.changed(local, gh, cfg),
        None => (true, true),
    };
    let winner = match (local_changed, github_changed) {
        (false, false) => return Decision::Unchanged,
        (false, true) if pull_empty() => return Decision::Unchanged,
        (false, true) => Side::Github,
        (true, false) if push_empty() => return Decision::Unchanged,
        (true, false) => Side::Local,
        (true, true) => {
            if pull_empty() && push_empty() {
                return Decision::Unchanged;
            }
            match prefer {
                None => return conflict(),
                Some(Prefer::Local) => Side::Local,
                Some(Prefer::Github) => Side::Github,
                Some(Prefer::Newer) => {
                    let (l, g) = edit_times(local, link, gh);
                    if g > l { Side::Github } else { Side::Local }
                }
            }
        }
    };
    match winner {
        Side::Github if !dir.pulls() => deferred(Side::Github),
        Side::Local if !dir.pushes() => deferred(Side::Local),
        // The winner has nothing to carry, so the other side's change goes,
        // unless it would overwrite a field the winner changed.
        Side::Github if pull_empty() => {
            if !dir.pushes() {
                deferred(Side::Local)
            } else if push_overwrites_github(local, link, gh, cfg) {
                conflict()
            } else {
                Decision::Push
            }
        }
        Side::Local if push_empty() => {
            if !dir.pulls() {
                deferred(Side::Github)
            } else if pull_overwrites_local(local, link, gh, cfg) {
                conflict()
            } else {
                Decision::Pull
            }
        }
        Side::Github => Decision::Pull,
        Side::Local => Decision::Push,
    }
}

/// Whether the comments of `gh` must be fetched: GitHub's count differs from
/// the one recorded at the last sync.
pub fn needs_comment_fetch(link: Option<&Link>, gh: &GithubIssue) -> bool {
    gh.comments != link.and_then(|k| k.comment_count).unwrap_or(0)
}

/// What happens to one issue's comments, apart from its field decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommentPlan {
    pub import: Vec<GithubComment>,
    /// (GitHub id, bd id) of comments bd posted before, found by their marker.
    pub adopt: Vec<(i64, i64)>,
    pub push: Vec<Comment>,
    /// GitHub's count, recorded by a pulling direction that fetched.
    pub fetched_count: Option<u64>,
}

impl CommentPlan {
    /// The `comment_count` to record: GitHub's after a pulling fetch, else
    /// the stored count plus what was adopted; plus what was posted.
    pub fn count(&self, stored: Option<u64>, pushed_ok: usize) -> u64 {
        self.fetched_count.unwrap_or(stored.unwrap_or(0) + self.adopt.len() as u64) + pushed_ok as u64
    }

    pub fn is_empty(&self) -> bool {
        self.import.is_empty() && self.adopt.is_empty() && self.push.is_empty()
    }
}

/// Plan the comments of bd issue `issue_id`: adopt fetched comments carrying
/// the marker of one of `local_comments`, import the other unknown ones in a
/// pulling direction, and push the bd comments GitHub does not have.
pub fn plan_comments(
    issue_id: &str,
    link: Option<&Link>,
    fetched: Option<&[GithubComment]>,
    local_comments: &[Comment],
    dir: Direction,
    push_comments: bool,
) -> CommentPlan {
    let mut plan = CommentPlan::default();
    let known: BTreeSet<String> = link.map(|k| k.comments.keys().cloned().collect()).unwrap_or_default();
    let mapped = link.map(Link::mapped).unwrap_or_default();
    if let Some(fetched) = fetched {
        for c in fetched.iter().filter(|c| !known.contains(&c.id.to_string())) {
            match comment_marker_of(&c.body) {
                Some((id, cid)) if id == issue_id && local_comments.iter().any(|l| l.id == cid) => {
                    plan.adopt.push((c.id, cid));
                }
                _ if dir.pulls() => plan.import.push(c.clone()),
                _ => {}
            }
        }
        if dir.pulls() {
            plan.fetched_count = Some(fetched.len() as u64);
        }
    }
    if push_comments && dir.pushes() {
        let adopted: BTreeSet<i64> = plan.adopt.iter().map(|(_, b)| *b).collect();
        plan.push =
            local_comments.iter().filter(|c| !mapped.contains(&c.id) && !adopted.contains(&c.id)).cloned().collect();
    }
    plan
}

/// Whether bd comments of an issue are not on GitHub yet (to fetch comments
/// for adoption before posting them).
pub fn has_unposted(link: Option<&Link>, local_comments: &[Comment]) -> bool {
    let mapped = link.map(Link::mapped).unwrap_or_default();
    local_comments.iter().any(|c| !mapped.contains(&c.id))
}

/// Everything one run applies to one linked bd issue.
#[derive(Clone, Debug)]
pub struct IssueApply {
    pub id: String,
    pub expected_revision: i64,
    pub repo: String,
    pub number: u64,
    pub pull: Option<PullChanges>,
    pub import: Vec<GithubComment>,
    pub adopt: Vec<(i64, i64)>,
    /// (GitHub id, bd id) of the bd comments posted.
    pub pushed_comments: Vec<(i64, i64)>,
    /// The issue as fetched, before bd's writes.
    pub github_seen: GithubIssue,
    /// The last PATCH answer, else the issue as fetched.
    pub github_after: GithubIssue,
    /// The latest GitHub time of bd's own writes this run.
    pub own_github_at: Option<Timestamp>,
    pub local_before: Issue,
    pub stamp: Stamp,
    pub comment_count: u64,
    pub set_external_ref: bool,
}

/// Why the pull part of an apply was rolled back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum PullError {
    /// The issue changed since it was read.
    Stale(String),
    Refused(String),
}

impl PullError {
    pub fn detail(&self) -> &str {
        match self {
            PullError::Stale(m) | PullError::Refused(m) => m,
        }
    }
}

/// What [`WriteCtx::github_apply`] did.
#[derive(Clone, Debug, Default)]
pub struct ApplyOutcome {
    /// The fields the pull part changed.
    pub changed: Vec<String>,
    pub notes: Vec<String>,
    pub pull_error: Option<PullError>,
    /// (GitHub id, bd id) of the comments imported.
    pub imported: Vec<(i64, i64)>,
    /// Whether `metadata.github` (or external_ref) was written.
    pub linked: bool,
}

/// Database failures, which abort a whole run; anything else is one issue's.
pub fn is_database_error(e: &Error) -> bool {
    matches!(e, Error::Sqlite(_) | Error::Io(_) | Error::Busy(_) | Error::Locked(_) | Error::Json(_))
}

/// The Link an apply leaves: `stored` merged with this run's comment ids,
/// count, stamps (as far as the pull part allowed) and times.
pub fn merged_link(
    stored: Option<&Link>,
    a: &IssueApply,
    local_after: &Issue,
    stamp: Stamp,
    imported: &[(i64, i64)],
    cfg: &SyncConfig,
) -> Link {
    let mut link = stored.cloned().unwrap_or_else(|| Link::new(&a.repo, a.number));
    link.repo = a.repo.to_ascii_lowercase();
    link.number = a.number;
    for (g, b) in imported.iter().chain(&a.adopt).chain(&a.pushed_comments) {
        link.comments.insert(g.to_string(), *b);
    }
    link.comment_count = Some(a.comment_count);
    if stamp.github {
        link.stamp_github(&a.github_after, cfg);
    }
    if stamp.local {
        link.stamp_local(local_after, cfg);
    }
    link.note_edit_times(&a.local_before, &a.github_seen, stamp);
    link.touch(&a.github_after);
    link.own_github_at = link.own_github_at.max(a.own_github_at);
    link
}

/// Whether an apply would change anything stored, judged before writing:
/// the pull part, comments to import or adopt, ids posted, a missing
/// external_ref, or a different sync state of the Link.
pub fn apply_needed(stored: Option<&Link>, a: &IssueApply, cfg: &SyncConfig) -> bool {
    if a.pull.as_ref().is_some_and(|p| !p.is_empty())
        || !a.import.is_empty()
        || !a.adopt.is_empty()
        || !a.pushed_comments.is_empty()
        || (a.set_external_ref && a.local_before.external_ref.is_none())
    {
        return true;
    }
    let merged = merged_link(stored, a, &a.local_before, a.stamp, &[], cfg);
    stored.is_none_or(|s| !merged.same_sync_state(s))
}

impl WriteCtx<'_> {
    /// Apply one run's results to linked bd issue `a.id`: the pull part (in
    /// a nested savepoint, rolled back alone on any refusal), comment
    /// imports, then one write of the merged Link.
    pub fn github_apply(&mut self, a: &IssueApply, cfg: &SyncConfig) -> Result<ApplyOutcome> {
        let mut out = ApplyOutcome::default();
        let mut dropped_assignee = false;
        let mut pulled = false;
        if let Some(p) = a.pull.as_ref().filter(|p| !p.is_empty()) {
            match self.savepoint(|tx| tx.github_pull_part(a, p)) {
                Ok((changed, dropped, notes)) => {
                    pulled = !changed.is_empty();
                    out.changed = changed;
                    dropped_assignee = dropped;
                    out.notes.extend(notes);
                }
                Err(e) if is_database_error(&e) => return Err(e),
                Err(Error::Conflict { id, field, expected, actual }) => {
                    out.pull_error = Some(PullError::Stale(format!(
                        "{id} changed since it was read (expected {field} {expected}, found {actual}); run again"
                    )));
                }
                Err(e) => out.pull_error = Some(PullError::Refused(e.to_string())),
            }
        }
        for c in &a.import {
            let bd = self.add_comment(&a.id, &import_text(c))?;
            out.imported.push((c.id, bd.id));
        }
        let current = issues::require(self.conn(), &a.id)?;
        let stored = Link::of(&current);
        let ok = out.pull_error.is_none();
        let stamp = Stamp { github: a.stamp.github && ok && !dropped_assignee, local: a.stamp.local && ok };
        let local_after = if pulled { &current } else { &a.local_before };
        let mut link = merged_link(stored.as_ref(), a, local_after, stamp, &out.imported, cfg);
        let want_ref = external_ref(&a.repo, a.number);
        let set_ref = a.set_external_ref && current.external_ref.as_deref() != Some(want_ref.as_str());
        let differs = stored.as_ref().is_none_or(|s| !link.same_sync_state(s));
        if differs || set_ref || pulled || !out.imported.is_empty() {
            link.own_local_at = Some(self.now());
            let patch = IssuePatch {
                set_metadata: vec![("github".into(), serde_json::to_value(&link)?)],
                external_ref: set_ref.then_some(Some(want_ref)),
                ..Default::default()
            };
            self.update_issue(&a.id, &patch, &Guard::default(), false)?;
            out.linked = true;
        }
        Ok(out)
    }

    /// The pull part: returns the changed fields, whether an assignee change
    /// was dropped, and notes.
    fn github_pull_part(&mut self, a: &IssueApply, p: &PullChanges) -> Result<(Vec<String>, bool, Vec<String>)> {
        let cur = issues::require(self.conn(), &a.id)?;
        let guard = Guard { if_revision: Some(a.expected_revision), ..Default::default() };
        guard.check(&cur)?;
        let mut notes = Vec::new();
        let mut dropped = false;
        let mut patch = IssuePatch {
            title: p.title.clone(),
            description: p.description.clone(),
            priority: p.priority,
            add_labels: p.add_labels.clone(),
            remove_labels: p.remove_labels.clone(),
            ..Default::default()
        };
        match &p.assignee {
            AssigneeChange::Keep => {}
            _ if cur.status == Status::InProgress => {
                dropped = true;
                notes.push(format!(
                    "assignee change from GitHub skipped: {} is in progress; it applies once the claim ends",
                    a.id
                ));
            }
            AssigneeChange::Set(actor) => patch.assignee = Some(Some(actor.clone())),
            AssigneeChange::Clear => patch.assignee = Some(None),
        }
        let mut changed: Vec<String> = Vec::new();
        if !patch.is_empty() {
            changed.extend(self.update_issue(&a.id, &patch, &guard, false)?.changed);
        }
        if let Some((open, failed)) = p.state {
            let outcome = if failed { Outcome::Failed } else { Outcome::Done };
            let reason = format!("closed on GitHub ({}#{})", a.repo, a.number);
            let close = CloseOptions { reason: Some(reason), outcome: Some(outcome), ..Default::default() };
            let now = issues::require(self.conn(), &a.id)?;
            if open {
                if now.status == Status::Closed {
                    self.reopen_issue(&a.id, Some("reopened on GitHub"), false)?;
                    changed.push("status".into());
                }
            } else if now.status != Status::Closed {
                self.close_issue(&a.id, &close)?;
                changed.push("status".into());
            } else if now.close_outcome != Some(outcome) {
                // close_outcome changes only by reopening and closing again.
                // Closed again at once: never an open child under a closed parent.
                self.reopen_issue(&a.id, Some("close outcome changed on GitHub"), true)?;
                self.close_issue(&a.id, &close)?;
                changed.push("close_outcome".into());
            }
        }
        changed.dedup();
        Ok((changed, dropped, notes))
    }

    /// Create a bd issue for GitHub issue `gh` of `repo`, with its comments,
    /// linked and stamped on both sides. Returns the issue and warnings
    /// (labels bd cannot hold).
    pub fn github_create(
        &mut self,
        repo: &str,
        gh: &GithubIssue,
        comments: Option<&[GithubComment]>,
        cfg: &SyncConfig,
    ) -> Result<(Issue, Vec<String>)> {
        let mut warnings = Vec::new();
        let mut labels = Vec::new();
        for l in &gh.labels {
            if cfg.bd_label_ok(l) {
                labels.push(l.clone());
            } else if cfg.priority_of(l).is_none() {
                warnings.push(format!("label {l:?} of #{} is not a valid bd label; left out", gh.number));
            }
        }
        let new = NewIssue {
            title: gh.title.clone(),
            description: normalize_body(&gh.body),
            issue_type: Some("task".into()),
            priority: cfg.priority_in(&gh.labels),
            assignee: gh.assignees.first().and_then(|l| cfg.actor_for(l)).map(String::from),
            labels,
            external_ref: Some(external_ref(repo, gh.number)),
            ..Default::default()
        };
        let created = self.create_issue(new)?;
        if !gh.open {
            let outcome = if gh.failed() { Outcome::Failed } else { Outcome::Done };
            let reason = format!("closed on GitHub ({repo}#{})", gh.number);
            self.close_issue(
                &created.id,
                &CloseOptions { reason: Some(reason), outcome: Some(outcome), ..Default::default() },
            )?;
        }
        let mut link = Link::new(&repo.to_ascii_lowercase(), gh.number);
        for c in comments.unwrap_or_default() {
            let bd = self.add_comment(&created.id, &import_text(c))?;
            link.comments.insert(c.id.to_string(), bd.id);
        }
        link.comment_count = Some(comments.map(|c| c.len() as u64).unwrap_or(0));
        let local = issues::require(self.conn(), &created.id)?;
        link.stamp_github(gh, cfg);
        link.stamp_local(&local, cfg);
        link.touch(gh);
        link.own_local_at = Some(self.now());
        let patch =
            IssuePatch { set_metadata: vec![("github".into(), serde_json::to_value(&link)?)], ..Default::default() };
        let out = self.update_issue(&created.id, &patch, &Guard::default(), false)?;
        Ok((out.issue, warnings))
    }

    /// Record a `github_synced` summary event of one run.
    pub fn github_synced(&mut self, summary: Value) -> Result<()> {
        self.emit("github_synced", None, summary)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
