//! Feature specs, the experimental feature `specs` (`experimental.features`).
//!
//! A spec is an issue labelled `spec` (pinned while it is in force, often
//! also `area:<name>`); its requirements are its children labelled
//! `requirement` (or `non-goal`): pinned while in force, closed by
//! `bd supersede <old> --with <new>` when they change, closed with a reason
//! when they no longer hold. `related` edges link a requirement or spec to
//! the issues and runs it came from. Specs nest: an open spec under an open
//! spec inherits its requirements in force.
//!
//! Everything here reads: the spec tree ([`show`], [`spec_views`],
//! [`render`]), the issues linked to specs ([`linked`]), drift since specs
//! were turned on ([`drift`], and its counts for `bd prime`,
//! [`unlinked_counts`]), spec parts not in the shape `bd spec` writes
//! ([`malformed`], part of drift and `bd doctor`), closed work from before then that no spec covers
//! ([`candidates`]) and the open specs ([`list`]). Lookups go by key
//! (labels by label, edges by either end, issues by id); the two listings of
//! issues by status search the ready index (`idx_issues_ready`), as
//! `bd stale` does.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use serde_json::Value;

use crate::config;
use crate::error::{Error, Result};
use crate::graph;
use crate::hierarchy;
use crate::issues;
use crate::model::{DepType, GATE_TYPE, Issue, IssueRef, Outcome, Status};
use crate::spec_edit::check_area;
use crate::time::Timestamp;

/// The experimental feature's name in `experimental.features`.
pub const FEATURE: &str = "specs";
/// The config key holding when specs were last turned on.
pub const SINCE_KEY: &str = "experimental.specs.since";
/// Nesting deeper than this is not walked (a warning says where it stopped).
pub const MAX_DEPTH: usize = 8;
/// The label of a spec issue.
pub const SPEC: &str = "spec";
/// The label of a requirement.
pub const REQUIREMENT: &str = "requirement";
/// The label of a non-goal (a requirement saying what the feature does not do).
pub const NON_GOAL: &str = "non-goal";
/// The label `bd spec none` puts on work that touches no spec.
pub const NONE: &str = "spec:none";
/// The refusal of every `bd spec` command while the feature is off.
pub const OFF: &str = "feature specs are off in this workspace (bd config set experimental.features specs)";

/// Whether the workspace has feature specs on.
pub fn is_on(conn: &Connection) -> Result<bool> {
    Ok(config::experimental(conn)?.contains(FEATURE))
}

/// [`OFF`] as an invalid-input error (exit 2) unless specs are on.
pub fn require_on(conn: &Connection) -> Result<()> {
    if is_on(conn)? { Ok(()) } else { Err(Error::invalid(OFF)) }
}

/// When specs were last turned on (`experimental.specs.since`), if known.
pub fn since(conn: &Connection) -> Result<Option<Timestamp>> {
    match config::get(conn, SINCE_KEY)? {
        Some(v) if !v.trim().is_empty() => Ok(Some(Timestamp::parse_rfc3339(&v)?)),
        _ => Ok(None),
    }
}

/// Whether `labels` mark a spec, a requirement or a non-goal: the issues
/// that make up specs themselves.
pub fn is_spec_part(labels: &[String]) -> bool {
    labels.iter().any(|l| l == SPEC || l == REQUIREMENT || l == NON_GOAL)
}

/// Issue text reaches terminals and agent context: control characters but
/// newlines and tabs, and direction controls, are dropped.
pub fn clean(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            !matches!(c,
                '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{61c}' | '\u{200e}' | '\u{200f}'
                | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The spec tree.

/// An issue as the spec tree reads it: with its parent and edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: Status,
    pub labels: Vec<String>,
    pub parent: Option<String>,
    pub created_at: Timestamp,
    /// The issues and runs it came from: its outgoing `related` edges, in id order.
    pub related: Vec<String>,
    /// What it is superseded by (its outgoing `supersedes` edges).
    pub supersedes: Vec<String>,
    pub close_reason: Option<String>,
    pub closed_at: Option<Timestamp>,
}

impl Node {
    fn has(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l == label)
    }

    pub fn is_spec(&self) -> bool {
        self.has(SPEC)
    }
}

fn is_spec(node: Option<&Node>) -> bool {
    node.is_some_and(Node::is_spec)
}

/// Where the spec tree gets its issues.
pub trait Source {
    /// The issue `id`, if it exists.
    fn node(&self, id: &str) -> Result<Option<Node>>;
    /// The ids of `id`'s children, in creation order.
    fn kids(&self, id: &str) -> Result<Vec<String>>;
}

/// A [`Source`] over a workspace, each issue read once.
pub struct DbSource<'c> {
    conn: &'c Connection,
    nodes: RefCell<HashMap<String, Option<Node>>>,
    kids: RefCell<HashMap<String, Vec<String>>>,
}

impl<'c> DbSource<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        DbSource { conn, nodes: RefCell::default(), kids: RefCell::default() }
    }

    fn node_of(&self, issue: Issue) -> Result<Node> {
        let parent = graph::parent_of(self.conn, &issue.id)?;
        let related = edges_out(self.conn, &issue.id, "related")?;
        let supersedes = edges_out(self.conn, &issue.id, "supersedes")?;
        Ok(Node {
            parent,
            related,
            supersedes,
            id: issue.id,
            title: issue.title,
            description: issue.description,
            status: issue.status,
            labels: issue.labels,
            created_at: issue.created_at,
            close_reason: issue.close_reason,
            closed_at: issue.closed_at,
        })
    }
}

impl Source for DbSource<'_> {
    fn node(&self, id: &str) -> Result<Option<Node>> {
        if let Some(n) = self.nodes.borrow().get(id) {
            return Ok(n.clone());
        }
        let node = match issues::get(self.conn, id)? {
            Some(issue) => Some(self.node_of(issue)?),
            None => None,
        };
        self.nodes.borrow_mut().insert(id.to_string(), node.clone());
        Ok(node)
    }

    fn kids(&self, id: &str) -> Result<Vec<String>> {
        if let Some(k) = self.kids.borrow().get(id) {
            return Ok(k.clone());
        }
        let cached = self.nodes.borrow().get(id).map(Option::is_some);
        let exists = match cached {
            Some(known) => known,
            None => issues::get(self.conn, id)?.is_some(),
        };
        let mut ids = Vec::new();
        if exists {
            for child in hierarchy::child_issues(self.conn, id, false)? {
                ids.push(child.id.clone());
                if !self.nodes.borrow().contains_key(&child.id) {
                    let node = self.node_of(child)?;
                    self.nodes.borrow_mut().insert(node.id.clone(), Some(node));
                }
            }
        }
        self.kids.borrow_mut().insert(id.to_string(), ids.clone());
        Ok(ids)
    }
}

/// The ids at the other end of `id`'s outgoing edges of `dep_type`, in order.
fn edges_out(conn: &Connection, id: &str, dep_type: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT depends_on_id FROM dependencies WHERE issue_id = ?1 AND dep_type = ?2 ORDER BY depends_on_id",
    )?;
    let rows = stmt.query_map(params![id, dep_type], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The ids at the other end of `id`'s incoming edges of `dep_type`, in order.
fn edges_in(conn: &Connection, id: &str, dep_type: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = ?2 ORDER BY issue_id",
    )?;
    let rows = stmt.query_map(params![id, dep_type], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The issues `id` has a `related` edge with, either direction, in id order.
fn related_of(conn: &Connection, id: &str) -> Result<Vec<String>> {
    let mut all: BTreeSet<String> = edges_out(conn, id, "related")?.into_iter().collect();
    all.extend(edges_in(conn, id, "related")?);
    Ok(all.into_iter().collect())
}

/// The ids of the issues labelled `label`, in id order.
fn labelled(conn: &Connection, label: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached("SELECT issue_id FROM labels WHERE label = ?1 ORDER BY issue_id")?;
    let rows = stmt.query_map([label], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// How many specs are open (not closed).
pub fn open_count(conn: &Connection) -> Result<usize> {
    let n: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM labels lb CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = lb.issue_id
             WHERE lb.label = ?1 AND i.status <> 'closed'",
        )?
        .query_row([SPEC], |r| r.get(0))?;
    Ok(n as usize)
}

/// A spec as its view names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpecRef {
    pub id: String,
    pub title: String,
    pub description: String,
}

/// A requirement (or non-goal) in force.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub description: String,
    /// The issues and runs it came from (its outgoing `related` edges).
    pub sources: Vec<String>,
}

/// A closed requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HistoryItem {
    #[serde(flatten)]
    pub item: Item,
    /// `superseded` (by `by`) or `removed` (for `reason`).
    pub outcome: &'static str,
    pub by: Option<String>,
    pub reason: String,
    pub closed_at: Option<Timestamp>,
}

/// The requirements in force a spec passes down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Inherited {
    pub spec: SpecRef,
    pub requirements: Vec<Item>,
    pub non_goals: Vec<Item>,
}

/// A spec: its requirements in force, non-goals, history, what it inherits
/// from the specs above it (outermost first) and its open sub-specs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpecView {
    pub spec: SpecRef,
    pub requirements: Vec<Item>,
    pub non_goals: Vec<Item>,
    pub history: Vec<HistoryItem>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub inherited: Vec<Inherited>,
    pub subspecs: Vec<SpecView>,
}

/// The spec issues `arg` names among `specs` (every issue labelled spec):
/// the one with that id, else every open spec of the area `arg`, in id order.
pub fn find_specs(specs: &[Node], arg: &str) -> Result<Vec<Node>> {
    if let Some(s) = specs.iter().find(|s| s.id == arg) {
        return Ok(vec![s.clone()]);
    }
    let area = format!("area:{arg}");
    let mut in_area: Vec<Node> = specs.iter().filter(|s| s.has(&area) && s.status != Status::Closed).cloned().collect();
    if in_area.is_empty() {
        return Err(no_spec(arg));
    }
    in_area.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(in_area)
}

fn no_spec(arg: &str) -> Error {
    Error::not_found("spec", format!("{arg} (name a spec issue's id or its area:<name> label)"))
}

/// The warning for a spec, requirement or non-goal neither pinned nor closed.
fn not_pinned(id: &str, status: Status) -> String {
    format!(
        "{id} is {status}, not pinned: pin it (bd update {id} --status pinned) or close it",
        status = status.as_str()
    )
}

/// The view of `spec` from its children: requirements and non-goals in
/// creation order, closed ones as history, a warning first for the spec
/// itself when it is neither pinned nor closed, then one for each
/// requirement or non-goal neither pinned nor closed. No errors,
/// inheritance or sub-specs yet.
pub fn spec_view(spec: &Node, children: &[Node]) -> SpecView {
    let mut reqs: Vec<&Node> = children.iter().filter(|c| c.has(REQUIREMENT) || c.has(NON_GOAL)).collect();
    reqs.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
    let item = |r: &Node| Item {
        id: r.id.clone(),
        title: clean(&r.title),
        description: clean(&r.description),
        sources: r.related.clone(),
    };
    let live: Vec<&Node> = reqs.iter().copied().filter(|r| r.status != Status::Closed).collect();
    let mut warnings = Vec::new();
    if !matches!(spec.status, Status::Pinned | Status::Closed) {
        warnings.push(not_pinned(&spec.id, spec.status));
    }
    warnings.extend(live.iter().filter(|r| r.status != Status::Pinned).map(|r| not_pinned(&r.id, r.status)));
    SpecView {
        spec: SpecRef { id: spec.id.clone(), title: clean(&spec.title), description: clean(&spec.description) },
        requirements: live.iter().filter(|r| !r.has(NON_GOAL)).map(|r| item(r)).collect(),
        non_goals: live.iter().filter(|r| r.has(NON_GOAL)).map(|r| item(r)).collect(),
        history: reqs
            .iter()
            .filter(|r| r.status == Status::Closed)
            .map(|r| {
                let by = r.supersedes.first().cloned();
                HistoryItem {
                    item: item(r),
                    outcome: if by.is_some() { "superseded" } else { "removed" },
                    by,
                    reason: clean(r.close_reason.as_deref().unwrap_or_default()),
                    closed_at: r.closed_at,
                }
            })
            .collect(),
        errors: Vec::new(),
        warnings,
        inherited: Vec::new(),
        subspecs: Vec::new(),
    }
}

/// A spec's chain of ancestor specs, nearest first, and why it stopped
/// where it did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ancestry {
    pub chain: Vec<Node>,
    /// How many open specs are above along the same walk, with no
    /// [`MAX_DEPTH`] cap; equal to `chain.len()` unless the cap was hit.
    pub depth: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// The ancestor specs of `id`. Only an open spec continues the chain: a
/// closed spec ends it with an error (an open spec under a closed one is
/// always a mistake), an issue that is not a spec or a cycle with a warning.
/// Past [`MAX_DEPTH`] the chain stops with a warning, but the walk goes on
/// only to count `depth`, recording nothing more.
pub fn ancestors(id: &str, src: &dyn Source) -> Result<Ancestry> {
    let mut up = Ancestry::default();
    let mut seen: HashSet<String> = HashSet::from([id.to_string()]);
    let mut at = id.to_string();
    let mut parent = src.node(id)?.and_then(|n| n.parent);
    let mut capped = false;
    while let Some(p) = parent {
        let issue = src.node(&p)?;
        let Some(issue) = issue.filter(Node::is_spec) else {
            if !capped {
                // Worth a warning only when it cuts a spec off: some spec above it would have passed requirements down.
                let mut above = src.node(&p)?.and_then(|n| n.parent);
                let mut n = 0;
                while let Some(a) = above.clone() {
                    if n >= MAX_DEPTH || is_spec(src.node(&a)?.as_ref()) {
                        break;
                    }
                    above = src.node(&a)?.and_then(|x| x.parent);
                    n += 1;
                }
                if let Some(a) = above
                    && is_spec(src.node(&a)?.as_ref())
                {
                    up.warnings.push(format!("{at}'s parent {p} is not a spec: spec {a} above it is not inherited"));
                }
            }
            break;
        };
        if issue.status == Status::Closed {
            // Only an open spec under a closed one is a mistake: a closed spec under a closed one was retired with it.
            if !capped && src.node(&at)?.map(|n| n.status) != Some(Status::Closed) {
                up.errors.push(format!(
                    "{at} is open but its parent spec {p} is closed, so it inherits nothing. Fix: reopen {p} if it was \
                     closed by mistake (bd reopen {p}, then bd update {p} --status pinned); close {at} if the feature \
                     was retired (its requirements and sub-specs first, deepest first); or move {at} under the spec that \
                     replaced {p} (bd update {at} --parent <spec>)."
                ));
            }
            break;
        }
        if seen.contains(&p) {
            if !capped {
                up.warnings.push(format!("{p} is its own ancestor: the chain stops there"));
            }
            break;
        }
        if !capped && up.chain.len() >= MAX_DEPTH {
            up.warnings.push(format!("{id} is nested deeper than {MAX_DEPTH} specs: nothing above {at} is inherited"));
            capped = true;
        }
        // Past the cap the walk only counts how deep `id` is, so roots can be placed shallowest first.
        seen.insert(p.clone());
        parent = issue.parent.clone();
        up.depth += 1;
        if !capped {
            up.chain.push(issue);
            at = p;
        }
    }
    Ok(up)
}

/// The children of `id` that exist, in creation order.
fn children(src: &dyn Source, id: &str) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    for k in src.kids(id)? {
        if let Some(n) = src.node(&k)? {
            out.push(n);
        }
    }
    Ok(out)
}

/// `issue`'s spec view nested with its open sub-specs (to [`MAX_DEPTH`]),
/// each given the requirements in force above it.
fn tree(
    src: &dyn Source,
    shown: &mut HashSet<String>,
    issue: &Node,
    depth: usize,
    seen: &HashSet<String>,
    inherited: Vec<Inherited>,
) -> Result<SpecView> {
    shown.insert(issue.id.clone());
    let below = children(src, &issue.id)?;
    let mut view = spec_view(issue, &below);
    let mut passed = inherited.clone();
    passed.push(Inherited {
        spec: view.spec.clone(),
        requirements: view.requirements.clone(),
        non_goals: view.non_goals.clone(),
    });
    view.inherited = inherited;
    for c in below.iter().filter(|c| c.is_spec() && c.status != Status::Closed) {
        if seen.contains(&c.id) {
            view.warnings.push(format!("{} is its own ancestor: not shown again", c.id));
        } else if depth >= MAX_DEPTH {
            view.warnings.push(format!("sub-spec {} not shown here: deeper than {MAX_DEPTH} levels", c.id));
        } else {
            let mut seen = seen.clone();
            seen.insert(c.id.clone());
            view.subspecs.push(tree(src, shown, c, depth + 1, &seen, passed.clone())?);
        }
    }
    Ok(view)
}

/// The views of the spec issues `roots`. Each nests its open sub-specs and
/// lists in `inherited` the requirements in force of the specs above it,
/// outermost first. A root shown inside an earlier root's tree is left out;
/// roots are taken shallowest first by their true depth (past
/// [`MAX_DEPTH`] too, so a root is always placed before any root its tree
/// would show), and the views kept in `roots`' order: every spec is shown
/// once.
pub fn spec_views(roots: &[Node], src: &dyn Source) -> Result<Vec<SpecView>> {
    let mut placed = Vec::with_capacity(roots.len());
    for (i, r) in roots.iter().enumerate() {
        placed.push((i, src.node(&r.id)?.unwrap_or_else(|| r.clone()), ancestors(&r.id, src)?));
    }
    placed.sort_by_key(|(_, _, up)| up.depth);
    let mut shown = HashSet::new();
    let mut views: Vec<(usize, SpecView)> = Vec::new();
    for (i, issue, up) in placed {
        if shown.contains(&issue.id) {
            continue;
        }
        let mut inherited = Vec::new();
        let mut warnings = up.warnings.clone();
        for a in up.chain.iter().rev() {
            let own = spec_view(a, &children(src, &a.id)?);
            warnings.extend(own.warnings.iter().map(|w| format!("inherited from {}: {w}", own.spec.id)));
            inherited.push(Inherited { spec: own.spec, requirements: own.requirements, non_goals: own.non_goals });
        }
        let mut view = tree(src, &mut shown, &issue, 1, &HashSet::from([issue.id.clone()]), inherited)?;
        view.errors.extend(up.errors);
        warnings.append(&mut view.warnings);
        view.warnings = warnings;
        views.push((i, view));
    }
    views.sort_by_key(|(i, _)| *i);
    Ok(views.into_iter().map(|(_, v)| v).collect())
}

/// Every issue labelled spec, of every status, in id order.
fn spec_nodes(src: &DbSource<'_>) -> Result<Vec<Node>> {
    let mut out = Vec::new();
    for id in labelled(src.conn, SPEC)? {
        if let Some(n) = src.node(&id)? {
            out.push(n);
        }
    }
    Ok(out)
}

/// The views of the specs `arg` names: a spec's id (or an id `bd show`
/// would resolve to one), or an area (every open spec labelled
/// `area:<arg>`). Not found (exit 3) when it names none; an id prefix
/// matching several issues is `bd show`'s ambiguous id error (exit 2).
pub fn show(conn: &Connection, arg: &str) -> Result<Vec<SpecView>> {
    let src = DbSource::new(conn);
    let specs = spec_nodes(&src)?;
    let roots = match find_specs(&specs, arg.trim()) {
        Ok(roots) => roots,
        Err(e) => match issues::lookup_id(conn, arg)? {
            Some(id) => match specs.iter().find(|s| s.id == id) {
                Some(s) => vec![s.clone()],
                None => return Err(e),
            },
            None => return Err(e),
        },
    };
    spec_views(&roots, &src)
}

/// `view` as Markdown, its headings starting at `level`; sub-specs one
/// level deeper, closed requirements only with `history`.
pub fn render(view: &SpecView, history: bool, level: usize) -> String {
    let h = |n: usize| "#".repeat(n.min(6));
    let mut lines: Vec<String> = vec![
        format!("{} {}{} ({})", h(level), if level > 1 { "Sub-feature: " } else { "" }, view.spec.title, view.spec.id),
        String::new(),
    ];
    if !view.spec.description.is_empty() {
        lines.push(view.spec.description.clone());
        lines.push(String::new());
    }
    for e in &view.errors {
        lines.push(format!("> Error: {e}"));
        lines.push(String::new());
    }
    for w in &view.warnings {
        lines.push(format!("> Warning: {w}"));
        lines.push(String::new());
    }
    // (heading text, the item, the spec it is inherited from)
    let section = |lines: &mut Vec<String>, title: &str, items: Vec<(String, &Item, Option<&str>)>| {
        lines.push(format!("{} {title}", h(level + 1)));
        lines.push(String::new());
        if items.is_empty() {
            lines.push("None recorded.".into());
        }
        for (head, r, from) in items {
            let mut refs = vec![r.id.clone()];
            if let Some(f) = from {
                refs.push(format!("spec {f}"));
            }
            if !r.sources.is_empty() {
                refs.push(format!("from {}", r.sources.join(", ")));
            }
            lines.push(format!("- {head} ({})", refs.join("; ")));
            if !r.description.is_empty() {
                lines.extend(
                    r.description.split('\n').map(|l| if l.is_empty() { String::new() } else { format!("  {l}") }),
                );
            }
        }
        lines.push(String::new());
    };
    section(&mut lines, "Requirements", view.requirements.iter().map(|r| (r.title.clone(), r, None)).collect());
    section(&mut lines, "Non-goals", view.non_goals.iter().map(|r| (r.title.clone(), r, None)).collect());
    // A nested view's inherited requirements are the views above it on the page: listed only at the top.
    if level == 1 {
        let mut inherited = Vec::new();
        for a in &view.inherited {
            inherited.extend(a.requirements.iter().map(|r| (r.title.clone(), r, Some(a.spec.id.as_str()))));
            inherited
                .extend(a.non_goals.iter().map(|r| (format!("Non-goal: {}", r.title), r, Some(a.spec.id.as_str()))));
        }
        if !inherited.is_empty() {
            section(&mut lines, "Inherited", inherited);
        }
    }
    if history {
        let items = view
            .history
            .iter()
            .map(|r| {
                let head = match &r.by {
                    Some(by) => format!("~~{}~~ superseded by {by}", r.item.title),
                    None => format!("~~{}~~ removed: {}", r.item.title, strip_removed(&r.reason)),
                };
                (head, &r.item, None)
            })
            .collect();
        section(&mut lines, "History", items);
    }
    for sub in &view.subspecs {
        lines.push(render(sub, history, level + 1).trim_end().to_string());
        lines.push(String::new());
    }
    format!("{}\n", lines.join("\n").trim_end())
}

/// A close reason without a leading `removed:` (any case), as History shows it.
fn strip_removed(reason: &str) -> &str {
    let prefix = "removed:";
    match reason.get(..prefix.len()) {
        Some(p) if p.eq_ignore_ascii_case(prefix) => reason[prefix.len()..].trim_start(),
        _ => reason,
    }
}

// ---------------------------------------------------------------------------
// Links, drift and candidates.

/// The issues linked to specs. Directly: those with a `related` edge
/// (either direction) to an issue labelled spec, requirement or non-goal,
/// of any status. A direct link covers the issue's whole subtree (linking a
/// feature epic covers its subtasks) and its ancestors (a playbook run's
/// link counts for the issue the run sits under). An issue labelled
/// `spec:none` counts as well, but covers only itself.
pub fn linked(conn: &Connection) -> Result<HashSet<String>> {
    let mut direct = BTreeSet::new();
    for label in [SPEC, REQUIREMENT, NON_GOAL] {
        for id in labelled(conn, label)? {
            direct.extend(related_of(conn, &id)?);
        }
    }
    let mut out = HashSet::new();
    // Down: each subtree, once.
    let mut below: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = direct.iter().cloned().collect();
    while let Some(id) = queue.pop() {
        if below.insert(id.clone()) {
            queue.extend(edges_in(conn, &id, "parent-child")?);
        }
    }
    // Up: once an issue is in, so is everything above it.
    // `above` stays closed upward, so an id already in it has its chain in:
    // each walk stops at the first ancestor already in it, which also ends
    // a (refused, but possible in a damaged database) parent cycle.
    let mut above: HashSet<String> = HashSet::new();
    for id in direct {
        let mut at = id;
        while above.insert(at.clone()) {
            match graph::parent_of(conn, &at)? {
                Some(p) => at = p,
                None => break,
            }
        }
    }
    out.extend(below);
    out.extend(above);
    out.extend(labelled(conn, NONE)?);
    Ok(out)
}

/// The `playbook.role` of the issue `id`'s metadata, if any.
fn role_of(conn: &Connection, id: &str) -> Result<Option<String>> {
    let metadata: Option<String> =
        conn.prepare_cached("SELECT metadata FROM issues WHERE id = ?1")?.query_row([id], |r| r.get(0)).optional()?;
    Ok(metadata
        .and_then(|m| serde_json::from_str::<Value>(&m).ok())
        .and_then(|m| m.pointer("/playbook/role").and_then(Value::as_str).map(str::to_string)))
}

/// Whether `issue` is of a kind that needs no spec: playbook runs, groups
/// and steps and everything below a step (review findings and their
/// follow-ups), gates, decisions, spec issues themselves, ephemeral issues,
/// work closed as failed (no behavior shipped), and work closed as a
/// duplicate or superseded (`bd duplicate`, `bd supersede`: its
/// replacement carries the work, and its link).
pub fn is_exempt(conn: &Connection, issue: &Issue) -> Result<bool> {
    Exempt::new(conn).check(issue)
}

/// [`is_exempt`] for many issues read in one transaction: each ancestor's
/// step role is read once per checker, however many issues sit under it.
struct Exempt<'c> {
    conn: &'c Connection,
    /// Whether an ancestor's `playbook.role` is `step`, by id.
    step: HashMap<String, bool>,
}

impl<'c> Exempt<'c> {
    fn new(conn: &'c Connection) -> Self {
        Exempt { conn, step: HashMap::new() }
    }

    fn check(&mut self, issue: &Issue) -> Result<bool> {
        self.check_scanned(&Scanned::from(issue))
    }

    /// [`Exempt::check`] over the fields a window scan reads.
    fn check_scanned(&mut self, issue: &Scanned) -> Result<bool> {
        if issue.metadata.pointer("/playbook/role").is_some()
            || issue.issue_type == GATE_TYPE
            || issue.issue_type == "decision"
            || issue.ephemeral
            || is_spec_part(&issue.labels)
            || issue.close_outcome == Some(Outcome::Failed)
            || replaced(self.conn, &issue.id)?
        {
            return Ok(true);
        }
        // The issue's own id can only come back as the last of a (refused)
        // parent cycle.
        for p in graph::ancestors(self.conn, &issue.id)? {
            if p == issue.id {
                break;
            }
            if self.is_step(&p)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_step(&mut self, id: &str) -> Result<bool> {
        if let Some(step) = self.step.get(id) {
            return Ok(*step);
        }
        let step = role_of(self.conn, id)?.as_deref() == Some("step");
        self.step.insert(id.to_string(), step);
        Ok(step)
    }
}

/// Whether the issue `id` was closed as a duplicate or superseded: an
/// outgoing `duplicates` or `supersedes` edge, its types bound from
/// [`DepType`] and read by source through `idx_deps_source`.
fn replaced(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM dependencies WHERE issue_id = ?1 AND dep_type IN (?2, ?3))")?
        .query_row(params![id, DepType::Duplicates.as_str(), DepType::Supersedes.as_str()], |r| r.get(0))?)
}

/// The fields of an issue that the window filter ([`Exempt`]) and the
/// printed refs use: what [`closed_between`] and [`open_created_since`]
/// read, leaving out the text fields a scan never looks at.
#[derive(Clone, Debug, PartialEq)]
struct Scanned {
    id: String,
    title: String,
    status: Status,
    priority: u8,
    issue_type: String,
    assignee: Option<String>,
    metadata: Value,
    ephemeral: bool,
    close_outcome: Option<Outcome>,
    labels: Vec<String>,
}

impl Scanned {
    /// The same ref as [`Issue::to_ref`].
    fn to_ref(&self) -> IssueRef {
        IssueRef {
            id: self.id.clone(),
            title: self.title.clone(),
            status: self.status,
            priority: self.priority,
            issue_type: self.issue_type.clone(),
            assignee: self.assignee.clone(),
        }
    }
}

impl From<&Issue> for Scanned {
    fn from(issue: &Issue) -> Self {
        Scanned {
            id: issue.id.clone(),
            title: issue.title.clone(),
            status: issue.status,
            priority: issue.priority,
            issue_type: issue.issue_type.clone(),
            assignee: issue.assignee.clone(),
            metadata: issue.metadata.clone(),
            ephemeral: issue.ephemeral,
            close_outcome: issue.close_outcome,
            labels: issue.labels.clone(),
        }
    }
}

/// The columns of a [`Scanned`] row, in [`scanned_from_row`]'s order. The
/// labels subquery is `issues::ISSUE_COLUMNS`' own; the test
/// `lean_rows_equal_full_rows` keeps the two in step.
const SCAN_COLUMNS: &str = "i.id, i.title, i.status, i.priority, i.issue_type, i.assignee, i.metadata, i.ephemeral,
    i.close_outcome,
    (SELECT json_group_array(label) FROM (SELECT label FROM labels l WHERE l.issue_id = i.id ORDER BY label))";

/// A [`SCAN_COLUMNS`] row, its metadata and labels decoded exactly as
/// `issues::issue_from_row` decodes them.
fn scanned_from_row(r: &Row<'_>) -> rusqlite::Result<Scanned> {
    let metadata: String = r.get(6)?;
    let labels: String = r.get(9)?;
    Ok(Scanned {
        id: r.get(0)?,
        title: r.get(1)?,
        status: r.get(2)?,
        priority: r.get::<_, i64>(3)? as u8,
        issue_type: r.get(4)?,
        assignee: r.get(5)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_else(|_| crate::model::empty_object()),
        ephemeral: r.get::<_, i64>(7)? != 0,
        close_outcome: r.get(8)?,
        labels: serde_json::from_str(&labels).unwrap_or_default(),
    })
}

/// Closed issues closed in `[from, to)`, in id order, reading only
/// [`SCAN_COLUMNS`].
fn closed_between(conn: &Connection, from: Timestamp, to: Timestamp) -> Result<Vec<Scanned>> {
    let sql = format!(
        "SELECT {SCAN_COLUMNS} FROM issues i INDEXED BY idx_issues_ready
         WHERE i.status = 'closed' AND i.closed_at >= ?1 AND i.closed_at < ?2 ORDER BY i.id"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![from, to], scanned_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Every status but closed as an SQL list, `'open','in_progress',...` in
/// `Status::ALL` order, so a new status joins it without editing the SQL and
/// the text (`prepare_cached`'s key) stays the same from call to call. The
/// values are `as_str`'s static identifiers, which hold no quote, never input.
fn not_closed_list() -> String {
    Status::ALL
        .iter()
        .filter(|s| **s != Status::Closed)
        .map(|s| format!("'{}'", s.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Issues not closed created at or after `since`, in id order, reading
/// only [`SCAN_COLUMNS`].
fn open_created_since(conn: &Connection, since: Timestamp) -> Result<Vec<Scanned>> {
    let sql = format!(
        "SELECT {SCAN_COLUMNS} FROM issues i INDEXED BY idx_issues_ready
         WHERE i.status IN ({}) AND i.created_at >= ?1 ORDER BY i.id",
        not_closed_list()
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([since], scanned_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Which window of [`scan_unlinked`] an issue came from.
#[derive(Clone, Copy)]
enum Window {
    /// Closed at or after `since`.
    Closed,
    /// Not closed, created at or after `since`.
    Open,
}

/// Calls `each` with every issue of the two windows since `since` (the
/// closed first, then the open, each in id order) that is neither linked
/// nor exempt: the one filter behind [`unlinked_since`] and
/// [`unlinked_counts`].
fn scan_unlinked(conn: &Connection, since: Timestamp, mut each: impl FnMut(Window, &Scanned)) -> Result<()> {
    let linked = linked(conn)?;
    let mut exempt = Exempt::new(conn);
    for (window, issues) in [
        (Window::Closed, closed_between(conn, since, Timestamp(i64::MAX))?),
        (Window::Open, open_created_since(conn, since)?),
    ] {
        for issue in issues {
            if !linked.contains(&issue.id) && !exempt.check_scanned(&issue)? {
                each(window, &issue);
            }
        }
    }
    Ok(())
}

/// Work since specs were turned on that no spec accounts for: closed at or
/// after `since` (`unlinked`), and open, created at or after it (`to_link`).
/// Both empty without `since`.
pub fn unlinked_since(conn: &Connection, since: Option<Timestamp>) -> Result<(Vec<IssueRef>, Vec<IssueRef>)> {
    let Some(since) = since else { return Ok((Vec::new(), Vec::new())) };
    let (mut closed, mut open) = (Vec::new(), Vec::new());
    scan_unlinked(conn, since, |window, issue| match window {
        Window::Closed => closed.push(issue.to_ref()),
        Window::Open => open.push(issue.to_ref()),
    })?;
    Ok((closed, open))
}

/// The lengths of [`unlinked_since`]'s two lists, without building them:
/// what `bd prime` prints. `(0, 0)` without `since`.
pub fn unlinked_counts(conn: &Connection, since: Option<Timestamp>) -> Result<(usize, usize)> {
    let Some(since) = since else { return Ok((0, 0)) };
    let (mut closed, mut open) = (0, 0);
    scan_unlinked(conn, since, |window, _| match window {
        Window::Closed => closed += 1,
        Window::Open => open += 1,
    })?;
    Ok((closed, open))
}

/// Whether the issue `id` was ever reopened: a `reopened` event in its
/// history (read by issue, through `idx_events_issue`).
fn was_reopened(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM events WHERE issue_id = ?1 AND op = 'reopened')")?
        .query_row([id], |r| r.get(0))?)
}

/// A requirement in force whose source came undone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Shaky {
    pub requirement: IssueRef,
    pub source: IssueRef,
    /// `reopened` (the source was closed, then reopened, and is not closed
    /// now) or `failed` (closed with outcome failed). A source never closed
    /// (work in progress) is not shaky.
    pub why: &'static str,
}

/// An open spec under a closed spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Orphaned {
    pub spec: IssueRef,
    pub parent: String,
}

/// What is wrong with the shape of a spec part ([`malformed`]). The
/// declaration order is the order a part's problems are listed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Problem {
    /// (a) A requirement or non-goal, not closed, whose parent is missing or not a spec.
    NotUnderSpec,
    /// (b) A spec, not closed, with no valid `area:<name>` label.
    NoArea,
    /// (c) A requirement or non-goal in force (pinned) with no `related`
    /// edge to an issue that is not itself a spec part.
    NoSource,
    /// (d) Labelled `non-goal` but not `requirement`, not closed.
    NonGoalOnly,
    /// (e) A spec, not closed, of a type other than `feature`.
    SpecType,
    /// (f) A requirement or non-goal, not closed, of a type other than `story`.
    RequirementType,
    /// (g) Labelled `spec` and also `requirement` or `non-goal`, not closed.
    SpecAndRequirement,
    /// (h) A requirement or non-goal (of any status) superseded by an issue
    /// that is not a requirement, or by one not under its own parent spec
    /// or a spec that spec was superseded by.
    SupersededElsewhere,
}

/// A spec part not in the shape `bd spec` writes, and the fix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Malformed {
    pub issue: IssueRef,
    pub problem: Problem,
    /// What is wrong and how to fix it: ids, fixed text and the issue's
    /// cleaned type only, never titles or label values.
    pub detail: String,
}

/// What `bd spec drift` reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// The start of the window (`experimental.specs.since` or `--since`).
    pub since: Option<Timestamp>,
    /// Work closed since then with no link to a spec, nor `spec:none`.
    pub unlinked: Vec<IssueRef>,
    /// Requirements and non-goals in force whose source was reopened or failed.
    pub shaky: Vec<Shaky>,
    /// Specs, requirements and non-goals neither pinned nor closed, in id
    /// order, each once.
    pub bad_status: Vec<IssueRef>,
    /// Open specs whose parent spec is closed.
    pub orphaned: Vec<Orphaned>,
    /// Spec parts not in the shape `bd spec` writes, whenever written; not
    /// gated by since ([`malformed`]).
    pub malformed: Vec<Malformed>,
    /// Open work created since then, not linked yet (not drift).
    pub to_link: Vec<IssueRef>,
}

impl Drift {
    /// How many problems: everything but `to_link` (`malformed` included).
    pub fn count(&self) -> usize {
        self.unlinked.len() + self.shaky.len() + self.bad_status.len() + self.orphaned.len() + self.malformed.len()
    }
}

/// Drift of the specs from the work since `since`.
pub fn drift(conn: &Connection, since: Option<Timestamp>) -> Result<Drift> {
    let (unlinked, to_link) = unlinked_since(conn, since)?;
    let mut shaky = Vec::new();
    let mut bad_status = Vec::new();
    let mut reqs: BTreeSet<String> = labelled(conn, REQUIREMENT)?.into_iter().collect();
    reqs.extend(labelled(conn, NON_GOAL)?);
    for id in &reqs {
        let Some(req) = issues::get(conn, id)? else { continue };
        match req.status {
            Status::Closed => {}
            Status::Pinned => {
                for src in edges_out(conn, id, "related")? {
                    let Some(source) = issues::get(conn, &src)? else { continue };
                    if is_spec_part(&source.labels) {
                        continue;
                    }
                    let why = if source.status != Status::Closed {
                        // Work in progress (never closed) is not shaky; work closed once and reopened is.
                        if !was_reopened(conn, &src)? {
                            continue;
                        }
                        "reopened"
                    } else if source.close_outcome == Some(Outcome::Failed) {
                        "failed"
                    } else {
                        continue;
                    };
                    shaky.push(Shaky { requirement: req.to_ref(), source: source.to_ref(), why });
                }
            }
            _ => bad_status.push(req.to_ref()),
        }
    }
    let mut orphaned = Vec::new();
    for id in labelled(conn, SPEC)? {
        let Some(spec) = issues::get(conn, &id)? else { continue };
        if spec.status == Status::Closed {
            continue;
        }
        if spec.status != Status::Pinned {
            bad_status.push(spec.to_ref());
        }
        if let Some(p) = graph::parent_of(conn, &id)?
            && let Some(parent) = issues::get(conn, &p)?
            && parent.status == Status::Closed
            && parent.labels.iter().any(|l| l == SPEC)
        {
            orphaned.push(Orphaned { spec: spec.to_ref(), parent: p });
        }
    }
    // String order, as the requirements' set; an issue labelled both spec and requirement once.
    bad_status.sort_by(|a, b| a.id.cmp(&b.id));
    bad_status.dedup_by(|a, b| a.id == b.id);
    let malformed = malformed(conn)?;
    Ok(Drift { since, unlinked, shaky, bad_status, orphaned, malformed, to_link })
}

// Shape: what bd spec writes.

/// The issues, parents and spec successors [`malformed`] reads, each once.
struct ShapeScan<'c> {
    conn: &'c Connection,
    issues: HashMap<String, Option<Issue>>,
    parents: HashMap<String, Option<String>>,
    successors: HashMap<String, HashSet<String>>,
}

impl<'c> ShapeScan<'c> {
    fn new(conn: &'c Connection) -> Self {
        ShapeScan { conn, issues: HashMap::new(), parents: HashMap::new(), successors: HashMap::new() }
    }

    /// The issue `id`, if it exists.
    fn issue(&mut self, id: &str) -> Result<Option<Issue>> {
        if let Some(i) = self.issues.get(id) {
            return Ok(i.clone());
        }
        let issue = issues::get(self.conn, id)?;
        self.issues.insert(id.to_string(), issue.clone());
        Ok(issue)
    }

    /// The parent of `id`, if it has one.
    fn parent(&mut self, id: &str) -> Result<Option<String>> {
        if let Some(p) = self.parents.get(id) {
            return Ok(p.clone());
        }
        let parent = graph::parent_of(self.conn, id)?;
        self.parents.insert(id.to_string(), parent.clone());
        Ok(parent)
    }

    /// Whether `id` exists and is labelled spec.
    fn is_spec(&mut self, id: &str) -> Result<bool> {
        Ok(self.issue(id)?.is_some_and(|i| has(&i.labels, SPEC)))
    }

    /// The specs the spec `spec` was superseded by, directly or through
    /// other specs (`supersedes` edges from old to new between issues
    /// labelled spec), to [`MAX_DEPTH`] steps; never `spec` itself. Empty
    /// unless `spec` exists and is labelled spec. Cycles end at specs seen.
    fn successors(&mut self, spec: &str) -> Result<HashSet<String>> {
        if let Some(s) = self.successors.get(spec) {
            return Ok(s.clone());
        }
        let mut seen: HashSet<String> = HashSet::new();
        if self.is_spec(spec)? {
            seen.insert(spec.to_string());
            let mut frontier = vec![spec.to_string()];
            for _ in 0..MAX_DEPTH {
                let mut next = Vec::new();
                for s in &frontier {
                    for t in edges_out(self.conn, s, "supersedes")? {
                        if !seen.contains(&t) && self.is_spec(&t)? {
                            seen.insert(t.clone());
                            next.push(t);
                        }
                    }
                }
                if next.is_empty() {
                    break;
                }
                frontier = next;
            }
            seen.remove(spec);
        }
        self.successors.insert(spec.to_string(), seen.clone());
        Ok(seen)
    }
}

/// Whether `labels` hold `label`.
fn has(labels: &[String], label: &str) -> bool {
    labels.iter().any(|l| l == label)
}

/// Whether `labels` mark a requirement or non-goal (and not a spec).
fn is_requirement(labels: &[String]) -> bool {
    (has(labels, REQUIREMENT) || has(labels, NON_GOAL)) && !has(labels, SPEC)
}

/// Every spec part (labelled spec, requirement or non-goal) not in the
/// shape `bd spec` writes, whenever it was written: one entry per issue
/// and [`Problem`], in id order, then [`Problem`] order. A spec is checked
/// for b, e and g only; a requirement or non-goal for a, c, d, f and h.
/// Reads only.
pub fn malformed(conn: &Connection) -> Result<Vec<Malformed>> {
    let mut ids: BTreeSet<String> = labelled(conn, SPEC)?.into_iter().collect();
    ids.extend(labelled(conn, REQUIREMENT)?);
    ids.extend(labelled(conn, NON_GOAL)?);
    let mut scan = ShapeScan::new(conn);
    let mut out = Vec::new();
    for id in &ids {
        let Some(issue) = scan.issue(id)? else { continue };
        let open = issue.status != Status::Closed;
        let labels = &issue.labels;
        let mut found: Vec<(Problem, String)> = Vec::new();
        if has(labels, SPEC) {
            if open && !labels.iter().any(|l| l.strip_prefix("area:").is_some_and(|a| check_area(a).is_ok())) {
                found.push((Problem::NoArea, format!("no area:<name> label (bd label add {id} area:<name>)")));
            }
            if open && issue.issue_type != "feature" {
                let t = clean(&issue.issue_type);
                found.push((Problem::SpecType, format!("type {t}, not feature (bd update {id} --type feature)")));
            }
            if open && (has(labels, REQUIREMENT) || has(labels, NON_GOAL)) {
                found.push((Problem::SpecAndRequirement, "labelled spec and requirement/non-goal: keep one".into()));
            }
        } else {
            let parent = scan.parent(id)?;
            let parent_spec = match &parent {
                Some(p) if scan.is_spec(p)? => Some(p.clone()),
                _ => None,
            };
            if open && parent_spec.is_none() {
                let detail = match &parent {
                    Some(p) => {
                        format!("parent {p} is not a spec: move it under its spec (bd update {id} --parent <spec>)")
                    }
                    None => format!("no parent: move it under its spec (bd update {id} --parent <spec>)"),
                };
                found.push((Problem::NotUnderSpec, detail));
            }
            if issue.status == Status::Pinned {
                let mut sourced = false;
                for src in edges_out(conn, id, "related")? {
                    if scan.issue(&src)?.is_some_and(|s| !is_spec_part(&s.labels)) {
                        sourced = true;
                        break;
                    }
                }
                if !sourced {
                    found.push((
                        Problem::NoSource,
                        format!("in force with no source (bd dep add {id} <issue or run> --type related)"),
                    ));
                }
            }
            if open && has(labels, NON_GOAL) && !has(labels, REQUIREMENT) {
                found.push((
                    Problem::NonGoalOnly,
                    format!("labelled non-goal but not requirement (bd label add {id} requirement)"),
                ));
            }
            if open && issue.issue_type != "story" {
                let t = clean(&issue.issue_type);
                found.push((Problem::RequirementType, format!("type {t}, not story (bd update {id} --type story)")));
            }
            let mut offenders: Vec<String> = Vec::new();
            for x in edges_out(conn, id, "supersedes")? {
                // A dangling edge is a damaged database, which `bd doctor` reports.
                let Some(target) = scan.issue(&x)? else { continue };
                if !is_requirement(&target.labels) {
                    offenders.push(format!("superseded by {x}, which is not a requirement"));
                    continue;
                }
                let px = scan.parent(&x)?;
                let allowed = match (&parent_spec, &px) {
                    (Some(p), Some(q)) => p == q || scan.successors(p)?.contains(q),
                    _ => false,
                };
                if !allowed {
                    let under = match &px {
                        Some(q) => format!("under {q}"),
                        None => "with no parent".to_string(),
                    };
                    let why = match (&parent_spec, &parent) {
                        (Some(p), _) => format!("not under its spec {p} or a spec it was superseded by"),
                        (None, Some(p)) => format!("and its parent {p} is not a spec"),
                        (None, None) => "and it has no parent spec".to_string(),
                    };
                    offenders.push(format!("superseded by {x} {under}, {why}"));
                }
            }
            if let Some(first) = offenders.first() {
                let more = offenders.len() - 1;
                let detail = if more > 0 { format!("{first} (and {more} more)") } else { first.clone() };
                found.push((Problem::SupersededElsewhere, detail));
            }
        }
        found.sort_by_key(|(problem, _)| *problem);
        out.extend(found.into_iter().map(|(problem, detail)| Malformed { issue: issue.to_ref(), problem, detail }));
    }
    Ok(out)
}

/// An issue in a group of candidates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Brief {
    pub id: String,
    pub title: String,
}

/// Closed work from before specs that no spec covers, grouped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CandidateGroup {
    /// `epic:<id>`, `label:<label>` or `ungrouped`.
    pub key: String,
    /// The epic's title, for an epic group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub issues: Vec<Brief>,
}

/// Labels that say nothing about a feature, left out of grouping.
fn groups_by(label: &str) -> bool {
    !["change:", "severity:", "spec:", "adr:"].iter().any(|p| label.starts_with(p))
}

/// Closed issues closed before `since` (every closed issue without it),
/// neither exempt nor linked: the work specs could be written from. Grouped
/// by their topmost ancestor (or themselves) of type epic that is not a
/// playbook run or group (`epic:<id>`), else by their first label in sorted
/// order that is not `change:*`, `severity:*`, `spec:*` or `adr:*`
/// (`label:<label>`), else `ungrouped`; the largest groups first, then by key.
pub fn candidates(conn: &Connection, since: Option<Timestamp>) -> Result<Vec<CandidateGroup>> {
    let linked = linked(conn)?;
    let closed = closed_between(conn, Timestamp(i64::MIN), since.unwrap_or(Timestamp(i64::MAX)))?;
    let mut issues_by_id: HashMap<String, Option<Issue>> = HashMap::new();
    let mut groups: BTreeMap<String, CandidateGroup> = BTreeMap::new();
    let mut exempt = Exempt::new(conn);
    for issue in closed {
        if linked.contains(&issue.id) || exempt.check_scanned(&issue)? {
            continue;
        }
        let mut epic: Option<(String, String)> = None;
        let above = graph::ancestors(conn, &issue.id)?.into_iter().filter(|a| *a != issue.id);
        for id in std::iter::once(issue.id.clone()).chain(above) {
            let node = match issues_by_id.get(&id) {
                Some(n) => n.clone(),
                None => {
                    let n = issues::get(conn, &id)?;
                    issues_by_id.insert(id.clone(), n.clone());
                    n
                }
            };
            let Some(node) = node else { break };
            if node.issue_type == "epic" && !issues::is_playbook_container(&node) {
                epic = Some((node.id.clone(), node.title.clone()));
            }
        }
        let (key, title) = match epic {
            Some((id, title)) => (format!("epic:{id}"), Some(title)),
            None => match issue.labels.iter().filter(|l| groups_by(l)).min() {
                Some(l) => (format!("label:{l}"), None),
                None => ("ungrouped".to_string(), None),
            },
        };
        groups
            .entry(key.clone())
            .or_insert_with(|| CandidateGroup { key, title, issues: Vec::new() })
            .issues
            .push(Brief { id: issue.id, title: issue.title });
    }
    let mut out: Vec<CandidateGroup> = groups.into_values().collect();
    out.sort_by(|a, b| b.issues.len().cmp(&a.issues.len()).then_with(|| a.key.cmp(&b.key)));
    Ok(out)
}

/// An open spec as `bd spec list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpecSummary {
    pub id: String,
    pub title: String,
    pub status: Status,
    /// Its `area:<name>` labels' names.
    pub areas: Vec<String>,
    /// Its parent spec, when that is not closed.
    pub parent: Option<String>,
    /// Its parent spec when that is closed (an orphan: then `parent` is None).
    pub closed_parent: Option<String>,
    /// Requirements in force (not closed), and non-goals.
    pub requirements: usize,
    pub non_goals: usize,
    /// Issues that are not spec parts with a `related` edge, either
    /// direction, to the spec or one of its own requirements.
    pub linked: usize,
}

/// Every open spec (labelled spec, not closed), in id order.
pub fn list(conn: &Connection) -> Result<Vec<SpecSummary>> {
    let src = DbSource::new(conn);
    // Every spec part, read once per listing. Edges end at issues that exist
    // (the dependencies' foreign keys cascade), so no other check is needed.
    let mut parts: HashSet<String> = HashSet::new();
    for label in [SPEC, REQUIREMENT, NON_GOAL] {
        parts.extend(labelled(conn, label)?);
    }
    let mut out = Vec::new();
    for spec in spec_nodes(&src)? {
        if spec.status == Status::Closed {
            continue;
        }
        let kids = children(&src, &spec.id)?;
        let reqs: Vec<&Node> = kids.iter().filter(|k| k.has(REQUIREMENT) || k.has(NON_GOAL)).collect();
        let mut linked: BTreeSet<String> = BTreeSet::new();
        for id in reqs.iter().map(|r| r.id.as_str()).chain([spec.id.as_str()]) {
            for other in related_of(conn, id)? {
                if !parts.contains(&other) {
                    linked.insert(other);
                }
            }
        }
        let live =
            |non_goal: bool| reqs.iter().filter(|r| r.status != Status::Closed && r.has(NON_GOAL) == non_goal).count();
        let (parent, closed_parent) = match &spec.parent {
            Some(p) => match src.node(p)? {
                Some(n) if n.is_spec() && n.status == Status::Closed => (None, Some(p.clone())),
                Some(n) if n.is_spec() => (Some(p.clone()), None),
                _ => (None, None),
            },
            None => (None, None),
        };
        out.push(SpecSummary {
            areas: spec.labels.iter().filter_map(|l| l.strip_prefix("area:")).map(clean).collect(),
            requirements: live(false),
            non_goals: live(true),
            linked: linked.len(),
            parent,
            closed_parent,
            title: clean(&spec.title),
            status: spec.status,
            id: spec.id,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
