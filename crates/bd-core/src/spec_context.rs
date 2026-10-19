//! The feature specs governing one issue (experimental `specs`): what
//! `bd show` and `bd claim` list, and whether a link covers it, which the
//! `bd close` hint asks.
//!
//! An issue's lineage is the issue, its ancestors (nearest first) and its
//! descendants (breadth-first, up to [`SPEC_WALK_LIMIT`]). The specs
//! governing it are those a `related` edge (either direction) links to any
//! issue of its lineage: a linked spec counts for itself, a linked
//! requirement or non-goal for its parent spec. That is the same coverage
//! [`specs::linked`] computes for the whole workspace (a link covers the
//! linked issue's subtree and its ancestors), asked of one issue.
//!
//! Every lookup goes by key (edges by either end, labels and issues by id),
//! the walk is bounded ([`SPEC_WALK_LIMIT`] descendants, [`SPEC_EDGE_LIMIT`]
//! related edges, each bound as a statement's LIMIT so the rows read are
//! bounded too), and a damaged parent cycle ends it. Everything here reads:
//! callers decide whether specs are on ([`specs::is_on`]) and escape titles,
//! which are kept as stored.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;

use rusqlite::{Connection, params};
use serde::Serialize;

use crate::error::Result;
use crate::graph;
use crate::hierarchy;
use crate::issues;
use crate::model::{Issue, Status};
use crate::specs::{self, Brief, DbSource, NON_GOAL, NONE, REQUIREMENT, SPEC};

/// How many descendants of an issue the walk looks at.
pub const SPEC_WALK_LIMIT: usize = 500;
/// How many `related` edges, over the whole lineage, the walk looks at.
pub const SPEC_EDGE_LIMIT: usize = 5000;

/// The walk's bounds: [`SPEC_WALK_LIMIT`] and [`SPEC_EDGE_LIMIT`] by
/// default; tests pass smaller ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub descendants: usize,
    pub edges: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { descendants: SPEC_WALK_LIMIT, edges: SPEC_EDGE_LIMIT }
    }
}

/// Which bound cut a walk short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    /// More descendants than [`Limits::descendants`].
    Descendants,
    /// More related edges than [`Limits::edges`].
    Edges,
}

/// The specs governing an issue, in spec id order, and whether the walk
/// was cut short (then more may govern it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Governing {
    pub specs: Vec<SpecContext>,
    pub truncated: Option<Cap>,
}

impl Governing {
    /// The governing specs' ids, in order.
    pub fn ids(&self) -> Vec<String> {
        self.specs.iter().map(|s| s.id.clone()).collect()
    }
}

/// One spec governing an issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpecContext {
    pub id: String,
    pub title: String,
    pub status: Status,
    /// Its `area:<name>` labels' names, sorted.
    pub areas: Vec<String>,
    /// The issues of the lineage linked to it, in id order.
    pub via: Vec<String>,
    /// Its requirements and non-goals linked directly (any status), in id order.
    pub linked: Vec<LinkedPart>,
    /// Its requirements in force (pinned children), in creation order.
    pub requirements: Vec<Brief>,
    /// Its non-goals in force (pinned children), in creation order.
    pub non_goals: Vec<Brief>,
    /// The open specs it inherits from, outermost first.
    pub inherits: Vec<String>,
}

/// A requirement or non-goal a lineage issue is linked to directly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkedPart {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub non_goal: bool,
}

/// Whether a spec link covers an issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// A link covers it, or it is labelled `spec:none`.
    Linked,
    /// The whole lineage was looked at and no link covers it.
    NotLinked,
    /// The walk was cut short before it found a link.
    Unknown,
}

/// The specs governing the issue `id`.
pub fn governing(conn: &Connection, id: &str) -> Result<Governing> {
    governing_with(conn, id, Limits::default())
}

/// Whether a spec link covers the issue `id`.
pub fn covered(conn: &Connection, id: &str) -> Result<Coverage> {
    covered_with(conn, id, Limits::default())
}

/// [`covered`] within `limits`: `spec:none` on the issue itself covers it;
/// otherwise the first link found does, and a walk cut short before one is
/// [`Coverage::Unknown`].
pub fn covered_with(conn: &Connection, id: &str, limits: Limits) -> Result<Coverage> {
    let mut w = Walker::new(conn, limits);
    if w.labels(id)?.iter().any(|l| l == NONE) {
        return Ok(Coverage::Linked);
    }
    let (cap, found) = w.walk(id, |_, _, _| ControlFlow::Break(()))?;
    Ok(match (found, cap) {
        (true, _) => Coverage::Linked,
        (false, Some(_)) => Coverage::Unknown,
        (false, None) => Coverage::NotLinked,
    })
}

/// [`governing`] within `limits`.
pub fn governing_with(conn: &Connection, id: &str, limits: Limits) -> Result<Governing> {
    let mut w = Walker::new(conn, limits);
    // (lineage id, part id, part is a spec, part is a non-goal)
    let mut found: Vec<(String, String, bool, bool)> = Vec::new();
    let (truncated, _) = w.walk(id, |at, part, labels| {
        let has = |l: &str| labels.iter().any(|x| x == l);
        found.push((at.to_string(), part.to_string(), has(SPEC), has(NON_GOAL)));
        ControlFlow::Continue(())
    })?;

    struct Group {
        via: BTreeSet<String>,
        /// Non-spec parts by id: whether each is a non-goal.
        parts: BTreeMap<String, bool>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut parents: HashMap<String, Option<String>> = HashMap::new();
    for (at, part, is_spec, non_goal) in found {
        let key = if is_spec {
            part.clone()
        } else {
            let parent = match parents.get(&part) {
                Some(p) => p.clone(),
                None => {
                    let p = graph::parent_of(conn, &part)?;
                    parents.insert(part.clone(), p.clone());
                    p
                }
            };
            parent.unwrap_or_else(|| part.clone())
        };
        let g = groups.entry(key).or_insert_with(|| Group { via: BTreeSet::new(), parts: BTreeMap::new() });
        g.via.insert(at);
        if !is_spec {
            g.parts.insert(part, non_goal);
        }
    }

    let src = DbSource::new(conn);
    let mut issues_read: HashMap<String, Option<Issue>> = HashMap::new();
    let mut get = |id: &str| -> Result<Option<Issue>> {
        if let Some(i) = issues_read.get(id) {
            return Ok(i.clone());
        }
        let i = issues::get(conn, id)?;
        issues_read.insert(id.to_string(), i.clone());
        Ok(i)
    };
    let mut out = Vec::with_capacity(groups.len());
    for (spec_id, group) in groups {
        let Some(spec) = get(&spec_id)? else { continue };
        let mut areas: Vec<String> =
            spec.labels.iter().filter_map(|l| l.strip_prefix("area:")).map(str::to_string).collect();
        areas.sort();
        let mut linked = Vec::with_capacity(group.parts.len());
        for (part, non_goal) in group.parts {
            if let Some(p) = get(&part)? {
                linked.push(LinkedPart { id: p.id, title: p.title, status: p.status, non_goal });
            }
        }
        let (mut requirements, mut non_goals) = (Vec::new(), Vec::new());
        for child in hierarchy::child_issues(conn, &spec_id, false)? {
            if child.status != Status::Pinned {
                continue;
            }
            let has = |l: &str| child.labels.iter().any(|x| x == l);
            if has(NON_GOAL) {
                non_goals.push(Brief { id: child.id, title: child.title });
            } else if has(REQUIREMENT) {
                requirements.push(Brief { id: child.id, title: child.title });
            }
        }
        let inherits = specs::ancestors(&spec_id, &src)?.chain.into_iter().rev().map(|n| n.id).collect();
        out.push(SpecContext {
            id: spec.id,
            title: spec.title,
            status: spec.status,
            areas,
            via: group.via.into_iter().collect(),
            linked,
            requirements,
            non_goals,
            inherits,
        });
    }
    Ok(Governing { specs: out, truncated })
}

/// A lineage walk: the bounds, the related edges counted so far, and each
/// issue's labels read once.
struct Walker<'c> {
    conn: &'c Connection,
    limits: Limits,
    edges: usize,
    labels: HashMap<String, Vec<String>>,
}

/// Why examining an issue's edges stopped the walk.
enum Stop {
    Cap(Cap),
    Visit,
}

/// A row count as a bound LIMIT.
fn limit(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl<'c> Walker<'c> {
    fn new(conn: &'c Connection, limits: Limits) -> Self {
        Walker { conn, limits, edges: 0, labels: HashMap::new() }
    }

    /// The labels of `id`, in order, read once.
    fn labels(&mut self, id: &str) -> Result<&[String]> {
        if !self.labels.contains_key(id) {
            let mut stmt = self.conn.prepare_cached("SELECT label FROM labels WHERE issue_id = ?1 ORDER BY label")?;
            let rows = stmt.query_map([id], |r| r.get(0))?;
            let labels: Vec<String> = rows.collect::<rusqlite::Result<_>>()?;
            self.labels.insert(id.to_string(), labels);
        }
        Ok(&self.labels[id])
    }

    /// Up to `n` ids of `id`'s children, in id order.
    fn children(&self, id: &str, n: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child'
             ORDER BY issue_id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![id, limit(n)], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Visits each spec part at the other end of `at`'s related edges (out,
    /// then in, each in id order), counting every edge against the bound.
    fn examine(
        &mut self,
        at: &str,
        visit: &mut impl FnMut(&str, &str, &[String]) -> ControlFlow<()>,
    ) -> Result<ControlFlow<Stop>> {
        const OUT: &str = "SELECT depends_on_id FROM dependencies WHERE issue_id = ?1 AND dep_type = 'related'
                           ORDER BY depends_on_id LIMIT ?2";
        const IN: &str = "SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'related'
                          ORDER BY issue_id LIMIT ?2";
        for sql in [OUT, IN] {
            // One row past the budget tells that the bound was crossed.
            let room = self.limits.edges - self.edges;
            let ends: Vec<String> = {
                let mut stmt = self.conn.prepare_cached(sql)?;
                let rows = stmt.query_map(params![at, limit(room.saturating_add(1))], |r| r.get(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            for end in ends {
                if self.edges == self.limits.edges {
                    return Ok(ControlFlow::Break(Stop::Cap(Cap::Edges)));
                }
                self.edges += 1;
                let labels = self.labels(&end)?;
                if specs::is_spec_part(labels) && visit(at, &end, labels).is_break() {
                    return Ok(ControlFlow::Break(Stop::Visit));
                }
            }
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Walks `id`'s lineage, calling `visit(lineage id, part id, part
    /// labels)` for each spec part linked to it, until `visit` breaks or a
    /// bound is crossed: which bound, and whether `visit` stopped it.
    fn walk(
        &mut self,
        id: &str,
        mut visit: impl FnMut(&str, &str, &[String]) -> ControlFlow<()>,
    ) -> Result<(Option<Cap>, bool)> {
        let stopped = |s: Stop| match s {
            Stop::Cap(c) => (Some(c), false),
            Stop::Visit => (None, true),
        };
        // The issue and its ancestors, nearest first; `seen` ends a damaged parent cycle.
        let mut seen: HashSet<String> = HashSet::from([id.to_string()]);
        let mut up = vec![id.to_string()];
        for a in graph::ancestors(self.conn, id)? {
            if seen.insert(a.clone()) {
                up.push(a);
            }
        }
        for at in &up {
            if let ControlFlow::Break(s) = self.examine(at, &mut visit)? {
                return Ok(stopped(s));
            }
        }
        // Its descendants, breadth-first, each examined as it is reached.
        let mut queue = VecDeque::from([id.to_string()]);
        let mut reached = 0;
        while let Some(node) = queue.pop_front() {
            let room = self.limits.descendants - reached;
            if room == 0 {
                // Nothing more may be reached: any child not reached yet means the walk was cut.
                if self.children(&node, 1)?.iter().any(|k| !seen.contains(k)) {
                    return Ok((Some(Cap::Descendants), false));
                }
                continue;
            }
            let kids = self.children(&node, room + 1)?;
            let hit_limit = kids.len() > room;
            for kid in kids {
                if seen.contains(&kid) {
                    continue;
                }
                if reached == self.limits.descendants {
                    return Ok((Some(Cap::Descendants), false));
                }
                seen.insert(kid.clone());
                reached += 1;
                if let ControlFlow::Break(s) = self.examine(&kid, &mut visit)? {
                    return Ok(stopped(s));
                }
                queue.push_back(kid);
            }
            if hit_limit {
                // The extra row was a child already seen (a damaged cycle):
                // more may lie past the LIMIT, so the walk counts as cut.
                return Ok((Some(Cap::Descendants), false));
            }
        }
        Ok((None, false))
    }
}

#[cfg(test)]
mod tests;
