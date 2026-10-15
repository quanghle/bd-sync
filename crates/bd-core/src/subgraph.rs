//! Bounded subgraphs of the dependency graph, for `bd graph`: the issues
//! reachable from one issue (following edges only down, or only up), or
//! every issue not closed or pinned, with the edges between them.
//!
//! Every read is a fixed-plan lookup: [`graph::dependencies_of`] and
//! [`graph::dependents_of`] per node, issues by primary key, and for
//! [`open_issues`] the `bd list` statement.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde::Serialize;

use crate::error::Result;
use crate::graph;
use crate::issues;
use crate::model::{DepType, Issue, ListQuery, ListSort, Status};

/// One issue of a [`Subgraph`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub priority: u8,
    pub issue_type: String,
    pub is_blocked: bool,
    pub assignee: Option<String>,
}

impl From<Issue> for GraphNode {
    fn from(i: Issue) -> GraphNode {
        GraphNode {
            id: i.id,
            title: i.title,
            status: i.status,
            priority: i.priority,
            issue_type: i.issue_type,
            is_blocked: i.is_blocked,
            assignee: i.assignee,
        }
    }
}

/// An edge of a [`Subgraph`]: `issue` depends on `depends_on`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GraphEdge {
    pub issue: String,
    pub depends_on: String,
    #[serde(rename = "type")]
    pub dep_type: DepType,
}

/// Issues sorted by id, and the edges of the selected types between them,
/// sorted by (depends_on, issue, type).
#[derive(Clone, Debug, Serialize)]
pub struct Subgraph {
    /// The issue the walk started from (`None` for every open issue).
    pub root: Option<String>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// More issues were selected than `max_nodes`: only the first are here.
    pub truncated: bool,
    pub max_nodes: usize,
}

/// Which edge types a subgraph follows and shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EdgeSet {
    /// Every type but `related` (as `bd dep tree`).
    #[default]
    Default,
    All,
    Only(Vec<DepType>),
}

impl EdgeSet {
    pub fn includes(&self, t: &DepType) -> bool {
        match self {
            EdgeSet::Default => *t != DepType::Related,
            EdgeSet::All => true,
            EdgeSet::Only(types) => types.contains(t),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Way {
    /// Towards what an issue depends on.
    Down,
    /// Towards what depends on an issue.
    Up,
}

/// The issues reachable from `root` by following edges of the selected types
/// only down (dependencies) or only up (dependents), breadth first: nearer
/// issues first, and at the same distance in id order. Past `max_nodes`
/// issues (the root included; at least 1) the walk stops and the subgraph is
/// marked truncated.
pub fn around(conn: &Connection, root: &str, edges: &EdgeSet, max_nodes: usize) -> Result<Subgraph> {
    let max_nodes = max_nodes.max(1);
    let first = issues::require(conn, root)?;
    let root = first.id.clone();
    let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::from([(root.clone(), first.into())]);
    let mut seen: BTreeSet<(String, Way)> = BTreeSet::new();
    let mut frontier = vec![(root.clone(), Way::Down), (root.clone(), Way::Up)];
    seen.extend(frontier.iter().cloned());
    let mut truncated = false;
    'walk: while !frontier.is_empty() {
        // Every neighbour at the next distance, in id order.
        let mut next: BTreeSet<(String, Way)> = BTreeSet::new();
        for (id, way) in &frontier {
            let found = match way {
                Way::Down => graph::dependencies_of(conn, id)?,
                Way::Up => graph::dependents_of(conn, id)?,
            };
            next.extend(found.into_iter().filter(|e| edges.includes(&e.dep_type)).map(|e| (e.id, *way)));
        }
        frontier = Vec::new();
        for (id, way) in next {
            if seen.contains(&(id.clone(), way)) {
                continue;
            }
            if !nodes.contains_key(&id) {
                if nodes.len() >= max_nodes {
                    truncated = true;
                    break 'walk;
                }
                nodes.insert(id.clone(), issues::require(conn, &id)?.into());
            }
            seen.insert((id.clone(), way));
            frontier.push((id, way));
        }
    }
    let nodes: Vec<GraphNode> = nodes.into_values().collect();
    let edges = edges_between(conn, &nodes, edges)?;
    Ok(Subgraph { root: Some(root), nodes, edges, truncated, max_nodes })
}

/// Every issue not closed or pinned, the first `max_nodes` (at least 1) in
/// id order, marked truncated when there are more.
pub fn open_issues(conn: &Connection, edges: &EdgeSet, max_nodes: usize) -> Result<Subgraph> {
    let max_nodes = max_nodes.max(1);
    let q = ListQuery { sort: ListSort::Id, limit: Some(max_nodes + 1), ..Default::default() };
    let mut listed = issues::list(conn, &q)?;
    let truncated = listed.len() > max_nodes;
    listed.truncate(max_nodes);
    let nodes: Vec<GraphNode> = listed.into_iter().map(GraphNode::from).collect();
    let edges = edges_between(conn, &nodes, edges)?;
    Ok(Subgraph { root: None, nodes, edges, truncated, max_nodes })
}

/// The edges of the selected types among `nodes`, sorted by (depends_on, issue, type).
fn edges_between(conn: &Connection, nodes: &[GraphNode], selected: &EdgeSet) -> Result<Vec<GraphEdge>> {
    let ids: BTreeSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let mut out = Vec::new();
    for n in nodes {
        for e in graph::dependencies_of(conn, &n.id)? {
            if selected.includes(&e.dep_type) && ids.contains(e.id.as_str()) {
                out.push(GraphEdge { issue: n.id.clone(), depends_on: e.id, dep_type: e.dep_type });
            }
        }
    }
    out.sort_by(|a, b| (&a.depends_on, &a.issue, &a.dep_type).cmp(&(&b.depends_on, &b.issue, &b.dep_type)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_sets_select_types() {
        assert!(EdgeSet::Default.includes(&DepType::Blocks));
        assert!(EdgeSet::Default.includes(&DepType::Custom("x".into())));
        assert!(!EdgeSet::Default.includes(&DepType::Related));
        assert!(EdgeSet::All.includes(&DepType::Related));
        let only = EdgeSet::Only(vec![DepType::ParentChild]);
        assert!(only.includes(&DepType::ParentChild) && !only.includes(&DepType::Blocks));
    }
}
