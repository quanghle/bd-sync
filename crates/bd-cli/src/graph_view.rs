//! Renderers of `bd graph`: a [`Subgraph`] as a text tree, Graphviz DOT, or
//! a self-contained HTML page with an inline SVG drawing.
//!
//! Arrows run from what an issue depends on to the issue (a blocker to what
//! it blocks, a parent to its children). Output may go to a file, past the
//! stdout escaper, so every text taken from issues is first made printable
//! ([`io::printable`]) and then escaped for its format. The HTML runs no
//! script and loads nothing: its Content-Security-Policy allows inline
//! styles only.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use bd_core::graph::MAX_INDENT;
use bd_core::subgraph::{GraphEdge, GraphNode, Subgraph};
use bd_core::{DepType, Status};

use crate::io;

/// Characters of a title shown in a label (the text tree, DOT).
pub const LABEL_CHARS: usize = 60;
/// Characters of a title that fit in an SVG box.
const BOX_CHARS: usize = 34;
/// The hard maximum of `--max-nodes`, named in truncation notes.
pub const MAX_NODES_LIMIT: usize = 2000;

/// `s` cut to `max` characters, the last one `…` when cut.
fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `s` made printable (control and bidi characters escaped), on one line,
/// and cut to [`LABEL_CHARS`] characters.
pub fn label_text(s: &str) -> String {
    let one_line: String =
        io::printable(s).chars().map(|c| if matches!(c, '\n' | '\r' | '\t') { ' ' } else { c }).collect();
    cut(&one_line, LABEL_CHARS)
}

/// `s` escaped for HTML and XML text and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `s` escaped for a double-quoted DOT string.
pub fn dot_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// `n` and the word for that many.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn truncation_note(g: &Subgraph) -> String {
    format!(
        "truncated: only the first {} issues are shown (--max-nodes {}, at most {MAX_NODES_LIMIT})",
        g.nodes.len(),
        g.max_nodes
    )
}

/// How a node is coloured: its status, or blocked when live and held back.
fn status_class(n: &GraphNode) -> &'static str {
    match n.status {
        Status::Closed => "closed",
        Status::Pinned => "pinned",
        Status::Blocked => "blocked",
        _ if n.is_blocked => "blocked",
        Status::InProgress => "in-progress",
        Status::Deferred => "deferred",
        Status::Open => "open",
    }
}

/// How an edge is drawn: one of a few styles, every other type alike.
fn edge_kind(t: &DepType) -> &'static str {
    match t {
        DepType::Blocks => "blocks",
        DepType::ConditionalBlocks => "conditional-blocks",
        DepType::WaitsFor => "waits-for",
        DepType::ParentChild => "parent-child",
        DepType::Related => "related",
        _ => "other",
    }
}

const EDGE_KINDS: [(&str, &str); 6] = [
    ("blocks", "blocks"),
    ("conditional-blocks", "conditional-blocks"),
    ("waits-for", "waits-for"),
    ("parent-child", "parent-child"),
    ("related", "related (no direction)"),
    ("other", "other types"),
];

fn node_line(n: &GraphNode) -> String {
    let mut s = format!("{} {} [{} P{}] {}", n.status.icon(), n.id, n.status, n.priority, label_text(&n.title));
    if let Some(a) = &n.assignee {
        s.push_str(&format!(" @{}", label_text(a)));
    }
    if n.is_blocked && !n.status.is_terminal() {
        s.push_str(" (blocked)");
    }
    s
}

/// The edges leaving each node (depends_on → issue), in the subgraph's order.
fn out_edges(g: &Subgraph) -> HashMap<&str, Vec<&GraphEdge>> {
    let mut out: HashMap<&str, Vec<&GraphEdge>> = HashMap::new();
    for e in &g.edges {
        out.entry(e.depends_on.as_str()).or_default().push(e);
    }
    out
}

/// An indented tree from prerequisites to dependents: the issues no drawn
/// arrow points to first, in id order, then any left (in cycles). An issue
/// reached again is marked `(shown above)` and not expanded again.
pub fn text(g: &Subgraph) -> String {
    let nodes: HashMap<&str, &GraphNode> = g.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let kids = out_edges(g);
    let pointed: HashSet<&str> = g.edges.iter().map(|e| e.issue.as_str()).collect();
    let starts = g
        .nodes
        .iter()
        .filter(|n| !pointed.contains(n.id.as_str()))
        .chain(g.nodes.iter().filter(|n| pointed.contains(n.id.as_str())));
    let none: Vec<&GraphEdge> = Vec::new();
    let mut printed: HashSet<&str> = HashSet::new();
    let mut out = String::new();
    for start in starts {
        if !printed.insert(start.id.as_str()) {
            continue;
        }
        let _ = writeln!(out, "{}", node_line(start));
        // The edges left to draw at each level, the prefix of their lines, and their depth.
        let mut stack: Vec<(&[&GraphEdge], String, usize)> =
            vec![(kids.get(start.id.as_str()).unwrap_or(&none).as_slice(), String::new(), 1)];
        while let Some((left, prefix, depth)) = stack.last_mut() {
            let cur: &[&GraphEdge] = left;
            let Some((e, rest)) = cur.split_first() else {
                stack.pop();
                continue;
            };
            *left = rest;
            let last = rest.is_empty();
            let (prefix, depth) = (prefix.clone(), *depth);
            let Some(node) = nodes.get(e.issue.as_str()) else { continue };
            let first = printed.insert(e.issue.as_str());
            let deep = if depth > MAX_INDENT { format!("[depth {depth}] ") } else { String::new() };
            let _ = writeln!(
                out,
                "{prefix}{}{deep}[{}] {}{}",
                if last { "└─ " } else { "├─ " },
                label_text(e.dep_type.as_str()),
                node_line(node),
                if first { "" } else { " (shown above)" }
            );
            if first {
                let below = kids.get(e.issue.as_str()).unwrap_or(&none).as_slice();
                if !below.is_empty() {
                    let mut next = prefix;
                    if depth < MAX_INDENT {
                        next.push_str(if last { "   " } else { "│  " });
                    }
                    stack.push((below, next, depth + 1));
                }
            }
        }
    }
    let _ =
        writeln!(out, "-- {}, {}", plural(g.nodes.len(), "issue", "issues"), plural(g.edges.len(), "edge", "edges"));
    if g.truncated {
        let _ = writeln!(out, "-- {}", truncation_note(g));
    }
    out
}

fn dot_fill(n: &GraphNode) -> &'static str {
    match status_class(n) {
        "closed" => "#e5e7eb",
        "pinned" => "#f3e8ff",
        "blocked" => "#fde2e2",
        "in-progress" => "#fef3c7",
        "deferred" => "#e0e7ff",
        _ => "#ffffff",
    }
}

fn dot_edge_style(t: &DepType) -> &'static str {
    match edge_kind(t) {
        "blocks" => "style=solid, penwidth=2",
        "conditional-blocks" => "style=dashed",
        "waits-for" => "style=dotted",
        "parent-child" => "style=solid, color=gray50, arrowhead=empty",
        "related" => "style=dashed, color=gray50, dir=none",
        _ => "style=dotted, color=gray50",
    }
}

/// A Graphviz `digraph`: a node per issue labelled `id · status · P#` over
/// its title and filled by status, an edge per dependency from what an
/// issue depends on to the issue, labelled and styled by type.
pub fn dot(g: &Subgraph) -> String {
    let mut out = String::from("digraph bd {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10];\n");
    out.push_str("  edge [fontname=\"Helvetica\", fontsize=9];\n");
    if g.truncated {
        let _ = writeln!(out, "  // {}", truncation_note(g));
    }
    for n in &g.nodes {
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{} · {} · P{}\\n{}\", fillcolor=\"{}\"];",
            dot_escape(&io::printable(&n.id)),
            dot_escape(&io::printable(&n.id)),
            n.status,
            n.priority,
            dot_escape(&label_text(&n.title)),
            dot_fill(n)
        );
    }
    for e in &g.edges {
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [label=\"{}\", {}];",
            dot_escape(&io::printable(&e.depends_on)),
            dot_escape(&io::printable(&e.issue)),
            dot_escape(&io::printable(e.dep_type.as_str())),
            dot_edge_style(&e.dep_type)
        );
    }
    out.push_str("}\n");
    out
}

const BOX_W: usize = 240;
const BOX_H: usize = 56;
const GAP_X: usize = 80;
const GAP_Y: usize = 24;
const MARGIN: usize = 20;

/// Where each node is drawn: its layer (column) and its place in it.
///
/// A node's layer is the longest path to it from the nodes nothing points
/// to, along the arrows; a depth-first search in id order sets aside the
/// edges that close a cycle, so cycles are safe. In each layer nodes are
/// ordered by the mean place of their predecessors, then by id.
fn layout(g: &Subgraph) -> (Vec<usize>, Vec<usize>, usize, usize) {
    let n = g.nodes.len();
    let index: HashMap<&str, usize> = g.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    for e in &g.edges {
        if let (Some(&a), Some(&b)) = (index.get(e.depends_on.as_str()), index.get(e.issue.as_str()))
            && a != b
            && !succ[a].contains(&b)
        {
            succ[a].push(b);
        }
    }
    // Depth first, without recursion: back edges set aside, nodes in post-order.
    let mut state = vec![0u8; n];
    let mut back: HashSet<(usize, usize)> = HashSet::new();
    let mut post = Vec::with_capacity(n);
    for s in 0..n {
        if state[s] != 0 {
            continue;
        }
        state[s] = 1;
        let mut stack = vec![(s, 0usize)];
        while let Some((v, i)) = stack.last_mut() {
            let v = *v;
            if let Some(&w) = succ[v].get(*i) {
                *i += 1;
                match state[w] {
                    0 => {
                        state[w] = 1;
                        stack.push((w, 0));
                    }
                    1 => {
                        back.insert((v, w));
                    }
                    _ => {}
                }
            } else {
                state[v] = 2;
                post.push(v);
                stack.pop();
            }
        }
    }
    let mut layer = vec![0usize; n];
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &v in post.iter().rev() {
        for &w in &succ[v] {
            if !back.contains(&(v, w)) {
                layer[w] = layer[w].max(layer[v] + 1);
                preds[w].push(v);
            }
        }
    }
    let layers = layer.iter().copied().max().map_or(0, |m| m + 1);
    let mut columns: Vec<Vec<usize>> = vec![Vec::new(); layers];
    for v in 0..n {
        columns[layer[v]].push(v);
    }
    let mut place = vec![0usize; n];
    for column in &mut columns {
        let key = |v: usize| -> f64 {
            if preds[v].is_empty() {
                0.0
            } else {
                preds[v].iter().map(|&p| place[p] as f64).sum::<f64>() / preds[v].len() as f64
            }
        };
        let mut keyed: Vec<(f64, usize)> = column.iter().map(|&v| (key(v), v)).collect();
        // Nodes are in id order, so their index breaks ties by id.
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        *column = keyed.into_iter().map(|(_, v)| v).collect();
        for (i, &v) in column.iter().enumerate() {
            place[v] = i;
        }
    }
    let rows = columns.iter().map(Vec::len).max().unwrap_or(0);
    (layer, place, layers, rows)
}

const HTML_STYLE: &str = "\
:root { color-scheme: light dark; --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #1f2328;
  --soft: #8c959f; --open: #ffffff; --in-progress: #fff4ce; --blocked: #ffe1e1; --closed: #eaeef2;
  --deferred: #e6e9ff; --pinned: #f3e8ff; --stroke: #8c959f; --warn: #9a6700; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #e6edf3; --soft: #6e7681;
    --open: #161b22; --in-progress: #3d2f00; --blocked: #4a1c1c; --closed: #21262d; --deferred: #1c2347;
    --pinned: #2e1f47; --stroke: #6e7681; --warn: #d29922; }
}
body { margin: 0; padding: 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.4 system-ui, -apple-system, \"Segoe UI\", sans-serif; }
h1 { font-size: 18px; margin: 0 0 4px; overflow-wrap: anywhere; }
p { margin: 0 0 12px; color: var(--muted); }
p.truncated { color: var(--warn); font-weight: 600; }
.canvas { overflow: auto; border: 1px solid var(--stroke); border-radius: 6px; }
svg text { fill: var(--fg); font: 12px system-ui, -apple-system, \"Segoe UI\", sans-serif; }
svg text.id { font-weight: 600; font-size: 11px; }
rect { stroke: var(--stroke); stroke-width: 1; }
.s-open { fill: var(--open); } .s-in-progress { fill: var(--in-progress); } .s-blocked { fill: var(--blocked); }
.s-closed { fill: var(--closed); } .s-deferred { fill: var(--deferred); } .s-pinned { fill: var(--pinned); }
.e { fill: none; stroke: var(--line); stroke-width: 1.5; }
.e-blocks { stroke-width: 2.5; }
.e-conditional-blocks { stroke-dasharray: 6 4; }
.e-waits-for { stroke-dasharray: 2 3; }
.e-parent-child { stroke: var(--soft); }
.e-related { stroke: var(--soft); stroke-dasharray: 6 4; }
.e-other { stroke: var(--soft); stroke-dasharray: 2 3; }
.head { fill: var(--line); } .head-soft { fill: var(--soft); } .head-empty { fill: var(--bg); stroke: var(--soft); }
ul.legend { list-style: none; padding: 0; margin: 12px 0 0; display: flex; flex-wrap: wrap; gap: 6px 18px;
  color: var(--muted); }
ul.legend li { display: flex; align-items: center; gap: 6px; }
ul.legend .swatch { display: inline-block; width: 14px; height: 14px; border: 1px solid var(--stroke);
  border-radius: 3px; }
";

/// A marker id and its class for an edge kind (`None`: no arrowhead).
fn marker(kind: &str) -> Option<&'static str> {
    match kind {
        "related" => None,
        "parent-child" => Some("head-empty"),
        "blocks" | "conditional-blocks" | "waits-for" => Some("head"),
        _ => Some("head-soft"),
    }
}

/// A self-contained HTML page: `title`, a truncation banner when truncated,
/// an inline SVG drawing in layers from prerequisites to dependents (each
/// issue's full title in its tooltip), and a legend. No script, nothing
/// loaded from anywhere.
pub fn html(g: &Subgraph, title: &str) -> String {
    let title = html_escape(&io::printable(title));
    let (layer, place, layers, rows) = layout(g);
    let span = |count: usize, size: usize, gap: usize| {
        if count == 0 { 2 * MARGIN } else { 2 * MARGIN + count * (size + gap) - gap }
    };
    let (width, height) = (span(layers, BOX_W, GAP_X), span(rows, BOX_H, GAP_Y));
    let x = |v: usize| MARGIN + layer[v] * (BOX_W + GAP_X);
    let y = |v: usize| MARGIN + place[v] * (BOX_H + GAP_Y);
    let index: HashMap<&str, usize> = g.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();

    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n",
    );
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(out, "<title>{title}</title>");
    let _ = writeln!(out, "<style>\n{HTML_STYLE}</style>\n</head>\n<body>");
    let _ = writeln!(out, "<h1>{title}</h1>");
    let _ = writeln!(
        out,
        "<p>{}, {}. Arrows run from what an issue depends on to the issue.</p>",
        plural(g.nodes.len(), "issue", "issues"),
        plural(g.edges.len(), "edge", "edges")
    );
    if g.truncated {
        let note = truncation_note(g);
        let _ = writeln!(out, "<p class=\"truncated\">{}</p>", html_escape(&(note[..1].to_uppercase() + &note[1..])));
    }
    let _ = writeln!(
        out,
        "<div class=\"canvas\">\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
         viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{title}\">"
    );
    out.push_str("<defs>\n");
    for class in ["head", "head-soft", "head-empty"] {
        let _ = writeln!(
            out,
            "<marker id=\"{class}\" viewBox=\"0 0 10 10\" refX=\"10\" refY=\"5\" markerWidth=\"8\" \
             markerHeight=\"8\" orient=\"auto\"><path class=\"{class}\" d=\"M0,0 L10,5 L0,10 z\"/></marker>"
        );
    }
    out.push_str("</defs>\n");
    for e in &g.edges {
        let (Some(&a), Some(&b)) = (index.get(e.depends_on.as_str()), index.get(e.issue.as_str())) else { continue };
        let (x1, y1) = (x(a) + BOX_W, y(a) + BOX_H / 2);
        let (x2, y2) = (x(b), y(b) + BOX_H / 2);
        let dx = (x2.abs_diff(x1) / 2).max(40);
        let kind = edge_kind(&e.dep_type);
        let head = marker(kind).map(|m| format!(" marker-end=\"url(#{m})\"")).unwrap_or_default();
        let _ = writeln!(
            out,
            "<path class=\"e e-{kind}\" d=\"M{x1},{y1} C{},{y1} {},{y2} {x2},{y2}\"{head}><title>{} depends on {} ({})</title></path>",
            x1 + dx,
            x2 as i64 - dx as i64,
            html_escape(&io::printable(&e.issue)),
            html_escape(&io::printable(&e.depends_on)),
            html_escape(&io::printable(e.dep_type.as_str())),
        );
    }
    for (v, n) in g.nodes.iter().enumerate() {
        let (nx, ny) = (x(v), y(v));
        let id = html_escape(&io::printable(&n.id));
        let _ = writeln!(
            out,
            "<g><title>{id}: {}</title><rect class=\"s-{}\" x=\"{nx}\" y=\"{ny}\" width=\"{BOX_W}\" \
             height=\"{BOX_H}\" rx=\"6\"/><text class=\"id\" x=\"{}\" y=\"{}\">{id} · {} · P{}{}</text>\
             <text x=\"{}\" y=\"{}\">{}</text></g>",
            html_escape(&io::printable(&n.title)),
            status_class(n),
            nx + 10,
            ny + 22,
            n.status,
            n.priority,
            if n.is_blocked && !n.status.is_terminal() { " · blocked" } else { "" },
            nx + 10,
            ny + 42,
            html_escape(&cut(&label_text(&n.title), BOX_CHARS)),
        );
    }
    out.push_str("</svg>\n</div>\n<ul class=\"legend\">\n");
    for (kind, label) in EDGE_KINDS {
        let head = marker(kind).map(|m| format!(" marker-end=\"url(#{m})\"")).unwrap_or_default();
        let _ = writeln!(
            out,
            "<li><svg width=\"44\" height=\"12\" aria-hidden=\"true\"><path class=\"e e-{kind}\" d=\"M2,6 L40,6\"{head}/></svg>{label}</li>"
        );
    }
    for status in ["open", "in-progress", "blocked", "deferred", "closed", "pinned"] {
        let _ = writeln!(
            out,
            "<li><span class=\"swatch\" style=\"background: var(--{status})\"></span>{}</li>",
            status.replace('-', " ")
        );
    }
    out.push_str("</ul>\n</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, title: &str) -> GraphNode {
        GraphNode {
            id: id.into(),
            title: title.into(),
            status: Status::Open,
            priority: 2,
            issue_type: "task".into(),
            is_blocked: false,
            assignee: None,
        }
    }

    fn edge(issue: &str, depends_on: &str, t: DepType) -> GraphEdge {
        GraphEdge { issue: issue.into(), depends_on: depends_on.into(), dep_type: t }
    }

    fn graph(nodes: Vec<GraphNode>, mut edges: Vec<GraphEdge>) -> Subgraph {
        edges.sort_by(|a, b| (&a.depends_on, &a.issue, &a.dep_type).cmp(&(&b.depends_on, &b.issue, &b.dep_type)));
        Subgraph { root: nodes.first().map(|n| n.id.clone()), nodes, edges, truncated: false, max_nodes: 200 }
    }

    const HOSTILE: &str = "\u{202e}x</text><script>alert(1)</script> \"q\" back\\slash\nline";

    #[test]
    fn hostile_titles_are_escaped_in_every_format() {
        let g = graph(vec![node("t-1", HOSTILE), node("t-2", "Plain")], vec![edge("t-2", "t-1", DepType::Blocks)]);
        for (name, out) in [("text", text(&g)), ("dot", dot(&g)), ("html", html(&g, HOSTILE))] {
            assert!(!out.contains('\u{202e}'), "{name} keeps a bidi override");
            assert!(out.contains("\\u202e"), "{name} shows the override escaped");
        }
        // HTML: markup only as entities.
        let h = html(&g, HOSTILE);
        assert!(!h.contains("<script"), "{h}");
        assert!(h.contains("x&lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt; &quot;q&quot;"), "{h}");
        // DOT: every string ends where it should (3 per node line: id, label, colour).
        let d = dot(&g);
        let line = d.lines().find(|l| l.starts_with("  \"t-1\" [")).unwrap();
        assert!(line.contains(r#"\"q\" back\\slash line"#), "{line}");
        assert_eq!(dot_strings(line), 3, "{line}");
        for l in d.lines() {
            dot_strings(l);
        }
        // Text: one line per issue (the newline gone) and a footer.
        let t = text(&g);
        assert_eq!(t.lines().count(), 3, "{t}");
    }

    /// The double-quoted strings on a DOT line, or a panic when one is left open.
    fn dot_strings(line: &str) -> usize {
        let (mut count, mut inside, mut chars) = (0, false, line.chars());
        while let Some(c) = chars.next() {
            match (inside, c) {
                (true, '\\') => {
                    chars.next();
                }
                (true, '"') => inside = false,
                (false, '"') => {
                    inside = true;
                    count += 1;
                }
                _ => {}
            }
        }
        assert!(!inside, "unterminated string: {line}");
        count
    }

    #[test]
    fn html_loads_nothing_and_runs_nothing() {
        let g = graph(
            vec![node("t-1", "A"), node("t-2", "B"), node("t-3", "C")],
            vec![
                edge("t-2", "t-1", DepType::Blocks),
                edge("t-3", "t-2", DepType::ParentChild),
                edge("t-1", "t-3", DepType::Related),
            ],
        );
        let h = html(&g, "Graph");
        assert!(h.starts_with("<!doctype html>"));
        assert!(!h.to_ascii_lowercase().contains("<script"));
        assert!(h.contains("content=\"default-src 'none'; style-src 'unsafe-inline'\""));
        let urls: Vec<&str> = h.match_indices("http").map(|(i, _)| &h[i..(i + 30).min(h.len())]).collect();
        assert!(
            urls.iter().all(|u| u.starts_with("http-equiv") || u.starts_with("http://www.w3.org/2000/svg\"")),
            "{urls:?}"
        );
        assert_eq!(h.matches("http://").count(), 1);
        assert!(h.contains("@media (prefers-color-scheme: dark)"));
        assert!(h.contains("class=\"e e-related\"") && h.contains("parent-child"), "legend and edges");
        assert_eq!(h.matches("<g><title>").count(), 3);
    }

    #[test]
    fn dot_golden() {
        let mut blocked = node("t-3", "Ship \"it\"");
        blocked.is_blocked = true;
        let g = graph(
            vec![node("t-1", "First"), node("t-2", "Second"), blocked],
            vec![edge("t-2", "t-1", DepType::ParentChild), edge("t-3", "t-2", DepType::Blocks)],
        );
        let expected = r##"digraph bd {
  rankdir=LR;
  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];
  edge [fontname="Helvetica", fontsize=9];
  "t-1" [label="t-1 · open · P2\nFirst", fillcolor="#ffffff"];
  "t-2" [label="t-2 · open · P2\nSecond", fillcolor="#ffffff"];
  "t-3" [label="t-3 · open · P2\nShip \"it\"", fillcolor="#fde2e2"];
  "t-1" -> "t-2" [label="parent-child", style=solid, color=gray50, arrowhead=empty];
  "t-2" -> "t-3" [label="blocks", style=solid, penwidth=2];
}
"##;
        assert_eq!(dot(&g), expected);
    }

    #[test]
    fn text_tree_draws_prefixes_and_marks_repeats() {
        // A diamond: 1 before 2 and 3, both before 4; 5 apart.
        let g = graph(
            vec![
                node("t-1", "Top"),
                node("t-2", "Left"),
                node("t-3", "Right"),
                node("t-4", "Bottom"),
                node("t-5", "Apart"),
            ],
            vec![
                edge("t-2", "t-1", DepType::Blocks),
                edge("t-3", "t-1", DepType::ParentChild),
                edge("t-4", "t-2", DepType::Blocks),
                edge("t-4", "t-3", DepType::Blocks),
            ],
        );
        let expected = "\
○ t-1 [open P2] Top
├─ [blocks] ○ t-2 [open P2] Left
│  └─ [blocks] ○ t-4 [open P2] Bottom
└─ [parent-child] ○ t-3 [open P2] Right
   └─ [blocks] ○ t-4 [open P2] Bottom (shown above)
○ t-5 [open P2] Apart
-- 5 issues, 4 edges
";
        assert_eq!(text(&g), expected);
    }

    #[test]
    fn cycles_are_drawn_once() {
        let g = graph(
            vec![node("t-1", "A"), node("t-2", "B")],
            vec![edge("t-2", "t-1", DepType::Blocks), edge("t-1", "t-2", DepType::Blocks)],
        );
        let t = text(&g);
        assert_eq!(t.lines().next(), Some("○ t-1 [open P2] A"), "{t}");
        assert!(t.contains("(shown above)"), "{t}");
        assert!(html(&g, "c").contains("<g><title>t-2: B</title>"));
    }

    #[test]
    fn deep_chains_stop_indenting() {
        let n = MAX_INDENT + 10;
        let nodes: Vec<GraphNode> = (0..n).map(|i| node(&format!("t-{i:03}"), "N")).collect();
        let edges = (1..n).map(|i| edge(&format!("t-{i:03}"), &format!("t-{:03}", i - 1), DepType::Blocks)).collect();
        let t = text(&graph(nodes, edges));
        let widest = t.lines().map(|l| l.chars().count()).max().unwrap();
        assert!(widest < 3 * MAX_INDENT + 60, "{widest}");
        assert!(t.contains(&format!("[depth {}] ", MAX_INDENT + 1)), "{t}");
    }

    #[test]
    fn truncation_is_said_in_every_format() {
        let mut g = graph(vec![node("t-1", "A")], Vec::new());
        g.truncated = true;
        g.max_nodes = 1;
        let note = "only the first 1 issues are shown (--max-nodes 1, at most 2000)";
        assert!(text(&g).contains(&format!("-- truncated: {note}")));
        assert!(dot(&g).contains(&format!("// truncated: {note}")));
        assert!(html(&g, "t").contains(&format!("<p class=\"truncated\">Truncated: {note}</p>")));
        g.truncated = false;
        assert!(!text(&g).contains("truncated") && !dot(&g).contains("truncated"));
        assert!(!html(&g, "t").contains("class=\"truncated\""));
    }

    #[test]
    fn labels_are_cut() {
        let long = "x".repeat(100);
        assert_eq!(label_text(&long).chars().count(), LABEL_CHARS);
        assert!(label_text(&long).ends_with('…'));
        assert_eq!(label_text("a\r\nb\tc"), "a  b c");
        assert_eq!(dot_escape("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        assert_eq!(html_escape("<a href='x'>&\"</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;");
    }
}
