//! The lineage walk over a workspace: what governs an issue, where the walk
//! is cut, and coverage agreeing with `specs::linked`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::config::{self, IdMode};
use crate::issues::CloseOptions;
use crate::model::{DepType, NewIssue};
use crate::store::{InitOptions, OpenOptions, Store, WriteCtx};
use crate::time::{Clock, ManualClock, Timestamp};

struct Ws {
    _dir: tempfile::TempDir,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Ws {
    fn new() -> Ws {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(Timestamp(1_700_000_000_000)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store =
            Store::init(&dir.path().join("bd.db"), InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts)
                .unwrap();
        let mut ws = Ws { _dir: dir, store, clock };
        ws.write(|tx| config::set(tx, "experimental.features", "specs"));
        ws
    }

    fn write<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.clock.advance(Duration::from_secs(60));
        self.store.write("test", "alice", f).unwrap()
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.write(|tx| tx.create_issue(new)).id
    }

    fn task(&mut self, title: &str, parent: Option<&str>) -> String {
        self.create(titled(title, &[], parent))
    }

    fn pinned(&mut self, title: &str, labels: &[&str], parent: Option<&str>) -> String {
        self.create(NewIssue { status: Some(Status::Pinned), ..titled(title, labels, parent) })
    }

    /// `from` related to `to` (an edge from `from`).
    fn relate(&mut self, from: &str, to: &str) {
        let (f, t) = (from.to_string(), to.to_string());
        self.write(|tx| tx.add_dependency(&f, &t, DepType::Related, None));
    }

    fn close(&mut self, id: &str) {
        let id = id.to_string();
        self.write(|tx| tx.close_issue(&id, &CloseOptions { force: true, ..Default::default() }));
    }

    fn governing(&self, id: &str) -> Governing {
        self.store.read(|r| governing(r.conn(), id)).unwrap()
    }

    fn governing_with(&self, id: &str, limits: Limits) -> Governing {
        self.store.read(|r| governing_with(r.conn(), id, limits)).unwrap()
    }

    fn covered(&self, id: &str) -> Coverage {
        self.store.read(|r| covered(r.conn(), id)).unwrap()
    }

    fn covered_with(&self, id: &str, limits: Limits) -> Coverage {
        self.store.read(|r| covered_with(r.conn(), id, limits)).unwrap()
    }
}

fn titled(title: &str, labels: &[&str], parent: Option<&str>) -> NewIssue {
    NewIssue {
        labels: labels.iter().map(|l| l.to_string()).collect(),
        parent: parent.map(String::from),
        ..NewIssue::titled(title)
    }
}

fn ids(g: &Governing) -> Vec<&str> {
    g.specs.iter().map(|s| s.id.as_str()).collect()
}

fn vias(g: &Governing) -> Vec<Vec<&str>> {
    g.specs.iter().map(|s| s.via.iter().map(String::as_str).collect()).collect()
}

#[test]
fn a_spec_linked_to_the_issue_itself_governs_it() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Checkout", &["spec", "area:checkout"], None);
    let work = ws.task("Work", None);
    let other = ws.task("Other", None);
    ws.relate(&work, &spec);
    let g = ws.governing(&work);
    assert_eq!(ids(&g), [spec.as_str()]);
    assert_eq!(vias(&g), [[work.as_str()]]);
    assert_eq!(g.specs[0].areas, ["checkout"]);
    assert!(g.specs[0].linked.is_empty());
    assert_eq!(g.truncated, None);
    assert_eq!(ws.covered(&work), Coverage::Linked);
    // An edge in the other direction links as well.
    let back = ws.task("Back", None);
    ws.relate(&spec, &back);
    assert_eq!(ids(&ws.governing(&back)), [spec.as_str()]);
    // Unrelated work: nothing governs it.
    assert_eq!(ws.governing(&other), Governing::default());
    assert_eq!(ws.covered(&other), Coverage::NotLinked);
}

#[test]
fn a_link_on_an_ancestor_or_a_grandchild_governs_the_issue() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Checkout", &["spec"], None);
    let rule = ws.pinned("Requires sign-in", &["requirement"], Some(&spec));
    let epic = ws.task("Epic", None);
    let task = ws.task("Task", Some(&epic));
    let leaf = ws.task("Leaf", Some(&task));
    ws.relate(&rule, &epic);

    // Through an ancestor: the requirement groups under its spec.
    let g = ws.governing(&leaf);
    assert_eq!(ids(&g), [spec.as_str()]);
    assert_eq!(vias(&g), [[epic.as_str()]]);
    assert_eq!(g.specs[0].linked.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), [rule.as_str()]);
    assert_eq!(ws.covered(&leaf), Coverage::Linked);

    // Through a grandchild.
    let top = ws.task("Top", None);
    let mid = ws.task("Mid", Some(&top));
    let low = ws.task("Low", Some(&mid));
    ws.relate(&low, &spec);
    let g = ws.governing(&top);
    assert_eq!(ids(&g), [spec.as_str()]);
    assert_eq!(vias(&g), [[low.as_str()]]);
    assert_eq!(ws.covered(&top), Coverage::Linked);
    assert_eq!(ws.covered(&mid), Coverage::Linked);
    // A sibling of the linked issue's ancestor is not in its lineage.
    let aside = ws.task("Aside", Some(&mid));
    assert_eq!(ws.governing(&aside), Governing::default());
    assert_eq!(ws.covered(&aside), Coverage::NotLinked);
}

#[test]
fn every_field_of_an_entry() {
    let mut ws = Ws::new();
    let root = ws.pinned("Payments", &["spec", "area:pay"], None);
    let sub = ws.pinned("Cards", &["spec", "area:cards"], Some(&root));
    let spec = ws.pinned("Checkout", &["spec", "area:zeta", "area:checkout"], Some(&sub));
    let rule = ws.pinned("Requires sign-in", &["requirement"], Some(&spec));
    let gone = ws.pinned("Old rule", &["requirement"], Some(&spec));
    let draft = ws.create(titled("Draft rule", &["requirement"], Some(&spec)));
    let never = ws.pinned("No guest checkout", &["non-goal"], Some(&spec));
    let work = ws.task("Work", None);
    let child = ws.task("Child", Some(&work));
    ws.relate(&work, &never);
    ws.relate(&child, &gone);
    ws.relate(&gone, &work);
    ws.close(&gone);

    let g = ws.governing(&work);
    assert_eq!(g.truncated, None);
    assert_eq!(g.ids(), std::slice::from_ref(&spec));
    let mut want_via = vec![work.clone(), child.clone()];
    want_via.sort();
    assert_eq!(
        serde_json::to_value(&g.specs[0]).unwrap(),
        json!({
            "id": spec,
            "title": "Checkout",
            "status": "pinned",
            "areas": ["checkout", "zeta"],
            "via": want_via,
            "linked": [
                { "id": gone, "title": "Old rule", "status": "closed", "non_goal": false },
                { "id": never, "title": "No guest checkout", "status": "pinned", "non_goal": true },
            ],
            "requirements": [{ "id": rule, "title": "Requires sign-in" }],
            "non_goals": [{ "id": never, "title": "No guest checkout" }],
            "inherits": [root, sub],
        })
    );
    // The open (unpinned) requirement is in force nowhere, so it is left out.
    assert!(!g.specs[0].requirements.iter().any(|b| b.id == draft));
}

#[test]
fn entries_are_sorted_by_spec_id_with_via_sorted_and_deduped() {
    let mut ws = Ws::new();
    let mut specs: Vec<String> = (0..11).map(|n| ws.pinned(&format!("Spec {n}"), &["spec"], None)).collect();
    let rule = ws.pinned("Rule", &["requirement"], Some(&specs[0]));
    let work = ws.task("Work", None);
    let kid = ws.task("Kid", Some(&work));
    for s in specs.iter().rev() {
        ws.relate(&work, s);
    }
    // Twice through the work, once through its child: one entry, two via.
    ws.relate(&work, &rule);
    ws.relate(&kid, &specs[0]);
    let g = ws.governing(&work);
    specs.sort();
    assert_eq!(g.ids(), specs, "in id order (t-10 before t-2)");
    let first = g.specs.iter().find(|s| s.linked.iter().any(|p| p.id == rule)).unwrap();
    let mut want = vec![work.clone(), kid.clone()];
    want.sort();
    assert_eq!(first.via, want);
    assert_eq!(g.specs.iter().filter(|s| s.id == first.id).count(), 1);
}

#[test]
fn two_links_to_one_spec_give_one_entry_with_both_via() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Spec", &["spec"], None);
    let rule = ws.pinned("Rule", &["requirement"], Some(&spec));
    let epic = ws.task("Epic", None);
    let task = ws.task("Task", Some(&epic));
    ws.relate(&epic, &spec);
    ws.relate(&task, &rule);
    let g = ws.governing(&task);
    assert_eq!(ids(&g), [spec.as_str()]);
    let mut want = vec![task.as_str(), epic.as_str()];
    want.sort();
    assert_eq!(vias(&g), [want]);
}

#[test]
fn a_parentless_part_groups_under_itself() {
    let mut ws = Ws::new();
    let stray = ws.pinned("Stray rule", &["requirement"], None);
    let work = ws.task("Work", None);
    ws.relate(&work, &stray);
    let g = ws.governing(&work);
    assert_eq!(ids(&g), [stray.as_str()]);
    assert_eq!(g.specs[0].linked[0].id, stray);
}

#[test]
fn a_parent_cycle_ends_the_walk() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Spec", &["spec"], None);
    let x = ws.task("X", None);
    let y = ws.task("Y", None);
    let z = ws.task("Z", None);
    let at = ws.clock.now().0;
    let (xr, yr) = (x.clone(), y.clone());
    ws.write(|tx| {
        let insert = "INSERT INTO dependencies (issue_id, depends_on_id, dep_type, created_at)
                      VALUES (?1, ?2, 'parent-child', ?3)";
        tx.conn().execute(insert, params![xr, yr, at])?;
        tx.conn().execute(insert, params![yr, xr, at])?;
        Ok(())
    });
    for id in [&x, &y] {
        assert_eq!(ws.governing(id), Governing::default());
        assert_eq!(ws.covered(id), Coverage::NotLinked);
    }
    ws.relate(&y, &spec);
    for id in [&x, &y] {
        assert_eq!(ids(&ws.governing(id)), [spec.as_str()], "{id}");
        assert_eq!(ws.covered(id), Coverage::Linked);
    }
    assert_eq!(ws.covered(&z), Coverage::NotLinked);
}

#[test]
fn the_descendant_bound_cuts_the_walk() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Spec", &["spec"], None);
    let epic = ws.task("Epic", None);
    let kids: Vec<String> = (0..5).map(|n| ws.task(&format!("Kid {n}"), Some(&epic))).collect();
    let three = Limits { descendants: 3, ..Limits::default() };
    let five = Limits { descendants: 5, ..Limits::default() };

    // Nothing linked: cut at 3, whole at 5 (exactly 5 descendants).
    assert_eq!(ws.governing_with(&epic, three).truncated, Some(Cap::Descendants));
    assert_eq!(ws.covered_with(&epic, three), Coverage::Unknown);
    assert_eq!(ws.governing_with(&epic, five).truncated, None);
    assert_eq!(ws.covered_with(&epic, five), Coverage::NotLinked);

    // The only link past the bound: unknown; within it: linked.
    let mut sorted = kids.clone();
    sorted.sort();
    ws.relate(&sorted[4], &spec);
    let g = ws.governing_with(&epic, three);
    assert_eq!(g, Governing { specs: vec![], truncated: Some(Cap::Descendants) });
    assert_eq!(ws.covered_with(&epic, three), Coverage::Unknown);
    assert_eq!(ids(&ws.governing_with(&epic, five)), [spec.as_str()]);
    assert_eq!(ws.covered_with(&epic, five), Coverage::Linked);
    ws.relate(&sorted[0], &spec);
    let g = ws.governing_with(&epic, three);
    assert_eq!((ids(&g), g.truncated), (vec![spec.as_str()], Some(Cap::Descendants)));
    assert_eq!(ws.covered_with(&epic, three), Coverage::Linked);

    // A grandchild past the bound, under a node reached within it.
    let top = ws.task("Top", None);
    let a = ws.task("A", Some(&top));
    ws.task("B", Some(&top));
    ws.task("C", Some(&a));
    let two = Limits { descendants: 2, ..Limits::default() };
    assert_eq!(ws.governing_with(&top, two).truncated, Some(Cap::Descendants));
    let three_ok = Limits { descendants: 3, ..Limits::default() };
    assert_eq!(ws.governing_with(&top, three_ok).truncated, None);
}

#[test]
fn the_edge_bound_cuts_the_walk() {
    let mut ws = Ws::new();
    let spec = ws.pinned("Spec", &["spec"], None);
    let work = ws.task("Work", None);
    let others: Vec<String> = (0..5).map(|n| ws.task(&format!("Other {n}"), None)).collect();
    for o in &others {
        ws.relate(&work, o);
    }
    let three = Limits { edges: 3, ..Limits::default() };
    assert_eq!(ws.governing_with(&work, three).truncated, Some(Cap::Edges));
    assert_eq!(ws.covered_with(&work, three), Coverage::Unknown);
    let five = Limits { edges: 5, ..Limits::default() };
    assert_eq!(ws.governing_with(&work, five).truncated, None);
    assert_eq!(ws.covered_with(&work, five), Coverage::NotLinked);
    // The edges count over the whole lineage: a parent's edge crosses the bound.
    let kid = ws.task("Kid", Some(&work));
    ws.relate(&kid, &spec);
    assert_eq!(ws.governing_with(&work, five).truncated, Some(Cap::Edges));
    let six = Limits { edges: 6, ..Limits::default() };
    let g = ws.governing_with(&work, six);
    assert_eq!((ids(&g), g.truncated), (vec![spec.as_str()], None));
}

#[test]
fn spec_none_covers_the_issue_but_governs_nothing() {
    let mut ws = Ws::new();
    let parent = ws.task("Parent", None);
    let none = ws.create(titled("Docs typo", &[NONE], Some(&parent)));
    assert_eq!(ws.covered(&none), Coverage::Linked);
    assert_eq!(ws.governing(&none), Governing::default());
    // It covers only itself.
    assert_eq!(ws.covered(&parent), Coverage::NotLinked);
}

/// xorshift64: seeded, no test-only crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// On seeded graphs of about 30 issues (spec trees, a forest of work,
/// links between them and among the specs, `spec:none`), an issue is
/// covered exactly when `specs::linked` holds it.
#[test]
fn covered_agrees_with_linked() {
    let (mut yes, mut no) = (0, 0);
    for seed in 1..=12u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut ws = Ws::new();
        let mut parts: Vec<String> = Vec::new();
        let mut all = Vec::new();
        for s in 0..3 {
            let parent = if s == 2 { Some(parts[0].clone()) } else { None };
            let spec = ws.pinned(&format!("Spec {s}"), &["spec"], parent.as_deref());
            parts.push(spec.clone());
            for r in 0..2 {
                let label = if r == 1 { NON_GOAL } else { REQUIREMENT };
                parts.push(ws.pinned(&format!("Part {s}.{r}"), &[label], Some(&spec)));
            }
        }
        all.extend(parts.iter().cloned());
        let mut work: Vec<String> = Vec::new();
        for n in 0..21 {
            let parent =
                if !work.is_empty() && rng.below(3) > 0 { Some(work[rng.below(work.len())].clone()) } else { None };
            let labels: &[&str] = if rng.below(10) == 0 { &[NONE] } else { &[] };
            let id = ws.create(titled(&format!("Work {n}"), labels, parent.as_deref()));
            work.push(id);
        }
        all.extend(work.iter().cloned());
        // Each pair related once, in either direction.
        let mut pairs: HashSet<(String, String)> = HashSet::new();
        let mut relate = |ws: &mut Ws, a: &str, b: &str| {
            let key = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
            if a != b && pairs.insert(key) {
                // A pair already parent and child is refused: skip it.
                let (f, t) = (a.to_string(), b.to_string());
                ws.clock.advance(Duration::from_secs(60));
                let _ = ws.store.write("test", "alice", |tx| tx.add_dependency(&f, &t, DepType::Related, None));
            }
        };
        for _ in 0..4 {
            let (w, p) = (work[rng.below(work.len())].clone(), parts[rng.below(parts.len())].clone());
            if rng.below(2) == 0 { relate(&mut ws, &w, &p) } else { relate(&mut ws, &p, &w) }
        }
        // Links that do not count: work to work.
        for _ in 0..3 {
            let (a, b) = (work[rng.below(work.len())].clone(), work[rng.below(work.len())].clone());
            relate(&mut ws, &a, &b);
        }
        // A spec related to another spec's part.
        if rng.below(2) == 0 {
            let (a, b) = (parts[3].clone(), parts[1].clone());
            relate(&mut ws, &a, &b);
        }
        let linked = ws.store.read(|r| specs::linked(r.conn())).unwrap();
        for id in &all {
            let c = ws.covered(id);
            if c == Coverage::Linked {
                yes += 1
            } else {
                no += 1
            }
            assert_ne!(c, Coverage::Unknown, "seed {seed}: {id}");
            assert_eq!(c == Coverage::Linked, linked.contains(id), "seed {seed}: {id} {c:?} vs {linked:?}");
            // Governing specs exist exactly when a link (not spec:none) covers it.
            let has_none = ws.store.read(|r| Ok(issues::get(r.conn(), id)?.unwrap().labels)).unwrap();
            if !has_none.iter().any(|l| l == NONE) {
                assert_eq!(!ws.governing(id).specs.is_empty(), c == Coverage::Linked, "seed {seed}: {id}");
            }
        }
    }
    assert!(yes > 30 && no > 30, "both kinds seen: {yes} linked, {no} not");
}
