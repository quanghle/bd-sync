//! The spec tree over issues held in memory (the cases of the former
//! `spec.mjs` tests), then links, drift and candidates over a workspace.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::model::{DepType, IssuePatch, NewIssue};
use crate::store::{InitOptions, OpenOptions, Store, WriteCtx};
use crate::time::{Clock, ManualClock};
use crate::{CloseOptions, Guard, IdMode, Queries};

/// Issues in memory: children in the order given.
struct Mem(Vec<Node>);

impl Source for Mem {
    fn node(&self, id: &str) -> Result<Option<Node>> {
        Ok(self.0.iter().find(|n| n.id == id).cloned())
    }

    fn kids(&self, id: &str) -> Result<Vec<String>> {
        Ok(self.0.iter().filter(|n| n.parent.as_deref() == Some(id)).map(|n| n.id.clone()).collect())
    }
}

fn node(id: &str, title: &str, status: Status, labels: &[&str], parent: Option<&str>) -> Node {
    Node {
        id: id.into(),
        title: title.into(),
        description: String::new(),
        status,
        labels: labels.iter().map(|l| l.to_string()).collect(),
        parent: parent.map(String::from),
        created_at: Timestamp(0),
        related: Vec::new(),
        supersedes: Vec::new(),
        close_reason: None,
        closed_at: None,
    }
}

/// A requirement: pinned, created in the order of its id's last digit, its parent the id before the last dot.
fn req(id: &str, title: &str) -> Node {
    let parent = id.rsplit_once('.').map(|(p, _)| p);
    let mut n = node(id, title, Status::Pinned, &["requirement"], parent);
    n.created_at = Timestamp(id.chars().last().and_then(|c| c.to_digit(10)).unwrap_or(0) as i64);
    n
}

fn non_goal(id: &str, title: &str) -> Node {
    Node { labels: vec!["non-goal".into()], ..req(id, title) }
}

fn sp(id: &str, title: &str, parent: Option<&str>) -> Node {
    node(id, title, Status::Pinned, &["spec", "area:checkout"], parent)
}

fn closed(n: Node) -> Node {
    Node { status: Status::Closed, ..n }
}

fn labels_spec() -> Node {
    Node {
        description: "Labels on issues.".into(),
        ..node("s", "Spec: labels", Status::Pinned, &["spec", "area:labels"], None)
    }
}

fn labels_children() -> Vec<Node> {
    vec![
        Node { related: vec!["bd-w2".into()], ..req("s.3", "Labels are case-insensitive") },
        Node {
            related: vec!["bd-w1".into()],
            description: "With -l.\nRepeatable.".into(),
            ..req("s.1", "Labels can be set at create")
        },
        Node {
            status: Status::Closed,
            supersedes: vec!["s.3".into()],
            related: vec!["bd-w1".into()],
            close_reason: Some("superseded by s.3".into()),
            ..req("s.2", "Labels are case-sensitive")
        },
        non_goal("s.4", "No label hierarchy"),
        Node { status: Status::Open, ..req("s.7", "Labels show in brief output\u{202e}") },
        Node {
            status: Status::Closed,
            close_reason: Some("Removed: dropped in bd-w3\u{1b}[31m".into()),
            ..req("s.5", "Labels have colours")
        },
        node("s.6", "Not a requirement", Status::Closed, &[], Some("s")),
    ]
}

/// Checkout (c) holds Cart (c.1) and Payment (c.2), which holds Saved cards (c.2.1); Receipts (r) is another spec
/// of the same area.
fn checkout() -> Vec<Node> {
    vec![
        sp("c", "Checkout", None),
        req("c.9", "Requires sign-in"),
        non_goal("c.8", "No guest checkout"),
        sp("c.1", "Cart", Some("c")),
        req("c.1.9", "Shows the total"),
        sp("c.2", "Payment", Some("c")),
        req("c.2.9", "Accepts cards"),
        sp("c.2.1", "Saved cards", Some("c.2")),
        req("c.2.1.9", "Lists saved cards"),
        closed(sp("c.3", "Old page", Some("c"))),
        sp("r", "Receipts", None),
    ]
}

fn specs_of(nodes: &[Node]) -> Vec<Node> {
    nodes.iter().filter(|n| n.is_spec()).cloned().collect()
}

fn get(nodes: &[Node], id: &str) -> Node {
    nodes.iter().find(|n| n.id == id).unwrap().clone()
}

fn ids(views: &[SpecView]) -> Vec<(String, Vec<String>)> {
    views.iter().map(|v| (v.spec.id.clone(), v.subspecs.iter().map(|s| s.spec.id.clone()).collect())).collect()
}

fn item_ids(items: &[Item]) -> Vec<&str> {
    items.iter().map(|i| i.id.as_str()).collect()
}

#[test]
fn finds_a_spec_by_id_or_every_open_spec_of_an_area_in_id_order() {
    let spec = labels_spec();
    let other = Node { id: "o".into(), labels: vec!["spec".into(), "area:query".into()], ..spec.clone() };
    let both = [spec.clone(), other.clone()];
    assert_eq!(find_specs(&both, "o").unwrap(), [other]);
    assert_eq!(find_specs(&both, "labels").unwrap(), std::slice::from_ref(&spec));
    let t = Node { id: "t".into(), ..spec.clone() };
    let u = Node { id: "u".into(), status: Status::Closed, ..spec.clone() };
    assert_eq!(find_specs(&[t.clone(), spec.clone(), u], "labels").unwrap(), [spec.clone(), t]);
    let e = find_specs(&[spec], "nope").unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert!(e.to_string().contains("nope (name a spec issue's id or its area:<name> label)"), "{e}");
}

#[test]
fn lists_requirements_in_force_in_creation_order_with_their_sources() {
    let view = spec_view(&labels_spec(), &labels_children());
    let reqs: Vec<(&str, Vec<String>)> = view.requirements.iter().map(|r| (r.id.as_str(), r.sources.clone())).collect();
    assert_eq!(reqs, [("s.1", vec!["bd-w1".to_string()]), ("s.3", vec!["bd-w2".to_string()]), ("s.7", vec![])]);
    assert_eq!(item_ids(&view.non_goals), ["s.4"]);
}

#[test]
fn warns_about_a_requirement_neither_pinned_nor_closed_direction_controls_dropped() {
    let view = spec_view(&labels_spec(), &labels_children());
    assert_eq!(view.warnings, ["s.7 is open, not pinned: pin it (bd update s.7 --status pinned) or close it"]);
    assert_eq!(view.requirements.last().unwrap().title, "Labels show in brief output");
    assert!(render(&view, false, 1).contains("> Warning: s.7 is open"));
}

#[test]
fn keeps_closed_requirements_as_history_control_characters_dropped() {
    let view = spec_view(&labels_spec(), &labels_children());
    let history: Vec<(&str, &str, Option<&str>, &str)> =
        view.history.iter().map(|h| (h.item.id.as_str(), h.outcome, h.by.as_deref(), h.reason.as_str())).collect();
    assert_eq!(
        history,
        [
            ("s.2", "superseded", Some("s.3"), "superseded by s.3"),
            ("s.5", "removed", None, "Removed: dropped in bd-w3[31m"),
        ]
    );
}

#[test]
fn nests_sub_specs_leaving_out_roots_another_root_contains_and_closed_sub_specs() {
    let tree = checkout();
    let src = Mem(tree.clone());
    let views = spec_views(&find_specs(&specs_of(&tree), "checkout").unwrap(), &src).unwrap();
    assert_eq!(ids(&views), [("c".to_string(), vec!["c.1".to_string(), "c.2".to_string()]), ("r".to_string(), vec![])]);
    assert_eq!(ids(&views[0].subspecs[1].subspecs), [("c.2.1".to_string(), vec![])]);
    assert_eq!(item_ids(&views[0].requirements), ["c.9"]);
    assert_eq!(item_ids(&views[0].subspecs[1].requirements), ["c.2.9"]);
    assert!(views[0].inherited.is_empty());
}

#[test]
fn gives_a_sub_spec_the_requirements_in_force_of_its_ancestors_outermost_first() {
    let tree = checkout();
    let src = Mem(tree.clone());
    let [view] = <[SpecView; 1]>::try_from(spec_views(&[get(&tree, "c.2.1")], &src).unwrap()).unwrap();
    let inherited: Vec<(&str, Vec<&str>, Vec<&str>)> = view
        .inherited
        .iter()
        .map(|a| (a.spec.id.as_str(), item_ids(&a.requirements), item_ids(&a.non_goals)))
        .collect();
    assert_eq!(inherited, [("c", vec!["c.9"], vec!["c.8"]), ("c.2", vec!["c.2.9"], vec![])]);
    assert!(render(&view, false, 1).contains(
        "## Inherited\n\n- Requires sign-in (c.9; spec c)\n- Non-goal: No guest checkout (c.8; spec c)\n- Accepts cards (c.2.9; spec c.2)\n"
    ));
}

#[test]
fn renders_sub_specs_one_heading_level_deeper() {
    let tree = checkout();
    let md = render(&spec_views(&[get(&tree, "c")], &Mem(tree.clone())).unwrap()[0], false, 1);
    assert!(md.contains("## Sub-feature: Payment (c.2)\n\n### Requirements\n\n- Accepts cards (c.2.9)\n"), "{md}");
    assert!(
        md.contains("### Sub-feature: Saved cards (c.2.1)\n\n#### Requirements\n\n- Lists saved cards (c.2.1.9)\n")
    );
    assert!(!md.contains("Inherited"));
}

#[test]
fn fills_inherited_on_nested_views_and_passes_no_closed_requirement_down() {
    let tree = checkout();
    let views = spec_views(&[get(&tree, "c")], &Mem(tree.clone())).unwrap();
    let saved = &views[0].subspecs[1].subspecs[0];
    let inherited: Vec<(&str, Vec<&str>)> =
        saved.inherited.iter().map(|a| (a.spec.id.as_str(), item_ids(&a.requirements))).collect();
    assert_eq!(inherited, [("c", vec!["c.9"]), ("c.2", vec!["c.2.9"])]);
}

#[test]
fn an_open_spec_under_a_closed_one_is_an_error_and_a_non_spec_parent_a_warning() {
    let issues = vec![
        sp("a", "A", None),
        req("a.9", "A rule"),
        closed(sp("a.1", "Closed B", Some("a"))),
        req("a.1.9", "B rule"),
        sp("a.1.1", "C", Some("a.1")),
        req("a.1.1.9", "C rule"),
        node("a.2", "An epic", Status::Open, &[], Some("a")),
        sp("a.2.1", "D", Some("a.2")),
    ];
    let src = Mem(issues.clone());
    let views = spec_views(&find_specs(&specs_of(&issues), "checkout").unwrap(), &src).unwrap();
    assert_eq!(views.iter().map(|v| v.spec.id.as_str()).collect::<Vec<_>>(), ["a", "a.1.1", "a.2.1"]);
    let (c, d) = (&views[1], &views[2]);
    assert!(c.inherited.is_empty());
    assert!(c.warnings.is_empty());
    assert_eq!(
        c.errors,
        [
            "a.1.1 is open but its parent spec a.1 is closed, so it inherits nothing. Fix: reopen a.1 if it was closed by mistake \
          (bd reopen a.1, then bd update a.1 --status pinned); close a.1.1 if the feature was retired (its requirements and \
          sub-specs first, deepest first); or move a.1.1 under the spec that replaced a.1 (bd update a.1.1 --parent <spec>)."
        ]
    );
    let retired = vec![closed(sp("w", "W", None)), closed(sp("w.1", "V", Some("w")))];
    assert!(spec_views(&[retired[1].clone()], &Mem(retired.clone())).unwrap()[0].errors.is_empty());
    assert_eq!(item_ids(&c.requirements), ["a.1.1.9"]);
    assert!(render(c, false, 1).contains("> Error: a.1.1 is open but its parent spec a.1 is closed"));
    assert!(views[0].errors.is_empty());
    assert_eq!(d.warnings, ["a.2.1's parent a.2 is not a spec: spec a above it is not inherited"]);
    let under_epic = vec![
        node("e", "Epic", Status::Open, &[], None),
        sp("e.1", "Top spec", Some("e")),
        sp("x", "Orphan", Some("gone")),
    ];
    let views = spec_views(&[under_epic[1].clone(), under_epic[2].clone()], &Mem(under_epic.clone())).unwrap();
    assert!(views.iter().all(|v| v.warnings.is_empty()), "{views:?}");
    assert!(ancestors("a.1.1", &src).unwrap().chain.is_empty());
}

#[test]
fn carries_an_inherited_requirements_warning_to_the_view_that_inherits_it() {
    let issues =
        vec![sp("a", "A", None), Node { status: Status::Open, ..req("a.9", "Open rule") }, sp("a.1", "B", Some("a"))];
    let views = spec_views(&[issues[2].clone()], &Mem(issues.clone())).unwrap();
    assert_eq!(
        views[0].warnings,
        ["inherited from a: a.9 is open, not pinned: pin it (bd update a.9 --status pinned) or close it"]
    );
}

#[test]
fn stops_at_the_depth_bound_with_a_warning_and_shows_a_root_past_it_on_its_own() {
    let deep: Vec<Node> = (0..MAX_DEPTH + 3)
        .map(|i| {
            let parent = (i > 0).then(|| format!("d{}", i - 1));
            sp(&format!("d{i}"), &format!("Level {i}"), parent.as_deref())
        })
        .collect();
    let src = Mem(deep.clone());
    let views = spec_views(&[deep[0].clone(), deep[MAX_DEPTH].clone()], &src).unwrap();
    let mut v = &views[0];
    for _ in 1..MAX_DEPTH {
        v = &v.subspecs[0];
    }
    assert!(v.subspecs.is_empty());
    assert_eq!(v.warnings, [format!("sub-spec d{MAX_DEPTH} not shown here: deeper than {MAX_DEPTH} levels")]);
    assert_eq!(
        views.iter().map(|x| x.spec.id.clone()).collect::<Vec<_>>(),
        ["d0".to_string(), format!("d{MAX_DEPTH}")]
    );
    let up = ancestors(&format!("d{}", MAX_DEPTH + 2), &src).unwrap();
    assert_eq!(up.chain.len(), MAX_DEPTH);
    assert_eq!(
        up.warnings,
        [format!("d{} is nested deeper than {MAX_DEPTH} specs: nothing above d2 is inherited", MAX_DEPTH + 2)]
    );
}

#[test]
fn stops_at_a_cycle_with_a_warning() {
    let lp = vec![sp("a", "A", Some("b")), sp("b", "B", Some("a"))];
    let src = Mem(lp.clone());
    let views = spec_views(&[lp[0].clone()], &src).unwrap();
    assert_eq!(views[0].subspecs[0].warnings, ["a is its own ancestor: not shown again"]);
    assert_eq!(
        ancestors("a", &src).unwrap(),
        Ancestry {
            chain: vec![lp[1].clone()],
            warnings: vec!["a is its own ancestor: the chain stops there".into()],
            errors: vec![]
        }
    );
}

#[test]
fn renders_requirements_and_non_goals_and_history_only_when_asked() {
    let view = spec_view(&labels_spec(), &labels_children());
    let md = render(&view, false, 1);
    assert!(md.contains("# Spec: labels (s)\n\nLabels on issues.\n"), "{md}");
    assert!(md.contains(
        "## Requirements\n\n- Labels can be set at create (s.1; from bd-w1)\n  With -l.\n  Repeatable.\n- Labels are case-insensitive (s.3; from bd-w2)\n"
    ));
    assert!(md.contains("## Non-goals\n\n- No label hierarchy (s.4)\n"));
    assert!(!md.contains("History"));
    let full = render(&view, true, 1);
    assert!(full.contains("- ~~Labels are case-sensitive~~ superseded by s.3 (s.2; from bd-w1)"));
    assert!(full.contains("- ~~Labels have colours~~ removed: dropped in bd-w3[31m (s.5)"));
    assert!(render(&spec_view(&labels_spec(), &[]), false, 1).contains("## Requirements\n\nNone recorded.\n"));
}

// ---------------------------------------------------------------------------
// Over a workspace.

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
        Ws { _dir: dir, store, clock }
    }

    fn write<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.clock.advance(Duration::from_secs(60));
        self.store.write("test", "alice", f).unwrap()
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.write(|tx| tx.create_issue(new)).id
    }

    fn close(&mut self, id: &str) {
        let id = id.to_string();
        self.write(|tx| tx.close_issue(&id, &CloseOptions { force: true, ..Default::default() }));
    }

    fn config(&mut self, key: &str, value: &str) {
        self.write(|tx| config::set(tx, key, value));
    }

    fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> T {
        self.store.read(|r| f(r.conn())).unwrap()
    }
}

fn titled(title: &str, labels: &[&str], parent: Option<&str>) -> NewIssue {
    NewIssue {
        labels: labels.iter().map(|l| l.to_string()).collect(),
        parent: parent.map(String::from),
        ..NewIssue::titled(title)
    }
}

fn pinned(title: &str, labels: &[&str], parent: Option<&str>) -> NewIssue {
    NewIssue { status: Some(Status::Pinned), ..titled(title, labels, parent) }
}

fn ref_ids(refs: &[IssueRef]) -> Vec<&str> {
    refs.iter().map(|r| r.id.as_str()).collect()
}

#[test]
fn turning_specs_on_sets_since_turning_off_keeps_it_and_on_again_resets_it() {
    let mut ws = Ws::new();
    assert_eq!(ws.read(since), None);
    ws.config("experimental.features", "specs");
    let first = ws.read(since).expect("set when turned on");
    assert_eq!(first, ws.clock.now());
    let mut events = ws.store.read(|r| r.events(&Default::default())).unwrap().events;
    events.sort_by_key(|e| e.seq);
    let keys: Vec<&str> =
        events.iter().filter(|e| e.op == "config_set").filter_map(|e| e.data["key"].as_str()).collect();
    assert_eq!(keys[keys.len() - 2..], ["experimental.features", SINCE_KEY], "each its own config_set event");
    ws.config("experimental.features", "");
    assert_eq!(ws.read(since), Some(first), "off keeps it");
    ws.config("experimental.features", "specs");
    let again = ws.read(since).unwrap();
    assert!(again > first, "on again resets it");
    // Setting the features to what they are changes nothing.
    ws.config("experimental.features", "specs");
    assert_eq!(ws.read(since), Some(again));
    // Backdating: any time bd parses, stored as RFC 3339.
    ws.config(SINCE_KEY, "2023-01-15T09:00:00Z");
    assert_eq!(ws.read(|c| config::get(c, SINCE_KEY)).as_deref(), Some("2023-01-15T09:00:00.000Z"));
    // Never in the future.
    let future = ws.store.write("test", "alice", |tx| config::set(tx, SINCE_KEY, "+1d")).unwrap_err();
    assert_eq!(future.exit_code(), 2);
    assert!(future.to_string().contains("in the future"), "{future}");
    ws.config(SINCE_KEY, "1d");
    assert_eq!(ws.read(since), Some(ws.clock.now().minus(Duration::from_secs(86_400))));
    let bad = ws.store.write("test", "alice", |tx| config::set(tx, SINCE_KEY, "soon")).unwrap_err();
    assert!(bad.to_string().contains(SINCE_KEY), "{bad}");
    let listed = ws.read(config::list);
    assert!(listed.iter().any(|e| e.key == SINCE_KEY), "config list shows it");
}

#[test]
fn require_on_refuses_while_specs_are_off() {
    let mut ws = Ws::new();
    let e = ws.store.read(|r| require_on(r.conn())).unwrap_err();
    assert_eq!((e.exit_code(), e.to_string()), (2, OFF.to_string()));
    ws.config("experimental.features", "specs");
    ws.read(require_on);
}

#[test]
fn show_reads_the_tree_from_the_workspace() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let work = ws.create(NewIssue::titled("Build checkout"));
    let r1 = ws.create(NewIssue {
        deps: vec![(DepType::Related, work.clone())],
        ..pinned("Requires sign-in", &["requirement"], Some(&spec))
    });
    let r2 = ws.create(pinned("Guests may check out", &["requirement"], Some(&spec)));
    let sub = ws.create(pinned("Payment", &["spec", "area:checkout"], Some(&spec)));
    ws.create(pinned("Accepts cards", &["requirement"], Some(&sub)));
    let (r2c, sub2) = (r2.clone(), r1.clone());
    ws.write(|tx| {
        tx.close_as(&r2c, &sub2, crate::Replacement::Supersede, &Default::default())?;
        Ok(())
    });
    // A later link from other work to the requirement links that work, but is not a source.
    let later = ws.create(NewIssue { deps: vec![(DepType::Related, r1.clone())], ..NewIssue::titled("Fix sign-in") });

    let views = ws.read(|c| show(c, "checkout"));
    assert_eq!(views.len(), 1, "the sub-spec is shown inside its spec");
    assert_eq!(views[0].requirements[0].sources, std::slice::from_ref(&work));
    assert!(!render(&views[0], false, 1).contains(&later), "an incoming link is not a source");
    assert!(ws.read(linked).contains(&later));
    assert_eq!(views[0].history[0].by.as_deref(), Some(r1.as_str()));
    assert_eq!(views[0].subspecs[0].inherited[0].requirements[0].id, r1);
    let md = render(&views[0], true, 1);
    assert!(md.contains(&format!("~~Guests may check out~~ superseded by {r1}")), "{md}");
    // By id, by the short id, and an unknown name.
    assert_eq!(ws.read(|c| show(c, &sub))[0].inherited.len(), 1);
    assert_eq!(ws.read(|c| show(c, sub.trim_start_matches("t-")))[0].spec.id, sub);
    let e = ws.store.read(|r| show(r.conn(), "nope")).unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert!(ws.store.read(|r| show(r.conn(), &work)).is_err(), "not a spec");

    let list = ws.read(list);
    assert_eq!(list.len(), 2);
    assert_eq!((list[0].requirements, list[0].non_goals, list[0].linked), (1, 0, 2));
    assert_eq!(list[0].areas, ["checkout"]);
    assert_eq!(list[1].parent.as_deref(), Some(spec.as_str()));
    assert_eq!(ws.read(open_count), 2);
}

#[test]
fn linked_issues_are_those_related_to_specs_marked_none_and_their_ancestors() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let req = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let epic = ws.create(NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled("Epic") });
    let task = ws.create(titled("Task", &[], Some(&epic)));
    let run = ws.create(NewIssue {
        issue_type: Some("epic".into()),
        metadata: Some(json!({ "playbook": { "role": "run" } })),
        ..titled("Run", &[], Some(&task))
    });
    let (r, q) = (run.clone(), req.clone());
    ws.write(|tx| tx.add_dependency(&q, &r, DepType::Related, None));
    let to_spec = ws.create(NewIssue { deps: vec![(DepType::Related, spec.clone())], ..NewIssue::titled("To spec") });
    let none = ws.create(titled("Refactor", &[NONE], None));
    let other = ws.create(NewIssue::titled("Other"));
    let linked = ws.read(linked);
    for id in [&run, &task, &epic, &to_spec, &none] {
        assert!(linked.contains(id), "{id} in {linked:?}");
    }
    assert!(!linked.contains(&other));
}

#[test]
fn exempt_kinds_never_drift() {
    let mut ws = Ws::new();
    let step_meta = json!({ "playbook": { "role": "step" } });
    let step = ws.create(NewIssue { metadata: Some(step_meta), ..NewIssue::titled("Step") });
    let finding = ws.create(titled("Finding", &[], Some(&step)));
    let decision = ws.create(NewIssue { issue_type: Some("decision".into()), ..NewIssue::titled("Decision") });
    let scratch = ws.create(NewIssue { ephemeral: true, ..NewIssue::titled("Scratch") });
    let req = ws.create(titled("Rule", &["requirement"], None));
    let plain = ws.create(NewIssue::titled("Plain"));
    let child_of_plain = ws.create(titled("Child", &[], Some(&plain)));
    ws.read(|c| {
        for id in [&step, &finding, &decision, &scratch, &req] {
            assert!(is_exempt(c, &issues::require(c, id)?)?, "{id}");
        }
        for id in [&plain, &child_of_plain] {
            assert!(!is_exempt(c, &issues::require(c, id)?)?, "{id}");
        }
        Ok(())
    });
}

#[test]
fn drift_reports_each_kind_and_partitions_work_at_since() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let old = ws.create(titled("Before specs", &["area-ish"], None));
    ws.close(&old);
    ws.config("experimental.features", "specs");
    let since_at = ws.read(since).unwrap();

    let done = ws.create(NewIssue::titled("Done since"));
    ws.close(&done);
    let open = ws.create(NewIssue::titled("Open since"));
    let failed = ws.create(NewIssue::titled("Failed source"));
    let fid = failed.clone();
    ws.write(|tx| tx.close_issue(&fid, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() }));
    let reopened = ws.create(NewIssue::titled("Reopened source"));
    ws.close(&reopened);
    let held = ws.create(NewIssue {
        deps: vec![(DepType::Related, failed.clone()), (DepType::Related, reopened.clone())],
        ..pinned("Held rule", &["requirement"], Some(&spec))
    });
    let rid = reopened.clone();
    ws.write(|tx| tx.reopen_issue(&rid, None, false));
    let loose = ws.create(titled("Loose rule", &["non-goal"], Some(&spec)));
    let retired = ws.create(pinned("Retired", &["spec"], None));
    let sub = ws.create(pinned("Sub", &["spec"], Some(&retired)));
    ws.close(&retired);
    let marked = ws.create(NewIssue::titled("Marked none"));
    let mid = marked.clone();
    ws.write(|tx| {
        tx.update_issue(
            &mid,
            &IssuePatch { add_labels: vec![NONE.into()], ..Default::default() },
            &Guard::default(),
            false,
        )
    });
    ws.close(&marked);

    let d = ws.read(|c| drift(c, Some(since_at)));
    assert_eq!(d.since, Some(since_at));
    assert_eq!(ref_ids(&d.unlinked), [done.as_str()], "closed since, unlinked (a source is linked); not before since");
    let shaky: Vec<(&str, &str, &str)> =
        d.shaky.iter().map(|s| (s.requirement.id.as_str(), s.source.id.as_str(), s.why)).collect();
    assert_eq!(shaky, [(held.as_str(), failed.as_str(), "failed"), (held.as_str(), reopened.as_str(), "reopened")]);
    assert_eq!(ref_ids(&d.bad_status), [loose.as_str()]);
    assert_eq!(
        d.orphaned.iter().map(|o| (o.spec.id.as_str(), o.parent.as_str())).collect::<Vec<_>>(),
        [(sub.as_str(), retired.as_str())]
    );
    assert_eq!(ref_ids(&d.to_link), [open.as_str()], "open since, unlinked: the reopened one is linked");
    assert_eq!(d.count(), 1 + 2 + 1 + 1);

    // Without since, nothing is in the window.
    let none = ws.read(|c| drift(c, None));
    assert!(none.unlinked.is_empty() && none.to_link.is_empty());
    // A since before everything takes the old work in too.
    let all = ws.read(|c| drift(c, Some(Timestamp(0))));
    assert!(ref_ids(&all.unlinked).contains(&old.as_str()));
}

#[test]
fn candidates_are_closed_work_from_before_since_grouped() {
    let mut ws = Ws::new();
    let epic = ws.create(NewIssue { issue_type: Some("epic".into()), ..NewIssue::titled("Sign-in") });
    let inner = ws.create(NewIssue { issue_type: Some("epic".into()), ..titled("Inner", &[], Some(&epic)) });
    let a = ws.create(titled("A", &["auth"], Some(&inner)));
    let b = ws.create(titled("B", &[], Some(&epic)));
    let run = ws.create(NewIssue {
        issue_type: Some("epic".into()),
        metadata: Some(json!({ "playbook": { "role": "run" } })),
        ..NewIssue::titled("Run")
    });
    let c = ws.create(titled("C", &["change:small", "ui"], Some(&run)));
    let d = ws.create(titled("D", &["adr:1", "severity:low"], None));
    let e = ws.create(titled("E", &["ui"], None));
    let linked = ws.create(NewIssue::titled("Linked"));
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let (l, s) = (linked.clone(), spec.clone());
    ws.write(|tx| tx.add_dependency(&l, &s, DepType::Related, None));
    for id in [&a, &b, &c, &d, &e, &linked] {
        ws.close(id);
    }
    ws.close(&inner);
    let before = ws.clock.now().plus(Duration::from_secs(1));
    ws.clock.advance(Duration::from_secs(120));
    let late = ws.create(NewIssue::titled("Late"));
    ws.close(&late);

    let groups = ws.read(|c| candidates(c, Some(before)));
    let shape: Vec<(&str, Option<&str>, Vec<&str>)> = groups
        .iter()
        .map(|g| (g.key.as_str(), g.title.as_deref(), g.issues.iter().map(|i| i.id.as_str()).collect()))
        .collect();
    let epic_key = format!("epic:{epic}");
    assert_eq!(
        shape,
        [
            (epic_key.as_str(), Some("Sign-in"), vec![inner.as_str(), a.as_str(), b.as_str()]),
            ("label:ui", None, vec![c.as_str(), e.as_str()]),
            ("ungrouped", None, vec![d.as_str()]),
        ]
    );
    // Without since, every closed issue is a candidate.
    let every = ws.read(|c| candidates(c, None));
    assert!(every.iter().any(|g| g.issues.iter().any(|i| i.id == late)));
}

#[test]
fn sources_and_shaky_read_only_the_requirements_own_related_edges() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let req = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    // Open work linked to the requirement (the rule's own link): linked, not a source, not shaky.
    let w = ws.create(NewIssue { deps: vec![(DepType::Related, req.clone())], ..NewIssue::titled("Open work") });
    let d = ws.read(|c| drift(c, Some(Timestamp(0))));
    assert!(d.shaky.is_empty(), "{:?}", d.shaky);
    assert!(ws.read(linked).contains(&w));
    let views = ws.read(|c| show(c, &spec));
    assert!(views[0].requirements[0].sources.is_empty());
    // The requirement's own source still in progress (never closed, as the run whose spec step added it): not shaky.
    let src = ws.create(NewIssue::titled("Source"));
    let (r, s2) = (req.clone(), src.clone());
    ws.write(|tx| tx.add_dependency(&r, &s2, DepType::Related, None));
    let shaky = |ws: &Ws| -> Vec<(String, &'static str)> {
        ws.read(|c| drift(c, Some(Timestamp(0)))).shaky.into_iter().map(|s| (s.source.id, s.why)).collect()
    };
    assert!(shaky(&ws).is_empty(), "work in progress is not shaky");
    // Closed: settled.
    ws.close(&src);
    assert!(shaky(&ws).is_empty());
    // Closed, then reopened: shaky.
    let s3 = src.clone();
    ws.write(|tx| tx.reopen_issue(&s3, Some("broke"), false));
    assert_eq!(shaky(&ws), [(src.clone(), "reopened")]);
    // Closed again, as failed: shaky.
    let s4 = src.clone();
    ws.write(|tx| tx.close_issue(&s4, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() }));
    assert_eq!(shaky(&ws), [(src.clone(), "failed")]);
}

#[test]
fn a_spec_none_mark_covers_only_its_issue() {
    let mut ws = Ws::new();
    let parent = ws.create(NewIssue::titled("Parent"));
    let child = ws.create(titled("Child", &[NONE], Some(&parent)));
    let sibling = ws.create(titled("Sibling", &[], Some(&parent)));
    let linked = ws.read(linked);
    assert!(linked.contains(&child));
    assert!(!linked.contains(&parent) && !linked.contains(&sibling), "{linked:?}");
}

#[test]
fn a_direct_link_covers_the_subtree_below_it() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let epic = ws.create(NewIssue {
        issue_type: Some("epic".into()),
        deps: vec![(DepType::Related, spec.clone())],
        ..NewIssue::titled("Feature epic")
    });
    let task = ws.create(titled("Task", &[], Some(&epic)));
    let sub = ws.create(titled("Subtask", &[], Some(&task)));
    let other = ws.create(NewIssue::titled("Other"));
    let linked = ws.read(linked);
    for id in [&epic, &task, &sub] {
        assert!(linked.contains(id), "{id}");
    }
    assert!(!linked.contains(&other));
}

#[test]
fn failed_duplicate_superseded_and_work_under_steps_need_no_spec() {
    let mut ws = Ws::new();
    ws.config("experimental.features", "specs");
    let since_at = ws.read(since);
    let failed = ws.create(NewIssue::titled("Failed"));
    let f = failed.clone();
    ws.write(|tx| tx.close_issue(&f, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() }));
    let canonical = ws.create(NewIssue::titled("Canonical"));
    let dup = ws.create(NewIssue::titled("Dup"));
    let old = ws.create(NewIssue::titled("Old"));
    let (d, o, c) = (dup.clone(), old.clone(), canonical.clone());
    ws.write(|tx| {
        tx.close_as(&d, &c, crate::Replacement::Duplicate, &Default::default())?;
        tx.close_as(&o, &c, crate::Replacement::Supersede, &Default::default())
    });
    let step =
        ws.create(NewIssue { metadata: Some(json!({ "playbook": { "role": "step" } })), ..NewIssue::titled("Step") });
    let finding = ws.create(titled("Finding", &[], Some(&step)));
    let follow_up = ws.create(titled("Follow-up", &[], Some(&finding)));
    ws.close(&follow_up);
    ws.close(&finding);
    let drift = ws.read(|c| drift(c, since_at));
    // Only the open canonical issue is left to link.
    assert!(drift.unlinked.is_empty(), "{:?}", drift.unlinked);
    assert_eq!(ref_ids(&drift.to_link), [canonical.as_str()]);
    ws.read(|c| {
        for id in [&failed, &dup, &old, &finding, &follow_up] {
            assert!(is_exempt(c, &issues::require(c, id)?)?, "{id}");
        }
        Ok(())
    });
}

#[test]
fn list_counts_distinct_linked_issues_that_are_not_spec_parts() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Spec", &["spec"], None));
    let other = ws.create(pinned("Other spec", &["spec"], None));
    let a = ws.create(NewIssue::titled("A"));
    let b = ws.create(NewIssue::titled("B"));
    let req = ws.create(NewIssue {
        deps: vec![(DepType::Related, a.clone()), (DepType::Related, other.clone())],
        ..pinned("Rule", &["requirement"], Some(&spec))
    });
    let (b2, r, s, a2) = (b.clone(), req.clone(), spec.clone(), a.clone());
    ws.write(|tx| {
        tx.add_dependency(&b2, &r, DepType::Related, None)?;
        tx.add_dependency(&a2, &s, DepType::Related, None)
    });
    let list = ws.read(list);
    assert_eq!(list[0].id, spec);
    assert_eq!(list[0].linked, 2, "a (twice) and b; the other spec is a spec part");
}
