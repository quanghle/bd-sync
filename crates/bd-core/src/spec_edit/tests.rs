//! The writes of `bd spec` over a workspace: each rule, refusals that write
//! nothing, and `spec_change`'s all-or-nothing supersede.

use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;

use super::*;
use crate::claims::ClaimOptions;
use crate::config;
use crate::model::{IssuePatch, NewIssue};
use crate::specs::{self, OFF};
use crate::store::{InitOptions, OpenOptions, Store};
use crate::time::{ManualClock, Timestamp};
use crate::{Guard, IdMode};

struct Ws {
    _dir: tempfile::TempDir,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Ws {
    /// A workspace with specs off.
    fn off() -> Ws {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(Timestamp(1_700_000_000_000)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let store =
            Store::init(&dir.path().join("bd.db"), InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts)
                .unwrap();
        Ws { _dir: dir, store, clock }
    }

    /// A workspace with specs on.
    fn new() -> Ws {
        let mut ws = Ws::off();
        ws.write(|tx| config::set(tx, "experimental.features", "specs"));
        ws
    }

    fn try_as<T>(&mut self, actor: &str, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        self.clock.advance(Duration::from_secs(60));
        self.store.write("test", actor, f)
    }

    fn try_write<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        self.try_as("alice", f)
    }

    fn write<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.try_write(f).unwrap()
    }

    fn create(&mut self, new: NewIssue) -> String {
        self.write(|tx| tx.create_issue(new)).id
    }

    fn close(&mut self, id: &str) {
        let id = id.to_string();
        self.write(|tx| tx.close_issue(&id, &CloseOptions { force: true, ..Default::default() }));
    }

    fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> T {
        self.store.read(|r| f(r.conn())).unwrap()
    }

    fn issue(&self, id: &str) -> Issue {
        self.read(|c| issues::require(c, id))
    }

    /// (issues, edges, events): what a refusal must leave unchanged.
    fn counts(&self) -> (i64, i64, i64) {
        self.read(|c| {
            let n = |sql: &str| c.query_row(sql, [], |r| r.get::<_, i64>(0));
            Ok((
                n("SELECT count(*) FROM issues")?,
                n("SELECT count(*) FROM dependencies")?,
                n("SELECT count(*) FROM events")?,
            ))
        })
    }

    fn edge(&self, from: &str, to: &str) -> Option<DepType> {
        self.read(|c| graph::load_edge(c, from, to)).map(|e| e.dep_type)
    }

    fn work(&mut self, title: &str) -> String {
        self.create(NewIssue::titled(title))
    }

    /// A pinned spec in area `checkout`.
    fn spec(&mut self) -> String {
        let s = sentence("Checkout", &[]);
        self.write(|tx| tx.spec_new("checkout", &s, None)).spec.id
    }

    fn add(&mut self, spec: &str, title: &str, from: &[&str], non_goal: bool) -> String {
        let s = sentence(title, from);
        self.write(|tx| tx.spec_add(spec, &s, non_goal)).requirement.id
    }

    fn set_status(&mut self, id: &str, status: Status) {
        let id = id.to_string();
        self.write(|tx| {
            tx.update_issue(&id, &IssuePatch { status: Some(status), ..Default::default() }, &Guard::default(), false)
        });
    }
}

fn sentence(title: &str, from: &[&str]) -> Sentence {
    Sentence { title: title.into(), description: String::new(), from: from.iter().map(|s| s.to_string()).collect() }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The error of a refused write, checking that it wrote nothing.
fn refused<T: std::fmt::Debug>(ws: &mut Ws, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Error {
    let before = ws.counts();
    let err = ws.try_write(f).unwrap_err();
    assert_eq!(ws.counts(), before, "a refusal writes nothing ({err})");
    err
}

fn is_invalid(e: &Error) -> bool {
    matches!(e, Error::Invalid(_))
}

fn is_refused(e: &Error) -> bool {
    matches!(e, Error::Refused(_))
}

#[test]
fn every_write_is_refused_while_specs_are_off() {
    let mut ws = Ws::off();
    let s = sentence("Rule", &["t-404"]);
    let checks: Vec<Error> = vec![
        refused(&mut ws, |tx| tx.spec_new("checkout", &s, Some("t-404"))),
        refused(&mut ws, |tx| tx.spec_add("t-404", &s, false)),
        refused(&mut ws, |tx| tx.spec_change("t-404", &s)),
        refused(&mut ws, |tx| tx.spec_remove("t-404", "obsolete", &[])),
        refused(&mut ws, |tx| tx.spec_link("t-404", &strings(&["t-405"]))),
    ];
    for e in checks {
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains(OFF), "{e}");
    }
}

#[test]
fn check_area_takes_plain_names_only() {
    for ok in ["checkout", "a/b.c-d_e", "A9", &"x".repeat(64)] {
        assert!(check_area(ok).is_ok(), "{ok}");
    }
    for bad in ["", &"x".repeat(65), "a b", "a,b", "a\u{7}b", "é"] {
        let e = check_area(bad).unwrap_err();
        assert!(is_invalid(&e) && e.to_string().contains("invalid area"), "{bad:?}: {e}");
    }
}

#[test]
fn new_creates_a_pinned_feature_labelled_spec_and_area() {
    let mut ws = Ws::new();
    let w = ws.work("Design");
    let s = Sentence { description: "What it is.".into(), ..sentence("Checkout", &[&w, &w]) };
    let out = ws.write(|tx| tx.spec_new("checkout", &s, None));
    assert_eq!(out.spec.status, Status::Pinned);
    assert_eq!(out.spec.issue_type, "feature");
    assert_eq!(out.spec.description, "What it is.");
    let mut labels = out.spec.labels.clone();
    labels.sort();
    assert_eq!(labels, ["area:checkout", "spec"]);
    assert_eq!((out.area.as_str(), out.parent.as_deref()), ("checkout", None));
    assert_eq!(out.sources, std::slice::from_ref(&w), "deduplicated");
    assert_eq!(ws.edge(&out.spec.id, &w), Some(DepType::Related));
    let json = serde_json::to_value(&out).unwrap();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["area", "parent", "sources", "spec"]);

    let sub = ws.write(|tx| tx.spec_new("checkout", &sentence("Payments", &[]), Some(&out.spec.id)));
    assert_eq!(sub.parent.as_deref(), Some(out.spec.id.as_str()));
    assert_eq!(ws.edge(&sub.spec.id, &out.spec.id), Some(DepType::ParentChild));
    let list = ws.read(specs::list);
    assert_eq!(list.iter().find(|l| l.id == sub.spec.id).unwrap().parent.as_deref(), Some(out.spec.id.as_str()));
}

#[test]
fn new_refuses_a_parent_not_in_force_and_a_bad_area() {
    let mut ws = Ws::new();
    let w = ws.work("Plain work");
    let s = sentence("Payments", &[]);
    let e = refused(&mut ws, |tx| tx.spec_new("checkout", &s, Some(&w)));
    assert!(is_invalid(&e) && e.to_string().contains("is not a spec"), "{e}");

    let unpinned = ws.spec();
    ws.set_status(&unpinned, Status::Open);
    let e = refused(&mut ws, |tx| tx.spec_new("checkout", &s, Some(&unpinned)));
    assert!(is_refused(&e) && e.to_string().contains(&format!("bd update {unpinned} --status pinned")), "{e}");

    let closed = ws.spec();
    ws.close(&closed);
    let e = refused(&mut ws, |tx| tx.spec_new("checkout", &s, Some(&closed)));
    assert!(is_refused(&e) && e.to_string().contains("closed spec"), "{e}");

    let e = refused(&mut ws, |tx| tx.spec_new("check out", &s, None));
    assert!(is_invalid(&e), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_new("checkout", &s, Some("t-404")));
    assert_eq!(e.exit_code(), 3, "{e}");
}

#[test]
fn add_creates_requirements_and_non_goals_with_their_sources() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w1 = ws.work("Build it");
    let w2 = ws.work("Old work");
    ws.close(&w2);
    let s = sentence("Requires sign-in", &[&w1, &w2, &w1]);
    let out = ws.write(|tx| tx.spec_add(&spec, &s, false));
    let r = &out.requirement;
    assert_eq!(
        (r.status, r.issue_type.as_str(), r.labels.clone()),
        (Status::Pinned, "story", strings(&["requirement"]))
    );
    assert_eq!(out.sources, [w1.clone(), w2.clone()], "a closed source is fine; duplicates give one edge");
    assert!(!out.non_goal);
    assert_eq!(ws.edge(&r.id, &spec), Some(DepType::ParentChild));
    let json = serde_json::to_value(&out).unwrap();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["non_goal", "requirement", "sources", "spec"]);

    let ng = ws.write(|tx| tx.spec_add(&spec, &sentence("No guest checkout", &[&w1]), true));
    let mut labels = ng.requirement.labels.clone();
    labels.sort();
    assert_eq!(labels, ["non-goal", "requirement"]);

    let view = &ws.read(|c| specs::show(c, &spec))[0];
    assert_eq!(view.requirements.len(), 1);
    assert_eq!(view.requirements[0].id, r.id);
    let mut srcs = view.requirements[0].sources.clone();
    srcs.sort();
    let mut want = vec![w1.clone(), w2.clone()];
    want.sort();
    assert_eq!(srcs, want);
    assert_eq!(view.non_goals[0].id, ng.requirement.id);
}

#[test]
fn add_refuses_bad_targets_and_sources() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let rule = ws.add(&spec, "Rule", &[&w], false);

    let e = refused(&mut ws, |tx| tx.spec_add(&w, &sentence("Rule", &[&w]), false));
    assert!(is_invalid(&e) && e.to_string().contains(&format!("{w} is not a spec")), "{e}");
    for part in [&spec, &rule] {
        let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence("Rule", &[part]), false));
        assert!(is_invalid(&e) && e.to_string().contains(&format!("--from {part} is part of a spec")), "{e}");
    }
    let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence("Rule", &["t-404"]), false));
    assert!(matches!(e, Error::NotFound { .. }), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence(&"x".repeat(501), &[&w]), false));
    assert_eq!(e.exit_code(), 2, "{e}");

    ws.set_status(&spec, Status::Open);
    let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence("Rule", &[&w]), false));
    assert!(e.to_string().contains(&format!("bd update {spec} --status pinned")), "{e}");
    ws.close(&spec);
    let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence("Rule", &[&w]), false));
    assert!(is_refused(&e) && e.to_string().contains("closed spec"), "{e}");
}

#[test]
fn add_and_change_refuse_a_requirement_without_a_source() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let rule = ws.add(&spec, "Rule", &[&w], false);
    let e = refused(&mut ws, |tx| tx.spec_add(&spec, &sentence("Rule", &[]), false));
    assert!(is_invalid(&e) && e.to_string().contains("--from"), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_change(&rule, &sentence("Rule", &[])));
    assert!(is_invalid(&e) && e.to_string().contains("--from"), "{e}");
}

#[test]
fn change_supersedes_the_old_requirement_by_the_new_one() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let old = ws.add(&spec, "Old rule", &[&w], false);
    let w2 = ws.work("Rework");
    let s = sentence("New rule", &[&w2]);
    let out = ws.write(|tx| tx.spec_change(&old, &s));
    let new = &out.requirement;
    assert_eq!(out.superseded.id, old);
    assert_eq!(out.superseded.status, Status::Closed);
    assert_eq!(out.superseded.close_reason.as_deref(), Some(format!("superseded by {}", new.id).as_str()));
    assert_eq!(out.superseded.close_outcome, Some(Outcome::Done));
    assert_eq!(ws.edge(&old, &new.id), Some(DepType::Supersedes));
    assert_eq!(new.status, Status::Pinned);
    assert_eq!(new.labels, ["requirement"]);
    assert_eq!(ws.edge(&new.id, &spec), Some(DepType::ParentChild));
    assert_eq!(ws.edge(&new.id, &w2), Some(DepType::Related));
    assert_eq!((out.spec.as_str(), out.non_goal, out.sources.clone()), (spec.as_str(), false, vec![w2.clone()]));
    let json = serde_json::to_value(&out).unwrap();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["non_goal", "requirement", "sources", "spec", "superseded"]);

    let view = &ws.read(|c| specs::show(c, &spec))[0];
    assert_eq!(view.requirements.last().unwrap().id, new.id);
    let text = specs::render(view, true, 1);
    assert!(text.contains(&format!("~~Old rule~~ superseded by {}", new.id)), "{text}");

    let ng = ws.add(&spec, "No guests", &[&w], true);
    let out = ws.write(|tx| tx.spec_change(&ng, &sentence("No guests, ever", &[&w])));
    assert!(out.non_goal);
    let mut labels = out.requirement.labels.clone();
    labels.sort();
    assert_eq!(labels, ["non-goal", "requirement"]);
}

#[test]
fn change_refuses_what_is_not_a_requirement_in_force() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let s = sentence("New rule", &[&w]);

    let e = refused(&mut ws, |tx| tx.spec_change(&w, &s));
    assert!(is_invalid(&e) && e.to_string().contains("is not a requirement"), "{e}");

    let closed = ws.add(&spec, "Closed rule", &[&w], false);
    let cid = closed.clone();
    ws.write(|tx| tx.spec_remove(&cid, "obsolete", &[]));
    let e = refused(&mut ws, |tx| tx.spec_change(&closed, &s));
    assert!(is_refused(&e) && e.to_string().contains("removed: obsolete"), "{e}");

    let stray = ws.create(NewIssue {
        labels: strings(&["requirement"]),
        status: Some(Status::Pinned),
        ..NewIssue::titled("Stray rule")
    });
    let e = refused(&mut ws, |tx| tx.spec_change(&stray, &s));
    assert!(is_invalid(&e) && e.to_string().contains("not a direct child of a spec"), "{e}");
    let under_work = ws.create(NewIssue {
        labels: strings(&["requirement"]),
        parent: Some(w.clone()),
        ..NewIssue::titled("Rule under work")
    });
    let e = refused(&mut ws, |tx| tx.spec_change(&under_work, &s));
    assert!(is_invalid(&e) && e.to_string().contains("not a direct child of a spec"), "{e}");

    let rule = ws.add(&spec, "Rule", &[&w], false);
    ws.set_status(&spec, Status::Open);
    let e = refused(&mut ws, |tx| tx.spec_change(&rule, &s));
    assert!(is_refused(&e) && e.to_string().contains(&format!("bd update {spec} --status pinned")), "{e}");

    // A requirement left open (not pinned) under a pinned spec can still change.
    ws.set_status(&spec, Status::Pinned);
    ws.set_status(&rule, Status::Open);
    ws.write(|tx| tx.spec_change(&rule, &s));
}

#[test]
fn change_writes_nothing_when_the_supersede_fails() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let old = ws.add(&spec, "Old rule", &[&w], false);
    ws.create(NewIssue { parent: Some(old.clone()), ..NewIssue::titled("Open child") });
    let kids = |ws: &Ws| {
        ws.read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child'",
                [&spec],
                |r| r.get::<_, i64>(0),
            )?)
        })
    };
    let before = kids(&ws);
    let e = refused(&mut ws, |tx| tx.spec_change(&old, &sentence("New rule", &[&w])));
    assert_eq!(e.exit_code(), 2, "{e}");
    assert_eq!(kids(&ws), before, "the new requirement was rolled back");
    assert_eq!(ws.issue(&old).status, Status::Pinned);
}

#[test]
fn change_and_remove_refuse_another_actors_claim() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let rule = ws.add(&spec, "Rule", &[&w], false);
    ws.set_status(&rule, Status::Open);
    let rid = rule.clone();
    ws.try_as("bob", |tx| tx.claim(&rid, &ClaimOptions::default())).unwrap();

    let before = ws.counts();
    let e = ws.try_write(|tx| tx.spec_change(&rule, &sentence("New rule", &[&w]))).unwrap_err();
    assert!(matches!(&e, Error::NotOwner { holder: Some(h), .. } if h == "bob"), "{e}");
    let e = ws.try_write(|tx| tx.spec_remove(&rule, "obsolete", std::slice::from_ref(&w))).unwrap_err();
    assert!(matches!(&e, Error::NotOwner { holder: Some(h), .. } if h == "bob"), "{e}");
    assert_eq!(ws.counts(), before);
    assert_eq!(ws.issue(&rule).assignee.as_deref(), Some("bob"));
}

#[test]
fn removed_reason_is_normalized() {
    for why in ["obsolete", "  obsolete ", "Removed: obsolete", "REMOVED:obsolete", "removed:   obsolete"] {
        assert_eq!(removed_reason(why).unwrap(), ("removed: obsolete".to_string(), "obsolete".to_string()), "{why:?}");
    }
    for why in ["", "  ", "removed:", "Removed:  "] {
        let e = removed_reason(why).unwrap_err();
        assert!(is_invalid(&e) && e.to_string().contains("(-r)"), "{why:?}: {e}");
    }
    // A multibyte character across the prefix's length does not panic.
    assert_eq!(removed_reason("éééé obsolete").unwrap().0, "removed: éééé obsolete");
    assert_eq!(removed_reason("removeé").unwrap().0, "removed: removeé");
    assert_eq!(removed_reason("abcdefgé").unwrap().0, "removed: abcdefgé", "byte 8 inside a character");
}

#[test]
fn remove_closes_the_requirement_with_its_reason_and_sources() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let w2 = ws.work("Removing work");
    let rule = ws.add(&spec, "Old rule", &[&w], false);
    let other = ws.add(&spec, "Other", &[&w], false);
    // Removal works under a spec that is no longer pinned.
    ws.set_status(&spec, Status::Open);
    let from = strings(&[&w, &w2, &w2]);
    let out = ws.write(|tx| tx.spec_remove(&rule, "Removed: obsolete", &from));
    assert_eq!(out.requirement.status, Status::Closed);
    assert_eq!(out.requirement.close_reason.as_deref(), Some("removed: obsolete"));
    assert_eq!(out.requirement.close_outcome, Some(Outcome::Done));
    assert_eq!(
        (out.reason.as_str(), out.why.as_str(), out.spec.as_str()),
        ("removed: obsolete", "obsolete", spec.as_str())
    );
    assert_eq!(out.sources, std::slice::from_ref(&w2), "only the edges added");
    assert_eq!(ws.edge(&rule, &w2), Some(DepType::Related));
    let json = serde_json::to_value(&out).unwrap();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["reason", "requirement", "sources", "spec"]);

    let view = &ws.read(|c| specs::show(c, &spec))[0];
    let text = specs::render(view, true, 1);
    assert!(text.contains("~~Old rule~~ removed: obsolete"), "{text}");
    assert!(text.contains(&w2), "{text}");

    let e = refused(&mut ws, |tx| tx.spec_remove(&rule, "again", &[]));
    assert!(is_refused(&e) && e.to_string().contains("already closed (removed: obsolete)"), "{e}");

    let e = refused(&mut ws, |tx| tx.spec_remove(&other, "removed:", &[]));
    assert!(is_invalid(&e), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_remove(&w, "obsolete", &[]));
    assert!(is_invalid(&e), "{e}");
    // An open requirement (not pinned) can be removed.
    ws.set_status(&other, Status::Open);
    ws.write(|tx| tx.spec_remove(&other, "obsolete", &[]));
}

#[test]
fn remove_writes_nothing_when_the_close_fails() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let rule = ws.add(&spec, "Rule", &[&w], false);
    ws.create(NewIssue { parent: Some(rule.clone()), ..NewIssue::titled("Open child") });
    let w2 = ws.work("Removing work");
    let e = refused(&mut ws, |tx| tx.spec_remove(&rule, "obsolete", std::slice::from_ref(&w2)));
    assert_eq!(e.exit_code(), 2, "{e}");
    assert_eq!(ws.edge(&rule, &w2), None);
}

#[test]
fn link_adds_related_edges_once() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Design");
    let rule = ws.add(&spec, "Rule", &[&w], false);
    let work = ws.work("Build it");
    ws.close(&work);
    assert!(ws.read(|c| specs::drift(c, Some(Timestamp(0)))).unlinked.iter().any(|r| r.id == work));

    let out = ws.write(|tx| tx.spec_link(&work, &strings(&[&rule, &spec, &rule])));
    assert_eq!(
        out,
        [
            Linked { issue: work.clone(), target: rule.clone(), already: false },
            Linked { issue: work.clone(), target: spec.clone(), already: false },
        ]
    );
    assert_eq!(ws.edge(&work, &rule), Some(DepType::Related));
    assert!(!ws.read(|c| specs::drift(c, Some(Timestamp(0)))).unlinked.iter().any(|r| r.id == work));
    assert_eq!(ws.issue(&work).status, Status::Closed, "the work is not touched");

    let before = ws.counts();
    let again = ws.write(|tx| tx.spec_link(&work, std::slice::from_ref(&rule)));
    assert!(again[0].already);
    assert_eq!(ws.counts(), before, "no new edge or event");

    // A related edge the other way counts as linked: the design is the rule's source.
    let back = ws.write(|tx| tx.spec_link(&w, std::slice::from_ref(&rule)));
    assert!(back[0].already);
    assert_eq!(ws.edge(&w, &rule), None);
}

#[test]
fn link_refuses_spec_parts_and_targets_out_of_force() {
    let mut ws = Ws::new();
    let spec = ws.spec();
    let w = ws.work("Work");
    let rule = ws.add(&spec, "Rule", &[&w], false);
    let work = ws.work("Build it");

    let e = refused(&mut ws, |tx| tx.spec_link(&rule, std::slice::from_ref(&spec)));
    assert!(is_invalid(&e) && e.to_string().contains("part of a spec"), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_link(&work, std::slice::from_ref(&w)));
    assert!(is_invalid(&e) && e.to_string().contains("is not a spec or requirement"), "{e}");
    let e = refused(&mut ws, |tx| tx.spec_link(&work, &strings(&["t-404"])));
    assert_eq!(e.exit_code(), 3, "{e}");
    let e = refused(&mut ws, |tx| tx.spec_link("t-404", std::slice::from_ref(&rule)));
    assert_eq!(e.exit_code(), 3, "{e}");

    let new = ws.write(|tx| tx.spec_change(&rule, &sentence("New rule", &[&w]))).requirement.id;
    let e = refused(&mut ws, |tx| tx.spec_link(&work, std::slice::from_ref(&rule)));
    assert!(is_refused(&e) && e.to_string().contains(&format!("{rule} is superseded by {new}: link that")), "{e}");

    let gone = ws.add(&spec, "Gone", &[&w], false);
    ws.write(|tx| tx.spec_remove(&gone, "obsolete", &[]));
    let e = refused(&mut ws, |tx| tx.spec_link(&work, std::slice::from_ref(&gone)));
    assert!(is_refused(&e) && e.to_string().contains("is closed (removed: obsolete)"), "{e}");

    // Every target is checked first: a good one before a bad one adds no edge.
    let e = refused(&mut ws, |tx| tx.spec_link(&work, &strings(&[&new, &w])));
    assert!(is_invalid(&e), "{e}");
    assert_eq!(ws.edge(&work, &new), None);

    // An edge of another type from the issue is refused before anything is written.
    let blocked = ws.create(NewIssue { deps: vec![(DepType::Blocks, new.clone())], ..NewIssue::titled("Waits") });
    let e = refused(&mut ws, |tx| tx.spec_link(&blocked, &strings(&[&spec, &new])));
    assert!(is_refused(&e) && e.to_string().contains("remove that edge first"), "{e}");
}
