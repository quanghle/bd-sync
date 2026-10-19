//! Specs as of a past point, over a workspace with a manual clock (60 s a
//! write); legacy and unrecorded changes by raw SQL.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::issues::DeleteOptions;
use crate::model::{DepType, IssuePatch, NewIssue};
use crate::specs::{self, render};
use crate::store::{InitOptions, OpenOptions, Store, WriteCtx};
use crate::time::{Clock, ManualClock};
use crate::{CloseOptions, Guard, IdMode, PruneOptions, Replacement};

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

    fn update(&mut self, id: &str, patch: IssuePatch) {
        let id = id.to_string();
        self.write(|tx| tx.update_issue(&id, &patch, &Guard::default(), false).map(|_| ()));
    }

    fn close(&mut self, id: &str, reason: &str) {
        let id = id.to_string();
        let opts = CloseOptions { reason: Some(reason.into()), force: true, ..Default::default() };
        self.write(|tx| tx.close_issue(&id, &opts).map(|_| ()));
    }

    fn supersede(&mut self, old: &str, new: &str) {
        let (old, new) = (old.to_string(), new.to_string());
        self.write(|tx| tx.close_as(&old, &new, Replacement::Supersede, &Default::default()).map(|_| ()));
    }

    /// Raw SQL in a write transaction: a change no event records.
    fn sql(&mut self, sql: &str) {
        self.store.write("sql", "alice", |tx| Ok(tx.conn().execute_batch(sql)?)).unwrap();
    }

    fn head(&self) -> i64 {
        self.store.read(|r| crate::events::head(r.conn())).unwrap()
    }

    /// The point just after the last write: as a seq, and as a time.
    fn now(&self) -> (Point, Point) {
        (Point::Seq(self.head()), Point::Time(self.clock.now()))
    }

    fn as_of(&self, arg: &str, point: Point) -> Result<Vec<SpecView>> {
        self.store.read(|r| show_as_of(r.conn(), arg, point))
    }

    fn at(&self, arg: &str, point: Point) -> Vec<SpecView> {
        self.as_of(arg, point).unwrap_or_else(|e| panic!("{arg} as of {point:?}: {e}"))
    }

    fn show(&self, arg: &str) -> Vec<SpecView> {
        self.store.read(|r| specs::show(r.conn(), arg)).unwrap()
    }

    fn changes(&self, target: Option<&str>, since: Point, until: Point) -> Result<Changes> {
        self.store.read(|r| changes(r.conn(), target, since, until))
    }

    fn ch(&self, target: Option<&str>, since: Point, until: Point) -> Changes {
        self.changes(target, since, until).unwrap_or_else(|e| panic!("{target:?} {since:?}..{until:?}: {e}"))
    }

    /// The changes from `since` to now.
    fn since(&self, target: &str, since: Point) -> Changes {
        self.ch(Some(target), since, self.now().0)
    }

    /// Import JSONL lines in one write.
    fn import(&mut self, jsonl: &str) {
        let jsonl = jsonl.to_string();
        let opts = crate::transfer::ImportOptions::default();
        self.write(|tx| tx.import_jsonl(&mut jsonl.as_bytes(), &opts).map(|_| ()));
    }

    fn label(&mut self, id: &str, add: &[&str], remove: &[&str]) {
        let patch = IssuePatch {
            add_labels: add.iter().map(|l| l.to_string()).collect(),
            remove_labels: remove.iter().map(|l| l.to_string()).collect(),
            ..Default::default()
        };
        self.update(id, patch);
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

/// The views without what `--as-of` adds.
fn cleared(mut views: Vec<SpecView>) -> Vec<SpecView> {
    fn clear(v: &mut SpecView) {
        v.unknown = None;
        v.as_of = None;
        v.incomplete = None;
        v.retained_from = None;
        v.subspecs.iter_mut().for_each(clear);
    }
    views.iter_mut().for_each(clear);
    views
}

fn reqs(view: &SpecView) -> Vec<&str> {
    view.requirements.iter().map(|r| r.id.as_str()).collect()
}

fn hist(view: &SpecView) -> Vec<(&str, &str)> {
    view.history.iter().map(|h| (h.item.id.as_str(), h.outcome)).collect()
}

fn unknowns(view: &SpecView) -> Vec<(&str, &str)> {
    view.unknown.iter().flatten().map(|u| (u.id.as_str(), u.key.as_str())).collect()
}

/// Checkout with a sourced requirement, a superseded one, a removed one, a
/// non-goal, a sub-spec with its own requirement and a closed sub-spec.
fn checkout(ws: &mut Ws) -> (String, String) {
    let spec =
        ws.create(NewIssue { description: "Paying.".into(), ..pinned("Checkout", &["spec", "area:checkout"], None) });
    let work = ws.create(NewIssue::titled("Build checkout"));
    let r1 = ws.create(NewIssue {
        deps: vec![(DepType::Related, work.clone())],
        description: "Signed in.\nAlways.".into(),
        ..pinned("Requires sign-in", &["requirement"], Some(&spec))
    });
    let r2 = ws.create(pinned("Guests may check out", &["requirement"], Some(&spec)));
    ws.supersede(&r2, &r1);
    let r3 = ws.create(pinned("Shows a banner", &["requirement"], Some(&spec)));
    ws.close(&r3, "removed: dropped");
    ws.create(pinned("No cash", &["non-goal"], Some(&spec)));
    let sub = ws.create(pinned("Payment", &["spec", "area:checkout"], Some(&spec)));
    ws.create(pinned("Accepts cards", &["requirement"], Some(&sub)));
    let old = ws.create(pinned("Old page", &["spec"], Some(&spec)));
    ws.close(&old, "retired");
    (spec, sub)
}

#[test]
fn unchanged_specs_show_as_they_do_now() {
    let mut ws = Ws::new();
    let (spec, sub) = checkout(&mut ws);
    let (seq, time) = ws.now();
    let later = Point::Time(ws.clock.now().plus(Duration::from_secs(86_400)));
    for arg in ["checkout", spec.as_str(), sub.as_str(), sub.trim_start_matches("t-")] {
        let now = ws.show(arg);
        for point in [seq, time, later] {
            let views = ws.at(arg, point);
            assert_eq!(views[0].as_of, Some(PointView::of(point)));
            assert_eq!(views[0].incomplete, Some(false));
            assert!(views[0].retained_from.is_some());
            assert_eq!(views[0].unknown.as_deref(), Some(&[][..]), "{arg} {point:?}");
            assert_eq!(cleared(views.clone()), now, "{arg} at {point:?}");
            assert_eq!(render(&cleared(views)[0], true, 1), render(&now[0], true, 1));
        }
    }
}

#[test]
fn a_requirement_added_later_is_absent_and_one_superseded_later_is_in_force() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let r1 = ws.create(pinned("Guests may check out", &["requirement"], Some(&spec)));
    let (t_seq, t_time) = ws.now();
    let r2 = ws.create(pinned("Requires sign-in", &["requirement"], Some(&spec)));
    let (mid, _) = ws.now();
    ws.supersede(&r1, &r2);
    for t in [t_seq, t_time] {
        let v = &ws.at("checkout", t)[0];
        assert_eq!(reqs(v), [r1.as_str()], "{t:?}");
        assert!(v.history.is_empty());
    }
    assert_eq!(reqs(&ws.at("checkout", mid)[0]), [r1.as_str(), r2.as_str()]);
    let v = &ws.at(&spec, ws.now().0)[0];
    assert_eq!(reqs(v), [r2.as_str()]);
    assert_eq!(hist(v), [(r1.as_str(), "superseded")]);
    assert_eq!(v.history[0].by.as_deref(), Some(r2.as_str()));
}

#[test]
fn a_requirement_closed_by_then_is_history_superseded_or_removed() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r1 = ws.create(pinned("One", &["requirement"], Some(&spec)));
    let r2 = ws.create(pinned("Two", &["requirement"], Some(&spec)));
    ws.close(&r1, "no longer holds");
    let (t, _) = ws.now();
    let v = &ws.at(&spec, t)[0];
    assert_eq!(hist(v), [(r1.as_str(), "removed")]);
    assert_eq!(v.history[0].reason, "no longer holds");
    assert_eq!(reqs(v), [r2.as_str()]);
    // Reopened later: still history then.
    let r = r1.clone();
    ws.write(|tx| tx.reopen_issue(&r, None, false).map(|_| ()));
    assert_eq!(hist(&ws.at(&spec, t)[0]), [(r1.as_str(), "removed")]);
    assert_eq!(reqs(&ws.at(&spec, ws.now().0)[0]), [r1.as_str(), r2.as_str()]);
}

#[test]
fn requirements_moved_deleted_or_purged_later_still_show_then() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let other = ws.create(pinned("Receipts", &["spec"], None));
    let moved = ws.create(pinned("Moved", &["requirement"], Some(&spec)));
    let deleted = ws.create(pinned("Deleted", &["requirement"], Some(&spec)));
    let purged = ws.create(NewIssue { ephemeral: true, ..pinned("Purged", &["requirement"], Some(&spec)) });
    let (t, time) = ws.now();
    ws.update(&moved, IssuePatch { parent: Some(Some(other.clone())), ..Default::default() });
    let d = deleted.clone();
    ws.write(|tx| tx.delete_issues(&[d], &DeleteOptions { force: true, ..Default::default() }).map(|_| ()));
    ws.close(&purged, "done");
    let outcome = ws.write(|tx| tx.purge_ephemeral(None, false));
    assert!(outcome.deleted.contains(&purged), "{:?}", outcome.deleted);
    assert_eq!(ws.store.read(|r| crate::issues::get(r.conn(), &purged)).unwrap(), None);

    for point in [t, time] {
        let v = &ws.at(&spec, point)[0];
        assert_eq!(reqs(v), [moved.as_str(), deleted.as_str(), purged.as_str()], "{point:?}");
        assert!(v.unknown.as_deref().unwrap().is_empty(), "{:?}", v.unknown);
        assert!(reqs(&ws.at(&other, point)[0]).is_empty());
    }
    let (now, _) = ws.now();
    assert!(reqs(&ws.at(&spec, now)[0]).is_empty());
    assert_eq!(reqs(&ws.at(&other, now)[0]), [moved.as_str()]);
}

#[test]
fn a_label_added_later_means_not_a_member_then() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &[], Some(&spec)));
    let (t, _) = ws.now();
    ws.update(&r, IssuePatch { add_labels: vec!["requirement".into()], ..Default::default() });
    assert!(reqs(&ws.at(&spec, t)[0]).is_empty());
    assert_eq!(reqs(&ws.at(&spec, ws.now().0)[0]), [r.as_str()]);
}

#[test]
fn a_requirement_not_pinned_then_keeps_the_warning() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(titled("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    ws.update(&r, IssuePatch { status: Some(Status::Pinned), ..Default::default() });
    let then = &ws.at(&spec, t)[0];
    assert_eq!(reqs(then), [r.as_str()]);
    assert!(then.warnings.iter().any(|w| w.starts_with(&format!("{r} is open, not pinned"))), "{:?}", then.warnings);
    assert!(ws.at(&spec, ws.now().0)[0].warnings.is_empty());
}

#[test]
fn a_sub_spec_added_later_is_absent_then() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let sub = ws.create(pinned("Payment", &["spec"], Some(&spec)));
    let sr = ws.create(pinned("Cards", &["requirement"], Some(&sub)));
    assert!(ws.at("checkout", t)[0].subspecs.is_empty());
    let now = &ws.at("checkout", ws.now().0)[0];
    assert_eq!(now.subspecs[0].spec.id, sub);
    assert_eq!(reqs(&now.subspecs[0]), [sr.as_str()]);
    assert_eq!(now.subspecs[0].unknown.as_deref(), Some(&[][..]));
    assert_eq!(now.subspecs[0].as_of, None, "only the top view says when");
    // The sub-spec on its own inherits its parent's requirements as they were.
    assert_eq!(ws.at(&sub, ws.now().0)[0].inherited[0].spec.id, spec);
}

#[test]
fn a_spec_or_area_that_was_not_one_then_is_not_found() {
    let mut ws = Ws::new();
    let early = ws.create(NewIssue::titled("Unrelated"));
    let (t, time) = ws.now();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    for point in [t, time] {
        let e = ws.as_of(&spec, point).unwrap_err();
        assert_eq!(e.exit_code(), 3, "{e}");
        assert!(e.to_string().contains(&format!("{spec} at {}", PointView::of(point).label())), "{e}");
    }
    let e = ws.as_of(&early, ws.now().0).unwrap_err();
    assert_eq!(e.exit_code(), 3, "not a spec: {e}");
    // An area whose label came later.
    ws.update(&spec, IssuePatch { add_labels: vec!["area:x".into()], ..Default::default() });
    let (labelled_at, _) = ws.now();
    let Point::Seq(n) = labelled_at else { unreachable!() };
    let e = ws.as_of("x", Point::Seq(n - 1)).unwrap_err();
    assert_eq!(e.exit_code(), 3, "{e}");
    assert!(e.to_string().contains(" at #"), "{e}");
    assert_eq!(ws.at("x", labelled_at)[0].spec.id, spec);
    // An area whose only spec lost the spec label later still has it then.
    ws.update(&spec, IssuePatch { remove_labels: vec!["spec".into()], ..Default::default() });
    assert_eq!(ws.at("x", labelled_at)[0].spec.id, spec);
    assert_eq!(ws.as_of("x", ws.now().0).unwrap_err().exit_code(), 3);
    // A seq past the newest event, as bd show --as-of.
    let e = ws.as_of(&spec, Point::Seq(ws.head() + 1)).unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains("past the newest event"), "{e}");
}

#[test]
fn a_point_before_retained_history_is_pruned() {
    let mut ws = Ws::new();
    let first = ws.clock.now();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    for i in 0..4 {
        ws.update(&spec, IssuePatch { description: Some(format!("v{i}")), ..Default::default() });
    }
    let head = ws.head();
    ws.write(|tx| tx.prune_events(&PruneOptions { before: Some(head - 1), ..Default::default() }));
    for (arg, point) in
        [(spec.as_str(), Point::Seq(1)), ("checkout", Point::Seq(1)), (spec.as_str(), Point::Time(first))]
    {
        let e = ws.as_of(arg, point).unwrap_err();
        assert_eq!((e.exit_code(), e.code()), (6, "history_pruned"), "{arg} {point:?}: {e}");
    }
    assert_eq!(ws.at(&spec, ws.now().0)[0].requirements.len(), 1);
}

#[test]
fn a_child_the_history_cannot_tell_is_listed_unknown_not_placed() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r1 = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let r2 = ws.create(pinned("Other rule", &["requirement"], Some(&spec)));
    let head = ws.head();
    ws.sql(&format!("UPDATE meta SET value = '{}' WHERE key = 'history_complete_from'", head + 1));
    ws.sql(&format!("UPDATE issues SET title = 'Changed' WHERE id = '{r1}'"));
    let views = ws.at(&spec, Point::Seq(head));
    let v = &views[0];
    assert_eq!(reqs(v), [r2.as_str()], "not placed");
    assert_eq!(unknowns(v), [(r1.as_str(), "title")]);
    let reason = &v.unknown.as_ref().unwrap()[0].reason;
    assert!(reason.contains("without a recorded event"), "{reason}");
    assert_eq!(v.incomplete, Some(true));
    let md = render(v, false, 1);
    assert!(md.contains(&format!("> Unknown: {r1} title: {reason}\n")), "{md}");
    let json = serde_json::to_value(&views).unwrap();
    assert_eq!(json[0]["unknown"][0]["id"], r1.as_str());
    assert_eq!(json[0]["incomplete"], true);
}

#[test]
fn an_unknown_description_keeps_the_requirement_placed() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r1 = ws.create(NewIssue { description: "Old.".into(), ..pinned("Rule", &["requirement"], Some(&spec)) });
    let head = ws.head();
    ws.sql(&format!("UPDATE issues SET description = 'New.' WHERE id = '{r1}'"));
    let v = &ws.at(&spec, Point::Seq(head))[0];
    assert_eq!(reqs(v), [r1.as_str()]);
    assert_eq!(v.requirements[0].description, "");
    assert_eq!(unknowns(v), [(r1.as_str(), "description")]);
}

#[test]
fn render_says_as_of_after_the_top_heading_only() {
    let mut ws = Ws::new();
    let (spec, _) = checkout(&mut ws);
    let n = ws.head();
    let md = render(&ws.at(&spec, Point::Seq(n))[0], false, 1);
    assert!(md.starts_with(&format!("# Checkout ({spec})\n\nAs of #{n}\n\nPaying.\n")), "{md}");
    assert_eq!(md.matches("As of").count(), 1, "{md}");
    assert!(!render(&ws.show(&spec)[0], false, 1).contains("As of"));
    let time = ws.clock.now();
    let md = render(&ws.at(&spec, Point::Time(time))[0], false, 1);
    assert!(md.contains(&format!("\n\nAs of {}\n\n", time.to_rfc3339())), "{md}");
}

#[test]
fn only_as_of_views_carry_the_added_keys() {
    let mut ws = Ws::new();
    let (spec, _) = checkout(&mut ws);
    let keys = ["unknown", "as_of", "incomplete", "retained_from"];
    fn walk(v: &Value, out: &mut Vec<String>) {
        if let Some(o) = v.as_object() {
            out.extend(o.keys().cloned());
            o.values().for_each(|x| walk(x, out));
        } else if let Some(a) = v.as_array() {
            a.iter().for_each(|x| walk(x, out));
        }
    }
    let mut now = Vec::new();
    walk(&serde_json::to_value(ws.show(&spec)).unwrap(), &mut now);
    for k in keys {
        assert!(!now.contains(&k.to_string()), "{k} in plain show");
    }
    let then = serde_json::to_value(ws.at(&spec, Point::Seq(ws.head()))).unwrap();
    for k in keys {
        assert!(then[0].get(k).is_some(), "{k} on the top view");
    }
    assert!(then[0]["subspecs"][0].get("unknown").is_some());
    assert!(then[0]["subspecs"][0].get("as_of").is_none());
    assert_eq!(then[0]["as_of"], json!({ "seq": ws.head(), "time": null }));
}

#[test]
fn bounds_parse_as_points_or_durations_ago() {
    let now = Timestamp(10_000_000_000);
    let ago = |s: u64| Point::Time(now.minus(Duration::from_secs(s)));
    assert_eq!(parse_bound("30d", now).unwrap(), ago(30 * 86_400));
    assert_eq!(parse_bound(" 2h ", now).unwrap(), ago(7_200));
    assert_eq!(parse_bound("-1h", now).unwrap(), ago(3_600));
    assert_eq!(parse_bound("12", now).unwrap(), Point::Seq(12));
    assert_eq!(parse_bound("#12", now).unwrap(), Point::Seq(12));
    assert_eq!(parse_bound("+1d", now).unwrap(), Point::Time(now.plus(Duration::from_secs(86_400))));
    assert_eq!(parse_bound("now", now).unwrap(), Point::Time(now));
    let t = Timestamp::parse_rfc3339("2026-01-15T09:00:00Z").unwrap();
    assert_eq!(parse_bound("2026-01-15T09:00:00Z", now).unwrap(), Point::Time(t));
    for bad in ["garbage", "#x", "", "-x"] {
        assert_eq!(parse_bound(bad, now).unwrap_err().exit_code(), 2, "{bad:?}");
    }
}

#[test]
fn rebuilding_more_issues_than_the_cap_is_refused() {
    let mut ws = Ws::new();
    let (spec, _) = checkout(&mut ws);
    let head = ws.head();
    let e = ws.store.read(|r| show_as_of_with_cap(r.conn(), &spec, Point::Seq(head), Limits::issues(1))).unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains(&format!("more than 1 issues to rebuild at #{head}")), "{e}");
    assert!(!e.to_string().contains("narrower window"), "show has no window: {e}");
    assert!(ws.store.read(|r| show_as_of_with_cap(r.conn(), &spec, Point::Seq(head), Limits::issues(50))).is_ok());
}

#[test]
fn events_after_a_point_are_read_in_one_window() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let (t, time) = ws.now();
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (u, until) = ws.now();
    ws.close(&r, "gone");
    ws.store
        .read(|c| {
            let conn = c.conn();
            let hist = History::load(conn)?;
            let all = events_after(conn, &hist, t, None)?;
            assert!(all.iter().all(|e| !t.includes(e)));
            assert!(all.iter().any(|e| e.op == "closed"));
            for (since, until) in [(t, Some(u)), (time, Some(until)), (t, Some(until)), (time, Some(u))] {
                let window = events_after(conn, &hist, since, until)?;
                assert!(!window.is_empty(), "{since:?}..{until:?}");
                let ops: Vec<(&str, Option<&str>)> =
                    window.iter().map(|e| (e.op.as_str(), e.issue_id.as_deref())).collect();
                assert_eq!(
                    ops,
                    [("created", Some(r.as_str())), ("dep_added", Some(r.as_str()))],
                    "{since:?}..{until:?}"
                );
            }
            // A child created later is tied to its spec by its parent edge's event.
            let after = After::of(&all, t);
            assert_eq!(after.kids.get(&spec), Some(&BTreeSet::from([r.clone()])));
            assert!(After::of(&all, u).kids.is_empty(), "nothing after u adds an edge");
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------------
// bd spec changes.

/// (kind, spec, id) of each change, in order.
fn kinds(c: &Changes) -> Vec<(&str, &str, &str)> {
    c.changes.iter().map(|x| (x.kind, x.spec.as_str(), x.id.as_str())).collect()
}

#[test]
fn an_added_requirement_or_non_goal_is_listed_with_its_sources() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let work = ws.create(NewIssue::titled("Build it"));
    let (t, _) = ws.now();
    let r = ws.create(NewIssue {
        deps: vec![(DepType::Related, work.clone())],
        ..pinned("Requires sign-in", &["requirement"], Some(&spec))
    });
    let (after_r, _) = ws.now();
    let n = ws.create(pinned("No cash", &["non-goal"], Some(&spec)));
    let c = ws.ch(Some("checkout"), t, ws.now().0);
    assert_eq!(kinds(&c), [("added", spec.as_str(), r.as_str()), ("added", spec.as_str(), n.as_str())]);
    let a = &c.changes[0];
    assert_eq!((a.item, a.title.as_str(), a.sources.clone()), ("requirement", "Requires sign-in", vec![work.clone()]));
    let Point::Seq(seq) = after_r else { unreachable!() };
    assert_eq!(a.seq, seq);
    assert_eq!(a.actor, "alice");
    assert_eq!(c.changes[1].item, "non-goal");
    assert_eq!(
        (a.by.as_ref(), a.reason.as_ref(), a.old_title.as_ref(), a.description_changed),
        (None, None, None, None)
    );
    let json = serde_json::to_value(a).unwrap();
    for k in ["by", "reason", "old_title", "description_changed"] {
        assert!(json.get(k).is_none(), "{k} in {json}");
    }
    assert_eq!(c.specs, [Brief { id: spec.clone(), title: "Checkout".into() }]);
    assert_eq!((c.since.clone(), c.until.clone()), (PointView::of(t), PointView::of(ws.now().0)));
    assert!(c.unknown.is_empty() && !c.incomplete);
    // The spec by id, as by area.
    assert_eq!(ws.since(&spec, t), c);
}

#[test]
fn a_supersede_folds_its_replacement() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let old = ws.create(pinned("Guests may check out", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let new = ws.create(pinned("Requires sign-in", &["requirement"], Some(&spec)));
    ws.supersede(&old, &new);
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("superseded", spec.as_str(), old.as_str())], "{:?}", c.changes);
    assert_eq!(c.changes[0].by, Some(Brief { id: new.clone(), title: "Requires sign-in".into() }));
    assert_eq!(c.changes[0].title, "Guests may check out");
    // A replacement created before the window is not folded: there is nothing to fold.
    let (t2, _) = ws.now();
    let third = ws.create(pinned("Requires a passkey", &["requirement"], Some(&spec)));
    let (t3, _) = ws.now();
    ws.supersede(&new, &third);
    assert_eq!(kinds(&ws.since(&spec, t3)), [("superseded", spec.as_str(), new.as_str())]);
    assert_eq!(kinds(&ws.since(&spec, t2)), [("superseded", spec.as_str(), new.as_str())]);
}

#[test]
fn a_removed_requirement_carries_its_close_reason() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Shows a banner", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    ws.close(&r, "removed: dropped");
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("removed", spec.as_str(), r.as_str())]);
    assert_eq!(c.changes[0].reason.as_deref(), Some("removed: dropped"));
    let date = c.changes[0].at.to_rfc3339()[..10].to_string();
    let md = render_changes(&c);
    assert!(md.contains(&format!("### Removed\n\n- Shows a banner ({r}; {date}): dropped\n")), "{md}");
}

#[test]
fn moves_unlabels_relabels_and_deletes_are_removals() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let other = ws.create(pinned("Receipts", &["spec"], None));
    let away = ws.create(pinned("Away", &[], None));
    let moved = ws.create(pinned("Moved", &["requirement"], Some(&spec)));
    let out = ws.create(pinned("Out", &["requirement"], Some(&spec)));
    let unlabelled = ws.create(pinned("Unlabelled", &["requirement"], Some(&spec)));
    let relabelled = ws.create(pinned("Relabelled", &["requirement"], Some(&spec)));
    let deleted = ws.create(pinned("Deleted", &["requirement"], Some(&spec)));
    let detached = ws.create(pinned("Detached", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    ws.update(&moved, IssuePatch { parent: Some(Some(other.clone())), ..Default::default() });
    ws.update(&out, IssuePatch { parent: Some(Some(away.clone())), ..Default::default() });
    ws.label(&unlabelled, &[], &["requirement"]);
    ws.label(&relabelled, &["non-goal"], &["requirement"]);
    let d = deleted.clone();
    ws.write(|tx| tx.delete_issues(&[d], &DeleteOptions { force: true, ..Default::default() }).map(|_| ()));
    ws.update(&detached, IssuePatch { parent: Some(None), ..Default::default() });
    let reasons = |c: &Changes| -> Vec<(String, &str, Option<String>)> {
        c.changes.iter().map(|x| (x.id.clone(), x.kind, x.reason.clone())).collect()
    };
    let c = ws.ch(Some("checkout"), t, ws.now().0);
    let some = |s: &str| Some(s.to_string());
    assert_eq!(
        reasons(&c),
        [
            (moved.clone(), "removed", Some(format!("moved to {other}"))),
            (out.clone(), "removed", Some(format!("moved to {away}"))),
            (unlabelled.clone(), "removed", some("unlabelled requirement")),
            (relabelled.clone(), "removed", some("relabelled non-goal")),
            (relabelled.clone(), "added", None),
            (deleted.clone(), "removed", some("deleted")),
            (detached.clone(), "removed", some("moved out")),
        ]
    );
    assert_eq!(c.changes[4].item, "non-goal");
    assert_eq!(c.changes[3].seq, c.changes[4].seq, "removed then added at one seq");
    // With both specs in scope, a move is a removal from one and an addition to the other.
    let all = ws.ch(None, t, ws.now().0);
    let m: Vec<(&str, &str)> =
        all.changes.iter().filter(|x| x.id == moved).map(|x| (x.kind, x.spec.as_str())).collect();
    assert_eq!(m, [("removed", spec.as_str()), ("added", other.as_str())]);
}

#[test]
fn a_purge_after_the_close_adds_nothing() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let p = ws.create(NewIssue { ephemeral: true, ..pinned("Purged", &["requirement"], Some(&spec)) });
    let (t, _) = ws.now();
    ws.close(&p, "done");
    let (closed, _) = ws.now();
    let outcome = ws.write(|tx| tx.purge_ephemeral(None, false));
    assert!(outcome.deleted.contains(&p));
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("removed", spec.as_str(), p.as_str())]);
    assert_eq!(c.changes[0].reason.as_deref(), Some("done"));
    assert!(ws.since(&spec, closed).changes.is_empty(), "closed before the window: nothing");
    assert!(ws.since(&spec, closed).unknown.is_empty());
}

#[test]
fn a_member_gone_with_a_purge_is_removed_as_purged() {
    // bd purges only closed issues, so an open member is purged only by a
    // run compaction: the transition itself, from an open member to gone.
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    ws.store
        .read(|c| {
            let rb = Rebuilder::new(c.conn(), Limits::issues(10), Refusal::Changes)?;
            let scope = BTreeSet::from([spec.clone()]);
            let before = State::of(rb.at(&r, t)?.as_ref(), &scope);
            assert!(before.open().is_some());
            let gone = State { member: Member::Out, gone: true, parent: None };
            let ev = Event {
                seq: 99,
                tx: 99,
                ts: Timestamp(1_700_000_000_000),
                actor: "bob".into(),
                op: "run_compacted".into(),
                issue_id: None,
                data: json!({}),
            };
            let mut keys = Vec::new();
            for (ops, reason) in
                [(&["run_compacted"][..], "purged"), (&["purged"][..], "purged"), (&["deleted"][..], "deleted")]
            {
                let out = transition(&rb, &r, 99, &ev, ops, &before, &gone, &mut keys)?;
                assert_eq!(out.len(), 1);
                assert_eq!(
                    (out[0].kind, out[0].reason.as_deref(), out[0].actor.as_str()),
                    ("removed", Some(reason), "bob")
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn title_and_description_edits_are_edited() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(NewIssue { description: "Old.".into(), ..pinned("Rule", &["requirement"], Some(&spec)) });
    let (t, _) = ws.now();
    ws.update(&r, IssuePatch { title: Some("Better rule".into()), ..Default::default() });
    let (t2, _) = ws.now();
    ws.update(&r, IssuePatch { description: Some("New.".into()), ..Default::default() });
    let c = ws.ch(Some(&spec), t, t2);
    assert_eq!(kinds(&c), [("edited", spec.as_str(), r.as_str())]);
    let e = &c.changes[0];
    assert_eq!(
        (e.old_title.as_deref(), e.title.as_str(), e.description_changed),
        (Some("Rule"), "Better rule", Some(false))
    );
    let c = ws.since(&spec, t2);
    let e = &c.changes[0];
    assert_eq!((e.kind, e.old_title.as_deref(), e.description_changed), ("edited", Some("Better rule"), Some(true)));
    // Other changes (a priority, a claim) are not changes to the spec.
    let (t3, _) = ws.now();
    ws.update(&r, IssuePatch { priority: Some(0), ..Default::default() });
    assert!(ws.since(&spec, t3).changes.is_empty());
}

#[test]
fn an_item_added_and_closed_in_the_window_is_listed_twice_in_order() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let (t, _) = ws.now();
    let r = ws.create(pinned("Brief", &["requirement"], Some(&spec)));
    ws.close(&r, "no longer holds");
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("added", spec.as_str(), r.as_str()), ("removed", spec.as_str(), r.as_str())]);
    assert!(c.changes[0].seq < c.changes[1].seq);
}

#[test]
fn a_child_at_both_ends_that_was_a_member_only_inside_the_window_is_listed_twice() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Note", &[], Some(&spec)));
    let (t, _) = ws.now();
    ws.label(&r, &["requirement"], &[]);
    ws.label(&r, &[], &["requirement"]);
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("added", spec.as_str(), r.as_str()), ("removed", spec.as_str(), r.as_str())]);
    assert_eq!(c.changes[1].reason.as_deref(), Some("unlabelled requirement"));
    // So is an edge added and removed inside the window.
    let s = ws.create(pinned("Loose", &["requirement"], None));
    let (t2, _) = ws.now();
    ws.update(&s, IssuePatch { parent: Some(Some(spec.clone())), ..Default::default() });
    ws.update(&s, IssuePatch { parent: Some(None), ..Default::default() });
    let c = ws.since(&spec, t2);
    assert_eq!(kinds(&c), [("added", spec.as_str(), s.as_str()), ("removed", spec.as_str(), s.as_str())]);
    assert_eq!(c.changes[1].reason.as_deref(), Some("moved out"));
}

#[test]
fn sub_specs_are_items_and_their_requirements_are_theirs() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let sub = ws.create(pinned("Payment", &["spec"], Some(&spec)));
    let sr = ws.create(pinned("Cards", &["requirement"], Some(&sub)));
    let (t2, _) = ws.now();
    let c = ws.ch(Some("checkout"), t, t2);
    assert_eq!(kinds(&c), [("added", spec.as_str(), sub.as_str()), ("added", sub.as_str(), sr.as_str())]);
    assert_eq!(c.changes[0].item, "spec");
    assert_eq!(c.specs.iter().map(|b| b.id.as_str()).collect::<Vec<_>>(), [spec.as_str(), sub.as_str()]);
    // Inherited requirements are not repeated for sub-specs.
    let r2 = ws.create(pinned("Rule two", &["requirement"], Some(&spec)));
    let (t3, _) = ws.now();
    let all = ws.ch(None, t2, t3);
    assert_eq!(kinds(&all), [("added", spec.as_str(), r2.as_str())]);
    assert!(ws.ch(Some(&sub), t2, t3).changes.is_empty());
    assert!(ws.ch(Some(&sub), t, t3).changes.iter().all(|x| x.id != r && x.id != r2));
    // A sub-spec closed is removed, as a spec.
    ws.close(&sub, "retired");
    let c = ws.since(&spec, t3);
    assert_eq!(kinds(&c), [("removed", spec.as_str(), sub.as_str())]);
    assert_eq!((c.changes[0].item, c.changes[0].reason.as_deref()), ("spec", Some("retired")));
}

#[test]
fn the_window_holds_events_after_since_up_to_until_and_windows_tile() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let a = ws.create(pinned("At since", &["requirement"], Some(&spec)));
    let (since, since_t) = ws.now();
    let b = ws.create(pinned("Inside", &["requirement"], Some(&spec)));
    let c = ws.create(pinned("At until", &["requirement"], Some(&spec)));
    let (until, until_t) = ws.now();
    ws.create(pinned("After", &["requirement"], Some(&spec)));
    for (s, u) in [(since, until), (since_t, until_t), (since, until_t), (since_t, until)] {
        let ids: Vec<String> = ws.ch(Some(&spec), s, u).changes.into_iter().map(|x| x.id).collect();
        assert_eq!(ids, [b.clone(), c.clone()], "{s:?}..{u:?}");
    }
    assert!(!ws.ch(Some(&spec), since, until).changes.iter().any(|x| x.id == a));
    // Two adjacent windows tile the joined one.
    ws.update(&b, IssuePatch { title: Some("Inside, renamed".into()), ..Default::default() });
    let (mid, _) = ws.now();
    ws.close(&c, "dropped");
    ws.label(&a, &["non-goal"], &["requirement"]);
    let (end, _) = ws.now();
    let key = |c: Changes| -> Vec<(i64, &'static str, String)> {
        c.changes.into_iter().map(|x| (x.seq, x.kind, x.id)).collect()
    };
    let mut parts = key(ws.ch(Some(&spec), since, mid));
    parts.extend(key(ws.ch(Some(&spec), mid, end)));
    assert_eq!(parts, key(ws.ch(Some(&spec), since, end)));
    assert!(parts.len() >= 6, "{parts:?}");
}

#[test]
fn an_empty_or_reversed_window_and_a_pruned_since_are_refused() {
    let mut ws = Ws::new();
    let first = ws.clock.now();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let (t, time) = ws.now();
    for (s, u) in [(t, t), (time, time), (time, t)] {
        let e = ws.changes(Some(&spec), s, u).unwrap_err();
        assert_eq!(e.exit_code(), 2, "{s:?}..{u:?}: {e}");
        assert!(e.to_string().contains("--since must be before --until"), "{e}");
    }
    // A seq since and the time it was written is a window (later events at that time count).
    assert!(ws.changes(Some(&spec), Point::Seq(1), time).is_ok());
    for i in 0..4 {
        ws.update(&spec, IssuePatch { description: Some(format!("v{i}")), ..Default::default() });
    }
    let head = ws.head();
    ws.write(|tx| tx.prune_events(&PruneOptions { before: Some(head - 1), ..Default::default() }));
    for since in [Point::Seq(1), Point::Time(first)] {
        let e = ws.changes(Some(&spec), since, ws.now().0).unwrap_err();
        assert_eq!((e.exit_code(), e.code()), (6, "history_pruned"), "{since:?}: {e}");
        let e = ws.changes(None, since, ws.now().0).unwrap_err();
        assert!(e.to_string().contains("history of the specs"), "{e}");
    }
    assert!(ws.changes(Some(&spec), Point::Seq(head - 2), ws.now().0).is_ok());
    // Not found at either end names both.
    let e = ws.changes(Some("nowhere"), Point::Seq(head - 2), ws.now().0).unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert!(e.to_string().contains(&format!("nowhere at #{} or #{}", head - 2, ws.head())), "{e}");
}

#[test]
fn a_since_before_the_first_event_of_an_unpruned_history_is_the_start() {
    let mut ws = Ws::new();
    let before = Point::Time(ws.clock.now().minus(Duration::from_secs(3600)));
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    assert_eq!(kinds(&ws.since("checkout", before)), [("added", spec.as_str(), r.as_str())]);
    assert_eq!(ws.changes(None, before, ws.now().1).unwrap().changes.len(), 1);
}

#[test]
fn a_spec_created_in_the_window_is_in_scope_from_its_end() {
    let mut ws = Ws::new();
    ws.create(NewIssue::titled("Unrelated"));
    let (t, _) = ws.now();
    let spec = ws.create(pinned("Checkout", &["spec", "area:checkout"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    assert_eq!(kinds(&ws.since("checkout", t)), [("added", spec.as_str(), r.as_str())]);
}

#[test]
fn a_child_the_history_cannot_tell_at_since_is_unknown_and_never_a_change() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let quiet = ws.create(pinned("Quiet", &["requirement"], Some(&spec)));
    let busy = ws.create(pinned("Busy", &["requirement"], Some(&spec)));
    let head = ws.head();
    ws.sql(&format!("UPDATE meta SET value = '{}' WHERE key = 'history_complete_from'", head + 1));
    ws.sql(&format!("UPDATE issues SET title = 'Changed' WHERE id IN ('{quiet}', '{busy}')"));
    let (t, _) = ws.now();
    let unrelated = ws.create(NewIssue::titled("Unrelated"));
    ws.close(&busy, "dropped");
    let c = ws.since(&spec, t);
    assert!(c.changes.is_empty(), "{:?}", c.changes);
    let u: Vec<(&str, &str)> = c.unknown.iter().map(|u| (u.id.as_str(), u.key.as_str())).collect();
    assert_eq!(u, [(quiet.as_str(), "title"), (busy.as_str(), "title")], "in id order");
    assert!(c.unknown[0].reason.contains("without a recorded event"), "{:?}", c.unknown);
    assert!(c.incomplete);
    assert!(c.unknown.iter().all(|u| u.id != unrelated));
    let md = render_changes(&c);
    assert!(
        md.starts_with(&format!("No spec changes between #{} and #{}.\n\n> Unknown: {quiet} title: ", head, ws.head())),
        "{md}"
    );
}

#[test]
fn rebuilding_more_issues_than_the_cap_is_refused_for_changes() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let (t, _) = ws.now();
    ws.create(pinned("One", &["requirement"], Some(&spec)));
    ws.create(pinned("Two", &["requirement"], Some(&spec)));
    let now = ws.now().0;
    let e = ws.store.read(|r| changes_with_cap(r.conn(), Some(&spec), t, now, Limits::issues(2))).unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains("more than 2 issues to rebuild"), "{e}");
    assert_eq!(
        ws.store.read(|r| changes_with_cap(r.conn(), Some(&spec), t, now, Limits::issues(3))).unwrap().changes.len(),
        2
    );
}

#[test]
fn a_create_import_after_the_point_adds_no_candidates() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let jsonl: String = (0..8).map(|i| format!("{{\"id\":\"t-{}\",\"title\":\"Imported {i}\"}}\n", 100 + i)).collect();
    ws.import(&jsonl);
    let now = ws.now().0;
    let limits = Limits::issues(4);
    let v = ws.store.read(|c| show_as_of_with_cap(c.conn(), &spec, t, limits)).unwrap();
    assert_eq!(reqs(&v[0]), [r.as_str()]);
    let c = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap();
    assert!(c.changes.is_empty() && c.unknown.is_empty(), "{c:?}");
    let after =
        ws.store.read(|c| Ok(After::of(&events_after(c.conn(), &History::load(c.conn())?, t, None)?, t))).unwrap();
    assert!(after.maybe.is_empty() && after.specs.is_empty() && after.hidden.is_empty(), "{after:?}");
}

#[test]
fn an_update_import_after_the_point_ties_the_child_by_its_snapshots() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    // The import drops its requirement label and renames it: no longer a member.
    ws.import(&format!(
        "{{\"id\":\"{r}\",\"title\":\"Renamed\",\"status\":\"pinned\",\"labels\":[],\
         \"dependencies\":[{{\"depends_on_id\":\"{spec}\",\"type\":\"parent-child\"}}]}}\n"
    ));
    let v = &ws.at(&spec, t)[0];
    assert_eq!(reqs(v), [r.as_str()]);
    assert_eq!(v.requirements[0].title, "Rule");
    assert!(reqs(&ws.at(&spec, ws.now().0)[0]).is_empty());
    let after =
        ws.store.read(|c| Ok(After::of(&events_after(c.conn(), &History::load(c.conn())?, t, None)?, t))).unwrap();
    assert_eq!(after.kids.get(&spec), Some(&BTreeSet::from([r.clone()])));
    assert!(after.maybe.is_empty() && after.hidden.is_empty(), "{after:?}");
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("removed", spec.as_str(), r.as_str())]);
    assert_eq!(c.changes[0].reason.as_deref(), Some("unlabelled requirement"));
}

#[test]
fn a_parent_spec_the_history_cannot_tell_is_listed_unknown_on_its_sub_spec() {
    let mut ws = Ws::new();
    let p = ws.create(pinned("Checkout", &["spec"], None));
    ws.create(pinned("Rule", &["requirement"], Some(&p)));
    let c = ws.create(pinned("Payment", &["spec"], Some(&p)));
    assert_eq!(ws.at(&c, ws.now().0)[0].inherited.len(), 1, "inherits now");
    let head = ws.head();
    ws.sql(&format!("UPDATE meta SET value = '{}' WHERE key = 'history_complete_from'", head + 1));
    ws.sql(&format!("UPDATE issues SET title = 'Changed' WHERE id = '{p}'"));
    let v = &ws.at(&c, Point::Seq(head))[0];
    assert_eq!(unknowns(v), [(p.as_str(), "title")]);
    assert!(v.inherited.is_empty(), "nothing guessed: {:?}", v.inherited);
    let md = render(v, false, 1);
    assert!(md.contains(&format!("> Unknown: {p} title: ")), "{md}");
}

#[test]
fn imported_requirements_keep_their_creation_order() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let line = |id: &str, day: u32| {
        format!(
            "{{\"id\":\"{id}\",\"title\":\"Rule {id}\",\"status\":\"pinned\",\"labels\":[\"requirement\"],\
             \"created_at\":\"2020-01-0{day}T00:00:00Z\",\
             \"dependencies\":[{{\"depends_on_id\":\"{spec}\",\"type\":\"parent-child\"}}]}}\n"
        )
    };
    ws.import(&[line("t-50", 3), line("t-51", 1), line("t-52", 2)].concat());
    let now = ws.show(&spec);
    assert_eq!(reqs(&now[0]), ["t-51", "t-52", "t-50"]);
    assert_eq!(cleared(ws.at(&spec, Point::Seq(ws.head()))), now);
}

#[test]
fn sub_specs_created_together_keep_their_creation_order() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    // Children that are not members, so the next two are its .9 and .10.
    while ws.create(titled("Filler", &[], Some(&spec))) != format!("{spec}.8") {}
    let s = spec.clone();
    let (nine, ten) = (format!("{spec}.9"), format!("{spec}.10"));
    ws.write(|tx| {
        assert_eq!(tx.create_issue(pinned("Nine", &["spec"], Some(&s)))?.id, nine);
        assert_eq!(tx.create_issue(pinned("Ten", &["spec"], Some(&s)))?.id, ten);
        Ok(())
    });
    let now = ws.show(&spec);
    let subs: Vec<&str> = now[0].subspecs.iter().map(|v| v.spec.id.as_str()).collect();
    assert_eq!(subs, [nine.as_str(), ten.as_str()]);
    assert_eq!(cleared(ws.at(&spec, Point::Seq(ws.head()))), now);
}

#[test]
fn ids_purged_later_that_were_never_children_do_not_count() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let child = ws.create(NewIssue { ephemeral: true, ..pinned("Brief", &["requirement"], Some(&spec)) });
    let limits = Limits::issues(4);
    let mut unrelated = Vec::new();
    for i in 0..limits.issues + 2 {
        let x = ws.create(NewIssue { ephemeral: true, ..NewIssue::titled(format!("Step {i}")) });
        ws.close(&x, "done");
        unrelated.push(x);
    }
    let (t, _) = ws.now();
    ws.close(&child, "done");
    let outcome = ws.write(|tx| tx.purge_ephemeral(None, false));
    assert!(outcome.deleted.contains(&child) && unrelated.iter().all(|x| outcome.deleted.contains(x)));
    let now = ws.now().0;
    let v = ws.store.read(|c| show_as_of_with_cap(c.conn(), &spec, t, limits)).unwrap();
    assert_eq!(reqs(&v[0]), [child.as_str()]);
    assert!(v[0].unknown.as_deref().unwrap().is_empty(), "{:?}", v[0].unknown);
    let c = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap();
    assert_eq!(kinds(&c), [("removed", spec.as_str(), child.as_str())]);
    assert_eq!(c.changes[0].reason.as_deref(), Some("done"));
}

#[test]
fn ids_purged_later_under_an_epic_do_not_count() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let limits = Limits::issues(4);
    // A run created and purged after the point: its children have parent-child edges, to the epic.
    let epic = ws.create(NewIssue { ephemeral: true, issue_type: Some("epic".into()), ..NewIssue::titled("Run") });
    let mut steps = Vec::new();
    for i in 0..limits.issues + 2 {
        steps.push(ws.create(NewIssue { ephemeral: true, ..titled(&format!("Step {i}"), &[], Some(&epic)) }));
    }
    for x in steps.iter().chain([&epic]) {
        ws.close(x, "done");
    }
    let outcome = ws.write(|tx| tx.purge_ephemeral(None, false));
    assert!(outcome.deleted.contains(&epic) && steps.iter().all(|x| outcome.deleted.contains(x)));
    let now = ws.now().0;
    let after =
        ws.store.read(|c| Ok(After::of(&events_after(c.conn(), &History::load(c.conn())?, t, None)?, t))).unwrap();
    assert!(steps.iter().all(|x| after.hidden.contains(x)), "{after:?}");
    let v = ws.store.read(|c| show_as_of_with_cap(c.conn(), &spec, t, limits)).unwrap();
    assert_eq!(reqs(&v[0]), [r.as_str()]);
    assert!(v[0].unknown.as_deref().unwrap().is_empty(), "{:?}", v[0].unknown);
    let c = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap();
    assert!(c.changes.is_empty() && c.unknown.is_empty(), "{c:?}");
}

#[test]
fn many_ids_purged_later_are_probed_without_loading_them() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let unrelated: Vec<String> = ws.write(|tx| {
        let mut out = Vec::new();
        for i in 0..300 {
            let x = tx.create_issue(NewIssue { ephemeral: true, ..NewIssue::titled(format!("Wisp {i}")) })?.id;
            tx.close_issue(&x, &CloseOptions { reason: Some("done".into()), force: true, ..Default::default() })?;
            out.push(x);
        }
        Ok(out)
    });
    let (t, _) = ws.now();
    let outcome = ws.write(|tx| tx.purge_ephemeral(None, false));
    assert!(unrelated.iter().all(|x| outcome.deleted.contains(x)));
    let now = ws.now().0;
    let limits = Limits::issues(4);
    READS.with(|c| c.set(0));
    let v = ws.store.read(|c| show_as_of_with_cap(c.conn(), &spec, t, limits)).unwrap();
    assert_eq!(reqs(&v[0]), [r.as_str()]);
    // Only the charged ids (the spec, its requirement) are loaded; the 300 probes load none.
    let reads = READS.with(|c| c.replace(0));
    assert!(reads <= limits.issues, "{reads} loads");
    let c = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap();
    assert!(c.changes.is_empty() && c.unknown.is_empty(), "{c:?}");
    let reads = READS.with(|c| c.get());
    assert!(reads <= limits.issues, "{reads} loads");
}

/// `r`'s JSONL line as exported, its parent-child edge to `spec` made `blocks`.
fn retyped_line(ws: &Ws, r: &str, spec: &str) -> String {
    let mut out = Vec::new();
    let opts = crate::transfer::ExportOptions::default();
    ws.store.read(|c| crate::transfer::export(c.conn(), ws.clock.now(), &mut out, &opts)).unwrap();
    let text = String::from_utf8(out).unwrap();
    let line = text.lines().find(|l| l.contains(&format!("\"id\":\"{r}\""))).unwrap();
    let mut v: Value = serde_json::from_str(line).unwrap();
    let deps = v["dependencies"].as_array_mut().unwrap();
    assert_eq!(deps.len(), 1, "{line}");
    assert_eq!(deps[0]["depends_on_id"], json!(spec));
    deps[0]["type"] = json!("blocks");
    format!("{v}\n")
}

/// The ops of the events of `id` after `t`.
fn ops_after(ws: &Ws, id: &str, t: Point) -> Vec<String> {
    let events = ws.store.read(|c| events_after(c.conn(), &History::load(c.conn())?, t, None)).unwrap();
    events.into_iter().filter(|e| e.issue_id.as_deref() == Some(id)).map(|e| e.op).collect()
}

#[test]
fn an_import_that_retypes_the_parent_edge_removes_the_child() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    let line = retyped_line(&ws, &r, &spec);
    ws.import(&line);
    // Content-identical: only the import's dep_added records the change.
    assert_eq!(ops_after(&ws, &r, t), ["dep_added"]);
    assert!(reqs(&ws.at(&spec, ws.now().0)[0]).is_empty());
    assert_eq!(reqs(&ws.at(&spec, t)[0]), [r.as_str()]);
    let c = ws.since(&spec, t);
    assert_eq!(kinds(&c), [("removed", spec.as_str(), r.as_str())]);
}

#[test]
fn an_import_that_retypes_a_parent_edge_added_in_the_window_removes_it_again() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let (t, _) = ws.now();
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let line = retyped_line(&ws, &r, &spec);
    ws.import(&line);
    assert_eq!(ops_after(&ws, &r, t).last().map(String::as_str), Some("dep_added"));
    let c = ws.since(&spec, t);
    let mine: Vec<&str> = c.changes.iter().filter(|x| x.spec == spec && x.id == r).map(|x| x.kind).collect();
    assert_eq!(mine.first(), Some(&"added"), "{c:?}");
    assert_eq!(mine.last(), Some(&"removed"), "{c:?}");
}

#[test]
fn many_transactions_past_the_replay_budget_are_refused() {
    let limits = Limits { issues: MAX_HISTORY_ISSUES, replay: 400 };
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    for i in 0..40 {
        ws.update(&r, IssuePatch { title: Some(format!("Rule v{i}")), ..Default::default() });
    }
    let now = ws.now().0;
    let e = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap_err();
    assert_eq!(e.exit_code(), 2, "{e}");
    assert!(e.to_string().contains("more than 400 events to replay: name a narrower window"), "{e}");
    let tiny = Limits { issues: MAX_HISTORY_ISSUES, replay: 1 };
    let e = ws.store.read(|c| show_as_of_with_cap(c.conn(), &spec, now, tiny)).unwrap_err();
    assert!(e.to_string().contains(&format!("more than 1 events to replay at {}", PointView::of(now).label())), "{e}");
    assert!(ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, Limits::default())).is_ok());

    // Notes alone cannot change a spec: those transactions are not rebuilt.
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Checkout", &["spec"], None));
    let r = ws.create(pinned("Rule", &["requirement"], Some(&spec)));
    let (t, _) = ws.now();
    for i in 0..40 {
        ws.update(&r, IssuePatch { notes: Some(format!("note {i}")), ..Default::default() });
    }
    let now = ws.now().0;
    let c = ws.store.read(|c| changes_with_cap(c.conn(), Some(&spec), t, now, limits)).unwrap();
    assert!(c.changes.is_empty() && c.unknown.is_empty(), "{c:?}");
}

fn change(seq: i64, kind: &'static str, item: &'static str, spec: &str, id: &str, title: &str) -> Change {
    Change {
        seq,
        at: Timestamp::parse_rfc3339("2026-09-02T23:59:00Z").unwrap(),
        actor: "alice".into(),
        spec: spec.into(),
        id: id.into(),
        item,
        kind,
        title: title.into(),
        sources: Vec::new(),
        by: None,
        reason: None,
        old_title: None,
        description_changed: None,
    }
}

#[test]
fn changes_render_as_markdown_sections() {
    let mut c = Changes {
        since: PointView::of(Point::Seq(10)),
        until: PointView::of(Point::Time(Timestamp::parse_rfc3339("2026-10-01T00:00:00Z").unwrap())),
        specs: vec![
            Brief { id: "t-1".into(), title: "Checkout".into() },
            Brief { id: "t-2".into(), title: "Quiet".into() },
            Brief { id: "t-3".into(), title: "Payment".into() },
        ],
        changes: Vec::new(),
        unknown: Vec::new(),
        incomplete: false,
    };
    assert_eq!(render_changes(&c), "No spec changes between #10 and 2026-10-01T00:00:00.000Z.\n");
    c.changes = vec![
        Change {
            sources: vec!["t-9".into(), "t-8".into()],
            ..change(11, "added", "requirement", "t-1", "t-4", "Sign in")
        },
        change(12, "added", "non-goal", "t-1", "t-5", "No cash"),
        change(13, "added", "spec", "t-1", "t-3", "Payment"),
        Change {
            by: Some(Brief { id: "t-4".into(), title: "Sign in".into() }),
            sources: vec!["t-9".into()],
            ..change(14, "superseded", "requirement", "t-1", "t-6", "Guests")
        },
        Change {
            old_title: Some("Old".into()),
            description_changed: Some(true),
            ..change(15, "edited", "requirement", "t-1", "t-7", "New")
        },
        Change {
            old_title: Some("Same".into()),
            description_changed: Some(false),
            ..change(16, "edited", "requirement", "t-3", "t-10", "Renamed")
        },
        Change {
            reason: Some("removed: dropped".into()),
            ..change(17, "removed", "requirement", "t-1", "t-11", "Banner")
        },
        Change {
            reason: Some("moved to t-1".into()),
            sources: vec!["t-9".into()],
            ..change(18, "removed", "requirement", "t-3", "t-12", "Moved")
        },
    ];
    c.unknown = vec![UnknownItem::new("t-13", "title", "changed without a recorded event")];
    let want = "\
# Spec changes between #10 and 2026-10-01T00:00:00.000Z

## Checkout (t-1)

### Added

- Sign in (t-4; from t-9, t-8; 2026-09-02)
- Non-goal: No cash (t-5; 2026-09-02)
- Sub-spec: Payment (t-3; 2026-09-02)

### Changed

- Guests (t-6) -> Sign in (t-4) (from t-9; 2026-09-02)
- Old (t-7) -> New (t-7) (2026-09-02; description changed)

### Removed

- Banner (t-11; 2026-09-02): dropped

## Payment (t-3)

### Changed

- Same (t-10) -> Renamed (t-10) (2026-09-02)

### Removed

- Moved (t-12; from t-9; 2026-09-02): moved to t-1

> Unknown: t-13 title: changed without a recorded event
";
    assert_eq!(render_changes(&c), want);
    let json = serde_json::to_value(&c).unwrap();
    let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    let mut want_keys = ["since", "until", "specs", "changes", "unknown", "incomplete"];
    want_keys.sort();
    assert_eq!(keys, want_keys);
    assert_eq!(json["changes"][3]["by"], json!({ "id": "t-4", "title": "Sign in" }));
    assert!(json["changes"][3].get("reason").is_none());
    assert_eq!(json["since"], json!({ "seq": 10, "time": null }));
}

#[test]
fn control_and_direction_characters_come_out_clean() {
    let mut ws = Ws::new();
    let spec = ws.create(pinned("Check\u{1b}[31mout\u{202e}", &["spec"], None));
    let (t, _) = ws.now();
    ws.create(pinned("Pay\u{1b}[2J now\u{202e}", &["requirement"], Some(&spec)));
    let c = ws.since(&spec, t);
    assert_eq!(c.changes[0].title, "Pay[2J now");
    assert_eq!(c.specs[0].title, "Check[31mout");
    let json = serde_json::to_string(&c).unwrap();
    let md = render_changes(&c);
    for bad in ['\u{1b}', '\u{202e}'] {
        assert!(!json.contains(bad) && !json.contains("\\u001b") && !json.contains("\\u202e"), "{json}");
        assert!(!md.contains(bad), "{md:?}");
    }
}
