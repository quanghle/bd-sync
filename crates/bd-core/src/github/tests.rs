use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::EventQuery;
use crate::model::DepType;
use crate::queries::Queries;
use crate::store::{InitOptions, OpenOptions, Store};
use crate::time::ManualClock;
use crate::{ClaimOptions, IdMode};

const T0: i64 = 1_800_000_000_000;
const REPO: &str = "acme/app";

fn at(min: i64) -> Timestamp {
    Timestamp(T0 + min * 60_000)
}

fn gh(n: u64, title: &str) -> GithubIssue {
    GithubIssue {
        number: n,
        node_id: format!("I_{n}"),
        title: title.into(),
        body: String::new(),
        open: true,
        state_reason: None,
        labels: vec![],
        assignees: vec![],
        updated_at: at(0),
        html_url: format!("https://github.com/acme/app/issues/{n}"),
        comments: 0,
        pull_request: false,
        author: None,
    }
}

fn issue(id: &str, title: &str) -> Issue {
    Issue {
        id: id.into(),
        title: title.into(),
        description: String::new(),
        design: String::new(),
        acceptance_criteria: String::new(),
        notes: String::new(),
        status: Status::Open,
        priority: 2,
        issue_type: "task".into(),
        assignee: None,
        created_by: "alice".into(),
        external_ref: None,
        estimated_minutes: None,
        metadata: json!({}),
        created_at: at(0),
        updated_at: at(0),
        started_at: None,
        closed_at: None,
        close_reason: None,
        close_outcome: None,
        due_at: None,
        defer_until: None,
        ephemeral: false,
        is_blocked: false,
        revision: 1,
        labels: vec![],
    }
}

fn cfg() -> SyncConfig {
    SyncConfig {
        assignees: vec![("octo".into(), "alice".into()), ("bob".into(), "bobby".into())],
        priority_prefix: Some("P".into()),
    }
}

fn synced(local: &Issue, g: &GithubIssue, c: &SyncConfig) -> Link {
    let mut link = Link::new(REPO, g.number);
    link.stamp_github(g, c);
    link.stamp_local(local, c);
    link
}

fn comment(id: i64, issue_id: &str, text: &str) -> Comment {
    Comment { id, issue_id: issue_id.into(), author: "alice".into(), text: text.into(), created_at: at(1) }
}

fn gh_comment(id: i64, body: &str) -> GithubComment {
    GithubComment {
        id,
        user: "octo".into(),
        body: body.into(),
        created_at: at(2),
        updated_at: at(2),
        html_url: format!("https://github.com/acme/app/issues/7#issuecomment-{id}"),
    }
}

#[test]
fn issues_and_comments_parse_strictly() {
    let v = json!({
        "number": 7, "node_id": "I_7", "title": "Crash", "body": null, "state": "closed",
        "state_reason": "duplicate", "labels": [{"name": "bug"}, "P1"], "assignees": [{"login": "octo"}],
        "updated_at": "2026-10-01T10:00:00Z", "html_url": "u", "comments": 2, "pull_request": {"url": "x"}
    });
    let g = GithubIssue::from_json(&v).unwrap();
    assert_eq!((g.number, g.body.as_str(), g.open, g.failed()), (7, "", false, false), "duplicate closes as done");
    assert_eq!((g.labels.clone(), g.assignees.clone()), (vec!["bug".to_string(), "P1".into()], vec!["octo".into()]));
    assert!(g.pull_request);
    let plain = GithubIssue::from_json(
        &json!({"number": 1, "title": "t", "state": "open", "updated_at": "2026-10-01T10:00:00Z"}),
    );
    assert!(!plain.unwrap().pull_request);
    for missing in ["number", "title", "state", "updated_at"] {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove(missing);
        assert!(GithubIssue::from_json(&v).is_err(), "{missing}");
    }
    let c = GithubComment::from_json(&json!({"id": 5, "user": {"login": "octo"}, "body": "hi",
        "created_at": "2026-10-01T10:00:00Z", "html_url": "u"}))
    .unwrap();
    assert_eq!((c.id, c.user.as_str(), c.updated_at), (5, "octo", c.created_at));
}

#[test]
fn projections_follow_the_mapping_rules() {
    let c = cfg();
    let mut g = gh(7, "Crash");
    g.body = "Steps\r\nto repro  \r\n\r\n<!-- bd:t-1 -->\r\n".into();
    g.labels = vec!["bug".into(), "P3".into(), "p1".into(), "x".repeat(60)];
    g.assignees = vec!["Octo".into(), "bob".into()];
    g.open = false;
    g.state_reason = Some("not_planned".into());
    let f = Fields::of_github(&g, &c);
    assert_eq!(f.body, "Steps\nto repro");
    assert_eq!((f.labels.clone(), f.priority, f.assignee.as_deref()), (vec!["bug".to_string()], Some(1), Some("octo")));
    assert!(f.failed && !f.open);
    assert_eq!(Fields::of_github(&g, &SyncConfig::default()).priority, None, "no prefix, no priority");
    // A comment marker is not an issue marker.
    assert_eq!(normalize_body("text\n<!-- bd:t-1#c4 -->"), "text\n<!-- bd:t-1#c4 -->");
    assert_eq!(marker_of("x\n<!-- bd:t-1#c4 -->"), None);
    assert_eq!(comment_marker_of("x\n\n<!-- bd:t-1#c4 -->\n"), Some(("t-1".into(), 4)));
    assert_eq!(marker_of("x\n\n<!-- bd:t-1 -->"), Some("t-1".into()));
    assert_eq!(marker_of("<!-- bd:t-1 -->\nmore"), None, "only the final line");

    let mut l = issue("t-1", "Crash");
    l.labels = vec!["bug".into(), "z".into()];
    l.assignee = Some("carol".into());
    let f = Fields::of_local(&l, &c);
    assert_eq!((f.priority, f.assignee.as_deref()), (Some(2), Some("carol")));
    assert_eq!(Fields::of_local(&l, &SyncConfig::default()).priority, None);
    let mut l2 = l.clone();
    l2.labels = vec!["z".into(), "bug".into()];
    assert_eq!(Fields::of_local(&l2, &c).hash(), f.hash(), "label order does not matter");
    assert_eq!(priority_of_label("priority:3", "priority:"), Some(3));
    assert_eq!(priority_of_label("P5", "P"), None);
}

#[test]
fn same_sync_state_ignores_what_github_moves_alone() {
    let c = cfg();
    let link = synced(&issue("t-1", "A"), &gh(7, "A"), &c);
    let mut other = link.clone();
    other.updated_at = Some(at(9));
    other.node_id = "x".into();
    other.url = "y".into();
    other.own_local_at = Some(at(1));
    other.own_github_at = Some(at(1));
    other.local_edit_at = Some(at(1));
    other.github_edit_at = Some(at(1));
    assert!(link.same_sync_state(&other));
    for change in [
        |l: &mut Link| l.github_hash = None,
        |l: &mut Link| l.local_hash = None,
        |l: &mut Link| {
            l.comments.insert("1".into(), 2);
        },
        |l: &mut Link| l.comment_count = Some(3),
    ] {
        let mut o = link.clone();
        change(&mut o);
        assert!(!link.same_sync_state(&o));
    }
}

#[test]
fn pulls_change_only_what_differs_and_keep_the_rest() {
    let c = cfg();
    let base_gh = gh(7, "A");
    let mut local = issue("t-1", "A");
    local.assignee = Some("carol".into());
    local.labels = vec!["y".repeat(200)];
    let link = synced(&local, &base_gh, &c);
    let mut g = base_gh.clone();
    g.title = "B".into();
    let p = pull_changes(&local, Some(&link), &g, &c);
    assert_eq!(p.title.as_deref(), Some("B"));
    assert_eq!(p.assignee, AssigneeChange::Keep, "an unmapped bd assignee stays");
    assert!(p.remove_labels.is_empty(), "a label GitHub cannot hold stays");
    assert_eq!(p.priority, None, "no priority label leaves the priority");
    assert_eq!(p.fields(), ["title"]);

    // A mapped login replaces, a mapped removal clears.
    let mut mine = issue("t-1", "A");
    let mut was = base_gh.clone();
    was.assignees = vec!["octo".into()];
    mine.assignee = Some("alice".into());
    let link = synced(&mine, &was, &c);
    let mut g = was.clone();
    g.assignees = vec!["bob".into()];
    assert_eq!(pull_changes(&mine, Some(&link), &g, &c).assignee, AssigneeChange::Set("bobby".into()));
    g.assignees = vec![];
    assert_eq!(pull_changes(&mine, Some(&link), &g, &c).assignee, AssigneeChange::Clear);
    g.assignees = vec!["stranger".into()];
    assert_eq!(pull_changes(&mine, Some(&link), &g, &c).assignee, AssigneeChange::Clear);

    // An outcome change between two closed states.
    let mut done = issue("t-1", "A");
    done.status = Status::Closed;
    done.close_outcome = Some(Outcome::Done);
    let mut g = base_gh.clone();
    g.open = false;
    g.state_reason = Some("not_planned".into());
    assert_eq!(pull_changes(&done, None, &g, &c).state, Some((false, true)));
    g.state_reason = Some("completed".into());
    assert_eq!(pull_changes(&done, None, &g, &c).state, None);
}

#[test]
fn pushes_send_only_what_differs_and_keep_the_rest() {
    let c = cfg();
    let mut g = gh(7, "A");
    g.assignees = vec!["stranger".into(), "bob".into()];
    let mut local = issue("t-1", "A");
    let link = synced(&local, &g, &c);
    local.title = "B".into();
    let body = push_body(&local, Some(&link), &g, &c);
    assert_eq!(body.keys().collect::<Vec<_>>(), ["title"], "{body:?}");

    // A mapped reassignment keeps the second assignee; an unassign removes only the first.
    let mut g = gh(7, "A");
    g.assignees = vec!["octo".into(), "carl".into()];
    let mut local = issue("t-1", "A");
    local.assignee = Some("alice".into());
    let link = synced(&local, &g, &c);
    local.assignee = Some("bobby".into());
    assert_eq!(push_body(&local, Some(&link), &g, &c)["assignees"], json!(["bob", "carl"]));
    local.assignee = None;
    assert_eq!(push_body(&local, Some(&link), &g, &c)["assignees"], json!(["carl"]));

    // Priority labels: P1 goes, P2 comes, P3 and a long label stay.
    let long = "l".repeat(60);
    let mut g = gh(7, "A");
    g.labels = vec![long.clone(), "P1".into(), "P3".into()];
    let mut local = issue("t-1", "A");
    local.priority = 1;
    let link = synced(&local, &g, &c);
    local.priority = 2;
    assert_eq!(push_body(&local, Some(&link), &g, &c)["labels"], json!([long, "P3", "P2"]));

    // No priority label on GitHub and an unchanged bd priority: none added.
    let g = gh(7, "A");
    let mut local = issue("t-1", "A");
    let link = synced(&local, &g, &c);
    local.title = "B".into();
    assert!(!push_body(&local, Some(&link), &g, &c).contains_key("labels"));

    // The marker in GitHub's body is kept.
    let mut g = gh(7, "A");
    g.body = "old\n\n<!-- bd:t-1 -->".into();
    let mut local = issue("t-1", "A");
    local.description = "new".into();
    assert_eq!(push_body(&local, None, &g, &SyncConfig::default())["body"], json!("new\n\n<!-- bd:t-1 -->"));

    // Closed failed is not_planned; a closed outcome change closes again with the new reason.
    let mut local = issue("t-1", "A");
    local.status = Status::Closed;
    local.close_outcome = Some(Outcome::Failed);
    let g = gh(7, "A");
    let body = push_body(&local, None, &g, &SyncConfig::default());
    assert_eq!((&body["state"], &body["state_reason"]), (&json!("closed"), &json!("not_planned")));
    let mut closed = gh(7, "A");
    closed.open = false;
    closed.state_reason = Some("completed".into());
    assert!(outcome_change(&local, &closed));
    let body = push_body(&local, None, &closed, &SyncConfig::default());
    assert_eq!(body.keys().collect::<Vec<_>>(), ["state", "state_reason"]);
    // GitHub dropped the reason: still unapplied, so bd is not stamped.
    assert_eq!(unapplied(&body, &local, None, &closed, &SyncConfig::default()), ["state"]);
}

#[test]
fn decisions_cover_every_branch() {
    let c = cfg();
    let g = gh(7, "A");
    let local = issue("t-1", "A");
    let link = synced(&local, &g, &c);
    let d = |l: &Issue, g: &GithubIssue, dir, prefer| decide(l, Some(&link), g, &c, dir, prefer);
    assert_eq!(d(&local, &g, Direction::Both, None), Decision::Unchanged);

    let mut edited = local.clone();
    edited.title = "Local".into();
    assert_eq!(d(&edited, &g, Direction::Push, None), Decision::Push);
    let deferred = d(&edited, &g, Direction::Pull, None);
    assert!(matches!(deferred, Decision::Deferred { side: Side::Local, .. }), "{deferred:?}");
    assert_eq!(deferred.planned_stamp(), Stamp::NONE);

    let mut theirs = g.clone();
    theirs.title = "GitHub".into();
    assert_eq!(d(&local, &theirs, Direction::Pull, None), Decision::Pull);
    assert!(matches!(d(&local, &theirs, Direction::Push, None), Decision::Deferred { side: Side::Github, .. }));

    assert!(matches!(d(&edited, &theirs, Direction::Both, None), Decision::Conflict { .. }));
    assert_eq!(d(&edited, &theirs, Direction::Both, Some(Prefer::Local)), Decision::Push);
    assert_eq!(d(&edited, &theirs, Direction::Both, Some(Prefer::Github)), Decision::Pull);
    assert!(matches!(d(&edited, &theirs, Direction::Pull, Some(Prefer::Local)), Decision::Deferred { .. }));
    // Converged: both changed the same way.
    let mut same = local.clone();
    same.title = "GitHub".into();
    assert_eq!(d(&same, &theirs, Direction::Both, None), Decision::Unchanged);

    let mut gate = local.clone();
    gate.issue_type = GATE_TYPE.into();
    assert!(matches!(d(&gate, &theirs, Direction::Both, None), Decision::Skip(_)));
}

#[test]
fn an_empty_winner_carries_the_other_sides_change() {
    let c = cfg();
    let g = GithubIssue { labels: vec!["P2".into()], ..gh(7, "A") };
    let local = issue("t-1", "A");
    let link = synced(&local, &g, &c);
    let d = |l: &Issue, g: &GithubIssue, dir, prefer| decide(l, Some(&link), g, &c, dir, prefer);
    // GitHub dropped the priority label (nothing to pull); bd reassigned to a mapped login.
    let theirs = GithubIssue { labels: vec![], ..g.clone() };
    let mine = Issue { assignee: Some("bobby".into()), ..local.clone() };
    assert!(pull_changes(&mine, Some(&link), &theirs, &c).is_empty());
    assert_eq!(d(&mine, &theirs, Direction::Both, Some(Prefer::Github)), Decision::Push);
    let deferred = d(&mine, &theirs, Direction::Pull, Some(Prefer::Github));
    assert!(matches!(deferred, Decision::Deferred { side: Side::Local, .. }), "{deferred:?}");

    // The mirror, where the carry would overwrite the winner's own change:
    // a conflict, not a write. bd (preferred) assigned the unmapped carol;
    // GitHub assigned the mapped octo.
    let mine = Issue { assignee: Some("carol".into()), ..local.clone() };
    let theirs = GithubIssue { assignees: vec!["octo".into()], ..g.clone() };
    assert!(push_body(&mine, Some(&link), &theirs, &c).is_empty());
    let r = d(&mine, &theirs, Direction::Both, Some(Prefer::Local));
    assert!(matches!(r, Decision::Conflict { .. }), "{r:?}");
    assert_eq!(r.planned_stamp(), Stamp::NONE);
    let deferred = d(&mine, &theirs, Direction::Push, Some(Prefer::Local));
    assert!(matches!(deferred, Decision::Deferred { side: Side::Github, .. }), "{deferred:?}");
    // Never synced: every field counts as changed on both sides.
    let r = decide(&mine, None, &theirs, &c, Direction::Both, Some(Prefer::Local));
    assert!(matches!(r, Decision::Conflict { .. }), "{r:?}");
    // GitHub (preferred) assigned the unmapped zed; bd assigned the mapped bobby.
    let mine = Issue { assignee: Some("bobby".into()), ..local.clone() };
    let theirs = GithubIssue { assignees: vec!["zed".into()], ..g.clone() };
    assert!(pull_changes(&mine, Some(&link), &theirs, &c).is_empty());
    let r = d(&mine, &theirs, Direction::Both, Some(Prefer::Github));
    assert!(matches!(r, Decision::Conflict { .. }), "{r:?}");
    // Priority: GitHub (preferred) dropped its label; bd moved to P1, which a push would label.
    let mine = Issue { priority: 1, ..local.clone() };
    let theirs = GithubIssue { labels: vec![], ..g.clone() };
    assert!(pull_changes(&mine, Some(&link), &theirs, &c).is_empty());
    let r = d(&mine, &theirs, Direction::Both, Some(Prefer::Github));
    assert!(matches!(r, Decision::Conflict { .. }), "{r:?}");
}

#[test]
fn newer_leaves_out_bd_githubs_own_writes() {
    let c = cfg();
    let g = gh(7, "A");
    let local = issue("t-1", "A");
    let mut link = synced(&local, &g, &c);
    // bd edited at 10:00, then a sync wrote the Link at 11:05; GitHub edited at 11:00.
    let mut edited = local.clone();
    edited.title = "Local".into();
    edited.updated_at = at(65);
    link.own_local_at = Some(at(65));
    link.local_edit_at = Some(at(0));
    let mut theirs = g.clone();
    theirs.title = "GitHub".into();
    theirs.updated_at = at(60);
    assert_eq!(edit_times(&edited, Some(&link), &theirs), (at(0), at(60)));
    assert_eq!(decide(&edited, Some(&link), &theirs, &c, Direction::Both, Some(Prefer::Newer)), Decision::Pull);
    // GitHub edited at 11:00, bd's own comment POST bumped it at 11:30; bd edited at 12:00.
    let mut link = synced(&local, &g, &c);
    link.own_github_at = Some(at(90));
    link.github_edit_at = Some(at(60));
    theirs.updated_at = at(90);
    edited.updated_at = at(120);
    assert_eq!(decide(&edited, Some(&link), &theirs, &c, Direction::Both, Some(Prefer::Newer)), Decision::Push);
    // Without timing fields: plain updated_at.
    assert_eq!(edit_times(&edited, None, &theirs), (at(120), at(90)));
}

#[test]
fn comment_plans_import_adopt_and_push() {
    let mut link = Link::new(REPO, 7);
    link.comments.insert("100".into(), 1);
    let local = vec![comment(1, "t-1", "imported before"), comment(5, "t-1", "mine"), comment(6, "t-1", "new")];
    let fetched = vec![
        gh_comment(100, "seen"),
        gh_comment(101, "foreign"),
        gh_comment(102, &format!("mine\n\n{}", comment_marker("t-1", 5))),
    ];
    for dir in [Direction::Pull, Direction::Push, Direction::Both] {
        let p = plan_comments("t-1", Some(&link), Some(&fetched), &local, dir, true);
        assert_eq!(p.adopt, [(102, 5)], "{dir:?}");
        let imported: Vec<i64> = p.import.iter().map(|c| c.id).collect();
        let pushed: Vec<i64> = p.push.iter().map(|c| c.id).collect();
        match dir {
            Direction::Push => {
                assert!(imported.is_empty() && p.fetched_count.is_none());
                assert_eq!(pushed, [6]);
                assert_eq!(p.count(Some(1), 1), 3, "stored + adopted + posted");
            }
            Direction::Pull => {
                assert_eq!((imported, pushed.len(), p.fetched_count), (vec![101], 0, Some(3)));
            }
            Direction::Both => assert_eq!((imported, pushed), (vec![101], vec![6])),
        }
    }
    let mut g = gh(7, "A");
    assert!(!needs_comment_fetch(None, &g));
    g.comments = 1;
    assert!(needs_comment_fetch(None, &g));
    link.comment_count = Some(1);
    assert!(!needs_comment_fetch(Some(&link), &g));
    link.comment_count = Some(0);
    assert!(needs_comment_fetch(Some(&link), &g));
}

struct Ws {
    _dir: tempfile::TempDir,
    store: Store,
    clock: Arc<ManualClock>,
}

impl Ws {
    fn new() -> Ws {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(at(0)));
        let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
        let path = dir.path().join(".bd").join("bd.db");
        let store = Store::init(&path, InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts).unwrap();
        Ws { _dir: dir, store, clock }
    }

    fn write<T>(&mut self, actor: &str, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> T {
        self.clock.advance(Duration::from_secs(60));
        self.store.write("test", actor, f).unwrap()
    }

    fn issue(&self, id: &str) -> Issue {
        self.store.read(|r| r.issue(id)).unwrap()
    }

    fn link(&self, id: &str) -> Link {
        Link::of(&self.issue(id)).unwrap()
    }

    fn head(&self) -> i64 {
        self.store.read(|r| r.event_head()).unwrap()
    }

    fn ops_since(&self, since: i64) -> Vec<String> {
        let q = EventQuery { since: Some(since), ..Default::default() };
        self.store.read(|r| r.events(&q)).unwrap().events.into_iter().map(|e| e.op).collect()
    }

    /// A bd issue created from GitHub issue `g`, linked and stamped.
    fn pulled(&mut self, g: &GithubIssue) -> String {
        self.write("sync", |tx| tx.github_create(REPO, g, None, &cfg())).0.id
    }

    fn apply(&mut self, a: &IssueApply) -> ApplyOutcome {
        self.write("sync", |tx| tx.github_apply(a, &cfg()))
    }
}

fn apply_of(local: &Issue, seen: &GithubIssue, stamp: Stamp) -> IssueApply {
    let link = Link::of(local);
    IssueApply {
        id: local.id.clone(),
        expected_revision: local.revision,
        repo: REPO.into(),
        number: seen.number,
        pull: None,
        import: vec![],
        adopt: vec![],
        pushed_comments: vec![],
        github_seen: seen.clone(),
        github_after: seen.clone(),
        own_github_at: None,
        local_before: local.clone(),
        stamp,
        comment_count: link.and_then(|k| k.comment_count).unwrap_or(0),
        set_external_ref: false,
    }
}

fn pull_apply(local: &Issue, g: &GithubIssue) -> IssueApply {
    let link = Link::of(local);
    let mut a = apply_of(local, g, Stamp::BOTH);
    a.pull = Some(pull_changes(local, link.as_ref(), g, &cfg()));
    a
}

#[test]
fn creating_a_closed_not_planned_issue_closes_it_failed() {
    let mut ws = Ws::new();
    let mut g = gh(7, "Crash");
    g.open = false;
    g.state_reason = Some("not_planned".into());
    g.labels = vec!["bug".into(), "P1".into(), "bad,label".into()];
    g.assignees = vec!["octo".into()];
    let head = ws.head();
    let (created, warnings) = ws.write("sync", |tx| tx.github_create(REPO, &g, None, &cfg()));
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let i = ws.issue(&created.id);
    assert_eq!((i.status, i.close_outcome, i.priority), (Status::Closed, Some(Outcome::Failed), 1));
    assert_eq!((i.labels.clone(), i.assignee.as_deref()), (vec!["bug".to_string()], Some("alice")));
    assert_eq!(i.external_ref.as_deref(), Some("gh:acme/app#7"));
    let q = EventQuery { since: Some(head), ..Default::default() };
    let events = ws.store.read(|r| r.events(&q)).unwrap().events;
    assert!(events.iter().any(|e| e.op == "created" && e.actor == "sync"));
    assert!(events.iter().any(|e| e.op == "closed" && e.actor == "sync"));
    let link = Link::of(&i).unwrap();
    assert_eq!(decide(&i, Some(&link), &g, &cfg(), Direction::Both, None), Decision::Unchanged);
}

#[test]
fn deferred_sides_keep_their_hashes() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    let before = ws.link(&id);
    // bd edits the title; a pull imports a comment without stamping either side.
    ws.write("alice", |tx| {
        tx.update_issue(
            &id,
            &IssuePatch { title: Some("Local".into()), ..Default::default() },
            &Guard::default(),
            false,
        )
    });
    let local = ws.issue(&id);
    let mut a = apply_of(&local, &g, Stamp::NONE);
    a.import = vec![gh_comment(100, "hello")];
    a.comment_count = 1;
    let out = ws.apply(&a);
    assert_eq!(out.imported.len(), 1);
    let link = ws.link(&id);
    assert_eq!((&link.local_hash, &link.local_assignee), (&before.local_hash, &before.local_assignee));
    assert_eq!(link.local_edit_at, Some(local.updated_at), "the bd edit time is kept for newer");
    assert_eq!((link.comment_count, link.comments.len()), (Some(1), 1));
    let now = ws.issue(&id);
    assert_eq!(decide(&now, Some(&link), &g, &cfg(), Direction::Push, None), Decision::Push);

    // GitHub edits the title; a push posts a comment without stamping either side.
    let mut theirs = g.clone();
    theirs.title = "GitHub".into();
    theirs.assignees = vec!["octo".into()];
    let mut a = apply_of(&now, &theirs, Stamp::NONE);
    a.pushed_comments = vec![(200, 9)];
    a.comment_count = 2;
    ws.apply(&a);
    let link = ws.link(&id);
    assert_eq!((&link.github_hash, &link.assignee), (&before.github_hash, &before.assignee));
    assert_eq!(link.comments.get("200"), Some(&9));
}

#[test]
fn unchanged_applies_write_only_what_changed() {
    let mut ws = Ws::new();
    let mut g = gh(7, "A");
    let id = ws.pulled(&g);
    g.comments = 1;
    let local = ws.issue(&id);
    let mut a = apply_of(&local, &g, Stamp::BOTH);
    a.import = vec![gh_comment(100, "hello")];
    a.comment_count = 1;
    let head = ws.head();
    ws.apply(&a);
    assert_eq!(ws.ops_since(head), ["commented", "updated"]);
    let link = ws.link(&id);
    assert_eq!((link.comments.contains_key("100"), link.comment_count), (true, Some(1)));

    // Nothing new: no write, even with GitHub's updated_at alone later.
    let local = ws.issue(&id);
    let mut a = apply_of(&local, &g, Stamp::BOTH);
    assert!(!apply_needed(Link::of(&local).as_ref(), &a, &cfg()));
    a.github_after.updated_at = at(500);
    assert!(!apply_needed(Link::of(&local).as_ref(), &a, &cfg()));
    let head = ws.head();
    ws.apply(&a);
    assert_eq!(ws.head(), head);
}

#[test]
fn imported_and_pushed_ids_land_in_one_link_write() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    let local = ws.issue(&id);
    let mut a = apply_of(&local, &g, Stamp::BOTH);
    a.import = vec![gh_comment(100, "theirs")];
    a.pushed_comments = vec![(101, 77)];
    a.comment_count = 2;
    let head = ws.head();
    ws.apply(&a);
    assert_eq!(ws.ops_since(head), ["commented", "updated"]);
    let link = ws.link(&id);
    assert_eq!(link.comments.get("101"), Some(&77));
    assert!(link.comments.contains_key("100"));
}

#[test]
fn a_stale_pull_part_still_records_comments() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    let local = ws.issue(&id);
    let before = ws.link(&id);
    let mut theirs = g.clone();
    theirs.title = "GitHub".into();
    let mut a = pull_apply(&local, &theirs);
    a.pushed_comments = vec![(101, 5)];
    a.comment_count = 1;
    ws.write("alice", |tx| {
        tx.update_issue(&id, &IssuePatch { notes: Some("n".into()), ..Default::default() }, &Guard::default(), false)
    });
    let out = ws.apply(&a);
    assert!(matches!(out.pull_error, Some(PullError::Stale(_))), "{:?}", out.pull_error);
    let link = ws.link(&id);
    assert_eq!(ws.issue(&id).title, "A");
    assert_eq!(link.comments.get("101"), Some(&5));
    assert_eq!((&link.github_hash, &link.local_hash), (&before.github_hash, &before.local_hash));
}

#[test]
fn another_actors_claim_refuses_the_close_but_not_the_comments() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    let claim = ws.write("bob", |tx| tx.claim(&id, &ClaimOptions::default()));
    let local = ws.issue(&id);
    let before = ws.link(&id);
    let mut closed = g.clone();
    closed.open = false;
    closed.state_reason = Some("completed".into());
    let mut a = pull_apply(&local, &closed);
    a.import = vec![gh_comment(100, "closing")];
    a.pushed_comments = vec![(101, 3)];
    a.comment_count = 2;
    let out = ws.apply(&a);
    let err = out.pull_error.expect("refused");
    assert!(err.detail().contains("bob"), "{err:?}");
    let now = ws.issue(&id);
    assert_eq!(now.status, Status::InProgress);
    let lease = ws.store.read(|r| r.lease(&id)).unwrap().expect("lease kept");
    assert_eq!(lease.token, claim.lease.token);
    let link = ws.link(&id);
    assert_eq!((link.comments.len(), link.comment_count), (2, Some(2)));
    assert_eq!(link.github_hash, before.github_hash);
}

#[test]
fn an_open_child_refuses_a_close_and_an_outcome_change() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    let child =
        ws.write("alice", |tx| tx.create_issue(NewIssue { parent: Some(id.clone()), ..NewIssue::titled("child") }));
    let mut closed = g.clone();
    closed.open = false;
    let local = ws.issue(&id);
    let out = ws.apply(&pull_apply(&local, &closed));
    assert!(
        matches!(out.pull_error, Some(PullError::Refused(ref m)) if m.contains("open child")),
        "{:?}",
        out.pull_error
    );

    // Closed done on both sides (child closed, parent closed, child reopened).
    ws.write("alice", |tx| tx.close_issue(&child.id, &CloseOptions::default()));
    let local = ws.issue(&id);
    ws.apply(&pull_apply(&local, &closed));
    assert_eq!(ws.issue(&id).close_outcome, Some(Outcome::Done));
    ws.write("alice", |tx| tx.reopen_issue(&child.id, None));
    let before = ws.link(&id);
    let mut failed = closed.clone();
    failed.state_reason = Some("not_planned".into());
    let local = ws.issue(&id);
    let head = ws.head();
    let out = ws.apply(&pull_apply(&local, &failed));
    assert!(matches!(out.pull_error, Some(PullError::Refused(_))), "{:?}", out.pull_error);
    let now = ws.issue(&id);
    assert_eq!((now.status, now.close_outcome), (Status::Closed, Some(Outcome::Done)));
    assert!(!ws.ops_since(head).iter().any(|o| o == "reopened"));
    assert_eq!(ws.link(&id).github_hash, before.github_hash);
}

#[test]
fn an_in_progress_issue_keeps_its_assignee() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    ws.write("carol", |tx| tx.claim(&id, &ClaimOptions::default()));
    let before = ws.link(&id);
    let mut theirs = g.clone();
    theirs.title = "B".into();
    theirs.assignees = vec!["octo".into()];
    let local = ws.issue(&id);
    let out = ws.apply(&pull_apply(&local, &theirs));
    assert!(out.pull_error.is_none(), "{:?}", out.pull_error);
    assert_eq!(out.notes.len(), 1);
    let now = ws.issue(&id);
    assert_eq!((now.title.as_str(), now.assignee.as_deref()), ("B", Some("carol")));
    let link = ws.link(&id);
    assert_eq!((&link.github_hash, &link.assignee), (&before.github_hash, &before.assignee));
    assert_eq!(link.local_hash, Some(Fields::of_local(&now, &cfg()).hash()));
}

#[test]
fn external_refs_and_summaries_are_written() {
    let mut ws = Ws::new();
    let id = ws.write("alice", |tx| tx.create_issue(NewIssue::titled("Mine"))).id;
    let g = gh(12, "Mine");
    let local = ws.issue(&id);
    let mut a = apply_of(&local, &g, Stamp::BOTH);
    a.set_external_ref = true;
    let out = ws.apply(&a);
    assert!(out.linked);
    assert_eq!(ws.issue(&id).external_ref.as_deref(), Some("gh:acme/app#12"));
    let head = ws.head();
    ws.write("sync", |tx| tx.github_synced(json!({ "repo": REPO })));
    assert_eq!(ws.ops_since(head), ["github_synced"]);
}

#[test]
fn closing_and_outcome_changes_keep_readiness_consistent() {
    let mut ws = Ws::new();
    let g = gh(7, "Blocker");
    let blocker = ws.pulled(&g);
    // `after` waits for the blocker to close; `fallback` runs only if it fails.
    let (after, fallback) = ws.write("alice", |tx| {
        let after = tx.create_issue(NewIssue::titled("After"))?;
        tx.add_dependency(&after.id, &blocker, DepType::Blocks, None)?;
        let fallback = tx.create_issue(NewIssue::titled("Fallback"))?;
        tx.add_dependency(&fallback.id, &blocker, DepType::ConditionalBlocks, None)?;
        Ok((after.id, fallback.id))
    });
    assert!(ws.issue(&after).is_blocked);
    let drift = |ws: &Ws| ws.store.read(|r| crate::graph::blocked_drift(r.conn())).unwrap();
    let mut done = g.clone();
    done.open = false;
    done.state_reason = Some("completed".into());
    let local = ws.issue(&blocker);
    ws.apply(&pull_apply(&local, &done));
    assert!(!ws.issue(&after).is_blocked);
    assert!(ws.issue(&fallback).is_blocked, "done: the fallback stays held");
    assert!(drift(&ws).is_empty());

    // done -> failed: reopened and closed again, and the fallback is free.
    let mut failed = done.clone();
    failed.state_reason = Some("not_planned".into());
    let local = ws.issue(&blocker);
    let head = ws.head();
    ws.apply(&pull_apply(&local, &failed));
    let now = ws.issue(&blocker);
    assert_eq!((now.status, now.close_outcome), (Status::Closed, Some(Outcome::Failed)));
    let ops = ws.ops_since(head);
    assert!(ops.contains(&"reopened".to_string()) && ops.contains(&"closed".to_string()), "{ops:?}");
    assert!(!ws.issue(&fallback).is_blocked && !ws.issue(&after).is_blocked);
    assert!(drift(&ws).is_empty());
    let link = ws.link(&blocker);
    assert_eq!(decide(&now, Some(&link), &failed, &cfg(), Direction::Both, None), Decision::Unchanged);

    // failed -> done holds the fallback back again.
    ws.apply(&pull_apply(&now, &done));
    assert_eq!(ws.issue(&blocker).close_outcome, Some(Outcome::Done));
    assert!(ws.issue(&fallback).is_blocked && !ws.issue(&after).is_blocked);
    assert!(drift(&ws).is_empty());
}

#[test]
fn a_conflict_that_imports_a_comment_keeps_newer_honest() {
    let mut ws = Ws::new();
    let g = gh(7, "A");
    let id = ws.pulled(&g);
    // bd edits at about 10:00 ...
    ws.write("alice", |tx| {
        tx.update_issue(
            &id,
            &IssuePatch { title: Some("Local".into()), ..Default::default() },
            &Guard::default(),
            false,
        )
    });
    // ... GitHub edits (and gains a comment) at 11:00; the sync at 11:05 reports the conflict, imports the comment.
    ws.clock.set(at(65));
    let mut theirs = g.clone();
    theirs.title = "GitHub".into();
    theirs.updated_at = at(60);
    theirs.comments = 1;
    let local = ws.issue(&id);
    let link = Link::of(&local).unwrap();
    assert!(matches!(decide(&local, Some(&link), &theirs, &cfg(), Direction::Both, None), Decision::Conflict { .. }));
    let mut a = apply_of(&local, &theirs, Stamp::NONE);
    a.import = vec![gh_comment(100, "hi")];
    a.comment_count = 1;
    ws.apply(&a);
    let now = ws.issue(&id);
    let link = Link::of(&now).unwrap();
    assert_eq!(link.own_local_at, Some(now.updated_at));
    assert_eq!(link.local_edit_at, Some(local.updated_at));
    assert_eq!(decide(&now, Some(&link), &theirs, &cfg(), Direction::Both, Some(Prefer::Newer)), Decision::Pull);
}

#[test]
fn markers_link_existing_issues() {
    let mut ws = Ws::new();
    let id = ws.write("alice", |tx| {
        let i = tx.create_issue(NewIssue::titled("Mine"))?;
        tx.add_comment(&i.id, "note")?;
        Ok(i.id)
    });
    let linked = ws.pulled(&gh(3, "Linked"));
    let with = |n: u64, id: &str| GithubIssue {
        body: format!("text\n\n{}", marker(id)),
        author: Some("BD-Bot".into()),
        ..gh(n, "x")
    };
    let found = ws
        .store
        .read(|r| {
            resolve_markers(
                r.conn(),
                &[with(10, &id), with(11, &linked), with(12, "t-404"), gh(13, "plain")],
                Some("bd-bot"),
            )
        })
        .unwrap();
    match &found[0] {
        MarkerMatch::Link { id: got, comments, .. } => assert_eq!((got, comments.len()), (&id, 1)),
        other => panic!("{other:?}"),
    }
    assert!(matches!(found[1], MarkerMatch::Error(_)));
    assert_eq!((&found[2], &found[3]), (&MarkerMatch::None, &MarkerMatch::None));
    let dup = ws.store.read(|r| resolve_markers(r.conn(), &[with(10, &id), with(14, &id)], Some("bd-bot"))).unwrap();
    assert!(dup.iter().all(|m| matches!(m, MarkerMatch::Error(_))));

    // Anyone else's marker is ignored: it neither links nor collides with bd's own.
    let foreign = |n: u64, author: Option<&str>| GithubIssue { author: author.map(String::from), ..with(n, &id) };
    let found = ws
        .store
        .read(|r| {
            resolve_markers(r.conn(), &[foreign(20, Some("mallory")), foreign(21, None), with(22, &id)], Some("bd-bot"))
        })
        .unwrap();
    assert_eq!((&found[0], &found[1]), (&MarkerMatch::None, &MarkerMatch::None));
    assert!(matches!(&found[2], MarkerMatch::Link { id: got, .. } if *got == id), "{:?}", found[2]);
    let unknown = ws.store.read(|r| resolve_markers(r.conn(), &[with(10, &id)], None)).unwrap();
    assert_eq!(unknown, [MarkerMatch::None], "without bd's own login, no marker counts");
    let all = ws.store.read(|r| linked_issues(r.conn())).unwrap();
    assert_eq!(all, [linked]);
}

fn linked_issues(conn: &Connection) -> Result<Vec<String>> {
    Ok(linked(conn, "ACME/app")?.into_iter().map(|i| i.id).collect())
}
