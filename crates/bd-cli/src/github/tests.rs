//! The sync engine against an in-memory GitHub ([`Fake`]): every platform.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use bd_core::github::{Fields, Link};
use bd_core::{
    ClaimOptions, CloseOptions, EventQuery, Guard, IdMode, InitOptions, IssuePatch, ManualClock, NewIssue, OpenOptions,
    Outcome, Queries, Store, WriteCtx,
};
use clap::Parser;

use super::*;
use crate::cli::Cli;

const T0: i64 = 1_800_000_000_000;

fn ts(min: i64) -> String {
    Timestamp(T0 + min * 60_000).to_rfc3339()
}

/// (prefix of "METHOD endpoint", status, headers).
type Scripted = (String, u16, Vec<(String, String)>);

#[derive(Default)]
struct State {
    issues: BTreeMap<u64, Value>,
    comments: BTreeMap<u64, Vec<Value>>,
    next_comment: i64,
    /// Minutes since T0; each GitHub write ticks it.
    clock: i64,
    log: Vec<String>,
    /// (prefix of "METHOD endpoint", status, headers): answered once each, in order.
    script: Vec<Scripted>,
    per_page: usize,
    /// Exact "METHOD endpoint" answered 200 with these headers and body, every time.
    answers: BTreeMap<String, (Vec<(String, String)>, Value)>,
    sleeps: Vec<Duration>,
    now_epoch: u64,
}

/// An in-memory GitHub: issues and comments as the REST API shapes them.
struct Fake(RefCell<State>);

fn issue_json(n: u64, title: &str) -> Value {
    json!({
        "number": n, "node_id": format!("I_{n}"), "title": title, "body": "", "state": "open",
        "state_reason": null, "labels": [], "assignees": [], "updated_at": ts(0),
        "html_url": format!("https://github.com/acme/app/issues/{n}"), "comments": 0,
        "user": {"login": "octo"}
    })
}

/// The account the fake `gh` is signed in as.
const SELF: &str = "bd-bot";

impl Fake {
    fn new() -> Fake {
        Fake(RefCell::new(State { next_comment: 1000, per_page: 100, now_epoch: 1_000_000, ..Default::default() }))
    }

    fn add(&self, n: u64, title: &str, f: impl FnOnce(&mut Value)) {
        let mut v = issue_json(n, title);
        f(&mut v);
        self.0.borrow_mut().issues.insert(n, v);
    }

    fn edit(&self, n: u64, f: impl FnOnce(&mut Value)) {
        let mut s = self.0.borrow_mut();
        s.clock += 1;
        let t = ts(s.clock);
        let v = s.issues.get_mut(&n).unwrap();
        f(v);
        v["updated_at"] = json!(t);
    }

    fn comment(&self, n: u64, body: &str) -> i64 {
        let mut s = self.0.borrow_mut();
        s.clock += 1;
        s.next_comment += 1;
        let (id, t) = (s.next_comment, ts(s.clock));
        s.comments.entry(n).or_default().push(json!({
            "id": id, "user": {"login": "octo"}, "body": body, "created_at": t, "updated_at": t,
            "html_url": format!("https://github.com/acme/app/issues/{n}#issuecomment-{id}")
        }));
        let count = s.comments[&n].len();
        let v = s.issues.get_mut(&n).unwrap();
        v["comments"] = json!(count);
        v["updated_at"] = json!(t);
        id
    }

    fn get(&self, n: u64) -> Value {
        self.0.borrow().issues[&n].clone()
    }

    fn script(&self, prefix: &str, status: u16, headers: &[(&str, &str)]) {
        let h = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.0.borrow_mut().script.push((prefix.into(), status, h));
    }

    fn answer_with(&self, line: &str, headers: &[(&str, &str)], body: Value) {
        let h = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.0.borrow_mut().answers.insert(line.into(), (h, body));
    }

    fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut self.0.borrow_mut().log)
    }

    fn writes(log: &[String]) -> Vec<&String> {
        log.iter().filter(|l| !l.starts_with("GET ")).collect()
    }

    fn answer(status: u16, headers: Vec<(String, String)>, body: Value) -> ApiResponse {
        ApiResponse { status, headers, body: serde_json::to_vec(&body).unwrap() }
    }
}

fn query(q: &str, key: &str) -> Option<String> {
    q.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(String::from))
}

fn names(v: &Value, field: &str) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.get(field).and_then(Value::as_str).map(String::from)).collect()
}

impl GithubApi for Fake {
    fn call(&self, method: &str, endpoint: &str, body: Option<&Value>) -> std::result::Result<ApiResponse, String> {
        let mut s = self.0.borrow_mut();
        let line = format!("{method} {endpoint}");
        s.log.push(match body {
            Some(b) => format!("{line} {b}"),
            None => line.clone(),
        });
        if let Some(i) = s.script.iter().position(|(p, ..)| line.starts_with(p.as_str())) {
            let (_, status, headers) = s.script.remove(i);
            return Ok(Fake::answer(status, headers, json!({ "message": "scripted" })));
        }
        if let Some((h, v)) = s.answers.get(&line) {
            return Ok(Fake::answer(200, h.clone(), v.clone()));
        }
        if (method, endpoint) == ("GET", "user") {
            return Ok(Fake::answer(200, vec![], json!({ "login": SELF })));
        }
        let (path, q) = endpoint.split_once('?').unwrap_or((endpoint, ""));
        let rest = path.strip_prefix("repos/acme/app/issues").expect("acme/app only");
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let page = |items: Vec<Value>, s: &State| -> ApiResponse {
            let page: usize = query(q, "page").and_then(|p| p.parse().ok()).unwrap_or(1);
            let per = s.per_page;
            let chunk: Vec<Value> = items.iter().skip((page - 1) * per).take(per).cloned().collect();
            let mut headers = Vec::new();
            if items.len() > page * per {
                headers.push(("link".into(), format!("<https://api.github.com/x?page={}>; rel=\"next\"", page + 1)));
            }
            Fake::answer(200, headers, Value::Array(chunk))
        };
        match (method, parts.as_slice()) {
            ("GET", []) => {
                let state = query(q, "state").unwrap_or_default();
                let labels = query(q, "labels");
                let items: Vec<Value> = s
                    .issues
                    .values()
                    .filter(|v| state == "all" || v["state"] == "open")
                    .filter(|v| labels.as_ref().is_none_or(|l| names(&v["labels"], "name").contains(l)))
                    .cloned()
                    .collect();
                Ok(page(items, &s))
            }
            ("GET", [n]) => Ok(match s.issues.get(&n.parse::<u64>().unwrap()) {
                Some(v) => Fake::answer(200, vec![], v.clone()),
                None => Fake::answer(404, vec![], json!({ "message": "Not Found" })),
            }),
            ("GET", [n, "comments"]) => {
                let items = s.comments.get(&n.parse::<u64>().unwrap()).cloned().unwrap_or_default();
                Ok(page(items, &s))
            }
            ("PATCH", [n]) => {
                let n: u64 = n.parse().unwrap();
                s.clock += 1;
                let t = ts(s.clock);
                let body = body.unwrap();
                let v = s.issues.get_mut(&n).unwrap();
                for key in ["title", "body"] {
                    if let Some(x) = body.get(key) {
                        v[key] = x.clone();
                    }
                }
                if let Some(l) = body.get("labels") {
                    v["labels"] = json!(l.as_array().unwrap().iter().map(|x| json!({"name": x})).collect::<Vec<_>>());
                }
                if let Some(a) = body.get("assignees") {
                    v["assignees"] =
                        json!(a.as_array().unwrap().iter().map(|x| json!({"login": x})).collect::<Vec<_>>());
                }
                // Like GitHub: a state_reason applies only with a change of state.
                if let Some(state) = body.get("state")
                    && *state != v["state"]
                {
                    v["state"] = state.clone();
                    v["state_reason"] = match state.as_str() {
                        Some("closed") => body.get("state_reason").cloned().unwrap_or(json!("completed")),
                        _ => json!("reopened"),
                    };
                }
                v["updated_at"] = json!(t);
                Ok(Fake::answer(200, vec![], v.clone()))
            }
            ("POST", []) => {
                let n = s.issues.keys().max().copied().unwrap_or(0) + 1;
                s.clock += 1;
                let t = ts(s.clock);
                let body = body.unwrap();
                let mut v = issue_json(n, body["title"].as_str().unwrap());
                v["user"] = json!({ "login": SELF });
                v["body"] = body["body"].clone();
                v["labels"] = json!(names_of(&body["labels"]).iter().map(|x| json!({"name": x})).collect::<Vec<_>>());
                v["assignees"] =
                    json!(names_of(&body["assignees"]).iter().map(|x| json!({"login": x})).collect::<Vec<_>>());
                v["updated_at"] = json!(t);
                s.issues.insert(n, v.clone());
                Ok(Fake::answer(201, vec![], v))
            }
            ("POST", [n, "comments"]) => {
                let n: u64 = n.parse().unwrap();
                s.clock += 1;
                s.next_comment += 1;
                let (id, t) = (s.next_comment, ts(s.clock));
                let c = json!({
                    "id": id, "user": {"login": "bd-bot"}, "body": body.unwrap()["body"], "created_at": t,
                    "updated_at": t, "html_url": format!("https://github.com/acme/app/issues/{n}#issuecomment-{id}")
                });
                s.comments.entry(n).or_default().push(c.clone());
                let count = s.comments[&n].len();
                let v = s.issues.get_mut(&n).unwrap();
                v["comments"] = json!(count);
                v["updated_at"] = json!(t);
                Ok(Fake::answer(201, vec![], c))
            }
            other => panic!("unexpected call {other:?}"),
        }
    }

    fn now_epoch(&self) -> u64 {
        self.0.borrow().now_epoch
    }

    fn sleep(&self, d: Duration) -> std::result::Result<(), String> {
        self.0.borrow_mut().sleeps.push(d);
        Ok(())
    }
}

fn names_of(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
}

struct Ws {
    _dir: tempfile::TempDir,
    app: App,
    clock: Arc<ManualClock>,
    fake: Fake,
}

fn ws() -> Ws {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".bd").join("bd.db");
    let clock = Arc::new(ManualClock::new(Timestamp(T0)));
    let opts = OpenOptions { clock: clock.clone(), ..Default::default() };
    let store = Store::init(&path, InitOptions { prefix: "t".into(), id_mode: IdMode::Counter }, opts).unwrap();
    let cli = Cli::try_parse_from(["bd", "--db", path.to_str().unwrap(), "--actor", "sync", "list"]).unwrap();
    let mut app = App::new(cli.global).unwrap();
    app.set_store(store);
    let mut ws = Ws { _dir: dir, app, clock, fake: Fake::new() };
    ws.config("github.assignees", "octo=alice,bob=bobby");
    ws.config("github.priority_labels", "P");
    ws
}

fn opts(dir: Direction) -> Opts {
    Opts {
        repo: Repo::parse("acme/app").unwrap(),
        dir,
        prefer: None,
        label: None,
        state_all: false,
        dry_run: false,
        create: false,
        comments: false,
        status: false,
    }
}

impl Ws {
    fn config(&mut self, key: &str, value: &str) {
        self.app.write("config", |tx| bd_core::config::set(tx, key, value)).unwrap();
    }

    fn tick(&self) {
        self.clock.advance(Duration::from_secs(60));
    }

    fn run_with(&mut self, o: &Opts) -> Report {
        self.tick();
        run(&mut self.app, &self.fake, o).unwrap()
    }

    fn run(&mut self, dir: Direction) -> Report {
        self.run_with(&opts(dir))
    }

    fn write<T>(&mut self, actor: &str, f: impl FnOnce(&mut WriteCtx<'_>) -> bd_core::Result<T>) -> T {
        self.tick();
        self.app.store().unwrap().write("test", actor, f).unwrap()
    }

    fn edit(&mut self, id: &str, patch: IssuePatch) {
        let id = id.to_string();
        self.write("alice", |tx| tx.update_issue(&id, &patch, &Guard::default(), false));
    }

    fn issue(&mut self, id: &str) -> Issue {
        self.app.read(|r| r.issue(id)).unwrap()
    }

    fn link(&mut self, id: &str) -> Link {
        Link::of(&self.issue(id)).unwrap()
    }

    fn by_ref(&mut self, n: u64) -> Issue {
        let r = format!("gh:acme/app#{n}");
        self.app
            .read(|r2| {
                Ok(github::linked(r2.conn(), "acme/app")?.into_iter().find(|i| i.external_ref.as_deref() == Some(&r)))
            })
            .unwrap()
            .unwrap_or_else(|| panic!("no bd issue linked to #{n}"))
    }

    fn head(&mut self) -> i64 {
        self.app.read(|r| r.event_head()).unwrap()
    }

    fn ops_since(&mut self, since: i64) -> Vec<String> {
        let q = EventQuery { since: Some(since), ..Default::default() };
        self.app.read(|r| r.events(&q)).unwrap().events.into_iter().map(|e| e.op).collect()
    }

    fn comments(&mut self, id: &str) -> Vec<Comment> {
        self.app.read(|r| r.comments(id)).unwrap()
    }
}

fn actions(r: &Report) -> Vec<(Option<u64>, String)> {
    r.results.iter().filter(|x| x.action != "unchanged").map(|x| (x.number, x.action.clone())).collect()
}

fn row(r: &Report, n: u64) -> &Row {
    r.results.iter().find(|x| x.number == Some(n)).unwrap_or_else(|| panic!("no row for #{n}: {:?}", r.results))
}

fn assert_quiet_rerun(w: &mut Ws, dir: Direction) {
    let head = w.head();
    w.fake.take_log();
    let r = w.run(dir);
    assert!(actions(&r).is_empty(), "{:?}", r.results);
    assert_eq!(w.head(), head, "nothing written");
    let log = w.fake.take_log();
    assert!(Fake::writes(&log).is_empty() && !log.iter().any(|l| l.contains("/comments")), "{log:?}");
}

#[test]
fn pull_creates_issues_across_pages_and_skips_pull_requests() {
    let mut w = ws();
    w.fake.0.borrow_mut().per_page = 2;
    w.fake.add(1, "One", |v| {
        v["labels"] = json!([{"name": "bug"}, {"name": "P1"}]);
        v["assignees"] = json!([{"login": "octo"}]);
    });
    w.fake.add(2, "PR", |v| v["pull_request"] = json!({"url": "x"}));
    w.fake.add(3, "Three", |v| v["assignees"] = json!([{"login": "stranger"}]));
    w.fake.add(4, "Four", |_| {});
    w.fake.add(5, "Five", |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("not_planned");
    });
    let r = w.run(Direction::Pull);
    assert_eq!(r.counts.get("created"), Some(&3), "{:?}", r.results);
    let log = w.fake.take_log();
    assert!(log.iter().any(|l| l.contains("page=2")), "{log:?}");
    let one = w.by_ref(1);
    assert_eq!(
        (one.priority, one.labels.clone(), one.assignee.as_deref()),
        (1, vec!["bug".to_string()], Some("alice"))
    );
    let three = w.by_ref(3);
    assert_eq!((three.assignee.clone(), w.link(&three.id).assignee.as_deref()), (None, Some("stranger")));
    assert_quiet_rerun(&mut w, Direction::Pull);

    // --state all brings the closed not_planned one, closed failed.
    let mut o = opts(Direction::Pull);
    o.state_all = true;
    w.run_with(&o);
    let five = w.by_ref(5);
    assert_eq!((five.status, five.close_outcome), (Status::Closed, Some(Outcome::Failed)));
}

#[test]
fn github_changes_touch_only_the_fields_that_changed() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Pull);
    let id = w.by_ref(7).id;
    let long = "l".repeat(70);
    w.edit(
        &id,
        IssuePatch { assignee: Some(Some("carol".into())), add_labels: vec![long.clone()], ..Default::default() },
    );
    w.run(Direction::Push);
    w.fake.edit(7, |v| v["title"] = json!("B"));
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 7).changed, ["title"], "{:?}", r.results);
    let i = w.issue(&id);
    assert_eq!((i.title.as_str(), i.assignee.as_deref(), i.labels.contains(&long)), ("B", Some("carol"), true));
    // A GitHub issue with no priority label leaves bd's priority, and a bd title push adds none.
    assert_eq!(i.priority, 2);
    w.edit(&id, IssuePatch { title: Some("C".into()), ..Default::default() });
    w.fake.take_log();
    w.run(Direction::Push);
    let log = w.fake.take_log();
    let patch = Fake::writes(&log);
    assert_eq!(patch.len(), 1, "{log:?}");
    assert!(patch[0].contains(r#""title":"C""#) && !patch[0].contains("labels"), "{patch:?}");
}

#[test]
fn a_closed_reason_change_on_github_changes_the_bd_outcome() {
    let mut w = ws();
    w.fake.add(7, "A", |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("completed");
    });
    let mut o = opts(Direction::Pull);
    o.state_all = true;
    w.run_with(&o);
    let id = w.by_ref(7).id;
    assert_eq!(w.issue(&id).close_outcome, Some(Outcome::Done));
    w.fake.edit(7, |v| v["state_reason"] = json!("not_planned"));
    let head = w.head();
    w.run_with(&o);
    let i = w.issue(&id);
    assert_eq!((i.status, i.close_outcome), (Status::Closed, Some(Outcome::Failed)));
    let ops = w.ops_since(head);
    assert!(ops.contains(&"reopened".to_string()) && ops.contains(&"closed".to_string()), "{ops:?}");
    let head = w.head();
    let r = w.run_with(&o);
    assert!(actions(&r).is_empty(), "{:?}", r.results);
    assert_eq!(w.head(), head);
}

#[test]
fn conflicts_are_reported_then_resolved() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    w.edit(&id, IssuePatch { title: Some("Local".into()), ..Default::default() });
    w.fake.edit(7, |v| v["title"] = json!("GitHub"));
    w.fake.take_log();
    let r = w.run(Direction::Both);
    assert_eq!(actions(&r), [(Some(7), "conflict".to_string())]);
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!((w.issue(&id).title, w.fake.get(7)["title"].clone()), ("Local".to_string(), json!("GitHub")));
    assert!(Fake::writes(&w.fake.take_log()).is_empty());

    let mut o = opts(Direction::Both);
    o.prefer = Some(Prefer::Github);
    w.run_with(&o);
    assert_eq!(w.issue(&id).title, "GitHub");
    assert_quiet_rerun(&mut w, Direction::Both);

    // --prefer local PATCHes only the title.
    w.edit(&id, IssuePatch { title: Some("Local again".into()), ..Default::default() });
    w.fake.edit(7, |v| v["title"] = json!("GitHub again"));
    o.prefer = Some(Prefer::Local);
    w.run_with(&o);
    let log = w.fake.take_log();
    let writes = Fake::writes(&log);
    assert_eq!(writes.len(), 1);
    assert!(writes[0].ends_with(r#"{"title":"Local again"}"#), "{writes:?}");
}

#[test]
fn one_sided_changes_wait_for_their_direction() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Pull);
    let id = w.by_ref(7).id;
    let before = w.link(&id);
    w.edit(&id, IssuePatch { title: Some("Local".into()), ..Default::default() });
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 7).action, "deferred");
    assert_eq!(w.link(&id).local_hash, before.local_hash);
    w.fake.take_log();
    w.run(Direction::Push);
    assert!(Fake::writes(&w.fake.take_log())[0].contains(r#""title":"Local""#));

    // The mirror: a GitHub edit is left by a push, applied by the next pull.
    w.fake.edit(7, |v| {
        v["title"] = json!("GitHub");
        v["assignees"] = json!([{"login": "octo"}]);
    });
    let before = w.link(&id);
    let r = w.run(Direction::Push);
    assert_eq!(row(&r, 7).action, "deferred");
    assert!(Fake::writes(&w.fake.take_log()).is_empty());
    let after = w.link(&id);
    assert_eq!((after.github_hash, after.assignee), (before.github_hash, before.assignee));
    w.run(Direction::Pull);
    let i = w.issue(&id);
    assert_eq!((i.title.as_str(), i.assignee.as_deref()), ("GitHub", Some("alice")));
}

#[test]
fn comments_flow_once_and_reruns_stay_quiet() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.fake.comment(7, "first");
    w.fake.comment(7, "second");
    let head = w.head();
    w.run(Direction::Pull);
    let id = w.by_ref(7).id;
    assert_eq!(w.ops_since(head).iter().filter(|o| *o == "commented").count(), 2);
    assert_quiet_rerun(&mut w, Direction::Pull);

    // A comment alone, no field change: imported once.
    w.fake.comment(7, "third");
    let head = w.head();
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 7).action, "comments");
    assert_eq!(w.ops_since(head).iter().filter(|o| *o == "commented").count(), 1);
    assert_quiet_rerun(&mut w, Direction::Pull);

    // A deleted comment: one fetch, a Link-only write, then quiet.
    w.fake.0.borrow_mut().comments.get_mut(&7).unwrap().pop();
    w.fake.edit(7, |v| v["comments"] = json!(2));
    w.fake.take_log();
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 7).action, "recorded", "{:?}", r.results);
    assert_eq!(w.link(&id).comment_count, Some(2));
    assert_quiet_rerun(&mut w, Direction::Pull);

    // GitHub's updated_at alone moving: nothing.
    w.fake.edit(7, |_| {});
    assert_quiet_rerun(&mut w, Direction::Both);
}

#[test]
fn comments_flow_during_conflicts_and_refused_closes() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.fake.add(8, "B", |_| {});
    w.run(Direction::Both);
    let (a, b) = (w.by_ref(7).id, w.by_ref(8).id);
    w.edit(&a, IssuePatch { title: Some("Local".into()), ..Default::default() });
    w.fake.edit(7, |v| v["title"] = json!("GitHub"));
    w.fake.comment(7, "during the conflict");
    // b is assigned to carol (synced), claimed by her, then closed on GitHub with a comment.
    w.edit(&b, IssuePatch { assignee: Some(Some("carol".into())), ..Default::default() });
    w.run(Direction::Push);
    let b2 = b.clone();
    w.write("carol", |tx| tx.claim(&b2, &ClaimOptions::default()));
    w.fake.edit(8, |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("completed");
    });
    w.fake.comment(8, "closing");
    let r = w.run(Direction::Both);
    assert_eq!(row(&r, 7).action, "conflict");
    assert_eq!(row(&r, 7).comments_imported, 1);
    assert_eq!(row(&r, 8).action, "error");
    assert!(row(&r, 8).detail.as_deref().unwrap().contains("carol"), "{:?}", row(&r, 8));
    assert_eq!(w.comments(&a).len(), 1);
    assert_eq!(w.comments(&b).len(), 1);
    assert_eq!(w.issue(&b).status, Status::InProgress);
    w.fake.take_log();
    w.run(Direction::Both);
    let log = w.fake.take_log();
    assert!(!log.iter().any(|l| l.contains("/comments")), "{log:?}");
}

#[test]
fn rate_limits_wait_briefly_or_stop_the_run() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.fake.script("GET repos/acme/app/issues?", 429, &[("retry-after", "0")]);
    let r = w.run(Direction::Pull);
    assert_eq!(r.counts.get("created"), Some(&1));
    assert_eq!(w.fake.0.borrow().sleeps, [Duration::ZERO]);
    w.fake.script(
        "GET repos/acme/app/issues?",
        403,
        &[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1000600")],
    );
    let e = run(&mut w.app, &w.fake, &opts(Direction::Pull)).unwrap_err().to_string();
    assert!(e.contains("rate limit") && e.contains("resets at"), "{e}");
}

#[test]
fn linked_issues_missing_from_the_listing_are_fetched() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.fake.add(8, "B", |_| {});
    w.run(Direction::Pull);
    w.fake.edit(7, |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("completed");
    });
    w.fake.0.borrow_mut().issues.remove(&8);
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 8).action, "gone");
    let a = w.by_ref(7);
    assert_eq!(a.status, Status::Closed);
    w.fake.take_log();
    w.run(Direction::Pull);
    assert!(!w.fake.take_log().iter().any(|l| l.ends_with("/issues/7")), "closed in bd: not fetched again");
}

#[test]
fn a_moved_issue_is_gone_and_never_rebound() {
    let mut w = ws();
    w.fake.add(5, "Five", |_| {});
    w.fake.add(12, "Twelve", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(5).id;
    let id2 = id.clone();
    w.write("alice", |tx| tx.add_comment(&id2, "from bd"));
    w.fake.0.borrow_mut().issues.remove(&5);
    // Transferred: GitHub's redirect answers with another number, or another repository.
    for (number, url) in
        [(12, "https://github.com/acme/other/issues/12"), (5, "https://github.com/ACME/other/issues/5")]
    {
        w.edit(&id, IssuePatch { title: Some(format!("edited for {url}")), ..Default::default() });
        let mut moved = issue_json(number, "Moved");
        moved["html_url"] = json!(url);
        w.fake.answer_with("GET repos/acme/app/issues/5", &[], moved);
        let mut o = opts(Direction::Both);
        o.comments = true;
        w.fake.take_log();
        let r = w.run_with(&o);
        assert_eq!(row(&r, 5).action, "gone", "{:?}", r.results);
        assert!(row(&r, 5).detail.as_deref().unwrap().contains("moved"));
        let log = w.fake.take_log();
        assert!(Fake::writes(&log).is_empty(), "{log:?}");
        assert_eq!(w.issue(&id).external_ref.as_deref(), Some("gh:acme/app#5"));
        assert_eq!(w.link(&id).number, 5);
    }
}

#[test]
fn an_issue_listed_twice_is_created_once() {
    let mut w = ws();
    w.fake.add(1, "One", |_| {});
    w.run(Direction::Pull);
    for (n, t) in [(2, "Two"), (3, "Three")] {
        w.fake.add(n, t, |_| {});
    }
    // An issue moved while paging: page 2 serves page 1's issues again.
    let base = "GET repos/acme/app/issues?state=open&sort=created&direction=asc&per_page=100";
    let next = "<https://api.github.com/x?page=2>; rel=\"next\"";
    let (one, two, three) = (w.fake.get(1), w.fake.get(2), w.fake.get(3));
    w.fake.answer_with(&format!("{base}&page=1"), &[("link", next)], json!([one, two]));
    w.fake.answer_with(&format!("{base}&page=2"), &[], json!([two, one, three]));
    let r = w.run(Direction::Pull);
    assert_eq!(actions(&r), [(Some(2), "created".to_string()), (Some(3), "created".to_string())], "{:?}", r.results);
    let refs: Vec<String> = w
        .app
        .read(|r| github::linked(r.conn(), "acme/app"))
        .unwrap()
        .into_iter()
        .filter_map(|i| i.external_ref)
        .collect();
    assert_eq!(refs.len(), 3, "{refs:?}");
    assert_quiet_rerun(&mut w, Direction::Pull);
}

#[test]
fn foreign_markers_never_link() {
    let mut w = ws();
    let id = w.write("alice", |tx| {
        let i = tx.create_issue(NewIssue::titled("Internal"))?;
        tx.add_comment(&i.id, "secret")?;
        Ok(i.id)
    });
    let body = format!("x\n\n{}", github::marker(&id));
    w.fake.add(99, "Bait", |v| {
        v["user"] = json!({ "login": "mallory" });
        v["body"] = json!(body);
    });
    let mut o = opts(Direction::Push);
    o.comments = true;
    w.fake.take_log();
    w.run_with(&o);
    let log = w.fake.take_log();
    assert!(Fake::writes(&log).is_empty(), "nothing of {id} reaches #99: {log:?}");
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 99).action, "created", "{:?}", r.results);
    assert_ne!(w.by_ref(99).id, id);
    assert_eq!(w.issue(&id).external_ref, None);
    assert_eq!(w.comments(&id).len(), 1);
}

#[test]
fn a_refused_login_lookup_ignores_markers_and_keeps_the_run() {
    let mut w = ws();
    let id = w.write("alice", |tx| Ok(tx.create_issue(NewIssue::titled("Mine"))?.id));
    let body = format!("x\n\n{}", github::marker(&id));
    w.fake.add(12, "Mine", |v| {
        v["user"] = json!({ "login": SELF });
        v["body"] = json!(body);
    });
    w.fake.add(13, "Other", |_| {});
    // An installation or Actions token cannot read `user`.
    w.fake.script("GET user", 403, &[]);
    let r = w.run(Direction::Pull);
    assert_eq!(r.aborted, None);
    assert_eq!(row(&r, 12).action, "created", "{:?}", r.results);
    assert_eq!(row(&r, 13).action, "created", "{:?}", r.results);
    assert_ne!(w.by_ref(12).id, id);
    assert_eq!(w.issue(&id).external_ref, None);
}

#[test]
fn a_failed_login_lookup_fails_the_run() {
    let mut w = ws();
    let id = w.write("alice", |tx| Ok(tx.create_issue(NewIssue::titled("Mine"))?.id));
    let body = format!("x\n\n{}", github::marker(&id));
    w.fake.add(12, "Mine", |v| {
        v["user"] = json!({ "login": SELF });
        v["body"] = json!(body);
    });
    // A transient failure, not a token that cannot read `user`.
    w.fake.script("GET user", 502, &[]);
    let head = w.head();
    let e = run(&mut w.app, &w.fake, &opts(Direction::Both)).unwrap_err().to_string();
    assert!(e.contains("GET user") && e.contains("502"), "{e}");
    assert!(w.ops_since(head).is_empty(), "nothing imported");
    assert!(Fake::writes(&w.fake.take_log()).is_empty(), "nothing pushed");
    assert_eq!(w.issue(&id).external_ref, None);
    // Run again once GitHub answers: the marker links, nothing is duplicated.
    let r = w.run(Direction::Pull);
    assert_eq!(r.results.len(), 1, "{:?}", r.results);
    assert_ne!(row(&r, 12).action, "created", "{:?}", r.results);
    assert_eq!(w.issue(&id).external_ref.as_deref(), Some("gh:acme/app#12"));
}

#[test]
fn markers_link_instead_of_duplicating() {
    let mut w = ws();
    let (id, cid) = w.write("alice", |tx| {
        let i = tx.create_issue(NewIssue { labels: vec!["sync".into()], ..NewIssue::titled("Mine") })?;
        let c = tx.add_comment(&i.id, "a note")?;
        Ok((i.id, c.id))
    });
    let marker_body = format!("\n\n{}", github::marker(&id));
    w.fake.add(12, "Mine", |v| {
        v["user"] = json!({ "login": SELF });
        v["body"] = json!(marker_body);
        v["labels"] = json!([{"name": "sync"}, {"name": "P2"}]);
    });
    w.fake.comment(12, &format!("a note\n\n{}", github::comment_marker(&id, cid)));
    w.fake.comment(12, &format!("again\n\n{}", github::comment_marker(&id, cid)));
    let head = w.head();
    let r = w.run(Direction::Pull);
    assert_eq!(actions(&r), [(Some(12), "linked".to_string())], "{:?}", r.results);
    assert_eq!(w.issue(&id).external_ref.as_deref(), Some("gh:acme/app#12"));
    assert!(!w.ops_since(head).contains(&"commented".to_string()));
    assert_eq!(w.link(&id).comments.len(), 2);
    assert_quiet_rerun(&mut w, Direction::Pull);

    // A marker naming an issue linked elsewhere is an error; nothing is created.
    let other = format!("\n\n{}", github::marker(&id));
    w.fake.add(13, "Copy", |v| {
        v["user"] = json!({ "login": SELF });
        v["body"] = json!(other);
    });
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 13).action, "error");
    let mut o = opts(Direction::Both);
    o.create = true;
    o.label = Some("sync".into());
    w.fake.take_log();
    w.run_with(&o);
    assert!(Fake::writes(&w.fake.take_log()).is_empty(), "no POST for a linked issue");
}

#[test]
fn a_crashed_create_with_comments_is_recovered_by_markers() {
    let mut w = ws();
    let (id, c1, c2) = w.write("alice", |tx| {
        let i = tx.create_issue(NewIssue { labels: vec!["sync".into()], ..NewIssue::titled("Publish me") })?;
        let a = tx.add_comment(&i.id, "one")?;
        let b = tx.add_comment(&i.id, "two")?;
        Ok((i.id, a.id, b.id))
    });
    // The push --create --comments ran on GitHub, then crashed before its bd write.
    let local = w.issue(&id);
    let body = github::create_body(&local, &mapping());
    w.fake.add(12, "Publish me", |v| {
        v["user"] = json!({ "login": SELF });
        v["body"] = body["body"].clone();
        v["labels"] = json!(names_of(&body["labels"]).iter().map(|x| json!({"name": x})).collect::<Vec<_>>());
    });
    let comments = w.comments(&id);
    w.fake.comment(12, &github::push_comment_body(&comments[0]));
    w.fake.comment(12, &github::push_comment_body(&comments[1]));
    let head = w.head();
    let r = w.run(Direction::Pull);
    assert_eq!(row(&r, 12).action, "linked", "{:?}", r.results);
    let link = w.link(&id);
    assert_eq!(link.comments.values().copied().collect::<Vec<_>>(), [c1, c2]);
    assert!(!w.ops_since(head).iter().any(|o| o == "commented" || o == "created"));
    let mut o = opts(Direction::Push);
    o.comments = true;
    w.fake.take_log();
    w.run_with(&o);
    assert!(Fake::writes(&w.fake.take_log()).is_empty());
}

#[test]
fn newer_follows_the_real_edit_times() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    // bd edits at T0+10m; GitHub edits and comments at T0+60m; a sync at T0+65m imports the comment.
    w.clock.set(Timestamp(T0 + 10 * 60_000));
    w.edit(&id, IssuePatch { title: Some("Local".into()), ..Default::default() });
    w.fake.0.borrow_mut().clock = 59;
    w.fake.edit(7, |v| v["title"] = json!("GitHub"));
    w.fake.comment(7, "hi");
    w.clock.set(Timestamp(T0 + 65 * 60_000));
    let r = w.run(Direction::Both);
    assert_eq!(row(&r, 7).action, "conflict");
    let mut o = opts(Direction::Both);
    o.prefer = Some(Prefer::Newer);
    w.run_with(&o);
    assert_eq!(w.issue(&id).title, "GitHub");

    // The mirror: GitHub at T0+100m, a bd comment posted during the conflict, bd at T0+120m.
    w.fake.0.borrow_mut().clock = 99;
    w.fake.edit(7, |v| v["title"] = json!("GitHub 2"));
    w.clock.set(Timestamp(T0 + 120 * 60_000));
    w.edit(&id, IssuePatch { title: Some("Local 2".into()), ..Default::default() });
    let id2 = id.clone();
    w.write("alice", |tx| tx.add_comment(&id2, "from bd"));
    w.fake.0.borrow_mut().clock = 200;
    let mut c = opts(Direction::Both);
    c.comments = true;
    let r = w.run_with(&c);
    assert_eq!((row(&r, 7).action.as_str(), row(&r, 7).comments_pushed), ("conflict", 1));
    w.run_with(&o);
    assert_eq!(w.fake.get(7)["title"], json!("Local 2"));
}

#[test]
fn pushes_keep_what_bd_cannot_represent() {
    let mut w = ws();
    let long = "l".repeat(60);
    let l2 = long.clone();
    w.fake.add(7, "A", |v| {
        v["assignees"] = json!([{"login": "stranger"}, {"login": "bob"}]);
        v["labels"] = json!([{"name": l2}, {"name": "P1"}, {"name": "P3"}]);
    });
    w.fake.add(8, "B", |v| v["assignees"] = json!([{"login": "octo"}, {"login": "carl"}]));
    w.run(Direction::Pull);
    let (a, b) = (w.by_ref(7).id, w.by_ref(8).id);
    w.edit(&a, IssuePatch { title: Some("A2".into()), ..Default::default() });
    w.fake.take_log();
    w.run(Direction::Push);
    let log = w.fake.take_log();
    assert!(Fake::writes(&log)[0].ends_with(r#"{"title":"A2"}"#), "{log:?}");
    let v = w.fake.get(7);
    assert_eq!(names(&v["assignees"], "login"), ["stranger", "bob"]);

    w.edit(&a, IssuePatch { priority: Some(2), ..Default::default() });
    w.run(Direction::Push);
    assert_eq!(names(&w.fake.get(7)["labels"], "name"), [long.as_str(), "P3", "P2"]);

    w.edit(&b, IssuePatch { assignee: Some(Some("bobby".into())), ..Default::default() });
    w.run(Direction::Push);
    assert_eq!(names(&w.fake.get(8)["assignees"], "login"), ["bob", "carl"]);
    assert_quiet_rerun(&mut w, Direction::Both);
}

#[test]
fn create_publishes_labelled_issues_once() {
    let mut w = ws();
    w.write("alice", |tx| {
        tx.create_issue(NewIssue { labels: vec!["sync".into()], ..NewIssue::titled("Publish") })?;
        tx.create_issue(NewIssue::titled("Private"))?;
        Ok(())
    });
    let mut o = opts(Direction::Push);
    o.create = true;
    o.label = Some("sync".into());
    let r = w.run_with(&o);
    assert_eq!(r.counts.get("created"), Some(&1), "{:?}", r.results);
    let log = w.fake.take_log();
    let post = Fake::writes(&log);
    assert_eq!(post.len(), 1);
    assert!(post[0].contains("<!-- bd:t-1 -->") && post[0].contains(r#""labels":["sync","P2"]"#), "{post:?}");
    assert_eq!(w.issue("t-1").external_ref.as_deref(), Some("gh:acme/app#1"));
    w.run_with(&o);
    assert!(Fake::writes(&w.fake.take_log()).is_empty());
}

#[test]
fn failed_pushes_are_reported_and_aborts_record_what_succeeded() {
    let mut w = ws();
    for n in 1..=3 {
        w.fake.add(n, &format!("Issue {n}"), |_| {});
    }
    w.run(Direction::Pull);
    let ids: Vec<String> = (1..=3).map(|n| w.by_ref(n).id).collect();
    for id in &ids {
        w.edit(id, IssuePatch { title: Some(format!("{id} edited")), ..Default::default() });
    }
    w.fake.script("PATCH repos/acme/app/issues/1", 422, &[]);
    let r = w.run(Direction::Push);
    assert_eq!(row(&r, 1).action, "error");
    assert_eq!((row(&r, 2).action.as_str(), row(&r, 3).action.as_str()), ("pushed", "pushed"));
    assert!(r.aborted.is_none());

    for id in &ids {
        w.edit(id, IssuePatch { title: Some(format!("{id} again")), ..Default::default() });
    }
    w.fake.script("PATCH repos/acme/app/issues/2", 500, &[]);
    let r = w.run(Direction::Push);
    assert!(r.aborted.is_some());
    assert_eq!(row(&r, 1).action, "pushed");
    let before = w.link(&ids[1]).local_hash;
    assert_ne!(before, Some(Fields::of_local(&w.issue(&ids[1]), &mapping()).hash()));
    w.fake.take_log();
    w.run(Direction::Push);
    let log = w.fake.take_log();
    let writes = Fake::writes(&log);
    assert_eq!(writes.len(), 2, "issues 2 and 3 remain: {writes:?}");
    assert!(writes[0].starts_with("PATCH repos/acme/app/issues/2"));
}

#[test]
fn pushed_comments_carry_markers_and_are_adopted_after_a_crash() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    let id2 = id.clone();
    w.write("alice", |tx| tx.add_comment(&id2, "from bd"));
    let mut o = opts(Direction::Push);
    o.comments = true;
    w.fake.take_log();
    w.run_with(&o);
    let log = w.fake.take_log();
    let posts = Fake::writes(&log);
    assert_eq!(posts.len(), 1);
    assert!(posts[0].contains("<!-- bd:t-1#c"), "{posts:?}");
    let head = w.head();
    w.run(Direction::Pull);
    assert!(!w.ops_since(head).contains(&"commented".to_string()), "not imported back");
    assert_quiet_rerun(&mut w, Direction::Both);

    // A crash after the POST: GitHub has the comment, bd never recorded it.
    let id3 = id.clone();
    let c = w.write("alice", |tx| tx.add_comment(&id3, "second"));
    w.fake.comment(7, &github::push_comment_body(&c));
    w.fake.comment(7, "foreign");
    let stored = w.link(&id).comment_count.unwrap();
    w.fake.take_log();
    let r = w.run_with(&o);
    assert_eq!(row(&r, 7).comments_adopted, 1, "{:?}", r.results);
    assert!(Fake::writes(&w.fake.take_log()).is_empty(), "nothing posted again");
    assert_eq!(w.link(&id).comment_count, Some(stored + 1));
    let head = w.head();
    w.run(Direction::Pull);
    assert_eq!(w.ops_since(head).iter().filter(|o| *o == "commented").count(), 1, "the foreign one");
}

#[test]
fn sync_comments_both_ways_on_one_issue() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    w.fake.comment(7, "from GitHub");
    let id2 = id.clone();
    w.write("alice", |tx| tx.add_comment(&id2, "from bd"));
    let mut o = opts(Direction::Both);
    o.comments = true;
    let r = w.run_with(&o);
    assert_eq!((row(&r, 7).comments_imported, row(&r, 7).comments_pushed), (1, 1));
    let link = w.link(&id);
    assert_eq!(link.comments.len(), 2);
    assert_eq!(link.comment_count, w.fake.get(7)["comments"].as_u64());
    let head = w.head();
    w.fake.take_log();
    w.run_with(&o);
    assert_eq!(w.head(), head);
    let log = w.fake.take_log();
    assert!(Fake::writes(&log).is_empty() && !log.iter().any(|l| l.contains("/comments")), "{log:?}");
}

#[test]
fn a_refused_close_still_posts_and_records_comments() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    let id2 = id.clone();
    w.write("alice", |tx| {
        tx.create_issue(NewIssue { parent: Some(id2.clone()), ..NewIssue::titled("child") })?;
        tx.add_comment(&id2, "from bd")
    });
    w.fake.edit(7, |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("completed");
    });
    let mut o = opts(Direction::Both);
    o.comments = true;
    let r = w.run_with(&o);
    assert_eq!((row(&r, 7).action.as_str(), row(&r, 7).comments_pushed), ("error", 1));
    let mut p = opts(Direction::Push);
    p.comments = true;
    w.fake.take_log();
    w.run_with(&p);
    assert!(Fake::writes(&w.fake.take_log()).is_empty());
}

#[test]
fn a_failed_comment_post_is_an_error_and_a_patch_still_counts() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.run(Direction::Both);
    let id = w.by_ref(7).id;
    let mut o = opts(Direction::Both);
    o.comments = true;

    // Pulled, then the comment POST is refused: the row says error, with what was pulled.
    w.fake.edit(7, |v| v["title"] = json!("GitHub"));
    let id2 = id.clone();
    w.write("alice", |tx| tx.add_comment(&id2, "one"));
    w.fake.script("POST repos/acme/app/issues/7/comments", 422, &[]);
    let r = w.run_with(&o);
    assert_eq!(row(&r, 7).action, "error", "{:?}", r.results);
    assert!(row(&r, 7).detail.as_deref().unwrap().starts_with("pulled title; then: "), "{:?}", r.results);
    assert_eq!(w.issue(&id).title, "GitHub");

    // Pushed, then the comment POST is refused: the summary still lists the push.
    w.edit(&id, IssuePatch { title: Some("Local".into()), ..Default::default() });
    w.fake.script("POST repos/acme/app/issues/7/comments", 422, &[]);
    let head = w.head();
    let r = w.run_with(&o);
    assert_eq!(row(&r, 7).action, "error", "{:?}", r.results);
    assert_eq!(w.fake.get(7)["title"], "Local");
    let q = EventQuery { since: Some(head), ..Default::default() };
    let events = w.app.read(|r| r.events(&q)).unwrap().events;
    let synced = events.iter().find(|e| e.op == "github_synced").expect("a summary");
    assert_eq!(synced.data["pushed"], json!([id]), "{:?}", synced.data);
}

#[test]
fn closed_outcome_changes_reach_github() {
    let mut w = ws();
    w.fake.add(7, "A", |v| {
        v["state"] = json!("closed");
        v["state_reason"] = json!("completed");
    });
    let mut o = opts(Direction::Push);
    o.state_all = true;
    let mut pull = opts(Direction::Pull);
    pull.state_all = true;
    w.run_with(&pull);
    let id = w.by_ref(7).id;
    let id2 = id.clone();
    w.write("alice", |tx| {
        tx.reopen_issue(&id2, None)?;
        tx.close_issue(&id2, &CloseOptions { outcome: Some(Outcome::Failed), ..Default::default() })
    });
    w.fake.take_log();
    w.run_with(&o);
    let log = w.fake.take_log();
    let writes = Fake::writes(&log);
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert!(writes[0].ends_with(r#"{"state":"open"}"#) && writes[1].contains("not_planned"), "{writes:?}");
    assert_eq!(w.fake.get(7)["state_reason"], json!("not_planned"));
    assert_quiet_rerun(&mut w, Direction::Both);
}

#[test]
fn a_failed_close_after_create_is_finished_by_the_next_push() {
    let mut w = ws();
    w.write("alice", |tx| {
        let i = tx.create_issue(NewIssue { labels: vec!["sync".into()], ..NewIssue::titled("Done already") })?;
        tx.close_issue(&i.id, &CloseOptions::default())
    });
    let mut o = opts(Direction::Push);
    o.create = true;
    o.label = Some("sync".into());
    o.state_all = true;
    w.fake.script("PATCH repos/acme/app/issues/1", 500, &[]);
    let r = w.run_with(&o);
    assert!(r.aborted.is_some());
    assert_eq!(w.issue("t-1").external_ref.as_deref(), Some("gh:acme/app#1"));
    assert_eq!(w.fake.get(1)["state"], json!("open"));
    w.run_with(&o);
    assert_eq!(w.fake.get(1)["state"], json!("closed"));
    assert_quiet_rerun(&mut w, Direction::Both);
}

#[test]
fn dry_runs_and_status_change_nothing() {
    let mut w = ws();
    w.fake.add(7, "A", |_| {});
    w.fake.comment(7, "hi");
    let head = w.head();
    let mut o = opts(Direction::Both);
    o.status = true;
    w.fake.take_log();
    let r = w.run_with(&o);
    assert_eq!(row(&r, 7).action, "would create");
    assert_eq!(w.head(), head);
    let log = w.fake.take_log();
    assert!(Fake::writes(&log).is_empty() && !log.iter().any(|l| l.contains("/comments")), "{log:?}");
    let _ = render(&r);
}

/// The mapping [`ws`] configures.
fn mapping() -> SyncConfig {
    SyncConfig {
        assignees: vec![("octo".into(), "alice".into()), ("bob".into(), "bobby".into())],
        priority_prefix: Some("P".into()),
    }
}
