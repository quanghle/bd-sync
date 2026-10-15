//! `bd github status|pull|push|sync`: two-way sync between GitHub Issues and
//! bd issues, through `gh api` (see [`crate::gh`]).
//!
//! A run reads one snapshot (the linked issues, their comments, the
//! `--create` candidates), fetches from GitHub (the listing, linked issues
//! missing from it, then comments where GitHub's count moved), resolves
//! issue markers in a second short read, plans every issue with the pure
//! engine in [`bd_core::github`], makes its GitHub writes, and finally
//! applies everything in exactly one write transaction, each issue in its own
//! savepoint. `gh` never runs while that transaction is open. Repositories
//! are checked against `github.repos` before any GitHub call; through `bd
//! serve` every subcommand needs an admin token.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use bd_core::gates::{self, GateRepos};
use bd_core::github::{
    self, CommentPlan, Decision, Direction, GithubComment, GithubIssue, IssueApply, Link, MarkerMatch, Prefer, Stamp,
    SyncConfig,
};
use bd_core::{Comment, Error, Issue, ListQuery, Result, Status, Timestamp, WorkFilter, comments, issues};
use serde::Serialize;
use serde_json::{Value, json};

use crate::app::{App, Out};
use crate::cli::{GithubArgs, GithubCommand, GithubState, PreferArg};
use crate::gh::{self, ApiResponse};
use crate::io;

/// How bd reaches the GitHub API: `gh` in production, a fake in tests.
pub trait GithubApi {
    /// One HTTP call: `method` on `endpoint` (relative to the API root).
    fn call(&self, method: &str, endpoint: &str, body: Option<&Value>) -> std::result::Result<ApiResponse, String>;
    /// Seconds since the epoch, for rate-limit resets.
    fn now_epoch(&self) -> u64;
    /// Wait before retrying a rate-limited call; fails once cancelled.
    fn sleep(&self, d: Duration) -> std::result::Result<(), String>;
}

/// [`GithubApi`] over `gh api`.
pub struct GhCli {
    pub host: Option<String>,
    pub cwd: PathBuf,
}

impl GithubApi for GhCli {
    fn call(&self, method: &str, endpoint: &str, body: Option<&Value>) -> std::result::Result<ApiResponse, String> {
        gh::gh_api(method, endpoint, self.host.as_deref(), body, &self.cwd)
    }

    fn now_epoch(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    fn sleep(&self, d: Duration) -> std::result::Result<(), String> {
        let end = std::time::Instant::now() + d;
        loop {
            if gh::gh_cancelled() {
                return Err("cancelled, the server is shutting down".into());
            }
            let left = end.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(());
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
}

/// The longest rate-limit wait a run sits through, and how many times per call.
const MAX_WAIT: Duration = Duration::from_secs(60);
const MAX_RETRIES: usize = 3;
/// Pages of 100 a listing reads at most.
const MAX_PAGES: usize = 1000;

/// Why a GitHub call failed: `fatal` stops a run's GitHub writes.
#[derive(Debug)]
struct Failure {
    fatal: bool,
    msg: String,
}

impl Failure {
    fn fatal(msg: impl Into<String>) -> Failure {
        Failure { fatal: true, msg: msg.into() }
    }
}

/// Call the API, waiting out short rate limits. Returns the final answer
/// whatever its status, except a rate limit that cannot wait (or a failure
/// to call at all), which is fatal.
fn call(
    api: &dyn GithubApi,
    method: &str,
    endpoint: &str,
    body: Option<&Value>,
) -> std::result::Result<ApiResponse, Failure> {
    let mut retries = 0;
    loop {
        let resp = api.call(method, endpoint, body).map_err(Failure::fatal)?;
        let Some(limit) = gh::rate_limit_wait(&resp, api.now_epoch()) else { return Ok(resp) };
        if limit.wait > MAX_WAIT || retries >= MAX_RETRIES {
            let reset = Timestamp((limit.reset_at as i64).saturating_mul(1000));
            return Err(Failure::fatal(format!(
                "GitHub rate limit reached ({method} {endpoint}); it resets at {reset}, run again then"
            )));
        }
        api.sleep(limit.wait).map_err(Failure::fatal)?;
        retries += 1;
    }
}

/// A non-2xx answer as a failure: 401, 403, 429 and 5xx are fatal, other
/// 4xx (validation, not found) concern one issue.
fn refused(method: &str, endpoint: &str, resp: &ApiResponse) -> Failure {
    let fatal = matches!(resp.status, 401 | 403 | 429) || resp.status >= 500;
    Failure { fatal, msg: format!("GitHub refused {method} {endpoint} (HTTP {}): {}", resp.status, resp.message()) }
}

/// Call and require a 2xx answer.
fn request(
    api: &dyn GithubApi,
    method: &str,
    endpoint: &str,
    body: Option<&Value>,
) -> std::result::Result<ApiResponse, Failure> {
    let resp = call(api, method, endpoint, body)?;
    if resp.ok() { Ok(resp) } else { Err(refused(method, endpoint, &resp)) }
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A repository: `owner/name`, on `host` when not the default one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repo {
    pub host: Option<String>,
    pub owner: String,
    pub name: String,
}

impl Repo {
    /// `OWNER/REPO` or `HOST/OWNER/REPO` (github.com is the default host).
    pub fn parse(s: &str) -> Result<Repo> {
        let s = s.trim();
        gates::validate_repo(s)?;
        let parts: Vec<&str> = s.split('/').collect();
        let (host, owner, name) = match parts.as_slice() {
            [o, n] => (None, *o, *n),
            [h, o, n] => (Some(h.to_ascii_lowercase()).filter(|h| h != "github.com"), *o, *n),
            _ => unreachable!("validated"),
        };
        Ok(Repo { host, owner: owner.to_string(), name: name.to_string() })
    }

    /// The lowercased `[host/]owner/name` that external_ref and metadata name.
    pub fn key(&self) -> String {
        match &self.host {
            Some(h) => format!("{h}/{}/{}", self.owner, self.name).to_ascii_lowercase(),
            None => format!("{}/{}", self.owner, self.name).to_ascii_lowercase(),
        }
    }

    fn path(&self) -> String {
        format!("repos/{}/{}", self.owner, self.name)
    }
}

/// Every page of `endpoint` (which has a query already).
fn paged(api: &dyn GithubApi, endpoint: &str) -> std::result::Result<Vec<Value>, Failure> {
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let resp = request(api, "GET", &format!("{endpoint}&per_page=100&page={page}"), None)?;
        let items = resp.json().map_err(Failure::fatal)?;
        let items =
            items.as_array().ok_or_else(|| Failure::fatal(format!("GitHub returned no list for {endpoint}")))?;
        out.extend(items.iter().cloned());
        if !gh::next_page(&resp) || items.is_empty() {
            break;
        }
    }
    Ok(out)
}

fn parse_issue(v: &Value) -> std::result::Result<GithubIssue, Failure> {
    GithubIssue::from_json(v).map_err(|e| Failure::fatal(e.to_string()))
}

/// The repository's issues (pull requests left out), oldest first.
fn list_issues(
    api: &dyn GithubApi,
    repo: &Repo,
    state_all: bool,
    label: Option<&str>,
) -> std::result::Result<Vec<GithubIssue>, Failure> {
    let state = if state_all { "all" } else { "open" };
    let labels = label.map(|l| format!("&labels={}", pct(l))).unwrap_or_default();
    let endpoint = format!("{}/issues?state={state}{labels}&sort=created&direction=asc", repo.path());
    let mut out = Vec::new();
    // Pages are offsets: an issue that moves while paging can be served twice.
    let mut seen = HashSet::new();
    for v in paged(api, &endpoint)? {
        let issue = parse_issue(&v)?;
        if !issue.pull_request && seen.insert(issue.number) {
            out.push(issue);
        }
    }
    Ok(out)
}

/// One issue; None when GitHub says it is gone (404, 410), or answers with
/// another issue: a transferred issue's GET follows the redirect to its new
/// repository and number, which must never be bound to the asked-for one.
fn get_issue(api: &dyn GithubApi, repo: &Repo, n: u64) -> std::result::Result<Option<GithubIssue>, Failure> {
    let endpoint = format!("{}/issues/{n}", repo.path());
    let resp = call(api, "GET", &endpoint, None)?;
    match resp.status {
        404 | 410 => Ok(None),
        _ if resp.ok() => {
            let issue = parse_issue(&resp.json().map_err(Failure::fatal)?)?;
            let tail = format!("/{}/{}/issues/{n}", repo.owner, repo.name).to_ascii_lowercase();
            let same = issue.number == n && issue.html_url.to_ascii_lowercase().ends_with(&tail);
            Ok(same.then_some(issue))
        }
        _ => Err(Failure::fatal(refused("GET", &endpoint, &resp).msg)),
    }
}

/// The login `gh` is signed in as, which bd's own issues are opened by;
/// None when this token cannot read `user` (401, 403 or 404: an App
/// installation or Actions token), and then markers are ignored this run.
/// Anyone can open an issue with a marker, so such a refusal must not stop
/// the run; any other failure (5xx, a 429) does, as ignoring markers then
/// could duplicate what a crashed push left unrecorded.
fn self_login(api: &dyn GithubApi) -> std::result::Result<Option<String>, Failure> {
    let resp = call(api, "GET", "user", None)?;
    match resp.status {
        401 | 403 | 404 => return Ok(None),
        _ if !resp.ok() => return Err(Failure::fatal(refused("GET", "user", &resp).msg)),
        _ => {}
    }
    let v = resp.json().map_err(Failure::fatal)?;
    Ok(v.get("login").and_then(Value::as_str).map(String::from))
}

fn list_comments(api: &dyn GithubApi, repo: &Repo, n: u64) -> std::result::Result<Vec<GithubComment>, Failure> {
    let endpoint = format!("{}/issues/{n}/comments?sort=created", repo.path());
    paged(api, &endpoint)?
        .iter()
        .map(|v| GithubComment::from_json(v).map_err(|e| Failure::fatal(e.to_string())))
        .collect()
}

/// A linked bd issue and its comments, as read.
type Local = (Issue, Vec<Comment>);

/// What a run does.
#[derive(Clone, Debug)]
pub struct Opts {
    pub repo: Repo,
    pub dir: Direction,
    pub prefer: Option<Prefer>,
    pub label: Option<String>,
    pub state_all: bool,
    pub dry_run: bool,
    pub create: bool,
    pub comments: bool,
    /// `bd github status`: a dry run of a sync.
    pub status: bool,
}

/// One issue's line of a run's result.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub comments_imported: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub comments_adopted: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub comments_pushed: usize,
    /// GitHub took this issue's PATCH, whatever happened next.
    #[serde(skip)]
    pub patched: bool,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictRow {
    pub id: String,
    pub number: u64,
    pub local_hash: String,
    pub github_hash: String,
}

/// What a run did, as `--json` prints it.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub repo: String,
    pub direction: &'static str,
    pub dry_run: bool,
    pub results: Vec<Row>,
    pub counts: BTreeMap<String, usize>,
    pub conflicts: Vec<ConflictRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aborted: Option<String>,
}

/// How a listed GitHub issue relates to bd.
enum Kind {
    /// Linked by external_ref (`Marker` when linked this run by its issue marker).
    Linked { local: Box<Issue>, link: Option<Box<Link>>, comments: Vec<Comment>, marker: bool },
    /// New to bd: created in a pulling direction.
    New,
    /// Cannot sync: a marker that cannot link, or several bd issues linked to one.
    Error(Option<String>, String),
}

/// One GitHub issue's plan and results.
struct Item {
    gh: GithubIssue,
    kind: Kind,
    decision: Decision,
    fetched: Option<Vec<GithubComment>>,
    comments: CommentPlan,
    would_fetch: bool,
    // Results of the GitHub writes.
    github_after: Option<GithubIssue>,
    stamp: Stamp,
    own_github_at: Option<Timestamp>,
    pushed: Vec<(i64, i64)>,
    pushed_fields: Vec<String>,
    unapplied: Vec<String>,
    error: Option<String>,
}

impl Item {
    fn new(gh: GithubIssue, kind: Kind) -> Item {
        Item {
            gh,
            kind,
            decision: Decision::Unchanged,
            fetched: None,
            comments: CommentPlan::default(),
            would_fetch: false,
            github_after: None,
            stamp: Stamp::NONE,
            own_github_at: None,
            pushed: Vec::new(),
            pushed_fields: Vec::new(),
            unapplied: Vec::new(),
            error: None,
        }
    }

    fn local(&self) -> Option<(&Issue, Option<&Link>, &[Comment], bool)> {
        match &self.kind {
            Kind::Linked { local, link, comments, marker } => Some((local, link.as_deref(), comments, *marker)),
            _ => None,
        }
    }
}

/// A bd issue `--create` publishes, and the results of doing so.
struct Publish {
    local: Issue,
    comments: Vec<Comment>,
    created: Option<GithubIssue>,
    after: Option<GithubIssue>,
    closed_ok: bool,
    own_github_at: Option<Timestamp>,
    pushed: Vec<(i64, i64)>,
    error: Option<String>,
}

fn later(a: Option<Timestamp>, b: Timestamp) -> Option<Timestamp> {
    Some(a.map_or(b, |a| a.max(b)))
}

fn fail_run(f: Failure) -> Error {
    Error::Io(std::io::Error::other(f.msg))
}

/// Run one `bd github` command against `api`; returns the report.
pub fn run(app: &mut App, api: &dyn GithubApi, o: &Opts) -> Result<Report> {
    let key = o.repo.key();
    let dir = o.dir;
    let want_comments = dir.pulls() || o.comments;

    // 1. The snapshot: config, linked issues and their comments, --create candidates.
    let (cfg, linked, mut candidates) = app.read(|r| {
        let cfg = SyncConfig::load(r.conn())?;
        let mut linked = Vec::new();
        for i in github::linked(r.conn(), &key)? {
            let c = if want_comments { comments::list(r.conn(), &i.id)? } else { Vec::new() };
            linked.push((i, c));
        }
        let mut candidates = Vec::new();
        if o.create
            && let Some(label) = &o.label
        {
            let q = ListQuery {
                filter: WorkFilter { labels_all: vec![label.clone()], ..Default::default() },
                all: o.state_all,
                ..Default::default()
            };
            for i in issues::list(r.conn(), &q)? {
                if i.external_ref.is_some() || i.ephemeral || i.issue_type == bd_core::GATE_TYPE {
                    continue;
                }
                if !o.state_all && i.status == Status::Closed {
                    continue;
                }
                let c = if o.comments { comments::list(r.conn(), &i.id)? } else { Vec::new() };
                candidates.push((i, c));
            }
        }
        Ok((cfg, linked, candidates))
    })?;

    // 2. Fetch the listing, and linked issues still open in bd that it left out.
    let listed = list_issues(api, &o.repo, o.state_all, o.label.as_deref()).map_err(fail_run)?;
    let mut rows: Vec<Row> = Vec::new();
    let mut by_number: HashMap<u64, Vec<(Issue, Vec<Comment>)>> = HashMap::new();
    for (i, c) in linked {
        match i.external_ref.as_deref().and_then(github::parse_external_ref) {
            Some((_, n)) => by_number.entry(n).or_default().push((i, c)),
            None => continue,
        }
    }
    let mut items: Vec<Item> = Vec::new();
    let mut unlinked: Vec<GithubIssue> = Vec::new();
    let link_item = |gh: GithubIssue, mut locals: Vec<(Issue, Vec<Comment>)>| -> Vec<Item> {
        if locals.len() > 1 {
            let ids: Vec<String> = locals.iter().map(|(i, _)| i.id.clone()).collect();
            let why = format!("#{} is linked from several bd issues: {}", gh.number, ids.join(", "));
            return ids.into_iter().map(|id| Item::new(gh.clone(), Kind::Error(Some(id), why.clone()))).collect();
        }
        let (local, comments) = locals.remove(0);
        let link = Link::of(&local).map(Box::new);
        vec![Item::new(gh, Kind::Linked { local: Box::new(local), link, comments, marker: false })]
    };
    for gh in listed {
        match by_number.remove(&gh.number) {
            Some(locals) => items.extend(link_item(gh, locals)),
            None => unlinked.push(gh),
        }
    }
    let mut missing: Vec<(u64, Vec<Local>)> = by_number.into_iter().collect();
    missing.sort_by_key(|(n, _)| *n);
    for (n, locals) in missing {
        if locals.iter().all(|(i, _)| i.status == Status::Closed) {
            continue;
        }
        match get_issue(api, &o.repo, n).map_err(fail_run)? {
            Some(gh) if !gh.pull_request => items.extend(link_item(gh, locals)),
            _ => {
                for (i, _) in locals {
                    rows.push(Row {
                        id: Some(i.id),
                        number: Some(n),
                        action: "gone".into(),
                        detail: Some(format!("#{n} no longer exists on GitHub, moved, or is a pull request")),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // 3. Issue markers of the unlinked ones, in a second short read.
    let login = if unlinked.iter().any(|g| github::marker_of(&g.body).is_some()) {
        self_login(api).map_err(fail_run)?
    } else {
        None
    };
    let markers = app.read(|r| github::resolve_markers(r.conn(), &unlinked, login.as_deref()))?;
    for (gh, m) in unlinked.into_iter().zip(markers) {
        let kind = match m {
            MarkerMatch::None => Kind::New,
            MarkerMatch::Error(e) => Kind::Error(None, e),
            MarkerMatch::Link { issue, comments, .. } => {
                candidates.retain(|(c, _)| c.id != issue.id);
                Kind::Linked { local: issue, link: None, comments, marker: true }
            }
        };
        items.push(Item::new(gh, kind));
    }

    // 4. Decide each issue's fields, then fetch the comments that moved.
    let dry = o.dry_run || o.status;
    for it in &mut items {
        let gh = it.gh.clone();
        let Some((local, link, local_comments, _)) = it.local() else { continue };
        let decision = github::decide(local, link, &gh, &cfg, dir, o.prefer);
        let skip = matches!(decision, Decision::Skip(_));
        let fetch = !skip
            && github::needs_comment_fetch(link, &gh)
            && (dir.pulls() || (o.comments && github::has_unposted(link, local_comments)));
        it.decision = decision;
        if fetch {
            if dry {
                it.would_fetch = true;
            } else {
                it.fetched = Some(list_comments(api, &o.repo, gh.number).map_err(fail_run)?);
            }
        }
    }
    if dir.pulls() && !dry {
        for it in items.iter_mut().filter(|it| matches!(it.kind, Kind::New) && it.gh.comments > 0) {
            it.fetched = Some(list_comments(api, &o.repo, it.gh.number).map_err(fail_run)?);
        }
    }
    for it in &mut items {
        if matches!(it.decision, Decision::Skip(_)) {
            continue;
        }
        let fetched = it.fetched.clone();
        let Some((local, link, local_comments, _)) = it.local() else { continue };
        let plan = github::plan_comments(&local.id, link, fetched.as_deref(), local_comments, dir, o.comments);
        it.comments = plan;
    }

    if dry {
        return Ok(dry_report(o, &cfg, items, candidates, rows));
    }

    // 5. GitHub writes, one issue after another; a fatal failure stops them.
    let mut aborted: Option<String> = None;
    if dir.pushes() {
        for it in items.iter_mut() {
            if aborted.is_some() {
                break;
            }
            if let Err(f) = push_item(api, &o.repo, &cfg, it) {
                if f.fatal {
                    aborted = Some(f.msg.clone());
                }
                it.error = Some(f.msg);
            }
        }
        let mut publishes: Vec<Publish> = candidates
            .drain(..)
            .map(|(local, comments)| Publish {
                local,
                comments,
                created: None,
                after: None,
                closed_ok: false,
                own_github_at: None,
                pushed: Vec::new(),
                error: None,
            })
            .collect();
        for p in publishes.iter_mut() {
            if aborted.is_some() {
                break;
            }
            if let Err(f) = publish(api, &o.repo, &cfg, p, o.comments) {
                if f.fatal {
                    aborted = Some(f.msg.clone());
                }
                p.error = Some(f.msg);
            }
        }
        return apply(app, o, &cfg, items, publishes, rows, aborted);
    }
    apply(app, o, &cfg, items, Vec::new(), rows, aborted)
}

/// PATCH a linked issue whose decision is Push, then post its comments.
fn push_item(api: &dyn GithubApi, repo: &Repo, cfg: &SyncConfig, it: &mut Item) -> std::result::Result<(), Failure> {
    let gh = it.gh.clone();
    let Some((local, link, _, _)) = it.local() else { return Ok(()) };
    let (local, link) = (local.clone(), link.cloned());
    let endpoint = format!("{}/issues/{}", repo.path(), gh.number);
    if it.decision == Decision::Push {
        let body = github::push_body(&local, link.as_ref(), &gh, cfg);
        if !body.is_empty() {
            if github::outcome_change(&local, &gh) {
                // GitHub applies a state_reason only with a change of state.
                let resp = request(api, "PATCH", &endpoint, Some(&json!({ "state": "open" })))?;
                let reopened = parse_issue(&resp.json().map_err(Failure::fatal)?)?;
                it.own_github_at = later(it.own_github_at, reopened.updated_at);
                it.github_after = Some(reopened);
                it.stamp = Stamp { github: true, local: false };
            }
            let resp = request(api, "PATCH", &endpoint, Some(&Value::Object(body.clone())))?;
            let after = parse_issue(&resp.json().map_err(Failure::fatal)?)?;
            it.own_github_at = later(it.own_github_at, after.updated_at);
            it.unapplied = github::unapplied(&body, &local, link.as_ref(), &after, cfg);
            it.stamp = Stamp { github: true, local: it.unapplied.is_empty() };
            it.pushed_fields = body.keys().filter(|k| *k != "state_reason").cloned().collect();
            it.github_after = Some(after);
        }
    }
    let to_post = it.comments.push.clone();
    post_comments(api, repo, gh.number, &to_post, &mut it.pushed, &mut it.own_github_at)
}

fn post_comments(
    api: &dyn GithubApi,
    repo: &Repo,
    number: u64,
    comments: &[Comment],
    pushed: &mut Vec<(i64, i64)>,
    own: &mut Option<Timestamp>,
) -> std::result::Result<(), Failure> {
    let endpoint = format!("{}/issues/{number}/comments", repo.path());
    for c in comments {
        let resp = request(api, "POST", &endpoint, Some(&json!({ "body": github::push_comment_body(c) })))?;
        let posted = GithubComment::from_json(&resp.json().map_err(Failure::fatal)?)
            .map_err(|e| Failure::fatal(e.to_string()))?;
        pushed.push((posted.id, c.id));
        *own = later(*own, posted.updated_at.max(posted.created_at));
    }
    Ok(())
}

/// Create a bd issue on GitHub (`--create`): POST, close it when bd's is
/// closed, then post its comments with `--comments`.
fn publish(
    api: &dyn GithubApi,
    repo: &Repo,
    cfg: &SyncConfig,
    p: &mut Publish,
    comments: bool,
) -> std::result::Result<(), Failure> {
    let body = github::create_body(&p.local, cfg);
    let resp = request(api, "POST", &format!("{}/issues", repo.path()), Some(&Value::Object(body)))?;
    let created = parse_issue(&resp.json().map_err(Failure::fatal)?)?;
    p.own_github_at = later(p.own_github_at, created.updated_at);
    p.after = Some(created.clone());
    p.created = Some(created.clone());
    p.closed_ok = p.local.status != Status::Closed;
    if !p.closed_ok {
        let endpoint = format!("{}/issues/{}", repo.path(), created.number);
        let resp = request(api, "PATCH", &endpoint, Some(&Value::Object(github::close_body(&p.local))))?;
        let after = parse_issue(&resp.json().map_err(Failure::fatal)?)?;
        p.own_github_at = later(p.own_github_at, after.updated_at);
        p.after = Some(after);
        p.closed_ok = true;
    }
    if comments {
        let list = p.comments.clone();
        post_comments(api, repo, created.number, &list, &mut p.pushed, &mut p.own_github_at)?;
    }
    Ok(())
}

fn count_rows(rows: &[Row]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for r in rows {
        *counts.entry(r.action.clone()).or_insert(0) += 1;
    }
    counts
}

fn decision_row(it: &Item, local: &Issue) -> Row {
    let mut row = Row { id: Some(local.id.clone()), number: Some(it.gh.number), ..Default::default() };
    match &it.decision {
        Decision::Conflict { .. } => {
            row.action = "conflict".into();
            row.detail = Some("both sides changed; pass --prefer local, github or newer".into());
        }
        Decision::Deferred { why, .. } => {
            row.action = "deferred".into();
            row.detail = Some(why.clone());
        }
        Decision::Skip(why) => {
            row.action = "skipped".into();
            row.detail = Some(why.clone());
        }
        _ => row.action = "unchanged".into(),
    }
    row
}

fn conflicts_of(items: &[Item]) -> Vec<ConflictRow> {
    items
        .iter()
        .filter_map(|it| match (&it.decision, it.local()) {
            (Decision::Conflict { local_hash, github_hash }, Some((local, ..))) => Some(ConflictRow {
                id: local.id.clone(),
                number: it.gh.number,
                local_hash: local_hash.clone(),
                github_hash: github_hash.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// The report of `status` and `--dry-run`: what a run would do.
fn dry_report(
    o: &Opts,
    cfg: &SyncConfig,
    items: Vec<Item>,
    candidates: Vec<(Issue, Vec<Comment>)>,
    mut rows: Vec<Row>,
) -> Report {
    for it in &items {
        let row = match &it.kind {
            Kind::Error(id, e) => Row {
                id: id.clone(),
                number: Some(it.gh.number),
                action: "error".into(),
                detail: Some(e.clone()),
                ..Default::default()
            },
            Kind::New if o.dir.pulls() => Row {
                number: Some(it.gh.number),
                action: "would create".into(),
                detail: Some(it.gh.title.clone()),
                ..Default::default()
            },
            Kind::New => continue,
            Kind::Linked { local, link, marker, .. } => {
                let mut row = decision_row(it, local);
                match &it.decision {
                    Decision::Pull => {
                        row.action = "would pull".into();
                        row.changed = github::pull_changes(local, link.as_deref(), &it.gh, cfg)
                            .fields()
                            .into_iter()
                            .map(String::from)
                            .collect();
                    }
                    Decision::Push => {
                        row.action = "would push".into();
                        row.changed = github::push_body(local, link.as_deref(), &it.gh, cfg)
                            .keys()
                            .filter(|k| *k != "state_reason")
                            .cloned()
                            .collect();
                    }
                    _ => {}
                }
                if *marker && !matches!(it.decision, Decision::Skip(_)) {
                    row.action = format!(
                        "would link{}",
                        if row.action == "unchanged" { String::new() } else { format!(" ({})", row.action) }
                    );
                }
                let mut notes = Vec::new();
                if it.would_fetch {
                    notes.push("would fetch comments".to_string());
                }
                if !it.comments.push.is_empty() {
                    notes.push(format!("would post {} comment(s)", it.comments.push.len()));
                }
                if !notes.is_empty() {
                    if row.action == "unchanged" {
                        row.action = "would sync comments".into();
                    }
                    let d = notes.join("; ");
                    row.detail = Some(row.detail.map(|x| format!("{x}; {d}")).unwrap_or(d));
                }
                row
            }
        };
        rows.push(row);
    }
    if o.dir.pushes() {
        for (local, comments) in &candidates {
            let mut detail = local.title.clone();
            if o.comments && !comments.is_empty() {
                detail.push_str(&format!("; would post {} comment(s)", comments.len()));
            }
            rows.push(Row {
                id: Some(local.id.clone()),
                action: "would create on GitHub".into(),
                detail: Some(detail),
                ..Default::default()
            });
        }
    }
    Report {
        repo: o.repo.key(),
        direction: if o.status { "status" } else { o.dir.as_str() },
        dry_run: true,
        counts: count_rows(&rows),
        conflicts: conflicts_of(&items),
        results: rows,
        aborted: None,
    }
}

/// What one issue's apply will be, decided before the write.
enum Plan {
    Create(GithubIssue, Option<Vec<GithubComment>>),
    Apply(Box<IssueApply>, Row),
}

/// Build each issue's apply, then run them all in one write transaction.
fn apply(
    app: &mut App,
    o: &Opts,
    cfg: &SyncConfig,
    items: Vec<Item>,
    publishes: Vec<Publish>,
    mut rows: Vec<Row>,
    aborted: Option<String>,
) -> Result<Report> {
    let key = o.repo.key();
    let mut plans: Vec<Plan> = Vec::new();
    let conflicts = conflicts_of(&items);
    for it in items {
        let (local, link, marker) = match &it.kind {
            Kind::Error(id, e) => {
                rows.push(Row {
                    id: id.clone(),
                    number: Some(it.gh.number),
                    action: "error".into(),
                    detail: Some(e.clone()),
                    ..Default::default()
                });
                continue;
            }
            Kind::New => {
                if o.dir.pulls() {
                    plans.push(Plan::Create(it.gh.clone(), it.fetched.clone()));
                }
                continue;
            }
            Kind::Linked { local, link, marker, .. } => ((**local).clone(), link.clone(), *marker),
        };
        let mut row = decision_row(&it, &local);
        if matches!(it.decision, Decision::Skip(_)) {
            rows.push(row);
            continue;
        }
        let stamp = match it.decision {
            Decision::Push => it.stamp,
            ref d => d.planned_stamp(),
        };
        // A Push whose PATCH failed (or never ran) re-stamps neither side.
        let stamp = if it.decision == Decision::Push && it.github_after.is_none() { Stamp::NONE } else { stamp };
        let pull = (it.decision == Decision::Pull).then(|| github::pull_changes(&local, link.as_deref(), &it.gh, cfg));
        let comment_count = it.comments.count(link.as_ref().and_then(|k| k.comment_count), it.pushed.len());
        let a = IssueApply {
            id: local.id.clone(),
            expected_revision: local.revision,
            repo: key.clone(),
            number: it.gh.number,
            pull,
            import: it.comments.import.clone(),
            adopt: it.comments.adopt.clone(),
            pushed_comments: it.pushed.clone(),
            github_seen: it.gh.clone(),
            github_after: it.github_after.clone().unwrap_or_else(|| it.gh.clone()),
            own_github_at: it.own_github_at,
            local_before: local.clone(),
            stamp,
            comment_count,
            set_external_ref: marker,
        };
        if it.decision == Decision::Push && it.github_after.is_some() {
            row.patched = true;
            row.action = "pushed".into();
            row.changed = it.pushed_fields.clone();
            if !it.unapplied.is_empty() {
                // Sent, but GitHub's answer dropped some fields: bd's side stays unstamped.
                row.action = "partial".into();
                row.detail =
                    Some(format!("GitHub did not apply {}; the next push tries again", it.unapplied.join(", ")));
            }
        }
        if let Some(e) = &it.error {
            row.action = "error".into();
            row.detail = Some(e.clone());
        } else if it.decision == Decision::Push && it.github_after.is_none() && aborted.is_some() {
            row.action = "skipped".into();
            row.detail = Some("not pushed: the run stopped first".into());
        }
        row.comments_adopted = a.adopt.len();
        row.comments_pushed = a.pushed_comments.len();
        if github::apply_needed(link.as_deref(), &a, cfg) {
            plans.push(Plan::Apply(Box::new(a), row));
        } else {
            rows.push(row);
        }
    }
    for p in publishes {
        let (Some(created), Some(after)) = (&p.created, &p.after) else {
            if let Some(e) = &p.error {
                rows.push(Row {
                    id: Some(p.local.id.clone()),
                    action: "error".into(),
                    detail: Some(e.clone()),
                    ..Default::default()
                });
            }
            continue;
        };
        // bd's side is stamped only once GitHub holds all of it (closed too).
        let local_ok = p.closed_ok && github::push_body(&p.local, None, after, cfg).is_empty();
        let a = IssueApply {
            id: p.local.id.clone(),
            expected_revision: p.local.revision,
            repo: key.clone(),
            number: created.number,
            pull: None,
            import: Vec::new(),
            adopt: Vec::new(),
            pushed_comments: p.pushed.clone(),
            github_seen: created.clone(),
            github_after: after.clone(),
            own_github_at: p.own_github_at,
            local_before: p.local.clone(),
            stamp: Stamp { github: true, local: local_ok },
            comment_count: p.pushed.len() as u64,
            set_external_ref: true,
        };
        let mut row = Row {
            id: Some(p.local.id.clone()),
            number: Some(created.number),
            action: "created".into(),
            detail: Some(format!("on GitHub as #{}", created.number)),
            comments_pushed: p.pushed.len(),
            ..Default::default()
        };
        if let Some(e) = &p.error {
            row.detail = Some(format!("on GitHub as #{}, then: {e}", created.number));
        }
        plans.push(Plan::Apply(Box::new(a), row));
    }

    if !plans.is_empty() {
        let direction = o.dir.as_str();
        let op = match o.dir {
            Direction::Pull => "github.pull",
            Direction::Push => "github.push",
            Direction::Both => "github.sync",
        };
        let applied = app.write(op, |tx| {
            let mut out = Vec::new();
            let mut changed_any = false;
            let (mut pushed, mut created, mut linked) = (Vec::new(), Vec::new(), Vec::new());
            for plan in &plans {
                match plan {
                    Plan::Create(gh, comments) => {
                        let mut row = Row { number: Some(gh.number), ..Default::default() };
                        match tx.savepoint(|tx| tx.github_create(&key, gh, comments.as_deref(), cfg)) {
                            Ok((issue, warnings)) => {
                                changed_any = true;
                                row.id = Some(issue.id.clone());
                                row.action = "created".into();
                                row.comments_imported = comments.as_ref().map_or(0, Vec::len);
                                let mut detail = issue.title.clone();
                                if !warnings.is_empty() {
                                    detail.push_str(&format!(" ({})", warnings.join("; ")));
                                }
                                row.detail = Some(detail);
                                created.push(issue.id);
                            }
                            Err(e) if github::is_database_error(&e) => return Err(e),
                            Err(e) => {
                                row.action = "error".into();
                                row.detail = Some(e.to_string());
                            }
                        }
                        out.push(row);
                    }
                    Plan::Apply(a, row) => {
                        let mut row = row.clone();
                        match tx.savepoint(|tx| tx.github_apply(a, cfg)) {
                            Ok(res) => {
                                changed_any |= res.linked || !res.imported.is_empty() || !res.changed.is_empty();
                                row.comments_imported = res.imported.len();
                                if let Some(err) = &res.pull_error {
                                    row.action = match err {
                                        github::PullError::Stale(_) => "stale".into(),
                                        github::PullError::Refused(_) => "error".into(),
                                    };
                                    row.detail = Some(err.detail().to_string());
                                } else if a.pull.is_some() {
                                    row.changed = res.changed.clone();
                                    if row.action == "error" {
                                        let e = row.detail.take().unwrap_or_default();
                                        row.detail = Some(format!("pulled {}; then: {e}", res.changed.join(", ")));
                                    } else {
                                        row.action = "pulled".into();
                                    }
                                } else if a.set_external_ref && row.action != "created" {
                                    if row.action == "unchanged" {
                                        row.action = "linked".into();
                                    }
                                    linked.push(a.id.clone());
                                }
                                if row.action == "created" {
                                    created.push(a.id.clone());
                                }
                                if row.patched {
                                    pushed.push(a.id.clone());
                                }
                                if row.action == "unchanged" {
                                    row.action = if row.comments_imported > 0 || row.comments_pushed > 0 {
                                        "comments".into()
                                    } else {
                                        "recorded".into()
                                    };
                                }
                                if !res.notes.is_empty() {
                                    let n = res.notes.join("; ");
                                    row.detail = Some(row.detail.map(|d| format!("{d}; {n}")).unwrap_or(n));
                                }
                            }
                            Err(e) if github::is_database_error(&e) => return Err(e),
                            Err(e) => {
                                row.action = "error".into();
                                row.detail = Some(e.to_string());
                            }
                        }
                        out.push(row);
                    }
                }
            }
            if changed_any {
                let counts = count_rows(&out);
                tx.github_synced(json!({
                    "repo": key,
                    "direction": direction,
                    "counts": counts,
                    "pushed": pushed,
                    "created": created,
                    "linked": linked,
                }))?;
            }
            Ok(out)
        })?;
        rows.extend(applied);
    }
    Ok(Report {
        repo: key,
        direction: o.dir.as_str(),
        dry_run: false,
        counts: count_rows(&rows),
        conflicts,
        results: rows,
        aborted,
    })
}

fn icon(action: &str) -> &'static str {
    match action {
        "created" | "would create" | "would create on GitHub" => "+",
        "pulled" | "would pull" => "↓",
        "pushed" | "would push" => "↑",
        "linked" => "⇄",
        "comments" | "recorded" | "would sync comments" => "…",
        "conflict" | "error" | "stale" | "gone" | "partial" => "!",
        "deferred" | "skipped" => "-",
        a if a.starts_with("would link") => "⇄",
        _ => "=",
    }
}

fn render(report: &Report) -> Out {
    let mut out = Out::new(report);
    for r in report.results.iter().filter(|r| r.action != "unchanged") {
        let who = match (&r.id, r.number) {
            (Some(id), Some(n)) => format!("{id} #{n}"),
            (Some(id), None) => id.clone(),
            (None, Some(n)) => format!("#{n}"),
            (None, None) => String::new(),
        };
        let mut line = format!("{} {who} {}", icon(&r.action), r.action);
        if !r.changed.is_empty() {
            line.push_str(&format!(": {}", r.changed.join(", ")));
        }
        let mut extra = Vec::new();
        if r.comments_imported > 0 {
            extra.push(format!("{} comment(s) imported", r.comments_imported));
        }
        if r.comments_adopted > 0 {
            extra.push(format!("{} comment(s) recognized", r.comments_adopted));
        }
        if r.comments_pushed > 0 {
            extra.push(format!("{} comment(s) posted", r.comments_pushed));
        }
        if let Some(d) = &r.detail {
            extra.insert(0, d.clone());
        }
        if !extra.is_empty() {
            line.push_str(&format!(" ({})", extra.join("; ")));
        }
        out = out.line(io_safe(&line));
        if let Some(id) = &r.id {
            out = out.id(id.clone());
        }
    }
    let summary: Vec<String> = report.counts.iter().map(|(a, n)| format!("{n} {a}")).collect();
    let prefix = if report.dry_run { "Dry run: " } else { "" };
    out = out.line(format!(
        "{prefix}{} {}: {}",
        report.direction,
        report.repo,
        if summary.is_empty() { "nothing to do".to_string() } else { summary.join(", ") }
    ));
    if let Some(a) = &report.aborted {
        out = out.line(format!("stopped: {}", io_safe(a)));
    }
    out
}

/// GitHub text (titles, messages) on one line, without control characters.
fn io_safe(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// The repository `gh repo view` sees in `cwd`.
fn own_repo(cwd: &std::path::Path) -> Result<Repo> {
    let args: Vec<String> = ["repo", "view", "--json", "nameWithOwner,url"].iter().map(|s| s.to_string()).collect();
    let v = gh::gh_json(&args, cwd).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    let name = v.get("nameWithOwner").and_then(Value::as_str).unwrap_or_default();
    let host = v
        .get("url")
        .and_then(Value::as_str)
        .and_then(|u| u.split("://").nth(1))
        .and_then(|rest| rest.split('/').next())
        .map(|h| h.to_ascii_lowercase())
        .filter(|h| h != "github.com");
    let full = match host {
        Some(h) => format!("{h}/{name}"),
        None => name.to_string(),
    };
    Repo::parse(&full)
        .map_err(|_| Error::Io(std::io::Error::other(format!("gh repo view returned no repository ({name:?})"))))
}

fn prefer_of(p: Option<PreferArg>) -> Option<Prefer> {
    p.map(|p| match p {
        PreferArg::Local => Prefer::Local,
        PreferArg::Github => Prefer::Github,
        PreferArg::Newer => Prefer::Newer,
    })
}

/// The repository a command syncs: `--repo`, checked against
/// `github.repos`, else the workspace's own.
fn resolve_repo(app: &mut App, args: &GithubArgs) -> Result<Repo> {
    let cwd = gh::workdir(app);
    let Some(raw) = &args.repo else { return own_repo(&cwd) };
    let repo = Repo::parse(raw)?;
    let served = io::in_server_process();
    let repos = app.read(|r| GateRepos::load_key(r.conn(), "github.repos", served))?;
    if repos.allows(&repo.key()) {
        return Ok(repo);
    }
    // Unset under bd serve: only the workspace's own repository.
    if repos == GateRepos::Only(Vec::new()) && own_repo(&cwd).is_ok_and(|own| own.key() == repo.key()) {
        return Ok(repo);
    }
    repos.require("github.repos", "bd github", &repo.key())?;
    Ok(repo)
}

pub fn cmd_github(app: &mut App, cmd: &GithubCommand) -> Result<i32> {
    io::require_admin("bd github")?;
    let (args, dir, dry_run, create, comments, status) = match cmd {
        GithubCommand::Status(a) => (a, Direction::Both, true, false, false, true),
        GithubCommand::Pull(a) => (&a.common, Direction::Pull, a.dry_run, false, false, false),
        GithubCommand::Push(a) => (&a.common, Direction::Push, a.dry_run, a.create, a.comments, false),
        GithubCommand::Sync(a) => (&a.common, Direction::Both, a.dry_run, a.create, a.comments, false),
    };
    let label = args.label.clone().filter(|l| !l.trim().is_empty());
    if create && label.is_none() {
        return Err(Error::invalid("--create needs --label: only bd issues carrying that label are created on GitHub"));
    }
    let repo = resolve_repo(app, args)?;
    let opts = Opts {
        repo: repo.clone(),
        dir,
        prefer: prefer_of(args.prefer),
        label,
        state_all: args.state == GithubState::All,
        dry_run,
        create,
        comments,
        status,
    };
    let api = GhCli { host: repo.host.clone(), cwd: gh::workdir(app) };
    let report = run(app, &api, &opts)?;
    let code = if report.aborted.is_some() { 1 } else { 0 };
    app.print(render(&report));
    Ok(code)
}

#[cfg(test)]
mod tests;
