//! Background jobs of `bd serve`: lease reclaim, gate checks, agent set
//! changes, backups, and pruning of request records, in every workspace under
//! the root, on timers.
//!
//! The scheduler scans `<root>/*/.bd/bd.db` every so often, so workspaces no
//! client has used since the server started are kept up too: dead workers'
//! claims are reclaimed, timers open, and backups are taken. Each
//! (workspace, job) pair has its own timer, first fired at a random point
//! within one interval, then every interval ±10%, so workspaces do not fire
//! in lockstep. A job never overlaps itself. Jobs run on blocking threads in
//! small lanes (database jobs, `gh` checks, backups) apart from the slots of
//! client requests, and every write is a short transaction of its own: `gh`
//! runs outside any transaction and backups are read transactions. A failed
//! job is logged and tried again later, backing off up to 32 intervals.
//!
//! Jobs run the CLI's own commands (`bd reclaim`, `bd gate check --type
//! local` or `--type gh`) as actor [`ACTOR`], with their I/O captured the way
//! a request's is, so events, checks and policies are those of the commands.
//! The agents job reads each harness's set from the workspace's
//! `.bd/agents` and records its revision ([`bd_core::agents::record_revisions`]),
//! appending an `agents_changed` event for each set that changed.
//! Backups ([`bd_cli::backup`], shared with `bd backup`) are [`Store::snapshot`]s
//! (`VACUUM INTO`) written under a temporary name and then renamed to
//! `<backup dir>/<name>/<name>-<UTC time>.db`; the newest `keep` are kept.
//!
//! On shutdown no job starts any more, and running ones get a grace period.
//! Abandoning one is safe: an unfinished transaction rolls back, and the
//! next backup removes the temporary file of an unfinished one.

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bd_core::agents::{AGENTS_DIR, AgentSet, Harness};
use bd_core::time::{format_duration_ms, parse_duration};
use bd_core::{Error, OpenOptions, Result, Store};
use clap::Parser;
use serde_json::Value;
use tokio::sync::{Semaphore, mpsc, watch};

use bd_cli::app::App;
use bd_cli::backup;
use bd_cli::cli::{Cli, Command, ServeArgs};
use bd_cli::io::{self, Capture};
use bd_cli::protocol::valid_workspace_name;

/// The actor of background writes: reclaims, and gates opened or escalated.
pub const ACTOR: &str = "bd-serve";
/// The shortest and longest intervals accepted for a job.
const MIN_EVERY: Duration = Duration::from_millis(100);
const MAX_EVERY: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// How long idempotency records are kept; retries come within seconds.
const REQUEST_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const PRUNE_EVERY: Duration = Duration::from_secs(60 * 60);
/// Records deleted per transaction, so pruning never holds the write lock long.
const PRUNE_BATCH: usize = 10_000;
/// New workspaces get their jobs within this long (or the shortest interval).
const SCAN_EVERY: Duration = Duration::from_secs(30);
/// A failing job waits at most this many intervals before trying again.
const MAX_BACKOFF: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Job {
    Reclaim,
    /// Timer, issue and human gates (and malformed ones): no `gh` needed.
    Gates,
    GhGates,
    /// Agent sets read for changes.
    Agents,
    Backup,
    Prune,
}

/// Jobs running at once per lane: database jobs, `gh` checks, backups.
const LANES: [usize; 3] = [2, 2, 1];

impl Job {
    const ALL: [Job; 6] = [Job::Reclaim, Job::Gates, Job::GhGates, Job::Agents, Job::Backup, Job::Prune];

    pub fn name(self) -> &'static str {
        match self {
            Job::Reclaim => "reclaim",
            Job::Gates => "gate-check",
            Job::GhGates => "gh-check",
            Job::Agents => "agents",
            Job::Backup => "backup",
            Job::Prune => "prune",
        }
    }

    fn lane(self) -> usize {
        match self {
            Job::Reclaim | Job::Gates | Job::Agents | Job::Prune => 0,
            Job::GhGates => 1,
            Job::Backup => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backups {
    pub dir: PathBuf,
    pub every: Duration,
    /// Backups kept per workspace (0 keeps all).
    pub keep: usize,
}

/// How often each job runs; `None` turns it off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub reclaim_every: Option<Duration>,
    pub gate_check_every: Option<Duration>,
    pub gh_check_every: Option<Duration>,
    pub agents_every: Option<Duration>,
    pub backups: Option<Backups>,
    pub prune_every: Option<Duration>,
}

impl Config {
    /// From `bd serve`'s flags. Creates the backup directory, so a bad one fails at startup.
    pub fn from_args(a: &ServeArgs) -> Result<Config> {
        let backups = match (&a.backup_dir, every("--backup-every", &a.backup_every)?) {
            (Some(dir), Some(every)) => {
                let bad = |e: std::io::Error| Error::invalid(format!("--backup-dir {}: {e}", dir.display()));
                backup::create_private_dir(dir).map_err(bad)?;
                Some(Backups { dir: std::path::absolute(dir).map_err(bad)?, every, keep: a.backup_keep })
            }
            _ => None,
        };
        Ok(Config {
            reclaim_every: every("--reclaim-every", &a.reclaim_every)?,
            gate_check_every: every("--gate-check-every", &a.gate_check_every)?,
            gh_check_every: every("--gh-check-every", &a.gh_check_every)?,
            agents_every: every("--agents-every", &a.agents_every)?,
            backups,
            prune_every: Some(PRUNE_EVERY),
        })
    }

    fn every(&self, job: Job) -> Option<Duration> {
        match job {
            Job::Reclaim => self.reclaim_every,
            Job::Gates => self.gate_check_every,
            Job::GhGates => self.gh_check_every,
            Job::Agents => self.agents_every,
            Job::Backup => self.backups.as_ref().map(|b| b.every),
            Job::Prune => self.prune_every,
        }
    }
}

/// An interval flag: a duration, or `0` / `off` for none.
fn every(flag: &str, value: &str) -> Result<Option<Duration>> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let d = parse_duration(v).map_err(|e| Error::invalid(format!("{flag} {value}: {e}")))?;
    if d.is_zero() {
        return Ok(None);
    }
    if d < MIN_EVERY || d > MAX_EVERY {
        return Err(Error::invalid(format!(
            "{flag} {value}: use {}ms to 365d, or 0 to turn it off",
            MIN_EVERY.as_millis()
        )));
    }
    Ok(Some(d))
}

fn show(d: Option<Duration>) -> String {
    d.map_or_else(|| "off".into(), |d| format_duration_ms(i64::try_from(d.as_millis()).unwrap_or(i64::MAX)))
}

/// A workspace under the server root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    pub name: String,
    pub dir: PathBuf,
    pub db: PathBuf,
}

/// What stands for `<root>/server.db` among the workspaces: only backed up.
/// No workspace has this name (theirs start with a letter or digit).
pub const SERVER: &str = "_server";

/// The workspaces `bd serve` serves from `root`: `<root>/<name>/.bd/bd.db`;
/// and `<root>/server.db` (as [`SERVER`]), which only backups touch.
fn discover(root: &Path) -> std::io::Result<Vec<Workspace>> {
    let mut found: Vec<Workspace> = std::fs::read_dir(root)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| valid_workspace_name(name))
        .filter_map(|name| {
            let dir = root.join(&name);
            let db = dir.join(".bd").join("bd.db");
            db.is_file().then_some(Workspace { name, dir, db })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    let server = crate::server_db::path(root);
    if server.is_file() {
        found.push(Workspace { name: SERVER.into(), dir: root.to_path_buf(), db: server });
    }
    Ok(found)
}

/// Runs one job in one workspace (on a blocking thread); false when it failed.
type Runner = Arc<dyn Fn(&Workspace, Job) -> bool + Send + Sync>;

/// Told the name of a workspace whose job may have appended events.
pub type Committed = Arc<dyn Fn(&str) + Send + Sync>;

/// The running scheduler.
pub struct Jobs {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    lanes: Vec<Arc<Semaphore>>,
}

/// Start the background jobs (inside the server's runtime); `committed`
/// hears of each job that may have written.
pub fn start(config: Config, root: PathBuf, open: OpenOptions, committed: Committed) -> Jobs {
    match &config.backups {
        Some(b) => tracing::info!(
            target: "bd::serve",
            reclaim_every = %show(config.reclaim_every),
            gate_check_every = %show(config.gate_check_every),
            gh_check_every = %show(config.gh_check_every),
            agents_every = %show(config.agents_every),
            backup_every = %show(Some(b.every)),
            backup_keep = b.keep,
            backup_dir = %b.dir.display(),
            "background jobs"
        ),
        None => tracing::info!(
            target: "bd::serve",
            reclaim_every = %show(config.reclaim_every),
            gate_check_every = %show(config.gate_check_every),
            gh_check_every = %show(config.gh_check_every),
            agents_every = %show(config.agents_every),
            backups = "off",
            "background jobs"
        ),
    }
    let backups = config.backups.clone();
    let unreadable = Unreadable::default();
    let runner: Runner = Arc::new(move |ws: &Workspace, job| {
        let ok = run(ws, job, &open, backups.as_ref(), &unreadable);
        if job != Job::Backup {
            // Reclaims, gate checks and agent set changes append events: followers check again.
            committed(&ws.name);
        }
        ok
    });
    spawn(config, root, runner)
}

fn spawn(config: Config, root: PathBuf, runner: Runner) -> Jobs {
    let lanes: Vec<Arc<Semaphore>> = LANES.iter().map(|&n| Arc::new(Semaphore::new(n))).collect();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(schedule(config, root, runner, lanes.clone(), stopped));
    Jobs { stop, task, lanes }
}

impl Jobs {
    /// Start no more jobs, then wait up to `grace` for running ones to finish.
    /// Returns how many were still running; they are abandoned.
    pub async fn stop(self, grace: Duration) -> usize {
        let _ = self.stop.send(true);
        let _ = self.task.await;
        let deadline = tokio::time::Instant::now() + grace;
        let mut running = 0;
        for (lane, &slots) in self.lanes.iter().zip(&LANES) {
            let all = u32::try_from(slots).unwrap_or(u32::MAX);
            if tokio::time::timeout_at(deadline, lane.acquire_many(all)).await.is_err() {
                running += slots.saturating_sub(lane.available_permits());
            }
        }
        if running == 0 {
            tracing::info!(target: "bd::serve", "background jobs stopped");
        } else {
            tracing::warn!(target: "bd::serve", running, "background jobs still running at shutdown; abandoning them");
        }
        running
    }
}

struct Slot {
    due: Instant,
    running: bool,
    failures: u32,
}

/// The wait before a job runs again: its interval, doubled per consecutive failure.
fn backoff(every: Duration, failures: u32) -> Duration {
    every.saturating_mul(2u32.saturating_pow(failures).min(MAX_BACKOFF))
}

/// `wait` after `from`, without overflowing the platform's clock.
fn after(from: Instant, wait: Duration) -> Instant {
    from.checked_add(wait).unwrap_or(from + MAX_EVERY)
}

async fn schedule(
    config: Config,
    root: PathBuf,
    runner: Runner,
    lanes: Vec<Arc<Semaphore>>,
    mut stop: watch::Receiver<bool>,
) {
    let jobs: Vec<(Job, Duration)> = Job::ALL.into_iter().filter_map(|j| config.every(j).map(|d| (j, d))).collect();
    let Some(shortest) = jobs.iter().map(|(_, d)| *d).min() else { return };
    let scan_every = shortest.min(SCAN_EVERY);
    let (done_tx, mut done) = mpsc::unbounded_channel::<(String, Job, bool)>();
    let mut rng = Rng::new();
    let mut workspaces: HashMap<String, Workspace> = HashMap::new();
    let mut slots: HashMap<(String, Job), Slot> = HashMap::new();
    let mut next_scan = Instant::now();
    loop {
        let now = Instant::now();
        if now >= next_scan {
            let dir = root.clone();
            match tokio::task::spawn_blocking(move || discover(&dir)).await {
                Ok(Ok(found)) => {
                    workspaces = found.into_iter().map(|w| (w.name.clone(), w)).collect();
                    for name in workspaces.keys() {
                        // server.db has accounts and tokens, no issues: backups are its only job.
                        let jobs = jobs.iter().filter(|(job, _)| name != SERVER || *job == Job::Backup);
                        for &(job, every) in jobs {
                            slots.entry((name.clone(), job)).or_insert_with(|| Slot {
                                due: after(now, every.mul_f64(rng.unit())),
                                running: false,
                                failures: 0,
                            });
                        }
                    }
                    slots.retain(|(name, _), s| s.running || workspaces.contains_key(name));
                }
                Ok(Err(e)) => {
                    tracing::warn!(target: "bd::serve", root = %root.display(), error = %e, "cannot list workspaces")
                }
                Err(e) => tracing::error!(target: "bd::serve", error = %e, "listing workspaces panicked"),
            }
            next_scan = after(now, scan_every);
        }

        let mut due: Vec<(Instant, String, Job)> = slots
            .iter()
            .filter(|(_, s)| !s.running && s.due <= now)
            .map(|((name, job), s)| (s.due, name.clone(), *job))
            .collect();
        due.sort();
        for (_, name, job) in due {
            let Some(ws) = workspaces.get(&name).cloned() else { continue };
            // A full lane: the job runs when one of the lane's jobs finishes.
            let Ok(permit) = lanes[job.lane()].clone().try_acquire_owned() else { continue };
            if let Some(slot) = slots.get_mut(&(name, job)) {
                slot.running = true;
            }
            let (runner, done_tx) = (runner.clone(), done_tx.clone());
            tokio::task::spawn_blocking(move || {
                let ok = std::panic::catch_unwind(AssertUnwindSafe(|| runner(&ws, job))).unwrap_or_else(|_| {
                    tracing::error!(target: "bd::serve", workspace = %ws.name, job = job.name(), "background job panicked");
                    false
                });
                drop(permit);
                let _ = done_tx.send((ws.name, job, ok));
            });
        }

        let next_due = slots.values().filter(|s| !s.running && s.due > now).map(|s| s.due).min();
        let wake = next_due.map_or(next_scan, |d| d.min(next_scan));
        tokio::select! {
            _ = stop.changed() => return,
            Some((name, job, ok)) = done.recv() => {
                let gone = !workspaces.contains_key(&name);
                let key = (name, job);
                if gone {
                    slots.remove(&key);
                } else if let Some(slot) = slots.get_mut(&key) {
                    slot.running = false;
                    slot.failures = if ok { 0 } else { slot.failures.saturating_add(1) };
                    let every = config.every(job).unwrap_or(shortest);
                    slot.due = after(Instant::now(), backoff(every, slot.failures).mul_f64(rng.between(0.9, 1.1)));
                }
            }
            _ = tokio::time::sleep_until(wake.into()) => {}
        }
    }
}

/// xorshift64, for jitter only.
struct Rng(u64);

impl Rng {
    fn new() -> Rng {
        use std::hash::BuildHasher;
        Rng(std::collections::hash_map::RandomState::new().hash_one(Instant::now()) | 1)
    }

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    fn between(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * self.unit()
    }
}

fn ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn run(ws: &Workspace, job: Job, open: &OpenOptions, backups: Option<&Backups>, unreadable: &Unreadable) -> bool {
    let started = Instant::now();
    let done = match (job, backups) {
        (Job::Reclaim, _) => reclaim(ws, open, started),
        (Job::Gates, _) => check_gates(ws, open, job, "local", started),
        (Job::GhGates, _) => check_gates(ws, open, job, "gh", started),
        (Job::Agents, _) => agents(ws, open, started, unreadable),
        (Job::Backup, Some(b)) => backup(ws, open, b, started).map(|_| ()),
        (Job::Backup, None) => Ok(()),
        (Job::Prune, _) => prune(ws, open, started),
    };
    match done {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                target: "bd::serve",
                workspace = %ws.name,
                job = job.name(),
                error = %e,
                ms = ms(started),
                "background job failed"
            );
            false
        }
    }
}

/// Output a background command may print: its `--json` list of reclaimed
/// leases or checked gates stays far below this.
const OUTPUT_LIMIT: usize = 4 << 20;

/// The I/O of a background command: a request's capture without client
/// input or a token, keeping stdout (up to [`OUTPUT_LIMIT`]) to read. Its
/// policy is a token's with no rights (no admin, not a person, owning no
/// claims): reclaiming expired leases and checking gates need none, and human
/// gates stay shut. Being in the server process, gate checks use the server's
/// `gate.repos` default.
fn capture() -> (Rc<RefCell<io::Buffer>>, Capture) {
    Capture::buffered(OUTPUT_LIMIT)
}

/// A bd command line run in a workspace as [`ACTOR`], parsed and dispatched
/// the way `bd serve` runs a request.
struct Background {
    app: App,
    command: Command,
}

impl Background {
    fn new(ws: &Workspace, open: &OpenOptions, argv: &[&str]) -> Result<Background> {
        let line = ["bd", "--json", "--actor", ACTOR].into_iter().chain(argv.iter().copied());
        let cli = Cli::try_parse_from(line).map_err(|e| Error::invalid(format!("bd {}: {e}", argv.join(" "))))?;
        let mut g = cli.global;
        g.db = Some(ws.db.clone());
        g.directory = Some(ws.dir.clone());
        g.remote = None;
        let mut app = App::new(g)?;
        app.set_store(Store::open(&ws.db, open.clone())?);
        Ok(Background { app, command: cli.command })
    }

    /// Run it and return its `--json` output.
    fn run(mut self) -> Result<Value> {
        let (out, capture) = capture();
        let (code, _) = io::capture(capture, || bd_cli::dispatch(&mut self.app, &self.command));
        code?;
        let out = out.borrow();
        Ok(serde_json::from_slice(out.output()?)?)
    }
}

fn reclaim(ws: &Workspace, open: &OpenOptions, started: Instant) -> Result<()> {
    let mut cmd = Background::new(ws, open, &["reclaim"])?;
    // Automatic reclaim, like `claim --next`'s: a workspace can turn it off.
    if !cmd.app.read(|r| bd_core::config::auto_reclaim(r.conn()))? {
        tracing::debug!(target: "bd::serve", workspace = %ws.name, job = "reclaim", "lease.auto_reclaim is off");
        return Ok(());
    }
    let out = cmd.run()?;
    let ids: Vec<&str> = out.as_array().into_iter().flatten().filter_map(|r| r["issue_id"].as_str()).collect();
    if ids.is_empty() {
        tracing::debug!(target: "bd::serve", workspace = %ws.name, job = "reclaim", ms = ms(started), "nothing to reclaim");
    } else {
        tracing::info!(
            target: "bd::serve",
            workspace = %ws.name,
            job = "reclaim",
            reclaimed = ids.len(),
            issues = %ids.join(","),
            ms = ms(started),
            "reclaimed expired leases"
        );
    }
    Ok(())
}

/// `bd gate check --type <kind>`; gates that could not be checked are logged one by one.
fn check_gates(ws: &Workspace, open: &OpenOptions, job: Job, kind: &str, started: Instant) -> Result<()> {
    let out = Background::new(ws, open, &["gate", "check", "--type", kind])?.run()?;
    let checked = out["checked"].as_array().map(Vec::as_slice).unwrap_or_default();
    let with = |action: &str| checked.iter().filter(|c| c["action"] == action).collect::<Vec<_>>();
    let id = |c: &Value| c["id"].as_str().unwrap_or_default().to_string();
    let (opened, escalated, errors) = (with("opened"), with("escalated"), with("error"));
    for c in &errors {
        tracing::warn!(
            target: "bd::serve",
            workspace = %ws.name,
            job = job.name(),
            gate = %id(c),
            error = c["detail"].as_str().unwrap_or_default(),
            "gate check failed"
        );
    }
    let changed: Vec<String> = opened.iter().chain(&escalated).map(|c| id(c)).collect();
    if changed.is_empty() {
        tracing::debug!(
            target: "bd::serve",
            workspace = %ws.name,
            job = job.name(),
            checked = checked.len(),
            errors = errors.len(),
            ms = ms(started),
            "checked gates"
        );
    } else {
        tracing::info!(
            target: "bd::serve",
            workspace = %ws.name,
            job = job.name(),
            checked = checked.len(),
            opened = opened.len(),
            escalated = escalated.len(),
            errors = errors.len(),
            gates = %changed.join(","),
            ms = ms(started),
            "checked gates"
        );
    }
    Ok(())
}

/// What reading each harness's set gave when it could not be read, by
/// workspace: a warning is logged when that changes, not on every run.
#[derive(Default)]
struct Unreadable(std::sync::Mutex<HashMap<(String, Harness), String>>);

impl Unreadable {
    /// Note what reading `h`'s set in workspace `ws` gave: `error`, or
    /// none. Returns whether that is news: an error other than the one
    /// noted before, or the first read since one.
    fn note(&self, ws: &str, h: Harness, error: Option<&str>) -> bool {
        let mut seen = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (ws.to_string(), h);
        match error {
            Some(e) if seen.get(&key).is_some_and(|before| before == e) => false,
            Some(e) => {
                seen.insert(key, e.to_string());
                true
            }
            None => seen.remove(&key).is_some(),
        }
    }
}

/// Read each harness's set in `ws` and record its revision: an
/// `agents_changed` event for each set that changed. A set that cannot be
/// read is left out (no event; its clients keep what they have) with a
/// warning when its error changes, and the job goes on as usual: only
/// failing to record fails it.
///
/// Each run reads and hashes every set (up to [`bd_core::agents::MAX_SET_BYTES`]
/// each), which is affordable at this job's interval; keeping each
/// workspace's last manifests (which `agents manifest` could serve too) is a
/// possible optimization.
fn agents(ws: &Workspace, open: &OpenOptions, started: Instant, unreadable: &Unreadable) -> Result<()> {
    let dir = ws.db.parent().unwrap_or(&ws.dir).join(AGENTS_DIR);
    let mut revisions = std::collections::BTreeMap::new();
    for h in Harness::ALL {
        match AgentSet::load(&dir, h) {
            Ok(set) => {
                if unreadable.note(&ws.name, h, None) {
                    tracing::info!(target: "bd::serve", workspace = %ws.name, job = "agents", harness = %h, "agent set readable again");
                }
                revisions.insert(h, set.revision);
            }
            Err(e) => {
                let error = e.to_string();
                if unreadable.note(&ws.name, h, Some(&error)) {
                    tracing::warn!(
                        target: "bd::serve",
                        workspace = %ws.name,
                        job = "agents",
                        harness = %h,
                        error = %error,
                        "agent set cannot be read; its clients keep what they have"
                    );
                }
            }
        }
    }
    let mut store = Store::open(&ws.db, open.clone())?;
    let changed = bd_core::agents::record_revisions(&mut store, ACTOR, &revisions)?;
    if changed.is_empty() {
        tracing::debug!(target: "bd::serve", workspace = %ws.name, job = "agents", ms = ms(started), "agent sets unchanged");
    } else {
        let harnesses: Vec<&str> = changed.iter().map(|c| c.harness.name()).collect();
        tracing::info!(
            target: "bd::serve",
            workspace = %ws.name,
            job = "agents",
            harnesses = %harnesses.join(","),
            ms = ms(started),
            "agent sets changed"
        );
    }
    Ok(())
}

fn prune(ws: &Workspace, open: &OpenOptions, started: Instant) -> Result<()> {
    let mut store = Store::open(&ws.db, open.clone())?;
    let mut records = 0;
    loop {
        let n = store.write("requests.prune", ACTOR, |tx| {
            let before = tx.now().minus(REQUEST_RETENTION);
            tx.prune_requests(before, PRUNE_BATCH)
        })?;
        records += n;
        if n < PRUNE_BATCH {
            break;
        }
    }
    if records > 0 {
        tracing::info!(target: "bd::serve", workspace = %ws.name, job = "prune", records, ms = ms(started), "pruned request records");
    }
    Ok(())
}

/// Back up `ws`; returns the new backup file.
fn backup(ws: &Workspace, open: &OpenOptions, b: &Backups, started: Instant) -> Result<PathBuf> {
    let taken = match ws.name == SERVER {
        true => backup::take_with(&b.dir, &ws.name, b.keep, |tmp| crate::server_db::snapshot(&ws.dir, tmp))?,
        false => backup::take(&Store::open(&ws.db, open.clone())?, &b.dir, &ws.name, b.keep)?,
    };
    if let Some(newer) = &taken.newer {
        tracing::warn!(
            target: "bd::serve",
            workspace = %ws.name,
            file = %taken.file.display(),
            newer = %newer.display(),
            "an existing backup is dated after the new one: check the clock (the oldest-dated backups are deleted first)"
        );
    }
    for (old, e) in &taken.undeleted {
        tracing::warn!(target: "bd::serve", file = %old.display(), error = %e, "cannot delete an old backup");
    }
    tracing::info!(
        target: "bd::serve",
        workspace = %ws.name,
        job = "backup",
        file = %taken.file.display(),
        bytes = taken.bytes,
        removed = taken.removed,
        ms = ms(started),
        "backed up"
    );
    Ok(taken.file)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Condvar, Mutex};

    use bd_core::{InitOptions, NewIssue, Queries};

    use super::*;

    fn millis(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
    }

    /// A root whose workspaces have a (fake) database file.
    fn root_with(names: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for name in names {
            add_workspace(root.path(), name);
        }
        root
    }

    fn add_workspace(root: &Path, name: &str) {
        std::fs::create_dir_all(root.join(name).join(".bd")).unwrap();
        std::fs::write(root.join(name).join(".bd").join("bd.db"), b"").unwrap();
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(millis(10));
        }
    }

    #[test]
    fn intervals_are_durations_or_off() {
        assert_eq!(every("--x", "0").unwrap(), None);
        assert_eq!(every("--x", "0s").unwrap(), None);
        assert_eq!(every("--x", " OFF ").unwrap(), None);
        assert_eq!(every("--x", "90s").unwrap(), Some(Duration::from_secs(90)));
        assert_eq!(every("--x", "100ms").unwrap(), Some(millis(100)));
        assert_eq!(every("--x", "10ms").unwrap_err().exit_code(), 2, "too short");
        assert_eq!(every("--x", "366d").unwrap_err().exit_code(), 2, "too long");
        assert_eq!(every("--x", "365d").unwrap(), Some(MAX_EVERY));
        let e = every("--reclaim-every", "soon").unwrap_err();
        assert!(e.to_string().starts_with("--reclaim-every soon: invalid duration"), "{e}");
        assert_eq!((show(None), show(Some(Duration::from_secs(90)))), ("off".to_string(), "1m30s".to_string()));
    }

    #[test]
    fn backoff_doubles_up_to_a_limit() {
        let m = Duration::from_secs(60);
        assert_eq!(backoff(m, 0), m);
        assert_eq!(backoff(m, 1), m * 2);
        assert_eq!(backoff(m, 3), m * 8);
        assert_eq!(backoff(m, 40), m * MAX_BACKOFF);
        let now = Instant::now();
        assert!(after(now, MAX_EVERY * MAX_BACKOFF) > now, "the longest wait fits the clock");
        let mut rng = Rng::new();
        for _ in 0..1000 {
            let (u, j) = (rng.unit(), rng.between(0.9, 1.1));
            assert!((0.0..1.0).contains(&u) && (0.9..1.1).contains(&j), "{u} {j}");
        }
    }

    #[test]
    fn workspaces_are_found_by_their_database() {
        let root = root_with(&["proj", "other.v2", ".hidden"]);
        std::fs::create_dir_all(root.path().join("empty").join(".bd")).unwrap();
        std::fs::write(root.path().join("server.db"), b"").unwrap();
        let names: Vec<String> = discover(root.path()).unwrap().into_iter().map(|w| w.name).collect();
        assert_eq!(names, ["other.v2", "proj", SERVER], "server.db too, last");
        assert!(discover(&root.path().join("missing")).is_err());
    }

    /// A root holding workspace `proj` with one issue.
    fn real_workspace() -> (tempfile::TempDir, Workspace) {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("proj").join(".bd").join("bd.db");
        let init = InitOptions { prefix: "t".into(), id_mode: Default::default() };
        let mut store = Store::init(&db, init, OpenOptions::default()).unwrap();
        store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled("Backed up"))).unwrap();
        let ws = discover(root.path()).unwrap().remove(0);
        (root, ws)
    }

    #[test]
    fn backups_are_snapshots_kept_per_workspace() {
        let (_root, ws) = real_workspace();
        let out = tempfile::tempdir().unwrap();
        let b = Backups { dir: out.path().to_path_buf(), every: Duration::from_secs(3600), keep: 2 };
        for _ in 0..3 {
            backup(&ws, &OpenOptions::default(), &b, Instant::now()).unwrap();
            std::thread::sleep(millis(5));
        }
        let files = backup::files(&out.path().join("proj"), "proj").unwrap();
        assert_eq!(files.len(), 2, "{files:?}");
        let restore = tempfile::tempdir().unwrap();
        let restored = restore.path().join("bd.db");
        std::fs::copy(&files[1], &restored).unwrap();
        let copy = Store::open(&restored, OpenOptions::default()).unwrap();
        let titles: Vec<String> =
            copy.read(|r| r.list(&Default::default())).unwrap().into_iter().map(|i| i.title).collect();
        assert_eq!(titles, ["Backed up"]);
    }

    #[test]
    fn the_servers_accounts_and_tokens_are_backed_up_beside_the_workspaces() {
        let root = tempfile::tempdir().unwrap();
        crate::auth::issue_token(root.path(), "ci", "ci", crate::auth::Role::Write, crate::auth::Kind::Agent, &[])
            .unwrap();
        let server = discover(root.path()).unwrap().into_iter().find(|w| w.name == SERVER).expect("server.db");
        let out = tempfile::tempdir().unwrap();
        let b = Backups { dir: out.path().to_path_buf(), every: Duration::from_secs(3600), keep: 2 };
        let file = backup(&server, &OpenOptions::default(), &b, Instant::now()).unwrap();
        assert_eq!(file.parent().unwrap(), out.path().join(SERVER));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let restored = tempfile::tempdir().unwrap();
        std::fs::copy(&file, crate::server_db::path(restored.path())).unwrap();
        let conn = crate::server_db::open(restored.path()).unwrap();
        let tokens: i64 = conn.query_row("SELECT count(*) FROM tokens", [], |r| r.get(0)).unwrap();
        assert_eq!(tokens, 1, "the token is in the copy");
    }

    #[test]
    fn a_new_backup_survives_backups_dated_in_the_future() {
        let (_root, ws) = real_workspace();
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        // Taken while the clock was years ahead (a restored VM, bad NTP, a board without an RTC).
        let future = ["proj-29990101T000000.000Z.db", "proj-29990102T000000.000Z.db"].map(|f| dir.join(f));
        for f in &future {
            std::fs::write(f, b"x").unwrap();
        }
        let mut b = Backups { dir: out.path().to_path_buf(), every: Duration::from_secs(3600), keep: 2 };
        let first = backup(&ws, &OpenOptions::default(), &b, Instant::now()).unwrap();
        assert!(first.is_file(), "the backup just written is kept");
        assert_eq!(backup::files(&dir, "proj").unwrap(), [first.clone(), future[1].clone()]);
        std::thread::sleep(millis(5));
        let second = backup(&ws, &OpenOptions::default(), &b, Instant::now()).unwrap();
        assert_eq!(backup::files(&dir, "proj").unwrap(), [second.clone(), future[1].clone()]);
        b.keep = 1;
        std::thread::sleep(millis(5));
        let third = backup(&ws, &OpenOptions::default(), &b, Instant::now()).unwrap();
        assert_eq!(backup::files(&dir, "proj").unwrap(), [third], "keep 1 keeps the new one");
    }

    #[test]
    fn the_agents_job_records_changed_sets_and_skips_unreadable_ones() {
        let (_root, ws) = real_workspace();
        let dir = ws.db.parent().unwrap().join(AGENTS_DIR);
        let (open, unreadable) = (OpenOptions::default(), Unreadable::default());
        let changes = || {
            let store = Store::open(&ws.db, OpenOptions::default()).unwrap();
            let q = bd_core::EventQuery { since: Some(0), ops: vec!["agents_changed".into()], ..Default::default() };
            store.read(|r| r.events(&q)).unwrap().events
        };
        agents(&ws, &open, Instant::now(), &unreadable).unwrap();
        assert!(changes().is_empty(), "nothing served");

        let skill = dir.join("claude").join("skills").join("deploy");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "deploy\n").unwrap();
        agents(&ws, &open, Instant::now(), &unreadable).unwrap();
        agents(&ws, &open, Instant::now(), &unreadable).unwrap();
        let events = changes();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!((events[0].actor.as_str(), events[0].data["harness"].as_str()), (ACTOR, Some("claude")));
        assert_eq!(events[0].data["revision"], AgentSet::load(&dir, Harness::Claude).unwrap().revision);

        // An unreadable set gets no event and fails nothing; the others are still recorded.
        std::fs::create_dir_all(dir.join("codex")).unwrap();
        std::fs::write(dir.join("codex").join("mcp.toml"), "not = [toml").unwrap();
        std::fs::write(skill.join("SKILL.md"), "deploy v2\n").unwrap();
        agents(&ws, &open, Instant::now(), &unreadable).unwrap();
        let events = changes();
        assert_eq!(events.iter().map(|e| e.data["harness"].as_str().unwrap()).collect::<Vec<_>>(), ["claude"; 2]);
        let noted = unreadable.0.lock().unwrap().get(&(ws.name.clone(), Harness::Codex)).cloned().unwrap();
        assert!(noted.contains("codex/mcp.toml"), "{noted}");
        assert!(!unreadable.note(&ws.name, Harness::Codex, Some(&noted)), "warned about already");
    }

    #[test]
    fn unreadable_sets_are_news_once_per_error() {
        let u = Unreadable::default();
        let (claude, codex) = (Harness::Claude, Harness::Codex);
        assert!(!u.note("proj", claude, None), "readable all along");
        assert!(u.note("proj", claude, Some("a: no SKILL.md")));
        assert!(!u.note("proj", claude, Some("a: no SKILL.md")), "the same error again");
        assert!(u.note("other", claude, Some("a: no SKILL.md")), "per workspace");
        assert!(u.note("proj", codex, Some("a: no SKILL.md")), "per harness");
        assert!(u.note("proj", claude, Some("mcp.json: not JSON")), "another error");
        assert!(u.note("proj", claude, None), "readable again");
        assert!(!u.note("proj", claude, None));
        assert!(u.note("proj", claude, Some("mcp.json: not JSON")), "broken again");
    }

    #[cfg(unix)]
    #[test]
    fn backups_are_private_to_the_server_user() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let base = tempfile::tempdir().unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = base.path().join("new").join("backups");
        let line = ["bd", "serve", "--root", ".", "--backup-dir", dir.to_str().unwrap()];
        let Command::Serve(args) = Cli::try_parse_from(line).unwrap().command else { panic!("not serve") };
        let config = Config::from_args(&args).unwrap();
        assert_eq!((mode(&base.path().join("new")), mode(&dir)), (0o700, 0o700), "created private");
        assert_eq!(mode(base.path()), 0o755, "an existing directory keeps its mode");

        let (_root, ws) = real_workspace();
        let file = backup(&ws, &OpenOptions::default(), config.backups.as_ref().unwrap(), Instant::now()).unwrap();
        assert_eq!((mode(&dir.join("proj")), mode(&file)), (0o700, 0o600));
    }

    /// What a test runner saw.
    #[derive(Default)]
    struct Seen {
        calls: Vec<(String, Job)>,
        running: HashSet<(String, Job)>,
        in_lane: usize,
        max_in_lane: usize,
        overlaps: usize,
    }

    fn recording(seen: &Arc<Mutex<Seen>>, work: Duration) -> Runner {
        let seen = seen.clone();
        Arc::new(move |ws: &Workspace, job| {
            let key = (ws.name.clone(), job);
            {
                let mut s = seen.lock().unwrap();
                s.overlaps += usize::from(!s.running.insert(key.clone()));
                s.in_lane += 1;
                s.max_in_lane = s.max_in_lane.max(s.in_lane);
                s.calls.push(key.clone());
            }
            std::thread::sleep(work);
            let mut s = seen.lock().unwrap();
            s.running.remove(&key);
            s.in_lane -= 1;
            true
        })
    }

    #[test]
    fn enabled_jobs_run_in_every_workspace_without_overlapping() {
        let rt = runtime();
        let root = root_with(&["a", "b", ".hidden"]);
        let config = Config { reclaim_every: Some(millis(100)), prune_every: Some(millis(150)), ..Default::default() };
        let seen = Arc::new(Mutex::new(Seen::default()));
        let jobs = {
            let _rt = rt.enter();
            spawn(config, root.path().to_path_buf(), recording(&seen, millis(20)))
        };
        let count = |ws: &str, job: Job| seen.lock().unwrap().calls.iter().filter(|c| c.0 == ws && c.1 == job).count();
        wait_for("each job to run 3 times in a and b", || {
            ["a", "b"].iter().all(|ws| count(ws, Job::Reclaim) >= 3 && count(ws, Job::Prune) >= 3)
        });
        add_workspace(root.path(), "c");
        wait_for("a new workspace to be picked up", || count("c", Job::Reclaim) >= 1);
        assert_eq!(rt.block_on(jobs.stop(Duration::from_secs(10))), 0);

        let s = seen.lock().unwrap();
        assert_eq!(s.overlaps, 0, "a job never overlaps itself");
        assert!(s.max_in_lane <= LANES[0], "at most {} database jobs at once: {}", LANES[0], s.max_in_lane);
        assert!(s.calls.iter().all(|(ws, job)| ws != ".hidden" && matches!(job, Job::Reclaim | Job::Prune)));
        let after = s.calls.len();
        drop(s);
        std::thread::sleep(millis(400));
        assert_eq!(seen.lock().unwrap().calls.len(), after, "nothing starts after stop");
    }

    #[test]
    fn stop_waits_for_running_jobs_only_up_to_the_grace_period() {
        let rt = runtime();
        let root = root_with(&["a"]);
        let config = Config { backups: None, gate_check_every: Some(millis(100)), ..Default::default() };
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started) = std::sync::mpsc::channel();
        let stuck: Runner = {
            let gate = gate.clone();
            let started_tx = Mutex::new(started_tx);
            Arc::new(move |_: &Workspace, _| {
                let _ = started_tx.lock().unwrap().send(());
                let (open, cv) = &*gate;
                let _held = cv.wait_while(open.lock().unwrap(), |open| !*open).unwrap();
                true
            })
        };
        let jobs = {
            let _rt = rt.enter();
            spawn(config.clone(), root.path().to_path_buf(), stuck)
        };
        started.recv_timeout(Duration::from_secs(20)).unwrap();
        let t = Instant::now();
        assert_eq!(rt.block_on(jobs.stop(millis(200))), 1, "the stuck job is abandoned");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();

        let seen = Arc::new(Mutex::new(Seen::default()));
        let jobs = {
            let _rt = rt.enter();
            spawn(config, root.path().to_path_buf(), recording(&seen, millis(300)))
        };
        wait_for("a job to start", || !seen.lock().unwrap().running.is_empty());
        assert_eq!(rt.block_on(jobs.stop(Duration::from_secs(20))), 0, "a job that finishes in time");
        assert!(seen.lock().unwrap().running.is_empty());
    }

    #[test]
    fn no_jobs_no_scheduler() {
        let rt = runtime();
        let root = root_with(&["a"]);
        let seen = Arc::new(Mutex::new(Seen::default()));
        let jobs = {
            let _rt = rt.enter();
            spawn(Config::default(), root.path().to_path_buf(), recording(&seen, Duration::ZERO))
        };
        assert_eq!(rt.block_on(jobs.stop(Duration::from_secs(1))), 0);
        assert!(seen.lock().unwrap().calls.is_empty());
    }
}
