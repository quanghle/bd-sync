//! `bd bench`: concurrent claim throughput on a scratch database.
//!
//! Seeds a random DAG of issues, then runs N workers that loop
//! `claim --next` -> (work) -> (heartbeat) -> `close --token` until the graph
//! is drained. Three modes:
//! * `threads`: worker threads in this process, one connection each;
//! * `processes`: one long-lived worker process each (cross-process locks);
//! * `cli`: a fresh `bd` process per claim and per close, which is what
//!   agents invoking the CLI experience end to end.
//!
//! Afterwards the event log is checked: every issue was claimed and closed
//! exactly once, and never claimed before all of its blockers closed.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use bd_core::config::IdMode;
use bd_core::doctor;
use bd_core::{
    ClaimOptions, CloseOptions, DepType, Durability, Error, InitOptions, NewIssue, OpenOptions, ReadyQuery, Result,
    Store,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::app::App;
use crate::cli::{BenchArgs, BenchMode, BenchWorkerArgs};

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

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[derive(Default, Serialize, Deserialize)]
struct WorkerStats {
    claims: usize,
    claim_us: Vec<u64>,
    close_us: Vec<u64>,
    busy_retries: u64,
    empty_polls: u64,
}

#[derive(Serialize)]
struct Latency {
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

fn latency(mut v: Vec<u64>) -> Latency {
    if v.is_empty() {
        return Latency { p50_us: 0, p95_us: 0, p99_us: 0, max_us: 0 };
    }
    v.sort_unstable();
    let pick = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    Latency { p50_us: pick(0.5), p95_us: pick(0.95), p99_us: pick(0.99), max_us: *v.last().unwrap_or(&0) }
}

#[derive(Serialize)]
struct Report {
    mode: String,
    workers: usize,
    issues: usize,
    edges: i64,
    durability: String,
    work_ms: u64,
    seed_ms: f64,
    elapsed_ms: f64,
    claims_per_sec: f64,
    transactions_per_sec: f64,
    claim_latency: Latency,
    close_latency: Latency,
    busy_retries: u64,
    empty_polls: u64,
    claims_by_worker: Vec<usize>,
    verified: bool,
    violations: Vec<String>,
    database: Option<PathBuf>,
}

fn bench_options(durability: Durability) -> OpenOptions {
    OpenOptions {
        busy_timeout: Duration::from_secs(60),
        slow_threshold: Duration::from_secs(3600),
        durability: Some(durability),
        ..Default::default()
    }
}

fn open_count(store: &Store) -> Result<i64> {
    Ok(store.connection().query_row("SELECT COUNT(*) FROM issues WHERE status <> 'closed'", [], |r| r.get(0))?)
}

/// The claim -> work -> close loop shared by `threads` and `processes`.
fn run_worker(
    path: &Path,
    opts: OpenOptions,
    actor: &str,
    work: Duration,
    heartbeat: bool,
    start: Option<Arc<Barrier>>,
) -> Result<WorkerStats> {
    let mut store = Store::open(path, opts)?;
    let mut s = WorkerStats::default();
    let q = ReadyQuery::default();
    if let Some(b) = start {
        b.wait();
    }
    loop {
        let t = Instant::now();
        let claim = store.write("claim", actor, |tx| tx.claim_next(&q, &ClaimOptions::default()))?;
        s.busy_retries += store.last_tx_stats().map_or(0, |x| u64::from(x.busy_retries));
        let Some(claim) = claim else {
            if open_count(&store)? == 0 {
                break;
            }
            s.empty_polls += 1;
            std::thread::sleep(Duration::from_micros(200));
            continue;
        };
        s.claim_us.push(t.elapsed().as_micros() as u64);
        s.claims += 1;
        if !work.is_zero() {
            std::thread::sleep(work);
        }
        let id = claim.issue.id.clone();
        if heartbeat {
            store.write("heartbeat", actor, |tx| tx.heartbeat(&id, Some(claim.lease.token), None))?;
        }
        let t = Instant::now();
        let close = CloseOptions { token: Some(claim.lease.token), ..Default::default() };
        store.write("close", actor, |tx| tx.close_issue(&id, &close))?;
        s.busy_retries += store.last_tx_stats().map_or(0, |x| u64::from(x.busy_retries));
        s.close_us.push(t.elapsed().as_micros() as u64);
    }
    Ok(s)
}

pub fn cmd_bench_worker(a: &BenchWorkerArgs) -> Result<()> {
    let opts = bench_options(Durability::parse(&a.durability)?);
    let stats = run_worker(&a.path, opts, &a.name, Duration::from_millis(a.work_ms), a.heartbeat, None)?;
    println!("{}", serde_json::to_string(&stats)?);
    Ok(())
}

/// One `bd` process per operation, driven from a thread.
fn run_cli_worker(
    exe: &Path,
    path: &Path,
    actor: &str,
    work: Duration,
    heartbeat: bool,
    start: Arc<Barrier>,
) -> Result<WorkerStats> {
    let probe = Store::open(path, bench_options(Durability::Normal))?;
    let bd = |args: &[&str]| -> Result<Value> {
        let out = Command::new(exe)
            .arg("--db")
            .arg(path)
            .args(["--actor", actor, "--json"])
            .args(args)
            .env("BD_LOG", "error")
            .env("BD_BUSY_TIMEOUT_MS", "60000")
            .output()?;
        if !out.status.success() {
            return Err(Error::invalid(format!(
                "bd {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    };
    let mut s = WorkerStats::default();
    start.wait();
    loop {
        let t = Instant::now();
        let claim = bd(&["claim", "--next"])?;
        if claim.is_null() {
            if open_count(&probe)? == 0 {
                break;
            }
            s.empty_polls += 1;
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        s.claim_us.push(t.elapsed().as_micros() as u64);
        s.claims += 1;
        let id = claim["issue"]["id"].as_str().unwrap_or_default().to_string();
        let token = claim["lease"]["token"].as_i64().unwrap_or_default().to_string();
        if !work.is_zero() {
            std::thread::sleep(work);
        }
        if heartbeat {
            bd(&["heartbeat", &id, "--token", &token])?;
        }
        let t = Instant::now();
        bd(&["close", &id, "--token", &token])?;
        s.close_us.push(t.elapsed().as_micros() as u64);
    }
    Ok(s)
}

fn scratch_path(keep: &Option<PathBuf>) -> Result<(PathBuf, Option<PathBuf>)> {
    match keep {
        Some(p) => {
            if p.exists() {
                return Err(Error::invalid(format!("{} already exists", p.display())));
            }
            Ok((p.clone(), None))
        }
        None => {
            let nanos =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("bd-bench-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            Ok((dir.join("bench.db"), Some(dir)))
        }
    }
}

fn seed(store: &mut Store, n: usize, deps: f64, seed: u64) -> Result<()> {
    let mut rng = Rng(seed.max(1));
    store.write("bench.seed", "bench", |tx| {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let priority = (rng.next() % 5) as u8;
            ids.push(
                tx.create_issue(NewIssue {
                    title: format!("job {i}"),
                    priority: Some(priority),
                    ..Default::default()
                })?
                .id,
            );
        }
        for i in 1..n {
            let mut k = deps.floor() as usize;
            if rng.unit() < deps.fract() {
                k += 1;
            }
            for _ in 0..k {
                let j = rng.below(i);
                tx.add_dependency(&ids[i], &ids[j], DepType::Blocks, None)?;
            }
        }
        Ok(())
    })
}

fn verify(store: &mut Store, n: usize) -> Result<Vec<String>> {
    let conn = store.connection();
    let mut violations = Vec::new();
    let (claims, distinct): (i64, i64) =
        conn.query_row("SELECT COUNT(*), COUNT(DISTINCT issue_id) FROM events WHERE op = 'claimed'", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    if claims != n as i64 || distinct != n as i64 {
        violations.push(format!("expected {n} claims of {n} issues, saw {claims} claims of {distinct}"));
    }
    let closed: i64 = conn.query_row("SELECT COUNT(*) FROM issues WHERE status = 'closed'", [], |r| r.get(0))?;
    if closed != n as i64 {
        violations.push(format!("{closed}/{n} issues closed"));
    }
    let early: i64 = conn.query_row(
        "SELECT COUNT(*) FROM dependencies d
         JOIN events c ON c.issue_id = d.issue_id AND c.op = 'claimed'
         JOIN events x ON x.issue_id = d.depends_on_id AND x.op = 'closed'
         WHERE d.dep_type = 'blocks' AND c.seq < x.seq",
        [],
        |r| r.get(0),
    )?;
    if early > 0 {
        violations.push(format!("{early} claims happened before a blocker closed"));
    }
    let report = doctor::diagnose(store, false, false)?;
    for c in report.checks.iter().filter(|c| c.severity == doctor::Severity::Error) {
        violations.push(format!("doctor {}: {}", c.name, c.detail));
    }
    Ok(violations)
}

fn run_threads(a: &BenchArgs, path: &Path, opts: &OpenOptions) -> Result<Vec<WorkerStats>> {
    let barrier = Arc::new(Barrier::new(a.workers));
    let exe = std::env::current_exe()?;
    let work = Duration::from_millis(a.work_ms);
    let handles: Vec<_> = (0..a.workers)
        .map(|w| {
            let (path, opts, barrier, exe) = (path.to_path_buf(), opts.clone(), barrier.clone(), exe.clone());
            let (mode, heartbeat) = (a.mode, a.heartbeat);
            std::thread::spawn(move || {
                let actor = format!("worker-{w}");
                if mode == BenchMode::Cli {
                    run_cli_worker(&exe, &path, &actor, work, heartbeat, barrier)
                } else {
                    run_worker(&path, opts, &actor, work, heartbeat, Some(barrier))
                }
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().map_err(|_| Error::invalid("worker panicked"))?).collect()
}

fn run_processes(a: &BenchArgs, path: &Path) -> Result<Vec<WorkerStats>> {
    let exe = std::env::current_exe()?;
    let children = (0..a.workers)
        .map(|w| {
            let mut cmd = Command::new(&exe);
            cmd.arg("bench-worker")
                .arg("--path")
                .arg(path)
                .args(["--name", &format!("worker-{w}")])
                .args(["--work-ms", &a.work_ms.to_string(), "--durability", &a.durability])
                .env("BD_LOG", "error")
                .stdout(std::process::Stdio::piped());
            if a.heartbeat {
                cmd.arg("--heartbeat");
            }
            cmd.spawn().map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut stats = Vec::new();
    for child in children {
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(Error::invalid("a bench worker process failed"));
        }
        stats.push(serde_json::from_slice::<WorkerStats>(&out.stdout)?);
    }
    Ok(stats)
}

pub fn cmd_bench(app: &mut App, a: &BenchArgs) -> Result<()> {
    if a.workers == 0 || a.issues == 0 {
        return Err(Error::invalid("--workers and --issues must be positive"));
    }
    let durability = Durability::parse(&a.durability)?;
    let (path, cleanup) = scratch_path(&a.keep)?;
    let opts = bench_options(durability);
    let mut store = Store::init(&path, InitOptions { prefix: "b".into(), id_mode: IdMode::Counter }, opts.clone())?;
    let seed_start = Instant::now();
    seed(&mut store, a.issues, a.deps.max(0.0), a.seed)?;
    let seed_ms = seed_start.elapsed().as_secs_f64() * 1e3;
    let edges: i64 = store.connection().query_row("SELECT COUNT(*) FROM dependencies", [], |r| r.get(0))?;

    let start = Instant::now();
    let all = match a.mode {
        BenchMode::Threads | BenchMode::Cli => run_threads(a, &path, &opts)?,
        BenchMode::Processes => run_processes(a, &path)?,
    };
    let elapsed = start.elapsed();
    let violations = verify(&mut store, a.issues)?;

    let total_claims: usize = all.iter().map(|s| s.claims).sum();
    let secs = elapsed.as_secs_f64().max(1e-9);
    let mut claim_us = Vec::new();
    let mut close_us = Vec::new();
    for s in &all {
        claim_us.extend_from_slice(&s.claim_us);
        close_us.extend_from_slice(&s.close_us);
    }
    let report = Report {
        mode: format!("{:?}", a.mode).to_ascii_lowercase(),
        workers: a.workers,
        issues: a.issues,
        edges,
        durability: a.durability.to_ascii_lowercase(),
        work_ms: a.work_ms,
        seed_ms,
        elapsed_ms: secs * 1e3,
        claims_per_sec: total_claims as f64 / secs,
        transactions_per_sec: (total_claims * if a.heartbeat { 3 } else { 2 }) as f64 / secs,
        claim_latency: latency(claim_us),
        close_latency: latency(close_us),
        busy_retries: all.iter().map(|s| s.busy_retries).sum(),
        empty_polls: all.iter().map(|s| s.empty_polls).sum(),
        claims_by_worker: all.iter().map(|s| s.claims).collect(),
        verified: violations.is_empty(),
        violations,
        database: a.keep.clone(),
    };
    drop(store);
    if let Some(dir) = cleanup {
        let _ = std::fs::remove_dir_all(dir);
    }
    if app.g.json {
        app.print_json(&json!(report));
    } else {
        println!(
            "bd bench [{}]: {} workers, {} issues, {} blocking edges, durability {}, work {}ms",
            report.mode, report.workers, report.issues, report.edges, report.durability, report.work_ms
        );
        println!("  seeded in      {:.1} ms", report.seed_ms);
        println!("  drained in     {:.1} ms", report.elapsed_ms);
        println!(
            "  throughput     {:.0} claims/s, {:.0} write tx/s",
            report.claims_per_sec, report.transactions_per_sec
        );
        let l = &report.claim_latency;
        println!("  claim latency  p50 {}µs  p95 {}µs  p99 {}µs  max {}µs", l.p50_us, l.p95_us, l.p99_us, l.max_us);
        let l = &report.close_latency;
        println!("  close latency  p50 {}µs  p95 {}µs  p99 {}µs  max {}µs", l.p50_us, l.p95_us, l.p99_us, l.max_us);
        if a.mode == BenchMode::Cli {
            println!(
                "  contention     {} empty polls (busy retries happen inside child processes)",
                report.empty_polls
            );
        } else {
            println!("  contention     {} busy retries, {} empty polls", report.busy_retries, report.empty_polls);
        }
        println!("  per worker     {:?}", report.claims_by_worker);
        if report.verified {
            println!("  verified       ✓ each issue claimed and closed exactly once, never before its blockers closed");
        } else {
            for v in &report.violations {
                println!("  VIOLATION      {v}");
            }
        }
    }
    if report.verified { Ok(()) } else { Err(Error::invalid("benchmark invariants violated")) }
}
