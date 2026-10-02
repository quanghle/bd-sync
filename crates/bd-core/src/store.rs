//! Connection management: WAL configuration, snapshot reads, serialized
//! writes, and the per-transaction write context.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;

use crate::config::{self, IdMode};
use crate::error::{Error, Result};
use crate::policy::Policy;
use crate::schema;
use crate::time::{Clock, SystemClock, Timestamp};

/// SQLite `synchronous` level. In WAL mode `normal` survives application
/// crashes; `full` also survives power loss at the cost of an fsync per commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Off,
    Normal,
    Full,
}

impl Durability {
    pub fn parse(s: &str) -> Result<Durability> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Durability::Off),
            "normal" => Ok(Durability::Normal),
            "full" => Ok(Durability::Full),
            other => Err(Error::invalid(format!("invalid durability {other:?} (valid: off, normal, full)"))),
        }
    }

    fn pragma(self) -> &'static str {
        match self {
            Durability::Off => "OFF",
            Durability::Normal => "NORMAL",
            Durability::Full => "FULL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenOptions {
    /// How long a writer waits for the write lock before failing with `Busy`.
    pub busy_timeout: Duration,
    pub clock: Arc<dyn Clock>,
    /// Overrides the workspace `durability` config when set.
    pub durability: Option<Durability>,
    /// Transactions slower than this are logged at WARN (`bd::slow`).
    pub slow_threshold: Duration,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions {
            busy_timeout: Duration::from_secs(10),
            clock: Arc::new(SystemClock),
            durability: None,
            slow_threshold: Duration::from_millis(250),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InitOptions {
    pub prefix: String,
    pub id_mode: IdMode,
}

/// Timing of the most recent write transaction.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TxStats {
    pub op: &'static str,
    pub lock_wait_us: u64,
    pub exec_us: u64,
    pub commit_us: u64,
    pub busy_retries: u32,
    pub events: u32,
}

impl TxStats {
    pub fn total_us(&self) -> u64 {
        self.lock_wait_us + self.exec_us + self.commit_us
    }
}

static BUSY_TIMEOUT_MS: AtomicU64 = AtomicU64::new(10_000);

thread_local! {
    static BUSY_STARTED: Cell<Option<Instant>> = const { Cell::new(None) };
    static BUSY_RETRIES: Cell<u32> = const { Cell::new(0) };
    static JITTER: Cell<u64> = Cell::new(jitter_seed());
}

fn jitter_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish() | 1
}

fn next_jitter() -> u64 {
    JITTER.with(|c| {
        let mut x = c.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.set(x);
        x
    })
}

/// Busy handler with short, jittered exponential backoff (20µs..2ms).
/// SQLite's default handler sleeps up to 100ms between probes, which wastes
/// most of the lock's free time when several processes contend for it.
fn busy_handler(attempt: i32) -> bool {
    let now = Instant::now();
    let started = BUSY_STARTED.with(|c| match (attempt, c.get()) {
        (0, _) | (_, None) => {
            c.set(Some(now));
            now
        }
        (_, Some(t)) => t,
    });
    if now.duration_since(started) >= Duration::from_millis(BUSY_TIMEOUT_MS.load(Ordering::Relaxed)) {
        return false;
    }
    BUSY_RETRIES.with(|c| c.set(c.get().saturating_add(1)));
    let cap_us = (20u64 << attempt.clamp(0, 7)).min(2_000);
    std::thread::sleep(Duration::from_micros(1 + next_jitter() % cap_us));
    true
}

/// A handle on one workspace database. Open one per thread or process; the
/// database file is the coordination point.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    path: PathBuf,
    opts: OpenOptions,
    last_tx: Option<TxStats>,
}

impl Store {
    /// Create and initialize a new workspace database at `path`.
    pub fn init(path: &Path, init: InitOptions, opts: OpenOptions) -> Result<Store> {
        config::validate_prefix(&init.prefix)?;
        if path.exists() {
            let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            if schema::user_version(&conn)? > 0 {
                return Err(Error::invalid(format!("{} is already initialized", path.display())));
            }
        }
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let conn = Connection::open(path)?;
        let mut store = Store::configure(conn, path, opts)?;
        schema::migrate(&mut store.conn)?;
        let workspace_id = format!("{:016x}", jitter_seed());
        store.write("init", "bd", |tx| {
            let c = tx.conn();
            for (k, v) in [("workspace_id", workspace_id.as_str()), ("created_by_version", env!("CARGO_PKG_VERSION"))] {
                c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", params![k, v])?;
            }
            c.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('created_at', ?1)",
                params![tx.now().to_rfc3339()],
            )?;
            config::set(tx, "issue_prefix", &init.prefix)?;
            config::set(tx, "id.mode", init.id_mode.as_str())?;
            Ok(())
        })?;
        store.apply_durability()?;
        Ok(store)
    }

    /// Open an existing workspace database, migrating it forward if needed.
    pub fn open(path: &Path, opts: OpenOptions) -> Result<Store> {
        if !path.exists() {
            return Err(Error::NoWorkspace(format!("no bd database at {}", path.display())));
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        let mut store = Store::configure(conn, path, opts)?;
        match schema::user_version(&store.conn)? {
            0 => {
                return Err(Error::NoWorkspace(format!("{} is not an initialized bd database", path.display())));
            }
            v if v > schema::LATEST_VERSION => {
                return Err(Error::SchemaTooNew { found: v, supported: schema::LATEST_VERSION });
            }
            v if v < schema::LATEST_VERSION => {
                schema::migrate(&mut store.conn)?;
            }
            _ => {}
        }
        store.apply_durability()?;
        Ok(store)
    }

    fn configure(conn: Connection, path: &Path, opts: OpenOptions) -> Result<Store> {
        BUSY_TIMEOUT_MS.store(u64::try_from(opts.busy_timeout.as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
        conn.busy_handler(Some(busy_handler))?;
        let mode: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::invalid(format!("could not enable WAL mode (got {mode})")));
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "cache_size", -16_000)?;
        conn.pragma_update(None, "mmap_size", 256i64 << 20)?;
        // Fewer, larger checkpoints: each one fsyncs, and that is the main
        // source of tail latency for small transactions.
        conn.pragma_update(None, "wal_autocheckpoint", 4_000)?;
        conn.set_prepared_statement_cache_capacity(256);
        Ok(Store { conn, path: path.to_path_buf(), opts, last_tx: None })
    }

    fn apply_durability(&mut self) -> Result<()> {
        let durability = match self.opts.durability {
            Some(d) => d,
            None => Durability::parse(&config::get_or_default(&self.conn, "durability")?)?,
        };
        self.conn.pragma_update(None, "synchronous", durability.pragma())?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn now(&self) -> Timestamp {
        self.opts.clock.now()
    }

    pub fn options(&self) -> &OpenOptions {
        &self.opts
    }

    /// Raw connection, for advanced read-only use.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Workspace metadata (`workspace_id`, `created_at`, `created_by_version`).
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        meta_get(&self.conn, key)
    }

    pub fn last_tx_stats(&self) -> Option<&TxStats> {
        self.last_tx.as_ref()
    }

    /// Run `f` against one consistent snapshot of the database.
    pub fn read<T>(&self, f: impl FnOnce(&ReadCtx<'_>) -> Result<T>) -> Result<T> {
        let tx = self.conn.unchecked_transaction()?;
        let ctx = ReadCtx { conn: &tx, now: self.opts.clock.now() };
        let out = f(&ctx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Run `f` inside one serialized write transaction (`BEGIN IMMEDIATE`).
    ///
    /// Holding the write lock for the whole closure makes every
    /// read-check-write sequence inside it atomic with respect to all other
    /// processes. On `Err` nothing is written. `op` labels logs and stats.
    pub fn write<T>(
        &mut self,
        op: &'static str,
        actor: &str,
        f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>,
    ) -> Result<T> {
        validate_actor(actor)?;
        let begin = Instant::now();
        match run_write(&mut self.conn, &self.opts, op, actor, f, begin) {
            Ok((out, stats)) => {
                if let Some(stats) = stats {
                    if Duration::from_micros(stats.total_us()) >= self.opts.slow_threshold {
                        tracing::warn!(
                            target: "bd::slow",
                            op,
                            actor,
                            total_ms = stats.total_us() / 1000,
                            lock_wait_ms = stats.lock_wait_us / 1000,
                            exec_ms = stats.exec_us / 1000,
                            commit_ms = stats.commit_us / 1000,
                            "slow write transaction"
                        );
                        let _ = self.bump_counter("slow_writes", 1);
                    }
                    self.last_tx = Some(stats);
                }
                Ok(out)
            }
            Err(e) => {
                tracing::debug!(target: "bd::tx", op, actor, error = %e, "rolled back");
                if let Some(counter) = contention_counter(&e) {
                    let _ = self.bump_counter(counter, 1);
                }
                Err(e)
            }
        }
    }

    /// Increment a durable observability counter in its own small transaction.
    pub fn bump_counter(&mut self, name: &str, delta: i64) -> Result<()> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        bump_counter_in(&tx, name, delta)?;
        tx.commit()?;
        Ok(())
    }

    /// Truncate the WAL into the main database file.
    pub fn checkpoint(&self) -> Result<(i64, i64)> {
        Ok(self.conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(1)?, r.get(2)?)))?)
    }

    /// Write a consistent, compacted copy of the database to `dest`, which
    /// must not exist, with `VACUUM INTO`: one self-contained file in
    /// rollback-journal mode. It runs as a read transaction, so writers carry
    /// on meanwhile. The copy holds the whole workspace, so on Unix only its
    /// owner may read it (mode 0600). It is checked (`quick_check`) and
    /// flushed to disk before this returns; on failure it is removed.
    pub fn snapshot(&self, dest: &Path) -> Result<()> {
        let target = dest.to_str().ok_or_else(|| Error::invalid(format!("{}: not a UTF-8 path", dest.display())))?;
        // Created empty first (VACUUM INTO accepts that): private from the
        // start, and a file that already exists is never touched.
        let mut create = std::fs::OpenOptions::new();
        create.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut create, 0o600);
        create.open(dest).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Error::invalid(format!("{} already exists", dest.display())),
            _ => Error::Io(e),
        })?;
        let written =
            self.conn.execute("VACUUM INTO ?1", [target]).map_err(Error::from).and_then(|_| verify_copy(dest));
        if written.is_err() {
            let mut journal = dest.as_os_str().to_owned();
            journal.push("-journal");
            let _ = std::fs::remove_file(journal);
            let _ = std::fs::remove_file(dest);
        }
        written
    }
}

fn verify_copy(path: &Path) -> Result<()> {
    let copy = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    let check: String = copy.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if check != "ok" {
        return Err(Error::Io(std::io::Error::other(format!("{}: integrity check failed: {check}", path.display()))));
    }
    drop(copy);
    // Write access: Windows flushes only handles that may write.
    std::fs::OpenOptions::new().write(true).open(path)?.sync_all()?;
    Ok(())
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch("PRAGMA optimize");
    }
}

/// The body of [`Store::write`]: one `BEGIN IMMEDIATE` transaction.
/// Returns `None` stats for dry runs (rolled back on purpose).
fn run_write<T>(
    conn: &mut Connection,
    opts: &OpenOptions,
    op: &'static str,
    actor: &str,
    f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>,
    begin: Instant,
) -> Result<(T, Option<TxStats>)> {
    BUSY_RETRIES.with(|c| c.set(0));
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| match Error::from(e) {
        Error::Busy(_) => {
            tracing::warn!(target: "bd::slow", op, waited_ms = begin.elapsed().as_millis() as u64, "write lock timeout");
            Error::Busy(format!("timed out after {:?} waiting for the write lock", opts.busy_timeout))
        }
        other => other,
    })?;
    let lock_wait = begin.elapsed();
    let mut ctx = WriteCtx {
        tx,
        actor: actor.to_string(),
        now: opts.clock.now(),
        first_seq: None,
        events: 0,
        rollback_only: false,
        policy: None,
    };
    let exec_start = Instant::now();
    let out = f(&mut ctx)?;
    if ctx.events > 0 && !ctx.rollback_only {
        ctx.auto_prune_events()?;
    }
    let exec = exec_start.elapsed();
    if ctx.rollback_only {
        tracing::debug!(target: "bd::tx", op, actor, "rolled back (dry run)");
        return Ok((out, None));
    }
    let events = ctx.events;
    let commit_start = Instant::now();
    ctx.tx.commit()?;
    let stats = TxStats {
        op,
        lock_wait_us: lock_wait.as_micros() as u64,
        exec_us: exec.as_micros() as u64,
        commit_us: commit_start.elapsed().as_micros() as u64,
        busy_retries: BUSY_RETRIES.with(|c| c.get()),
        events,
    };
    tracing::debug!(
        target: "bd::tx",
        op,
        actor,
        lock_wait_us = stats.lock_wait_us,
        exec_us = stats.exec_us,
        commit_us = stats.commit_us,
        busy_retries = stats.busy_retries,
        events,
        "committed"
    );
    Ok((out, Some(stats)))
}

fn contention_counter(e: &Error) -> Option<&'static str> {
    match e {
        Error::AlreadyClaimed { .. } | Error::NotClaimable { .. } => Some("claim_conflicts"),
        Error::Conflict { .. } => Some("cas_conflicts"),
        Error::LeaseLost { .. } => Some("lease_lost"),
        Error::NotOwner { .. } | Error::ClaimsHeld { .. } => Some("not_owner"),
        _ => None,
    }
}

pub(crate) fn bump_counter_in(conn: &Connection, name: &str, delta: i64) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO counters (name, value) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
    )?
    .execute(params![name, delta])?;
    Ok(())
}

pub fn validate_actor(actor: &str) -> Result<()> {
    if actor.trim().is_empty() {
        return Err(Error::invalid("actor must not be empty"));
    }
    if actor.chars().count() > 255 {
        return Err(Error::invalid("actor must be at most 255 characters"));
    }
    Ok(())
}

/// Read access to a consistent snapshot.
pub struct ReadCtx<'a> {
    conn: &'a Connection,
    now: Timestamp,
}

impl ReadCtx<'_> {
    pub fn conn(&self) -> &Connection {
        self.conn
    }

    pub fn now(&self) -> Timestamp {
        self.now
    }
}

/// State of one write transaction: the actor, a single `now` for every row
/// it touches, and the event sequence it has allocated.
pub struct WriteCtx<'c> {
    tx: Transaction<'c>,
    actor: String,
    now: Timestamp,
    first_seq: Option<i64>,
    events: u32,
    rollback_only: bool,
    policy: Option<Policy>,
}

impl WriteCtx<'_> {
    /// Make the enclosing [`Store::write`] roll back instead of committing
    /// (dry runs). The closure's result is still returned.
    pub fn set_rollback_only(&mut self) {
        self.rollback_only = true;
    }

    /// Whether [`WriteCtx::set_rollback_only`] was called.
    pub fn is_rollback_only(&self) -> bool {
        self.rollback_only
    }

    /// Limit what this transaction may override ([`crate::policy`]). `bd
    /// serve` sets one per request; without one, nothing is limited.
    pub fn set_policy(&mut self, policy: Option<Policy>) {
        self.policy = policy;
    }

    pub fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
    }

    /// Run `f` in a savepoint: if it fails, what it wrote (its events
    /// included) is undone and the transaction goes on without it.
    pub fn savepoint<T>(&mut self, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        let (first_seq, events) = (self.first_seq, self.events);
        self.tx.execute_batch("SAVEPOINT bd_step")?;
        match f(self) {
            Ok(out) => {
                self.tx.execute_batch("RELEASE bd_step")?;
                Ok(out)
            }
            Err(e) => {
                // AUTOINCREMENT's counter rolls back too, so event seqs stay gapless.
                self.tx.execute_batch("ROLLBACK TO bd_step; RELEASE bd_step")?;
                self.first_seq = first_seq;
                self.events = events;
                Err(e)
            }
        }
    }

    pub fn conn(&self) -> &Connection {
        &self.tx
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Sequence number of the first event this transaction wrote, if any.
    pub fn tx_seq(&self) -> Option<i64> {
        self.first_seq
    }

    /// Append an event in this transaction and return its sequence number.
    pub(crate) fn emit(&mut self, op: &str, issue_id: Option<&str>, data: Value) -> Result<i64> {
        let data = serde_json::to_string(&data)?;
        self.tx
            .prepare_cached("INSERT INTO events (tx, ts, actor, op, issue_id, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
            .execute(params![self.first_seq.unwrap_or(0), self.now, self.actor, op, issue_id, data])?;
        let seq = self.tx.last_insert_rowid();
        if self.first_seq.is_none() {
            self.tx.prepare_cached("UPDATE events SET tx = ?1 WHERE seq = ?1")?.execute([seq])?;
            self.first_seq = Some(seq);
        }
        self.events += 1;
        Ok(seq)
    }

    pub(crate) fn bump_counter(&self, name: &str, delta: i64) -> Result<()> {
        bump_counter_in(&self.tx, name, delta)
    }
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?.query_row([key], |r| r.get(0)).optional()?)
}
