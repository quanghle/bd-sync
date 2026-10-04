//! `<root>/server.db`: what `bd serve` keeps about who may call it, apart
//! from the workspaces' own databases. The accounts that signed in, the
//! access tokens (only the SHA-256 of their secrets) and the OAuth clients
//! that registered, one row each, in SQLite (WAL, mode 0600 on Unix), so
//! the server issuing and refreshing tokens and an admin creating or
//! revoking others change them in transactions of their own.
//!
//! Each row keeps its record as JSON (`data`), with the columns lookups use
//! beside it ([`token_keys`], [`account_keys`]): a token's secret hash,
//! refresh family, actor, name and when it ended; an account's issuer and
//! subject, actor and login; a client's ID. Actors and logins are kept
//! lowercase (`*_key`), as accounts and tokens are told apart regardless of
//! case. `seq` keeps the order rows were added in.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::Value;

/// How long a change waits for another one to finish. Debug builds take
/// `BD_TEST_BUSY_MS` instead, so tests need not wait it out.
fn busy_wait() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("BD_TEST_BUSY_MS").ok().and_then(|v| v.parse().ok()) {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(10)
}

/// The schema this bd writes (`PRAGMA user_version`).
const VERSION: i64 = 2;

const SCHEMA: &str = "
CREATE TABLE accounts (
    seq INTEGER PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    login_key TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE INDEX accounts_actor ON accounts (actor_key);
CREATE INDEX accounts_login ON accounts (login_key);
CREATE TABLE tokens (
    seq INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    family TEXT,
    actor_key TEXT NOT NULL,
    name TEXT NOT NULL,
    ended_at INTEGER,
    data TEXT NOT NULL
);
CREATE INDEX tokens_sha256 ON tokens (sha256);
CREATE INDEX tokens_family ON tokens (family) WHERE family IS NOT NULL;
CREATE INDEX tokens_actor ON tokens (actor_key);
CREATE INDEX tokens_name ON tokens (name);
CREATE INDEX tokens_ended ON tokens (ended_at) WHERE ended_at IS NOT NULL;
CREATE TABLE oauth_clients (
    seq INTEGER PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    data TEXT NOT NULL
);
CREATE TABLE auth_events (
    seq INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT,
    actor_key TEXT,
    provider TEXT,
    issuer TEXT,
    subject TEXT,
    token TEXT,
    client TEXT,
    detail TEXT
);
CREATE INDEX auth_events_at ON auth_events (at);
CREATE INDEX auth_events_actor ON auth_events (actor_key) WHERE actor_key IS NOT NULL;
CREATE INDEX auth_events_account ON auth_events (issuer, subject) WHERE subject IS NOT NULL;
";

pub fn path(root: &Path) -> PathBuf {
    root.join("server.db")
}

/// What tells `<root>/server.db` from a file created in its place (its
/// inode, on Unix); `None` if it does not exist, or elsewhere.
pub fn file_id(root: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(path(root)).ok()?).into()
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        None
    }
}

/// A connection to `<root>/server.db`, created (mode 0600) and brought to
/// this bd's schema if needed: for changes, and for `bd serve`.
pub fn open(root: &Path) -> Result<Connection> {
    let path = path(root);
    let io_error = |e: std::io::Error| Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    // Created here first, so that it never exists with wider permissions (SQLite gives its -wal and -shm files the
    // database's).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(&path).map_err(io_error)?;
    connect(&path)
}

/// A connection to `<root>/server.db` if it exists: reads never create it,
/// so that a mistaken `--root` is not left with one.
pub fn open_existing(root: &Path) -> Result<Option<Connection>> {
    let path = path(root);
    match path.try_exists() {
        Ok(true) => connect(&path).map(Some),
        Ok(false) => Ok(None),
        Err(e) => Err(Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))),
    }
}

fn connect(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(|e| failed(path, e))?;
    conn.busy_timeout(busy_wait()).map_err(|e| failed(path, e))?;
    conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| failed(path, e))?;
    conn.pragma_update(None, "synchronous", "FULL").map_err(|e| failed(path, e))?;
    // What is deleted is overwritten, not left in free pages (an erased account must be gone); the write-ahead log is
    // cut back whenever it starts over, rather than keep old pages at its end.
    conn.pragma_update(None, "secure_delete", "ON").map_err(|e| failed(path, e))?;
    conn.pragma_update(None, "journal_size_limit", 0).map_err(|e| failed(path, e))?;
    migrate(&conn).map_err(|e| failed(path, e))?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == VERSION {
        return Ok(());
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    // Another process may have created it meanwhile.
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let done = match version {
        0 => conn.execute_batch(&format!("{SCHEMA}PRAGMA user_version = {VERSION};")),
        VERSION => Ok(()),
        other => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(format!("its schema {other} is not this bd's ({VERSION}): use the bd that wrote it")),
            ));
        }
    };
    match done {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Run `f` in a write transaction of `conn`, committed if it succeeds.
pub fn write<T>(root: &Path, conn: &mut Connection, f: impl FnOnce(&rusqlite::Transaction) -> Result<T>) -> Result<T> {
    let path = path(root);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| failed(&path, e))?;
    let out = f(&tx)?;
    tx.commit().map_err(|e| failed(&path, e))?;
    Ok(out)
}

/// Run `f` in a read transaction of `conn`: whatever it reads is of one
/// moment, however many statements it takes.
pub fn read<T>(root: &Path, conn: &mut Connection, f: impl FnOnce(&rusqlite::Transaction) -> Result<T>) -> Result<T> {
    let path = path(root);
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred).map_err(|e| failed(&path, e))?;
    let out = f(&tx)?;
    tx.finish().map_err(|e| failed(&path, e))?;
    Ok(out)
}

/// Copy the write-ahead log into the database and empty it, so that what
/// was just deleted (and overwritten there, with `secure_delete`) is in no
/// file any more: whether it could, which it cannot while another
/// connection reads an older state of it.
pub fn scrub(root: &Path) -> Result<bool> {
    let path = path(root);
    let conn = connect(&path)?;
    let busy: i64 =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0)).map_err(|e| failed(&path, e))?;
    Ok(busy == 0)
}

/// `e` of the database at `path`, said so.
pub fn failed(path: &Path, e: rusqlite::Error) -> Error {
    match Error::from(e) {
        Error::Busy(_) => {
            Error::Busy(format!("another bd process is changing {} and did not finish in time; retry", path.display()))
        }
        Error::Sqlite(e) => Error::Io(std::io::Error::other(format!("{}: {e}", path.display()))),
        other => other,
    }
}

/// Write a consistent, compacted copy of `<root>/server.db` to `dest`, which
/// must not exist, as workspaces' backups are written (`bd_core::store::snapshot`):
/// created 0600 first, `VACUUM INTO` in a read transaction, checked and
/// flushed; removed if anything failed.
pub fn snapshot(root: &Path, dest: &Path) -> Result<()> {
    let Some(conn) = open_existing(root)? else {
        return Err(Error::invalid(format!("{} does not exist", path(root).display())));
    };
    bd_core::store::snapshot(&conn, dest).map_err(|e| match e {
        Error::Sqlite(e) => failed(&path(root), e),
        other => other,
    })
}

/// Write a table's rows back after a change: `upsert` those of `after`
/// whose record (as JSON, given it) is not as in `before`, and `delete`
/// (by `key`) those it no longer has. Rows unchanged are not written.
pub fn sync_rows<T: serde::Serialize, K: Eq + std::hash::Hash>(
    before: &[T],
    after: &[T],
    key: impl Fn(&T) -> K,
    mut delete: impl FnMut(&K) -> Result<()>,
    mut upsert: impl FnMut(&T, &str) -> Result<()>,
) -> Result<()> {
    let was: std::collections::HashMap<K, String> =
        before.iter().map(|r| Ok((key(r), serde_json::to_string(r)?))).collect::<Result<_>>()?;
    let kept: std::collections::HashSet<K> = after.iter().map(&key).collect();
    for gone in was.keys().filter(|k| !kept.contains(*k)) {
        delete(gone)?;
    }
    for row in after {
        let data = serde_json::to_string(row)?;
        if was.get(&key(row)) != Some(&data) {
            upsert(row, &data)?;
        }
    }
    Ok(())
}

/// How long the audit trail keeps an event.
pub const EVENTS_KEPT: Duration = Duration::from_secs(90 * 24 * 3600);

/// A change of who may call the server, for its audit trail
/// (`auth_events`): what happened, to which account and token, and why.
/// Never a secret or an email: an actor, a provider's subject, names.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct AuthEvent {
    /// `signed_in`, `token_created`, `refreshed`, `revoked`, `forgotten`,
    /// `client_registered`, `linked`, `named`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The token's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The OAuth client's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Why, or how.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Record `event`, as of now, in the transaction of the change it is of.
pub fn record(tx: &rusqlite::Transaction, event: &AuthEvent) -> Result<()> {
    tx.execute(
        "INSERT INTO auth_events (at, kind, actor, actor_key, provider, issuer, subject, token, client, detail) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            Timestamp::now().millis(),
            event.kind,
            event.actor,
            event.actor.as_deref().map(key),
            event.provider,
            event.issuer,
            event.subject,
            event.token,
            event.client,
            event.detail
        ],
    )?;
    Ok(())
}

/// Delete the events older than [`EVENTS_KEPT`].
pub fn prune_events(tx: &rusqlite::Transaction) -> Result<()> {
    let kept = i64::try_from(EVENTS_KEPT.as_millis()).unwrap_or(i64::MAX);
    tx.execute("DELETE FROM auth_events WHERE at < ?1", [Timestamp::now().millis() - kept])?;
    Ok(())
}

/// Delete the events of the account with this issuer and subject (it is
/// being forgotten).
pub fn erase_events(tx: &rusqlite::Transaction, issuer: &str, subject: &str) -> Result<()> {
    tx.execute("DELETE FROM auth_events WHERE issuer = ?1 AND subject = ?2", [issuer, subject])?;
    Ok(())
}

/// An event as kept: when, and what.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct KeptEvent {
    pub at: Timestamp,
    #[serde(flatten)]
    pub event: AuthEvent,
}

/// The latest `limit` events since `since` (milliseconds), of `actor` or its sub-actors if given, of `kinds` if any,
/// oldest first.
pub fn events(root: &Path, since: i64, actor: Option<&str>, kinds: &[String], limit: usize) -> Result<Vec<KeptEvent>> {
    let Some(conn) = open_existing(root)? else { return Ok(Vec::new()) };
    let mut sql = String::from(
        "SELECT at, kind, actor, provider, issuer, subject, token, client, detail FROM auth_events WHERE at >= ?",
    );
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(since)];
    if let Some(actor) = actor {
        // The actor itself, and its sub-actors by key range ('0' follows '/').
        let key = key(actor);
        sql.push_str(" AND (actor_key = ? OR (actor_key > ? AND actor_key < ?))");
        let (low, high) = (format!("{key}/"), format!("{key}0"));
        args.push(Box::new(key));
        args.push(Box::new(low));
        args.push(Box::new(high));
    }
    if !kinds.is_empty() {
        sql.push_str(&format!(" AND kind IN ({})", vec!["?"; kinds.len()].join(", ")));
        args.extend(kinds.iter().map(|k| Box::new(k.clone()) as Box<dyn rusqlite::ToSql>));
    }
    // The latest `limit`, given oldest first.
    sql.push_str(" ORDER BY seq DESC LIMIT ?");
    args.push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
        let kind: String = r.get(1)?;
        let event = AuthEvent {
            kind: KINDS.iter().copied().find(|k| *k == kind).unwrap_or("other"),
            actor: r.get(2)?,
            provider: r.get(3)?,
            issuer: r.get(4)?,
            subject: r.get(5)?,
            token: r.get(6)?,
            client: r.get(7)?,
            detail: r.get(8)?,
        };
        Ok(KeptEvent { at: Timestamp::from_millis(r.get(0)?), event })
    })?;
    let mut out = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    out.reverse();
    Ok(out)
}

/// The kinds of [`AuthEvent`].
pub const KINDS: &[&str] =
    &["signed_in", "token_created", "refreshed", "revoked", "forgotten", "client_registered", "linked", "named"];

/// How actors and logins are compared: regardless of case.
pub fn key(name: &str) -> String {
    name.to_lowercase()
}

/// The keys an actor key is related to as itself or one of its ancestors
/// (`alice/ci` is related to `alice/ci` and `alice`), and the range of its
/// descendants' keys (`alice/ci/...`): together, every key related to it.
pub fn related_keys(key: &str) -> (Vec<String>, (String, String)) {
    let mut exact: Vec<String> = key.match_indices('/').map(|(i, _)| key[..i].to_string()).collect();
    exact.push(key.to_string());
    // Keys starting with `<key>/` sort after `<key>/` and before `<key>0` ('0' follows '/').
    (exact, (format!("{key}/"), format!("{key}0")))
}

/// The lookup columns of a token's record: its actor's key, its name, and
/// when it ended, in milliseconds: when it was revoked, or, for a sign-in's
/// token, when it expired and could no longer be refreshed either, whichever
/// came first.
pub fn token_keys(t: &Value) -> (String, String, Option<i64>) {
    let at = |v: &Value| v.as_str().and_then(|s| Timestamp::parse_rfc3339(s).ok()).map(|t| t.millis());
    let expired = match (t.get("identity").is_some_and(|i| !i.is_null()), at(&t["expires_at"])) {
        (true, Some(expires)) => Some(at(&t["refresh"]["until"]).map_or(expires, |until| until.max(expires))),
        _ => None,
    };
    let ended = match (at(&t["revoked_at"]), expired) {
        (Some(revoked), Some(expired)) => Some(revoked.min(expired)),
        (revoked, expired) => revoked.or(expired),
    };
    (key(t["actor"].as_str().unwrap_or_default()), t["name"].as_str().unwrap_or_default().to_string(), ended)
}

/// The lookup columns of an account's record: its actor's and its login's keys.
pub fn account_keys(a: &Value) -> (String, String) {
    (key(a["actor"].as_str().unwrap_or_default()), key(a["login"].as_str().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every lookup server.db's code prepares uses an index: none reads a
    /// whole table but those that read every row by design.
    #[test]
    fn lookups_use_their_indexes() {
        const INDEXED: &[&str] = &[
            "SELECT seq, data FROM tokens WHERE id = ?1",
            "SELECT data FROM tokens WHERE sha256 = ?1 ORDER BY seq",
            "SELECT data FROM tokens WHERE family = ?1 ORDER BY seq",
            "SELECT data FROM tokens WHERE name = ?1 ORDER BY seq",
            "SELECT seq, data FROM tokens WHERE actor_key = ?1",
            "SELECT seq, data FROM tokens WHERE actor_key > ?1 AND actor_key < ?2",
            "DELETE FROM tokens WHERE id = ?1",
            "DELETE FROM tokens WHERE ended_at <= ?1",
            "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2",
            "SELECT seq, data FROM accounts WHERE actor_key = ?1",
            "SELECT seq, data FROM accounts WHERE actor_key > ?1 AND actor_key < ?2",
            "SELECT seq, data FROM accounts WHERE login_key = ?1",
            "SELECT seq, data FROM accounts WHERE login_key > ?1 AND login_key < ?2",
            "DELETE FROM accounts WHERE issuer = ?1 AND subject = ?2",
            "SELECT data FROM oauth_clients WHERE client_id = ?1",
            "DELETE FROM oauth_clients WHERE client_id = ?1",
            "DELETE FROM auth_events WHERE at < ?1",
            "DELETE FROM auth_events WHERE issuer = ?1 AND subject = ?2",
            "SELECT at FROM auth_events WHERE at >= ?1 AND (actor_key = ?2 OR (actor_key > ?3 AND actor_key < ?4)) \
             ORDER BY seq DESC LIMIT ?5",
        ];
        let dir = tempfile::tempdir().unwrap();
        let conn = open(dir.path()).unwrap();
        for sql in INDEXED {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let n = stmt.parameter_count();
            let args: Vec<&dyn rusqlite::ToSql> = (0..n).map(|_| &"x" as &dyn rusqlite::ToSql).collect();
            let plan: Vec<String> =
                stmt.query_map(args.as_slice(), |r| r.get::<_, String>(3)).unwrap().map(Result::unwrap).collect();
            assert!(plan.iter().all(|step| !step.starts_with("SCAN")), "{sql}: {plan:?}");
            assert!(plan.iter().any(|step| step.starts_with("SEARCH")), "{sql}: {plan:?}");
        }
    }

    #[test]
    fn related_keys_are_ancestors_self_and_descendants() {
        let (exact, (low, high)) = related_keys("alice/ci");
        assert_eq!(exact, ["alice", "alice/ci"]);
        for descendant in ["alice/ci/a", "alice/ci/zz", "alice/ci/\u{e9}"] {
            assert!(descendant > low.as_str() && descendant < high.as_str(), "{descendant}");
        }
        for other in ["alice/ci", "alice/cia", "alice/ci-2", "alice/ci0", "alice/c", "bob"] {
            assert!(!(other > low.as_str() && other < high.as_str()), "{other}");
        }
    }

    #[test]
    fn reads_never_create_the_database_and_a_foreign_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_existing(dir.path()).unwrap().is_none());
        assert!(!path(dir.path()).exists());
        let conn = open(dir.path()).unwrap();
        assert!(open_existing(dir.path()).unwrap().is_some());
        conn.execute_batch("PRAGMA user_version = 9").unwrap();
        let e = open(dir.path()).unwrap_err().to_string();
        assert!(e.contains("server.db") && e.contains("schema 9"), "{e}");
    }

    #[test]
    fn tokens_end_when_they_expire_and_can_no_longer_be_refreshed() {
        let t = |v: Value| token_keys(&v).2;
        let (expires, until) = ("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z");
        let ms = |s: &str| Timestamp::parse_rfc3339(s).unwrap().millis();
        let id = serde_json::json!({ "login": "a" });
        assert_eq!(t(serde_json::json!({ "actor": "A", "expires_at": expires })), None, "an admin's");
        assert_eq!(t(serde_json::json!({ "identity": id, "expires_at": expires })), Some(ms(expires)));
        let refreshed = serde_json::json!({ "identity": id, "expires_at": expires, "refresh": { "until": until } });
        assert_eq!(t(refreshed.clone()), Some(ms(until)));
        let mut revoked = refreshed;
        revoked["revoked_at"] = "2025-12-01T00:00:00.000Z".into();
        assert_eq!(t(revoked.clone()), Some(ms("2025-12-01T00:00:00.000Z")), "revoked before it expired");
        revoked["revoked_at"] = "2026-03-01T00:00:00.000Z".into();
        assert_eq!(t(revoked), Some(ms(until)), "revoked after it could no longer be refreshed");
        let admin = serde_json::json!({ "actor": "A", "revoked_at": "2025-12-01T00:00:00Z" });
        assert_eq!(t(admin), Some(ms("2025-12-01T00:00:00Z")), "an admin's too");
        assert_eq!(token_keys(&serde_json::json!({ "actor": "GitHub:Alice", "name": "n" })).0, "github:alice");
    }
}
