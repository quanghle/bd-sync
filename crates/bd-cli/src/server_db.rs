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

/// How long a change waits for another one to finish.
const BUSY_WAIT: Duration = Duration::from_secs(10);

/// The schema this bd writes (`PRAGMA user_version`).
const VERSION: i64 = 1;

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
    conn.busy_timeout(BUSY_WAIT).map_err(|e| failed(path, e))?;
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
