//! SQLite schema and forward-only migrations, versioned by `PRAGMA user_version`.

use rusqlite::Connection;

use crate::error::{Error, Result};

pub const LATEST_VERSION: i64 = 3;

const V1: &str = r#"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE issues (
    id                  TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    design              TEXT NOT NULL DEFAULT '',
    acceptance_criteria TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'open',
    priority            INTEGER NOT NULL DEFAULT 2,
    issue_type          TEXT NOT NULL DEFAULT 'task',
    assignee            TEXT,
    created_by          TEXT NOT NULL DEFAULT '',
    external_ref        TEXT,
    estimated_minutes   INTEGER,
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    started_at          INTEGER,
    closed_at           INTEGER,
    close_reason        TEXT,
    close_outcome       TEXT,
    due_at              INTEGER,
    defer_until         INTEGER,
    is_blocked          INTEGER NOT NULL DEFAULT 0,
    revision            INTEGER NOT NULL DEFAULT 1,
    CHECK (status IN ('open','in_progress','blocked','deferred','closed','pinned')),
    CHECK (priority BETWEEN 0 AND 4),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK (status <> 'in_progress' OR assignee IS NOT NULL),
    CHECK (close_outcome IS NULL OR close_outcome IN ('done','failed')),
    CHECK (is_blocked IN (0, 1)),
    CHECK (json_valid(metadata))
);
-- Ready queue: equality on (status, is_blocked) then the priority policy order.
-- Indexes are kept minimal: every index is extra pages written per claim/close.
CREATE INDEX idx_issues_ready    ON issues(status, is_blocked, priority, created_at, id);
CREATE INDEX idx_issues_assignee ON issues(assignee, status) WHERE assignee IS NOT NULL;
CREATE INDEX idx_issues_deferral ON issues(defer_until) WHERE defer_until IS NOT NULL;
CREATE INDEX idx_issues_blocked  ON issues(priority, created_at) WHERE is_blocked = 1;

CREATE TABLE dependencies (
    issue_id      TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    depends_on_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    dep_type      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',
    metadata      TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (issue_id, depends_on_id),
    CHECK (issue_id <> depends_on_id),
    CHECK (json_valid(metadata))
) WITHOUT ROWID;
CREATE INDEX idx_deps_target ON dependencies(depends_on_id, dep_type, issue_id);
CREATE INDEX idx_deps_source ON dependencies(issue_id, dep_type, depends_on_id);

CREATE TABLE labels (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label    TEXT NOT NULL,
    PRIMARY KEY (issue_id, label)
) WITHOUT ROWID;
CREATE INDEX idx_labels_label ON labels(label, issue_id);

CREATE TABLE comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id   TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    author     TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_comments_issue ON comments(issue_id, created_at, id);

-- One row per live claim. Invariant: a lease exists iff its issue is
-- in_progress, and holder = issues.assignee.
CREATE TABLE leases (
    issue_id     TEXT PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    holder       TEXT NOT NULL,
    token        INTEGER NOT NULL,
    granted_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    heartbeat_at INTEGER NOT NULL,
    renewals     INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX idx_leases_expires ON leases(expires_at);

CREATE TABLE memories (
    key        TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    revision   INTEGER NOT NULL DEFAULT 1
) WITHOUT ROWID;

-- Transactional event history. AUTOINCREMENT never reuses a seq (even after
-- pruning), and because writers are serialized by BEGIN IMMEDIATE, seq order
-- equals commit order and a rolled-back transaction burns no seq.
CREATE TABLE events (
    seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    tx       INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    actor    TEXT NOT NULL,
    op       TEXT NOT NULL,
    issue_id TEXT,
    data     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_issue ON events(issue_id, seq) WHERE issue_id IS NOT NULL;
CREATE INDEX idx_events_ts    ON events(ts);

CREATE TABLE child_counters (
    parent_id  TEXT PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    last_child INTEGER NOT NULL
) WITHOUT ROWID;

-- Durable counters: sequential ids and observability totals.
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;
"#;

// v2: ephemeral issues (scratch work such as ephemeral playbook runs): kept
// out of exports and deleted by `purge` once closed. No index: purge scans.
const V2: &str = r#"
ALTER TABLE issues ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0 CHECK (ephemeral IN (0, 1));
"#;

// v3: idempotency records for writes sent through `bd serve`: a retried
// request finds its id here and gets the stored response instead of running
// again. Pruned oldest first in rowid order, so no index beyond the key.
const V3: &str = r#"
CREATE TABLE requests (
    id         TEXT PRIMARY KEY,
    principal  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    op         TEXT NOT NULL,
    tx         INTEGER,
    created_at INTEGER NOT NULL,
    response   TEXT
);
"#;

const MIGRATIONS: &[(i64, &str)] = &[(1, V1), (2, V2), (3, V3)];

pub fn user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

/// Apply every migration above the database's current version, atomically.
pub fn migrate(conn: &mut Connection) -> Result<i64> {
    let current = user_version(conn)?;
    if current > LATEST_VERSION {
        return Err(Error::SchemaTooNew { found: current, supported: LATEST_VERSION });
    }
    if current == LATEST_VERSION {
        return Ok(current);
    }
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Re-read under the write lock: another process may have migrated first.
    let current = user_version(&tx)?;
    for (version, sql) in MIGRATIONS {
        if *version > current {
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", version)?;
        }
    }
    tx.commit()?;
    Ok(LATEST_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_databases_migrate_to_ephemeral_column() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute("INSERT INTO issues (id, title, created_at, updated_at) VALUES ('t-1', 'old', 0, 0)", []).unwrap();
        assert_eq!(migrate(&mut conn).unwrap(), LATEST_VERSION);
        let eph: i64 = conn.query_row("SELECT ephemeral FROM issues WHERE id = 't-1'", [], |r| r.get(0)).unwrap();
        assert_eq!(eph, 0);
        assert!(conn.execute("UPDATE issues SET ephemeral = 2 WHERE id = 't-1'", []).is_err(), "0/1 only");
    }

    #[test]
    fn v2_databases_gain_the_requests_table() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V1).unwrap();
        conn.execute_batch(V2).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        assert_eq!(migrate(&mut conn).unwrap(), LATEST_VERSION);
        conn.execute(
            "INSERT INTO requests (id, principal, actor, op, created_at) VALUES ('r1', 'p', 'a', 'create', 0)",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO requests (id, principal, actor, op, created_at) VALUES ('r1', 'p', 'a', 'x', 0)",
                []
            )
            .is_err(),
            "request ids are unique"
        );
    }
}
