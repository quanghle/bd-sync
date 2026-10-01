//! Idempotency records for writes that arrive over a network.
//!
//! A client that loses a response cannot tell whether its write happened, so
//! it retries with the same request id. [`WriteCtx::record_request`] stores
//! the id in the same transaction as the write: the write commits at most
//! once, and the response saved after it finished is replayed to retries.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::store::WriteCtx;
use crate::time::Timestamp;

/// Longest accepted request id.
pub const MAX_ID_LEN: usize = 128;

/// One recorded request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RequestRecord {
    pub id: String,
    /// Who sent it: a caller-defined principal, such as an access-token id.
    pub principal: String,
    pub actor: String,
    pub op: String,
    /// `tx` of the events the request's transaction appended, if any.
    pub tx: Option<i64>,
    pub created_at: Timestamp,
    /// The response stored once the request finished; opaque to the engine.
    pub response: Option<String>,
}

/// Request ids are 1 to [`MAX_ID_LEN`] ASCII letters, digits, `-` or `_`.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid request id {id:?}: use 1-{MAX_ID_LEN} letters, digits, '-' or '_'")))
    }
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<RequestRecord>> {
    Ok(conn
        .prepare_cached("SELECT id, principal, actor, op, tx, created_at, response FROM requests WHERE id = ?1")?
        .query_row([id], |r| {
            Ok(RequestRecord {
                id: r.get(0)?,
                principal: r.get(1)?,
                actor: r.get(2)?,
                op: r.get(3)?,
                tx: r.get(4)?,
                created_at: r.get(5)?,
                response: r.get(6)?,
            })
        })
        .optional()?)
}

impl WriteCtx<'_> {
    /// Record that this transaction carries out request `id` on behalf of
    /// `principal`. Fails with [`Error::Refused`] if the id is already
    /// recorded, which rolls the whole transaction back.
    pub fn record_request(&mut self, id: &str, principal: &str, op: &str) -> Result<()> {
        validate_id(id)?;
        let inserted = self
            .conn()
            .prepare_cached(
                "INSERT INTO requests (id, principal, actor, op, tx, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO NOTHING",
            )?
            .execute(params![id, principal, self.actor(), op, self.tx_seq(), self.now()])?;
        if inserted == 0 {
            return Err(Error::Refused(format!("request {id} was already applied")));
        }
        Ok(())
    }

    /// Store the response of a recorded request, for replay to retries.
    /// Returns false when `id` is not recorded.
    pub fn save_request_response(&mut self, id: &str, response: &str) -> Result<bool> {
        let n = self
            .conn()
            .prepare_cached("UPDATE requests SET response = ?2 WHERE id = ?1")?
            .execute(params![id, response])?;
        Ok(n > 0)
    }

    /// Delete up to `limit` records created before `before`, oldest first.
    pub fn prune_requests(&mut self, before: Timestamp, limit: usize) -> Result<usize> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        Ok(self
            .conn()
            .prepare_cached(
                "DELETE FROM requests WHERE rowid IN
                   (SELECT rowid FROM requests WHERE created_at < ?1 ORDER BY rowid LIMIT ?2)",
            )?
            .execute(params![before, limit])?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::IdMode;
    use crate::store::{InitOptions, OpenOptions, Store};
    use crate::{Clock, ManualClock, NewIssue};

    fn store(dir: &tempfile::TempDir, clock: std::sync::Arc<ManualClock>) -> Store {
        Store::init(
            &dir.path().join("bd.db"),
            InitOptions { prefix: "t".into(), id_mode: IdMode::Counter },
            OpenOptions { clock, ..Default::default() },
        )
        .unwrap()
    }

    #[test]
    fn a_request_id_commits_at_most_once() {
        let dir = tempfile::tempdir().unwrap();
        let clock = std::sync::Arc::new(ManualClock::new(Timestamp(1_000_000)));
        let mut s = store(&dir, clock.clone());
        let created = s
            .write("create", "alice", |tx| {
                let issue = tx.create_issue(NewIssue::titled("once"))?;
                tx.record_request("req-1", "tok-a", "create")?;
                Ok(issue)
            })
            .unwrap();
        let rec = s.read(|r| get(r.conn(), "req-1")).unwrap().unwrap();
        assert_eq!((rec.principal.as_str(), rec.actor.as_str(), rec.op.as_str()), ("tok-a", "alice", "create"));
        assert!(rec.tx.is_some(), "linked to the events of its transaction");
        assert_eq!(rec.response, None);

        let again = s.write("create", "alice", |tx| {
            tx.create_issue(NewIssue::titled("twice"))?;
            tx.record_request("req-1", "tok-a", "create")
        });
        assert!(matches!(again, Err(Error::Refused(_))), "{again:?}");
        let titles: Vec<String> =
            s.read(|r| crate::Queries::list(r, &Default::default())).unwrap().into_iter().map(|i| i.title).collect();
        assert_eq!(titles, vec![created.title], "the duplicate rolled back entirely");

        assert!(s.write("respond", "alice", |tx| tx.save_request_response("req-1", "{\"exit_code\":0}")).unwrap());
        assert!(!s.write("respond", "alice", |tx| tx.save_request_response("nope", "{}")).unwrap());
        let rec = s.read(|r| get(r.conn(), "req-1")).unwrap().unwrap();
        assert_eq!(rec.response.as_deref(), Some("{\"exit_code\":0}"));

        clock.advance(Duration::from_secs(60));
        s.write("record", "alice", |tx| tx.record_request("req-2", "tok-a", "update")).unwrap();
        let cutoff = clock.now().minus(Duration::from_secs(30));
        assert_eq!(s.write("prune", "bd", |tx| tx.prune_requests(cutoff, 100)).unwrap(), 1);
        assert!(s.read(|r| get(r.conn(), "req-1")).unwrap().is_none());
        assert!(s.read(|r| get(r.conn(), "req-2")).unwrap().is_some());
    }

    #[test]
    fn request_ids_are_validated() {
        for ok in ["a", "0f9e-AB_c", &"x".repeat(MAX_ID_LEN)] {
            assert!(validate_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "has space", "slash/no", "ü", &"x".repeat(MAX_ID_LEN + 1)] {
            assert!(validate_id(bad).is_err(), "{bad}");
        }
    }
}
