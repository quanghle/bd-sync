//! Issue comments: an append-only discussion thread per issue.

use rusqlite::{Connection, params};
use serde_json::json;

use crate::error::{Error, Result};
use crate::ids;
use crate::model::Comment;
use crate::store::WriteCtx;

const MAX_COMMENT_BYTES: usize = 1 << 20;

pub fn list(conn: &Connection, issue_id: &str) -> Result<Vec<Comment>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, issue_id, author, text, created_at FROM comments WHERE issue_id = ?1 ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([issue_id], |r| {
        Ok(Comment { id: r.get(0)?, issue_id: r.get(1)?, author: r.get(2)?, text: r.get(3)?, created_at: r.get(4)? })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn count(conn: &Connection, issue_id: &str) -> Result<i64> {
    Ok(conn.prepare_cached("SELECT COUNT(*) FROM comments WHERE issue_id = ?1")?.query_row([issue_id], |r| r.get(0))?)
}

impl WriteCtx<'_> {
    /// Append a comment authored by the transaction's actor.
    pub fn add_comment(&mut self, issue_id: &str, text: &str) -> Result<Comment> {
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Err(Error::invalid("comment text must not be empty"));
        }
        if text.len() > MAX_COMMENT_BYTES {
            return Err(Error::invalid("comment exceeds 1 MiB"));
        }
        if !ids::exists(self.conn(), issue_id)? {
            return Err(Error::not_found("issue", issue_id));
        }
        self.conn()
            .prepare_cached("INSERT INTO comments (issue_id, author, text, created_at) VALUES (?1, ?2, ?3, ?4)")?
            .execute(params![issue_id, self.actor(), text, self.now()])?;
        let id = self.conn().last_insert_rowid();
        self.emit("commented", Some(issue_id), json!({ "comment_id": id, "text": text }))?;
        Ok(Comment {
            id,
            issue_id: issue_id.to_string(),
            author: self.actor().to_string(),
            text: text.to_string(),
            created_at: self.now(),
        })
    }
}
