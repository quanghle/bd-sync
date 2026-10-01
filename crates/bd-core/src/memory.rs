//! Durable workspace memory: short insights that agents store once and get
//! back in every session (`bd prime`).

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;

use crate::error::{Error, Result};
use crate::filter::like_escape;
use crate::model::Memory;
use crate::store::WriteCtx;

const MAX_MEMORY_BYTES: usize = 64 * 1024;

/// Derive a key from content the way beads does: lowercase, non-alphanumeric
/// runs become `-`, first 8 words, at most 60 characters.
pub fn derive_key(content: &str) -> Result<String> {
    let lower = content.to_lowercase();
    let mut slug = String::new();
    let mut dash = false;
    for c in lower.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
    }
    let words: Vec<&str> = slug.trim_matches('-').split('-').filter(|w| !w.is_empty()).take(8).collect();
    let mut key = words.join("-");
    if key.len() > 60 {
        key.truncate(60);
        key = key.trim_end_matches('-').to_string();
    }
    if key.is_empty() {
        return Err(Error::invalid("could not derive a key from the content; pass an explicit key"));
    }
    Ok(key)
}

pub fn validate_key(key: &str) -> Result<String> {
    let k = key.trim();
    let ok = !k.is_empty()
        && k.len() <= 128
        && k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'));
    if ok {
        Ok(k.to_string())
    } else {
        Err(Error::invalid(format!("invalid memory key {key:?} (letters, digits, - _ . : /; max 128)")))
    }
}

const MEMORY_COLUMNS: &str = "key, content, created_at, updated_at, created_by, updated_by, revision";

fn memory_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Memory> {
    Ok(Memory {
        key: r.get(0)?,
        content: r.get(1)?,
        created_at: r.get(2)?,
        updated_at: r.get(3)?,
        created_by: r.get(4)?,
        updated_by: r.get(5)?,
        revision: r.get(6)?,
    })
}

pub fn get(conn: &Connection, key: &str) -> Result<Option<Memory>> {
    let sql = format!("SELECT {MEMORY_COLUMNS} FROM memories WHERE key = ?1");
    Ok(conn.prepare_cached(&sql)?.query_row([key], memory_from_row).optional()?)
}

/// All memories ordered by key, optionally filtered by a case-insensitive
/// substring of the key or content.
pub fn list(conn: &Connection, query: Option<&str>) -> Result<Vec<Memory>> {
    let q = query.map(str::trim).filter(|q| !q.is_empty());
    let sql = match q {
        Some(_) => format!(
            "SELECT {MEMORY_COLUMNS} FROM memories
             WHERE key LIKE ?1 ESCAPE '\\' OR content LIKE ?1 ESCAPE '\\' ORDER BY key"
        ),
        None => format!("SELECT {MEMORY_COLUMNS} FROM memories ORDER BY key"),
    };
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = match q {
        Some(q) => {
            stmt.query_map([format!("%{}%", like_escape(q))], memory_from_row)?.collect::<rusqlite::Result<Vec<_>>>()
        }
        None => stmt.query_map([], memory_from_row)?.collect::<rusqlite::Result<Vec<_>>>(),
    };
    Ok(rows?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAction {
    Created,
    Updated,
    Unchanged,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemoryWrite {
    pub memory: Memory,
    pub action: MemoryAction,
}

impl WriteCtx<'_> {
    /// Store (or overwrite) a memory. `key = None` derives one from the
    /// content. `if_revision = Some(0)` means "create only"; any other value
    /// must match the stored revision (compare-and-set).
    pub fn remember(&mut self, key: Option<&str>, content: &str, if_revision: Option<i64>) -> Result<MemoryWrite> {
        let content = content.trim();
        if content.is_empty() {
            return Err(Error::invalid("memory content must not be empty"));
        }
        if content.len() > MAX_MEMORY_BYTES {
            return Err(Error::invalid("memory content exceeds 64 KiB"));
        }
        let key = match key {
            Some(k) => validate_key(k)?,
            None => derive_key(content)?,
        };
        let existing = get(self.conn(), &key)?;
        if let Some(expected) = if_revision {
            let actual = existing.as_ref().map_or(0, |m| m.revision);
            if actual != expected {
                return Err(Error::Conflict {
                    id: format!("memory:{key}"),
                    field: "revision",
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
        }
        let action = match &existing {
            Some(m) if m.content == content => {
                return Ok(MemoryWrite { memory: m.clone(), action: MemoryAction::Unchanged });
            }
            Some(_) => MemoryAction::Updated,
            None => MemoryAction::Created,
        };
        self.conn()
            .prepare_cached(
                "INSERT INTO memories (key, content, created_at, updated_at, created_by, updated_by, revision)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?4, 1)
                 ON CONFLICT(key) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at,
                     updated_by = excluded.updated_by, revision = memories.revision + 1",
            )?
            .execute(params![key, content, self.now(), self.actor()])?;
        let memory = get(self.conn(), &key)?.ok_or_else(|| Error::not_found("memory", key.as_str()))?;
        self.emit(
            "memory_set",
            None,
            json!({
                "key": key,
                "content": content,
                "previous": existing.map(|m| m.content),
                "revision": memory.revision,
            }),
        )?;
        Ok(MemoryWrite { memory, action })
    }

    /// Delete a memory; returns it if it existed.
    pub fn forget(&mut self, key: &str) -> Result<Option<Memory>> {
        let Some(existing) = get(self.conn(), key)? else {
            return Ok(None);
        };
        self.conn().prepare_cached("DELETE FROM memories WHERE key = ?1")?.execute([key])?;
        self.emit("memory_deleted", None, json!({ "key": key, "content": existing.content }))?;
        Ok(Some(existing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_derive_like_beads() {
        assert_eq!(derive_key("Always run tests with -race flag").unwrap(), "always-run-tests-with-race-flag");
        assert_eq!(
            derive_key("one two three four five six seven eight nine ten").unwrap(),
            "one-two-three-four-five-six-seven-eight"
        );
        assert!(derive_key("!!!").is_err());
        let long = "abcdefghij".repeat(10);
        assert!(derive_key(&long).unwrap().len() <= 60);
    }

    #[test]
    fn explicit_keys_are_validated() {
        assert_eq!(validate_key(" auth-jwt ").unwrap(), "auth-jwt");
        assert!(validate_key("has space").is_err());
        assert!(validate_key("").is_err());
    }
}
