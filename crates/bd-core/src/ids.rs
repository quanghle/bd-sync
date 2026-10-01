//! Issue id allocation.
//!
//! Hash ids follow beads: `prefix-` + base36(sha256(title|description|creator|
//! nanos|nonce)), with the length chosen so the birthday-collision probability
//! across the workspace stays <= 25% (3..=8 chars). Collisions are resolved by
//! probing nonces, then longer lengths, under the write lock.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::config::{self, IdMode};
use crate::error::{Error, Result};

const MIN_LEN: usize = 3;
const MAX_LEN: usize = 8;
const MAX_COLLISION_PROB: f64 = 0.25;

pub(crate) fn adaptive_length(existing: i64) -> usize {
    let n = existing.max(0) as f64;
    for len in MIN_LEN..=MAX_LEN {
        let space = 36f64.powi(len as i32);
        let prob = 1.0 - (-(n * n) / (2.0 * space)).exp();
        if prob <= MAX_COLLISION_PROB {
            return len;
        }
    }
    MAX_LEN
}

fn hash_bytes_for(len: usize) -> usize {
    match len {
        3 => 2,
        4 => 3,
        5 | 6 => 4,
        _ => 5,
    }
}

pub(crate) fn base36(bytes: &[u8], len: usize) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut n: u64 = 0;
    for b in bytes {
        n = (n << 8) | u64::from(*b);
    }
    let mut digits = Vec::with_capacity(len);
    loop {
        digits.push(ALPHABET[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    while digits.len() < len {
        digits.push(b'0');
    }
    digits.truncate(len);
    digits.reverse();
    String::from_utf8(digits).expect("base36 alphabet is ASCII")
}

pub(crate) fn hash_id(
    prefix: &str,
    title: &str,
    description: &str,
    creator: &str,
    nanos: u128,
    nonce: u32,
    len: usize,
) -> String {
    let content = format!("{title}|{description}|{creator}|{nanos}|{nonce}");
    let digest = Sha256::digest(content.as_bytes());
    format!("{prefix}-{}", base36(&digest[..hash_bytes_for(len)], len))
}

pub(crate) fn exists(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn.prepare_cached("SELECT 1 FROM issues WHERE id = ?1")?.exists([id])?)
}

/// Allocate a fresh top-level id.
pub(crate) fn next_issue_id(conn: &Connection, title: &str, description: &str, creator: &str) -> Result<String> {
    let prefix = config::prefix(conn)?;
    match config::id_mode(conn)? {
        IdMode::Counter => loop {
            let n: i64 = conn
                .prepare_cached(
                    "INSERT INTO counters (name, value) VALUES ('issue_seq', 1)
                     ON CONFLICT(name) DO UPDATE SET value = value + 1 RETURNING value",
                )?
                .query_row([], |r| r.get(0))?;
            let id = format!("{prefix}-{n}");
            if !exists(conn, &id)? {
                return Ok(id);
            }
        },
        IdMode::Hash => {
            // MAX(rowid) is O(1) and never undercounts the issues ever created,
            // so it is a safe (slightly conservative) population estimate.
            let population: i64 =
                conn.prepare_cached("SELECT COALESCE(MAX(rowid), 0) FROM issues")?.query_row([], |r| r.get(0))?;
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            for len in adaptive_length(population + 1)..=MAX_LEN {
                for nonce in 0..10 {
                    let id = hash_id(&prefix, title, description, creator, nanos, nonce, len);
                    if !exists(conn, &id)? {
                        return Ok(id);
                    }
                }
            }
            Err(Error::invalid("could not allocate a unique issue id"))
        }
    }
}

/// Allocate `parent.N`, the next hierarchical child id.
pub(crate) fn next_child_id(conn: &Connection, parent: &str) -> Result<String> {
    let last: i64 = conn
        .prepare_cached("SELECT last_child FROM child_counters WHERE parent_id = ?1")?
        .query_row([parent], |r| r.get(0))
        .optional()?
        .unwrap_or(0);
    let mut max_existing = 0i64;
    let mut stmt = conn
        .prepare_cached("SELECT issue_id FROM dependencies WHERE depends_on_id = ?1 AND dep_type = 'parent-child'")?;
    let children = stmt.query_map([parent], |r| r.get::<_, String>(0))?;
    for child in children {
        let child = child?;
        if let Some(n) =
            child.strip_prefix(parent).and_then(|s| s.strip_prefix('.')).and_then(|s| s.parse::<i64>().ok())
        {
            max_existing = max_existing.max(n);
        }
    }
    let mut n = last.max(max_existing) + 1;
    while exists(conn, &format!("{parent}.{n}"))? {
        n += 1;
    }
    conn.prepare_cached(
        "INSERT INTO child_counters (parent_id, last_child) VALUES (?1, ?2)
         ON CONFLICT(parent_id) DO UPDATE SET last_child = excluded.last_child",
    )?
    .execute(params![parent, n])?;
    Ok(format!("{parent}.{n}"))
}

pub(crate) fn validate_explicit_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 255
        && id.starts_with(|c: char| c.is_ascii_alphanumeric())
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok { Ok(()) } else { Err(Error::invalid(format!("invalid issue id {id:?} (letters, digits, '-', '_', '.')"))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_lengths_grow_with_population() {
        assert_eq!(adaptive_length(0), 3);
        assert_eq!(adaptive_length(100), 3);
        assert_eq!(adaptive_length(300), 4);
        assert!(adaptive_length(10_000_000) >= 7);
    }

    #[test]
    fn base36_pads_and_truncates() {
        assert_eq!(base36(&[0, 0], 3), "000");
        assert_eq!(base36(&[0, 35], 3), "00z");
        assert_eq!(base36(&[0xff, 0xff], 3).len(), 3);
        assert_eq!(base36(&[1, 2, 3, 4, 5], 8).len(), 8);
    }

    #[test]
    fn hash_ids_are_stable() {
        let a = hash_id("bd", "t", "d", "alice", 42, 0, 4);
        let b = hash_id("bd", "t", "d", "alice", 42, 0, 4);
        let c = hash_id("bd", "t", "d", "alice", 42, 1, 4);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("bd-") && a.len() == 7);
    }
}
