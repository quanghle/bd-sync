//! Workspace configuration stored in the `config` table.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;

use crate::error::{Error, Result};
use crate::store::{Durability, WriteCtx};
use crate::time::parse_duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IdMode {
    /// `prefix-<base36 hash>`, adaptive length; collision-resistant across workspaces.
    #[default]
    Hash,
    /// `prefix-<n>`, sequential.
    Counter,
}

impl IdMode {
    pub fn as_str(self) -> &'static str {
        match self {
            IdMode::Hash => "hash",
            IdMode::Counter => "counter",
        }
    }

    pub fn parse(s: &str) -> Result<IdMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hash" => Ok(IdMode::Hash),
            "counter" | "sequential" => Ok(IdMode::Counter),
            other => Err(Error::invalid(format!("invalid id mode {other:?} (valid: hash, counter)"))),
        }
    }
}

/// Known keys: (key, default, description).
pub const KNOWN: &[(&str, &str, &str)] = &[
    ("issue_prefix", "bd", "Prefix for new issue ids"),
    ("id.mode", "hash", "Id scheme: hash | counter"),
    ("lease.ttl", "5m", "Claim lease duration; heartbeat faster than this"),
    ("lease.grace", "10m", "How long past expiry a lease must be before reclaim reverts it"),
    ("lease.auto_reclaim", "true", "claim --next reclaims stale leases (past grace) first"),
    ("claim.pools", "", "Comma-separated pool assignees anyone may claim from"),
    ("types.custom", "", "Comma-separated extra issue types"),
    ("durability", "normal", "SQLite synchronous level: off | normal | full"),
    ("events.retain_days", "0", "Prune events older than N days after writes (0 = keep)"),
    ("events.retain_rows", "0", "Keep at most N events (0 = keep all)"),
];

#[derive(Clone, Debug, Serialize)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
    pub default: Option<String>,
    pub is_default: bool,
    pub description: String,
}

pub fn default_for(key: &str) -> Option<&'static str> {
    KNOWN.iter().find(|(k, _, _)| *k == key).map(|(_, d, _)| *d)
}

pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn.prepare_cached("SELECT value FROM config WHERE key = ?1")?.query_row([key], |r| r.get(0)).optional()?)
}

pub fn get_or_default(conn: &Connection, key: &str) -> Result<String> {
    match get(conn, key)? {
        Some(v) => Ok(v),
        None => default_for(key).map(str::to_string).ok_or_else(|| Error::not_found("config key", key)),
    }
}

/// Validate and store a config value; records a `config_set` event.
pub fn set(ctx: &mut WriteCtx<'_>, key: &str, value: &str) -> Result<()> {
    let value = validate(key, value)?;
    let previous = get(ctx.conn(), key)?;
    if previous.as_deref() == Some(value.as_str()) {
        return Ok(());
    }
    ctx.conn()
        .prepare_cached(
            "INSERT INTO config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )?
        .execute(params![key, value])?;
    ctx.emit("config_set", None, json!({ "key": key, "value": value, "previous": previous }))?;
    Ok(())
}

pub fn unset(ctx: &mut WriteCtx<'_>, key: &str) -> Result<bool> {
    if key == "issue_prefix" {
        return Err(Error::invalid("issue_prefix cannot be unset"));
    }
    let previous = get(ctx.conn(), key)?;
    let removed = ctx.conn().execute("DELETE FROM config WHERE key = ?1", [key])? > 0;
    if removed {
        ctx.emit("config_unset", None, json!({ "key": key, "previous": previous }))?;
    }
    Ok(removed)
}

pub fn list(conn: &Connection) -> Result<Vec<ConfigEntry>> {
    let mut stored: Vec<(String, String)> = conn
        .prepare_cached("SELECT key, value FROM config ORDER BY key")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out = Vec::new();
    for (key, default, description) in KNOWN {
        let value = match stored.iter().position(|(k, _)| k == key) {
            Some(i) => stored.remove(i).1,
            None => default.to_string(),
        };
        out.push(ConfigEntry {
            key: key.to_string(),
            is_default: value == *default,
            value,
            default: Some(default.to_string()),
            description: description.to_string(),
        });
    }
    for (key, value) in stored {
        out.push(ConfigEntry { key, value, default: None, is_default: false, description: String::new() });
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

fn validate(key: &str, value: &str) -> Result<String> {
    let v = value.trim();
    match key {
        "issue_prefix" => {
            let p = v.trim_end_matches('-').to_ascii_lowercase();
            validate_prefix(&p)?;
            Ok(p)
        }
        "id.mode" => Ok(IdMode::parse(v)?.as_str().to_string()),
        "lease.ttl" | "lease.grace" => {
            let d = parse_duration(v)?;
            if key == "lease.ttl" && d < Duration::from_secs(1) {
                return Err(Error::invalid("lease.ttl must be at least 1s"));
            }
            Ok(v.to_string())
        }
        "lease.auto_reclaim" => Ok(parse_bool(v)?.to_string()),
        "claim.pools" | "types.custom" => Ok(split_list(v).join(",")),
        "durability" => {
            Durability::parse(v)?;
            Ok(v.to_ascii_lowercase())
        }
        "events.retain_days" | "events.retain_rows" => {
            v.parse::<u64>().map_err(|_| Error::invalid(format!("{key} must be a non-negative integer")))?;
            Ok(v.to_string())
        }
        k if k.starts_with("custom.") && k.len() > "custom.".len() => Ok(value.to_string()),
        other => Err(Error::invalid(format!(
            "unknown config key {other:?} (known: {}; free-form keys must start with custom.)",
            KNOWN.iter().map(|(k, _, _)| *k).collect::<Vec<_>>().join(", ")
        ))),
    }
}

pub fn validate_prefix(prefix: &str) -> Result<()> {
    let ok = !prefix.is_empty()
        && prefix.len() <= 32
        && prefix.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && prefix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid issue prefix {prefix:?} (lowercase letters, digits and '-', max 32)")))
    }
}

pub fn parse_bool(v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(Error::invalid(format!("invalid boolean {other:?}"))),
    }
}

pub fn split_list(v: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !out.iter().any(|x| x == item) {
            out.push(item.to_string());
        }
    }
    out
}

pub fn prefix(conn: &Connection) -> Result<String> {
    get_or_default(conn, "issue_prefix")
}

pub fn id_mode(conn: &Connection) -> Result<IdMode> {
    IdMode::parse(&get_or_default(conn, "id.mode")?)
}

pub fn lease_ttl(conn: &Connection) -> Result<Duration> {
    parse_duration(&get_or_default(conn, "lease.ttl")?)
}

pub fn lease_grace(conn: &Connection) -> Result<Duration> {
    parse_duration(&get_or_default(conn, "lease.grace")?)
}

pub fn auto_reclaim(conn: &Connection) -> Result<bool> {
    parse_bool(&get_or_default(conn, "lease.auto_reclaim")?)
}

pub fn claim_pools(conn: &Connection) -> Result<Vec<String>> {
    Ok(split_list(&get_or_default(conn, "claim.pools")?))
}

pub fn custom_types(conn: &Connection) -> Result<Vec<String>> {
    Ok(split_list(&get_or_default(conn, "types.custom")?))
}

pub fn retain_days(conn: &Connection) -> Result<u64> {
    Ok(get_or_default(conn, "events.retain_days")?.parse().unwrap_or(0))
}

pub fn retain_rows(conn: &Connection) -> Result<u64> {
    Ok(get_or_default(conn, "events.retain_rows")?.parse().unwrap_or(0))
}
