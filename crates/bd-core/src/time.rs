//! Timestamps (UTC milliseconds), clocks, and human duration/date parsing.

use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// A UTC instant with millisecond precision, stored as INTEGER in SQLite and
/// rendered as RFC 3339 (`2026-10-01T05:28:15.123Z`) in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub const fn from_millis(ms: i64) -> Self {
        Timestamp(ms)
    }

    pub const fn millis(self) -> i64 {
        self.0
    }

    pub fn now() -> Self {
        Timestamp(Utc::now().timestamp_millis())
    }

    pub fn plus(self, d: Duration) -> Self {
        Timestamp(self.0.saturating_add(duration_ms(d)))
    }

    pub fn minus(self, d: Duration) -> Self {
        Timestamp(self.0.saturating_sub(duration_ms(d)))
    }

    /// Signed distance `self - earlier` in milliseconds.
    pub fn since(self, earlier: Timestamp) -> i64 {
        self.0 - earlier.0
    }

    pub fn to_rfc3339(self) -> String {
        match DateTime::<Utc>::from_timestamp_millis(self.0) {
            Some(dt) => dt.to_rfc3339_opts(SecondsFormat::Millis, true),
            None => self.0.to_string(),
        }
    }

    pub fn parse_rfc3339(s: &str) -> Result<Self> {
        DateTime::parse_from_rfc3339(s.trim())
            .map(|dt| Timestamp(dt.with_timezone(&Utc).timestamp_millis()))
            .map_err(|e| Error::invalid(format!("invalid timestamp {s:?}: {e}")))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Millis(i64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Millis(ms) => Ok(Timestamp(ms)),
            Raw::Text(s) => Timestamp::parse_rfc3339(&s).map_err(serde::de::Error::custom),
        }
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0))
    }
}

impl FromSql for Timestamp {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        i64::column_result(v).map(Timestamp)
    }
}

pub(crate) fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// Source of "now". The engine reads the clock once per transaction, after
/// the write lock is acquired, so every row a transaction touches shares one
/// timestamp.
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A settable clock for deterministic tests (lease expiry without sleeping).
#[derive(Debug)]
pub struct ManualClock {
    ms: AtomicI64,
}

impl ManualClock {
    pub fn new(start: Timestamp) -> Self {
        ManualClock { ms: AtomicI64::new(start.0) }
    }

    pub fn set(&self, t: Timestamp) {
        self.ms.store(t.0, Ordering::SeqCst);
    }

    pub fn advance(&self, d: Duration) {
        self.ms.fetch_add(duration_ms(d), Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.ms.load(Ordering::SeqCst))
    }
}

/// Parse durations such as `250ms`, `30s`, `5m`, `1h30m`, `2d`, `1w`.
/// A bare number is seconds.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let s = input.trim();
    if s.is_empty() {
        return Err(Error::invalid("empty duration"));
    }
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let bad = || Error::invalid(format!("invalid duration {input:?} (examples: 90s, 5m, 1h30m, 2d)"));
    let mut total_ms: u128 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if digits == 0 {
            return Err(bad());
        }
        let n: u128 = rest[..digits].parse().map_err(|_| bad())?;
        rest = &rest[digits..];
        let unit_len = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
        let unit_ms: u128 = match &rest[..unit_len] {
            "ms" => 1,
            "s" | "sec" | "secs" => 1_000,
            "m" | "min" | "mins" => 60_000,
            "h" | "hr" | "hrs" => 3_600_000,
            "d" | "day" | "days" => 86_400_000,
            "w" | "wk" | "wks" => 604_800_000,
            _ => return Err(bad()),
        };
        rest = &rest[unit_len..];
        total_ms = total_ms.saturating_add(n.saturating_mul(unit_ms));
    }
    Ok(Duration::from_millis(u64::try_from(total_ms).unwrap_or(u64::MAX)))
}

/// Compact human rendering: `4m59s`, `2h`, `350ms`.
pub fn format_duration_ms(ms: i64) -> String {
    let neg = ms < 0;
    let mut ms = ms.unsigned_abs();
    if ms < 1_000 {
        return format!("{}{}ms", if neg { "-" } else { "" }, ms);
    }
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    for (unit, len) in [("d", 86_400_000u64), ("h", 3_600_000), ("m", 60_000), ("s", 1_000)] {
        if ms >= len {
            out.push_str(&format!("{}{}", ms / len, unit));
            ms %= len;
        }
    }
    out
}

/// Parse a point in time: RFC 3339, `YYYY-MM-DD` (local midnight),
/// `YYYY-MM-DD HH:MM` (local), relative `+2h` / `2d`, `now`, `tomorrow`.
pub fn parse_when(input: &str, now: Timestamp) -> Result<Timestamp> {
    let s = input.trim();
    match s {
        "now" => return Ok(now),
        "tomorrow" => {
            let local = DateTime::<Utc>::from_timestamp_millis(now.0)
                .ok_or_else(|| Error::invalid("clock out of range"))?
                .with_timezone(&Local);
            let date = local.date_naive().succ_opt().ok_or_else(|| Error::invalid("date overflow"))?;
            return local_midnight(date, input);
        }
        _ => {}
    }
    if let Some(rel) = s.strip_prefix('+') {
        return Ok(now.plus(parse_duration(rel)?));
    }
    if let Ok(ts) = Timestamp::parse_rfc3339(s) {
        return Ok(ts);
    }
    if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return local_midnight(date, input);
    }
    for fmt in ["%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return local_datetime(ndt, input);
        }
    }
    if let Ok(d) = parse_duration(s) {
        return Ok(now.plus(d));
    }
    Err(Error::invalid(format!(
        "invalid time {input:?} (examples: 2026-01-15, 2026-01-15T09:00:00Z, +2h, 3d, tomorrow)"
    )))
}

fn local_midnight(date: NaiveDate, input: &str) -> Result<Timestamp> {
    local_datetime(date.and_hms_opt(0, 0, 0).expect("midnight is valid"), input)
}

fn local_datetime(ndt: NaiveDateTime, input: &str) -> Result<Timestamp> {
    Local
        .from_local_datetime(&ndt)
        .earliest()
        .map(|dt| Timestamp(dt.with_timezone(&Utc).timestamp_millis()))
        .ok_or_else(|| Error::invalid(format!("time {input:?} does not exist in the local timezone")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("m").is_err());
        assert_eq!(format_duration_ms(299_000), "4m59s");
        assert_eq!(format_duration_ms(350), "350ms");
    }

    #[test]
    fn rfc3339_round_trip() {
        let t = Timestamp::parse_rfc3339("2026-10-01T05:28:15.123Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-01T05:28:15.123Z");
        let json = serde_json::to_string(&t).unwrap();
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
        let from_ms: Timestamp = serde_json::from_str("1000").unwrap();
        assert_eq!(from_ms, Timestamp(1000));
    }

    #[test]
    fn relative_times() {
        let now = Timestamp(1_000_000);
        assert_eq!(parse_when("+2h", now).unwrap(), Timestamp(1_000_000 + 7_200_000));
        assert_eq!(parse_when("3d", now).unwrap(), Timestamp(1_000_000 + 259_200_000));
        assert_eq!(parse_when("now", now).unwrap(), now);
        assert!(parse_when("whenever", now).is_err());
    }
}
