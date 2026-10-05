//! `bd serve`'s counters since it started, served at `GET /metrics` in the
//! Prometheus text format to admin tokens: answers by status class and the
//! busy ones, requests refused for their access token, connections refused
//! over the limits, panics, commands and MCP tool calls. Counts only: no
//! actor, token, workspace or address is a label, so nothing here names
//! anyone. And [`Throttle`], which keeps a warning repeated under load from
//! flooding the log.

use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Counter {
        Counter(AtomicU64::new(0))
    }

    pub fn add(&self) {
        self.0.fetch_add(1, Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// Answers by status class: 1xx to 5xx.
static RESPONSES: [Counter; 5] = [Counter::new(), Counter::new(), Counter::new(), Counter::new(), Counter::new()];
/// 503 answers: busy, or shutting down.
pub static BUSY: Counter = Counter::new();
pub static REFUSED_UNKNOWN_TOKEN: Counter = Counter::new();
pub static REFUSED_EXPIRED_TOKEN: Counter = Counter::new();
/// Known tokens asking what they may not: another workspace, endpoint or actor, a write with a read token.
pub static REFUSED_FORBIDDEN: Counter = Counter::new();
pub static CONNECTIONS: Counter = Counter::new();
pub static CONNECTIONS_REFUSED_PEER: Counter = Counter::new();
pub static CONNECTIONS_REFUSED_TOTAL: Counter = Counter::new();
pub static PANICS: Counter = Counter::new();
pub static COMMANDS: Counter = Counter::new();
pub static TOOL_CALLS: Counter = Counter::new();
/// Connections open now.
pub static OPEN: AtomicI64 = AtomicI64::new(0);

static STARTED: OnceLock<(Instant, u64)> = OnceLock::new();

/// Note when the server started (once).
pub fn start() {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    STARTED.get_or_init(|| (Instant::now(), since_epoch));
}

/// Count an answer of `status`.
pub fn answered(status: u16) {
    if let Some(c) = RESPONSES.get(usize::from(status / 100).wrapping_sub(1)) {
        c.add();
    }
    if status == 503 {
        BUSY.add();
    }
}

/// A connection open while this lives.
pub struct Open(());

impl Open {
    pub fn counted() -> Open {
        CONNECTIONS.add();
        OPEN.fetch_add(1, Relaxed);
        Open(())
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Relaxed);
    }
}

/// The counters in the Prometheus text exposition format.
pub fn render() -> String {
    let mut out = String::new();
    let mut counter = |name: &str, help: &str, values: &[(&str, u64)]| {
        let _ = writeln!(out, "# HELP bd_serve_{name} {help}\n# TYPE bd_serve_{name} counter");
        for (labels, v) in values {
            let _ = writeln!(out, "bd_serve_{name}{labels} {v}");
        }
    };
    let classes: Vec<(String, u64)> =
        RESPONSES.iter().enumerate().map(|(i, c)| (format!("{{class=\"{}xx\"}}", i + 1), c.get())).collect();
    let classes: Vec<(&str, u64)> = classes.iter().map(|(l, v)| (l.as_str(), *v)).collect();
    counter("responses_total", "HTTP answers, by status class.", &classes);
    counter("busy_total", "Answers 503: busy or shutting down; clients retry them.", &[("", BUSY.get())]);
    counter(
        "refused_total",
        "Requests refused for their access token.",
        &[
            ("{reason=\"unknown_token\"}", REFUSED_UNKNOWN_TOKEN.get()),
            ("{reason=\"expired_token\"}", REFUSED_EXPIRED_TOKEN.get()),
            ("{reason=\"forbidden\"}", REFUSED_FORBIDDEN.get()),
        ],
    );
    counter("connections_total", "Connections accepted.", &[("", CONNECTIONS.get())]);
    counter(
        "connections_refused_total",
        "Connections closed at once over a limit.",
        &[("{limit=\"peer\"}", CONNECTIONS_REFUSED_PEER.get()), ("{limit=\"total\"}", CONNECTIONS_REFUSED_TOTAL.get())],
    );
    counter("panics_total", "Commands, tool calls and jobs that panicked.", &[("", PANICS.get())]);
    counter("commands_total", "Command lines run through /v2/exec.", &[("", COMMANDS.get())]);
    counter("tool_calls_total", "MCP tool calls run.", &[("", TOOL_CALLS.get())]);
    let _ = writeln!(
        out,
        "# HELP bd_serve_connections_open Connections open now.\n# TYPE bd_serve_connections_open gauge\n\
         bd_serve_connections_open {}",
        OPEN.load(Relaxed)
    );
    let started = STARTED.get().map_or(0, |s| s.1);
    let _ = writeln!(
        out,
        "# HELP bd_serve_start_time_seconds When the server started, in seconds since the Unix epoch.\n\
         # TYPE bd_serve_start_time_seconds gauge\nbd_serve_start_time_seconds {started}"
    );
    out
}

/// A warning logged at most once per `every`: [`Throttle::pass`] says
/// whether to log now, with how many were left out since the last.
pub struct Throttle {
    every_ms: u64,
    /// Milliseconds since the server started at the last warning, plus one (0: never).
    last: AtomicU64,
    skipped: AtomicU64,
}

impl Throttle {
    pub const fn new(every_ms: u64) -> Throttle {
        Throttle { every_ms, last: AtomicU64::new(0), skipped: AtomicU64::new(0) }
    }

    /// `Some(left out since the last)` when this one is to be logged.
    pub fn pass(&self) -> Option<u64> {
        let base = STARTED.get_or_init(|| (Instant::now(), 0)).0;
        self.pass_at(u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX).saturating_add(1))
    }

    fn pass_at(&self, now: u64) -> Option<u64> {
        let last = self.last.load(Relaxed);
        let due = last == 0 || now.saturating_sub(last) >= self.every_ms;
        if due && self.last.compare_exchange(last, now, Relaxed, Relaxed).is_ok() {
            Some(self.skipped.swap(0, Relaxed))
        } else {
            self.skipped.fetch_add(1, Relaxed);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_throttle_passes_once_per_period_and_counts_the_rest() {
        let t = Throttle::new(60_000);
        assert_eq!(t.pass_at(1), Some(0));
        assert_eq!(t.pass_at(2), None);
        assert_eq!(t.pass_at(59_000), None);
        assert_eq!(t.pass_at(60_001), Some(2));
        assert_eq!(t.pass_at(60_002), None);
    }

    #[test]
    fn counters_render_as_prometheus_text() {
        answered(503);
        answered(204);
        let text = render();
        assert!(text.contains("# TYPE bd_serve_responses_total counter"), "{text}");
        assert!(text.contains("bd_serve_responses_total{class=\"5xx\"} "), "{text}");
        assert!(text.contains("bd_serve_refused_total{reason=\"unknown_token\"} "), "{text}");
        assert!(text.lines().all(|l| l.starts_with('#') || l.split(' ').count() == 2), "{text}");
        assert!(BUSY.get() >= 1);
    }
}
