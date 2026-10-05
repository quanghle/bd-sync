//! `bd stats`, `bd metrics` and `bd doctor`.

use bd_core::doctor::{self, Severity};
use bd_core::metrics::{self, Metrics};
use bd_core::{Queries, Result};

use crate::app::{App, Out};
use crate::cli::*;
use crate::io;

pub fn cmd_stats(app: &mut App) -> Result<()> {
    let stats = app.read(|r| r.stats())?;
    let mut out = Out::new(&stats).line(format!("Issues: {} total", stats.total));
    for (s, n) in &stats.by_status {
        out = out.line(format!("  {:<12} {n}", s));
    }
    out = out
        .line(format!(
            "Ready: {}   Waiting on children: {}   Blocked: {}   Deferred: {}",
            stats.ready, stats.waiting_on_children, stats.blocked, stats.deferred
        ))
        .line(format!("Leases: {} active, {} expired", stats.leases_active, stats.leases_expired));
    if !stats.closable_epics.is_empty() {
        out = out.line(format!("Epics ready to close: {}", stats.closable_epics.join(", ")));
    }
    app.print(out);
    Ok(())
}

fn prom_line(o: &mut String, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
    if labels.is_empty() {
        o.push_str(&format!("{name} {value}\n"));
    } else {
        let l: Vec<String> =
            labels.iter().map(|(k, v)| format!("{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))).collect();
        o.push_str(&format!("{name}{{{}}} {value}\n", l.join(",")));
    }
}

fn prom_header(o: &mut String, name: &str, kind: &str, help: &str) {
    o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
}

pub fn prometheus(m: &Metrics) -> String {
    let mut o = String::new();
    prom_header(&mut o, "bd_issues", "gauge", "Issues by status");
    for (s, n) in &m.stats.by_status {
        prom_line(&mut o, "bd_issues", &[("status", s)], n);
    }
    prom_header(&mut o, "bd_ready_issues", "gauge", "Ready issues by priority");
    for (p, n) in &m.ready_by_priority {
        prom_line(&mut o, "bd_ready_issues", &[("priority", p)], n);
    }
    for (name, help, v) in [
        ("bd_blocked_issues", "Live issues held back by dependencies", m.stats.blocked),
        ("bd_waiting_issues", "Open issues held back by their open children", m.stats.waiting_on_children),
        ("bd_deferred_issues", "Live issues hidden by a deferral", m.stats.deferred),
        ("bd_leases_active", "Live claim leases", m.leases.active),
        ("bd_leases_expired", "Leases past expiry", m.leases.expired),
        ("bd_leases_expiring_soon", "Leases expiring within 60s", m.leases.expiring_soon),
        ("bd_leases_reclaimable", "Leases expired past the grace window", m.leases.reclaimable),
        ("bd_events_head_seq", "Highest event sequence number", m.events_head),
        ("bd_events_retained", "Events retained in the log", m.events_retained),
        ("bd_db_size_bytes", "Main database size", m.db.size_bytes),
    ] {
        prom_header(&mut o, name, "gauge", help);
        prom_line(&mut o, name, &[], v);
    }
    if let Some(age) = m.leases.oldest_heartbeat_age_ms {
        prom_header(&mut o, "bd_lease_oldest_heartbeat_age_seconds", "gauge", "Age of the stalest heartbeat");
        prom_line(&mut o, "bd_lease_oldest_heartbeat_age_seconds", &[], age as f64 / 1000.0);
    }
    if let Some(w) = m.db.wal_bytes {
        prom_header(&mut o, "bd_db_wal_bytes", "gauge", "WAL file size");
        prom_line(&mut o, "bd_db_wal_bytes", &[], w);
    }
    prom_header(&mut o, "bd_events_total", "counter", "Retained events by op");
    for (op, n) in &m.ops_total {
        prom_line(&mut o, "bd_events_total", &[("op", op)], n);
    }
    prom_header(&mut o, "bd_events_24h", "gauge", "Events by op in the last 24h");
    for (op, n) in &m.ops_24h {
        prom_line(&mut o, "bd_events_24h", &[("op", op)], n);
    }
    prom_header(&mut o, "bd_counter_total", "counter", "Durable counters (contention, reclaims, slow writes)");
    for (k, n) in &m.counters {
        prom_line(&mut o, "bd_counter_total", &[("name", k)], n);
    }
    for (name, help, p) in [
        ("bd_lead_time_seconds", "created -> closed, last 30 days", &m.lead_time),
        ("bd_cycle_time_seconds", "started -> closed, last 30 days", &m.cycle_time),
        ("bd_queue_wait_seconds", "created -> started, last 30 days", &m.queue_wait),
    ] {
        prom_header(&mut o, name, "summary", help);
        for (q, v) in [("0.5", p.p50_ms), ("0.9", p.p90_ms), ("0.99", p.p99_ms)] {
            if let Some(v) = v {
                prom_line(&mut o, name, &[("quantile", q)], v as f64 / 1000.0);
            }
        }
        prom_line(&mut o, &format!("{name}_count"), &[], p.count);
    }
    o
}

pub fn cmd_metrics(app: &mut App, a: &MetricsArgs) -> Result<()> {
    let path = app.db_path()?;
    let m = app.read(|r| metrics::metrics(r.conn(), r.now(), Some(&path)))?;
    if app.g.json || a.format == MetricsFormat::Json {
        app.print_json(&m);
    } else {
        io::out(prometheus(&m));
    }
    Ok(())
}

pub fn cmd_doctor(app: &mut App, a: &DoctorArgs) -> Result<i32> {
    io::require_admin("bd doctor")?;
    let report = doctor::diagnose(app.store()?, a.fix, a.full)?;
    if app.g.json {
        app.print_json(&report);
    } else {
        for c in &report.checks {
            let icon = match (c.severity, c.fixed) {
                (_, true) => "✓ fixed",
                (Severity::Ok, _) => "✓",
                (Severity::Warn, _) => "!",
                (Severity::Error, _) => "✗",
            };
            io::outln(format!("{icon} {:<20} {}", c.name, c.detail));
        }
        io::outln(if report.ok { "healthy" } else { "problems found (run `bd doctor --fix`)" });
    }
    Ok(if report.ok { 0 } else { 1 })
}
