//! Structured diagnostics on stderr via `tracing`.
//!
//! Filter with `BD_LOG` (EnvFilter syntax, default `warn`; `bd serve` adds
//! `bd::serve=info`, one line per request): `BD_LOG=bd=debug`
//! shows per-transaction lock/exec/commit timings; `bd::slow` warnings report
//! slow transactions and commands. Colors only on a terminal (and never with
//! `NO_COLOR`), so log files stay plain text. Logs never leave the machine.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;

use crate::cli::LogFormat;

pub fn init(format: LogFormat, default_filter: &str) {
    let filter = EnvFilter::try_from_env("BD_LOG").unwrap_or_else(|_| EnvFilter::new(default_filter));
    let ansi = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_ansi(ansi);
    let _ = match format {
        LogFormat::Json => builder.json().flatten_event(true).with_current_span(false).try_init(),
        LogFormat::Text => builder.compact().try_init(),
    };
}
