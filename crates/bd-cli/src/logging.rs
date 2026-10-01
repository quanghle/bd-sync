//! Structured diagnostics on stderr via `tracing`.
//!
//! Filter with `BD_LOG` (EnvFilter syntax, default `warn`): `BD_LOG=bd=debug`
//! shows per-transaction lock/exec/commit timings; `bd::slow` warnings report
//! slow transactions and commands. Logs never leave the machine.

use tracing_subscriber::EnvFilter;

use crate::cli::LogFormat;

pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_env("BD_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_target(true);
    let _ = match format {
        LogFormat::Json => builder.json().flatten_event(true).with_current_span(false).try_init(),
        LogFormat::Text => builder.compact().try_init(),
    };
}
