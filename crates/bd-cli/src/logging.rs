//! Structured diagnostics on stderr via `tracing`.
//!
//! Filter with `BD_LOG` (EnvFilter syntax, default `warn`; `bd serve` adds
//! `bd::serve=info`: one line per request, and per background job that
//! changed something): `BD_LOG=bd=debug`
//! shows per-transaction lock/exec/commit timings; `bd::slow` warnings report
//! slow transactions and commands. Colors only on a terminal (and never with
//! `NO_COLOR`), so log files stay plain text. Logs never leave the machine.

use std::fmt::{self, Write as _};
use std::io::IsTerminal;

use tracing::field::{Field, Visit};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::field::{MakeVisitor, VisitFmt, VisitOutput};
use tracing_subscriber::fmt::format::Writer;

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
        LogFormat::Text => builder.compact().fmt_fields(Escaped).try_init(),
    };
}

/// Text logs' fields, every control character escaped: values from requests
/// (a client ID, a redirect URI) are logged, and a newline in one must not
/// start a line of its own, passing for another entry (log injection). The
/// JSON format escapes them already.
struct Escaped;

impl<'w> MakeVisitor<Writer<'w>> for Escaped {
    type Visitor = EscapedFields<'w>;

    fn make_visitor(&self, writer: Writer<'w>) -> EscapedFields<'w> {
        EscapedFields { writer, first: true, result: Ok(()) }
    }
}

struct EscapedFields<'w> {
    writer: Writer<'w>,
    first: bool,
    result: fmt::Result,
}

impl Visit for EscapedFields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_debug(field, &value)
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.result.is_err() {
            return;
        }
        let text = escape(&format!("{value:?}"));
        let sep = if std::mem::take(&mut self.first) { "" } else { " " };
        self.result = match field.name() {
            "message" => write!(self.writer, "{sep}{text}"),
            name => write!(self.writer, "{sep}{name}={text}"),
        };
    }
}

impl VisitOutput<fmt::Result> for EscapedFields<'_> {
    fn finish(self) -> fmt::Result {
        self.result
    }
}

impl VisitFmt for EscapedFields<'_> {
    fn writer(&mut self) -> &mut dyn fmt::Write {
        &mut self.writer
    }
}

/// `text` with its control characters written as escapes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn logged_values_cannot_start_lines_of_their_own() {
        let out = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = out.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || Sink(sink.clone()))
            .with_ansi(false)
            .compact()
            .fmt_fields(Escaped)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let client = "x\n2026-10-04T00:00:00Z  INFO bd::serve: forged\r\u{1b}[31m";
            tracing::info!(target: "bd::serve", client = %client, why = ?"a\nb", plain = "c\nd", "refused\nhere");
        });
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert_eq!(text.matches('\n').count(), 1, "one entry, one line: {text}");
        assert!(text.contains(r"client=x\n2026-10-04T00:00:00Z  INFO bd::serve: forged\r\u{1b}[31m"), "{text}");
        assert!(text.contains(r#"why="a\nb""#) && text.contains(r"refused\nhere"), "{text}");
    }

    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
