//! Remote workspaces: forward commands to `bd serve`.
//!
//! A workspace is remote when `--remote URL` or `$BD_REMOTE` is set, or when
//! the nearest `.bd/` holds a `remote.toml` (written by `bd remote set`):
//!
//! ```toml
//! url = "https://bd.example.com/w/proj"
//! ca_cert = "ca.pem"   # optional, relative to this file: trust a private CA
//! ```
//!
//! The access token comes from `$BD_TOKEN` when `--remote` or `$BD_REMOTE`
//! names the workspace, else from the user's credentials file (`bd remote
//! login`, see [`crate::credentials`]), never from a file in the repository.
//! `$BD_TOKEN` is bound to no URL, so it never goes to one a checkout's
//! `remote.toml` names: a cloned repository could name its own server. The command line travels unchanged; the
//! server runs it and streams back its output and exit code. Each invocation
//! gets a request id that its retries reuse, so a write whose answer was lost
//! is applied once: a write's answer is held until it has arrived whole, and
//! asked for again when it does not; one that cannot be recovered fails as
//! [`Error::AnswerLost`] (exit 9), never as safe to run again. A read prints
//! a large output as it arrives, so it is not retried once it has.
//! `events --follow` and `events --wait` are long polls whose answers say
//! where the next one continues (`follow_events`).

mod client;
mod cmd;
mod config;
mod delivery;
mod events;
mod forward;
mod renew;

pub use client::response_error;
pub use cmd::cmd_remote;
pub use config::{Trust, ca_certificates, configured, detect, is_loopback};
pub use events::Polled;
pub use forward::{is_hook, run, unavailable};

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::actor;
use renew::Renewing;

/// A workspace on a bd server.
pub struct Remote {
    /// Workspace URL without a trailing slash.
    pub url: String,
    /// The access token sent: a renewed one replaces it.
    token: Mutex<String>,
    /// The saved sign-in token this remote renews, if it does.
    renewing: Option<Mutex<Renewing>>,
    /// The CA certificates to trust instead of the system's, as read by [`Trust::load`].
    roots: Option<Vec<ureq::tls::Certificate<'static>>>,
    /// How long failures in transit are retried.
    retry: Duration,
    connect_timeout: Duration,
    /// Limit for each step of an attempt: sending the request, the server's
    /// work until its answer starts, and each wait for more of the answer.
    attempt_timeout: Duration,
    /// Limit for a whole attempt, for commands that must answer quickly.
    total_timeout: Option<Duration>,
    /// When every request must have ended, retries included, and the time
    /// that leaves from when it was set ([`Remote::within`]).
    deadline: Option<(Instant, Duration)>,
}

/// Where the remote workspace setting came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `--remote URL` or `$BD_REMOTE`.
    Flag,
    /// A `.bd/remote.toml` file.
    File(PathBuf),
}

/// The remote workspace an invocation uses, before its access token is looked up.
#[derive(Clone, Debug)]
pub struct Configured {
    pub url: String,
    pub source: Source,
    pub ca_cert: Option<PathBuf>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub fn env_actor() -> Option<String> {
    env("BD_ACTOR").or_else(|| env("BEADS_ACTOR"))
}

/// `argv` without its global `--session <name>` or `--session=<name>`: the
/// session label carries it (see [`identity`]), and a server that predates
/// the flag would refuse it. Arguments after `--` are left alone.
pub fn without_session_flag(argv: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut args = argv.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--" => {
                out.push(a);
                out.extend(args.by_ref());
            }
            "--session" => {
                args.next();
            }
            s if s.starts_with("--session=") => {}
            _ => out.push(a),
        }
    }
    out
}

/// Who a request asks to act as, besides an `--actor` in its argv: the
/// client's `$BD_ACTOR`, else its agent session ([`actor::session`]), which
/// the server turns into the sub-actor `<token actor>/<session>`.
pub fn identity() -> (Option<String>, Option<String>) {
    match env_actor() {
        Some(a) => (Some(a), None),
        None => (None, actor::session(&actor::session_env).map(|s| s.label)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_flag_is_not_forwarded() {
        let v = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert_eq!(
            without_session_flag(v(&["--session", "agent-1", "close", "t-1", "--session=x", "--reason", "r"])),
            v(&["close", "t-1", "--reason", "r"])
        );
        assert_eq!(
            without_session_flag(v(&["comment", "add", "t-1", "--", "--session", "x"])),
            v(&["comment", "add", "t-1", "--", "--session", "x"]),
            "after --, text"
        );
        assert_eq!(without_session_flag(v(&["create", "--session x"])), v(&["create", "--session x"]));
    }
}
