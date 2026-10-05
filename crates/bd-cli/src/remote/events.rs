//! `events --follow` and `events --wait` as long polls, and the event polls
//! of `bd agents watch`.

use std::time::{Duration, Instant};

use bd_core::{Error, Result};

use super::{Remote, identity, response_error};
use crate::app::App;
use crate::cli::EventsArgs;
use crate::io;
use crate::protocol::{ExecRequest, ExecResponse};
use std::io::Write;

/// How long a remote follower asks the server to wait for a new event; the
/// server's `--max-wait` (25 s by default) caps it. The client waits up to
/// two minutes for an answer to start.
const FOLLOW_WAIT: Duration = Duration::from_secs(90);
/// Events per answer while following, as the local `events --follow` reads them.
const FOLLOW_BATCH: usize = 1000;

/// `events` on the server from `since`, at most `limit` events, waiting up
/// to `wait` for the first; with the command's filters and output format.
fn events_request(
    app: &App,
    remote: &Remote,
    a: &EventsArgs,
    since: Option<i64>,
    limit: Option<usize>,
    wait: Option<Duration>,
) -> ExecRequest {
    let mut argv: Vec<String> = Vec::new();
    if app.g.json {
        argv.push("--json".into());
    }
    if let Some(actor) = &app.g.actor {
        argv.extend(["--actor".into(), actor.clone()]);
    }
    argv.push("events".into());
    if let Some(c) = since {
        argv.extend(["--since".into(), c.to_string()]);
    }
    if let Some(n) = limit {
        argv.extend(["--limit".into(), n.to_string()]);
    }
    if let Some(w) = wait {
        argv.extend(["--wait".into(), format!("{}ms", w.as_millis())]);
    }
    if let Some(issue) = &a.issue {
        argv.extend(["--issue".into(), issue.clone()]);
    }
    for op in &a.ops {
        argv.extend(["--op".into(), op.clone()]);
    }
    if let Some(by) = &a.by_actor {
        argv.extend(["--by".into(), by.clone()]);
    }
    let (actor, session) = identity();
    ExecRequest { argv, actor, session, location: Some(remote.url.clone()), ..Default::default() }
}

/// Print the events of an answer; returns where they end (the cursor to
/// continue from), or the exit code of a failure, whose error is printed.
fn print_events(remote: &Remote, r: ExecResponse) -> Result<std::result::Result<i64, i32>> {
    if r.exit_code != 0 {
        let _ = std::io::stderr().write_all(io::printable(&r.stderr).as_bytes());
        return Ok(Err(r.exit_code));
    }
    let cursor = r.cursor.ok_or_else(|| Error::Remote(format!("{}: the server sent no event cursor", remote.url)))?;
    io::out(&r.stdout);
    Ok(Ok(cursor))
}

/// Continue with the full id of the issue `--issue` named, as the server
/// resolved it (its issue frame): like a local follower, which resolves it
/// once, a remote one keeps following that issue, also once it is deleted
/// (a partial id no longer resolves then) or a new issue makes a partial id
/// ambiguous.
fn pin_issue(a: &mut EventsArgs, r: &ExecResponse) {
    if let (Some(issue), Some(id)) = (&mut a.issue, &r.issue) {
        issue.clone_from(id);
    }
}

/// `events --follow`: long polls. Each request waits on the server until an
/// event matching the filters follows the cursor (or the server's wait
/// ends), and its answer says where to continue, so every event is printed
/// once, in order, however requests fail and are retried. Under load,
/// events arrive in batches: a request starts at most once per interval.
pub(super) fn follow_events(app: &App, remote: &Remote, a: &EventsArgs) -> Result<i32> {
    let interval = Duration::from_millis(a.interval_ms.max(200));
    let mut a = a.clone();
    let mut cursor = match a.since {
        Some(since) => since,
        // First the most recent events, as the local command prints them.
        None => {
            let response = remote.exec(&events_request(app, remote, &a, None, a.limit, None))?;
            pin_issue(&mut a, &response);
            match print_events(remote, response)? {
                Ok(cursor) => cursor,
                Err(code) => return Ok(code),
            }
        }
    };
    let mut first = a.since.is_some();
    loop {
        let started = Instant::now();
        let limit = match a.limit {
            Some(n) if first => n.min(FOLLOW_BATCH),
            _ => FOLLOW_BATCH,
        };
        let response =
            remote.long_poll(&events_request(app, remote, &a, Some(cursor), Some(limit), Some(FOLLOW_WAIT)))?;
        pin_issue(&mut a, &response);
        if response.exit_code == 6 && !first {
            // Retention deleted events after the cursor before they were read (the follower fell far
            // behind): the answer's cursor continues at the oldest event kept.
            let resume = response.cursor.filter(|&c| c > cursor).ok_or_else(|| {
                Error::Remote(format!("{}: the server sent no event cursor past the pruned events", remote.url))
            })?;
            let pruned = match resume - cursor {
                1 => format!("event #{resume} was pruned before it was read"),
                _ => format!("events #{} to #{resume} were pruned before they were read", cursor + 1),
            };
            io::errln(format!("warning: {pruned}; continuing after #{resume}"));
            cursor = resume;
        } else {
            cursor = match print_events(remote, response)? {
                Ok(next) => next,
                Err(code) => return Ok(code),
            };
            first = false;
        }
        if let Some(rest) = interval.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
    }
}

/// `events --since N --wait D`: long polls of at most [`FOLLOW_WAIT`] until
/// an event matching the filters follows `N`, or `D` has passed.
pub(super) fn wait_for_events(app: &App, remote: &Remote, a: &EventsArgs, since: i64, wait: Duration) -> Result<i32> {
    let interval = Duration::from_millis(a.interval_ms.max(200));
    let started = Instant::now();
    let mut a = a.clone();
    let mut cursor = since;
    loop {
        let round = Instant::now();
        let left = wait.saturating_sub(started.elapsed());
        let request = events_request(app, remote, &a, Some(cursor), a.limit, Some(left.min(FOLLOW_WAIT)));
        let response = remote.long_poll(&request)?;
        pin_issue(&mut a, &response);
        let found = !response.stdout.is_empty();
        cursor = match print_events(remote, response)? {
            Ok(next) => next,
            Err(code) => return Ok(code),
        };
        let left = wait.saturating_sub(started.elapsed());
        if found || left.is_zero() {
            return Ok(0);
        }
        // An answer before its wait ended (the server's followers are full): ask again after the interval.
        std::thread::sleep(interval.saturating_sub(round.elapsed()).min(left));
    }
}

/// What a long poll for events found ([`Remote::poll_events`]).
pub enum Polled {
    /// The events that followed the cursor (none when the wait ended
    /// first), and the cursor to continue from.
    Events(Vec<bd_core::Event>, i64),
    /// Retention deleted events that followed the cursor before they were read.
    Truncated,
}

impl Remote {
    /// Events with one of `ops` after `since`: a long poll that the server
    /// holds until one is committed, for at most [`FOLLOW_WAIT`] (its
    /// `--max-wait` caps that), retried like any.
    pub fn poll_events(&self, ops: &[&str], since: i64) -> Result<Polled> {
        let mut argv: Vec<String> = vec!["--json".into(), "events".into(), "--since".into(), since.to_string()];
        argv.extend(["--limit".into(), FOLLOW_BATCH.to_string()]);
        argv.extend(["--wait".into(), format!("{}ms", FOLLOW_WAIT.as_millis())]);
        for op in ops {
            argv.extend(["--op".into(), op.to_string()]);
        }
        let (actor, session) = identity();
        let request = ExecRequest { argv, actor, session, location: Some(self.url.clone()), ..Default::default() };
        let response = self.long_poll(&request)?;
        match response.exit_code {
            0 => {}
            6 => return Ok(Polled::Truncated),
            _ => return Err(response_error(&response, &self.url)),
        }
        let unexpected = |why: String| Error::Remote(format!("{}: unexpected events answer: {why}", self.url));
        let cursor = response.cursor.ok_or_else(|| unexpected("no event cursor".into()))?;
        let events = response
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<std::result::Result<Vec<bd_core::Event>, _>>()
            .map_err(|e| unexpected(e.to_string()))?;
        Ok(Polled::Events(events, cursor))
    }

    /// The workspace's events head: the cursor after its newest event.
    pub fn event_head(&self) -> Result<i64> {
        let (actor, session) = identity();
        let request = ExecRequest {
            argv: vec!["info".into(), "--json".into()],
            actor,
            session,
            location: Some(self.url.clone()),
            ..Default::default()
        };
        let response = self.exec(&request)?;
        if response.exit_code == 7 {
            return Err(response_error(&response, &self.url));
        }
        if response.exit_code != 0 {
            return Err(Error::Remote(format!("{}: bd info failed: {}", self.url, response.stderr.trim())));
        }
        let info: serde_json::Value = serde_json::from_str(&response.stdout)?;
        info["events_head"].as_i64().ok_or_else(|| Error::Remote(format!("{}: bd info has no events_head", self.url)))
    }
}
