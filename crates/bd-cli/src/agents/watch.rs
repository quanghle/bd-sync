//! `bd agents watch`: pull a checkout's agent assets each time the
//! workspace's sets change, until interrupted.
//!
//! In a remote workspace the server says when they change: its agents job
//! (`bd serve --agents-every`) appends an `agents_changed` event for each
//! harness whose set changed, and the watch waits for those with long polls
//! (`events --since N --wait D --op agents_changed`), which the server holds
//! without a command slot (`bd serve`'s `follow` module). It reads the events head
//! first, then pulls, then waits for events after that head, so a change
//! made during the first pull is not missed. A pull follows each answer
//! with an event naming a watched harness and a revision other than the one
//! last pulled. A cursor that retention deleted events after (the watch
//! fell far behind) starts over: the head again, then a pull.
//!
//! Events alone can leave the checkout behind: the job compares the sets
//! with what it recorded once per interval, so a set changed and changed
//! back in between gets no event, though a pull may have caught it changed
//! (a deploy that empties a set and fills it again); and a server may run
//! no agents job at all (`--agents-every 0`). So each wait that ends with
//! no event (every `--max-wait` of the server) is followed by one read of
//! the server's manifests, and a pull when a watched set's revision differs
//! from the one last pulled. A request starts at most once per
//! `--interval`.
//!
//! A local workspace has no server to say so: its `.bd/agents` is read
//! every `--interval`, and a pull follows when a watched set's revision
//! differs from the one last pulled.
//!
//! Each pull is `bd agents pull`'s ([`super::sync_checkout`], applying):
//! removals applied, new or changed skills and MCP definitions left
//! waiting for `bd agents approve`, which this never runs. The
//! checkout's mutex is held only while a pull writes, so session hooks and
//! other bd commands in the checkout run meanwhile. Each pull's report is
//! printed as `pull` prints it (with `--json`, as one line).
//!
//! Failures do not end the watch, except a refused access token (exit 7).
//! One is reported on stderr when it starts (or turns into a failure of
//! another kind), and once more when it is over, never per attempt; a
//! remote workspace is tried again after pauses doubling up to
//! [`MAX_PAUSE`], a local one every `--interval`. Ctrl-C (and SIGTERM on
//! Unix) ends it with exit 0, once a pull under way has finished; a second
//! one ends it at once, with exit 130.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bd_core::agents::{AGENTS_CHANGED, AgentSet, AgentsChanged, Harness};
use bd_core::{Error, Event, Result};

use super::checkout::Checkout;
use super::show;
use super::sync::{Options, Source};
use crate::app::App;
use crate::cli::AgentsWatchArgs;
use crate::io;
use crate::remote::{Polled, Remote};

/// The first pause after a failure in a remote workspace; each failure in
/// a row doubles it, up to [`MAX_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_secs(1);
const MAX_PAUSE: Duration = Duration::from_secs(30);

pub fn cmd_watch(app: &App, remote: Option<&Remote>, a: &AgentsWatchArgs) -> Result<()> {
    io::require_local("bd agents watch")?;
    let checkout = super::find_checkout(app, remote.is_some())?;
    let harnesses = super::harnesses(&a.harnesses, &checkout)?;
    let pulling = interrupt::on_interrupt()?;
    let mut watch = Watch {
        app,
        remote,
        checkout,
        harnesses,
        interval: a.interval,
        pulled: BTreeMap::new(),
        pulling,
        failing: None,
        pause: FIRST_PAUSE,
    };
    match remote {
        Some(remote) => watch.remote(remote),
        None => watch.local(),
    }
}

struct Watch<'a> {
    app: &'a App,
    remote: Option<&'a Remote>,
    checkout: Checkout,
    harnesses: Vec<Harness>,
    interval: Duration,
    /// The revision of each harness's set the last pull found.
    pulled: BTreeMap<Harness, String>,
    /// Held while a pull runs, so an interrupt waits for it.
    pulling: Arc<Mutex<()>>,
    /// The kind of failure reported last, while failures last.
    failing: Option<&'static str>,
    /// The pause after the next failure in a remote workspace.
    pause: Duration,
}

fn lock(m: &Mutex<()>) -> MutexGuard<'_, ()> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Watch<'_> {
    /// Wait for events naming a watched harness on the server, pulling after each.
    fn remote(&mut self, remote: &Remote) -> Result<()> {
        let mut cursor: Option<i64> = None;
        let mut due = true;
        // Compare the server's revisions with those pulled, after a wait that saw no event.
        let mut compare = false;
        let mut requested: Option<Instant> = None;
        loop {
            let head = match cursor {
                Some(c) => c,
                None => match remote.event_head() {
                    Ok(head) => *cursor.insert(head),
                    Err(e) => {
                        let pause = self.failed(e)?;
                        std::thread::sleep(pause);
                        continue;
                    }
                },
            };
            if due {
                if let Err(e) = self.pull() {
                    let pause = self.failed(e)?;
                    std::thread::sleep(pause);
                    continue;
                }
                due = false;
                self.working();
            }
            if let Some(at) = requested {
                std::thread::sleep(self.interval.saturating_sub(at.elapsed()));
            }
            requested = Some(Instant::now());
            if compare {
                match self.behind(remote) {
                    Ok(behind) => {
                        self.working();
                        (due, compare) = (behind, false);
                    }
                    Err(e) => {
                        let pause = self.failed(e)?;
                        std::thread::sleep(pause);
                    }
                }
                continue;
            }
            match remote.poll_events(&[AGENTS_CHANGED], head) {
                Ok(Polled::Events(events, next)) => {
                    self.working();
                    (due, compare) = (self.news(&events), events.is_empty());
                    cursor = Some(next);
                }
                Ok(Polled::Truncated) => {
                    self.working();
                    io::errln(format!(
                        "bd agents watch: events after #{head} were deleted before they were read; pulling again"
                    ));
                    (cursor, due) = (None, true);
                }
                Err(e) => {
                    let pause = self.failed(e)?;
                    std::thread::sleep(pause);
                }
            }
        }
    }

    /// Whether `events` change a watched harness's set to a revision not pulled yet.
    fn news(&self, events: &[Event]) -> bool {
        let mut latest = BTreeMap::new();
        for e in events {
            if let Ok(c) = serde_json::from_value::<AgentsChanged>(e.data.clone()) {
                latest.insert(c.harness, c.revision);
            }
        }
        latest.iter().any(|(h, revision)| self.harnesses.contains(h) && self.pulled.get(h) != Some(revision))
    }

    /// Whether a watched set's revision on the server differs from the one
    /// last pulled: one read of the manifests.
    fn behind(&self, remote: &Remote) -> Result<bool> {
        let manifests = super::RemoteSource { app: self.app, remote }.manifests(&self.harnesses)?;
        Ok(manifests.iter().any(|(h, m)| self.pulled.get(h) != Some(&m.revision)))
    }

    /// Read the workspace's own sets every interval, pulling when one changed.
    fn local(&mut self) -> Result<()> {
        let dir = super::agents_dir(self.app)?;
        loop {
            let started = Instant::now();
            let checked = self
                .harnesses
                .iter()
                .map(|&h| AgentSet::load(&dir, h).map(|set| (h, set.revision)))
                .collect::<Result<BTreeMap<Harness, String>>>()
                .and_then(|now| if now == self.pulled { Ok(()) } else { self.pull() });
            match checked {
                Ok(()) => self.working(),
                Err(e) => {
                    self.failed(e)?;
                }
            }
            std::thread::sleep(self.interval.saturating_sub(started.elapsed()));
        }
    }

    /// Pull as `bd agents pull` does, and print its report.
    fn pull(&mut self) -> Result<()> {
        let _pulling = lock(&self.pulling);
        let opts = Options {
            apply: true,
            force: false,
            review: false,
            lock_wait: Duration::from_millis(self.app.g.busy_timeout_ms),
        };
        let report = super::sync_checkout(self.app, self.remote, &self.checkout, &self.harnesses, opts)?;
        if self.app.g.json {
            io::outln(serde_json::to_string(&report)?);
        } else {
            self.app.print(super::render(&report));
        }
        self.pulled = report.harnesses.iter().map(|(h, r)| (*h, r.server_revision.clone())).collect();
        Ok(())
    }

    /// A failure: the error that ends the watch, or the pause before the
    /// next try. Reported when failures start or change kind.
    fn failed(&mut self, e: Error) -> Result<Duration> {
        if matches!(e, Error::Unauthorized(_)) {
            return Err(e);
        }
        if self.failing.replace(e.code()) != Some(e.code()) {
            io::errln(show::printable(&format!("bd agents watch: {e} (trying again)")));
        }
        let pause = self.pause;
        self.pause = (self.pause * 2).min(MAX_PAUSE);
        Ok(pause)
    }

    /// A success: says so after failures.
    fn working(&mut self) {
        self.pause = FIRST_PAUSE;
        if self.failing.take().is_some() {
            io::errln("bd agents watch: working again");
        }
    }
}

/// Ctrl-C, and SIGTERM on Unix: exit 0 once no pull is under way; a second
/// one exits 130 at once. Every pull can be cut short safely (each file is
/// written whole, and the checkout's mutex is the system's to release), but
/// waiting for one leaves its report printed and its changes recorded.
mod interrupt {
    use std::sync::{Arc, Mutex};

    use bd_core::Result;

    #[cfg(unix)]
    struct Signals(tokio::signal::unix::Signal, tokio::signal::unix::Signal);

    #[cfg(unix)]
    impl Signals {
        fn new() -> std::io::Result<Signals> {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Signals(signal(SignalKind::interrupt())?, signal(SignalKind::terminate())?))
        }

        async fn recv(&mut self) {
            tokio::select! {
                _ = self.0.recv() => {}
                _ = self.1.recv() => {}
            }
        }
    }

    #[cfg(windows)]
    struct Signals(tokio::signal::windows::CtrlC);

    #[cfg(windows)]
    impl Signals {
        fn new() -> std::io::Result<Signals> {
            Ok(Signals(tokio::signal::windows::ctrl_c()?))
        }

        async fn recv(&mut self) {
            self.0.recv().await;
        }
    }

    /// Catch interrupts from now on; returns the mutex a pull holds.
    pub fn on_interrupt() -> Result<Arc<Mutex<()>>> {
        let pulling = Arc::new(Mutex::new(()));
        let held = pulling.clone();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let mut signals = {
            let _context = runtime.enter();
            Signals::new()?
        };
        std::thread::Builder::new().name("bd-watch-signals".into()).spawn(move || {
            runtime.block_on(async move {
                signals.recv().await;
                let (idle, finished) = tokio::sync::oneshot::channel();
                // Held until the process exits, so no pull starts meanwhile.
                std::thread::spawn(move || {
                    let _idle = super::lock(&held);
                    let _ = idle.send(());
                    loop {
                        std::thread::park();
                    }
                });
                tokio::select! {
                    _ = finished => std::process::exit(0),
                    _ = signals.recv() => std::process::exit(130),
                }
            })
        })?;
        Ok(pulling)
    }
}
