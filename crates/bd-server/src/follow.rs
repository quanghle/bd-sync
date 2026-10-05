//! Long polls for new events: how `bd serve` answers `events --since N --wait
//! D`, and so remote `events --follow`, as soon as a matching event is
//! committed, without polling the database for each client.
//!
//! Such a request first checks whether an event matching its filters follows
//! `N`. If none does, it waits on its workspace's [`Feeds`] entry before its
//! command runs: it holds no command slot, database connection, transaction
//! or memory budget meanwhile, only its connection, its small parsed request
//! (a larger one, over 16 KiB, is answered at once) and a place among the
//! server's followers (`--max-followers`; a request past that is answered at
//! once, and its client polls). Each time the workspace's events head moves
//! past what the request has seen, it checks again (its filters may skip the
//! new events), and its command runs once a matching event follows `N`, when
//! its wait ends (at most `--max-wait`), or when the server stops.
//!
//! A feed learns of commits three ways. Requests that may write, and
//! background jobs, kick it when they finish; and while anyone waits, it reads
//! the head every [`HEAD_CHECK_EVERY`] as well, for commits by other
//! processes on the server's host (a local `bd` opening the same `bd.db`).
//! One watcher task per workspace reads the head, however many requests wait,
//! and only while some do. Once it has woken them, it waits
//! [`HEAD_CHECK_GAP`] before reading again, so that a burst of commits wakes
//! them once, and followers whose filters skip a busy workspace's events cost
//! the server a bounded number of checks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bd_core::Result;
use tokio::sync::{Notify, watch};

use bd_cli::cli::{Cli, Command, EventsArgs};

/// How often the head of a workspace is read while requests wait on it, to
/// see commits by other processes.
pub const HEAD_CHECK_EVERY: Duration = Duration::from_millis(500);
/// The least time between two wake-ups of the requests waiting on a workspace.
pub const HEAD_CHECK_GAP: Duration = Duration::from_millis(100);

/// Reads a workspace's events head (called on a blocking thread).
pub type HeadReader = Arc<dyn Fn() -> Result<i64> + Send + Sync>;

/// The event feeds of a server's workspaces, by name.
pub struct Feeds {
    feeds: Mutex<HashMap<String, Arc<Feed>>>,
    every: Duration,
    gap: Duration,
}

struct Feed {
    /// The events head last read.
    head: watch::Sender<i64>,
    /// Commits in this process.
    kick: Notify,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    waiters: usize,
    /// The watcher task runs.
    watching: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Feeds {
    /// Feeds whose heads are read every `every` while requests wait, and
    /// after commits; but `gap` after a read that woke them.
    pub fn new(every: Duration, gap: Duration) -> Feeds {
        Feeds { feeds: Mutex::default(), every, gap }
    }

    /// A command that may have appended events in workspace `name` finished.
    pub fn committed(&self, name: &str) {
        if let Some(feed) = lock(&self.feeds).get(name) {
            feed.kick.notify_one();
        }
    }

    /// Wait on the events of workspace `name`, whose head `read` reads. The
    /// first waiter starts the workspace's watcher (in the current runtime).
    pub fn subscribe(&self, name: &str, read: impl FnOnce() -> HeadReader) -> Subscription {
        let feed = lock(&self.feeds)
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(Feed { head: watch::Sender::new(0), kick: Notify::new(), state: Mutex::default() })
            })
            .clone();
        let mut state = lock(&feed.state);
        state.waiters += 1;
        if !state.watching {
            state.watching = true;
            tokio::spawn(watch(feed.clone(), read(), (self.every, self.gap), name.to_string()));
        }
        drop(state);
        Subscription { head: feed.head.subscribe(), feed }
    }

    /// Requests waiting on workspace `name`, and whether its watcher runs.
    #[cfg(test)]
    fn state(&self, name: &str) -> (usize, bool) {
        lock(&self.feeds).get(name).map_or((0, false), |f| {
            let state = lock(&f.state);
            (state.waiters, state.watching)
        })
    }
}

/// Read the head at once, then after kicks and every `every`, until nobody
/// waits; but `gap` after a read that found it moved.
async fn watch(feed: Arc<Feed>, read: HeadReader, (every, gap): (Duration, Duration), workspace: String) {
    let mut failing = false;
    let mut first = true;
    loop {
        // The first read catches up with commits made while nobody waited: it wakes nobody.
        let catching_up = std::mem::take(&mut first);
        let reader = read.clone();
        let mut moved = false;
        match tokio::task::spawn_blocking(move || reader()).await {
            Ok(Ok(head)) => {
                failing = false;
                moved = feed.head.send_if_modified(|h| std::mem::replace(h, head) != head);
            }
            Ok(Err(e)) => {
                if !std::mem::replace(&mut failing, true) {
                    tracing::warn!(target: "bd::serve", %workspace, error = %e, "cannot read the events head");
                }
            }
            Err(_) => {
                if !std::mem::replace(&mut failing, true) {
                    tracing::error!(target: "bd::serve", %workspace, "reading the events head panicked");
                }
            }
        }
        {
            let mut state = lock(&feed.state);
            if state.waiters == 0 {
                state.watching = false;
                return;
            }
        }
        if moved && !catching_up {
            // Kicks meanwhile are kept: one read follows them all.
            tokio::time::sleep(gap).await;
        }
        tokio::select! {
            _ = feed.kick.notified() => {}
            _ = tokio::time::sleep(every) => {}
        }
    }
}

/// A request waiting on a workspace's events.
pub struct Subscription {
    feed: Arc<Feed>,
    head: watch::Receiver<i64>,
}

impl Subscription {
    /// Returns once the events head is past `cursor`.
    pub async fn past(&mut self, cursor: i64) {
        if self.head.wait_for(|head| *head > cursor).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        lock(&self.feed.state).waiters -= 1;
    }
}

/// A request `events --since N --wait D`.
pub struct Wait {
    pub args: EventsArgs,
    pub since: i64,
    pub wait: Duration,
}

/// The wait a request's command line asks for, if it is `events --since N
/// --wait D`. Only short command lines are parsed here, on the server's
/// async threads; any other runs without waiting.
pub fn requested(argv: &[String]) -> Option<(Cli, Wait)> {
    use clap::Parser;
    let short = argv.len() <= 64 && argv.iter().map(String::len).sum::<usize>() <= 4096;
    if !short || !argv.iter().any(|a| a == "--wait" || a.starts_with("--wait=")) {
        return None;
    }
    let cli = Cli::try_parse_from(std::iter::once("bd").chain(argv.iter().map(String::as_str))).ok()?;
    let Command::Events(a) = &cli.command else { return None };
    let (Some(since), Some(wait)) = (a.since, a.wait) else { return None };
    if a.action.is_some() || a.follow {
        return None;
    }
    let args = a.clone();
    Some((cli, Wait { args, since, wait }))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
    }

    /// A head that tests move, counting its reads.
    #[derive(Default)]
    struct Head {
        seq: AtomicI64,
        reads: AtomicUsize,
    }

    fn reader(head: &Arc<Head>) -> impl FnOnce() -> HeadReader {
        let head = head.clone();
        move || {
            Arc::new(move || {
                let seq = head.seq.load(Ordering::SeqCst);
                head.reads.fetch_add(1, Ordering::SeqCst);
                Ok(seq)
            })
        }
    }

    async fn until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn only_event_waits_are_held() {
        let (_, w) = requested(&argv("--json events --since 12 --wait 30s --op closed --issue t-1")).unwrap();
        assert_eq!(
            (w.since, w.wait, w.args.ops.as_slice()),
            (12, Duration::from_secs(30), &["closed".to_string()][..])
        );
        assert_eq!(requested(&argv("events --since=3 --wait=250ms")).unwrap().1.wait, Duration::from_millis(250));
        for other in [
            "events --since 12",
            "events --wait 30s",
            "events --since 1 --wait soon",
            "create --wait",
            "list --title-contains --wait",
            "events --follow --since 1 --wait 1s",
        ] {
            assert!(requested(&argv(other)).is_none(), "{other}");
        }
        let long: Vec<String> = argv("events --since 1 --wait 1s").into_iter().chain(["x".repeat(5000)]).collect();
        assert!(requested(&long).is_none(), "long command lines are not parsed on async threads");
    }

    #[test]
    fn commits_wake_waiters_without_polling_per_waiter() {
        let rt = runtime();
        let feeds = Arc::new(Feeds::new(Duration::from_secs(3600), Duration::from_millis(10)));
        let head = Arc::new(Head::default());
        head.seq.store(10, Ordering::SeqCst);
        rt.block_on(async {
            let waiters: Vec<_> = (0..20)
                .map(|_| {
                    let mut sub = feeds.subscribe("proj", reader(&head));
                    tokio::spawn(async move {
                        let started = Instant::now();
                        sub.past(10).await;
                        started.elapsed()
                    })
                })
                .collect();
            until("the first read", || head.reads.load(Ordering::SeqCst) > 0).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(head.reads.load(Ordering::SeqCst), 1, "one watcher reads the head for all waiters");
            assert!(waiters.iter().all(|w| !w.is_finished()), "nothing past 10 yet");
            feeds.committed("other");
            head.seq.store(11, Ordering::SeqCst);
            feeds.committed("proj");
            for w in waiters {
                let waited = tokio::time::timeout(Duration::from_secs(20), w).await.unwrap().unwrap();
                assert!(waited < Duration::from_secs(10), "{waited:?}");
            }
            assert!(head.reads.load(Ordering::SeqCst) <= 3, "{}", head.reads.load(Ordering::SeqCst));
        });
        assert_eq!(feeds.state("proj").0, 0, "subscriptions end with their requests");
    }

    #[test]
    fn bursts_of_commits_wake_waiters_once() {
        let rt = runtime();
        let feeds = Arc::new(Feeds::new(Duration::from_millis(50), Duration::from_secs(3600)));
        let head = Arc::new(Head::default());
        rt.block_on(async {
            let mut sub = feeds.subscribe("proj", reader(&head));
            // Reads that find nothing new do not hold back the next one.
            until("reads on the timer", || head.reads.load(Ordering::SeqCst) >= 3).await;
            head.seq.store(1, Ordering::SeqCst);
            feeds.committed("proj");
            tokio::time::timeout(Duration::from_secs(20), sub.past(0)).await.expect("a commit is read at once");
            // Waiters were woken: commits right after it wait for the gap, and are read together.
            let reads = head.reads.load(Ordering::SeqCst);
            for seq in 2..=50 {
                head.seq.store(seq, Ordering::SeqCst);
                feeds.committed("proj");
            }
            assert!(tokio::time::timeout(Duration::from_millis(300), sub.past(1)).await.is_err(), "held for the gap");
            assert_eq!(head.reads.load(Ordering::SeqCst), reads, "not even read");
        });
    }

    #[test]
    fn heads_are_read_on_a_timer_only_while_requests_wait() {
        let rt = runtime();
        let feeds = Arc::new(Feeds::new(Duration::from_millis(20), Duration::from_millis(5)));
        let head = Arc::new(Head::default());
        rt.block_on(async {
            let mut sub = feeds.subscribe("proj", reader(&head));
            // Another process commits: no kick, but the timer sees it.
            head.seq.store(5, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(20), sub.past(4)).await.expect("seen by the timer");
            drop(sub);
            until("the watcher to stop", || !feeds.state("proj").1).await;
            let reads = head.reads.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(head.reads.load(Ordering::SeqCst), reads, "the watcher stopped with the last waiter");

            // A new waiter starts it again, and the head it knew is kept.
            let mut sub = feeds.subscribe("proj", reader(&head));
            assert!(tokio::time::timeout(Duration::from_millis(100), sub.past(5)).await.is_err());
            head.seq.store(6, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(20), sub.past(5)).await.expect("seen again");
        });
    }

    #[test]
    fn a_failing_head_read_keeps_waiters_waiting() {
        let rt = runtime();
        let feeds = Feeds::new(Duration::from_millis(10), Duration::ZERO);
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        rt.block_on(async {
            let mut sub = feeds.subscribe("proj", move || -> HeadReader {
                Arc::new(move || {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Err(bd_core::Error::invalid("gone"))
                })
            });
            assert!(tokio::time::timeout(Duration::from_millis(200), sub.past(0)).await.is_err());
        });
        assert!(reads.load(Ordering::SeqCst) > 1, "and it is tried again");
    }
}
