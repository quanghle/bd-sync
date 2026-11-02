//! The memory requests may hold while `bd serve` receives and answers them.
//!
//! A [`Budget`] is a count of bytes free and a ledger of what each caller
//! uses, under one mutex, with no queue: a request that fits goes ahead at
//! once, whoever is waiting, and one that does not waits for a release and
//! tries again. Grants are RAII values, so memory comes back however a
//! request ends: answered, refused, dropped mid-wait or panicking.
//!
//! An [`Upload`] is a request whose body is arriving. It grows its grant as
//! bytes come in instead of reserving what its client declared, and then
//! takes its answer's share with [`Upload::answer`]. What it finally keeps
//! is a [`Held`], which the job and the answer carry until they are done.
//!
//! Three rules decide who gets what:
//!
//! - The cap: everything a [`Caller`] holds, has pledged or is waiting for
//!   counts against it, and past it a request is refused with [`Busy::Cap`]
//!   at once. A pledge counts against the caller alone and moves nothing in
//!   the shared budget, so nobody ever waits on a cap, and declaring a large
//!   body reserves nothing.
//! - The reserve: a [`Class::Large`] take leaves that many bytes free, so
//!   large bodies cannot crowd out [`Class::Ordinary`] requests.
//! - Seniority: two uploads that each hold part of what the other needs
//!   would stall each other, and retrying together they would fail forever.
//!   So a large upload that cannot go on registers as waiting, and it gets
//!   [`Busy::Full`] at once if an older upload is waiting too. The oldest
//!   waiting upload thus gets through, unless what it needs is held by
//!   something that is not waiting, and then it times out. Ordinary requests
//!   have no part in this.
//!
//! One request has one allowance for all its waits, so memory waits cannot
//! stretch a request without bound.
//!
//! Nothing here touches a store or does I/O, and sizes and times are passed
//! in, so this module knows nothing of HTTP or of the server's limits.

use std::collections::{BTreeSet, HashMap};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::{Instant, timeout_at};

/// Why memory was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Busy {
    /// The caller would pass its cap.
    Cap,
    /// The budget has no room for this request, now or within its allowance.
    Full,
}

/// How a take stands towards the reserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// May use the whole budget, and never yields to an older upload.
    Ordinary,
    /// Stops at the reserve; an upload's take also yields to older ones.
    Large,
}

/// Who a grant is charged to. The key is whatever the server decides it
/// cannot be varied by a client: see `serve::caller_of`.
#[derive(Clone, Debug)]
pub struct Caller(Arc<str>);

/// The memory requests share, and the ledger of who uses it.
pub struct Budget {
    total: u64,
    reserve: u64,
    cap: u64,
    state: Mutex<State>,
    /// Fired when memory comes back, or a large upload starts to wait.
    released: Notify,
}

struct State {
    free: u64,
    /// What each caller holds, has pledged or is waiting for. A caller using
    /// nothing has no entry.
    callers: HashMap<Arc<str>, u64>,
    next_seq: u64,
    /// The uploads waiting for growth or for a large answer, oldest first.
    waiting: BTreeSet<u64>,
}

/// A grant, given back when dropped.
///
/// `held` bytes are taken from the shared budget; `pledged` bytes are only
/// charged to the caller, and become held as they are taken.
pub struct Held {
    budget: Arc<Budget>,
    caller: Caller,
    held: u64,
    pledged: u64,
}

/// A request whose body is arriving: its grant, its place among uploads and
/// what is left of its wait allowance. Dropping it gives back its grant.
pub struct Upload {
    grant: Held,
    seq: u64,
    left: Duration,
}

/// Takes an upload's place in [`State::waiting`] away when its wait ends,
/// however it ends. An older upload leaving wakes nobody: no younger upload
/// is parked behind it, as each is refused on seeing an older one.
struct Waiting<'a> {
    budget: &'a Budget,
    seq: Option<u64>,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(seq) = self.seq {
            lock(&self.budget.state).waiting.remove(&seq);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Budget {
    /// `total` bytes to share, of which [`Class::Large`] takes leave
    /// `reserve` free, and at most `cap` for one caller.
    pub fn new(total: u64, reserve: u64, cap: u64) -> Arc<Budget> {
        Arc::new(Budget {
            total,
            reserve,
            cap,
            state: Mutex::new(State { free: total, callers: HashMap::new(), next_seq: 0, waiting: BTreeSet::new() }),
            released: Notify::new(),
        })
    }

    /// The caller named by `key`.
    pub fn caller(key: &str) -> Caller {
        Caller(Arc::from(key))
    }

    /// Admits an upload: charges its caller `pledge` (or `first`, if more)
    /// and takes `first` from the budget, waiting up to `wait`. What remains
    /// of `wait` is the allowance for all the upload's later waits.
    pub async fn admit(
        self: &Arc<Self>,
        caller: &Caller,
        first: u64,
        pledge: u64,
        wait: Duration,
    ) -> Result<Upload, Busy> {
        let charged = pledge.max(first);
        let seq = {
            let mut state = lock(&self.state);
            self.charge(&mut state, caller, charged)?;
            let seq = state.next_seq;
            state.next_seq += 1;
            seq
        };
        let mut upload = Upload { grant: self.grant(caller, charged), seq, left: wait };
        upload.grant.acquire(first, Class::Ordinary, None, &mut upload.left).await?;
        Ok(upload)
    }

    /// Takes `n` bytes for a request with no upload left, waiting up to
    /// `allowance`.
    pub async fn take(
        self: &Arc<Self>,
        caller: &Caller,
        n: u64,
        class: Class,
        mut allowance: Duration,
    ) -> Result<Held, Busy> {
        let mut held = self.grant(caller, 0);
        held.acquire(n, class, None, &mut allowance).await?;
        Ok(held)
    }

    fn grant(self: &Arc<Self>, caller: &Caller, pledged: u64) -> Held {
        Held { budget: Arc::clone(self), caller: caller.clone(), held: 0, pledged }
    }

    /// Adds `extra` to what `caller` uses, unless that would pass the cap.
    fn charge(&self, state: &mut State, caller: &Caller, extra: u64) -> Result<(), Busy> {
        if extra == 0 {
            return Ok(());
        }
        let used = state.callers.get(&*caller.0).copied().unwrap_or(0);
        let used = used.checked_add(extra).filter(|used| *used <= self.cap).ok_or(Busy::Cap)?;
        state.callers.insert(Arc::clone(&caller.0), used);
        Ok(())
    }

    /// Returns `held` bytes to the budget and takes `held + pledged` off the
    /// caller, removing its entry at zero. Only memory given back can let a
    /// waiter go on, so a pledge alone wakes nobody.
    fn give_back(&self, caller: &Caller, held: u64, pledged: u64) {
        let amount = held.saturating_add(pledged);
        if amount == 0 {
            return;
        }
        let sound = {
            let mut state = lock(&self.state);
            let free = state.free.saturating_add(held);
            state.free = free.min(self.total);
            let used = state.callers.get(&*caller.0).copied().unwrap_or(0);
            let rest = used.saturating_sub(amount);
            if rest == 0 {
                state.callers.remove(&*caller.0);
            } else {
                state.callers.insert(Arc::clone(&caller.0), rest);
            }
            free <= self.total && used >= amount
        };
        if !sound {
            tracing::error!(target: "bd::serve", held, pledged, "the request budget's ledger does not add up");
        }
        debug_assert!(sound, "the request budget's ledger does not add up");
        if held > 0 {
            self.released.notify_waiters();
        }
    }
}

impl Held {
    /// Takes `n` more bytes from the budget, using what is pledged first.
    ///
    /// Anything past the pledge is charged before any wait and stays pledged
    /// on `self`, so a failed or cancelled wait gives it back through
    /// [`Drop`]. A caller past its cap is refused at once. With `seq`, a
    /// [`Class::Large`] take takes part in seniority. The time spent waiting
    /// comes off `left`, and with nothing left it does not wait.
    async fn acquire(&mut self, n: u64, class: Class, seq: Option<u64>, left: &mut Duration) -> Result<(), Busy> {
        if n == 0 {
            return Ok(());
        }
        let budget = Arc::clone(&self.budget);
        let floor = match class {
            Class::Ordinary => 0,
            Class::Large => budget.reserve,
        };
        let need = n.saturating_add(floor);
        {
            let mut state = lock(&budget.state);
            let extra = n.saturating_sub(self.pledged);
            budget.charge(&mut state, &self.caller, extra)?;
            self.pledged += extra;
            if self.fit(&mut state, n, need) {
                return Ok(());
            }
        }
        if left.is_zero() {
            return Err(Busy::Full);
        }

        let started = Instant::now();
        let deadline = started + *left;
        let mut place = Waiting { budget: &budget, seq: None };
        let outcome = loop {
            // Enabled before the check, so a release after it is not lost.
            let mut notified = pin!(budget.released.notified());
            notified.as_mut().enable();
            let mut newly_waiting = false;
            {
                let mut state = lock(&budget.state);
                if self.fit(&mut state, n, need) {
                    break Ok(());
                }
                if let (Class::Large, Some(seq)) = (class, seq) {
                    newly_waiting = state.waiting.insert(seq);
                    place.seq = Some(seq);
                    if state.waiting.first() != Some(&seq) {
                        break Err(Busy::Full);
                    }
                }
            }
            if newly_waiting {
                // Younger waiters must see this upload, and give way to it.
                budget.released.notify_waiters();
            }
            if timeout_at(deadline, notified.as_mut()).await.is_err() {
                break Err(Busy::Full);
            }
        };
        *left = left.saturating_sub(started.elapsed());
        outcome
    }

    /// Moves `n` bytes from pledged to held, if `need` are free.
    fn fit(&mut self, state: &mut State, n: u64, need: u64) -> bool {
        if state.free < need {
            return false;
        }
        state.free -= n;
        self.pledged -= n;
        self.held += n;
        true
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.budget.give_back(&self.caller, self.held, self.pledged);
    }
}

impl Upload {
    /// Grows the grant to `to` bytes held in all.
    pub async fn grow(&mut self, to: u64, class: Class) -> Result<(), Busy> {
        let n = to.saturating_sub(self.grant.held);
        self.grant.acquire(n, class, Some(self.seq), &mut self.left).await
    }

    /// Takes `n` bytes for the answer, from the upload's pledge first. The
    /// wait is the upload's own: a large answer keeps its place among
    /// uploads, or it could stall with a younger upload that is growing.
    pub async fn answer(&mut self, n: u64, class: Class) -> Result<Held, Busy> {
        let pledged = n.min(self.grant.pledged);
        self.grant.pledged -= pledged;
        let mut answer = self.grant.budget.grant(&self.grant.caller, pledged);
        answer.acquire(n, class, Some(self.seq), &mut self.left).await?;
        Ok(answer)
    }

    /// Ends the upload: gives back any pledge left and keeps what is held.
    pub fn finish(self) -> Held {
        let mut grant = self.grant;
        let pledged = std::mem::take(&mut grant.pledged);
        grant.budget.give_back(&grant.caller, 0, pledged);
        grant
    }

    /// The bytes this upload holds of the shared budget.
    pub fn held(&self) -> u64 {
        self.grant.held
    }

    /// What is left of the allowance for waiting.
    pub fn left(&self) -> Duration {
        self.left
    }
}

#[cfg(test)]
impl Budget {
    pub(crate) fn free(&self) -> u64 {
        lock(&self.state).free
    }

    pub(crate) fn ledger_len(&self) -> usize {
        lock(&self.state).callers.len()
    }

    /// `(total, reserve, cap)`.
    pub(crate) fn limits(&self) -> (u64, u64, u64) {
        (self.total, self.reserve, self.cap)
    }

    pub(crate) fn used(&self, caller: &Caller) -> u64 {
        lock(&self.state).callers.get(&*caller.0).copied().unwrap_or(0)
    }

    pub(crate) fn waiting_len(&self) -> usize {
        lock(&self.state).waiting.len()
    }

    /// Panics unless the ledger is sound at this moment.
    pub(crate) fn check(&self) {
        let state = lock(&self.state);
        assert!(state.free <= self.total, "{} free", state.free);
        for used in state.callers.values() {
            assert!((1..=self.cap).contains(used), "{used} used");
        }
        let used: u64 = state.callers.values().sum();
        assert!(self.total - state.free <= used, "the ledger lost bytes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::task::{JoinHandle, JoinSet};
    use tokio::time::{sleep, timeout};

    const WAIT: Duration = Duration::from_secs(15);
    const NO_WAIT: Duration = Duration::ZERO;

    /// 100 bytes, 10 of them kept from large bodies, 80 for one caller.
    fn budget() -> Arc<Budget> {
        Budget::new(100, 10, 80)
    }

    /// The same, for tests where one job holds most of it.
    fn budget_with_no_cap() -> Arc<Budget> {
        Budget::new(100, 10, 100)
    }

    fn caller(key: &str) -> Caller {
        Budget::caller(key)
    }

    /// Lets every other task run until it parks. The paused clock stays
    /// where it is, as this task never sleeps.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Runs `f`, which must finish without the clock moving.
    async fn at_once<T>(f: impl Future<Output = T>) -> T {
        let started = Instant::now();
        let out = f.await;
        assert_eq!(started.elapsed(), Duration::ZERO, "it waited");
        out
    }

    fn assert_all_back(budget: &Budget) {
        assert_eq!(budget.free(), budget.limits().0);
        assert_eq!(budget.ledger_len(), 0);
        assert_eq!(budget.waiting_len(), 0);
    }

    async fn upload(budget: &Arc<Budget>, key: &str, first: u64) -> Upload {
        let who = caller(key);
        budget.admit(&who, first, first, WAIT).await.unwrap()
    }

    async fn holding(budget: &Arc<Budget>, key: &str, n: u64) -> Held {
        let who = caller(key);
        budget.take(&who, n, Class::Ordinary, WAIT).await.unwrap()
    }

    /// Grows `upload` in a task of its own, handing it back with the result.
    fn grow_in_task(mut upload: Upload, to: u64) -> JoinHandle<(Upload, Result<(), Busy>)> {
        tokio::spawn(async move {
            let result = upload.grow(to, Class::Large).await;
            (upload, result)
        })
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_first_grant_and_the_pledge_count_against_the_caller_only() {
        let budget = budget();
        let alice = caller("alice");
        let bob = caller("bob");
        let upload = at_once(budget.admit(&alice, 5, 70, WAIT)).await.unwrap();
        assert_eq!(upload.held(), 5);
        assert_eq!(budget.free(), 95, "a pledge moves nothing shared");
        assert_eq!(budget.used(&alice), 70);
        assert_eq!(budget.used(&bob), 0);

        let other = at_once(budget.admit(&bob, 5, 0, WAIT)).await.unwrap();
        assert_eq!(budget.used(&bob), 5, "the first grant is charged whole");
        drop(upload);
        drop(other);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn grants_use_the_pledge_before_charging_more() {
        let budget = budget();
        let alice = caller("alice");
        let mut upload = budget.admit(&alice, 5, 30, WAIT).await.unwrap();
        upload.grow(30, Class::Large).await.unwrap();
        assert_eq!((upload.held(), budget.free()), (30, 70));
        assert_eq!(budget.used(&alice), 30, "all of it was pledged");
        upload.grow(40, Class::Large).await.unwrap();
        assert_eq!(budget.used(&alice), 40, "only the excess is charged");
        upload.grow(20, Class::Large).await.unwrap();
        assert_eq!(upload.held(), 40, "growing to less changes nothing");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn finishing_gives_back_the_pledge_and_keeps_what_is_held() {
        let budget = budget();
        let alice = caller("alice");
        let upload = budget.admit(&alice, 5, 70, WAIT).await.unwrap();
        let held = upload.finish();
        assert_eq!(budget.used(&alice), 5);
        assert_eq!(budget.free(), 95);
        drop(held);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn nothing_asked_for_needs_nothing_and_leaves_no_entry() {
        let budget = budget();
        let alice = caller("alice");
        let filler = holding(&budget, "filler", 80).await;
        let more = holding(&budget, "more", 20).await;

        let mut upload = at_once(budget.admit(&alice, 0, 0, WAIT)).await.unwrap();
        assert_eq!(budget.used(&alice), 0);
        assert_eq!(budget.ledger_len(), 2, "no entry for nothing");
        at_once(upload.grow(0, Class::Large)).await.unwrap();
        let answer = at_once(upload.answer(0, Class::Large)).await.unwrap();
        let zero = budget.take(&alice, 0, Class::Large, NO_WAIT).await.unwrap();
        drop((answer, zero, upload, filler, more));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_caller_over_its_cap_is_refused_at_once() {
        let budget = budget();
        let alice = caller("alice");

        // At admission, with no wait, and the caller's other requests count.
        let over = at_once(budget.admit(&alice, 5, 81, WAIT)).await;
        assert_eq!(over.err(), Some(Busy::Cap));
        let first = budget.admit(&alice, 5, 70, WAIT).await.unwrap();
        let over = at_once(budget.admit(&alice, 5, 11, WAIT)).await;
        assert_eq!(over.err(), Some(Busy::Cap));
        assert_eq!(budget.used(&alice), 70, "a refusal charges nothing");

        // At growth, past what is pledged.
        let mut growing = budget.admit(&alice, 5, 5, WAIT).await.unwrap();
        let over = at_once(growing.grow(11, Class::Ordinary)).await;
        assert_eq!(over, Err(Busy::Cap));
        at_once(growing.grow(10, Class::Ordinary)).await.unwrap();

        // At the answer, and by `take`.
        let over = at_once(growing.answer(1, Class::Ordinary)).await;
        assert_eq!(over.err(), Some(Busy::Cap));
        let over = at_once(budget.take(&alice, 1, Class::Ordinary, WAIT)).await;
        assert_eq!(over.err(), Some(Busy::Cap));

        // Another caller is untouched, all the while.
        let bob = caller("bob");
        let bob = at_once(budget.admit(&bob, 5, 80, WAIT)).await;
        drop((bob, growing, first));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn what_a_caller_waits_for_counts_against_its_cap() {
        let budget = budget();
        let alice = caller("alice");
        let filler = holding(&budget, "filler", 80).await;

        let waiter = {
            let budget = Arc::clone(&budget);
            let alice = alice.clone();
            tokio::spawn(async move { budget.take(&alice, 50, Class::Ordinary, WAIT).await.map(drop) })
        };
        settle().await;
        assert!(!waiter.is_finished());
        assert_eq!(budget.free(), 20, "it holds none of it");
        assert_eq!(budget.used(&alice), 50);
        let over = at_once(budget.take(&alice, 31, Class::Ordinary, WAIT)).await;
        assert_eq!(over.err(), Some(Busy::Cap));

        drop(filler);
        assert_eq!(waiter.await.unwrap(), Ok(()));
        assert_all_back(&budget);
    }

    /// Where a request can wait for memory: the three waits of a request.
    #[derive(Clone, Copy)]
    enum At {
        Admission,
        Growth,
        Answer,
    }

    async fn wants_fifty(budget: Arc<Budget>, at: At) -> Result<(), Busy> {
        let big = caller("big");
        match at {
            At::Admission => budget.admit(&big, 50, 50, WAIT).await.map(drop),
            At::Growth => {
                let mut upload = budget.admit(&big, 5, 5, WAIT).await?;
                upload.grow(55, Class::Large).await
            }
            At::Answer => {
                let mut upload = budget.admit(&big, 5, 5, WAIT).await?;
                upload.answer(50, Class::Large).await.map(drop)
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_large_waiter_delays_no_one_that_fits() {
        for at in [At::Admission, At::Growth, At::Answer] {
            let budget = budget();
            let filler = holding(&budget, "filler", 60).await;
            let waiter = tokio::spawn(wants_fifty(Arc::clone(&budget), at));
            settle().await;
            assert!(!waiter.is_finished(), "the large request must be waiting");

            let small = at_once(holding(&budget, "small", 10)).await;
            let body = at_once(upload(&budget, "body", 10)).await;
            assert!(!waiter.is_finished());

            drop((filler, small, body));
            assert_eq!(waiter.await.unwrap(), Ok(()));
            assert_all_back(&budget);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_release_wakes_every_waiter_that_now_fits() {
        let budget = budget();
        let filler = holding(&budget, "filler", 80).await;
        let waiters: Vec<_> = ["a", "b", "c"]
            .map(|key| {
                let budget = Arc::clone(&budget);
                tokio::spawn(async move {
                    let n = 30;
                    budget
                        .take(&caller(key), n, Class::Ordinary, WAIT)
                        .await
                        .map(|held| tokio::spawn(sleep_then_drop(held)))
                })
            })
            .into_iter()
            .collect();
        settle().await;
        let started = Instant::now();
        drop(filler);
        for waiter in waiters {
            assert!(waiter.await.unwrap().is_ok());
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
        sleep(Duration::from_secs(2)).await;
        assert_all_back(&budget);
    }

    async fn sleep_then_drop(held: Held) {
        sleep(Duration::from_secs(1)).await;
        drop(held);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn large_bodies_stop_at_the_reserve_and_ordinary_requests_go_on() {
        let budget = budget();
        let filler = holding(&budget, "filler", 80).await;

        let mut body = upload(&budget, "body", 5).await;
        body.grow(10, Class::Large).await.unwrap();
        assert_eq!(budget.free(), 10, "exactly the reserve is left");
        body.left = NO_WAIT;
        let stopped = at_once(body.grow(11, Class::Large)).await;
        assert_eq!(stopped, Err(Busy::Full));

        // An ordinary body, an answer and a plain take may all use it.
        let ordinary = at_once(upload(&budget, "ordinary", 4)).await;
        let share = at_once(body.answer(3, Class::Ordinary)).await.unwrap();
        let take = at_once(holding(&budget, "take", 3)).await;
        assert_eq!(budget.free(), 0);

        // Large takes stop at it whatever they are for.
        drop((take, share));
        let who = caller("take");
        let large = budget.take(&who, 1, Class::Large, NO_WAIT).await;
        assert_eq!(large.err(), Some(Busy::Full));
        drop((ordinary, body, filler));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_younger_upload_gives_way_to_an_older_one_already_waiting() {
        let budget = budget();
        let older = upload(&budget, "older", 40).await;
        let mut younger = upload(&budget, "younger", 40).await;

        let older = grow_in_task(older, 60);
        settle().await;
        assert!(!older.is_finished());
        assert_eq!(budget.waiting_len(), 1);

        let refused = at_once(younger.grow(60, Class::Large)).await;
        assert_eq!(refused, Err(Busy::Full));
        assert!(!older.is_finished(), "only freed memory lets the older on");
        assert_eq!(budget.waiting_len(), 1, "the refused left no trace");

        drop(younger);
        let started = Instant::now();
        let (older, result) = older.await.unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(older.held(), 60);
        drop(older);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn an_older_upload_starting_to_wait_wakes_and_refuses_a_younger_one() {
        let budget = budget();
        let older = upload(&budget, "older", 40).await;
        let younger = upload(&budget, "younger", 40).await;

        let younger = grow_in_task(younger, 60);
        settle().await;
        assert!(!younger.is_finished());
        let started = Instant::now();
        let older = grow_in_task(older, 60);

        let (younger, refused) = younger.await.unwrap();
        assert_eq!(refused, Err(Busy::Full));
        assert_eq!(started.elapsed(), Duration::ZERO);
        drop(younger);
        let (older, result) = older.await.unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(started.elapsed(), Duration::ZERO);
        drop(older);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn of_two_uploads_that_do_not_fit_exactly_one_is_refused() {
        for younger_first in [false, true] {
            let budget = budget();
            let older = upload(&budget, "older", 40).await;
            let younger = upload(&budget, "younger", 40).await;
            let run =
                |mut upload: Upload| tokio::spawn(async move { upload.grow(60, Class::Large).await.map(|()| upload) });
            let (older, younger) = if younger_first {
                let younger = run(younger);
                (run(older), younger)
            } else {
                let older = run(older);
                (older, run(younger))
            };
            // A refused upload is dropped by its task, as a handler would.
            let older = older.await.unwrap();
            let younger = younger.await.unwrap();
            assert_eq!(younger.as_ref().err(), Some(&Busy::Full));
            assert_eq!(older.as_ref().map(Upload::held).ok(), Some(60));
            drop(older);
            assert_all_back(&budget);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn an_older_upload_waiting_for_its_answer_evicts_a_younger_one_growing() {
        let budget = budget();
        let mut older = upload(&budget, "older", 40).await;
        let younger = upload(&budget, "younger", 40).await;

        // The younger is parked first, so the answer's arrival must wake it.
        let younger = grow_in_task(younger, 60);
        settle().await;
        assert!(!younger.is_finished());
        let answer = tokio::spawn(async move {
            let answer = older.answer(30, Class::Large).await;
            (older, answer)
        });
        let (younger, refused) = younger.await.unwrap();
        assert_eq!(refused, Err(Busy::Full));
        drop(younger);
        let (older, answer) = answer.await.unwrap();
        let answer = answer.unwrap();
        assert_eq!(budget.free(), 30);
        assert_eq!(older.left(), WAIT, "no time passed");
        drop((older, answer));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_younger_upload_that_fits_does_not_yield() {
        let budget = budget();
        let older = upload(&budget, "older", 40).await;
        let mut younger = upload(&budget, "younger", 30).await;
        let older = grow_in_task(older, 75);
        settle().await;
        assert!(!older.is_finished());

        at_once(younger.grow(35, Class::Large)).await.unwrap();
        assert_eq!(younger.held(), 35);
        drop(younger);
        let (older, result) = older.await.unwrap();
        assert_eq!(result, Ok(()));
        drop(older);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ordinary_waits_take_no_part_in_seniority() {
        let budget = budget();
        let mut older = upload(&budget, "older", 40).await;
        let mut younger = upload(&budget, "younger", 40).await;

        // An older upload waiting as ordinary does not register.
        let result = timeout(Duration::from_secs(1), older.grow(65, Class::Ordinary));
        assert!(result.await.is_err(), "it waits");
        assert_eq!(budget.waiting_len(), 0);

        // And an ordinary request never yields to one that did.
        let large = tokio::spawn(async move {
            let result = older.grow(70, Class::Large).await;
            (older, result)
        });
        settle().await;
        assert_eq!(budget.waiting_len(), 1);
        let ordinary = timeout(Duration::from_secs(1), younger.grow(65, Class::Ordinary));
        assert!(ordinary.await.is_err(), "it waits, it is not refused");
        drop(younger);
        let (older, result) = large.await.unwrap();
        assert_eq!(result, Ok(()));
        drop(older);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_oldest_times_out_when_what_it_needs_is_not_waiting() {
        let budget = budget_with_no_cap();
        let job = holding(&budget, "job", 85).await;
        let mut oldest = upload(&budget, "oldest", 5).await;

        let started = Instant::now();
        assert_eq!(oldest.grow(30, Class::Large).await, Err(Busy::Full));
        assert_eq!(started.elapsed(), WAIT);
        assert_eq!(oldest.left(), Duration::ZERO);
        assert_eq!(budget.waiting_len(), 0);
        drop((oldest, job));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_allowance_is_spent_across_all_of_a_requests_waits() {
        let budget = budget();
        let released = holding(&budget, "a", 20).await;
        let job = holding(&budget, "b", 65).await;
        let who = caller("c");
        let wait = Duration::from_secs(10);
        let mut upload = budget.admit(&who, 5, 5, wait).await.unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_secs(4)).await;
            drop(released);
        });

        // Four seconds of it go here.
        let started = Instant::now();
        upload.grow(20, Class::Large).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(4));
        assert_eq!(upload.left(), Duration::from_secs(6));

        // The rest here, nothing being released.
        assert_eq!(upload.grow(45, Class::Large).await, Err(Busy::Full));
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(upload.left(), Duration::ZERO);

        // And with none left, waits are refused without waiting, at every wait.
        let grow = at_once(upload.grow(45, Class::Large)).await;
        assert_eq!(grow, Err(Busy::Full));
        let answer = at_once(upload.answer(45, Class::Large)).await;
        assert_eq!(answer.err(), Some(Busy::Full));
        assert_eq!(budget.waiting_len(), 0);
        drop((upload, job));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_time_spent_at_admission_comes_off_the_allowance() {
        let budget = budget_with_no_cap();
        let job = holding(&budget, "job", 100).await;
        tokio::spawn(sleep_then_drop(job));
        let who = caller("a");
        let wait = Duration::from_secs(10);
        let upload = budget.admit(&who, 5, 5, wait).await.unwrap();
        assert_eq!(upload.left(), Duration::from_secs(9));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_take_with_no_allowance_is_refused_without_waiting() {
        let budget = budget_with_no_cap();
        let job = holding(&budget, "job", 100).await;
        let who = caller("a");
        let take = budget.take(&who, 1, Class::Ordinary, NO_WAIT);
        assert_eq!(at_once(take).await.err(), Some(Busy::Full));
        let started = Instant::now();
        let take = budget.take(&who, 1, Class::Ordinary, WAIT);
        assert_eq!(take.await.err(), Some(Busy::Full));
        assert_eq!(started.elapsed(), WAIT);
        drop(job);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn an_answered_request_gives_everything_back() {
        let budget = budget();
        let who = caller("a");
        let mut sized = budget.admit(&who, 5, 30, WAIT).await.unwrap();
        sized.grow(20, Class::Large).await.unwrap();
        let share = sized.answer(10, Class::Large).await.unwrap();
        assert_eq!(budget.free(), 70);
        let body = sized.finish();
        assert_eq!(budget.used(&who), 30);
        drop(body);
        assert_eq!(budget.used(&who), 10, "the answer outlives the body");
        drop(share);
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_finished_body_keeps_its_pledged_answer_within_the_cap() {
        let budget = budget();
        let alice = caller("alice");
        let mut sized = budget.admit(&alice, 5, 80, WAIT).await.unwrap();
        sized.grow(70, Class::Large).await.unwrap();
        let share = at_once(sized.answer(10, Class::Ordinary)).await.unwrap();
        assert_eq!(budget.used(&alice), 80, "exactly the cap, and no refusal");
        drop((sized, share));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_refused_request_gives_everything_back() {
        let budget = budget();
        let who = caller("a");
        let mut capped = budget.admit(&who, 5, 70, WAIT).await.unwrap();
        assert_eq!(capped.grow(81, Class::Large).await, Err(Busy::Cap));
        drop(capped);
        assert_all_back(&budget);

        let budget = budget_with_no_cap();
        let job = holding(&budget, "job", 95).await;
        let mut full = budget.admit(&who, 5, 5, NO_WAIT).await.unwrap();
        assert_eq!(full.grow(20, Class::Large).await, Err(Busy::Full));
        assert_eq!(budget.used(&who), 20, "still the upload's");
        let answer = full.answer(20, Class::Large).await;
        assert_eq!(answer.err(), Some(Busy::Full));
        drop((full, job));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_wait_dropped_part_way_gives_everything_back() {
        const SHORT: Duration = Duration::from_secs(1);
        let budget = budget_with_no_cap();
        let job = holding(&budget, "job", 90).await;
        let alice = caller("alice");

        assert!(timeout(SHORT, budget.admit(&alice, 20, 20, WAIT)).await.is_err());
        assert_eq!(budget.used(&alice), 0, "admission");
        let take = budget.take(&alice, 20, Class::Ordinary, WAIT);
        assert!(timeout(SHORT, take).await.is_err());
        assert_eq!(budget.used(&alice), 0, "take");

        let mut older = budget.admit(&alice, 5, 5, WAIT).await.unwrap();
        assert!(timeout(SHORT, older.grow(50, Class::Large)).await.is_err());
        assert_eq!(budget.waiting_len(), 0, "growth");
        assert_eq!(budget.used(&alice), 50, "pledged until the upload goes");
        assert!(timeout(SHORT, older.answer(20, Class::Large)).await.is_err());
        assert_eq!(budget.waiting_len(), 0, "answer");

        // A dropped wait leaves no place behind for others to yield to.
        let mut younger = upload(&budget, "b", 5).await;
        let wait = timeout(SHORT, younger.grow(50, Class::Large));
        assert!(wait.await.is_err(), "it waits, it is not refused");

        drop((older, younger, job));
        assert_all_back(&budget);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_panic_in_a_job_gives_everything_back() {
        let budget = budget();
        let alice = caller("alice");
        let mut upload = budget.admit(&alice, 5, 30, WAIT).await.unwrap();
        let answer = upload.answer(10, Class::Ordinary).await.unwrap();
        let body = upload.finish();
        let job = tokio::task::spawn_blocking(move || {
            let _held = (body, answer);
            panic!("the job failed");
        });
        assert!(job.await.unwrap_err().is_panic());
        assert_all_back(&budget);
    }

    #[derive(Clone, Copy)]
    struct Xorshift(u64);

    impl Xorshift {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// One request's random path through the budget, checking the ledger
    /// after each step. Returns whether it was refused on the cap.
    async fn wander(budget: &Arc<Budget>, rng: &mut Xorshift) -> bool {
        let (total, _, cap) = budget.limits();
        let who = caller(["a", "b", "c", "d", "e"][rng.below(5) as usize]);
        let first = rng.below(total / 16);
        let pledge = rng.below(cap * 5 / 4);
        let wait = Duration::from_micros(rng.below(2000));

        let admitted = if rng.below(4) == 0 {
            let admit = budget.admit(&who, first, pledge, wait);
            let cut = Duration::from_micros(rng.below(500));
            timeout(cut, admit).await.unwrap_or(Err(Busy::Full))
        } else {
            budget.admit(&who, first, pledge, wait).await
        };
        budget.check();
        let mut upload = match admitted {
            Ok(upload) => upload,
            Err(busy) => return busy == Busy::Cap,
        };

        let class = |rng: &mut Xorshift| match rng.below(2) {
            0 => Class::Ordinary,
            _ => Class::Large,
        };
        for _ in 0..rng.below(5) {
            let to = upload.held() + rng.below(total / 8);
            let class = class(rng);
            let grown = if rng.below(3) == 0 {
                let cut = Duration::from_micros(rng.below(500));
                timeout(cut, upload.grow(to, class)).await.unwrap_or(Ok(()))
            } else {
                upload.grow(to, class).await
            };
            budget.check();
            if grown.is_err() {
                return grown == Err(Busy::Cap);
            }
            tokio::task::yield_now().await;
        }

        let n = rng.below(total / 8);
        let class = class(rng);
        let answer = if rng.below(3) == 0 {
            let cut = Duration::from_micros(rng.below(500));
            timeout(cut, upload.answer(n, class)).await
        } else {
            Ok(upload.answer(n, class).await)
        };
        budget.check();
        let held = rng.below(2) == 0;
        match answer {
            Ok(Ok(answer)) if held => {
                let body = upload.finish();
                budget.check();
                sleep(Duration::from_micros(rng.below(300))).await;
                drop((answer, body));
            }
            Ok(Ok(answer)) => drop((answer, upload)),
            Ok(Err(busy)) => return busy == Busy::Cap,
            Err(_cancelled) => {}
        }
        budget.check();
        false
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_ledger_stays_sound_under_random_requests() {
        const TOTAL: u64 = 1 << 20;
        let budget = Budget::new(TOTAL, TOTAL / 8, TOTAL / 2);
        let mut tasks = JoinSet::new();
        for task in 1..=32u64 {
            let budget = Arc::clone(&budget);
            tasks.spawn(async move {
                let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(task));
                let mut capped = 0;
                for _ in 0..300 {
                    capped += u32::from(wander(&budget, &mut rng).await);
                }
                capped
            });
        }
        let mut capped = 0;
        while let Some(task) = tasks.join_next().await {
            capped += task.expect("a task failed");
        }
        assert!(capped > 0, "no request reached the cap: a weak test");
        assert_all_back(&budget);
    }
}
