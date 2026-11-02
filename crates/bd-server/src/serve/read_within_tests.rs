//! `read_within` and `Segments`. Bodies are scripted and the clock is paused,
//! so a test of a minute takes no time and every poll of a body can look at
//! the budget. Connections and the handlers are tested in
//! `crates/bd/tests/remote.rs`.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use hyper::body::{Frame, SizeHint};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, Sleep, sleep};

use super::*;
use crate::budget::{Budget, Held};

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
const MAX: usize = 64 * MIB;
const TOTAL: u64 = 256 << 20;
const NOW: Duration = Duration::ZERO;

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The default server's budget.
fn server_budget() -> Arc<Budget> {
    Budget::new(TOTAL, RESERVE as u64, (BODY_COPIES * MAX + ANSWER_BUDGET) as u64)
}

/// A budget with neither reserve nor cap to think of.
fn plain_budget(total: usize) -> Arc<Budget> {
    Budget::new(total as u64, 0, total as u64)
}

enum Next {
    Data(Bytes),
    Trailers,
    Fail,
    End,
}

/// What a body does next, once this long has passed since it was polled.
type Step = (Duration, Next);

fn data(after: Duration, n: usize) -> Step {
    (after, Next::Data(Bytes::from(vec![b'x'; n])))
}

/// `frames` frames of `n` bytes, one every `every`.
fn steady(frames: usize, every: Duration, n: usize) -> Vec<Step> {
    let frame = Bytes::from(vec![b'x'; n]);
    (0..frames).map(|_| (every, Next::Data(frame.clone()))).collect()
}

/// Longer than any body lasts.
fn silence() -> Step {
    (secs(3600), Next::End)
}

/// What a poll of a body saw.
#[derive(Clone, Copy)]
struct Seen {
    at: Duration,
    received: u64,
    in_use: u64,
}

type Polls = Arc<Mutex<Vec<Seen>>>;

/// A request body that plays its steps on the paused clock. Like hyper's, its
/// size hint shrinks as frames are read. Every poll checks the budget's
/// ledger and notes what is in use.
struct Scripted {
    steps: VecDeque<Step>,
    exact: Option<u64>,
    sent: u64,
    timer: Option<Pin<Box<Sleep>>>,
    budget: Arc<Budget>,
    began: Instant,
    polls: Polls,
}

impl Scripted {
    fn new(budget: &Arc<Budget>, exact: Option<u64>, steps: Vec<Step>) -> (Scripted, Polls) {
        let polls = Polls::default();
        let body = Scripted {
            steps: steps.into(),
            exact,
            sent: 0,
            timer: None,
            budget: Arc::clone(budget),
            began: Instant::now(),
            polls: Arc::clone(&polls),
        };
        (body, polls)
    }

    fn note(&self) {
        self.budget.check();
        let (total, _, _) = self.budget.limits();
        let seen = Seen { at: self.began.elapsed(), received: self.sent, in_use: total - self.budget.free() };
        lock(&self.polls).push(seen);
    }
}

impl hyper::body::Body for Scripted {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<std::io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.timer.is_none() {
            this.note();
        }
        let Some((after, _)) = this.steps.front() else { return Poll::Ready(None) };
        let after = *after;
        if !after.is_zero() {
            ready!(this.timer.get_or_insert_with(|| Box::pin(sleep(after))).as_mut().poll(cx));
            this.timer = None;
        }
        Poll::Ready(match this.steps.pop_front().map(|(_, next)| next) {
            Some(Next::Data(bytes)) => {
                this.sent += bytes.len() as u64;
                Some(Ok(Frame::data(bytes)))
            }
            Some(Next::Trailers) => Some(Ok(Frame::trailers(HeaderMap::new()))),
            Some(Next::Fail) => Some(Err(std::io::Error::other("the connection was reset"))),
            Some(Next::End) | None => None,
        })
    }

    fn size_hint(&self) -> SizeHint {
        self.exact.map_or_else(SizeHint::default, |n| SizeHint::with_exact(n.saturating_sub(self.sent)))
    }
}

struct Read {
    result: std::result::Result<Vec<u8>, BodyError>,
    took: Duration,
    polls: Vec<Seen>,
}

/// Admits a request as the handlers do, and reads `steps` as its body.
async fn read(budget: &Arc<Budget>, exact: Option<u64>, max: usize, steps: Vec<Step>) -> Read {
    let (first, pledge) = first_and_pledge(exact, max, ANSWER_BUDGET);
    let mut upload = budget.admit(&Budget::caller("alice"), first, pledge, QUEUE_WAIT).await.unwrap();
    let (body, polls) = Scripted::new(budget, exact, steps);
    let started = Instant::now();
    let result = read_within(body, max, &mut upload).await;
    let took = started.elapsed();
    let polls = lock(&polls).clone();
    Read { result, took, polls }
}

async fn held_by_another(budget: &Arc<Budget>, n: usize) -> Held {
    budget.take(&Budget::caller("another"), n as u64, Class::Ordinary, NOW).await.unwrap()
}

fn release_after(after: Duration, held: Held) -> JoinHandle<()> {
    tokio::spawn(async move {
        sleep(after).await;
        drop(held);
    })
}

fn assert_all_back(budget: &Budget) {
    assert_eq!(budget.free(), budget.limits().0);
    assert_eq!(budget.ledger_len(), 0);
    assert_eq!(budget.waiting_len(), 0);
}

/// `took` is `at`, to the granularity of tokio's timers.
#[track_caller]
fn assert_took(took: Duration, at: Duration) {
    assert!(took >= at && took <= at + Duration::from_millis(5), "took {took:?}, not {at:?}");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_holds_what_has_arrived_and_no_more() {
    let len = 4 * MIB;
    for exact in [None, Some(len as u64)] {
        let budget = server_budget();
        let got = read(&budget, exact, MAX, steady(len / (64 * KIB), Duration::from_millis(1), 64 * KIB)).await;
        assert_eq!(got.result.unwrap().len(), len);
        assert!(got.polls.len() > 64, "every frame was seen");
        for seen in got.polls {
            assert!(seen.in_use <= (FIRST_GRANT + BODY_COPIES * seen.received as usize) as u64, "{}", seen.in_use);
            assert!(exact.is_none() || seen.in_use <= (BODY_COPIES * len) as u64, "{}", seen.in_use);
            assert!(seen.in_use >= (BODY_COPIES * seen.received as usize) as u64, "less than it needs");
        }
        assert_all_back(&budget);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_small_body_never_holds_more_than_twice_its_size() {
    let budget = server_budget();
    let got = read(&budget, Some(KIB as u64), MAX, steady(2, NOW, KIB / 2)).await;
    assert_eq!(got.result.unwrap().len(), KIB);
    assert!(got.polls.iter().all(|seen| seen.in_use <= (BODY_COPIES * KIB) as u64));
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn declaring_a_size_moves_nothing_shared() {
    let budget = server_budget();
    let alice = Budget::caller("alice");
    let declared = 125 * MIB / 2;
    let (first, pledge) = first_and_pledge(Some(declared as u64), MAX, ANSWER_BUDGET);
    let upload = budget.admit(&alice, first, pledge, QUEUE_WAIT).await.unwrap();
    assert_eq!(budget.free(), TOTAL - FIRST_GRANT as u64, "only the first grant");
    assert_eq!(budget.used(&alice), (BODY_COPIES * declared + ANSWER_BUDGET) as u64);
    drop(upload);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_that_stops_part_way_holds_no_answer_share() {
    let budget = server_budget();
    let alice = Budget::caller("alice");
    let declared = 32 * MIB;
    let (first, pledge) = first_and_pledge(Some(declared as u64), MAX, ANSWER_BUDGET);
    let mut upload = budget.admit(&alice, first, pledge, QUEUE_WAIT).await.unwrap();

    let mut steps = steady(8, Duration::from_millis(10), 256 * KIB);
    steps.push(silence());
    let (body, polls) = Scripted::new(&budget, Some(declared as u64), steps);
    let result = read_within(body, MAX, &mut upload).await;
    assert!(matches!(result, Err(BodyError::Slow)), "{result:?}");

    let polls = lock(&polls);
    assert!(polls.len() > 8);
    for seen in polls.iter() {
        assert!(seen.in_use <= (FIRST_GRANT + BODY_COPIES * seen.received as usize) as u64, "{}", seen.in_use);
    }
    assert_eq!(budget.free(), TOTAL - upload.held(), "up to the point it was cut");
    assert_eq!(budget.used(&alice), pledge, "still pledged, and only pledged");
    drop(upload);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn uploads_at_once_keep_the_ledger_sound() {
    let budget = Budget::new(8 << 20, 1 << 20, 6 << 20);
    let mut uploads = JoinSet::new();
    for n in 0..24 {
        let budget = Arc::clone(&budget);
        uploads.spawn(async move {
            let caller = Budget::caller(&format!("caller {}", n % 4));
            let frames = 6 + n % 8;
            let exact = (n % 2 == 0).then_some((frames * 256 * KIB) as u64);
            let (first, pledge) = first_and_pledge(exact, 4 * MIB, 64 * KIB);
            let Ok(mut upload) = budget.admit(&caller, first, pledge, QUEUE_WAIT).await else { return false };
            let every = Duration::from_millis(500 + 250 * n as u64);
            let (body, _) = Scripted::new(&budget, exact, steady(frames, every, 256 * KIB));
            let answered = match read_within(body, 4 * MIB, &mut upload).await {
                Ok(bytes) => upload.answer(64 << 10, class_of(bytes.len())).await.ok(),
                Err(BodyError::Busy(_)) => None,
                Err(e) => panic!("{e:?}"),
            };
            budget.check();
            let held = answered.map(|answer| (answer, upload.finish()));
            sleep(Duration::from_millis(250)).await;
            held.is_some()
        });
    }
    let (mut served, mut refused) = (0, 0);
    while let Some(outcome) = uploads.join_next().await {
        if outcome.unwrap() {
            served += 1;
        } else {
            refused += 1;
        }
    }
    assert!(served > 0 && refused > 0, "{served} served and {refused} refused: too easy to show anything");
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_byte_a_second_is_cut_at_30_s() {
    let budget = server_budget();
    let got = read(&budget, None, MAX, steady(120, secs(1), 1)).await;
    assert!(matches!(got.result, Err(BodyError::Slow)), "{:?}", got.result);
    assert_took(got.took, BODY_WINDOW);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_sized_body_is_cut_as_a_chunked_one_is() {
    let budget = server_budget();
    let got = read(&budget, Some(125 * MIB as u64 / 2), MAX, steady(120, secs(1), 1)).await;
    assert!(matches!(got.result, Err(BodyError::Slow)), "{:?}", got.result);
    assert_took(got.took, BODY_WINDOW);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_sent_at_once_is_cut_within_a_minute_of_going_silent() {
    let budget = server_budget();
    let mut steps = steady(MAX / MIB, NOW, MIB);
    steps.push(silence());
    let got = read(&budget, None, MAX, steps).await;
    assert!(matches!(got.result, Err(BodyError::Slow)), "{:?}", got.result);
    assert_took(got.took, 2 * BODY_WINDOW);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_steady_17_kib_a_second_completes() {
    let budget = server_budget();
    let got = read(&budget, None, MAX, steady(90, secs(1), 17 * KIB)).await;
    assert_eq!(got.result.unwrap().len(), 90 * 17 * KIB);
    assert_took(got.took, secs(90));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_steady_15_kib_a_second_does_not() {
    let budget = server_budget();
    let got = read(&budget, None, MAX, steady(90, secs(1), 15 * KIB)).await;
    assert!(matches!(got.result, Err(BodyError::Slow)), "{:?}", got.result);
    assert_took(got.took, BODY_WINDOW);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_finishing_inside_the_window_completes() {
    let budget = server_budget();
    let end = (Duration::from_millis(29_900), Next::End);
    let got = read(&budget, None, MAX, vec![data(NOW, 1), end]).await;
    assert_eq!(got.result.unwrap().len(), 1);
    assert_took(got.took, Duration::from_millis(29_900));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_frame_after_its_window_does_not_save_it() {
    for late in [BODY_WINDOW, BODY_WINDOW + Duration::from_millis(1)] {
        let budget = server_budget();
        let got = read(&budget, None, MAX, vec![data(NOW, 1), data(late, MIB)]).await;
        assert!(matches!(got.result, Err(BodyError::Slow)), "{:?}", got.result);
        assert_took(got.took, BODY_WINDOW);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_memory_wait_counts_in_no_window() {
    let budget = plain_budget(4 * MIB);
    let release = release_after(secs(12), held_by_another(&budget, 3900 * KIB).await);
    // Under 480 KiB by the end of the first 30 s, were the wait counted.
    let got = read(&budget, None, MAX, vec![data(NOW, 400 * KIB), data(secs(25), 200 * KIB)]).await;
    assert_eq!(got.result.unwrap().len(), 600 * KIB);
    assert_took(got.took, secs(37));
    assert_took(got.polls[1].at, secs(12));
    release.await.unwrap();
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn memory_waits_end_once_15_s_is_spent() {
    let budget = plain_budget(1200 * KIB);
    let pieces = [
        held_by_another(&budget, 356 * KIB).await,
        held_by_another(&budget, 356 * KIB).await,
        held_by_another(&budget, 356 * KIB).await,
    ];
    let releases: Vec<_> = pieces.into_iter().zip(1..).map(|(held, n)| release_after(n * secs(6), held)).collect();
    // Each frame needs what the next release gives; the third comes too late.
    let steps = vec![data(NOW, 100 * KIB), data(NOW, 100 * KIB), data(NOW, 300 * KIB), silence()];
    let got = read(&budget, None, MAX, steps).await;
    assert!(matches!(got.result, Err(BodyError::Busy(Busy::Full))), "{:?}", got.result);
    assert_took(got.took, QUEUE_WAIT);
    for release in releases {
        release.await.unwrap();
    }
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_whole_limit_is_120_s() {
    let budget = server_budget();
    let got = read(&budget, None, MAX, steady(200, secs(1), 20 * KIB)).await;
    assert!(matches!(got.result, Err(BodyError::Late(wait)) if wait == BODY_TIMEOUT), "{:?}", got.result);
    assert_took(got.took, BODY_TIMEOUT);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_frame_always_ready_does_not_outrun_the_whole_limit() {
    let budget = server_budget();
    let mut steps = steady(120, secs(1), 20 * KIB);
    steps.extend(steady(4, NOW, 20 * KIB));
    let got = read(&budget, None, MAX, steps).await;
    assert!(matches!(got.result, Err(BodyError::Late(_))), "{:?}", got.result);
    assert_took(got.took, BODY_TIMEOUT);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reading_ends_by_135_s_however_long_it_waited() {
    let budget = plain_budget(8 * MIB);
    let release = release_after(secs(14), held_by_another(&budget, 8 * MIB - 196 * KIB).await);
    let mut steps = vec![data(NOW, 400 * KIB)];
    steps.extend(steady(200, secs(1), 20 * KIB));
    let got = read(&budget, None, MAX, steps).await;
    assert!(matches!(got.result, Err(BodyError::Late(_))), "{:?}", got.result);
    assert_took(got.took, BODY_TIMEOUT + secs(14));
    assert!(got.took <= BODY_TIMEOUT + QUEUE_WAIT);
    release.await.unwrap();
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_caller_at_its_cap_is_refused_part_way() {
    let budget = Budget::new(64 << 20, 0, 1 << 20);
    let got = read(&budget, None, MAX, steady(64, NOW, 64 * KIB)).await;
    assert!(matches!(got.result, Err(BodyError::Busy(Busy::Cap))), "{:?}", got.result);
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_past_the_limit_is_too_large_and_one_at_it_is_not() {
    for exact in [None, Some(MIB as u64)] {
        let budget = server_budget();
        let got = read(&budget, exact, MIB, steady(2, NOW, MIB / 2)).await;
        assert_eq!(got.result.unwrap().len(), MIB);

        let mut steps = steady(2, NOW, MIB / 2);
        steps.push(data(NOW, 1));
        let got = read(&budget, exact, MIB, steps).await;
        assert!(matches!(got.result, Err(BodyError::TooLarge)), "{:?}", got.result);
        assert_all_back(&budget);
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_body_stops_at_what_it_declared() {
    let budget = server_budget();
    let got = read(&budget, Some(KIB as u64), MAX, steady(2, NOW, KIB)).await;
    assert!(matches!(got.result, Err(BodyError::TooLarge)), "{:?}", got.result);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_unreadable_frame_says_why() {
    let budget = server_budget();
    let got = read(&budget, None, MAX, vec![data(NOW, 1), (NOW, Next::Fail)]).await;
    match got.result {
        Err(BodyError::Unreadable(why)) => assert_eq!(why, "the connection was reset"),
        other => panic!("{other:?}"),
    }
    assert_all_back(&budget);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_bytes_come_back_whole_across_segments_and_frames() {
    let budget = server_budget();
    let len = BODY_SEGMENT + 2000;
    let body: Vec<u8> = (0..len).map(|n| (n % 251) as u8).collect();
    let (head, tail) = body.split_at(BODY_SEGMENT - 1000);
    let mut steps = vec![(NOW, Next::Data(Bytes::copy_from_slice(head)))];
    steps.extend(tail.iter().map(|byte| (NOW, Next::Data(Bytes::copy_from_slice(&[*byte])))));
    steps.push((NOW, Next::Trailers));
    let got = read(&budget, Some(len as u64), MAX, steps).await;
    assert!(got.result.unwrap() == body);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_empty_body_is_empty() {
    let budget = server_budget();
    let got = read(&budget, Some(0), MAX, Vec::new()).await;
    assert!(got.result.unwrap().is_empty());
    assert_all_back(&budget);
}

#[test]
fn large_starts_past_one_mib_received() {
    assert_eq!(class_of(ORDINARY_BODY), Class::Ordinary);
    assert_eq!(class_of(ORDINARY_BODY + 1), Class::Large);
}

#[test]
fn a_segment_costs_little_after_one_push() {
    let mut segments = Segments::default();
    segments.push(b"x");
    assert!(segments.capacity() <= 64, "{}", segments.capacity());
}

#[test]
fn a_segment_never_passes_its_size_whatever_the_frames() {
    for frame in [1, 12 * KIB, 64 * KIB + 1, BODY_SEGMENT - 1, 3 * BODY_SEGMENT] {
        let mut segments = Segments::default();
        let mut pushed = 0;
        while pushed < 3 * BODY_SEGMENT {
            segments.push(&vec![b'x'; frame.min(3 * BODY_SEGMENT - pushed)]);
            pushed += frame;
        }
        assert_eq!(segments.parts.len(), 3, "{frame}");
        assert!(segments.parts.iter().all(|part| part.capacity() <= BODY_SEGMENT), "{frame}");
    }
}

#[test]
fn segments_join_in_order_across_the_boundary() {
    let body: Vec<u8> = (0..2 * BODY_SEGMENT + 17).map(|n| (n % 251) as u8).collect();
    let mut segments = Segments::default();
    for frame in body.chunks(BODY_SEGMENT / 3 + 5) {
        segments.push(frame);
    }
    assert_eq!(segments.parts.len(), 3);
    assert!(segments.join() == body);
}

#[test]
fn a_single_part_is_returned_without_copying() {
    let mut segments = Segments::default();
    segments.push(b"one part");
    let bytes = segments.parts[0].as_ptr();
    let joined = segments.join();
    assert_eq!(joined.as_ptr(), bytes);
    assert_eq!(joined, b"one part");
}

#[test]
fn no_segments_join_to_nothing() {
    assert!(Segments::default().join().is_empty());
}

/// The ADR's 4 MiB of 1-byte frames, without a socket or a timer. On the old
/// code every frame kept a buffer of its own; here they cost what arrived.
#[test]
fn segments_cost_what_arrived() {
    let body: Vec<u8> = (0..4 * MIB).map(|n| (n % 251) as u8).collect();
    let mut segments = Segments::default();
    for byte in &body {
        segments.push(std::slice::from_ref(byte));
    }
    assert!(segments.capacity() <= 5 * MIB, "{}", segments.capacity());
    assert!(segments.join() == body);
}

async fn answer_of(response: Response<Body>) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn a_slow_body_is_a_timeout_the_client_reads_as_remote() {
    let (status, answer) = answer_of(BodyError::Slow.response("request", MAX)).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(answer["error"]["code"], "remote");
    assert_eq!(answer["error"]["exit_code"], 8);
    assert_eq!(answer["error"]["message"], "the request body arrived slower than 16 KiB/s");

    let (status, answer) = answer_of(BodyError::Slow.oauth("invalid_request", MAX)).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(answer["error"], "invalid_request");
}

#[tokio::test]
async fn a_body_with_no_memory_is_busy() {
    let cases = [
        (Busy::Cap, "the server is busy with other requests of yours; retry shortly"),
        (Busy::Full, "the server is busy receiving other requests; retry shortly"),
    ];
    for (busy, message) in cases {
        let (status, answer) = answer_of(BodyError::Busy(busy).response("request", MAX)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer["error"]["code"], "busy");
        assert_eq!(answer["error"]["exit_code"], 5);
        assert_eq!(answer["error"]["message"], message);

        let (status, answer) = answer_of(BodyError::Busy(busy).oauth("invalid_request", MAX)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer["error"], "temporarily_unavailable");
    }
}
