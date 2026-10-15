//! Secrets of sign-in fetched by the admin's own command instead of read
//! from files: a vault, a cloud's secret manager, a password manager, bd
//! knowing none of them. Each field of `auth.toml` that names a secret file
//! (`github.private_key` and `client_secret_file`, `oidc.<name>`'s
//! `client_secret_file` and `signed_secret.key_file`, `authorizer.token_file`)
//! takes `{ secret = "<name>" }` instead of a path ([`Source`]), and
//! `[secrets]` names the command that fetches them:
//!
//! ```toml
//! [secrets]
//! command = ["bin/bd-secrets"]   # run as is, no shell (relative to the root if it has a /)
//! timeout = "10s"                # an answer within this (1s to 60s)
//! env = ["VAULT_CREDENTIALS"]    # passed to the command, besides PATH, HOME, LANG and Windows' basics
//! ttl = "10m"                    # how long an answer is good for, unless it says (1m to 24h)
//! max_stale = "1h"               # how long past that the last answer is used while the command fails (up to 7d)
//!
//! [github]
//! private_key = { secret = "github-app-key" }
//! ```
//!
//! It is asked for every secret at once (`{"version": 1, "secrets":
//! ["github-app-key"]}` on stdin) and answers with one JSON object
//! ([`Answer`]: `{"secrets": {"github-app-key": "..."}, "ttl": "10m"}` on
//! stdout), exactly the names asked. It runs as the authorizer's command
//! does (`helper.rs`).
//!
//! Answers are kept per root, in memory only ([`current`]). A keeper thread
//! per root asks again once three quarters of an answer's `ttl` passed (on
//! its own timer, whether requests come or not), at once when `auth.toml`
//! names fewer or other secrets or another command, and every
//! [`RETRY_AFTER`] while the command fails. A kept answer serves the
//! command that gave it and the names it gave, whatever else `[secrets]`
//! changes, up to `max_stale` past its `ttl`; then sign-in fails closed
//! (busy, try again) until the command answers. A new answer replaces the
//! kept one only once the fields it serves take it (a key must be a key),
//! and only if `auth.toml` still asks that command for those names when it
//! comes (or cannot be read just then: it serves that command only). Only
//! `bd serve check` waits for the command (and, in the background, the
//! server's report of its first answer); the server's start and requests
//! never do. bd never puts a value in the log, a message or `Debug`; the
//! command's stderr is logged when it fails, with the values it was last
//! given left out (only those: it must print none there). Names are no
//! secrets, and failures name them, but one shaped like a long token is
//! refused ([`name_ok`]), in case a value was pasted in its place.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::helper::{self, Helper};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
/// What a `ttl`, written or answered, is held to.
const TTL_RANGE: (Duration, Duration) = (Duration::from_secs(60), Duration::from_secs(24 * 3600));
const DEFAULT_MAX_STALE: Duration = Duration::from_secs(3600);
const MAX_MAX_STALE: Duration = Duration::from_secs(7 * 24 * 3600);
/// After the command failed, it is not run again for this long.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// The largest answer read.
const MAX_ANSWER: u64 = 256 << 10;
/// The longest secret name.
const MAX_NAME: usize = 256;
/// The version of the request sent.
const VERSION: u32 = 1;

/// Where a secret of `auth.toml` comes from: a file, as written (relative
/// to the root unless absolute), or the secrets helper, by name. Written as
/// a path, or as `{ secret = "<name>" }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    File(PathBuf),
    Named(String),
}

impl From<&str> for Source {
    fn from(path: &str) -> Source {
        Source::File(path.into())
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Source, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Source;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a file's path, or { secret = \"<name>\" } for one the [secrets] command fetches")
            }

            fn visit_str<E: serde::de::Error>(self, path: &str) -> Result<Source, E> {
                Ok(Source::File(path.into()))
            }

            // serde's own messages would quote what was written: a value pasted here, perhaps.
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Source, E> {
                Err(E::custom(NOT_A_SOURCE))
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Source, E> {
                Err(E::custom(NOT_A_SOURCE))
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Source, E> {
                Err(E::custom(NOT_A_SOURCE))
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Source, E> {
                Err(E::custom(NOT_A_SOURCE))
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Source, M::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Named {
                    secret: helper::Word,
                }
                let Named { secret: helper::Word(secret) } =
                    Named::deserialize(serde::de::value::MapAccessDeserializer::new(&mut map))?;
                // Never quoted: a value pasted here by mistake must not reach a message.
                if !name_ok(&secret) {
                    return Err(serde::de::Error::custom(format!(
                        "{{ secret = ... }} takes a secret's name: 1 to {MAX_NAME} printable characters, no spaces, \
                         and no run of more than {MAX_RANDOM_RUN} letters and digits mixing both (a value, pasted in \
                         its place?)"
                    )));
                }
                Ok(Source::Named(secret))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// The longest run of letters and digits, mixing both, a name may hold:
/// longer, it looks like a secret (a token, a hex client secret), pasted in
/// the name's place. Long enough for the IDs vaults name secrets by (a
/// 26-character item ID, a 32-hex version).
const MAX_RANDOM_RUN: usize = 32;

/// What a field naming a secret is told when it is neither a path nor
/// `{ secret = "<name>" }`.
const NOT_A_SOURCE: &str = "a file's path, or { secret = \"<name>\" } for one the [secrets] command fetches";

/// Whether `name` is one a secret may have: printable ASCII, no spaces, and
/// no run of more than [`MAX_RANDOM_RUN`] letters and digits mixing both,
/// such as a token or a hex client secret. A guard against a value pasted
/// in a name's place, not a proof: a value with punctuation in it passes.
fn name_ok(name: &str) -> bool {
    let random = name.split(|c: char| !c.is_ascii_alphanumeric()).any(|run| {
        run.len() > MAX_RANDOM_RUN
            && run.bytes().any(|b| b.is_ascii_digit())
            && run.bytes().any(|b| b.is_ascii_alphabetic())
    });
    (1..=MAX_NAME).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_graphic()) && !random
}

impl Source {
    /// An empty path (a name is never empty).
    pub fn is_empty(&self) -> bool {
        matches!(self, Source::File(p) if p.as_os_str().is_empty())
    }

    /// The file, as written, if it is one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Source::File(p) => Some(p),
            Source::Named(_) => None,
        }
    }

    /// The secret's name, if the helper fetches it.
    pub fn name(&self) -> Option<&str> {
        match self {
            Source::File(_) => None,
            Source::Named(n) => Some(n),
        }
    }

    /// The secret `field` names, if `pass` reads it: how messages name
    /// where it came from (`github.private_key /srv/bd/app.pem`,
    /// `github.private_key (secret github-app-key)`), and its bytes.
    pub(crate) fn read(&self, field: &str, root: &Path, pass: &Pass<'_>) -> Result<Option<(String, Vec<u8>)>, String> {
        match (self, pass) {
            (Source::File(file), Pass::Files) => {
                let path = if file.is_relative() { root.join(file) } else { file.clone() };
                let at = format!("{field} {}", path.display());
                let bytes = std::fs::read(&path).map_err(|e| format!("{at}: {e}"))?;
                Ok(Some((at, bytes)))
            }
            // A name the answer does not give leaves its field empty: only steps needing it wait.
            (Source::Named(name), Pass::Answer(fetched)) => Ok(fetched
                .values
                .get(name)
                .map(|value| (format!("{field} (secret {name})"), value.0.as_bytes().to_vec()))),
            _ => Ok(None),
        }
    }
}

/// Which of `auth.toml`'s secrets a load reads: its files (with the rest of
/// its settings), or those the `[secrets]` command answered with.
pub(crate) enum Pass<'a> {
    Files,
    Answer(&'a Fetched),
}

/// `[secrets]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretsDoc {
    #[serde(deserialize_with = "crate::helper::argv")]
    command: Vec<String>,
    #[serde(default, deserialize_with = "crate::helper::env_names")]
    env: Vec<String>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    max_stale: Option<String>,
}

/// The secrets helper, as `[secrets]` configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secrets {
    pub helper: Helper,
    /// How long an answer that names no `ttl` is good for.
    pub ttl: Duration,
    /// How long past its `ttl` an answer is used while the command fails.
    pub max_stale: Duration,
}

/// `[secrets]` from what `auth.toml` says.
pub(crate) fn parse(doc: SecretsDoc) -> Result<Secrets, String> {
    let helper = helper::parse("secrets", doc.command, doc.env, doc.timeout.as_deref(), DEFAULT_TIMEOUT)?;
    let duration = |field: &str, raw: &Option<String>, default: Duration| match raw {
        None => Ok(default),
        Some(raw) => bd_core::time::parse_duration(raw).map_err(|e| format!("secrets.{field}: {e}")),
    };
    let ttl = duration("ttl", &doc.ttl, DEFAULT_TTL)?;
    if !(TTL_RANGE.0..=TTL_RANGE.1).contains(&ttl) {
        return Err(format!("secrets.ttl {:?}: use 1m to 24h", doc.ttl.unwrap_or_default()));
    }
    let max_stale = duration("max_stale", &doc.max_stale, DEFAULT_MAX_STALE)?;
    if max_stale > MAX_MAX_STALE {
        return Err(format!("secrets.max_stale {:?}: use at most 7d", doc.max_stale.unwrap_or_default()));
    }
    Ok(Secrets { helper, ttl, max_stale })
}

/// A secret's value, never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Value(Arc<str>);

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Value(..)")
    }
}

/// One line of printable text (`what`, at most `max` bytes) in `bytes`,
/// from `at`: a client secret or a token, read from a file (trimmed) or
/// fetched.
pub(crate) fn one_line(bytes: &[u8], at: &str, what: &str, max: usize) -> Result<String, String> {
    let secret = std::str::from_utf8(bytes).unwrap_or_default().trim();
    if secret.is_empty() || secret.len() > max || !secret.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{at}: not {what} (one line of printable characters)"));
    }
    Ok(secret.to_string())
}

/// The secrets of an answer, by name, and until when it serves (none for
/// one being checked).
#[derive(Debug)]
pub struct Fetched {
    values: HashMap<String, Value>,
    pub good_until: Option<Instant>,
}

impl Fetched {
    fn of(values: &HashMap<String, Value>, names: &BTreeSet<String>) -> Fetched {
        let values = names.iter().filter_map(|n| Some((n.clone(), values.get(n)?.clone()))).collect();
        Fetched { values, good_until: None }
    }
}

/// Whether an answer serves the fields that name its secrets: their own
/// loading of it (`oauth::load`'s), which says why not.
pub(crate) type Check = Arc<dyn Fn(&Fetched) -> Result<(), String> + Send + Sync>;

/// What `auth.toml` asks the command for, and how to tell an answer serves
/// the fields that name its secrets.
#[derive(Clone)]
pub(crate) struct Wanted {
    pub secrets: Secrets,
    pub names: BTreeSet<String>,
    pub check: Check,
}

/// What `auth.toml` wants now: nothing (no file, no `[secrets]`), or why it
/// cannot be told (unreadable, or invalid, perhaps while it is saved).
pub(crate) type Reader = Arc<dyn Fn() -> Result<Option<Wanted>, String> + Send + Sync>;

/// What the command answers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    secrets: BTreeMap<String, String>,
    #[serde(default)]
    ttl: Option<String>,
}

/// A root's answers, and its keeper's state.
#[derive(Default)]
struct Slot {
    state: Mutex<State>,
    /// Wakes the keeper (settings loaded again), and those waiting for its
    /// attempt (an attempt ended).
    wake: Condvar,
    /// Counts the answers stored: settings loaded with an older one are
    /// loaded again. Changed and read with the state held.
    generation: AtomicU64,
}

#[derive(Default)]
struct State {
    /// How the keeper reads what `auth.toml` wants; none: it ends.
    reader: Option<Reader>,
    /// Since when `auth.toml` has wanted nothing: after [`GONE_AFTER`] of
    /// it (not a save under way), the answer is forgotten and the keeper ends.
    gone_since: Option<Instant>,
    answer: Option<Kept>,
    /// The last failure, of which command and names, and when its attempt
    /// began: the command is not run again for them within [`RETRY_AFTER`].
    failed: Option<(Instant, Asked, String)>,
    /// Whether the keeper is asking the command (only it does).
    running: bool,
    /// Whether the keeper runs.
    keeper: bool,
    /// Counts the loads that woke the keeper: one that came while it read
    /// `auth.toml` keeps it from napping on what it read.
    pokes: u64,
    /// Whether the fields as they are now refuse a value of the kept answer
    /// (one moved to another field): asked again at once.
    refit: bool,
}

/// What is asked: of which helper, for which names.
#[derive(Clone, PartialEq, Eq)]
struct Asked {
    secrets: Secrets,
    names: BTreeSet<String>,
}

impl Asked {
    fn of(wanted: &Wanted) -> Asked {
        Asked { secrets: wanted.secrets.clone(), names: wanted.names.clone() }
    }
}

/// An answer kept: of which command, for which names, when, and for how
/// long it is good.
struct Kept {
    argv: Vec<String>,
    names: BTreeSet<String>,
    values: HashMap<String, Value>,
    at: Instant,
    ttl: Duration,
}

impl Kept {
    /// Until when it serves, `max_stale` past its `ttl`. It serves the
    /// command that gave it, name by name: the command's other settings, and
    /// `ttl` and `max_stale`, do not change what it answered.
    fn good_until(&self, max_stale: Duration) -> Instant {
        self.at + self.ttl + max_stale
    }
}

type Slots = HashMap<PathBuf, Arc<Slot>>;
static SLOTS: LazyLock<Mutex<Slots>> = LazyLock::new(Default::default);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn slot(root: &Path) -> Arc<Slot> {
    lock(&SLOTS).entry(root.to_path_buf()).or_default().clone()
}

/// Forget `root`'s answers, as if never asked; its keeper ends. Tests only:
/// the server forgets an answer once `auth.toml` wants none (the keeper).
#[cfg(test)]
pub(crate) fn forget(root: &Path) {
    if let Some(slot) = lock(&SLOTS).remove(root) {
        let mut state = lock(&slot.state);
        (state.reader, state.answer) = (None, None);
        slot.wake.notify_all();
    }
}

/// Whether `root`'s keeper has seen `auth.toml` want nothing of the
/// command, and the generation of its answers. Tests only.
#[cfg(all(test, unix))]
pub(crate) fn seen(root: &Path) -> (bool, u64) {
    lock(&SLOTS)
        .get(root)
        .map_or((false, 0), |s| (lock(&s.state).gone_since.is_some(), s.generation.load(Ordering::SeqCst)))
}

/// The generation of `root`'s answers now: settings loaded with another
/// are loaded again.
pub(crate) fn generation(root: &Path) -> u64 {
    lock(&SLOTS).get(root).map_or(0, |s| s.generation.load(Ordering::SeqCst))
}

/// Keep `root`'s secrets as `reader` tells `auth.toml` wants them: its
/// keeper started unless it runs, and woken to read it again.
pub(crate) fn ensure(root: &Path, reader: Reader) {
    let slot = slot(root);
    let mut state = lock(&slot.state);
    state.reader = Some(reader);
    keep(root, &slot, &mut state);
    state.pokes += 1;
    slot.wake.notify_all();
}

/// Wake `root`'s keeper, if it runs, to read `auth.toml` again: a load found
/// it wants nothing of the command now.
pub(crate) fn poke(root: &Path) {
    let Some(slot) = lock(&SLOTS).get(root).cloned() else { return };
    lock(&slot.state).pokes += 1;
    slot.wake.notify_all();
}

/// The fields as they are now refuse a value of `root`'s kept answer (a
/// name moved to another field): its keeper asks again at once.
pub(crate) fn refit(root: &Path) {
    let Some(slot) = lock(&SLOTS).get(root).cloned() else { return };
    let mut state = lock(&slot.state);
    if !state.refit {
        state.refit = true;
        slot.wake.notify_all();
    }
}

/// What of `names` the answer kept for `secrets`' command gives now, each
/// on its own (none if it gives none, or no longer serves), and the
/// generation of the root's answers, read together. Never waits, never runs
/// the command.
pub(crate) fn current(root: &Path, secrets: &Secrets, names: &BTreeSet<String>) -> (Option<Fetched>, u64) {
    let Some(slot) = lock(&SLOTS).get(root).cloned() else { return (None, 0) };
    let state = lock(&slot.state);
    (served(&state, secrets, names), slot.generation.load(Ordering::SeqCst))
}

fn served(state: &State, secrets: &Secrets, names: &BTreeSet<String>) -> Option<Fetched> {
    let kept = state.answer.as_ref().filter(|k| k.argv == secrets.helper.argv)?;
    let good_until = kept.good_until(secrets.max_stale);
    let fetched = Fetched { good_until: Some(good_until), ..Fetched::of(&kept.values, names) };
    (Instant::now() < good_until && !fetched.values.is_empty()).then_some(fetched)
}

/// Wait (`bd serve check`, the server's report of its first answer) until
/// an answer serves all of `wanted`, or the keeper's attempt at it fails:
/// why. Bounded by the command's timeout, and a little more.
pub(crate) fn wait(root: &Path, reader: Reader, wanted: &Wanted) -> Result<(), String> {
    ensure(root, reader);
    let slot = slot(root);
    let asked = Asked::of(wanted);
    let deadline = Instant::now() + wanted.secrets.helper.timeout + Duration::from_secs(5);
    let mut state = lock(&slot.state);
    loop {
        let all = served(&state, &wanted.secrets, &wanted.names);
        if all.is_some_and(|f| f.values.len() == wanted.names.len()) {
            return Ok(());
        }
        if let Some((_, of, why)) = &state.failed
            && *of == asked
            && !state.running
        {
            return Err(why.clone());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "the [secrets] command did not answer within {}",
                helper::fmt_duration(wanted.secrets.helper.timeout)
            ));
        }
        state = slot.wake.wait_timeout(state, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
    }
}

/// How long `auth.toml` must want nothing before its answer is forgotten:
/// longer than a save that replaces or empties it takes.
const GONE_AFTER: Duration = Duration::from_secs(10);
/// The longest the keeper sleeps without reading `auth.toml` again.
const KEEPER_NAP: Duration = Duration::from_secs(60);

/// Start `root`'s keeper unless it runs. One the system will not start is
/// logged, and tried again at the next load.
fn keep(root: &Path, slot: &Arc<Slot>, state: &mut State) {
    if state.keeper {
        return;
    }
    state.keeper = true;
    let (root, kept) = (root.to_path_buf(), slot.clone());
    let started = std::thread::Builder::new().name("bd-secrets".into()).spawn(move || keeper(&root, kept));
    if let Err(e) = started {
        state.keeper = false;
        tracing::warn!(target: "bd::serve", error = %e, "the [secrets] keeper could not be started; tried again at the next load");
    }
}

/// The keeper running: when it ends other than by deciding to (a panic
/// outside an attempt, which [`attempt`] catches), `keeper` and `running`
/// are cleared, so that the next load starts another and no one waits on it.
struct Keeping {
    slot: Arc<Slot>,
}

impl Drop for Keeping {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut state = lock(&self.slot.state);
            (state.keeper, state.running) = (false, false);
            self.slot.wake.notify_all();
        }
    }
}

/// Sleep `d`, or until woken; at once if a load came since `seen` (one that
/// came while the state was not held would wake no one).
fn nap<'a>(
    slot: &'a Slot,
    state: std::sync::MutexGuard<'a, State>,
    d: Duration,
    seen: u64,
) -> std::sync::MutexGuard<'a, State> {
    if state.pokes != seen {
        return state;
    }
    slot.wake.wait_timeout(state, d).unwrap_or_else(std::sync::PoisonError::into_inner).0
}

/// Whether `wanted` still asks `asked`'s command for its names.
fn same_ask(wanted: &Wanted, asked: &Asked) -> bool {
    wanted.secrets.helper.argv == asked.secrets.helper.argv && wanted.names == asked.names
}

/// Keep `slot`'s answer for what `auth.toml` wants, read again before each
/// attempt (and at least every [`KEEPER_NAP`], or at once when a load wakes
/// it): ask when due (three quarters of its `ttl`; at once with no answer
/// for all the names wanted, with one for more names than wanted, or with
/// one the fields refuse; [`RETRY_AFTER`] after the start of an attempt that
/// failed). Nothing is asked while `auth.toml` is invalid (perhaps a save
/// under way); the kept answer stays. The only one asking the command.
fn keeper(root: &Path, slot: Arc<Slot>) {
    let _keeping = Keeping { slot: slot.clone() };
    let mut state = lock(&slot.state);
    loop {
        let Some(reader) = state.reader.clone() else {
            // Forgotten.
            state.keeper = false;
            return;
        };
        let seen = state.pokes;
        drop(state);
        let read = attempt(|| reader());
        state = lock(&slot.state);
        let now = Instant::now();
        let wanted = match read {
            Err(_) => {
                state = nap(&slot, state, KEEPER_NAP, seen);
                continue;
            }
            Ok(Some(wanted)) => {
                state.gone_since = None;
                wanted
            }
            Ok(None) => {
                let since = *state.gone_since.get_or_insert(now);
                let left = GONE_AFTER.saturating_sub(now.duration_since(since));
                // A load that came while this was read (auth.toml back, perhaps) is read before anything is forgotten.
                if left.is_zero() && state.pokes == seen {
                    (state.answer, state.failed, state.gone_since) = (None, None, None);
                    state.keeper = false;
                    return;
                }
                state = nap(&slot, state, left, seen);
                continue;
            }
        };
        let asked = Asked::of(&wanted);
        let mut due = match &state.answer {
            Some(k) if k.argv == asked.secrets.helper.argv && k.names == asked.names && !state.refit => {
                k.at + k.ttl * 3 / 4
            }
            _ => now,
        };
        if let Some((at, of, _)) = &state.failed
            && *of == asked
        {
            due = due.max(*at + RETRY_AFTER);
        }
        if due > now {
            state = nap(&slot, state, (due - now).min(KEEPER_NAP), seen);
            continue;
        }
        state.running = true;
        let known: Vec<Value> = state.answer.iter().flat_map(|k| k.values.values().cloned()).collect();
        drop(state);
        // Asked, and the answer checked by the fields it is for, without the state held.
        let answered = attempt(|| {
            // A process that may run no command (`helper::forbid`) says why: no command ran, so none is blamed (as
            // `PANICKED`). `helper::run` keeps its own check, the one that enforces it; this one only picks the words.
            if let Some(why) = helper::forbidden() {
                return Err(why.to_string());
            }
            let (values, ttl) = ask(root, &asked, &known).map_err(|e| format!("the [secrets] command failed: {e}"))?;
            (wanted.check)(&Fetched::of(&values, &asked.names))
                .map_err(|e| format!("the [secrets] command failed: its answer does not serve: {e}"))?;
            Ok((values, ttl))
        });
        // auth.toml may have changed while the command ran: an answer to what it no longer asks is not kept. One
        // that cannot be read just then (or wants nothing, perhaps while saved) keeps it: it serves its command only.
        let still = match attempt(|| reader()) {
            Ok(Some(now_wanted)) => same_ask(&now_wanted, &asked),
            _ => true,
        };
        state = lock(&slot.state);
        state.running = false;
        if state.reader.is_none() || !still {
            slot.wake.notify_all();
            continue;
        }
        let settled = settle(&slot, &mut state, &asked, now, answered);
        slot.wake.notify_all();
        if let Err(why) = settled {
            let serving = served(&state, &asked.secrets, &asked.names);
            let left = serving.and_then(|f| f.good_until).map(|t| t.saturating_duration_since(Instant::now()));
            match left {
                Some(left) => tracing::warn!(
                    target: "bd::serve",
                    error = %why,
                    last_answer_serves_for = %helper::fmt_duration(left),
                    "the [secrets] command's last answer serves until secrets.max_stale runs out"
                ),
                None => tracing::warn!(
                    target: "bd::serve",
                    error = %why,
                    "sign-in needing the [secrets] command's secrets is unavailable until it answers"
                ),
            }
        }
    }
}

/// Run `f`, a step of the keeper's (reading `auth.toml`, asking the command,
/// checking its answer): a panic in it (bd's own, logged as every panic is)
/// is counted, and comes back as why it failed, the keeper going on.
fn attempt<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        crate::metrics::PANICS.add();
        Err(PANICKED.into())
    })
}

/// Why an attempt failed when bd itself panicked in it.
const PANICKED: &str = "bd's own handling of the [secrets] command panicked (logged)";

/// Keep what the attempt begun at `began` for `asked` came to: an answer
/// replaces the one kept (a new generation, so settings are loaded again
/// with it), and the fields no longer need a refit; a failure is noted (the
/// kept answer serving on), and told.
fn settle(
    slot: &Slot,
    state: &mut State,
    asked: &Asked,
    began: Instant,
    answered: Result<(HashMap<String, Value>, Duration), String>,
) -> Result<(), String> {
    match answered {
        Ok((values, ttl)) => {
            slot.generation.fetch_add(1, Ordering::SeqCst);
            let (argv, names) = (asked.secrets.helper.argv.clone(), asked.names.clone());
            // Its ttl counted from when it was asked for: the vault's clock started then, perhaps.
            state.answer = Some(Kept { argv, names, values, at: began, ttl });
            (state.failed, state.refit) = (None, false);
            Ok(())
        }
        Err(why) => {
            state.failed = Some((began, asked.clone(), why.clone()));
            Err(why)
        }
    }
}

/// Run the command for `asked`: the values of exactly its names, and how
/// long they are good for. `known` are left out of what it says on stderr.
fn ask(root: &Path, asked: &Asked, known: &[Value]) -> Result<(HashMap<String, Value>, Duration), String> {
    let body = serde_json::json!({ "version": VERSION, "secrets": asked.names });
    // Values left out, before run cuts it: no part of one is shown.
    let shown = |err: &str| without(err, known);
    let bytes = helper::run(root, &asked.secrets.helper, body.to_string().as_bytes(), MAX_ANSWER, &shown)?;
    // serde's message may quote what it read, a value: only where it went wrong.
    let answer: Answer = serde_json::from_slice(&bytes).map_err(|e| {
        format!("its answer is not one JSON object of secrets and ttl (line {}, column {})", e.line(), e.column())
    })?;
    let missing: Vec<&str> =
        asked.names.iter().filter(|n| !answer.secrets.contains_key(*n)).map(String::as_str).collect();
    if !missing.is_empty() {
        return Err(format!("its answer lacks {}", missing.join(", ")));
    }
    let extra: Vec<&str> = answer.secrets.keys().filter(|n| !asked.names.contains(*n)).map(|n| shown_name(n)).collect();
    if !extra.is_empty() {
        return Err(format!("its answer names secrets not asked for: {}", extra.join(", ")));
    }
    if let Some((name, _)) = answer.secrets.iter().find(|(_, v)| v.trim().is_empty()) {
        return Err(format!("its answer gives {name} empty"));
    }
    let ttl = match &answer.ttl {
        None => asked.secrets.ttl,
        Some(raw) => {
            let ttl = bd_core::time::parse_duration(raw).map_err(|_| "its ttl is not a duration such as 10m")?;
            ttl.clamp(TTL_RANGE.0, TTL_RANGE.1)
        }
    };
    let values = answer.secrets.into_iter().map(|(n, v)| (n, Value(v.into()))).collect();
    Ok((values, ttl))
}

/// A name the command answered with that was not asked for, as messages
/// show it: as is if it could be a secret's name, else not at all.
fn shown_name(name: &str) -> &str {
    if name_ok(name) { name } else { "<a name that is no secret's>" }
}

/// `text` with each of `known`'s values, and each line of a value of
/// several (a key), replaced by `<secret>`.
fn without(text: &str, known: &[Value]) -> String {
    let mut pieces: Vec<&str> = known
        .iter()
        .flat_map(|v| std::iter::once(v.0.trim()).chain(v.0.lines().map(str::trim)))
        .filter(|p| p.len() >= 4)
        .collect();
    // Longest first, so that a value is replaced whole before a line of it.
    pieces.sort_by_key(|p| std::cmp::Reverse(p.len()));
    pieces.dedup();
    let mut text = text.to_string();
    for piece in pieces {
        text = text.replace(piece, "<secret>");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(text: &str) -> Result<Secrets, String> {
        // As auth.toml's errors show it: the message, never the line quoted (oauth/config.rs).
        parse(toml::from_str::<SecretsDoc>(text).map_err(|e| e.message().to_string())?)
    }

    #[cfg(unix)]
    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_table_is_checked() {
        let s = secrets(r#"command = ["bin/bd-secrets", "--vault", "corp"]"#).unwrap();
        assert_eq!(s.helper.argv, ["bin/bd-secrets", "--vault", "corp"]);
        assert_eq!((s.helper.timeout, s.ttl, s.max_stale), (DEFAULT_TIMEOUT, DEFAULT_TTL, DEFAULT_MAX_STALE));
        let s = secrets("command = [\"x\"]\nttl = \"1h\"\nmax_stale = \"0s\"\ntimeout = \"30s\"").unwrap();
        assert_eq!(
            (s.ttl, s.max_stale, s.helper.timeout),
            (Duration::from_secs(3600), Duration::ZERO, Duration::from_secs(30))
        );
        for (bad, says) in [
            ("command = []", "secrets.command is empty"),
            ("command = \"bin/bd-secrets --token hvs.s3cret\"", "not a string"),
            ("env = [\"X\"]", "missing field `command`"),
            ("command = [\"x\"]\nenv = [\"VAULT_TOKEN=hvs.s3cret\"]", "entry 1 is not a variable name"),
            ("command = [\"x\"]\nenv = \"VAULT_TOKEN=hvs.s3cret\"", "not a string"),
            ("command = [\"x\"]\ntimeout = \"2m\"", "1s to 60s"),
            ("command = [\"x\"]\nttl = \"10s\"", "1m to 24h"),
            ("command = [\"x\"]\nttl = \"2d\"", "1m to 24h"),
            ("command = [\"x\"]\nmax_stale = \"8d\"", "at most 7d"),
            ("command = [\"x\"]\nmax_stale = \"a while\"", "secrets.max_stale"),
            ("command = [\"x\"]\nurl = \"https://vault\"", "unknown field"),
        ] {
            let e = secrets(bad).unwrap_err();
            assert!(e.contains(says) && !e.contains("s3cret"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_source_is_a_path_or_a_name() {
        #[derive(Deserialize)]
        struct Doc {
            key: Source,
        }
        // As auth.toml's errors show it: the message, never the line quoted (oauth/config.rs).
        let key = |text: &str| toml::from_str::<Doc>(text).map(|d| d.key).map_err(|e| e.message().to_string());
        assert_eq!(key("key = \"app.pem\"").unwrap(), Source::File("app.pem".into()));
        assert_eq!(key("key = { secret = \"kv/github-app-key\" }").unwrap(), Source::Named("kv/github-app-key".into()));
        // Names as vaults write them are names.
        for name in [
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/bd-AbCdEf",
            "op://Private/bd/client_secret",
            "bd-github-app-key-2024",
            "team+bd+github+app+v2",
            "op://Private/abcdefghij0123456789klmnop/password",
            "https://bd-vault.vault.azure.net/secrets/github-key/0123456789abcdef0123456789abcdef",
            "3f2a8c1e-9b7d-4e21-a5c3-0d6f1b2e4a98",
            "projects/my-project-1234/secrets/bd-oidc-client/versions/latest",
        ] {
            assert_eq!(key(&format!("key = {{ secret = \"{name}\" }}")).unwrap(), Source::Named(name.into()));
        }
        // A value pasted in a name's place (a hex client secret, a token): refused, never quoted.
        for value in ["0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c", "ghp_R4nd0mT0kenV4lueS3cretXyz123456789AbC"] {
            let e = key(&format!("key = {{ secret = \"{value}\" }}")).unwrap_err();
            assert!(e.contains("takes a secret's name") && !e.contains(&value[..8]), "{e}");
        }
        for (bad, says) in [
            ("key = { secret = \"\" }", "takes a secret's name"),
            ("key = { secret = \"two words\" }", "takes a secret's name"),
            ("key = { secret = \"-----BEGIN KEY-----\\nMIIE\" }", "takes a secret's name"),
            ("key = { name = \"x\" }", "unknown field"),
            ("key = {}", "missing field `secret`"),
            ("key = 7", "a file's path, or { secret"),
        ] {
            let e = key(bad).unwrap_err();
            assert!(e.contains(says) && !e.contains("BEGIN") && !e.contains("words"), "{bad}: {e}");
        }
        assert!(Source::from("").is_empty() && !Source::Named("x".into()).is_empty());
    }

    #[test]
    fn values_are_left_out_of_what_is_shown() {
        let key = Value("-----BEGIN KEY-----\nMIIEpAIBAAKCAQEA\n-----END KEY-----\n".into());
        let known = [Value("s3cret-value".into()), key, Value("abc".into())];
        assert_eq!(
            without("got s3cret-value; then MIIEpAIBAAKCAQEA and abc", &known),
            "got <secret>; then <secret> and abc",
            "too short to tell from other text: kept"
        );
        assert_eq!(format!("{:?}", known[0]), "Value(..)");
    }

    #[cfg(unix)]
    fn script(dir: &Path, body: &str) {
        let path = dir.join("bd-secrets");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn helper(ttl: Duration, max_stale: Duration) -> Secrets {
        // Run by sh, never exec'd itself: a script just written may still be open in a child another thread
        // forks meanwhile ("text file busy").
        let argv = vec!["/bin/sh".into(), "./bd-secrets".into()];
        let helper = Helper { argv, env: vec![], timeout: Duration::from_secs(5) };
        Secrets { helper, ttl, max_stale }
    }

    #[cfg(unix)]
    fn value(f: &Fetched, name: &str) -> String {
        f.values[name].0.to_string()
    }

    #[cfg(unix)]
    #[test]
    fn answers_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let s = helper(DEFAULT_TTL, Duration::ZERO);
        let asked = Asked { secrets: s, names: names(&["a", "b"]) };
        let answer = |json: &str| {
            script(dir.path(), &format!("cat > request.json\nprintf '%s' '{json}'"));
            ask(dir.path(), &asked, &[])
        };
        let (values, ttl) = answer(r#"{"secrets":{"a":"x1","b":"-----BEGIN\nk\n-----END"},"ttl":"2h"}"#).unwrap();
        assert_eq!(
            (values["a"].0.as_ref(), values["b"].0.as_ref(), ttl),
            ("x1", "-----BEGIN\nk\n-----END", Duration::from_secs(7200))
        );
        let sent: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("request.json")).unwrap()).unwrap();
        assert_eq!(sent, serde_json::json!({ "version": 1, "secrets": ["a", "b"] }));
        assert_eq!(answer(r#"{"secrets":{"a":"x","b":"y"},"ttl":"5s"}"#).unwrap().1, TTL_RANGE.0, "held to the range");
        assert_eq!(answer(r#"{"secrets":{"a":"x","b":"y"},"ttl":"30d"}"#).unwrap().1, TTL_RANGE.1);
        assert_eq!(answer(r#"{"secrets":{"a":"x","b":"y"}}"#).unwrap().1, DEFAULT_TTL);
        for (json, says) in [
            (r#"{"secrets":{"a":"x"}}"#, "lacks b"),
            (r#"{"secrets":{"a":"x","b":"y","c":"z"}}"#, "not asked for: c"),
            (r#"{"secrets":{"a":"x","b":" "}}"#, "gives b empty"),
            (r#"{"secrets":{"a":"x","b":"y"},"ttl":"soon"}"#, "not a duration"),
            (r#"{"secrets":{"a":"x","b":"y"},"note":"hi"}"#, "not one JSON object"),
            (r#"{"secrets":{"a":"s3cret","b":7}}"#, "line 1, column"),
            ("not json", "not one JSON object"),
        ] {
            let e = answer(json).unwrap_err();
            assert!(e.contains(says) && !e.contains("s3cret"), "{json}: {e}");
        }
        script(dir.path(), "cat >/dev/null\necho 'vault said no to s3cret-value' >&2\nexit 2");
        let e = ask(dir.path(), &asked, &[Value("s3cret-value".into())]).unwrap_err();
        assert!(e.contains("exited with") && e.contains("vault said no to <secret>"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn a_chatty_command_is_heard_out_and_its_secrets_left_out_of_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let asked = Asked { secrets: helper(DEFAULT_TTL, Duration::ZERO), names: names(&["a"]) };
        // 8 KiB of warnings, a line at a time, then the answer: never stopped by a closed pipe.
        script(
            dir.path(),
            "cat >/dev/null\ni=0; while [ $i -lt 128 ]; do echo 'warning: a line of 63 bytes of chatter from the vault cli....' >&2; \
             i=$((i+1)); done\nprintf '{\"secrets\":{\"a\":\"x\"}}'",
        );
        assert_eq!(ask(dir.path(), &asked, &[]).unwrap().0["a"].0.as_ref(), "x");
        // A known value straddling where the log cuts stderr: no part shown.
        let known = [Value("SUPERSECRET-1".into())];
        for after in ["", "and the rest of the line"] {
            let before = helper::MAX_STDERR - 6;
            script(
                dir.path(),
                &format!(
                    "cat >/dev/null\nhead -c {before} /dev/zero | tr '\\0' x >&2\necho SUPERSECRET-1 {after} >&2\nexit 1"
                ),
            );
            let e = ask(dir.path(), &asked, &known).unwrap_err();
            assert!(e.contains("xxxx") && !e.contains("SUPERS"), "{after}: {e}");
        }
        // Or where what is kept of it ends, copies of it before (which shrink, left out, below the log's cut):
        // the line cut there is left out whole.
        let long = "Z9".repeat(850);
        let known = [Value(long.clone().into())];
        script(
            dir.path(),
            &format!("cat >/dev/null\ni=0; while [ $i -lt 40 ]; do echo '{long}' >&2; i=$((i+1)); done\nexit 1"),
        );
        let e = ask(dir.path(), &asked, &known).unwrap_err();
        assert!(e.contains("<secret>") && !e.contains("Z9Z9"), "{e}");
    }

    #[cfg(unix)]
    fn passes() -> Check {
        Arc::new(|_| Ok(()))
    }

    /// Wait for `done`, at most 10 s.
    #[cfg(unix)]
    fn until(what: &str, done: impl Fn() -> bool) {
        let at = Instant::now();
        while !done() {
            assert!(at.elapsed() < Duration::from_secs(10), "never: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Make `root`'s kept answer older by `by`, and wake its keeper.
    #[cfg(unix)]
    fn age(root: &Path, by: Duration) {
        let slot = slot(root);
        lock(&slot.state).answer.as_mut().unwrap().at -= by;
        slot.wake.notify_all();
    }

    /// Move `root`'s last failure back past [`RETRY_AFTER`], and wake its keeper.
    #[cfg(unix)]
    fn retry_now(root: &Path) {
        let slot = slot(root);
        lock(&slot.state).failed.as_mut().unwrap().0 -= RETRY_AFTER;
        slot.wake.notify_all();
    }

    #[cfg(unix)]
    fn counting(root: &Path) -> impl Fn() -> u32 + '_ {
        // Each run counts itself and answers with the count, unless `fail` exists.
        script(
            root,
            "cat >/dev/null\n[ -e fail ] && { echo down >&2; exit 1; }\nn=$(( $(cat runs 2>/dev/null || echo 0) + 1 ))\n\
             echo $n > runs\nprintf '{\"secrets\":{\"a\":\"v%s\"}}' $n",
        );
        move || std::fs::read_to_string(root.join("runs")).map_or(0, |r| r.trim().parse().unwrap())
    }

    /// A test's `auth.toml`: what it wants (or that it is invalid), changed by the test, read by the keeper.
    #[cfg(unix)]
    #[derive(Clone)]
    struct Toml(Arc<Mutex<(Read, u64)>>);

    /// What a read of `auth.toml` finds.
    #[cfg(unix)]
    type Read = Result<Option<Wanted>, String>;

    #[cfg(unix)]
    impl Toml {
        fn new(wanted: &Wanted) -> Toml {
            Toml(Arc::new(Mutex::new((Ok(Some(wanted.clone())), 0))))
        }

        fn set(&self, wanted: Option<&Wanted>) {
            lock(&self.0).0 = Ok(wanted.cloned());
        }

        fn invalid(&self) {
            lock(&self.0).0 = Err("line 3: unknown field".into());
        }

        /// How many times it was read: a read counted after a change saw it.
        fn reads(&self) -> u64 {
            lock(&self.0).1
        }

        fn reader(&self) -> Reader {
            let toml = self.0.clone();
            Arc::new(move || {
                let mut toml = lock(&toml);
                toml.1 += 1;
                toml.0.clone()
            })
        }

        /// What a load does: the keeper started unless it runs, and woken.
        fn load(&self, root: &Path) {
            ensure(root, self.reader());
        }
    }

    #[cfg(unix)]
    fn wanted(secrets: &Secrets, list: &[&str], check: Check) -> Wanted {
        Wanted { secrets: secrets.clone(), names: names(list), check }
    }

    /// The value of `name` in the answer serving `wanted` now.
    #[cfg(unix)]
    fn now(root: &Path, wanted: &Wanted, name: &str) -> Option<String> {
        current(root, &wanted.secrets, &wanted.names).0.map(|f| value(&f, name))
    }

    #[cfg(unix)]
    #[test]
    fn the_keeper_refreshes_ahead_on_its_own_and_an_answer_serves_stale_only_so_long() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(60), Duration::from_secs(60)), &["a"], passes());
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        assert_eq!((now(root, &w, "a").as_deref(), runs()), (Some("v1"), 1), "the start waited for one run");

        // Past three quarters of its ttl: asked again with no load at all, a new generation.
        let before = generation(root);
        age(root, Duration::from_secs(50));
        until("refreshed", || generation(root) != before);
        assert_eq!((now(root, &w, "a").as_deref(), runs()), (Some("v2"), 2));

        // Failing: the kept answer serves to max_stale past its ttl, and says until when.
        std::fs::write(root.join("fail"), "").unwrap();
        age(root, Duration::from_secs(90));
        until("failed", || lock(&slot(root).state).failed.is_some());
        let served = current(root, &w.secrets, &w.names).0.unwrap();
        assert!(served.good_until.unwrap() < Instant::now() + Duration::from_secs(31));
        // Past it: none; not run again within RETRY_AFTER of the failed attempt's start.
        age(root, Duration::from_secs(60));
        assert_eq!(now(root, &w, "a"), None);
        std::fs::remove_file(root.join("fail")).unwrap();
        toml.load(root);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!((now(root, &w, "a"), runs()), (None, 2), "within RETRY_AFTER: not run again");
        // Then asked again by the keeper, which recovers it without any request waiting.
        retry_now(root);
        until("recovered", || now(root, &w, "a").is_some());
        assert_eq!((now(root, &w, "a").as_deref(), runs()), (Some("v3"), 3));

        // [secrets] gone for good (not a save under way): forgotten, and the keeper ends.
        toml.set(None);
        toml.load(root);
        until("seen gone", || lock(&slot(root).state).gone_since.is_some());
        lock(&slot(root).state).gone_since = Some(Instant::now() - GONE_AFTER);
        slot(root).wake.notify_all();
        until("keeper ended", || !lock(&slot(root).state).keeper);
        assert!(lock(&slot(root).state).answer.is_none());
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn auth_toml_saved_meanwhile_forgets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(600), Duration::from_secs(60)), &["a"], passes());
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        // Replaced or emptied while saved: for a moment, nothing wanted.
        toml.set(None);
        toml.load(root);
        until("seen gone", || lock(&slot(root).state).gone_since.is_some());
        toml.set(Some(&w));
        toml.load(root);
        until("seen back", || lock(&slot(root).state).gone_since.is_none());
        assert_eq!((now(root, &w, "a").as_deref(), runs()), (Some("v1"), 1), "kept, and not asked again");
        assert!(lock(&slot(root).state).keeper);
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn the_keeper_reads_auth_toml_before_each_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // The command fails, unless given --fixed; each run notes its arguments.
        script(
            root,
            "cat >/dev/null\necho \"$*\" >> ran\n[ \"$1\" = --fixed ] || { echo down >&2; exit 1; }\n\
             printf '{\"secrets\":{\"a\":\"ok\"}}'",
        );
        let broken = wanted(&helper(Duration::from_secs(600), Duration::ZERO), &["a"], passes());
        let toml = Toml::new(&broken);
        assert!(wait(root, toml.reader(), &broken).unwrap_err().contains("down"));
        // The admin fixes the command; no load follows (admin tokens only). The next attempt runs the fixed one.
        let mut fixed = broken.clone();
        fixed.secrets.helper.argv.push("--fixed".into());
        toml.set(Some(&fixed));
        retry_now(root);
        until("fixed", || now(root, &fixed, "a").is_some());
        let ran = std::fs::read_to_string(root.join("ran")).unwrap();
        assert_eq!(ran.lines().collect::<Vec<_>>(), ["", "--fixed"], "never the old command again");
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_kept_answer_serves_its_command_and_names_whatever_else_changes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(600), Duration::from_secs(60)), &["a"], passes());
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        // An admin riding out an outage raises max_stale, the timeout, the ttl; passes a variable.
        let mut patient = w.clone();
        let s = &mut patient.secrets;
        (s.max_stale, s.ttl, s.helper.timeout) =
            (Duration::from_secs(6 * 3600), Duration::from_secs(3600), Duration::from_secs(30));
        s.helper.env.push("VAULT_CREDENTIALS".into());
        assert_eq!(now(root, &patient, "a").as_deref(), Some("v1"));
        // max_stale as it is now decides how long.
        std::fs::write(root.join("fail"), "").unwrap();
        age(root, Duration::from_secs(700));
        assert_eq!(now(root, &w, "a"), None, "past ttl + 60s");
        assert_eq!(now(root, &patient, "a").as_deref(), Some("v1"));
        std::fs::remove_file(root.join("fail")).unwrap();
        // Another command: its own answer, asked for once auth.toml names it.
        let mut other = patient.clone();
        other.secrets.helper.argv.push("--other".into());
        assert_eq!(now(root, &other, "a"), None);
        toml.set(Some(&other));
        toml.load(root);
        until("asked", || now(root, &other, "a").is_some());
        assert!(runs() >= 2);
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn fewer_names_are_asked_for_at_once_while_the_kept_answer_serves() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        script(
            root,
            "cat > request.json\nif grep -q '\"b\"' request.json; then printf '{\"secrets\":{\"a\":\"a1\",\"b\":\"b1\"}}'; \
             else printf '{\"secrets\":{\"a\":\"a2\"}}'; fi",
        );
        let s = helper(Duration::from_secs(3600), Duration::from_secs(60));
        let both = wanted(&s, &["a", "b"], passes());
        let toml = Toml::new(&both);
        wait(root, toml.reader(), &both).unwrap();
        // b no longer named: a is served from what is kept, and asked for alone at once.
        let alone = wanted(&s, &["a"], passes());
        toml.set(Some(&alone));
        assert!(matches!(now(root, &alone, "a").as_deref(), Some("a1" | "a2")));
        toml.load(root);
        until("asked alone", || now(root, &alone, "a").as_deref() == Some("a2"));
        let kept = lock(&slot(root).state).answer.as_ref().map(|k| k.names.clone()).unwrap();
        assert_eq!(kept, names(&["a"]), "b no longer kept");
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn an_answer_its_fields_refuse_never_replaces_the_one_kept() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        script(root, "cat >/dev/null\nprintf '{\"secrets\":{\"a\":\"%s\"}}' \"$(cat vault)\"");
        let vault = |v: &str| std::fs::write(root.join("vault"), v).unwrap();
        let keys: Check = Arc::new(|f| match f.values["a"].0.starts_with("key") {
            true => Ok(()),
            false => Err("github.private_key (secret a): not a usable RSA key".into()),
        });
        let w = wanted(&helper(Duration::from_secs(60), Duration::from_secs(3600)), &["a"], keys);
        let toml = Toml::new(&w);
        vault("garbage");
        let e = wait(root, toml.reader(), &w).unwrap_err();
        assert!(e.contains("does not serve: github.private_key (secret a): not a usable RSA key"), "{e}");
        assert!(!e.contains("garbage"), "{e}");
        vault("key-1");
        retry_now(root);
        until("key-1", || now(root, &w, "a").as_deref() == Some("key-1"));
        // A botched rotation: refused, and the good key serves on, the failure retried.
        vault("garbage");
        age(root, Duration::from_secs(50));
        until("refused", || lock(&slot(root).state).failed.is_some());
        assert_eq!(now(root, &w, "a").as_deref(), Some("key-1"));
        vault("key-2");
        retry_now(root);
        until("fixed", || now(root, &w, "a").as_deref() == Some("key-2"));
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_start_waits_and_the_command_runs_once_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(600), Duration::ZERO), &["a"], passes());
        let toml = Toml::new(&w);
        // A load, before any answer: nothing served at once, the keeper asking.
        let at = Instant::now();
        toml.load(root);
        assert_eq!(now(root, &w, "a"), None);
        assert!(at.elapsed() < Duration::from_millis(200));
        until("answered", || now(root, &w, "a").is_some());
        forget(root);

        // The start, with a load already under way: one run, waited for.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs_now = counting(root);
        toml.load(root);
        wait(root, toml.reader(), &w).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!((now(root, &w, "a").as_deref(), runs_now()), (Some("v1"), 1));
        forget(root);
        // A failure is told to the start, and its retry clock starts with the attempt.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        script(root, "cat >/dev/null\nsleep 5");
        let mut slow = w.clone();
        slow.secrets.helper.timeout = Duration::from_secs(1);
        let began = Instant::now();
        let e = wait(root, Toml::new(&slow).reader(), &slow).unwrap_err();
        assert!(e.contains("did not answer within"), "{e}");
        let failed_at = lock(&slot(root).state).failed.as_ref().unwrap().0;
        assert!(failed_at < began + Duration::from_millis(500), "the attempt's start, not its end");
        forget(root);
        drop(runs);
    }

    #[cfg(unix)]
    #[test]
    fn a_check_that_panics_is_a_failed_attempt_and_the_keeper_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let boom = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check: Check = {
            let boom = boom.clone();
            Arc::new(move |_| match boom.swap(false, Ordering::SeqCst) {
                true => panic!("a check that panics (expected in this test)"),
                false => Ok(()),
            })
        };
        let w = wanted(&helper(Duration::from_secs(60), Duration::from_secs(600)), &["a"], check);
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        let panics = crate::metrics::PANICS.get();
        boom.store(true, Ordering::SeqCst);
        age(root, Duration::from_secs(50));
        until("failed", || lock(&slot(root).state).failed.is_some());
        let kept = slot(root);
        let state = lock(&kept.state);
        let why = state.failed.as_ref().unwrap().2.clone();
        assert_eq!(why, PANICKED, "bd's own, not blamed on the command");
        assert!(state.keeper && !state.running, "the keeper goes on, not left running");
        drop(state);
        assert!(crate::metrics::PANICS.get() > panics, "counted");
        assert_eq!(now(root, &w, "a").as_deref(), Some("v1"), "the kept answer serves on");
        // Retried as any failure is, with no load.
        retry_now(root);
        until("refreshed", || now(root, &w, "a").as_deref() == Some("v3"));
        assert_eq!(runs(), 3);
        forget(root);
    }

    /// A process that may run no command asks nothing, and its keeper says why as is, blaming no command. Run in
    /// a child process: a forbidden process stays so.
    #[cfg(unix)]
    #[test]
    fn a_forbidden_process_asks_nothing_and_says_why() {
        if let Some(dir) = crate::helper::forbid_tests::child_dir() {
            let root = dir.as_path();
            let runs = counting(root);
            let w = wanted(&helper(Duration::from_secs(600), Duration::ZERO), &["a"], passes());
            crate::helper::forbid("not in this process".into());
            assert_eq!(wait(root, Toml::new(&w).reader(), &w).unwrap_err(), "not in this process");
            assert_eq!(runs(), 0, "the command ran");
            forget(root);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        crate::helper::forbid_tests::rerun(
            concat!(module_path!(), "::a_forbidden_process_asks_nothing_and_says_why"),
            dir.path(),
        );
        assert!(!dir.path().join("runs").exists(), "the command ran");
    }

    /// A keeper that ends by a panic outside an attempt leaves no flag set: the next load starts another.
    #[test]
    fn a_keeper_that_panics_leaves_nothing_set() {
        let slot = Arc::new(Slot::default());
        let mut state = lock(&slot.state);
        (state.keeper, state.running) = (true, true);
        drop(state);
        let kept = slot.clone();
        let ended = std::thread::spawn(move || {
            let _keeping = Keeping { slot: kept };
            panic!("a keeper that panics (expected in this test)");
        })
        .join();
        assert!(ended.is_err());
        let state = lock(&slot.state);
        assert!(!state.keeper && !state.running);
        // A keeper that ends as it decides to keeps its own flags.
        drop(state);
        lock(&slot.state).keeper = true;
        drop(Keeping { slot: slot.clone() });
        assert!(lock(&slot.state).keeper);
    }

    #[cfg(unix)]
    #[test]
    fn each_name_serves_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // The vault holds a only.
        script(
            root,
            "cat > request.json\ngrep -q '\"b\"' request.json && { echo 'no secret b' >&2; exit 1; }\nprintf '{\"secrets\":{\"a\":\"a1\"}}'",
        );
        let s = helper(Duration::from_secs(600), Duration::from_secs(60));
        let a = wanted(&s, &["a"], passes());
        let toml = Toml::new(&a);
        wait(root, toml.reader(), &a).unwrap();
        // auth.toml now names b too, which the vault lacks: a serves on, b is asked for (and fails) on its own.
        let both = wanted(&s, &["a", "b"], passes());
        toml.set(Some(&both));
        toml.load(root);
        until("asked for both", || lock(&slot(root).state).failed.is_some());
        let (fetched, _) = current(root, &both.secrets, &both.names);
        let fetched = fetched.unwrap();
        assert_eq!((value(&fetched, "a"), fetched.values.contains_key("b")), ("a1".into(), false));
        assert!(wait(root, toml.reader(), &both).unwrap_err().contains("no secret b"), "all of them: told why not");
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_refit_or_any_new_answer_is_seen_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(600), Duration::from_secs(60)), &["a"], passes());
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        // The fields refuse the kept value (a name moved): asked again at once, fresh as the answer is.
        let before = generation(root);
        refit(root);
        until("asked again", || runs() == 2);
        until("stored", || generation(root) != before);
        // Every answer stored is a new generation, even with the same values (settings made without it reload).
        script(root, "cat >/dev/null\nprintf '{\"secrets\":{\"a\":\"same\"}}'");
        refit(root);
        until("same values", || now(root, &w, "a").as_deref() == Some("same"));
        let before = generation(root);
        refit(root);
        until("stored again", || generation(root) != before);
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_load_while_the_keeper_reads_is_never_lost() {
        let slot = Slot::default();
        let state = lock(&slot.state);
        let seen = state.pokes;
        drop(state);
        lock(&slot.state).pokes += 1;
        let at = Instant::now();
        let state = nap(&slot, lock(&slot.state), Duration::from_secs(60), seen);
        assert!(at.elapsed() < Duration::from_millis(100), "no nap after a load came");
        drop(state);
    }

    #[cfg(unix)]
    #[test]
    fn an_answer_to_what_auth_toml_no_longer_asks_is_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        script(root, "cat >/dev/null\n[ \"$1\" = --b ] || sleep 1\nprintf '{\"secrets\":{\"a\":\"%s\"}}' \"${1:-x}\"");
        let x = wanted(&helper(Duration::from_secs(600), Duration::from_secs(60)), &["a"], passes());
        let mut b = x.clone();
        b.secrets.helper.argv.push("--b".into());
        let toml = Toml::new(&x);
        toml.load(root);
        until("asking x", || lock(&slot(root).state).running);
        // The admin changes the command while x is asked: x's answer is dropped, b's kept.
        toml.set(Some(&b));
        until("b answered", || now(root, &b, "a").as_deref() == Some("--b"));
        assert_eq!(now(root, &x, "a"), None, "never x's");
        assert_eq!(generation(root), 1, "b's the only answer ever stored: x's was never kept, even for a moment");
        forget(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_removed_or_invalid_auth_toml_stops_the_asking_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let runs = counting(root);
        let w = wanted(&helper(Duration::from_secs(60), Duration::from_secs(600)), &["a"], passes());
        let toml = Toml::new(&w);
        wait(root, toml.reader(), &w).unwrap();
        // Invalid (fields naming secrets, [secrets] gone): not asked, even when due; the kept answer stays. Aged
        // once the keeper has read it invalid, not while it acts on a read from before.
        toml.invalid();
        let read = toml.reads();
        poke(root);
        until("read invalid", || toml.reads() > read);
        age(root, Duration::from_secs(50));
        poke(root);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!((runs(), now(root, &w, "a").as_deref()), (1, Some("v1")));
        // Valid without [secrets]: a load's poke has the keeper see it at once, not after its nap.
        toml.set(None);
        poke(root);
        until("seen gone", || lock(&slot(root).state).gone_since.is_some());
        assert_eq!(runs(), 1);
        forget(root);
    }
}
