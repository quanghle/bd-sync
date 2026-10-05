//! Requests to `bd serve`: retries under one request id, timeouts and
//! deadlines, reading streamed answers, and the server's errors.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use bd_core::{Error, Result};
use serde::Serialize;

use super::delivery::Delivery;
use super::{Configured, Remote, Trust, env};
use crate::credentials;
use crate::protocol::{ErrorBody, ExecRequest, ExecResponse, FRAMES_CONTENT_TYPE, Frame, PROTOCOL, PROTOCOL_HEADER};
use crate::stream::{Cut, FrameReader};

/// How long a request that failed in transit is retried, unless
/// `$BD_REMOTE_RETRY_SECS` says otherwise (0: one attempt). A write that may
/// have run gets it again from that failure, to ask for its stored answer.
const RETRY_BUDGET: Duration = Duration::from_secs(30);
/// `bd prime` runs from session hooks, which must not stall: it retries this long.
const PRIME_RETRY_BUDGET: Duration = Duration::from_secs(3);
/// A long poll that failed at least this long after it was sent (refused by
/// bd serve as busy or shutting down, or cut off by a crash, a proxy or a
/// timeout) waited on the server: its retries get a fresh retry time, up to
/// [`FRESH_WINDOWS`] times.
const HELD: Duration = Duration::from_secs(1);
const FRESH_WINDOWS: u32 = 5;
/// The pause before the first retry, doubling up to [`MAX_RETRY_DELAY`].
const FIRST_RETRY_DELAY: Duration = Duration::from_millis(200);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(4);

fn retry_budget() -> Duration {
    env("BD_REMOTE_RETRY_SECS").and_then(|s| s.parse().ok()).map_or(RETRY_BUDGET, Duration::from_secs)
}

/// When the failed attempts of one request are tried again
/// ([`Remote::exec_as`]): for the retry time from when it was sent, or for a
/// long poll from its first failure.
struct Retries {
    budget: Duration,
    long_poll: bool,
    /// When the retries end (a long poll's is set at its first failure).
    until: Option<Instant>,
    /// The pause before the next attempt, from `first_delay` doubling up to `max_delay`.
    delay: Duration,
    first_delay: Duration,
    max_delay: Duration,
    /// Fresh retry times a long poll got.
    fresh: u32,
    first_failure: Option<Instant>,
    retried: bool,
}

impl Retries {
    fn new(budget: Duration, long_poll: bool, now: Instant) -> Retries {
        Retries {
            budget,
            long_poll,
            until: (!long_poll).then(|| now + budget),
            delay: FIRST_RETRY_DELAY,
            first_delay: FIRST_RETRY_DELAY,
            max_delay: MAX_RETRY_DELAY,
            fresh: 0,
            first_failure: None,
            retried: false,
        }
    }

    /// Attempts at least `pace` apart.
    fn paced(mut self, pace: Duration) -> Retries {
        (self.first_delay, self.max_delay) = (FIRST_RETRY_DELAY.max(pace), MAX_RETRY_DELAY.max(pace));
        self.delay = self.first_delay;
        self
    }

    /// An attempt failed at `now`: whether to try again, after [`Retries::delay`].
    /// `held`: the server had it for [`HELD`] or more once it was sent.
    /// `restart`: the first failure after which a write may have run.
    fn failed(&mut self, now: Instant, held: bool, restart: bool) -> bool {
        self.first_failure.get_or_insert(now);
        let mut until = self.until.unwrap_or(now + self.budget);
        // The first failure that may have run a write restarts the retry time: a gateway timeout
        // arrives only once the proxy's own has passed (Cloudflare's 524 after 100 s), maybe past
        // the retry time, and the write's stored answer must still be asked for.
        if restart && !self.budget.is_zero() {
            until = until.max(now + self.budget.max(self.delay));
        }
        // A long poll's retry may wait on the server too: when it failed after the server had
        // held it, the time went to waiting, not to reaching the server, so the retries get the
        // whole retry time again from this failure. Only a retry time that ends later counts.
        // Refused connections never extend it: a server that is gone still ends the request.
        if self.long_poll && held && self.fresh < FRESH_WINDOWS && now + self.budget > until {
            self.fresh += 1;
            until = now + self.budget;
            self.delay = self.first_delay;
        }
        self.until = Some(until);
        now + self.delay <= until
    }

    /// The pause is over: the next attempt starts.
    fn retrying(&mut self) {
        self.retried = true;
        self.delay = (self.delay * 2).min(self.max_delay);
    }

    /// How the retries ended at `now`: for how long they went on since the first failure.
    fn gave_up(&self, now: Instant) -> String {
        match self.first_failure.filter(|_| self.retried) {
            Some(first) => {
                format!("gave up after retrying for {:.1}s", now.saturating_duration_since(first).as_secs_f64())
            }
            None => format!("not retried: the retry time of {}s had passed", self.budget.as_secs()),
        }
    }
}

/// A request body that notes when its last byte was handed to the
/// connection: after connecting, the TLS handshake and the headers.
struct Sending<'a> {
    rest: &'a [u8],
    sent: Option<Instant>,
}

impl std::io::Read for Sending<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = std::io::Read::read(&mut self.rest, buf)?;
        if self.rest.is_empty() && self.sent.is_none() {
            self.sent = Some(Instant::now());
        }
        Ok(n)
    }
}

impl Remote {
    /// The CA certificates come from `trust`, never from `c.ca_cert` again.
    pub fn new(c: Configured, trust: Trust, token: String) -> Remote {
        Remote {
            url: c.url,
            token: Mutex::new(token),
            renewing: None,
            roots: trust.certs,
            retry: retry_budget(),
            connect_timeout: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(120),
            total_timeout: None,
            deadline: None,
        }
    }

    /// Settings for commands that must answer within seconds (`bd prime` in
    /// hooks, `bd remote show`). `$BD_REMOTE_RETRY_SECS` still wins.
    pub fn quick(mut self) -> Remote {
        if env("BD_REMOTE_RETRY_SECS").is_none() {
            self.retry = PRIME_RETRY_BUDGET;
        }
        self.connect_timeout = Duration::from_secs(3);
        self.attempt_timeout = Duration::from_secs(15);
        self.total_timeout = Some(self.attempt_timeout);
        self
    }

    /// Every request ends within `budget` from now, retries included, even
    /// against a server that accepts the connection and never answers: for
    /// session hooks, which must not hold up the session.
    pub fn within(mut self, budget: Duration) -> Remote {
        self.deadline = Some((Instant::now() + budget, budget));
        self
    }

    /// The time left before the deadline, if there is one.
    pub(super) fn time_left(&self) -> Option<Duration> {
        self.deadline.map(|(at, _)| at.saturating_duration_since(Instant::now()))
    }

    fn agent(&self) -> Result<ureq::Agent> {
        let mut tls = ureq::tls::TlsConfig::builder();
        if let Some(certs) = &self.roots {
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(certs));
        }
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(self.connect_timeout))
            .timeout_send_request(Some(self.attempt_timeout))
            .timeout_send_body(Some(self.attempt_timeout))
            .timeout_recv_response(Some(self.attempt_timeout))
            .timeout_global(self.total_timeout)
            .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(tls.build())
            .build();
        Ok(config.into())
    }

    /// Send one request and collect its whole answer (the client's own small requests).
    pub fn exec(&self, request: &ExecRequest) -> Result<ExecResponse> {
        self.exec_into(request, &mut Delivery::collect())
    }

    /// Like [`Remote::exec`]; a `write` whose answer is lost fails with
    /// [`Error::AnswerLost`], never as safe to run again. Nothing is printed,
    /// however long the answer.
    pub fn exec_collected(&self, request: &ExecRequest, write: bool) -> Result<ExecResponse> {
        self.exec_into(request, &mut Delivery::new(Vec::new(), true, write))
    }

    /// Like [`Remote::exec`], for a request the server may hold until it has
    /// something to say: it is retried for as long after its first failure,
    /// not after it was sent.
    pub(super) fn long_poll(&self, request: &ExecRequest) -> Result<ExecResponse> {
        let mut out = Delivery::collect();
        out.long_poll = true;
        self.exec_into(request, &mut out)
    }

    /// Send one request; its answer goes to `out`. Failures in transit and
    /// busy answers are retried with the same request id, for up to the
    /// remote's retry budget, as long as no output has reached the user. A
    /// write that may have run without its answer arriving fails with
    /// [`Error::AnswerLost`], never as safe to run again.
    pub(super) fn exec_into(&self, request: &ExecRequest, out: &mut Delivery) -> Result<ExecResponse> {
        let token = self.access_token(false)?;
        let result = self.exec_as(&token, request, out);
        // A token refused before the command ran may have expired here first (another clock, or a
        // refresh by another process): renewed, the request is tried once more.
        if !(result.is_err() && out.token_refused && self.renewing.is_some()) {
            return result;
        }
        out.token_refused = false;
        match self.access_token(true) {
            Ok(renewed) if renewed != token => self.exec_as(&renewed, request, out),
            _ => result,
        }
    }

    /// [`Remote::exec_into`] with this access token.
    fn exec_as(&self, token: &str, request: &ExecRequest, out: &mut Delivery) -> Result<ExecResponse> {
        let agent = self.agent()?;
        let body = serde_json::to_vec(request)?;
        let endpoint = format!("{}/v{PROTOCOL}/exec", self.url);
        let authorization = format!("Bearer {token}");
        // A request made once the deadline has passed (a set wanted after the mutex wait) fails at once.
        if let Some((_, allowed)) = self.deadline.filter(|&(at, _)| Instant::now() >= at) {
            return Err(Error::Remote(format!(
                "{}: no time left of the {:.1}s allowed",
                self.url,
                allowed.as_secs_f64()
            )));
        }
        let mut retries = Retries::new(self.retry, out.long_poll, Instant::now());
        // Some attempt may have run the command on the server.
        let mut reached = false;
        let lost = |why: String| {
            Error::AnswerLost(format!("{}: {why}; the command may have taken effect on the server", self.url))
        };
        loop {
            let was_reached = reached;
            let mut sending = Sending { rest: &body, sent: None };
            let mut post = agent.post(&endpoint);
            if let Some(left) = self.time_left() {
                let whole = self.total_timeout.map_or(left, |t| t.min(left));
                post = post
                    .config()
                    .timeout_global(Some(whole))
                    .timeout_connect(Some(self.connect_timeout.min(left)))
                    .build();
            }
            let sent = post
                .header("authorization", &authorization)
                .header("accept", FRAMES_CONTENT_TYPE)
                .header("content-length", body.len())
                .content_type("application/json")
                .send(ureq::SendBody::from_reader(&mut sending));
            let failure = match sent {
                Ok(response) if response.status() == 200 => match self.receive(response, out)? {
                    Ok(done) => return Ok(done),
                    // The command ran, but its answer cannot be read: asking again would not help.
                    Err(Cut::Malformed(why)) if out.write => return Err(lost(format!("unexpected answer: {why}"))),
                    Err(Cut::Malformed(why)) => {
                        return Err(Error::Remote(format!("{}: unexpected answer: {why}", self.url)));
                    }
                    // Only a read prints as it arrives: running it again is harmless.
                    Err(cut) if out.printed => {
                        return Err(Error::Remote(format!("{}: {cut}, so the output above is incomplete", self.url)));
                    }
                    Err(cut) => {
                        reached = true;
                        cut.to_string()
                    }
                },
                Ok(mut response) => {
                    let status = response.status().as_u16();
                    let bd = response.headers().contains_key(PROTOCOL_HEADER);
                    // bd serve answers 503 before running a command (busy, shutting down). Any other
                    // server error may come after the command ran: from bd serve, or from a proxy in
                    // front of it (a gateway timeout, Cloudflare's 520 and 524, Envoy's 503).
                    let may_have_run = status >= 500 && !(bd && status == 503);
                    match (status, response.body_mut().with_config().limit(1 << 20).read_to_string()) {
                        // 409 "pending": an earlier attempt of this request is still running.
                        (409, Ok(text)) if error_code(&text).as_deref() == Some("pending") => {
                            reached = true;
                            format!("HTTP {status}{}", error_message(&text))
                        }
                        // The command failed on the server, possibly after taking effect.
                        (500, Ok(text)) if bd && out.write => {
                            return Err(lost(format!("HTTP 500{}", error_message(&text))));
                        }
                        (429 | 503, Ok(text)) if !may_have_run => format!("HTTP {status}{}", error_message(&text)),
                        (_, Ok(text)) if may_have_run && !bd => {
                            reached = true;
                            format!("HTTP {status}{}", error_message(&text))
                        }
                        (_, Ok(text)) if reached && out.write => {
                            let why = format!("HTTP {status}{}", error_message(&text));
                            return Err(lost(format!("{why}, after an earlier attempt that may have run")));
                        }
                        (_, Ok(text)) => {
                            out.token_refused = status == 401 && bd;
                            return Err(http_error(status, &text, &self.url, bd));
                        }
                        (_, Err(e)) => {
                            reached |= may_have_run || status == 409;
                            format!("HTTP {status}, reading the response: {e}")
                        }
                    }
                }
                Err(e) if retryable(&e) => {
                    if before_sending(&e) {
                        sending.sent = None;
                    }
                    reached |= !before_sending(&e);
                    e.to_string()
                }
                Err(e) => {
                    reached |= !before_sending(&e);
                    let e = format!("{e}{}", certificate_advice(&e.to_string()));
                    if reached && out.write {
                        return Err(lost(e));
                    }
                    return Err(Error::Remote(format!("{}: {e}", self.url)));
                }
            };
            let now = Instant::now();
            // Timed from when the request was sent, not from connecting: a slow TLS handshake is not held.
            let held = sending.sent.is_some_and(|at| now.saturating_duration_since(at) >= HELD);
            let again = retries.failed(now, held, reached && !was_reached && out.write);
            let past_deadline = self.deadline.filter(|&(at, _)| now + retries.delay > at);
            if !again || past_deadline.is_some() {
                let failure = match past_deadline {
                    Some((_, allowed)) => {
                        format!("{failure} (no answer within the {:.1}s allowed)", allowed.as_secs_f64())
                    }
                    None => format!("{failure} ({})", retries.gave_up(now)),
                };
                if reached && out.write {
                    return Err(lost(failure));
                }
                return Err(Error::Remote(format!("{}: {failure}", self.url)));
            }
            tracing::debug!(target: "bd::remote", url = %self.url, %failure, "retrying");
            std::thread::sleep(retries.delay);
            retries.retrying();
        }
    }

    /// Read a 200 answer into `out`: the command's outcome, or where the answer
    /// was cut off. An error is a local failure (writing stdout or an output
    /// file), which ends the request.
    fn receive(
        &self,
        response: ureq::http::Response<ureq::Body>,
        out: &mut Delivery,
    ) -> Result<std::result::Result<ExecResponse, Cut>> {
        let headers = response.headers();
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !content_type.starts_with(FRAMES_CONTENT_TYPE) {
            return Ok(Err(Cut::Malformed(format!("content type {content_type:?}, not a bd answer (check the URL)"))));
        }
        out.start(headers.contains_key("content-length"));
        let idle = self.time_left().map_or(self.attempt_timeout, |left| left.min(self.attempt_timeout));
        let frames = FrameReader::spawn(response.into_body().into_reader(), idle)?;
        loop {
            match frames.next() {
                Ok(Some(Frame::Stdout(text))) => out.stdout(&text)?,
                Ok(Some(Frame::File { path, data })) => out.file(&path, &data)?,
                Ok(Some(Frame::Issue(id))) => out.issue = Some(id.into_owned()),
                Ok(Some(Frame::Cursor(seq))) => out.cursor = Some(seq),
                Ok(Some(Frame::Exit(exit))) => return out.exit(exit).map(Ok),
                Ok(None) => return Ok(Err(Cut::Broken("the answer ended before the command did".into()))),
                Err(cut) => return Ok(Err(cut)),
            }
        }
    }

    /// POST `body` to the server's endpoint `<server>/v2/auth/<path>` (GitHub
    /// sign-in, which needs no token, or revocation, sent with this remote's
    /// token): its JSON answer. Failures in transit, busy answers and a
    /// proxy's server errors are retried for the retry time, at least `pace`
    /// apart; the server's own refusals end it.
    pub fn auth_request<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        pace: Duration,
    ) -> Result<T> {
        let token = self.token.lock().unwrap_or_else(|p| p.into_inner()).clone();
        self.auth_post(path, &token, body, pace, None)
    }

    /// [`Remote::auth_request`] with `bearer` as its bearer token (none if
    /// empty), ending within `limit` if given.
    pub(super) fn auth_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        bearer: &str,
        body: &impl Serialize,
        pace: Duration,
        limit: Option<Duration>,
    ) -> Result<T> {
        use crate::agents::show::printable;
        let server = credentials::keys(&self.url)?.server;
        let endpoint = format!("{server}/v{PROTOCOL}/auth/{path}");
        let agent = self.agent()?;
        let body = serde_json::to_vec(body)?;
        let mut retries = Retries::new(self.retry, false, Instant::now()).paced(pace);
        let hard = limit.map(|l| Instant::now() + l);
        let left = || {
            let to_hard = hard.map(|h| h.saturating_duration_since(Instant::now()));
            [self.time_left(), to_hard].into_iter().flatten().min()
        };
        loop {
            let mut post = agent.post(&endpoint);
            if let Some(left) = left() {
                post = post.config().timeout_global(Some(left)).build();
            }
            if !bearer.is_empty() {
                post = post.header("authorization", &format!("Bearer {bearer}"));
            }
            let sent = post.header("accept", "application/json").content_type("application/json").send(&body[..]);
            let failure = match sent {
                Ok(mut response) => {
                    let status = response.status().as_u16();
                    let bd = response.headers().contains_key(PROTOCOL_HEADER);
                    match (status, bd, response.body_mut().with_config().limit(1 << 20).read_to_string()) {
                        (200, true, Ok(text)) => {
                            return serde_json::from_str(&text).map_err(|e| {
                                Error::Remote(format!(
                                    "{server}: unexpected sign-in answer: {}",
                                    printable(&e.to_string())
                                ))
                            });
                        }
                        (503, true, Ok(text)) => format!("HTTP 503{}", printable(&error_message(&text))),
                        (_, true, Ok(text)) => return Err(sign_in_error(status, &text, &server)),
                        (_, true, Err(e)) => format!("HTTP {status}, reading the answer: {e}"),
                        (500.., false, _) => format!("HTTP {status}"),
                        (_, false, _) => {
                            return Err(Error::Remote(format!(
                                "{server}: HTTP {status} to a sign-in: not a bd server; check the URL"
                            )));
                        }
                    }
                }
                Err(e) if retryable(&e) => e.to_string(),
                Err(e) => return Err(Error::Remote(format!("{server}: {e}{}", certificate_advice(&e.to_string())))),
            };
            let now = Instant::now();
            let again = retries.failed(now, false, false);
            if !again || left().is_some_and(|left| retries.delay > left) {
                let why = if again { "no answer within the time allowed".to_string() } else { retries.gave_up(now) };
                return Err(Error::Remote(format!("{server}: {failure} ({why})")));
            }
            tracing::debug!(target: "bd::remote", %server, %failure, "retrying");
            std::thread::sleep(retries.delay);
            retries.retrying();
        }
    }
}

/// The error a failed command reported (its `--json` error, or its first stderr line).
pub fn response_error(r: &ExecResponse, url: &str) -> Error {
    let detail = r.stderr.lines().find_map(|l| serde_json::from_str::<ErrorBody>(l).ok()).map(|b| b.error);
    let message = match &detail {
        Some(d) => d.message.clone(),
        None => r.stderr.lines().next().unwrap_or("failed").trim_start_matches("error: ").to_string(),
    };
    match detail.map_or(r.exit_code, |d| d.exit_code) {
        7 => Error::Unauthorized(format!("{url}: {message}")),
        9 => Error::AnswerLost(format!("{url}: {message}")),
        2 => Error::invalid(format!("{url}: {message}")),
        3 => Error::NoWorkspace(format!("{url}: {message}")),
        _ => Error::Remote(format!("{url}: {message}")),
    }
}

/// bd serve's refusal of a GitHub sign-in step, as an error.
fn sign_in_error(status: u16, body: &str, server: &str) -> Error {
    let detail = serde_json::from_str::<ErrorBody>(body).ok().map(|b| b.error);
    let message =
        detail.as_ref().map_or_else(|| format!("HTTP {status}"), |d| crate::agents::show::printable(&d.message));
    match detail.map_or(0, |d| d.exit_code) {
        7 => Error::Unauthorized(format!("{server}: {message}")),
        2 => Error::invalid(format!("{server}: {message}")),
        3 => Error::NoWorkspace(format!("{server}: {message}")),
        _ => Error::Remote(format!("{server}: {message}")),
    }
}

/// Failures before the request was sent in full: the server cannot have run
/// it. Anything else (a reset, a malformed or oversized answer head) may come
/// after it ran.
fn before_sending(e: &ureq::Error) -> bool {
    use std::io::ErrorKind as K;
    use ureq::Error as E;
    use ureq::Timeout as T;
    match e {
        E::ConnectionFailed
        | E::HostNotFound
        | E::BadUri(_)
        | E::Http(_)
        | E::InvalidProxyUrl
        | E::ConnectProxyFailed(_)
        | E::RequireHttpsOnly(_)
        | E::TlsRequired
        | E::Tls(_)
        | E::Pem(_)
        | E::Rustls(_)
        | E::RedirectFailed
        | E::TooManyRedirects => true,
        E::Timeout(t) => matches!(t, T::Resolve | T::Connect | T::SendRequest | T::SendBody),
        // rustls reports certificate and handshake failures as InvalidData.
        E::Io(io) => matches!(
            io.kind(),
            K::ConnectionRefused | K::AddrNotAvailable | K::HostUnreachable | K::NetworkUnreachable | K::InvalidData
        ),
        _ => false,
    }
}

/// Failures worth retrying: the request may not have arrived, or its answer was lost.
fn retryable(e: &ureq::Error) -> bool {
    match e {
        // rustls reports certificate and handshake failures as InvalidData; retrying cannot fix those.
        ureq::Error::Io(io) => io.kind() != std::io::ErrorKind::InvalidData,
        ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed | ureq::Error::BodyStalled => true,
        _ => false,
    }
}

/// What to do about a rejected server certificate (rustls describes it only in text).
fn certificate_advice(error: &str) -> &'static str {
    if error.contains("CaUsedAsEndEntity") {
        " (the server's certificate is a CA certificate: issue it with basicConstraints CA:FALSE, or sign it with a \
         separate CA)"
    } else if error.contains("invalid peer certificate") {
        " (to trust a private CA or a self-signed certificate, set BD_CA_CERT or ca_cert in .bd/remote.toml)"
    } else {
        ""
    }
}

fn error_message(body: &str) -> String {
    serde_json::from_str::<ErrorBody>(body).map(|b| format!(": {}", b.error.message)).unwrap_or_default()
}

fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ErrorBody>(body).ok().map(|b| b.error.code)
}

/// The error of a non-200 answer; `bd` says whether a bd server sent it.
fn http_error(status: u16, body: &str, url: &str, bd: bool) -> Error {
    let detail = serde_json::from_str::<ErrorBody>(body).ok().map(|b| b.error);
    let message = detail.as_ref().map_or_else(|| format!("HTTP {status}"), |d| d.message.clone());
    match (status, detail.as_ref().map(|d| d.code.as_str())) {
        (401 | 403, _) | (_, Some("unauthorized")) => Error::Unauthorized(format!("{url}: {message}")),
        (404, _) if bd => Error::not_found("workspace", url),
        (404, _) => Error::Remote(format!("{url}: not a bd server ({message}); check the URL")),
        (400 | 413, _) => Error::invalid(format!("{url}: {message}")),
        _ => Error::Remote(format!("{url}: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_errors_keep_their_exit_codes() {
        let body = |code: &str| format!(r#"{{"error":{{"code":"{code}","message":"m","exit_code":7}}}}"#);
        assert_eq!(http_error(401, &body("unauthorized"), "u", true).exit_code(), 7);
        assert_eq!(http_error(403, &body("unauthorized"), "u", true).exit_code(), 7);
        assert_eq!(http_error(404, &body("not_found"), "u", true).exit_code(), 3);
        assert_eq!(http_error(413, &body("invalid"), "u", true).exit_code(), 2);
        assert_eq!(http_error(500, "not json", "u", false).exit_code(), 8);
        let other = http_error(404, &body("not_found"), "u", false);
        assert_eq!(other.exit_code(), 8, "a 404 without the protocol header is not a missing workspace");
        assert!(other.to_string().contains("not a bd server"), "{other}");
    }

    #[test]
    fn certificate_errors_explain_the_fix() {
        let ca = "io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))";
        assert!(certificate_advice(ca).contains("CA:FALSE"));
        assert!(certificate_advice("io: invalid peer certificate: UnknownIssuer").contains("BD_CA_CERT"));
        assert_eq!(certificate_advice("io: Connection refused"), "");
    }

    /// Attempts of a request with `retries`, from `start`: each fails `took`
    /// after it starts, held by the server if `held`. Returns when each
    /// failed, and when the retries gave up.
    fn attempts(retries: &mut Retries, start: Instant, mut each: impl FnMut(usize) -> (f64, bool)) -> Vec<Instant> {
        let mut failed = Vec::new();
        let mut at = start;
        loop {
            let (took, held) = each(failed.len());
            let now = at + Duration::from_secs_f64(took);
            failed.push(now);
            if !retries.failed(now, held, false) {
                return failed;
            }
            at = now + retries.delay;
            retries.retrying();
            assert!(failed.len() < 1000, "the retries never end");
        }
    }

    fn secs(from: Instant, to: Instant) -> f64 {
        (to - from).as_secs_f64()
    }

    #[test]
    fn long_polls_are_retried_for_the_retry_time_from_their_first_failure() {
        let start = Instant::now();
        // A long wait, then refused connections while the server restarts.
        let mut r = Retries::new(Duration::from_secs(30), true, start);
        let failed = attempts(&mut r, start, |n| if n == 0 { (60.0, true) } else { (0.01, false) });
        let (first, last) = (failed[0], *failed.last().unwrap());
        assert!(failed.len() > 2, "retried: {}", failed.len());
        assert!(secs(first, last) <= 30.0 && secs(first, last) > 25.0, "{}", secs(first, last));
        assert_eq!(r.fresh, 0, "the first failure starts the retry time; it is not a fresh one");
        assert_eq!(r.gave_up(last), format!("gave up after retrying for {:.1}s", secs(first, last)));

        // Any other request: from when it was sent, whatever the server held.
        let mut r = Retries::new(Duration::from_secs(30), false, start);
        let failed = attempts(&mut r, start, |n| if n == 0 { (20.0, true) } else { (2.0, true) });
        assert!(secs(start, *failed.last().unwrap()) - 2.0 <= 30.0, "the last attempt started in time");
        assert_eq!(r.fresh, 0);

        // One that failed after its retry time is not retried, and says so.
        let mut r = Retries::new(Duration::from_secs(30), false, start);
        assert_eq!(attempts(&mut r, start, |_| (120.0, true)).len(), 1);
        assert_eq!(r.gave_up(start + Duration::from_secs(120)), "not retried: the retry time of 30s had passed");
        let mut r = Retries::new(Duration::ZERO, true, start);
        assert_eq!(attempts(&mut r, start, |_| (10.0, true)).len(), 1, "a retry time of 0: one attempt");
    }

    #[test]
    fn long_polls_held_and_cut_get_a_fresh_retry_time_up_to_five_times() {
        let start = Instant::now();
        // A restart's 503 after a wait; refused connections; then the retry waits, and is cut off
        // past the first retry time (a crash, a proxy's 502, a timeout): a fresh one.
        let mut r = Retries::new(Duration::from_secs(30), true, start);
        let failed = attempts(&mut r, start, |n| match n {
            0 => (25.0, true),
            1..=4 => (0.01, false),
            5 => (25.0, true),
            _ => (0.01, false),
        });
        assert_eq!(r.fresh, 1);
        let fresh = failed[5];
        assert!(secs(failed[0], fresh) > 30.0, "past the first retry time: {}", secs(failed[0], fresh));
        assert!(secs(fresh, *failed.last().unwrap()) > 25.0, "a whole retry time from the cut");

        // A server that holds every attempt and refuses it: each later failure ends the retry
        // time later, which counts, until 5 fresh ones; then the last retry time runs out.
        let mut r = Retries::new(Duration::from_secs(2), true, start);
        let failed = attempts(&mut r, start, |_| (1.2, true));
        assert_eq!(r.fresh, FRESH_WINDOWS);
        assert_eq!(failed.len(), 8, "the first failure, 5 fresh retry times, and the rest of the last one");
        let (first, last) = (failed[0], *failed.last().unwrap());
        assert_eq!(r.gave_up(last), format!("gave up after retrying for {:.1}s", secs(first, last)));

        // Quick failures never extend it.
        let mut r = Retries::new(Duration::from_secs(2), true, start);
        let failed = attempts(&mut r, start, |n| if n == 0 { (1.2, true) } else { (0.5, false) });
        assert_eq!(r.fresh, 0);
        assert!(secs(failed[0], *failed.last().unwrap()) <= 2.0);
    }

    #[test]
    fn writes_get_the_retry_time_again_once_they_may_have_run() {
        let start = Instant::now();
        let mut r = Retries::new(Duration::from_secs(30), false, start);
        // A gateway timeout after 100 s: the write may have run, and its answer is asked for.
        assert!(r.failed(start + Duration::from_secs(100), true, true));
        r.retrying();
        assert!(r.failed(start + Duration::from_secs(125), false, false));
        assert!(!r.failed(start + Duration::from_secs(131), false, false));
        assert_eq!(r.fresh, 0, "only long polls get fresh retry times");
        assert_eq!(r.gave_up(start + Duration::from_secs(131)), "gave up after retrying for 31.0s");
    }

    #[test]
    fn request_bodies_note_when_they_were_sent() {
        let body = b"0123456789";
        let mut sending = Sending { rest: body, sent: None };
        let mut buf = [0u8; 4];
        assert_eq!(std::io::Read::read(&mut sending, &mut buf).unwrap(), 4);
        assert!(sending.sent.is_none(), "not all of it yet");
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut sending, &mut rest).unwrap();
        assert_eq!(rest, b"456789");
        assert!(sending.sent.is_some());
    }
}
