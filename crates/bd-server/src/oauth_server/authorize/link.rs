//! A one-time link adding a passkey on another device, made at a browser
//! approval (`super::passkey`): how it is opened and spent, and how each of
//! its steps is counted and logged.
//!
//! [`landing`] shows a page whose script POSTs the link's secret, read from the
//! URL's fragment, to [`begin`]: a live link is sealed by its public id, bound
//! to the browser that posted it, into a flow (nothing is written, nothing
//! spent) and goes on through [`begun`] to a provider, in that browser alone,
//! as the flow's URL can be logged. Back from there, [`signed_in`] holds what
//! is the provider's and `admitted_step` what is this server's to decide: only
//! the very account of the link, a person's, gets the registration page, and
//! every other way it can end is told apart in the log alone, the page being
//! the one notice [`pages::link_unusable`]. The page's one POST goes to
//! [`register`]. No gate, operation or workspace is looked at anywhere: the
//! row's workspace is only what the rules are asked about at the sign-in, a
//! link makes no token, and a passkey added through it approves nothing.
//!
//! [`record`] is the one place that counts `passkey_links_total` or writes a
//! `passkey link` log line. A link made or replaced at an approval is counted
//! and logs no line of its own: the approval's line says `link made`, and the
//! audit events say the rest. Nothing here ever holds the link's secret or its
//! hash: only the link's public id, by its first [`crate::passkeys::PREFIX`]
//! characters.

use std::net::IpAddr;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use bd_core::Error;

use super::super::{CHOOSE, PASSKEY_LINK, PASSKEY_LINK_REGISTER, form, pages};
use super::passkey::{self, Failure, LinkPrepared, Why};
use crate::auth;
use crate::metrics::{self, Counter, Throttle};
use crate::oauth::{self, Admitted, SignIn};
use crate::passkeys::{self, Link, Linked};

use super::*;

/// How a step of a link ended, as logs and `/metrics` tell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Made at an approval.
    Made,
    /// A live link replaced by a new one.
    Ended,
    /// A live link opened: on to the sign-in.
    Started,
    /// No such live link: anyone may ask, so its line is throttled.
    Unusable,
    /// Signed in, but not as the account the link belongs to.
    WrongAccount,
    /// The rules or the authorizer did not let the account in.
    NotAdmitted,
    /// The account's access is not a person's.
    NotHuman,
    /// The very account signed in: the registration page.
    PageShown,
    /// The link was spent and its passkey stored.
    Registered,
    /// Refused at the passkey: its ceremony, the account's limit, or an
    /// address passkeys cannot be used at.
    PasskeyRefused,
    /// The server was too busy to decide.
    Busy,
    /// Something went wrong here or at the provider.
    Failed,
}

impl Outcome {
    /// Its label in logs.
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Made => "made",
            Outcome::Ended => "ended",
            Outcome::Started => "started",
            Outcome::Unusable => "unusable",
            Outcome::WrongAccount => "wrong account",
            Outcome::NotAdmitted => "not admitted",
            Outcome::NotHuman => "not human",
            Outcome::PageShown => "page shown",
            Outcome::Registered => "registered",
            Outcome::PasskeyRefused => "passkey refused",
            Outcome::Busy => "busy",
            Outcome::Failed => "failed",
        }
    }

    /// The `passkey_links_total` series it counts in, if any.
    pub fn counter(self) -> Option<&'static Counter> {
        match self {
            Outcome::Made => Some(&metrics::PASSKEY_LINKS_MADE),
            Outcome::Ended => Some(&metrics::PASSKEY_LINKS_ENDED),
            Outcome::Started => Some(&metrics::PASSKEY_LINKS_STARTED),
            Outcome::Unusable => Some(&metrics::PASSKEY_LINKS_UNUSABLE),
            Outcome::WrongAccount => Some(&metrics::PASSKEY_LINKS_WRONG_ACCOUNT),
            Outcome::NotAdmitted | Outcome::NotHuman | Outcome::PasskeyRefused | Outcome::Busy | Outcome::Failed => {
                Some(&metrics::PASSKEY_LINKS_REFUSED)
            }
            Outcome::Registered => Some(&metrics::PASSKEY_LINKS_REGISTERED),
            Outcome::PageShown => None,
        }
    }
}

/// What is known of a link's step, as it learns it: the provider, then the
/// account (never an email), the prefixes of the link, of the passkey that
/// vouched for it and of the new one, and the peer's address. Empty where
/// unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub provider: String,
    pub login: String,
    pub subject: String,
    pub actor: String,
    pub link: String,
    pub vouched_by: String,
    pub credential: String,
    pub peer: Option<IpAddr>,
}

/// Count `outcome` and log its one `passkey link` line. `detail` is a fixed
/// phrase of this server's, never a form value. [`Outcome::Unusable`] is
/// always counted, and logged at most once a minute with the peer alone: anyone
/// may ask, and the count is what shows a flood. [`Outcome::Made`] and
/// [`Outcome::Ended`] log nothing.
pub fn record(outcome: Outcome, seen: &Seen, detail: &'static str) {
    if let Some(counter) = outcome.counter() {
        counter.add();
    }
    let logged = match outcome {
        Outcome::Made | Outcome::Ended => false,
        Outcome::Unusable => {
            static UNUSABLE: Throttle = Throttle::new(60_000);
            let skipped = UNUSABLE.pass();
            if let Some(skipped) = skipped {
                let peer = seen.peer.map(tracing::field::display);
                tracing::info!(target: "bd::serve", outcome = outcome.label(), peer, skipped, "passkey link");
            }
            skipped.is_some()
        }
        _ => {
            tracing::info!(
                target: "bd::serve",
                outcome = outcome.label(),
                provider = %seen.provider,
                login = %seen.login,
                subject = %seen.subject,
                actor = %seen.actor,
                link = %seen.link,
                vouched_by = %seen.vouched_by,
                credential = %seen.credential,
                detail,
                "passkey link"
            );
            true
        }
    };
    #[cfg(test)]
    {
        RECORDED.with(|r| r.borrow_mut().push((outcome, detail, logged)));
        RECORDED_SEEN.with(|r| r.borrow_mut().push(seen.clone()));
    }
    #[cfg(not(test))]
    let _ = logged;
}

/// Count a link made at an approval, and the live link it replaced, if any:
/// called once its write committed.
pub(super) fn made(replaced: bool) {
    record(Outcome::Made, &Seen::default(), "");
    if replaced {
        record(Outcome::Ended, &Seen::default(), "");
    }
}

/// The title of a link's refusals.
const TITLE: &str = "Couldn't add a passkey";

const NOT_GIVEN: &str = "This link isn't one this server gave. Open the link again.";

/// The detail of a refusal that names only a server's settings.
const NO_SETTINGS: &str = "sign-in settings unavailable";

/// A refusal that says what went wrong: never that a link can't be used, which
/// is [`uniform`]'s to say.
fn refusal(status: u16, why: &str) -> Answer {
    Answer::Page(pages::notice(status, TITLE, why))
}

/// The one notice of a link that can't be used, whyever: only `outcome` and
/// `detail`, which the log alone sees, tell the reasons apart.
fn uniform(outcome: Outcome, seen: &Seen, detail: &'static str) -> Answer {
    record(outcome, seen, detail);
    Answer::Page(pages::link_unusable())
}

/// The answer to a failure of `server.db`, or of the step that was to follow it.
pub(super) fn store_failed(seen: &Seen, error: &Error, doing: &str) -> Answer {
    match error {
        Error::Busy(_) | Error::Locked(_) => {
            record(Outcome::Busy, seen, "server busy");
            refusal(503, "The server is busy. Try again in a moment.")
        }
        _ => {
            record(Outcome::Failed, seen, "internal error");
            internal(error, doing)
        }
    }
}

/// Whether `secret` is what a link carries: 32 bytes, in lowercase hex.
fn well_formed(secret: &str) -> bool {
    secret.len() == 64 && secret.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `GET <issuer>/oauth/passkey-link`: the page whose script POSTs the secret in
/// the URL's fragment, which no request carries. `cookies` is the browser's
/// `Cookie` header: it gets a cookie if it has none, which the flow is bound
/// to at the POST.
pub fn landing(issuer: &str, cookies: &str) -> (Answer, Vec<String>) {
    let page = Answer::Page(pages::landing_link(&format!("{issuer}{PASSKEY_LINK}")));
    if cookie(issuer, cookies).is_some() {
        return (page, Vec::new());
    }
    match auth::random_hex(32) {
        Ok(value) => (page, vec![set_cookie(issuer, &value)]),
        Err(e) => (internal(&e, "opening a passkey link"), Vec::new()),
    }
}

/// `POST <issuer>/oauth/passkey-link` with `link=<secret>`: a live link goes on
/// to sign in, by its public id alone. Nothing is written and nothing spent,
/// and a link that can't be used learns nothing of why. `browser` is the value
/// of the `bd_oauth` cookie the POST came with: the flow goes on in a URL's
/// query, where a proxy's log can see it, so it is bound here, to that browser
/// alone, and that URL is no stand-in for the secret.
pub fn begin(cx: &Ctx<'_>, body: &str, browser: &str, peer: Option<IpAddr>) -> Answer {
    let mut seen = Seen { peer, ..Seen::default() };
    if let Err(answer) = settings(cx) {
        record(Outcome::Failed, &seen, NO_SETTINGS);
        return answer;
    }
    let pairs = form::decode(body).unwrap_or_default();
    let Some(secret) = form::single(&pairs, "link").filter(|s| well_formed(s)) else {
        return uniform(Outcome::Unusable, &seen, "no live link");
    };
    let link = match passkeys::link_by_secret(cx.root, &auth::hash(secret)) {
        Ok(Some(link)) => link,
        Ok(None) => return uniform(Outcome::Unusable, &seen, "no live link"),
        Err(e) => return store_failed(&seen, &e, "opening a passkey link"),
    };
    seen.link = passkeys::prefix(&link.id).to_string();
    seen.vouched_by = passkeys::prefix(&link.vouched_by).to_string();
    let pending = Pending { then: Then::Link { id: link.id }, browser: auth::hash(browser), until: until(), at: None };
    let flow = match lock(cx.flows).sealer.seal(LINK_BEGIN, &pending) {
        Ok(flow) => flow,
        Err(e) => return store_failed(&seen, &e, "opening a passkey link"),
    };
    record(Outcome::Started, &seen, "");
    let query = form::encode(&[("flow", flow.as_str())]);
    Answer::Page(pages::sign_in_onward(&format!("{}{CHOOSE}?{query}", cx.issuer)))
}

/// `GET <issuer>/oauth/choose?flow=<sealed>` for a flow [`begin`] sealed: only
/// from the browser it was bound to at the POST, which keeps its cookie (no
/// other is drawn), on to the provider, or to a page choosing one, which names
/// neither a workspace nor an account.
pub(super) fn begun(
    cx: &Ctx<'_>,
    pending: Pending,
    provider: Option<&str>,
    browser: Option<&str>,
) -> (Answer, Vec<String>) {
    let Then::Link { id } = pending.then else {
        return (refusal(400, NOT_GIVEN), Vec::new());
    };
    if provider.is_some() {
        return (refusal(400, NOT_GIVEN), Vec::new());
    }
    if pending.until <= now_millis() {
        return (refusal(400, "This sign-in has expired. Open the link again."), Vec::new());
    }
    let Some(browser) = browser.filter(|b| auth::hash(b) == pending.browser) else {
        return (refusal(400, "This sign-in started in a different browser. Open the link again."), Vec::new());
    };
    let sign_in = match settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let providers = sign_in.browser_providers();
    match providers.as_slice() {
        [] => (approval_not_found(), Vec::new()),
        [(provider, _)] => start(cx, &sign_in, Then::Link { id }, provider, browser, None),
        several => {
            let then = Then::Link { id };
            let pending = Pending { then, browser: auth::hash(browser), until: until(), at: None };
            let flow = match lock(cx.flows).sealer.seal(CHOOSING, &pending) {
                Ok(f) => f,
                Err(e) => return (internal(&e, "opening a passkey link"), Vec::new()),
            };
            let options: Vec<(String, String)> = several
                .iter()
                .map(|(name, label)| {
                    let query = form::encode(&[("flow", flow.as_str()), ("provider", name)]);
                    (label.to_string(), format!("{}{CHOOSE}?{query}", cx.issuer))
                })
                .collect();
            (Answer::Page(pages::choose("Sign in to add a passkey", &options)), vec![set_cookie(cx.issuer, browser)])
        }
    }
}

/// What came back from the provider for the link `id`: the provider's half.
/// Its failures are said as a gate's are, before the row is read, and no code
/// is exchanged for a link that can't be used. The sign-in asks the rules about
/// the row's workspace, with no client, as a gate's does about its own.
pub(super) fn signed_in(
    cx: &Ctx<'_>,
    sign_in: &SignIn,
    back: &gate::Returned<'_>,
    id: &str,
    fresh: &mut Option<String>,
) -> Answer {
    let provider = back.provider;
    let mut seen = Seen { provider: provider.to_string(), link: passkeys::prefix(id).to_string(), ..Seen::default() };
    let label = match (provider, sign_in.oidc(provider)) {
        ("github", _) => "GitHub".to_string(),
        (_, Some(oidc)) => oidc.label.clone(),
        _ => {
            record(Outcome::Failed, &seen, NO_SETTINGS);
            return approval_not_found();
        }
    };
    if let Some(error) = back.error {
        tracing::info!(target: "bd::serve", %provider, %error, "link sign-in did not complete at the provider");
        return match error {
            // Apple says `user_cancelled_authorize`.
            "access_denied" | "user_cancelled_authorize" => {
                record(Outcome::Failed, &seen, "cancelled at the provider");
                refusal(403, &format!("The sign-in was cancelled at {label}. Open the link again."))
            }
            _ => {
                record(Outcome::Failed, &seen, "provider error");
                refusal(502, &format!("{label} didn't complete the sign-in. Open the link again."))
            }
        };
    }
    let Some(code) = back.code.filter(|c| !c.is_empty()) else {
        record(Outcome::Failed, &seen, "no sign-in code");
        return refusal(400, &format!("{label} didn't return a sign-in code. Open the link again."));
    };
    let link = match passkeys::link_by_id(cx.root, id) {
        Ok(Some(link)) => link,
        Ok(None) => return uniform(Outcome::Unusable, &seen, "no live link"),
        Err(e) => return store_failed(&seen, &e, "reading a passkey link"),
    };
    let callback_url = format!("{}{}", cx.issuer, super::super::callback(provider));
    let workspace = &link.workspace;
    let mut signed_in_as = None;
    let admitted = match sign_in.oidc(provider) {
        None => {
            let as_who = &mut signed_in_as;
            oauth::web_sign_in(cx.root, sign_in, code, &callback_url, back.verifier, workspace, None, as_who)
        }
        Some(oidc) => oidc
            .metadata()
            .and_then(|md| oidc.sign_in(&md, code, &callback_url, back.verifier, back.nonce))
            .and_then(|claims| {
                signed_in_as = Some(claims.login.clone());
                oauth::admit_oidc(cx.root, sign_in, oidc, &claims, workspace, None)
            }),
    };
    seen.login = signed_in_as.unwrap_or_default();
    admitted_step(cx, &label, seen, admitted, &link, fresh)
}

/// The decision half of [`signed_in`], once `label`'s provider answered with
/// `admitted`: the registration page, or why not, recorded once whichever way
/// it ends. Only `server.db` is touched: no workspace's, gate's or operation's
/// state, and no token.
fn admitted_step(
    cx: &Ctx<'_>,
    label: &str,
    mut seen: Seen,
    admitted: Result<Admitted, Error>,
    link: &Link,
    fresh: &mut Option<String>,
) -> Answer {
    seen.link = passkeys::prefix(&link.id).to_string();
    seen.vouched_by = passkeys::prefix(&link.vouched_by).to_string();
    let provider = seen.provider.clone();
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "link sign-in not admitted");
            return uniform(Outcome::NotAdmitted, &seen, "not admitted");
        }
        Err(Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "link sign-in did not complete");
            record(Outcome::Failed, &seen, "sign-in did not complete");
            return refusal(400, &format!("{label} didn't finish signing you in. Open the link again."));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "link sign-in failed");
            record(Outcome::Failed, &seen, "provider unreachable");
            return refusal(502, &format!("{label} didn't respond as expected. Try again in a moment."));
        }
        Err(Error::Busy(why) | Error::Locked(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "link sign-in could not be decided");
            record(Outcome::Busy, &seen, "access check unavailable");
            return refusal(503, "The server couldn't check your access just now. Try again in a moment.");
        }
        Err(e) => {
            record(Outcome::Failed, &seen, "internal error");
            return internal(&e, "finishing a passkey link's sign-in");
        }
    };
    let user = &admitted.user;
    seen.login = user.login.clone();
    seen.subject = user.subject.clone();
    // The exact pair the link was made for: a login or a subject alone is not an account.
    if user.issuer != link.issuer || user.subject != link.subject {
        return uniform(Outcome::WrongAccount, &seen, "another account");
    }
    if admitted.grant.kind != auth::Kind::Human {
        return uniform(Outcome::NotHuman, &seen, "not a person's access");
    }
    let detail = "to add a passkey through a link; no token issued";
    let actor = match auth::bind_account(cx.root, user, admitted.by_login, detail) {
        Ok(actor) => actor,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "link sign-in not bound");
            return uniform(Outcome::NotAdmitted, &seen, "account not bound");
        }
        Err(e) => return store_failed(&seen, &e, "binding an account to add a passkey"),
    };
    seen.actor = actor.clone();
    // The sign-in took a while, and the link may have gone meanwhile.
    let link = match passkeys::link_by_id(cx.root, &link.id) {
        Ok(Some(link)) => link,
        Ok(None) => return uniform(Outcome::Unusable, &seen, "no live link"),
        Err(e) => return store_failed(&seen, &e, "reading a passkey link"),
    };
    let (ceremony, credentials) = match passkey::prepare_link(cx, user, &actor, &link) {
        Ok(LinkPrepared::Ask { ceremony, credentials }) => (ceremony, credentials),
        Ok(LinkPrepared::Full) => {
            record(Outcome::PasskeyRefused, &seen, "limit reached");
            return Answer::Page(pages::link_limit());
        }
        Ok(LinkPrepared::Unavailable(why)) => {
            record(Outcome::PasskeyRefused, &seen, "passkeys unavailable at this address");
            return Answer::Page(pages::link_unavailable(why));
        }
        Err(e) => return store_failed(&seen, &e, "asking for a passkey"),
    };
    let secrets = (|| Ok::<_, Error>((auth::random_hex(32)?, auth::random_hex(32)?, auth::random_hex(4)?)))();
    let (id, value, suffix) = match secrets {
        Ok(secrets) => secrets,
        Err(e) => return store_failed(&seen, &e, "asking for a passkey"),
    };
    let action = format!("{}{PASSKEY_LINK_REGISTER}", cx.issuer);
    let page = pages::register_link(&action, &id, &actor, &passkey::link_ask(&ceremony, &credentials));
    *fresh = Some(set_link_page_cookie(cx.issuer, &suffix, &value, STEP_TTL));
    let kept = LinkPage {
        link: link.id,
        login: user.login.clone(),
        browser: auth::hash(&value),
        cookie: suffix,
        ceremony: *ceremony,
    };
    lock(cx.flows).link_pages.put(auth::hash(&id), kept);
    record(Outcome::PageShown, &seen, "");
    Answer::Page(page)
}

/// `POST <issuer>/oauth/passkey-link/register` with `id=<page id>` and a
/// registration's fields: the page [`signed_in`] showed, from the browser its
/// cookie binds it to, taken once, so a page refused is opened again from the
/// link, which a refusal leaves live. Its account, actor and link are what the
/// page kept: the form names none of them.
pub fn register(cx: &Ctx<'_>, body: &str, cookies: &str) -> (Answer, Vec<String>) {
    let pairs = form::decode(body).unwrap_or_default();
    // Read only if it occurs exactly once, before anything is looked up or taken.
    let Some(id) = form::single(&pairs, "id").filter(|v| !v.is_empty()) else {
        return (refusal(400, "The form arrived incomplete. Open the link again."), Vec::new());
    };
    let key = auth::hash(id);
    let page = {
        let mut flows = lock(cx.flows);
        if flows.links_spent.get_mut(&key).is_some() {
            return (refusal(400, "This page was already used. Open the link again."), Vec::new());
        }
        // Taken only by the browser it is bound to: another one that learned its id must not spend it.
        let bound = |p: &LinkPage| {
            link_page_cookie(cx.issuer, cookies, &p.cookie).map(auth::hash).as_deref() == Some(&p.browser)
        };
        match flows.link_pages.get_mut(&key).map(|p| bound(p)) {
            None => return (refusal(400, "This page has expired. Open the link again."), Vec::new()),
            Some(false) => {
                let why = "This page started in a different browser. Open the link again in this one.";
                return (refusal(403, why), Vec::new());
            }
            Some(true) => {}
        }
        let Some(page) = flows.link_pages.take(&key) else {
            return (refusal(400, "This page has expired. Open the link again."), Vec::new());
        };
        flows.links_spent.put(key, ());
        page
    };
    let cleared = vec![set_link_page_cookie(cx.issuer, &page.cookie, "", Duration::ZERO)];
    let c = &page.ceremony;
    let mut seen = Seen {
        provider: c.provider.clone(),
        login: page.login.clone(),
        subject: c.subject.clone(),
        actor: c.actor.clone(),
        link: passkeys::prefix(&page.link).to_string(),
        ..Seen::default()
    };
    // `[oauth]` may have been turned off since the page was shown.
    if let Err(answer) = settings(cx) {
        record(Outcome::Failed, &seen, NO_SETTINGS);
        return (answer, cleared);
    }
    let answer = match passkey::verify_link(cx, c, &page.link, &pairs) {
        Ok((credential, linked)) => {
            seen.credential = credential;
            match linked {
                Linked::Inserted { vouched_by } => {
                    seen.vouched_by = passkeys::prefix(&vouched_by).to_string();
                    record(Outcome::Registered, &seen, "");
                    Answer::Page(pages::link_added())
                }
                Linked::LinkGone | Linked::VouchGone => uniform(Outcome::Unusable, &seen, "no live link"),
                Linked::LimitReached => {
                    record(Outcome::PasskeyRefused, &seen, "limit reached");
                    Answer::Page(pages::link_limit())
                }
                Linked::CredentialTaken => {
                    record(Outcome::PasskeyRefused, &seen, Why::CredentialTaken.detail());
                    Answer::Page(pages::link_failed())
                }
            }
        }
        Err(Failure::Refused { why, credential }) => {
            seen.credential = credential;
            record(Outcome::PasskeyRefused, &seen, why.detail());
            Answer::Page(pages::link_failed())
        }
        Err(Failure::Store { error, credential }) => {
            seen.credential = credential;
            store_failed(&seen, &error, "adding a passkey through a link")
        }
    };
    (answer, cleared)
}

/// [`signed_in`] once `provider` (as the pages name it, `label`) answered with
/// `admitted`, as tests drive it.
#[cfg(test)]
pub(super) fn after_sign_in(
    cx: &Ctx<'_>,
    label: &str,
    provider: &str,
    admitted: Result<Admitted, Error>,
    link: &Link,
    fresh: &mut Option<String>,
) -> Answer {
    let seen = Seen { provider: provider.to_string(), ..Seen::default() };
    admitted_step(cx, label, seen, admitted, link, fresh)
}

/// What a test browser's page cookie `ab12` holds: well-formed, as
/// [`link_page_cookie`] wants it.
#[cfg(test)]
pub const TEST_BROWSER: &str = "abababababababababababababababababababababababababababababababab";

/// Keep a registration page under `id` for the link `link_id`, as a sign-in
/// would: bound to the browser whose cookie `ab12` holds [`TEST_BROWSER`].
#[cfg(test)]
pub(super) fn test_keep_page(flows: &Mutex<Flows>, id: &str, link_id: &str, ceremony: Ceremony) {
    let page = LinkPage {
        link: link_id.to_string(),
        login: "alice".into(),
        browser: auth::hash(TEST_BROWSER),
        cookie: "ab12".into(),
        ceremony,
    };
    lock(flows).link_pages.put(auth::hash(id), page);
}

/// [`test_keep_page`], with a ceremony of its own.
#[cfg(test)]
pub fn test_put_page(flows: &Mutex<Flows>, id: &str, link_id: &str) {
    test_keep_page(flows, id, link_id, Ceremony::for_test("https://github.com", "1", false, [0; 32]));
}

/// What [`record`] was called with, as tests see it: the outcome, the detail
/// and whether a line was logged.
#[cfg(test)]
pub(crate) type Recorded = (Outcome, &'static str, bool);

#[cfg(test)]
thread_local! {
    static RECORDED: std::cell::RefCell<Vec<Recorded>> = const { std::cell::RefCell::new(Vec::new()) };
    static RECORDED_SEEN: std::cell::RefCell<Vec<Seen>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// What [`record`] recorded on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_recorded() -> Vec<Recorded> {
    RECORDED.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

/// What [`record`] was told of each step on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_seen() -> Vec<Seen> {
    RECORDED_SEEN.with(|r| std::mem::take(&mut *r.borrow_mut()))
}
