//! A close or discard that open human gates refused, approved in the
//! browser by a person who may open those gates, through the authorization
//! server's own sign-in. The refused request travels sealed in its link
//! (`bd_cli::approval_link`); through the sign-in it rides in request
//! cookies of its own (`set_request_cookies`), checked against the digest
//! the sealed flow (`Then::Operation`) carries.
//!
//! 1. `GET <public url>/w/<ws>/<op>/<issue>?request=<sealed>` ([`begin`]):
//!    only the shapes and the seal are checked, and nothing is looked up, so
//!    the answer is the same for any genuine link, whatever it names. The
//!    flow ([`Then::Operation`]) is sealed for a hop to `/oauth/choose`
//!    ([`OP_BEGIN`], bound to the browser there: [`begun`]), and the link's
//!    token rides in request cookies.
//! 2. Back at the provider's callback ([`signed_in`]): the account is
//!    judged for the workspace as a gate's approver is, only a grant of kind
//!    human goes on, and the account is bound to its actor with no token
//!    issued. Then the request cookies are checked against the flow's
//!    digest and opened again under the path's AAD, and only then is the
//!    target looked up ([`Operations::find`]): the page names the gates the
//!    operation gets past, and is shown only to a person who may open every
//!    one, with a cookie of its own (`bd_op_<suffix>`) and a one-time id.
//! 3. `POST` to the same path ([`approve`]): taken once, from that browser,
//!    the sealed request is performed exactly ([`Operations::perform`]) as
//!    the approver, never anything the form names.
//!
//! Every way an operation's approval ends, once its flow is known to be
//! one, is counted and logged once, by [`record`] alone.

use std::sync::Mutex;
use std::time::Duration;

use bd_cli::approval_link::{self, MAX_QUERY, Op, Opened, OperationRequest};
use bd_cli::protocol::valid_workspace_name;
use bd_core::Error;

use super::super::pages::{self};
use super::super::{CHOOSE, form};
use super::gate::{Approver, Returned};
use crate::oauth::{self, Admitted, SignIn};
use crate::{auth, metrics};

use super::*;

/// What a close or discard request's path names, as the server finds it
/// for the person who signed in to approve it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpFound {
    NoWorkspace,
    NoIssue,
    /// A close whose target is closed already: nothing to do.
    Done,
    /// The target is no longer what the request was for: why, in words.
    Changed(String),
    /// No open human gate is in the way any more.
    NotHeld,
    Op(Box<OpInfo>),
}

/// What an operation's approval page shows of its target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpInfo {
    pub id: String,
    pub title: String,
    pub status: String,
    /// The run or parent a closed issue belongs to: id and title.
    pub part_of: Option<(String, String)>,
    /// The open human gates the operation gets past.
    pub gates: Vec<GateInWay>,
    /// For a discard, the issues it deletes (id and title, at most
    /// [`pages::MAX_DELETES`]) and how many there are in all.
    pub deletes: Option<(Vec<(String, String)>, usize)>,
}

/// An open human gate in an operation's way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateInWay {
    pub id: String,
    pub title: String,
    /// Its approvers, if it names any (`Some([])`: a stored list that is
    /// not valid, which matches nobody).
    pub approvers: Option<Vec<String>>,
    /// Whether the person who signed in may open it (`policy::may_open`).
    pub may_open: bool,
}

/// What came of performing an approved operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Performed {
    Closed,
    Discarded {
        count: usize,
    },
    /// The close's target was closed meanwhile.
    Done,
    /// No open human gate is in the way any more.
    NotHeld,
    /// The target is no longer what the request was for: why.
    Changed(String),
    /// The workspace or issue is gone.
    Gone(OpFound),
    /// The transaction refused it as the approver: why.
    Refused(String),
}

/// The server's closes and discards, as approvals need them.
pub trait Operations: Sync {
    /// The target of `req` and the gates in its way, as `approver` would
    /// get past them.
    fn find(&self, req: &OperationRequest, approver: &Approver<'_>) -> Result<OpFound, Error>;
    /// Perform `req` exactly, as `actor`, a person (`oidc_approver`: the
    /// verified reference of the OIDC account that signed in), in one
    /// transaction that checks the target again and never takes over a
    /// claim.
    fn perform(&self, req: &OperationRequest, actor: &str, oidc_approver: Option<&str>) -> Result<Performed, Error>;
}

/// How an operation's approval ended, as `/metrics` counts it
/// (`bd_serve_operation_approvals_total{outcome}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The close or discard was performed.
    Approved,
    /// Refused: the account, the browser, the request or the transaction.
    Refused,
    /// The target is no longer what the request was for, or no longer held.
    NotReady,
    /// Nothing left to do: no such workspace or issue, or already closed.
    Gone,
    /// The server or workspace was too busy to decide.
    Busy,
    /// Something went wrong here: settings, or an internal error.
    Failed,
}

impl Outcome {
    /// Its label in logs and metrics.
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Refused => "refused",
            Outcome::NotReady => "not_ready",
            Outcome::Gone => "gone",
            Outcome::Busy => "busy",
            Outcome::Failed => "failed",
        }
    }

    fn counter(self) -> &'static metrics::Counter {
        match self {
            Outcome::Approved => &metrics::OPERATIONS_APPROVED,
            Outcome::Refused => &metrics::OPERATIONS_REFUSED,
            Outcome::NotReady => &metrics::OPERATIONS_NOT_READY,
            Outcome::Gone => &metrics::OPERATIONS_GONE,
            Outcome::Busy => &metrics::OPERATIONS_BUSY,
            Outcome::Failed => &metrics::OPERATIONS_FAILED,
        }
    }
}

/// Who an approval was for, as far as it is known: the provider the sign-in
/// started with, then, once the provider identified the account, its login,
/// subject and actor (never an email). Empty where unknown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Who<'a> {
    pub provider: &'a str,
    pub login: &'a str,
    pub subject: &'a str,
    pub actor: &'a str,
}

impl<'a> Who<'a> {
    /// Only the provider the sign-in started with: nothing else is known yet.
    pub fn provider_only(provider: &'a str) -> Who<'a> {
        Who { provider, ..Who::default() }
    }
}

/// Count and log how an operation's approval ended: one counter increment
/// and one `operation approval` line. `detail` is a fixed phrase of this
/// server's, never the request's reason, an issue's title or a provider's text.
pub fn record(outcome: Outcome, who: &Who<'_>, workspace: &str, op: &str, issue: &str, detail: &'static str) {
    outcome.counter().add();
    tracing::info!(
        target: "bd::serve",
        outcome = outcome.label(),
        provider = %who.provider,
        login = %who.login,
        subject = %who.subject,
        actor = %who.actor,
        %workspace,
        %issue,
        %op,
        detail,
        "operation approval"
    );
    #[cfg(test)]
    RECORDED.with(|r| r.borrow_mut().push((outcome, workspace.into(), op.into(), issue.into(), detail)));
}

/// What [`record`] was called with, as tests see it: the outcome, workspace,
/// operation, issue and detail.
#[cfg(test)]
pub(crate) type Recorded = (Outcome, String, String, String, &'static str);

#[cfg(test)]
thread_local! {
    static RECORDED: std::cell::RefCell<Vec<Recorded>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// What [`record`] recorded on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_recorded() -> Vec<Recorded> {
    RECORDED.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

/// The title of the pages refusing an operation's approval.
const TITLE: &str = "Couldn't approve the operation";

const EXPIRED: &str = "This approval has expired. Open the link again.";

const AGAIN: &str = "Open the approval link again.";

fn not_found() -> Answer {
    approval_not_found()
}

fn refusal(status: u16, why: &str) -> Answer {
    Answer::Page(pages::notice(status, TITLE, why))
}

/// Whether `workspace` and `issue` have the shapes a link's path may have:
/// anything else names nothing of bd's, and is kept out of logs.
pub fn path_ok(workspace: &str, issue: &str) -> bool {
    valid_workspace_name(workspace) && bd_core::gates::approval_id_ok(issue)
}

/// The workspace and issue of a path as [`record`] may log them: empty
/// when they have no shape of bd's.
pub fn logged<'p>(workspace: &'p str, issue: &'p str) -> (&'p str, &'p str) {
    if path_ok(workspace, issue) { (workspace, issue) } else { ("", "") }
}

/// The `request` a link's query carries.
fn request_of_query(query: &str) -> Option<String> {
    form::decode(query)?.into_iter().find(|(k, _)| k == "request").map(|(_, v)| v)
}

/// `GET <public url>/w/<workspace>/<op>/<issue>?request=<sealed>`: on to
/// the chooser, with the flow sealed for the hop there ([`OP_BEGIN`]) and
/// the link's token in request cookies. Only the shapes and the seal are
/// checked: a genuine link gets the same answer whatever it names, one that
/// is not genuine the answer of a path nothing is at, and one past its
/// time 410. Nothing is looked up and nothing recorded.
pub fn begin(cx: &Ctx<'_>, workspace: &str, op: &str, issue: &str, query: &str) -> (Answer, Vec<String>) {
    let Some(op) = Op::from_path(op).filter(|_| path_ok(workspace, issue)) else {
        return (not_found(), Vec::new());
    };
    if query.len() > MAX_QUERY {
        return (
            refusal(400, "This link is too long to be one this server gave. Open the link you were given."),
            Vec::new(),
        );
    }
    if let Err(answer) = settings(cx) {
        return (answer, Vec::new());
    }
    let Some(key) = cx.links else { return (not_found(), Vec::new()) };
    let Some(token) = request_of_query(query) else { return (not_found(), Vec::new()) };
    match approval_link::open(key, &token, workspace, op, issue, now_millis()) {
        Opened::Invalid => return (not_found(), Vec::new()),
        Opened::Expired(_) => {
            let why = "This approval link has expired. Ask for the operation again to get a new one.";
            return (Answer::Page(pages::notice(410, "Link expired", why)), Vec::new());
        }
        Opened::Valid(_) => {}
    }
    let Some(parts) = request_parts(token.len()) else { return (not_found(), Vec::new()) };
    let digest = auth::hash(&token);
    let then = Then::Operation {
        workspace: workspace.to_string(),
        op: op.as_str().to_string(),
        issue: issue.to_string(),
        digest: digest.clone(),
        parts,
    };
    let pending = Pending { then, browser: String::new(), until: until(), at: None };
    match lock(cx.flows).sealer.seal(OP_BEGIN, &pending) {
        Ok(flow) => {
            let url = format!("{}{CHOOSE}?{}", cx.issuer, form::encode(&[("flow", flow.as_str())]));
            (Answer::Redirect(url), set_request_cookies(cx.issuer, &digest, &token, 2 * STEP_TTL))
        }
        Err(e) => (internal(&e, "starting an operation's approval"), Vec::new()),
    }
}

/// `GET <issuer>/oauth/choose?flow=<sealed>` for a flow [`begin`] sealed:
/// bound to the browser's cookie (a new one if it has none), then on to the
/// provider, or to a page choosing one.
pub(super) fn begun(
    cx: &Ctx<'_>,
    pending: Pending,
    provider: Option<&str>,
    browser: Option<&str>,
) -> (Answer, Vec<String>) {
    let malformed =
        || (refusal(400, "This link isn't one this server gave. Open the approval link again."), Vec::new());
    let Some(flow) = pending.then.operation() else { return malformed() };
    let Some(op) = Op::from_path(&flow.op) else { return malformed() };
    if provider.is_some() {
        return malformed();
    }
    if pending.until <= now_millis() {
        return (refusal(400, "This sign-in has expired. Open the approval link again."), Vec::new());
    }
    let sign_in = match settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let browser = match browser {
        Some(b) => b.to_string(),
        None => match auth::random_hex(32) {
            Ok(b) => b,
            Err(e) => return (internal(&e, "starting an operation's approval"), Vec::new()),
        },
    };
    let providers = sign_in.browser_providers();
    match providers.as_slice() {
        [] => (not_found(), Vec::new()),
        [(provider, _)] => start(cx, &sign_in, pending.then, provider, &browser, None),
        several => {
            let heading = format!("Sign in to approve {} {} in {}", op.phrase(), flow.issue, flow.workspace);
            let pending = Pending { then: pending.then, browser: auth::hash(&browser), until: until(), at: None };
            let sealed = match lock(cx.flows).sealer.seal(CHOOSING, &pending) {
                Ok(f) => f,
                Err(e) => return (internal(&e, "starting an operation's approval"), Vec::new()),
            };
            let options: Vec<(String, String)> = several
                .iter()
                .map(|(name, label)| {
                    let query = form::encode(&[("flow", sealed.as_str()), ("provider", name)]);
                    (label.to_string(), format!("{}{CHOOSE}?{query}", cx.issuer))
                })
                .collect();
            (Answer::Page(pages::choose(&heading, &options)), vec![set_cookie(cx.issuer, &browser)])
        }
    }
}

/// The flow a provider's callback (`query`, the browser's `cookies`) comes
/// back with, opened whether or not it has expired: what it approves and the
/// provider it started with, if it is an operation's. Only the issuer's
/// cookie names and the sealer are used, never `auth.toml`, so a callback
/// is known for an operation's whatever the settings say now.
pub fn operation_flow(cx: &Ctx<'_>, query: &str, cookies: &str) -> Option<(OpFlow, String)> {
    let pending = opened_flow(cx, query, cookies)?;
    let flow = pending.then.operation()?;
    Some((flow, pending.at?.provider))
}

/// The flow sealed for the provider that `query`'s `state` names, as the
/// browser's `cookies` carry it, opened whether or not it has expired.
pub(super) fn opened_flow(cx: &Ctx<'_>, query: &str, cookies: &str) -> Option<Pending> {
    let state = form::decode(query)?.into_iter().find(|(k, _)| k == "state").map(|(_, v)| v)?;
    let sealed = flow_cookie(cx.issuer, cookies, &state)?;
    lock(cx.flows).sealer.open(AT_PROVIDER, sealed)
}

/// Who the operation approval page `id` was shown to, if it is still
/// waiting for its POST at the path of `op` of `issue` in `workspace`: its
/// provider, login, subject and actor. Peeked: neither taken nor spent.
pub fn pending_operation(
    flows: &Mutex<Flows>,
    id: &str,
    workspace: &str,
    op: &str,
    issue: &str,
) -> Option<(String, String, String, String)> {
    let key = auth::hash(id);
    let mut flows = lock(flows);
    if flows.operations_spent.get_mut(&key).is_some() {
        return None;
    }
    let a = flows.operations.get_mut(&key)?;
    let r = &a.request;
    (r.workspace == workspace && r.op.as_str() == op && r.issue == issue)
        .then(|| (a.provider.clone(), a.login.clone(), a.subject.clone(), a.actor.clone()))
}

/// Who an approval was for, owned, as a step learns it.
#[derive(Clone, Debug, Default)]
struct Seen {
    provider: String,
    login: String,
    subject: String,
    actor: String,
}

impl Seen {
    fn who(&self) -> Who<'_> {
        Who { provider: &self.provider, login: &self.login, subject: &self.subject, actor: &self.actor }
    }
}

/// How a step of an operation's approval answered, and the outcome to
/// record, if it ended there.
struct Step {
    answer: Answer,
    outcome: Option<Outcome>,
    who: Seen,
    detail: &'static str,
}

impl Step {
    fn ended(outcome: Outcome, who: &Seen, detail: &'static str, answer: Answer) -> Step {
        Step { answer, outcome: Some(outcome), who: who.clone(), detail }
    }
}

/// Back from the provider, signed in to approve the operation `flow`
/// carries: the approval page if the account may approve it, its cookie in
/// `fresh`. Every way it ends but the page is recorded, once.
pub(super) fn signed_in(
    cx: &Ctx<'_>,
    sign_in: &SignIn,
    back: &Returned<'_>,
    flow: &OpFlow,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Answer {
    finish(signed_in_inner(cx, sign_in, back, flow, cookies, fresh), flow)
}

/// `step`'s answer, its outcome recorded if it ended the approval.
fn finish(step: Step, flow: &OpFlow) -> Answer {
    if let Some(outcome) = step.outcome {
        record(outcome, &step.who.who(), &flow.workspace, &flow.op, &flow.issue, step.detail);
    }
    step.answer
}

/// [`signed_in`] once `provider` (as the pages name it, `label`) answered
/// with `admitted`, as tests drive it.
#[cfg(test)]
pub(super) fn after_sign_in(
    cx: &Ctx<'_>,
    label: &str,
    provider: &str,
    admitted: Result<Admitted, Error>,
    flow: &OpFlow,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Answer {
    let seen = Seen { provider: provider.to_string(), ..Seen::default() };
    finish(admitted_step(cx, label, seen, admitted, None, flow, cookies, fresh), flow)
}

/// A provider's callback for a flow sealed in `flows` for `issuer`, at
/// GitHub, for the browser whose cookie is `browser`: an operation's
/// (`close` of `t-1` in `proj`) if `operation`, else a gate's. Its query
/// and the `Cookie` header the browser sends with it.
#[cfg(test)]
pub fn test_callback(flows: &Mutex<Flows>, issuer: &str, operation: bool, browser: &str) -> (String, String) {
    let then = if operation {
        let digest = auth::hash("token");
        Then::Operation { workspace: "proj".into(), op: "close".into(), issue: "t-1".into(), digest, parts: 1 }
    } else {
        Then::Gate { workspace: "proj".into(), gate: "t-1".into() }
    };
    let state = "st4te";
    let at = AtProvider { provider: "github".into(), state: state.into(), verifier: "v".into(), nonce: "n".into() };
    let pending = Pending { then, browser: auth::hash(browser), until: until(), at: Some(at) };
    let sealed = lock(flows).sealer.seal(AT_PROVIDER, &pending).expect("sealed");
    let cookie = set_flow_cookie(issuer, state, &sealed, STEP_TTL);
    let cookie = cookie.split("; ").next().unwrap_or_default().to_string();
    (form::encode(&[("state", state), ("code", "c0de")]), cookie)
}

/// Keep `request`'s approval page as shown under `id`, as a sign-in would.
#[cfg(test)]
pub fn test_put_operation(flows: &Mutex<Flows>, id: &str, request: OperationRequest) {
    let approval = OperationApproval {
        request,
        provider: "github".into(),
        login: "alice".into(),
        subject: "1".into(),
        actor: "github:alice".into(),
        oidc_approver: None,
        browser: auth::hash("value"),
        cookie: "ab12".into(),
    };
    lock(flows).operations.put(auth::hash(id), approval);
}

fn signed_in_inner(
    cx: &Ctx<'_>,
    sign_in: &SignIn,
    back: &Returned<'_>,
    flow: &OpFlow,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Step {
    let provider = back.provider;
    let seen = Seen { provider: provider.to_string(), ..Seen::default() };
    let label = match (provider, sign_in.oidc(provider)) {
        ("github", _) => "GitHub".to_string(),
        (_, Some(oidc)) => oidc.label.clone(),
        _ => return Step::ended(Outcome::Failed, &seen, "sign-in settings unavailable", not_found()),
    };
    if let Some(error) = back.error {
        tracing::info!(target: "bd::serve", %provider, %error, "operation sign-in did not complete at the provider");
        return match error {
            // Apple says `user_cancelled_authorize`.
            "access_denied" | "user_cancelled_authorize" => {
                let why = format!("The sign-in was cancelled at {label}. {AGAIN}");
                Step::ended(Outcome::Refused, &seen, "cancelled at the provider", refusal(403, &why))
            }
            _ => {
                let why = format!("{label} didn't complete the sign-in. {AGAIN}");
                Step::ended(Outcome::Refused, &seen, "provider error", refusal(502, &why))
            }
        };
    }
    let Some(code) = back.code.filter(|c| !c.is_empty()) else {
        let why = format!("{label} didn't return a sign-in code. {AGAIN}");
        return Step::ended(Outcome::Refused, &seen, "no sign-in code", refusal(400, &why));
    };
    let callback_url = format!("{}{}", cx.issuer, super::super::callback(provider));
    let workspace = flow.workspace.as_str();
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
    admitted_step(cx, &label, seen, admitted, signed_in_as.as_deref(), flow, cookies, fresh)
}

/// [`signed_in`] once the provider answered: `admitted`, what the rules or
/// the authorizer made of the account (`signed_in_as`, its login).
#[allow(clippy::too_many_arguments)]
fn admitted_step(
    cx: &Ctx<'_>,
    label: &str,
    mut seen: Seen,
    admitted: Result<Admitted, Error>,
    signed_in_as: Option<&str>,
    flow: &OpFlow,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Step {
    let provider = seen.provider.clone();
    let workspace = flow.workspace.as_str();
    let account = signed_in_as.map_or(String::new(), |login| format!(" ({login})"));
    let may_not = || format!("Your {label} account{account} may not approve operations in this workspace.");
    let admitted = match admitted {
        Ok(a) => a,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "operation sign-in refused");
            return Step::ended(Outcome::Refused, &seen, "not admitted", refusal(403, &may_not()));
        }
        Err(Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "operation sign-in did not complete");
            let why = format!("{label} didn't finish signing you in. {AGAIN}");
            return Step::ended(Outcome::Failed, &seen, "sign-in did not complete", refusal(400, &why));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "operation sign-in failed");
            let why = format!("{label} didn't respond as expected. Try again in a moment.");
            return Step::ended(Outcome::Failed, &seen, "provider unreachable", refusal(502, &why));
        }
        Err(Error::Busy(why) | Error::Locked(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "operation sign-in could not be decided");
            let why = "The server couldn't check your access just now. Try again in a moment.";
            return Step::ended(Outcome::Busy, &seen, "access check unavailable", refusal(503, why));
        }
        Err(e) => {
            let answer = internal(&e, "finishing an operation's sign-in");
            return Step::ended(Outcome::Failed, &seen, "internal error", answer);
        }
    };
    let user = &admitted.user;
    seen.login = user.login.clone();
    seen.subject = user.subject.clone();
    // Only a person approves, before anything about the operation's target is looked up.
    if admitted.grant.kind != auth::Kind::Human {
        return Step::ended(Outcome::Refused, &seen, "not a person's access", refusal(403, &may_not()));
    }
    let Some(op) = Op::from_path(&flow.op) else {
        return Step::ended(Outcome::Refused, &seen, "malformed flow", refusal(400, AGAIN));
    };
    let detail = format!("to approve {} {} in {workspace}; no token issued", op.phrase(), flow.issue);
    let actor = match auth::bind_account(cx.root, user, admitted.by_login, &detail) {
        Ok(actor) => actor,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "operation approval refused");
            let why = format!(
                "Your {label} account{account} can't act on this server just now. Ask the server's admin about it."
            );
            return Step::ended(Outcome::Refused, &seen, "account not bound", refusal(403, &why));
        }
        Err(Error::Busy(_) | Error::Locked(_)) => {
            let why = "The server is busy. Try again in a moment.";
            return Step::ended(Outcome::Busy, &seen, "server busy", refusal(503, why));
        }
        Err(e) => {
            let answer = internal(&e, "binding an account to approve an operation");
            return Step::ended(Outcome::Failed, &seen, "internal error", answer);
        }
    };
    seen.actor = actor.clone();
    // The link's token, as it rode through the sign-in: only the one the flow was sealed with.
    let token = request_cookies(cx.issuer, cookies, &flow.digest, flow.parts).filter(|t| auth::hash(t) == flow.digest);
    let Some(token) = token else {
        let why = format!("The approval link didn't come through the sign-in in this browser. {AGAIN}");
        return Step::ended(Outcome::Refused, &seen, "request cookies missing", refusal(400, &why));
    };
    let Some(key) = cx.links else {
        return Step::ended(Outcome::Failed, &seen, "link key unavailable", not_found());
    };
    let request = match approval_link::open(key, &token, workspace, op, &flow.issue, now_millis()) {
        Opened::Valid(r) => *r,
        Opened::Invalid => return Step::ended(Outcome::Refused, &seen, "invalid request", not_found()),
        Opened::Expired(_) => {
            let why = "This approval link has expired. Ask for the operation again to get a new one.";
            let answer = Answer::Page(pages::notice(410, "Link expired", why));
            return Step::ended(Outcome::Refused, &seen, "request expired", answer);
        }
    };
    // From the identity the provider proved; never logged or shown.
    let oidc_approver = user.oidc_approver();
    let found = if (cx.workspace_exists)(workspace) {
        let approver = Approver { actor: &actor, oidc_approver: oidc_approver.as_deref() };
        match cx.operations.find(&request, &approver) {
            Ok(found) => found,
            Err(Error::Busy(_) | Error::Locked(_)) => {
                let why = "The workspace is busy. Try again in a moment.";
                return Step::ended(Outcome::Busy, &seen, "workspace busy", refusal(503, why));
            }
            Err(e) => {
                let answer = internal(&e, "looking up an operation to approve");
                return Step::ended(Outcome::Failed, &seen, "internal error", answer);
            }
        }
    } else {
        OpFound::NoWorkspace
    };
    let info = match found {
        OpFound::Op(info) => info,
        other => {
            let (outcome, detail, answer) = not_op(&other, &request);
            return Step::ended(outcome, &seen, detail, answer);
        }
    };
    let shut: Vec<&GateInWay> = info.gates.iter().filter(|g| !g.may_open).collect();
    if !shut.is_empty() {
        let mut why = format!("You're signed in as {actor}, and you may not open every gate this {op} gets past:");
        for g in &shut {
            let who = match g.approvers.as_deref() {
                None => "a person".to_string(),
                Some([]) => "nobody: its approvers aren't valid".to_string(),
                Some(list) => list.join(" or "),
            };
            why.push_str(&format!(" {} (approved by {who});", g.id));
        }
        why.pop();
        why.push('.');
        if oidc_approver.is_some() {
            why.push_str(&format!(
                " An account signed in with {label} matches only an oidc:sha256: identity reference for its own \
                 issuer and subject."
            ));
        }
        let answer = refusal(403, &bd_cli::io::printable(&why));
        return Step::ended(Outcome::Refused, &seen, "not an approver", answer);
    }
    let secrets = (|| Ok::<_, Error>((auth::random_hex(32)?, auth::random_hex(32)?, auth::random_hex(4)?)))();
    let (id, value, suffix) = match secrets {
        Ok(s) => s,
        Err(e) => {
            let answer = internal(&e, "asking for an operation's approval");
            return Step::ended(Outcome::Failed, &seen, "internal error", answer);
        }
    };
    let action = format!("{}/w/{workspace}/{op}/{}", cx.issuer, flow.issue);
    let gates: Vec<(String, String, Option<Vec<String>>)> =
        info.gates.iter().map(|g| (g.id.clone(), g.title.clone(), g.approvers.clone())).collect();
    let page = pages::approve_operation(&pages::ApproveOperation {
        workspace,
        op_label: op.as_str(),
        issue: &info.id,
        title: &info.title,
        status: &info.status,
        part_of: info.part_of.as_ref().map(|(id, title)| (id.as_str(), title.as_str())),
        reason: request.reason.as_deref(),
        requester: &request.requester,
        at: request.at,
        failed: request.failed,
        force: request.force,
        gates: &gates,
        deletes: info.deletes.as_ref().map(|(listed, total)| (listed.as_slice(), *total)),
        provider: label,
        actor: &actor,
        id: &id,
        action: &action,
    });
    *fresh = Some(set_op_cookie(cx.issuer, workspace, op.as_str(), &flow.issue, &suffix, &value, STEP_TTL));
    let approval = OperationApproval {
        request,
        provider: user.provider.clone(),
        login: user.login.clone(),
        subject: user.subject.clone(),
        actor,
        oidc_approver,
        browser: auth::hash(&value),
        cookie: suffix,
    };
    lock(cx.flows).operations.put(auth::hash(&id), approval);
    Step { answer: Answer::Page(page), outcome: None, who: seen, detail: "" }
}

/// The answer, outcome and detail for a target that is not there to
/// approve: told only to a person the rules let into the workspace.
fn not_op(found: &OpFound, req: &OperationRequest) -> (Outcome, &'static str, Answer) {
    let (ws, issue, op) = (&req.workspace, &req.issue, req.op);
    let page =
        |status, title: &str, why: String| Answer::Page(pages::notice(status, title, &bd_cli::io::printable(&why)));
    match found {
        OpFound::NoWorkspace => (
            Outcome::Gone,
            "no such workspace",
            page(404, "Nothing to do", format!("This server has no workspace {ws}.")),
        ),
        OpFound::NoIssue => (
            Outcome::Gone,
            "no such issue",
            page(404, "Nothing to do", format!("Workspace {ws} has no issue {issue}: nothing to {op}.")),
        ),
        OpFound::Done => (
            Outcome::Gone,
            "already closed",
            page(409, "Nothing to do", format!("{issue} in {ws} is closed already: nothing to do.")),
        ),
        OpFound::Changed(why) => (
            Outcome::NotReady,
            "target changed",
            page(409, "Not what was asked", format!("{why} The {op} asked for no longer applies.")),
        ),
        OpFound::NotHeld => (
            Outcome::NotReady,
            "no longer held",
            page(
                409,
                "No approval needed",
                format!(
                    "No open human gate holds {issue} in {ws} back any more: the {op} needs no approval. Ask for it \
                     again."
                ),
            ),
        ),
        OpFound::Op(_) => (Outcome::Failed, "internal error", not_found()),
    }
}

/// `POST <public url>/w/<workspace>/<op>/<issue>` with `approval=<id>`:
/// the approval the page [`signed_in`] showed, from the browser its cookie
/// binds it to, taken once. The sealed request is performed as the
/// approver. Every answer is recorded, once.
pub fn approve(
    cx: &Ctx<'_>,
    workspace: &str,
    op: &str,
    issue: &str,
    body: &str,
    cookies: &str,
) -> (Answer, Vec<String>) {
    let (step, cleared) = approve_inner(cx, workspace, op, issue, body, cookies);
    let (ws, id) = logged(workspace, issue);
    let op = Op::from_path(op).map_or("", Op::as_str);
    record(step.outcome.unwrap_or(Outcome::Failed), &step.who.who(), ws, op, id, step.detail);
    (step.answer, cleared)
}

fn approve_inner(
    cx: &Ctx<'_>,
    workspace: &str,
    op: &str,
    issue: &str,
    body: &str,
    cookies: &str,
) -> (Step, Vec<String>) {
    let nobody = Seen::default();
    let ended = |outcome, who: &Seen, detail, answer| (Step::ended(outcome, who, detail, answer), Vec::new());
    let Some(op) = Op::from_path(op).filter(|_| path_ok(workspace, issue)) else {
        return ended(Outcome::Refused, &nobody, "malformed path", not_found());
    };
    let pairs = form::decode(body).unwrap_or_default();
    let Some(id) = pairs.iter().find(|(k, _)| k == "approval").map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    else {
        let answer = refusal(400, "The form arrived incomplete. Open the approval link again.");
        return ended(Outcome::Refused, &nobody, "form incomplete", answer);
    };
    let key = auth::hash(id);
    let approval = {
        let mut flows = lock(cx.flows);
        if flows.operations_spent.get_mut(&key).is_some() {
            return ended(Outcome::Refused, &nobody, "already used", refusal(400, "This approval was already used."));
        }
        // Taken only by the browser it is bound to: another one that learned its id must not spend it.
        let bound = |a: &OperationApproval| {
            op_cookie(cx.issuer, cookies, &a.cookie).map(auth::hash).as_deref() == Some(&a.browser)
        };
        let here =
            |a: &OperationApproval| a.request.workspace == workspace && a.request.op == op && a.request.issue == issue;
        let seen = |a: &OperationApproval| Seen {
            provider: a.provider.clone(),
            login: a.login.clone(),
            subject: a.subject.clone(),
            actor: a.actor.clone(),
        };
        match flows.operations.get_mut(&key).map(|a| (bound(a), here(a), seen(a))) {
            None => return ended(Outcome::Refused, &nobody, "unknown or expired", refusal(400, EXPIRED)),
            Some((false, _, _)) => {
                let why = "This approval started in a different browser. Open the approval link again in this one.";
                return ended(Outcome::Refused, &nobody, "different browser", refusal(403, why));
            }
            Some((true, false, who)) => {
                let answer = refusal(400, "This approval is for another operation.");
                return ended(Outcome::Refused, &who, "another operation", answer);
            }
            Some((true, true, _)) => {}
        }
        let Some(approval) = flows.operations.take(&key) else {
            return ended(Outcome::Refused, &nobody, "unknown or expired", refusal(400, EXPIRED));
        };
        flows.operations_spent.put(key, ());
        approval
    };
    let who = Seen {
        provider: approval.provider.clone(),
        login: approval.login.clone(),
        subject: approval.subject.clone(),
        actor: approval.actor.clone(),
    };
    let cleared = vec![set_op_cookie(cx.issuer, workspace, op.as_str(), issue, &approval.cookie, "", Duration::ZERO)];
    let with = |outcome, detail, answer| (Step::ended(outcome, &who, detail, answer), cleared.clone());
    // `[oauth]` may have been turned off since the page was shown.
    if let Err(answer) = settings(cx) {
        return with(Outcome::Failed, "sign-in settings unavailable", answer);
    }
    let request = &approval.request;
    if request.until <= now_millis() {
        let why = "This approval link has expired. Ask for the operation again to get a new one.";
        return with(Outcome::Refused, "request expired", Answer::Page(pages::notice(410, "Link expired", why)));
    }
    let actor = &approval.actor;
    // The request as sealed and the reference the sign-in proved: nothing in the form is read but its id.
    let performed = cx.operations.perform(request, actor, approval.oidc_approver.as_deref());
    let page =
        |status, title: &str, why: String| Answer::Page(pages::notice(status, title, &bd_cli::io::printable(&why)));
    let requester = &request.requester;
    match performed {
        Ok(Performed::Closed) => {
            let why =
                format!("{issue} in {workspace} is closed, recorded as done by {actor} at {requester}'s request.");
            with(Outcome::Approved, "performed", page(200, "Approved", why))
        }
        Ok(Performed::Discarded { count }) => {
            let why = format!(
                "Run {issue} in {workspace} is discarded: {count} issue{} deleted, recorded as done by {actor} at \
                 {requester}'s request.",
                if count == 1 { "" } else { "s" }
            );
            with(Outcome::Approved, "performed", page(200, "Approved", why))
        }
        Ok(Performed::Done) => {
            let (outcome, detail, answer) = not_op(&OpFound::Done, request);
            with(outcome, detail, answer)
        }
        Ok(Performed::Gone(found)) => {
            let (_, detail, answer) = not_op(&found, request);
            with(Outcome::Gone, detail, answer)
        }
        Ok(Performed::NotHeld) => {
            let (outcome, detail, answer) = not_op(&OpFound::NotHeld, request);
            with(outcome, detail, answer)
        }
        Ok(Performed::Changed(why)) => {
            let (outcome, detail, answer) = not_op(&OpFound::Changed(why), request);
            with(outcome, detail, answer)
        }
        Ok(Performed::Refused(why)) => {
            let why = format!(
                "{why} Nothing was changed. If another actor holds a claim on this work, it must be released first; \
                 then ask for the {op} again."
            );
            with(Outcome::Refused, "refused by the workspace", page(403, TITLE, why))
        }
        Err(Error::Busy(_) | Error::Locked(_)) => {
            let answer = refusal(503, "The workspace is busy. Open the approval link again in a moment.");
            with(Outcome::Busy, "workspace busy", answer)
        }
        Err(e) => with(Outcome::Failed, "internal error", internal(&e, "approving an operation")),
    }
}
