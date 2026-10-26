//! A human gate approved in the browser, through the authorization server's
//! own sign-in:
//!
//! 1. `GET <public url>/w/<ws>/gates/<id>` ([`begin`]): only the shapes of
//!    the name and id are checked, and nothing is looked up, so the answer
//!    is the same for any gate, or none. The flow ([`Then::Gate`]) is sealed
//!    for a hop to `/oauth/choose`, where the browser's `bd_oauth` cookie is
//!    seen and the flow bound to it ([`begun`]); then on to the provider.
//! 2. Back at the provider's callback ([`signed_in`]): the account is judged
//!    for the gate's workspace as a sign-in is (`oauth::judge`: the deny
//!    list, then the authorizer, its event `sign_in` with no client, or the
//!    rules), and only a grant of kind human may approve. The account is
//!    bound to its actor ([`auth::bind_account`]), and no token is issued.
//!    Only then is it told whether the workspace, issue or gate exists, and
//!    whether it is waiting for approval and the account one of its
//!    approvers (`bd_core::policy::approved_by`: an OIDC account matches
//!    only the `oidc:sha256:` reference of its own issuer and subject, never
//!    an actor; a GitHub account matches by its actor); if so, the approval
//!    page, with a cookie of its own. The approval kept in memory holds the
//!    account's reference, computed from the identity the provider proved.
//! 3. `POST` to the same path ([`approve`]): the approval, bound to that
//!    cookie and posted once, resolves the gate as the account's actor
//!    with the reference kept at step 2, never one the form names
//!    ([`Gates::approve`]), its state, arming and approvers checked again in
//!    the transaction.

use std::time::Duration;

use bd_cli::protocol::valid_workspace_name;
use bd_core::Error;

use super::super::pages::{self};
use super::super::{CHOOSE, form};
use crate::oauth::{self, SignIn};
use crate::{auth, metrics};

use super::*;

/// What a gate's path names, as the server finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    NoWorkspace,
    NoIssue,
    /// An issue, but not a gate.
    NotGate,
    /// A gate that opens on its own condition, not by approval.
    NotHuman,
    Gate(Box<GateInfo>),
}

/// A human gate, as its approval page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateInfo {
    pub id: String,
    pub title: String,
    pub resolved: bool,
    /// Waiting for approval: open, and the work it holds back waits for
    /// nothing else (`GateView::is_armed`).
    pub armed: bool,
    /// Its approvers, if it names any (`Some([])`: a stored list that is
    /// not valid, which matches nobody).
    pub approvers: Option<Vec<String>>,
    /// The issues it holds back: id, title and status.
    pub holds: Vec<(String, String, String)>,
    /// The run or parent it belongs to: id and title.
    pub part_of: Option<(String, String)>,
}

/// What came of an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approved {
    /// The gate is resolved: the issues it released, and the runs that
    /// finished with it.
    Opened { unblocked: Vec<String>, completed: Vec<String> },
    /// Someone resolved it first.
    Resolved,
    /// No longer waiting for approval (deferred, or blocked again).
    NotArmed,
    /// No longer a human gate there.
    Gone(Found),
    /// The approver may not open it: why.
    Refused(String),
}

/// The server's gates, as approvals need them.
pub trait Gates: Sync {
    /// The gate `gate` (an exact id) of `workspace`.
    fn find(&self, workspace: &str, gate: &str) -> Result<Found, Error>;
    /// Resolve it as `actor`, a person, in one transaction that checks it
    /// again: still a human gate, open, armed, and the person one who may
    /// open it. `oidc_approver` is the verified reference of the OIDC account
    /// that signed in (`auth::Identity::oidc_approver`), None for a GitHub
    /// account: with one, only that reference among the approvers lets it
    /// open the gate, never `actor`.
    fn approve(&self, workspace: &str, gate: &str, actor: &str, oidc_approver: Option<&str>)
    -> Result<Approved, Error>;
}

/// The title of the pages refusing an approval.
const TITLE: &str = "Couldn't approve the gate";

const NOT_READY: &str =
    "This gate is not ready to approve: the work it holds back still waits for other work, or the gate is deferred.";

const EXPIRED: &str = "This approval has expired. Open the link again.";

/// Whether `id` may be a gate's id in a path ([`bd_core::gates::approval_id_ok`]).
/// Anything else is no issue of bd's, and kept out of cookie paths and logs.
pub fn gate_id_ok(id: &str) -> bool {
    bd_core::gates::approval_id_ok(id)
}

fn not_found() -> Answer {
    Answer::Page(pages::notice(404, "Not found", "There is nothing to approve here."))
}

fn refusal(status: u16, why: &str) -> Answer {
    Answer::Page(pages::notice(status, TITLE, why))
}

/// Sign-in settings that approve gates: `[oauth]` with a provider people
/// sign in with in a browser; else not found.
fn settings(cx: &Ctx<'_>) -> Result<SignIn, Answer> {
    match oauth::load(cx.root) {
        Ok(Some(s)) if s.oauth.is_some() && !s.browser_providers().is_empty() => Ok(s),
        Ok(_) | Err(Error::Invalid(_)) => Err(not_found()),
        Err(e) => Err(internal(&e, "reading auth.toml for a gate's approval")),
    }
}

/// `GET <public url>/w/<workspace>/gates/<gate>`: on to the chooser, with
/// the flow sealed for the hop there ([`GATE_BEGIN`]). Nothing is looked
/// up and no cookie set: the answer tells nothing of the gate.
pub fn begin(cx: &Ctx<'_>, workspace: &str, gate: &str) -> (Answer, Vec<String>) {
    if !valid_workspace_name(workspace) || !gate_id_ok(gate) {
        return (not_found(), Vec::new());
    }
    if let Err(answer) = settings(cx) {
        return (answer, Vec::new());
    }
    let then = Then::Gate { workspace: workspace.to_string(), gate: gate.to_string() };
    let pending = Pending { then, browser: String::new(), until: until(), at: None };
    match lock(cx.flows).sealer.seal(GATE_BEGIN, &pending) {
        Ok(flow) => {
            let url = format!("{}{CHOOSE}?{}", cx.issuer, form::encode(&[("flow", flow.as_str())]));
            (Answer::Redirect(url), Vec::new())
        }
        Err(e) => (internal(&e, "starting a gate's approval"), Vec::new()),
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
    let Then::Gate { workspace, gate } = pending.then else {
        return (refusal(400, "This link isn't one this server gave. Open the gate's link again."), Vec::new());
    };
    if provider.is_some() {
        return (refusal(400, "This link isn't one this server gave. Open the gate's link again."), Vec::new());
    }
    if pending.until <= now_millis() {
        return (refusal(400, "This sign-in has expired. Open the gate's link again."), Vec::new());
    }
    let sign_in = match settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    // Another sign-in under way in this browser keeps its cookie.
    let browser = match browser {
        Some(b) => b.to_string(),
        None => match auth::random_hex(32) {
            Ok(b) => b,
            Err(e) => return (internal(&e, "starting a gate's approval"), Vec::new()),
        },
    };
    let providers = sign_in.browser_providers();
    match providers.as_slice() {
        [] => (not_found(), Vec::new()),
        [(provider, _)] => start(cx, &sign_in, Then::Gate { workspace, gate }, provider, &browser, None),
        several => {
            let heading = format!("Sign in to approve gate {gate} in {workspace}");
            let then = Then::Gate { workspace, gate };
            let pending = Pending { then, browser: auth::hash(&browser), until: until(), at: None };
            let flow = match lock(cx.flows).sealer.seal(CHOOSING, &pending) {
                Ok(f) => f,
                Err(e) => return (internal(&e, "starting a gate's approval"), Vec::new()),
            };
            let options: Vec<(String, String)> = several
                .iter()
                .map(|(name, label)| {
                    let query = form::encode(&[("flow", flow.as_str()), ("provider", name)]);
                    (label.to_string(), format!("{}{CHOOSE}?{query}", cx.issuer))
                })
                .collect();
            (Answer::Page(pages::choose(&heading, &options)), vec![set_cookie(cx.issuer, &browser)])
        }
    }
}

/// What came back from the provider for a gate's approval.
pub(super) struct Returned<'a> {
    pub(super) provider: &'a str,
    pub(super) error: Option<&'a str>,
    pub(super) code: Option<&'a str>,
    /// This server's PKCE verifier and nonce there.
    pub(super) verifier: &'a str,
    pub(super) nonce: &'a str,
}

/// Back from the provider, signed in to approve `gate` of `workspace`: the
/// approval page if the account may approve it, its cookie in `fresh`.
/// Every way it can end is a page of this server's, never a redirect.
pub(super) fn signed_in(
    cx: &Ctx<'_>,
    sign_in: &SignIn,
    back: &Returned<'_>,
    workspace: &str,
    gate: &str,
    fresh: &mut Option<String>,
) -> Answer {
    let provider = back.provider;
    let label = match (provider, sign_in.oidc(provider)) {
        ("github", _) => "GitHub".to_string(),
        (_, Some(oidc)) => oidc.label.clone(),
        _ => return not_found(),
    };
    if let Some(error) = back.error {
        tracing::info!(target: "bd::serve", %provider, %error, "gate sign-in did not complete at the provider");
        return match error {
            // Apple says `user_cancelled_authorize`.
            "access_denied" | "user_cancelled_authorize" => refusal(
                403,
                &format!("The sign-in was cancelled at {label}. Open the gate's link again to approve it."),
            ),
            _ => refusal(502, &format!("{label} didn't complete the sign-in. Open the gate's link again.")),
        };
    }
    let Some(code) = back.code.filter(|c| !c.is_empty()) else {
        return refusal(400, &format!("{label} didn't return a sign-in code. Open the gate's link again."));
    };
    let callback_url = format!("{}{}", cx.issuer, super::super::callback(provider));
    // Who signed in, once the provider said: named on the page if the account is refused.
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
    let account = signed_in_as.map_or(String::new(), |login| format!(" ({login})"));
    let may_not = || format!("Your {label} account{account} may not approve gates in this workspace.");
    let admitted = match admitted {
        Ok(a) => a,
        Err(Error::Unauthorized(why)) => {
            metrics::APPROVALS_REFUSED.add();
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "gate approval refused");
            return refusal(403, &may_not());
        }
        Err(Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "gate sign-in did not complete");
            return refusal(400, &format!("{label} didn't finish signing you in. Open the gate's link again."));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "gate sign-in failed");
            return refusal(502, &format!("{label} didn't respond as expected. Try again in a moment."));
        }
        Err(Error::Busy(why) | Error::Locked(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "gate sign-in could not be decided");
            return refusal(503, "The server couldn't check your access just now. Try again in a moment.");
        }
        Err(e) => return internal(&e, "finishing a gate's sign-in"),
    };
    let user = &admitted.user;
    // Only a person approves, before anything about the gate is looked up.
    if admitted.grant.kind != auth::Kind::Human {
        metrics::APPROVALS_REFUSED.add();
        tracing::info!(
            target: "bd::serve",
            %provider,
            login = %user.login,
            subject = %user.subject,
            %workspace,
            "gate approval refused: the account's access is not a person's"
        );
        return refusal(403, &may_not());
    }
    let detail = format!("to approve gate {gate} in {workspace}; no token issued");
    let actor = match auth::bind_account(cx.root, user, admitted.by_login, &detail) {
        Ok(actor) => actor,
        Err(Error::Unauthorized(why)) => {
            metrics::APPROVALS_REFUSED.add();
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "gate approval refused");
            let why = format!(
                "Your {label} account{account} can't act on this server just now. Ask the server's admin about it."
            );
            return refusal(403, &why);
        }
        Err(Error::Busy(_) | Error::Locked(_)) => {
            return refusal(503, "The server is busy. Try again in a moment.");
        }
        Err(e) => return internal(&e, "binding an account to approve a gate"),
    };
    // From the identity the provider proved; never logged or shown.
    let oidc_approver = user.oidc_approver();
    let found = if (cx.workspace_exists)(workspace) {
        match cx.gates.find(workspace, gate) {
            Ok(found) => found,
            Err(Error::Busy(_) | Error::Locked(_)) => {
                return refusal(503, "The workspace is busy. Try again in a moment.");
            }
            Err(e) => return internal(&e, "looking up a gate to approve"),
        }
    } else {
        Found::NoWorkspace
    };
    let info = match found {
        Found::Gate(info) => info,
        other => return gone(&other, workspace, gate),
    };
    if info.resolved {
        return resolved(gate);
    }
    if !info.armed {
        return Answer::Page(pages::notice(409, "Not ready", NOT_READY));
    }
    if let Some(list) = &info.approvers
        && !bd_core::policy::approved_by(list, &actor, oidc_approver.as_deref())
    {
        metrics::APPROVALS_REFUSED.add();
        tracing::info!(
            target: "bd::serve",
            %provider,
            login = %user.login,
            subject = %user.subject,
            %actor,
            %workspace,
            %gate,
            "gate approval refused: not an approver"
        );
        let why = match list.as_slice() {
            [] => "Its approvers aren't valid, so nobody can approve it. A human admin can replace or clear them with \
                   bd gate update."
                .to_string(),
            list => {
                let mut why = format!("Only {} can approve it; you're signed in as {actor}.", list.join(" or "));
                if oidc_approver.is_some() {
                    why.push_str(&format!(
                        " An account signed in with {label} matches only an oidc:sha256: identity reference for its \
                         own issuer and subject."
                    ));
                }
                why
            }
        };
        return refusal(403, &bd_cli::io::printable(&why));
    }
    let secrets = (|| Ok::<_, Error>((auth::random_hex(32)?, auth::random_hex(32)?, auth::random_hex(4)?)))();
    let (id, value, suffix) = match secrets {
        Ok(s) => s,
        Err(e) => return internal(&e, "asking for a gate's approval"),
    };
    let action = format!("{}/w/{workspace}/gates/{gate}", cx.issuer);
    let page = pages::approve_gate(&pages::ApproveGate {
        workspace,
        gate: &info.id,
        title: &info.title,
        holds: &info.holds,
        part_of: info.part_of.as_ref().map(|(id, title)| (id.as_str(), title.as_str())),
        approvers: info.approvers.as_deref(),
        provider: &label,
        actor: &actor,
        id: &id,
        action: &action,
    });
    *fresh = Some(set_gate_cookie(cx.issuer, workspace, gate, &suffix, &value, STEP_TTL));
    let approval = Approval {
        workspace: workspace.to_string(),
        gate: gate.to_string(),
        actor,
        provider: user.provider.clone(),
        login: user.login.clone(),
        subject: user.subject.clone(),
        oidc_approver,
        browser: auth::hash(&value),
        cookie: suffix,
    };
    lock(cx.flows).approvals.put(auth::hash(&id), approval);
    Answer::Page(page)
}

/// The page for a path that names no human gate: told only to a person
/// the rules let into the workspace.
fn gone(found: &Found, workspace: &str, gate: &str) -> Answer {
    let (title, why) = match found {
        Found::NoWorkspace => ("No such workspace", format!("This server has no workspace {workspace}.")),
        Found::NoIssue => ("No such gate", format!("Workspace {workspace} has no issue {gate}.")),
        Found::NotGate => ("Not a gate", format!("{gate} in {workspace} is not a gate: there is nothing to approve.")),
        Found::NotHuman => (
            "Not a human gate",
            format!("{gate} in {workspace} is not a human gate: it opens on its own condition, not by approval."),
        ),
        Found::Gate(_) => return not_found(),
    };
    Answer::Page(pages::notice(404, title, &why))
}

fn resolved(gate: &str) -> Answer {
    Answer::Page(pages::notice(
        409,
        "Already resolved",
        &format!("Gate {gate} is already resolved: nothing to approve."),
    ))
}

/// `POST <public url>/w/<workspace>/gates/<gate>` with `approval=<id>`:
/// the approval the page [`signed_in`] showed, from the browser its cookie
/// binds it to, taken once. The gate is resolved as the approver.
pub fn approve(cx: &Ctx<'_>, workspace: &str, gate: &str, body: &str, cookies: &str) -> (Answer, Vec<String>) {
    if !valid_workspace_name(workspace) || !gate_id_ok(gate) {
        return (not_found(), Vec::new());
    }
    let pairs = form::decode(body).unwrap_or_default();
    let Some(id) = pairs.iter().find(|(k, _)| k == "approval").map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    else {
        return (refusal(400, "The form arrived incomplete. Open the gate's link again."), Vec::new());
    };
    let key = auth::hash(id);
    let approval = {
        let mut flows = lock(cx.flows);
        if flows.approvals_spent.get_mut(&key).is_some() {
            return (refusal(400, "This approval was already used."), Vec::new());
        }
        // Taken only by the browser it is bound to: another one that learned its id must not spend it.
        let bound =
            |a: &Approval| gate_cookie(cx.issuer, cookies, &a.cookie).map(auth::hash).as_deref() == Some(&a.browser);
        match flows.approvals.get_mut(&key).map(|a| (bound(a), a.workspace == workspace && a.gate == gate)) {
            None => return (refusal(400, EXPIRED), Vec::new()),
            Some((false, _)) => {
                let why = "This approval started in a different browser. Open the gate's link again in this one.";
                return (refusal(403, why), Vec::new());
            }
            Some((true, false)) => return (refusal(400, "This approval is for another gate."), Vec::new()),
            Some((true, true)) => {}
        }
        let Some(approval) = flows.approvals.take(&key) else {
            return (refusal(400, EXPIRED), Vec::new());
        };
        flows.approvals_spent.put(key, ());
        approval
    };
    let cleared = vec![set_gate_cookie(cx.issuer, workspace, gate, &approval.cookie, "", Duration::ZERO)];
    // `[oauth]` may have been turned off since the page was shown.
    if let Err(answer) = settings(cx) {
        return (answer, cleared);
    }
    let actor = &approval.actor;
    // The reference the sign-in proved, kept with the approval: nothing in the form is read but its id.
    let (outcome, answer) = match cx.gates.approve(workspace, gate, actor, approval.oidc_approver.as_deref()) {
        Ok(Approved::Opened { unblocked, completed }) => {
            metrics::APPROVALS.add();
            let mut why = format!("Gate {gate} in {workspace} is resolved, recorded as approved by {actor}.");
            if !unblocked.is_empty() {
                why.push_str(" The work it held back can go ahead.");
            }
            if !completed.is_empty() {
                why.push_str(" Its run is complete.");
            }
            ("approved", Answer::Page(pages::notice(200, "Approved", &bd_cli::io::printable(&why))))
        }
        Ok(Approved::Resolved) => ("already resolved", resolved(gate)),
        Ok(Approved::NotArmed) => ("not ready", Answer::Page(pages::notice(409, "Not ready", NOT_READY))),
        Ok(Approved::Gone(found)) => ("gone", gone(&found, workspace, gate)),
        Ok(Approved::Refused(why)) => {
            metrics::APPROVALS_REFUSED.add();
            ("refused", refusal(403, &bd_cli::io::printable(&why)))
        }
        Err(Error::Busy(_) | Error::Locked(_)) => {
            ("busy", refusal(503, "The workspace is busy. Open the gate's link again in a moment."))
        }
        Err(e) => ("failed", internal(&e, "approving a gate")),
    };
    tracing::info!(
        target: "bd::serve",
        outcome,
        provider = %approval.provider,
        login = %approval.login,
        subject = %approval.subject,
        %actor,
        %workspace,
        %gate,
        "gate approval"
    );
    (answer, cleared)
}
