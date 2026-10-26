//! Human gates approved in the browser: `<public url>/w/<name>/gates/<id>`
//! (`oauth_server/authorize/gate.rs`), served only while the authorization
//! server is (`[oauth]` with a browser provider, and `--public-url`), and
//! the gates it approves ([`authorize::Gates`] for [`Server`]).

use bd_core::gates::{self, GateKind};
use bd_core::issues;
use bd_core::model::GATE_TYPE;
use bd_core::policy::Policy;

use super::*;

/// Not found, as for any path the server does not serve: approvals cannot
/// be served now, or never could.
fn no_approvals() -> Response<Body> {
    html_page(pages::notice(404, "Not found", "There is nothing to approve here."))
}

/// `GET` (the approval page, after a sign-in) or `POST` (the approval) at
/// `<public url>/w/<workspace>/gates/<gate>`. Without `--public-url`,
/// `[oauth]`, or a browser provider, there is no such page.
pub(super) async fn gate_approval(
    server: &Arc<Server>,
    workspace: &str,
    gate: &str,
    req: Request<Incoming>,
) -> Response<Body> {
    let issuer = match server.approvals_issuer() {
        Ok(Some(issuer)) => issuer,
        Ok(None) => return no_approvals(),
        // Settings that cannot be used now (startup refused them; edited since): no approvals, said in the log.
        Err(e @ Error::Invalid(_)) => {
            log_misconfigured(&e);
            return no_approvals();
        }
        Err(e) => return sign_in_misconfigured(&e),
    };
    let (workspace, gate) = (workspace.to_string(), gate.to_string());
    let srv = server.clone();
    if req.method() != Method::POST {
        let done = blocking(move || Ok(srv.authorizing(&issuer, |cx| authorize::gate::begin(cx, &workspace, &gate))));
        return match done.await {
            Ok((answer, cookies)) => answered(answer, &cookies, false),
            Err(e) => Reject::internal(e).response(),
        };
    }
    // Only the approval page posts here: its cookie is SameSite=Strict, and this keeps out other sites' requests.
    if !same_origin(req.headers(), &issuer) {
        metrics::APPROVALS_REFUSED.add();
        let why = "The approval came from another site. Open the gate's link again.";
        return html_page(pages::notice(403, "Couldn't approve the gate", why));
    }
    let cookies: String =
        req.headers().get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; ");
    let Ok(body) = read_body(req.into_body(), MAX_CONSENT_BODY, HEADER_TIMEOUT).await else {
        let why = "The approval didn't arrive complete. Open the gate's link again.";
        return html_page(pages::notice(400, "Couldn't approve the gate", why));
    };
    let body = String::from_utf8_lossy(&body).into_owned();
    let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
        let why = "Too many sign-ins are in progress. Try again in a moment.";
        return html_page(pages::notice(503, "The server is busy", why));
    };
    let done = blocking(move || {
        let _permit = permit;
        Ok(srv.authorizing(&issuer, |cx| authorize::gate::approve(cx, &workspace, &gate, &body, &cookies)))
    })
    .await;
    match done {
        Ok((answer, cookies)) => answered(answer, &cookies, true),
        Err(e) => Reject::internal(e).response(),
    }
}

impl authorize::Gates for Server {
    fn find(&self, workspace: &str, gate: &str) -> Result<authorize::Found> {
        let Some(ws) = self.workspace(workspace) else { return Ok(authorize::Found::NoWorkspace) };
        let store = ws.take(&self.open)?;
        let found = store.read(|r| find_gate(r.conn(), gate));
        ws.give(store);
        found
    }

    fn approve(
        &self,
        workspace: &str,
        gate: &str,
        actor: &str,
        oidc_approver: Option<&str>,
    ) -> Result<authorize::Approved> {
        use authorize::{Approved, Found};
        let Some(ws) = self.workspace(workspace) else { return Ok(Approved::Gone(Found::NoWorkspace)) };
        let mut store = ws.take(&self.open)?;
        let reason = format!("approved in the browser by {actor}");
        let done = store.write("gate.resolve", actor, |tx| {
            // A person, as the approver's actor: the same checks as a human token's `bd gate resolve`, its
            // approvers among them, an OIDC account matching only by the reference its sign-in proved.
            tx.set_policy(Some(Policy {
                actor: actor.to_string(),
                admin: false,
                human: true,
                max_claims: None,
                oidc_approver: oidc_approver.map(String::from),
            }));
            let Some(issue) = issues::get(tx.conn(), gate)? else { return Ok(Approved::Gone(Found::NoIssue)) };
            if issue.issue_type != GATE_TYPE {
                return Ok(Approved::Gone(Found::NotGate));
            }
            if !gates::spec_of(&issue).is_ok_and(|s| s.kind == GateKind::Human) {
                return Ok(Approved::Gone(Found::NotHuman));
            }
            if issue.status.is_terminal() {
                return Ok(Approved::Resolved);
            }
            // As the page found it: open, and holding back work that waits for nothing else.
            if !gates::view_of(tx.conn(), &issue)?.is_armed() {
                return Ok(Approved::NotArmed);
            }
            let closed = tx.resolve_gate(gate, Some(&reason), false, Some("browser"))?;
            Ok(Approved::Opened {
                unblocked: closed.unblocked.into_iter().map(|i| i.id).collect(),
                completed: closed.completed.into_iter().map(|i| i.id).collect(),
            })
        });
        ws.give(store);
        match done {
            Ok(opened @ Approved::Opened { .. }) => {
                // Requests waiting for events check again.
                self.feeds.committed(&ws.name);
                Ok(opened)
            }
            Ok(other) => Ok(other),
            Err(Error::Unauthorized(why)) => Ok(Approved::Refused(why)),
            Err(e) => Err(e),
        }
    }
}

/// The gate `id` (exactly) as its approval page shows it, or what `id` is instead.
fn find_gate(conn: &rusqlite::Connection, id: &str) -> Result<authorize::Found> {
    use authorize::{Found, GateInfo};
    let Some(issue) = issues::get(conn, id)? else { return Ok(Found::NoIssue) };
    if issue.issue_type != GATE_TYPE {
        return Ok(Found::NotGate);
    }
    if !gates::spec_of(&issue).is_ok_and(|s| s.kind == GateKind::Human) {
        return Ok(Found::NotHuman);
    }
    let view = gates::view_of(conn, &issue)?;
    let part_of = gates::run_of(conn, id)?.map(|r| (r.id, r.title));
    Ok(Found::Gate(Box::new(GateInfo {
        armed: view.is_armed(),
        resolved: issue.status.is_terminal(),
        approvers: gates::approvers_of(&issue),
        holds: view.blocks.into_iter().map(|b| (b.id, b.title, b.status.to_string())).collect(),
        part_of,
        id: issue.id,
        title: issue.title,
    })))
}
