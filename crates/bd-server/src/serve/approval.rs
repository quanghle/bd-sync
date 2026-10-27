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
    fn find(&self, workspace: &str, gate: &str, approver: &authorize::Approver<'_>) -> Result<authorize::Found> {
        let Some(ws) = self.workspace(workspace) else { return Ok(authorize::Found::NoWorkspace) };
        let store = ws.take(&self.open)?;
        let found = store.read(|r| find_gate(r.conn(), gate, approver));
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

/// The gate `id` (exactly) as its approval page shows it, or what `id` is
/// instead. Its approval packet is read, in the same read as the arming
/// check, only when the gate is open and armed and `approver` may open it
/// (`policy::approved_by`, as the approval page and the approval check):
/// nobody else causes it to be read.
fn find_gate(conn: &rusqlite::Connection, id: &str, approver: &authorize::Approver<'_>) -> Result<authorize::Found> {
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
    let approvers = gates::approvers_of(&issue);
    let eligible = !issue.status.is_terminal()
        && view.is_armed()
        && approvers.as_ref().is_none_or(|l| bd_core::policy::approved_by(l, approver.actor, approver.oidc_approver));
    let packet = eligible.then(|| gates::packet::collect(conn, &issue.id, &view.blocks)).transpose()?;
    Ok(Found::Gate(Box::new(GateInfo {
        armed: view.is_armed(),
        resolved: issue.status.is_terminal(),
        approvers,
        holds: view.blocks.into_iter().map(|b| (b.id, b.title, b.status.to_string())).collect(),
        part_of,
        packet,
        id: issue.id,
        title: issue.title,
    })))
}

#[cfg(test)]
mod tests {
    use bd_core::gates::packet::Role;
    use bd_core::gates::{GateSpec, NewGate};
    use bd_core::model::{DepType, NewIssue};
    use bd_core::store::InitOptions;

    use super::authorize::{Approver, Found, GateInfo};
    use super::*;

    const CAROL: &str = "carol";
    /// An OIDC identity reference, as `gate create --oidc-approver` stores one.
    const REFERENCE: &str = "oidc:sha256:cc1c733abb44cc4515567045ad93eceb8b582889810bd9739c65c8d0e3c71247";

    struct Ws {
        dir: tempfile::TempDir,
        store: Store,
    }

    impl Ws {
        fn new() -> Ws {
            let dir = tempfile::tempdir().unwrap();
            let init = InitOptions { prefix: "t".into(), id_mode: Default::default() };
            let store = Store::init(&dir.path().join("bd.db"), init, OpenOptions::default()).unwrap();
            Ws { dir, store }
        }

        fn task(&mut self, title: &str) -> String {
            let new = NewIssue { description: format!("{title} DESCRIBED"), ..NewIssue::titled(title) };
            self.store.write("test", "alice", |tx| tx.create_issue(new)).unwrap().id
        }

        /// A human gate holding back `held`, naming `approvers` if any.
        fn gate(&mut self, held: &str, approvers: Option<&[&str]>) -> String {
            let mut spec = GateSpec::new(GateKind::Human);
            spec.approvers = approvers.map(|l| l.iter().map(|a| a.to_string()).collect());
            let g = NewGate {
                spec,
                blocks: vec![held.to_string()],
                title: None,
                description: "GATE-DESCRIBED".into(),
                assignee: None,
                parent: None,
                priority: None,
                ephemeral: false,
            };
            self.store.write("test", "alice", |tx| tx.create_gate(g)).unwrap().id
        }

        fn find(&self, gate: &str, actor: &str, oidc_approver: Option<&str>) -> Result<Found> {
            let approver = Approver { actor, oidc_approver };
            self.store.read(|r| find_gate(r.conn(), gate, &approver))
        }

        fn info(&self, gate: &str, actor: &str, oidc_approver: Option<&str>) -> GateInfo {
            match self.find(gate, actor, oidc_approver).unwrap() {
                Found::Gate(info) => *info,
                other => panic!("{gate}: {other:?}"),
            }
        }

        /// Break the comments table, as a damaged workspace would have it, on
        /// a connection of its own to the workspace's database.
        fn lose_comments(&self) {
            let raw = rusqlite::Connection::open(self.dir.path().join("bd.db")).unwrap();
            raw.execute_batch("ALTER TABLE comments RENAME TO comments_gone").unwrap();
        }
    }

    #[test]
    fn an_armed_gate_without_approvers_comes_with_its_packet() {
        let mut ws = Ws::new();
        let task = ws.task("Deploy");
        let gate = ws.gate(&task, None);
        let info = ws.info(&gate, "alice", None);
        assert!(info.armed && !info.resolved);
        let packet = info.packet.expect("packet");
        let order: Vec<(Role, &str)> = packet.sources.iter().map(|s| (s.role, s.id.as_str())).collect();
        assert_eq!(order, [(Role::Gate, gate.as_str()), (Role::Held, task.as_str())]);
        assert!(!packet.playbook);
    }

    #[test]
    fn only_an_approver_causes_the_packet_to_be_read() {
        let mut ws = Ws::new();
        let task = ws.task("Keys");
        let gate = ws.gate(&task, Some(&[CAROL]));
        let alice = ws.info(&gate, "alice", None);
        assert!(alice.armed, "the gate is found as it is");
        assert_eq!(alice.approvers.as_deref(), Some(&[CAROL.to_string()][..]));
        assert_eq!(alice.packet, None);
        assert!(ws.info(&gate, CAROL, None).packet.is_some());
        assert!(ws.info(&gate, "carol/copilot-1", None).packet.is_some(), "a session of the approver");
        // An OIDC account matches by its reference only, never by its actor.
        assert_eq!(ws.info(&gate, CAROL, Some(REFERENCE)).packet, None);
    }

    #[test]
    fn an_oidc_approver_matches_only_by_its_reference() {
        let mut ws = Ws::new();
        let task = ws.task("Rotate");
        let gate = ws.gate(&task, Some(&[REFERENCE]));
        assert!(ws.info(&gate, "oidc:dex:u-1", Some(REFERENCE)).packet.is_some());
        assert_eq!(ws.info(&gate, "oidc:dex:u-1", None).packet, None);
        assert_eq!(ws.info(&gate, REFERENCE, None).packet, None, "a reference is never an actor");
        let other = "oidc:sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(ws.info(&gate, "oidc:dex:u-1", Some(other)).packet, None);
    }

    #[test]
    fn unarmed_and_resolved_gates_come_without_a_packet() {
        let mut ws = Ws::new();
        let (held, first) = (ws.task("Held"), ws.task("First"));
        ws.store.write("test", "alice", |tx| tx.add_dependency(&held, &first, DepType::Blocks, None)).unwrap();
        let unarmed = ws.gate(&held, None);
        let info = ws.info(&unarmed, "alice", None);
        assert!(!info.armed);
        assert_eq!(info.packet, None);

        let task = ws.task("Done");
        let resolved = ws.gate(&task, None);
        ws.store.write("test", "alice", |tx| tx.resolve_gate(&resolved, None, false, None)).unwrap();
        let info = ws.info(&resolved, "alice", None);
        assert!(info.resolved);
        assert_eq!(info.packet, None);
    }

    #[test]
    fn a_failed_read_refuses_only_an_eligible_approver() {
        let mut ws = Ws::new();
        let task = ws.task("Keys");
        let gate = ws.gate(&task, Some(&[CAROL]));
        let (held, first) = (ws.task("Held"), ws.task("First"));
        ws.store.write("test", "alice", |tx| tx.add_dependency(&held, &first, DepType::Blocks, None)).unwrap();
        let unarmed = ws.gate(&held, None);
        ws.lose_comments();
        // Nobody else causes the packet to be read, so nothing fails for them.
        let alice = ws.info(&gate, "alice", None);
        assert!(alice.armed && alice.packet.is_none());
        let info = ws.info(&unarmed, CAROL, None);
        assert!(!info.armed && info.packet.is_none());
        // The approver's packet cannot be read: refused, never a page without it.
        assert!(ws.find(&gate, CAROL, None).is_err());
    }
}
