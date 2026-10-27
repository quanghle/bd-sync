//! Human gates approved in the browser: `<public url>/w/<name>/gates/<id>`
//! (`oauth_server/authorize/gate.rs`), served only while the authorization
//! server is (`[oauth]` with a browser provider, and `--public-url`), and
//! the gates it approves ([`authorize::Gates`] for [`Server`]); and closes
//! and discards that open human gates refused, approved from their sealed
//! links `<public url>/w/<name>/(close|discard)/<id>?request=...`
//! (`oauth_server/authorize/operation.rs`, [`authorize::Operations`] for
//! [`Server`]).

use bd_cli::approval_link::{Op, OperationRequest};
use bd_core::gates::{self, GateKind};
use bd_core::issues::{self, CloseOptions};
use bd_core::model::{GATE_TYPE, Outcome, Status};
use bd_core::playbook::{self, DiscardOptions};
use bd_core::policy::{self, Policy};

use crate::oauth_server::form;

use super::*;

/// Not found, as for any path the server does not serve: approvals cannot
/// be served now, or never could.
fn no_approvals() -> Response<Body> {
    html_page(pages::notice(404, "Not found", "There is nothing to approve here."))
}

/// `GET` (the approval page, after a sign-in) or `POST` (the approval) at
/// `<public url>/w/<workspace>/gates/<gate>`; any other method gets 405
/// (`Allow: GET, POST`) once the page is served. Without `--public-url`,
/// `[oauth]`, or a browser provider, there is no such page: every method
/// gets 404.
pub(super) async fn gate_approval<B>(
    server: &Arc<Server>,
    workspace: &str,
    gate: &str,
    req: Request<B>,
) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
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
    // Only once the page is served, so a server without approvals answers 404 to every method.
    if req.method() != Method::GET && req.method() != Method::POST {
        let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET or POST", 2).response();
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
        return r;
    }
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

/// `GET` (on to the sign-in, after checking the link's seal) or `POST` (the
/// approval) at `<public url>/w/<workspace>/<op>/<issue>`, as
/// [`gate_approval`] serves a gate's page: 404 for every method while
/// approvals are not served, 405 for other methods once they are. Every
/// answer to a POST is recorded once (`authorize::record`); a POST while the
/// sign-in settings cannot be used only when its approval id names a page
/// this process showed for that path, which it leaves waiting.
pub(super) async fn operation_approval<B>(
    server: &Arc<Server>,
    workspace: &str,
    op: Op,
    issue: &str,
    req: Request<B>,
) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let issuer = match server.approvals_issuer() {
        Ok(Some(issuer)) => issuer,
        Ok(None) => {
            unusable_settings_post(server, workspace, op, issue, req).await;
            return no_approvals();
        }
        Err(e @ Error::Invalid(_)) => {
            log_misconfigured(&e);
            unusable_settings_post(server, workspace, op, issue, req).await;
            return no_approvals();
        }
        Err(e) => {
            unusable_settings_post(server, workspace, op, issue, req).await;
            return sign_in_misconfigured(&e);
        }
    };
    if req.method() != Method::GET && req.method() != Method::POST {
        let mut r = Reject::new(StatusCode::METHOD_NOT_ALLOWED, "invalid", "use GET or POST", 2).response();
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
        return r;
    }
    let (workspace, issue) = (workspace.to_string(), issue.to_string());
    let srv = server.clone();
    if req.method() != Method::POST {
        let query = req.uri().query().unwrap_or_default().to_string();
        let done = blocking(move || {
            Ok(srv.authorizing(&issuer, |cx| authorize::operation::begin(cx, &workspace, op.as_str(), &issue, &query)))
        });
        return match done.await {
            Ok((answer, cookies)) => answered(answer, &cookies, false),
            Err(e) => Reject::internal(e).response(),
        };
    }
    let (logged_ws, logged_issue) = authorize::operation::logged(&workspace, &issue);
    let record = |outcome, detail| {
        authorize::record(outcome, &authorize::Who::default(), logged_ws, op.as_str(), logged_issue, detail);
    };
    const TITLE: &str = "Couldn't approve the operation";
    // Only the approval page posts here: its cookie is SameSite=Strict, and this keeps out other sites' requests.
    if !same_origin(req.headers(), &issuer) {
        record(authorize::Outcome::Refused, "cross-site");
        let why = "The approval came from another site. Open the approval link again.";
        return html_page(pages::notice(403, TITLE, why));
    }
    let cookies: String =
        req.headers().get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; ");
    let Ok(body) = read_body(req.into_body(), MAX_CONSENT_BODY, HEADER_TIMEOUT).await else {
        record(authorize::Outcome::Refused, "form unreadable");
        let why = "The approval didn't arrive complete. Open the approval link again.";
        return html_page(pages::notice(400, TITLE, why));
    };
    let body = String::from_utf8_lossy(&body).into_owned();
    let Ok(permit) = server.sign_ins.clone().try_acquire_owned() else {
        record(authorize::Outcome::Busy, "too many sign-ins");
        let why = "Too many sign-ins are in progress. Try again in a moment.";
        return html_page(pages::notice(503, "The server is busy", why));
    };
    let (ws, id) = (workspace.clone(), issue.clone());
    let done = blocking(move || {
        let _permit = permit;
        Ok(srv.authorizing(&issuer, |cx| authorize::operation::approve(cx, &ws, op.as_str(), &id, &body, &cookies)))
    })
    .await;
    match done {
        Ok((answer, cookies)) => answered(answer, &cookies, true),
        Err(e) => {
            // The step did not finish (it panicked): it never recorded its outcome.
            record(authorize::Outcome::Failed, "internal error");
            Reject::internal(e).response()
        }
    }
}

/// A POST to an operation's approval path while the sign-in settings cannot
/// be used: recorded as failed when its `approval` id names a page this
/// process showed for this very path and still waiting for it (peeked, not
/// taken, so it can be posted again once the settings are repaired); not
/// otherwise, as anyone may post anything here.
async fn unusable_settings_post<B>(server: &Server, workspace: &str, op: Op, issue: &str, req: Request<B>)
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() != Method::POST || server.public_issuer().is_none() {
        return;
    }
    let Ok(body) = read_body(req.into_body(), MAX_CONSENT_BODY, HEADER_TIMEOUT).await else { return };
    let pairs = form::decode(&String::from_utf8_lossy(&body)).unwrap_or_default();
    let Some(id) = pairs.iter().find(|(k, _)| k == "approval").map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    else {
        return;
    };
    if let Some((provider, login, subject, actor)) =
        authorize::pending_operation(&server.flows, id, workspace, op.as_str(), issue)
    {
        let who = authorize::Who { provider: &provider, login: &login, subject: &subject, actor: &actor };
        authorize::record(
            authorize::Outcome::Failed,
            &who,
            workspace,
            op.as_str(),
            issue,
            "sign-in settings unavailable",
        );
    }
}

/// The ids an operation is checked over: the issue closed, or every issue of
/// the run discarded; its run (for a close), and for a discard what it
/// deletes. Or why `issue` is not what `req` was for.
type Targets = (Vec<String>, Option<(String, String)>, Option<(Vec<(String, String)>, usize)>);

fn targets(
    conn: &rusqlite::Connection,
    req: &OperationRequest,
    issue: &bd_core::model::Issue,
) -> Result<std::result::Result<Targets, authorize::OpFound>> {
    use authorize::OpFound;
    let id = &issue.id;
    match req.op {
        Op::Close => {
            if issue.status == Status::Closed {
                return Ok(Err(OpFound::Done));
            }
            if issue.status == Status::Pinned {
                return Ok(Err(OpFound::Changed(format!("{id} is pinned now."))));
            }
            if issue.issue_type == GATE_TYPE {
                return Ok(Err(OpFound::Changed(format!("{id} is a gate."))));
            }
            let part_of = gates::run_of(conn, id)?.map(|r| (r.id, r.title));
            Ok(Ok((vec![id.clone()], part_of, None)))
        }
        Op::Discard => {
            // A run closed (a forced close leaves its steps) is still discarded: only being a run counts.
            if playbook::role_of(issue) != Some(playbook::Role::Run) {
                return Ok(Err(OpFound::Changed(format!("{id} is not a playbook run."))));
            }
            let all = playbook::run_issues(conn, id)?;
            let total = all.len();
            let listed = all.iter().take(pages::MAX_DELETES).map(|i| (i.id.clone(), i.title.clone())).collect();
            Ok(Ok((all.into_iter().map(|i| i.id).collect(), None, Some((listed, total)))))
        }
    }
}

/// `req`'s target as its approval page shows it to `approver`.
fn find_operation(
    conn: &rusqlite::Connection,
    req: &OperationRequest,
    approver: &authorize::Approver<'_>,
) -> Result<authorize::OpFound> {
    use authorize::{GateInWay, OpFound, OpInfo};
    let Some(issue) = issues::get(conn, &req.issue)? else { return Ok(OpFound::NoIssue) };
    let (ids, part_of, deletes) = match targets(conn, req, &issue)? {
        Ok(t) => t,
        Err(found) => return Ok(found),
    };
    let in_the_way = policy::gates_in_the_way(conn, &ids)?;
    if in_the_way.is_empty() {
        return Ok(OpFound::NotHeld);
    }
    let person = approver_policy(approver.actor, approver.oidc_approver);
    let gates = in_the_way
        .into_iter()
        .map(|g| GateInWay {
            may_open: policy::may_open(&person, &g),
            approvers: gates::approvers_of(&g),
            id: g.id,
            title: g.title,
        })
        .collect();
    Ok(OpFound::Op(Box::new(OpInfo {
        status: issue.status.to_string(),
        id: issue.id,
        title: issue.title,
        part_of,
        gates,
        deletes,
    })))
}

/// The policy a person approving in the browser acts under: human, not an
/// admin, no claim limit, and an OIDC account matching only by its reference.
fn approver_policy(actor: &str, oidc_approver: Option<&str>) -> Policy {
    Policy {
        actor: actor.to_string(),
        admin: false,
        human: true,
        max_claims: None,
        oidc_approver: oidc_approver.map(String::from),
    }
}

impl authorize::Operations for Server {
    fn find(&self, req: &OperationRequest, approver: &authorize::Approver<'_>) -> Result<authorize::OpFound> {
        let Some(ws) = self.workspace(&req.workspace) else { return Ok(authorize::OpFound::NoWorkspace) };
        let store = ws.take(&self.open)?;
        let found = store.read(|r| find_operation(r.conn(), req, approver));
        ws.give(store);
        found
    }

    fn perform(
        &self,
        req: &OperationRequest,
        actor: &str,
        oidc_approver: Option<&str>,
    ) -> Result<authorize::Performed> {
        use authorize::{OpFound, Performed};
        let Some(ws) = self.workspace(&req.workspace) else { return Ok(Performed::Gone(OpFound::NoWorkspace)) };
        let mut store = ws.take(&self.open)?;
        let done = perform_in(&mut store, req, actor, oidc_approver);
        ws.give(store);
        match done {
            Ok(performed @ (Performed::Closed | Performed::Discarded { .. })) => {
                // Requests waiting for events check again.
                self.feeds.committed(&ws.name);
                Ok(performed)
            }
            other => other,
        }
    }
}

/// Perform `req` in `store` as `actor`, in one transaction: the target
/// checked again, then exactly the close or discard asked for, with the
/// sealed reason and flags, never taking over a claim. A refusal of the
/// transaction's (another actor's claim, a gate the approver may not open)
/// is [`authorize::Performed::Refused`], nothing written.
fn perform_in(
    store: &mut Store,
    req: &OperationRequest,
    actor: &str,
    oidc_approver: Option<&str>,
) -> Result<authorize::Performed> {
    use authorize::{OpFound, Performed};
    let command = match req.op {
        Op::Close => "close",
        Op::Discard => "playbook.discard",
    };
    let done = store.write(command, actor, |tx| {
        // A person, as the approver's actor: the same checks as a human token's own close or discard.
        tx.set_policy(Some(approver_policy(actor, oidc_approver)));
        let Some(issue) = issues::get(tx.conn(), &req.issue)? else { return Ok(Performed::Gone(OpFound::NoIssue)) };
        let ids = match targets(tx.conn(), req, &issue)? {
            Ok((ids, _, _)) => ids,
            Err(OpFound::Done) => return Ok(Performed::Done),
            Err(OpFound::Changed(why)) => return Ok(Performed::Changed(why)),
            Err(other) => return Ok(Performed::Gone(other)),
        };
        if policy::gates_in_the_way(tx.conn(), &ids)?.is_empty() {
            return Ok(Performed::NotHeld);
        }
        match req.op {
            Op::Close => {
                tx.close_issue(
                    &req.issue,
                    &CloseOptions {
                        reason: req.reason.clone(),
                        outcome: Some(if req.failed { Outcome::Failed } else { Outcome::Done }),
                        force: req.force,
                        take_over: false,
                        via: Some("browser".into()),
                        requested_by: Some(req.requester.clone()),
                        ..CloseOptions::default()
                    },
                )?;
                Ok(Performed::Closed)
            }
            Op::Discard => {
                let out = tx.discard_run(
                    &req.issue,
                    &DiscardOptions {
                        force: req.force,
                        take_over: false,
                        dry_run: false,
                        reason: req.reason.clone(),
                        via: Some("browser".into()),
                        requested_by: Some(req.requester.clone()),
                    },
                )?;
                Ok(Performed::Discarded { count: out.deleted.len() })
            }
        }
    });
    match done.map_err(Error::into_unmarked) {
        Ok(performed) => Ok(performed),
        Err(
            e @ (Error::Unauthorized(_)
            | Error::Needs { .. }
            | Error::NotOwner { .. }
            | Error::ClaimsHeld { .. }
            | Error::Refused(_)),
        ) => Ok(Performed::Refused(e.to_string())),
        Err(e) => Err(e),
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
        match done.map_err(Error::into_unmarked) {
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
    use bd_core::Queries;
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

    const AGENT: &str = "alice/agent-1";

    impl Ws {
        /// A run of `steps` plain steps and a last one held by a human gate naming `approvers`.
        fn run(&mut self, steps: usize, approvers: &str) -> String {
            let mut toml = String::new();
            for i in 0..steps {
                toml.push_str(&format!("[[steps]]\nid = \"s{i}\"\n"));
            }
            toml.push_str(&format!(
                "[[steps]]\nid = \"ship\"\n[steps.gate]\ntype = \"human\"\napprovers = {approvers}\n"
            ));
            let pb = playbook::parse_toml(&toml, "test.toml", "test").unwrap();
            let plan = playbook::compile(&pb, &playbook::RunRequest::default(), &playbook::Loader::default()).unwrap();
            let opts = playbook::StartOptions::default();
            self.store.write("run", "alice", |tx| tx.start_run(&plan, &opts)).unwrap().run.id
        }

        fn issues_of(&self, run: &str) -> Vec<bd_core::model::Issue> {
            self.store.read(|r| playbook::run_issues(r.conn(), run)).unwrap()
        }

        fn gate_of(&self, run: &str) -> String {
            self.issues_of(run).into_iter().find(|i| i.issue_type == GATE_TYPE).unwrap().id
        }

        fn issue(&self, id: &str) -> Option<bd_core::model::Issue> {
            self.store.read(|r| issues::get(r.conn(), id)).unwrap()
        }

        fn find_op(&self, req: &OperationRequest, actor: &str, oidc_approver: Option<&str>) -> authorize::OpFound {
            let approver = Approver { actor, oidc_approver };
            self.store.read(|r| find_operation(r.conn(), req, &approver)).unwrap()
        }

        fn op_info(&self, req: &OperationRequest, actor: &str, oidc_approver: Option<&str>) -> authorize::OpInfo {
            match self.find_op(req, actor, oidc_approver) {
                authorize::OpFound::Op(info) => *info,
                other => panic!("{other:?}"),
            }
        }

        fn perform(&mut self, req: &OperationRequest, actor: &str) -> authorize::Performed {
            perform_in(&mut self.store, req, actor, None).unwrap()
        }

        fn events(&self, id: &str, op: &str) -> Vec<bd_core::model::Event> {
            let q =
                bd_core::events::EventQuery { issue_id: Some(id.into()), ops: vec![op.into()], ..Default::default() };
            self.store.read(|r| r.events(&q)).unwrap().events
        }

        fn head(&self) -> usize {
            let q = bd_core::events::EventQuery { limit: Some(100_000), ..Default::default() };
            self.store.read(|r| r.events(&q)).unwrap().events.len()
        }
    }

    fn requested(op: Op, issue: &str, reason: &str) -> OperationRequest {
        OperationRequest {
            reason: Some(reason.into()),
            force: true,
            ..OperationRequest::new("proj".into(), op, issue.into(), AGENT.into(), 1)
        }
    }

    #[test]
    fn an_operation_lists_the_gates_in_its_way_and_who_may_open_them() {
        let mut ws = Ws::new();
        let task = ws.task("Abandoned");
        let carols = ws.gate(&task, Some(&["github:carol", REFERENCE]));
        let anyone = ws.gate(&task, None);
        let req = requested(Op::Close, &task, "why");
        let may_open = |info: &authorize::OpInfo| -> Vec<(String, bool)> {
            info.gates.iter().map(|g| (g.id.clone(), g.may_open)).collect()
        };
        let mut both = [carols.clone(), anyone.clone()];
        both.sort();
        let opens = |carol: bool| -> Vec<(String, bool)> {
            both.iter().map(|g| (g.clone(), if *g == carols { carol } else { true })).collect()
        };
        let info = ws.op_info(&req, "github:carol", None);
        assert_eq!(may_open(&info), opens(true));
        assert_eq!((info.id.as_str(), info.title.as_str(), info.status.as_str()), (task.as_str(), "Abandoned", "open"));
        assert_eq!((info.part_of.clone(), info.deletes.clone()), (None, None));
        let listed = info.gates.iter().find(|g| g.id == carols).unwrap();
        assert_eq!(listed.approvers.as_deref(), Some(&["github:carol".to_string(), REFERENCE.to_string()][..]));
        assert_eq!(info.gates.iter().find(|g| g.id == anyone).unwrap().approvers, None);
        assert_eq!(may_open(&ws.op_info(&req, "github:carol/laptop", None)), opens(true), "a session of the approver");
        assert_eq!(may_open(&ws.op_info(&req, "oidc:dex:u-1", Some(REFERENCE))), opens(true), "by its reference");
        assert_eq!(
            may_open(&ws.op_info(&req, "github:carol", Some(REFERENCE.replace('c', "d").as_str()))),
            opens(false)
        );
        assert_eq!(may_open(&ws.op_info(&req, "github:alice", None)), opens(false));

        // A step of a run: part of it.
        let run = ws.run(1, "[\"github:carol\"]");
        let step = ws.issues_of(&run).into_iter().find(|i| i.id.ends_with(".ship")).unwrap().id;
        let info = ws.op_info(&requested(Op::Close, &step, "why"), "github:carol", None);
        assert_eq!(info.part_of.map(|(id, _)| id), Some(run));
    }

    #[test]
    fn a_target_no_longer_as_asked_is_told_apart() {
        use authorize::OpFound;
        let mut ws = Ws::new();
        let task = ws.task("Held");
        let gate = ws.gate(&task, None);
        let close = |id: &str| requested(Op::Close, id, "why");
        assert!(matches!(ws.find_op(&close(&gate), "a", None), OpFound::Changed(why) if why.contains("is a gate")));
        assert_eq!(ws.find_op(&close("t-404"), "a", None), OpFound::NoIssue);
        assert!(
            matches!(ws.find_op(&requested(Op::Discard, &task, "x"), "a", None), OpFound::Changed(why) if why.contains("not a playbook run"))
        );
        let free = ws.task("Free");
        assert_eq!(ws.find_op(&close(&free), "a", None), OpFound::NotHeld);
        let pinned = ws.task("Pinned");
        ws.gate(&pinned, None);
        let pin = bd_core::model::IssuePatch { status: Some(Status::Pinned), ..Default::default() };
        ws.store.write("test", "alice", |tx| tx.update_issue(&pinned, &pin, &Default::default(), false)).unwrap();
        assert!(matches!(ws.find_op(&close(&pinned), "a", None), OpFound::Changed(why) if why.contains("pinned")));
        ws.store.write("test", "alice", |tx| tx.close_issue(&free, &CloseOptions::default())).unwrap();
        assert_eq!(ws.find_op(&close(&free), "a", None), OpFound::Done);
        // The gate resolved meanwhile: not held, and nothing performed.
        ws.store.write("test", "alice", |tx| tx.resolve_gate(&gate, None, false, None)).unwrap();
        assert_eq!(ws.find_op(&close(&task), "a", None), OpFound::NotHeld);
        let head = ws.head();
        assert_eq!(ws.perform(&close(&task), "github:alice"), authorize::Performed::NotHeld);
        assert_eq!(ws.issue(&task).unwrap().status, Status::Open);
        assert_eq!(ws.head(), head, "nothing written");
    }

    #[test]
    fn a_force_closed_run_with_an_open_gate_is_still_discarded_and_its_deletes_are_capped() {
        let mut ws = Ws::new();
        let run = ws.run(pages::MAX_DELETES + 1, "[\"github:carol\"]");
        let all = ws.issues_of(&run);
        ws.store
            .write("test", "alice", |tx| tx.close_issue(&run, &CloseOptions { force: true, ..CloseOptions::default() }))
            .unwrap();
        assert!(ws.issue(&run).unwrap().status.is_terminal());
        let req = requested(Op::Discard, &run, "  cleanup\n");
        let info = ws.op_info(&req, "github:carol", None);
        let (listed, total) = info.deletes.clone().unwrap();
        assert_eq!((listed.len(), total), (pages::MAX_DELETES, all.len()));
        assert_eq!(listed[0].0, run);
        assert_eq!(
            info.gates.iter().map(|g| (g.id.clone(), g.may_open)).collect::<Vec<_>>(),
            [(ws.gate_of(&run), true)]
        );

        // Discarded as the approver: every issue of the run, each deleted event saying how and at whose request.
        assert_eq!(ws.perform(&req, "github:carol"), authorize::Performed::Discarded { count: all.len() });
        for issue in &all {
            assert!(ws.issue(&issue.id).is_none(), "{}", issue.id);
            let event = ws.events(&issue.id, "deleted").pop().unwrap();
            assert_eq!(event.actor, "github:carol");
            assert_eq!(event.data["reason"], "  cleanup\n", "byte for byte");
            assert_eq!(
                (event.data["via"].as_str(), event.data["requested_by"].as_str()),
                (Some("browser"), Some(AGENT))
            );
        }
        assert_eq!(ws.perform(&req, "github:carol"), authorize::Performed::Gone(authorize::OpFound::NoIssue));
    }

    #[test]
    fn an_approved_close_is_performed_exactly_as_the_approver() {
        let mut ws = Ws::new();
        let task = ws.task("Abandoned");
        ws.gate(&task, None);
        let mut req = requested(Op::Close, &task, "  why\n");
        req.failed = true;
        assert_eq!(ws.perform(&req, "github:alice"), authorize::Performed::Closed);
        let closed = ws.issue(&task).unwrap();
        assert_eq!(closed.status, Status::Closed);
        let event = ws.events(&task, "closed").pop().unwrap();
        assert_eq!(event.actor, "github:alice");
        assert_eq!(event.data["reason"], "  why\n", "byte for byte");
        assert_eq!(event.data["outcome"], "failed");
        assert_eq!((event.data["via"].as_str(), event.data["requested_by"].as_str()), (Some("browser"), Some(AGENT)));
        assert_eq!(ws.perform(&req, "github:alice"), authorize::Performed::Done);
    }

    #[test]
    fn an_approved_operation_never_takes_over_a_claim_nor_closes_a_gate() {
        use authorize::Performed;
        let mut ws = Ws::new();
        let task = ws.task("Claimed");
        let gate = ws.gate(&task, None);
        let opts = bd_core::ClaimOptions { allow_blocked: true, ..Default::default() };
        let claim = ws.store.write("claim", "bob", |tx| tx.claim(&task, &opts)).unwrap();
        let head = ws.head();
        // Bob's own request, approved by alice: his live claim is his to release first.
        let mut req = requested(Op::Close, &task, "why");
        req.requester = "bob".into();
        let Performed::Refused(why) = ws.perform(&req, "github:alice") else { panic!("not refused") };
        assert!(why.contains("bob"), "{why}");
        let held = ws.issue(&task).unwrap();
        assert_eq!((held.status, held.assignee.as_deref()), (Status::InProgress, Some("bob")));
        let leases = ws.store.read(|r| bd_core::claims::leases(r.conn(), bd_core::Timestamp::now())).unwrap();
        assert!(
            leases.iter().any(|l| l.lease.issue_id == task && l.lease.token == claim.lease.token),
            "the lease is intact"
        );
        assert_eq!(ws.head(), head, "nothing written");
        // A gate is never closed this way.
        assert!(matches!(ws.perform(&requested(Op::Close, &gate, "why"), "github:alice"), Performed::Changed(_)));
        assert!(!ws.issue(&gate).unwrap().status.is_terminal());
        assert_eq!(ws.head(), head, "nothing written");
        // A gate the approver may not open: refused by the transaction too.
        let other = ws.task("Carol's");
        ws.gate(&other, Some(&[CAROL]));
        assert!(matches!(ws.perform(&requested(Op::Close, &other, "why"), "github:alice"), Performed::Refused(_)));
        assert_eq!(ws.issue(&other).unwrap().status, Status::Open);
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
