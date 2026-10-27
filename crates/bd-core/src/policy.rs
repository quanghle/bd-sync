//! Who may end or take over a claim, and what else the caller of a write
//! transaction may override.
//!
//! **Claims** are protected from every caller, with or without a policy. A
//! live claim (an `in_progress` issue whose lease has not been expired for
//! `lease.grace`, see [`crate::claims`]) is its holder's alone: ending or
//! taking over one held by an actor other than the transaction's (releasing
//! it, closing it, reassigning it or moving it out of `in_progress`, deleting
//! it, also by discarding or compacting its run, importing over it, or
//! reclaiming it with a grace shorter than `lease.grace`) needs that
//! operation's `take_over` (`--take-over`), and the override is recorded in
//! its event (`claim_override`: the holder and the lease token). `force`
//! never does: it only gets past structural refusals (open children,
//! blockers, dependents, an unfinished run), and the claim is checked before
//! those, so the first refusal names the holder (exit 4; one listing every
//! holder when an operation would end several claims). Any other actor name
//! counts, the holder's root actor (`alice` for `alice/agent-1`) and its
//! siblings too: each sub-actor is its own lease holder. A claim past its
//! grace is anyone's to reclaim, claim, close or release; reserving or
//! reassigning work nobody has claimed is not limited. A playbook run or
//! group claimed by another actor stays open, still claimed, when its last
//! open step closes. Claiming a live claim again needs its lease's token,
//! even for the same actor ([`WriteCtx::claim`]).
//!
//! The CLI and the library run without a **policy**, so beyond that whoever
//! holds the database may do anything. `bd serve` sets one for each request
//! from its access token ([`WriteCtx::set_policy`]), and the engine enforces
//! it where the override happens, so a command gets the same answer however
//! it reaches the engine (on its own, in a `bd batch`, or through a
//! playbook):
//!
//! * **Claims**: taking over another actor's live claim also needs
//!   [`Policy::admin`], unless the policy's actor owns it (holds it itself,
//!   or a sub-actor `<actor>/<agent>` does). A caller that may not take it
//!   over is refused that way whether or not it passed `take_over` (except a
//!   release or reassignment without it, which fails as before: not the
//!   holder's).
//! * **Human gates** need [`Policy::human`] to be opened (closed or pinned),
//!   retyped, given another condition, or deleted while open, and for the
//!   work they hold back to get past them early: removing its `blocks` edge
//!   to the gate, closing it with `force`, pinning or deleting it (or a
//!   container holding it), or moving it, or the gate, out of a live parent.
//!   A playbook run or group whose last open step closes is refused too when
//!   a human gate holds it. An import may not do any of that either.
//! * **Approvers** narrow that further: a human gate whose
//!   `metadata.gate.approvers` names actors or OIDC identity references
//!   ([`crate::gates::approvers_of`]) is shut, on every path above, to a
//!   person it does not name ([`approved_by`]), admins included. A caller
//!   signed in with an OIDC provider ([`Policy::oidc_approver`]) matches
//!   only the reference of its own issuer and subject
//!   ([`crate::gates::oidc_approver`]), never an actor: the actor an OIDC
//!   account acts as is bound at its first sign-in from its login, which
//!   proves nothing about who it is. Any other caller matches an actor
//!   approver or a sub-actor of one ([`approves`], ignoring ASCII case),
//!   and never a reference, however its actor is spelled. A list stored
//!   invalid matches nobody. Changing an open human gate's
//!   approvers (by update, `bd gate update` or import) needs a person who may
//!   open it, or a human admin ([`may_edit_approvers`]), which is how an
//!   invalid list is repaired. Without a policy approvers are informational.
//! * **`metadata.playbook`**, which makes runs and groups close themselves,
//!   is written by playbook runs; other callers need [`Policy::admin`] to
//!   change it on an existing issue (by update or import).
//! * **Work held**: with [`Policy::max_claims`], the policy's actor and its
//!   sub-actors may hold at most that many issues, claimed or reserved
//!   (assigned to one of them, not closed or pinned), at the end of the
//!   transaction: a transaction that leaves them more than that, and more
//!   than they held before it, is refused, however it gave them the work
//!   (claiming, updating, creating, importing, in a batch or a playbook).
//!   A claim whose lease died counts until it is reclaimed.
//!
//! Gates are never claims: an issue cannot be a gate and `in_progress`.
//!
//! Which repositories GitHub gates may watch is a workspace setting rather
//! than a token's: see [`crate::gates::GateRepos`].

use std::collections::{BTreeMap, HashSet};

use rusqlite::params;
use serde_json::{Value, json};

use crate::claims;
use crate::error::{Error, Need, Result};
use crate::gates::{self, GateKind};
use crate::graph;
use crate::issues::{self, ISSUE_COLUMNS, issue_from_row};
use crate::model::{DepType, GATE_TYPE, Issue, Lease, Status};
use crate::store::WriteCtx;

/// What the caller of a write transaction may override.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The caller's own actor: claims held by it or its sub-actors
    /// (`<actor>/<agent>`) are the caller's to take over (with `take_over`).
    pub actor: String,
    /// May take over anyone's live claims (with `take_over`, like everyone).
    pub admin: bool,
    /// A person: may open human gates and move work past them.
    pub human: bool,
    /// The most issues the actor and its sub-actors may hold, claimed or
    /// reserved; `None` for no limit.
    pub max_claims: Option<u32>,
    /// The canonical identity reference ([`crate::gates::oidc_approver`]) of
    /// the verified OIDC account behind the caller, set only by `bd serve`
    /// from an authenticated token's account or a browser sign-in, never
    /// from what a request says. With one, the caller matches only gate
    /// approvers equal to it ([`approved_by`]). `None` by default.
    pub oidc_approver: Option<String>,
}

/// Issues `actor` and its sub-actors hold: assigned to one of them, and not
/// closed or pinned.
pub(crate) fn held_by(conn: &rusqlite::Connection, actor: &str) -> Result<u32> {
    // Sub-actors `<actor>/<name>` sort between `<actor>/` and `<actor>0` ('0' follows '/').
    let n: i64 = conn
        .prepare_cached(
            "SELECT (SELECT COUNT(*) FROM issues WHERE assignee = ?1 AND status NOT IN ('closed','pinned'))
                  + (SELECT COUNT(*) FROM issues
                     WHERE assignee > ?1 || '/' AND assignee < ?1 || '0' AND status NOT IN ('closed','pinned'))",
        )?
        .query_row([actor], |r| r.get(0))?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

impl Policy {
    /// Whether `holder` is the policy's actor or one of its sub-actors.
    pub fn owns(&self, holder: &str) -> bool {
        is_actor_or_sub_actor(&self.actor, holder)
    }
}

/// `actor` is `root`, or a sub-actor `<root>/<name>`.
pub fn is_actor_or_sub_actor(root: &str, actor: &str) -> bool {
    !root.is_empty()
        && (actor == root
            || actor.strip_prefix(root).and_then(|r| r.strip_prefix('/')).is_some_and(|r| !r.trim().is_empty()))
}

/// Whether `actor` is `approver` or one of its sub-actors
/// (`<approver>/<name>`), ignoring ASCII case. An OIDC identity reference
/// ([`gates::is_oidc_reference`], any spelling) is never matched by an actor.
pub fn approves(approver: &str, actor: &str) -> bool {
    if approver.is_empty() || gates::is_oidc_reference(approver) {
        return false;
    }
    if approver.eq_ignore_ascii_case(actor) {
        return true;
    }
    actor.get(..approver.len()).is_some_and(|head| head.eq_ignore_ascii_case(approver))
        && actor[approver.len()..].strip_prefix('/').is_some_and(|rest| !rest.trim().is_empty())
}

/// Whether a caller acting as `actor`, with the verified OIDC identity
/// reference `oidc_approver` when it signed in with an OIDC provider, is
/// one of `approvers`. With a reference, only an approver equal to it
/// counts (a malformed one matches nothing), never an actor; without one,
/// an actor approver or a sub-actor of one ([`approves`]). The one rule
/// every approval uses: the engine's ([`may_open`]), the browser's and
/// `bd gate review`'s.
pub fn approved_by(approvers: &[String], actor: &str, oidc_approver: Option<&str>) -> bool {
    match oidc_approver {
        Some(r) => gates::oidc_reference_ok(r) && approvers.iter().any(|a| a == r),
        None => approvers.iter().any(|a| approves(a, actor)),
    }
}

/// Whether `policy` may open human gate `gate`: a person, and one of its
/// approvers ([`approved_by`]) when it has any. A list stored invalid
/// reads as empty and matches nobody.
pub fn may_open(policy: &Policy, gate: &Issue) -> bool {
    policy.human
        && gates::approvers_of(gate).is_none_or(|l| approved_by(&l, &policy.actor, policy.oidc_approver.as_deref()))
}

/// Whether `policy` may change the approvers of open human gate `gate`: a
/// person who may open it, or a human admin (whatever the list stored).
pub fn may_edit_approvers(policy: &Policy, gate: &Issue) -> bool {
    policy.human && (policy.admin || may_open(policy, gate))
}

/// `metadata.gate.approvers` as stored, absent read as null.
fn raw_approvers(issue: &Issue) -> &Value {
    issue.metadata.pointer("/gate/approvers").unwrap_or(&Value::Null)
}

/// An open (not closed or pinned) gate whose condition is `human`. Only the
/// condition's type counts, so a human gate with an otherwise invalid
/// condition is still one.
pub fn is_open_human_gate(issue: &Issue) -> bool {
    issue.issue_type == GATE_TYPE
        && !issue.status.is_terminal()
        && issue
            .metadata
            .pointer("/gate/type")
            .and_then(Value::as_str)
            .is_some_and(|t| GateKind::parse(t).ok() == Some(GateKind::Human))
}

/// How an issue stands in the way of a human gate.
enum Hold {
    /// It is an open human gate.
    Is,
    /// It waits for this gate, through its own `blocks` edge or its parent's.
    HeldBy(String),
    /// Work below it waits for this gate (or the gate is below it).
    Contains(String),
}

/// Which open human gates are shut to the caller (see [`WriteCtx::shut`]).
type Shut<'a> = &'a dyn Fn(&Issue) -> bool;

/// Open gates (of any condition) `id` depends on through its own `blocks` edges, in id order.
fn open_gates_on(conn: &rusqlite::Connection, id: &str) -> Result<Vec<Issue>> {
    let sql = format!(
        "SELECT {ISSUE_COLUMNS} FROM dependencies d
         CROSS JOIN issues i INDEXED BY sqlite_autoindex_issues_1 ON i.id = d.depends_on_id
         WHERE d.issue_id = ?1 AND d.dep_type = 'blocks' AND i.issue_type = 'gate'
           AND i.status NOT IN ('closed','pinned')
         ORDER BY i.id"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let gates = stmt.query_map([id], issue_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(gates)
}

/// Shut open human gates `id` depends on through its own `blocks` edges.
fn human_gates_on(conn: &rusqlite::Connection, id: &str, shut: Shut<'_>) -> Result<Option<String>> {
    Ok(open_gates_on(conn, id)?.into_iter().find(|g| shut(g)).map(|g| g.id))
}

/// Every open human gate in the way of closing (with `force`) or deleting
/// the live issues among `ids`, whoever the caller: each that is one, the
/// gates on its own and its live ancestors' `blocks` edges (up to a terminal
/// ancestor), the gates below it in the hierarchy, and those on its live
/// descendants' `blocks` edges. Deduplicated, in id order.
///
/// It is the set the hold walks look through: for any policy `p`,
/// `human_hold` with `shut` = open human gate not [`may_open`] by `p` finds
/// a hold iff some gate returned here is not [`may_open`] by `p`. Read only
/// on a refusal's path, so a close that succeeds pays nothing for it.
pub fn gates_in_the_way(conn: &rusqlite::Connection, ids: &[String]) -> Result<Vec<Issue>> {
    fn add(found: &mut BTreeMap<String, Issue>, gates: Vec<Issue>) {
        for g in gates.into_iter().filter(is_open_human_gate) {
            found.entry(g.id.clone()).or_insert(g);
        }
    }
    let mut found: BTreeMap<String, Issue> = BTreeMap::new();
    for id in ids {
        let Some(issue) = issues::get(conn, id)? else { continue };
        if issue.status.is_terminal() {
            continue;
        }
        add(&mut found, vec![issue]);
        let mut seen = HashSet::new();
        let mut cur = id.clone();
        loop {
            add(&mut found, open_gates_on(conn, &cur)?);
            let Some(p) = graph::parent_of(conn, &cur)? else { break };
            if !seen.insert(p.clone()) || issues::get(conn, &p)?.is_none_or(|i| i.status.is_terminal()) {
                break;
            }
            cur = p;
        }
        for d in issues::descendants(conn, id)? {
            let live = !d.status.is_terminal();
            let d_id = d.id.clone();
            add(&mut found, vec![d]);
            if live {
                add(&mut found, open_gates_on(conn, &d_id)?);
            }
        }
    }
    Ok(found.into_values().collect())
}

/// The shut human gate holding `id` back: through `id`'s own `blocks` edges,
/// or an ancestor's (up to a closed one, below which nothing is blocked).
fn holding_gate(conn: &rusqlite::Connection, id: &str, shut: Shut<'_>) -> Result<Option<String>> {
    holding_gate_in(conn, id, &mut HashSet::new(), shut)
}

/// [`holding_gate`], skipping what an earlier walk found: `clear` holds
/// issues from which the walk up to the first terminal ancestor met no shut
/// human gate, and gets this walk's issues when it meets none either (the
/// policy, and so `shut`, is fixed for the transaction).
fn holding_gate_in(
    conn: &rusqlite::Connection,
    id: &str,
    clear: &mut HashSet<String>,
    shut: Shut<'_>,
) -> Result<Option<String>> {
    let mut walked = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = id.to_string();
    loop {
        if clear.contains(&cur) {
            break;
        }
        if let Some(g) = human_gates_on(conn, &cur, shut)? {
            return Ok(Some(g));
        }
        let parent = graph::parent_of(conn, &cur)?;
        walked.push(cur);
        let Some(p) = parent else { break };
        if !seen.insert(p.clone()) || issues::get(conn, &p)?.is_none_or(|i| i.status.is_terminal()) {
            break;
        }
        cur = p;
    }
    clear.extend(walked);
    Ok(None)
}

/// A shut human gate below `id` in the hierarchy, or one holding back live work below it.
fn gate_below(conn: &rusqlite::Connection, id: &str, shut: Shut<'_>) -> Result<Option<String>> {
    for d in issues::descendants(conn, id)? {
        if shut(&d) {
            return Ok(Some(d.id));
        }
        if !d.status.is_terminal()
            && let Some(g) = human_gates_on(conn, &d.id, shut)?
        {
            return Ok(Some(g));
        }
    }
    Ok(None)
}

fn human_hold(conn: &rusqlite::Connection, issue: &Issue, shut: Shut<'_>) -> Result<Option<Hold>> {
    if issue.status.is_terminal() {
        return Ok(None);
    }
    if shut(issue) {
        return Ok(Some(Hold::Is));
    }
    if let Some(g) = holding_gate(conn, &issue.id, shut)? {
        return Ok(Some(Hold::HeldBy(g)));
    }
    Ok(gate_below(conn, &issue.id, shut)?.map(Hold::Contains))
}

/// `metadata.playbook` makes runs and groups close themselves when their
/// last step does: playbook runs write it, and otherwise only admins may
/// (closing one still checks claims and human gates then).
fn check_playbook_metadata(policy: &Policy, old: &Issue, metadata: &Value) -> Result<()> {
    if policy.admin || old.metadata.get("playbook") == metadata.get("playbook") {
        return Ok(());
    }
    Err(Error::Unauthorized(format!(
        "{}: metadata.playbook belongs to playbook runs (it makes runs and groups close themselves); changing it \
         needs an admin access token",
        old.id
    )))
}

/// `what` completes "only a person can ...", e.g. "close it".
fn human_only(id: &str, hold: &Hold, what: &str) -> Error {
    let message = match hold {
        Hold::Is => format!("{id} is a human gate: only a person can {what} (with a human access token)"),
        Hold::HeldBy(g) => format!(
            "{id} waits for human gate {g}: only a person can {what} before {g} is resolved (with a human access token)"
        ),
        Hold::Contains(g) => format!(
            "{id} holds work that waits for human gate {g}: only a person can {what} before {g} is resolved \
             (with a human access token)"
        ),
    };
    let gate = match hold {
        Hold::Is => id,
        Hold::HeldBy(g) | Hold::Contains(g) => g,
    };
    Error::with_needs(&[Need::Human], message).with_gate(gate)
}

/// The refusal for a person who is not one of `approvers` (the gate's, as
/// [`gates::approvers_of`] reads them): the shapes of [`human_only`].
fn approvers_only(id: &str, hold: &Hold, what: &str, approvers: &[String], policy: &Policy) -> Error {
    const FIX: &str = "a human admin can replace or clear them with bd gate update";
    let Some((last, rest)) = approvers.split_last() else {
        return Error::Unauthorized(match hold {
            Hold::Is => format!("{id} is a human gate whose approvers are not valid, so nobody can {what}; {FIX}"),
            Hold::HeldBy(g) => format!(
                "{id} waits for human gate {g}, whose approvers are not valid, so nobody can {what} before {g} is \
                 resolved; {FIX}"
            ),
            Hold::Contains(g) => format!(
                "{id} holds work that waits for human gate {g}, whose approvers are not valid, so nobody can {what} \
                 before {g} is resolved; {FIX}"
            ),
        });
    };
    let who = if rest.is_empty() { last.clone() } else { format!("{} or {last}", rest.join(", ")) };
    let actor = &policy.actor;
    // The caller's own reference is never printed.
    let note = if policy.oidc_approver.is_some() {
        "; an account signed in with an OIDC provider matches only an oidc:sha256: identity reference for its own \
         issuer and subject"
    } else {
        ""
    };
    Error::Unauthorized(match hold {
        Hold::Is => format!("{id} is a human gate: only {who} can {what} ({actor} is not an approver{note})"),
        Hold::HeldBy(g) => format!(
            "{id} waits for human gate {g}: only {who} can {what} before {g} is resolved ({actor} is not an \
             approver{note})"
        ),
        Hold::Contains(g) => format!(
            "{id} holds work that waits for human gate {g}: only {who} can {what} before {g} is resolved \
             ({actor} is not an approver{note})"
        ),
    })
}

/// Why `policy` may not get past `gate` (as `hold` stands to it): a caller
/// that is not a person is told so ([`human_only`]); a person, who its
/// approvers are ([`approvers_only`]).
fn gate_refusal_for(policy: Option<&Policy>, id: &str, hold: &Hold, what: &str, gate: Option<&Issue>) -> Error {
    match policy.filter(|p| p.human).zip(gate.and_then(gates::approvers_of)) {
        Some((p, approvers)) => approvers_only(id, hold, what, &approvers, p),
        None => human_only(id, hold, what),
    }
}

/// The refusal for changing the approvers of open human gate `gate`.
fn approvers_edit(policy: &Policy, gate: &Issue) -> Error {
    let id = &gate.id;
    if !policy.human {
        return human_only(id, &Hold::Is, "change its approvers");
    }
    let which = match gates::approvers_of(gate) {
        Some(l) if l.is_empty() => " (its approvers are not valid)".to_string(),
        Some(l) => format!(" ({})", l.join(", ")),
        None => String::new(),
    };
    Error::Unauthorized(format!(
        "{id}: changing a human gate's approvers needs a human access token of one of its approvers{which}, or a \
         human admin's"
    ))
}

/// One open human gate and, when it is shut to the caller, the live work it holds back.
struct HumanHold {
    /// The gate as it was before the import.
    gate: Issue,
    /// Shut to the caller ([`WriteCtx::shut`]): the work below is only walked then.
    shut: bool,
    /// Work that depends on the gate through a `blocks` edge.
    direct: Vec<String>,
    /// Work below that in the hierarchy, each with the directly held issue above it.
    below: Vec<(String, String)>,
    /// The gate and the directly held work, each with a live container above it.
    around: Vec<(String, String)>,
}

/// What an import under a policy must leave be: every open human gate shut
/// to the caller, still holding back the same work, and the approvers of
/// every open human gate, unless the caller may change them.
pub(crate) struct HumanHolds(Vec<HumanHold>);

/// A live claim held by an actor other than the transaction's.
pub(crate) struct LiveClaim {
    pub holder: String,
    /// `None` only if the claim lost its lease row (`doctor` reports that).
    pub lease: Option<Lease>,
}

impl WriteCtx<'_> {
    /// Under [`Policy::max_claims`], refuse a transaction that leaves the
    /// policy's actor holding more work than that, and more than before it.
    pub(crate) fn check_work_held(&self) -> Result<()> {
        let Some((actor, max)) = self.policy().and_then(|p| Some((p.actor.as_str(), p.max_claims?))) else {
            return Ok(());
        };
        let held = held_by(self.conn(), actor)?;
        if held <= max || held <= self.held_before.unwrap_or(0) {
            return Ok(());
        }
        Err(Error::Unauthorized(format!(
            "{actor} and its agents would hold {held} issues (claimed or reserved), and its access token allows at \
             most {max}: close or release some first"
        )))
    }

    /// Limits on claim overrides, unless the caller is an admin (or unlimited).
    fn claim_limits(&self) -> Option<&Policy> {
        self.policy().filter(|p| !p.admin)
    }

    /// Whether human gates may be shut to this caller: any policy, as
    /// approvers bind people too.
    fn gates_limited(&self) -> bool {
        self.policy().is_some()
    }

    /// Whether `gate` is an open human gate this caller may not open
    /// ([`may_open`]); never without a policy.
    fn shut(&self, gate: &Issue) -> bool {
        is_open_human_gate(gate) && self.policy().is_some_and(|p| !may_open(p, gate))
    }

    /// The refusal for getting past the gate `hold` names (`id` itself for
    /// [`Hold::Is`]), worded for this caller.
    fn gate_refusal(&self, id: &str, hold: &Hold, what: &str) -> Result<Error> {
        let gate = match hold {
            Hold::Is => id,
            Hold::HeldBy(g) | Hold::Contains(g) => g,
        };
        let gate = issues::get(self.conn(), gate)?;
        Ok(gate_refusal_for(self.policy(), id, hold, what, gate.as_ref()))
    }

    /// `issue`'s claim, if it is live and held by an actor other than this
    /// transaction's (see the module docs).
    pub(crate) fn others_live_claim(&self, issue: &Issue) -> Result<Option<LiveClaim>> {
        let Some(holder) = issue.assignee.as_deref().filter(|_| issue.status == Status::InProgress) else {
            return Ok(None);
        };
        if holder == self.actor() {
            return Ok(None);
        }
        let lease = claims::get_lease(self.conn(), &issue.id)?;
        if let Some(l) = &lease
            && claims::is_reclaimable(self.conn(), l, self.now())?
        {
            return Ok(None);
        }
        Ok(Some(LiveClaim { holder: holder.to_string(), lease }))
    }

    /// Ending or taking over `issue`'s claim. Another actor's live claim
    /// needs `take_over` (and the policy's leave); returns the override to
    /// record in the write's event, if it is one. Callers check this before
    /// any refusal that `force` gets past, so that the first answer about
    /// someone else's work names its holder.
    pub(crate) fn check_claim_override(&self, issue: &Issue, take_over: bool) -> Result<Option<Value>> {
        let Some(LiveClaim { holder, lease }) = self.others_live_claim(issue)? else { return Ok(None) };
        if self.claim_limits().is_some_and(|p| !p.owns(&holder)) {
            let message = format!(
                "{} is claimed by {holder}: ending or taking over another actor's claim needs an admin access token",
                issue.id
            );
            return Err(Error::with_needs(&[Need::Admin], message));
        }
        if !take_over {
            return Err(Error::NotOwner { id: issue.id.clone(), holder: Some(holder), actor: self.actor().into() });
        }
        Ok(Some(json!({ "holder": holder, "token": lease.map(|l| l.token) })))
    }

    /// [`Self::check_claim_override`] for every issue `what` (an operation,
    /// e.g. "discarding t-1") would end at once: without `take_over`, one
    /// refusal lists every live claim of another actor among them. Returns
    /// the overrides by issue id.
    pub(crate) fn check_claim_overrides(
        &self,
        issues: impl IntoIterator<Item = Issue>,
        take_over: bool,
        what: &str,
    ) -> Result<BTreeMap<String, Value>> {
        let mut overrides = BTreeMap::new();
        let mut held = Vec::new();
        for issue in issues {
            match self.check_claim_override(&issue, take_over) {
                Ok(Some(o)) => {
                    overrides.insert(issue.id, o);
                }
                Ok(None) => {}
                Err(Error::NotOwner { id, holder, .. }) => held.push((id, holder.unwrap_or_default())),
                Err(e) => return Err(e),
            }
        }
        self.not_holders(held, what)?;
        Ok(overrides)
    }

    /// The refusal for ending the live claims `held` (issue, holder) of other
    /// actors without `take_over`: one names its holder, several are listed.
    fn not_holders(&self, mut held: Vec<(String, String)>, what: &str) -> Result<()> {
        match held.len() {
            0 => Ok(()),
            1 => {
                let (id, holder) = held.remove(0);
                Err(Error::NotOwner { id, holder: Some(holder), actor: self.actor().into() })
            }
            _ => Err(Error::ClaimsHeld { what: what.to_string(), held }),
        }
    }

    /// Refuse, up front, ending the claims of `ids` when other actors hold
    /// live claims on any of them and `take_over` is not set, listing them
    /// all (e.g. `bd close A B`, before the first close is refused alone).
    pub fn check_take_over(&self, ids: &[String], take_over: bool, what: &str) -> Result<()> {
        self.check_claim_overrides(self.held_by_others(ids)?, take_over, what).map(|_| ())
    }

    /// [`Self::check_take_over`] for releases, answering as a single
    /// [`WriteCtx::release`] does: without `take_over`, someone else's claim
    /// is refused as not the caller's (exit 4) before any policy answer.
    pub fn check_release_take_over(&self, ids: &[String], take_over: bool, what: &str) -> Result<()> {
        if take_over {
            return self.check_take_over(ids, true, what);
        }
        let mut held = Vec::new();
        for issue in self.held_by_others(ids)? {
            if let Some(LiveClaim { holder, .. }) = self.others_live_claim(&issue)? {
                held.push((issue.id, holder));
            }
        }
        self.not_holders(held, what)
    }

    /// Of `ids`, the `in_progress` issues assigned to an actor other than
    /// this transaction's: the only ones whose claims may need a takeover.
    fn held_by_others<'a>(&self, ids: impl IntoIterator<Item = &'a String>) -> Result<Vec<Issue>> {
        let mut out = Vec::new();
        for id in ids {
            let held: bool = self
                .conn()
                .prepare_cached(
                    "SELECT EXISTS (SELECT 1 FROM issues WHERE id = ?1 AND status = 'in_progress' AND assignee IS NOT ?2)",
                )?
                .query_row(params![id, self.actor()], |r| r.get(0))?;
            if held {
                out.extend(issues::get(self.conn(), id)?);
            }
        }
        Ok(out)
    }

    /// Closing `issue` past human gates (with `force`: despite blockers or
    /// open children). Claims are checked first, by the caller.
    pub(crate) fn check_close(&self, issue: &Issue, force: bool) -> Result<()> {
        if !self.gates_limited() {
            return Ok(());
        }
        if self.shut(issue) {
            return Err(self.gate_refusal(&issue.id, &Hold::Is, "open it")?);
        }
        // Without force, a close that gets here is not held back by anything.
        if force && let Some(hold) = human_hold(self.conn(), issue, &|g| self.shut(g))? {
            let refusal = self.gate_refusal(&issue.id, &hold, "close it")?;
            if self.approvable(std::slice::from_ref(&issue.id), issue.issue_type == GATE_TYPE)? {
                return Err(refusal.approvable());
            }
            return Err(refusal);
        }
        Ok(())
    }

    /// Whether a refusal to close (`target_gate`: the target is a gate) or
    /// delete `ids` past human gates is one a person could approve in a
    /// browser: the target is not a gate, and every open human gate in the
    /// way ([`gates_in_the_way`]) names a valid approver list (or none), so
    /// some person may open each. Called only once the hold is found.
    fn approvable(&self, ids: &[String], target_gate: bool) -> Result<bool> {
        if target_gate {
            return Ok(false);
        }
        let gates = gates_in_the_way(self.conn(), ids)?;
        Ok(!gates.is_empty() && gates.iter().all(|g| gates::approvers_of(g).is_none_or(|l| !l.is_empty())))
    }

    /// Updating `old` to `new`, moving it out from under `moved_from` (its
    /// parent until now) if set. `playbook`: a run's own bookkeeping.
    /// Returns the claim override, if any.
    pub(crate) fn check_update(
        &self,
        old: &Issue,
        new: &Issue,
        moved_from: Option<&str>,
        playbook: bool,
        take_over: bool,
    ) -> Result<Option<Value>> {
        let claimed = old.status == Status::InProgress;
        let mut claim_override = None;
        if claimed && (new.status != Status::InProgress || new.assignee != old.assignee) {
            claim_override = self.check_claim_override(old, take_over)?;
        }
        if self.gates_limited() && !old.status.is_terminal() {
            // Approvers do not make a gate any less human, so editing them never trips this.
            if self.shut(old) && !is_open_human_gate(new) {
                let what = if new.status.is_terminal() { "open it" } else { "change its type or condition" };
                return Err(self.gate_refusal(&old.id, &Hold::Is, what)?);
            }
            if new.status.is_terminal()
                && let Some(hold) = human_hold(self.conn(), old, &|g| self.shut(g))?
            {
                return Err(self.gate_refusal(&old.id, &hold, "pin it")?);
            }
            if let Some(parent) = moved_from {
                self.check_move_out(old, parent)?;
            }
        }
        // Compared as stored, so an edit from one invalid list to another counts too.
        if let Some(policy) = self.policy()
            && is_open_human_gate(old)
            && raw_approvers(old) != raw_approvers(new)
            && !may_edit_approvers(policy, old)
        {
            return Err(approvers_edit(policy, old));
        }
        if let Some(policy) = self.policy().filter(|_| !playbook) {
            check_playbook_metadata(policy, old, &new.metadata)?;
        }
        Ok(claim_override)
    }

    /// Moving live `issue` out from under `parent`: if it is a human gate,
    /// waits for one, or holds work that does, the parent could then close
    /// (or be closed, pinned or deleted) with that gate still shut.
    fn check_move_out(&self, issue: &Issue, parent: &str) -> Result<()> {
        if issues::require(self.conn(), parent)?.status.is_terminal() {
            return Ok(());
        }
        match human_hold(self.conn(), issue, &|g| self.shut(g))? {
            Some(hold) => Err(self.gate_refusal(&issue.id, &hold, &format!("move it out of {parent}"))?),
            None => Ok(()),
        }
    }

    /// Before closing container `c` because its last open step closed: a
    /// claim of another actor stays (the container stays open, as if it had
    /// work left), and a container a human gate holds is refused as if
    /// closed by hand. Returns whether it may close.
    ///
    /// `c` is live and nothing below it is, so no gate below it can hold it
    /// ([`human_hold`] would find none there): only one on its own `blocks`
    /// edges or its live ancestors' can. `clear` carries the issues found
    /// free of those up a cascade of closing containers, so each is looked
    /// at once however deep the cascade.
    pub(crate) fn check_auto_close(&self, c: &Issue, clear: &mut HashSet<String>) -> Result<bool> {
        if self.others_live_claim(c)?.is_some() {
            return Ok(false);
        }
        if self.gates_limited() {
            debug_assert!(!c.status.is_terminal() && !is_open_human_gate(c));
            if let Some(g) = holding_gate_in(self.conn(), &c.id, clear, &|g| self.shut(g))? {
                let hold = Hold::HeldBy(g);
                return Err(self.gate_refusal(&c.id, &hold, "close it (its last open step just closed)")?);
            }
        }
        Ok(true)
    }

    /// Removing the edge `issue -> target`.
    pub(crate) fn check_edge_removal(&self, issue: &str, target: &str, dep_type: &DepType) -> Result<()> {
        if !self.gates_limited() || !matches!(dep_type, DepType::Blocks | DepType::ParentChild) {
            return Ok(());
        }
        if issues::require(self.conn(), issue)?.status.is_terminal() {
            return Ok(());
        }
        if *dep_type == DepType::Blocks {
            if self.shut(&issues::require(self.conn(), target)?) {
                return Err(self.gate_refusal(issue, &Hold::HeldBy(target.to_string()), "remove that edge")?);
            }
            return Ok(());
        }
        self.check_move_out(&issues::require(self.conn(), issue)?, target)
    }

    /// Ending the claims of every issue in `ids`, deleted at once (with
    /// `take_over`: despite other actors' live claims). Returns the claim
    /// overrides by issue id.
    pub(crate) fn check_removal_claims<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a String>,
        take_over: bool,
        what: &str,
    ) -> Result<BTreeMap<String, Value>> {
        self.check_claim_overrides(self.held_by_others(ids)?, take_over, what)
    }

    /// Deleting every issue in `ids` at once past human gates.
    pub(crate) fn check_removal_gates<'a>(&self, ids: impl IntoIterator<Item = &'a String>) -> Result<()> {
        if !self.gates_limited() {
            return Ok(());
        }
        let ids: Vec<String> = ids.into_iter().cloned().collect();
        for id in &ids {
            let Some(issue) = issues::get(self.conn(), id)? else { continue };
            if let Some(hold) = human_hold(self.conn(), &issue, &|g| self.shut(g))? {
                let refusal = self.gate_refusal(id, &hold, "delete it")?;
                if self.approvable(&ids, false)? {
                    return Err(refusal.approvable());
                }
                return Err(refusal);
            }
        }
        Ok(())
    }

    /// Refuse an import changing `old`'s `metadata.playbook` (see [`check_playbook_metadata`]).
    pub(crate) fn check_playbook_import(&self, old: &Issue, metadata: &Value) -> Result<()> {
        match self.policy() {
            Some(policy) => check_playbook_metadata(policy, old, metadata),
            None => Ok(()),
        }
    }

    /// Snapshot of every open human gate, with the work held back by those
    /// shut to the caller, for an import to leave be (`None` without a
    /// policy).
    pub(crate) fn human_holds(&self) -> Result<Option<HumanHolds>> {
        if !self.gates_limited() {
            return Ok(None);
        }
        let sql = format!(
            "SELECT {ISSUE_COLUMNS} FROM issues i
             WHERE i.issue_type = 'gate' AND i.status NOT IN ('closed','pinned') ORDER BY i.id"
        );
        let gates: Vec<Issue> = {
            let mut stmt = self.conn().prepare_cached(&sql)?;
            stmt.query_map([], issue_from_row)?.collect::<rusqlite::Result<_>>()?
        };
        let mut holds = Vec::new();
        for g in gates.into_iter().filter(is_open_human_gate) {
            if !self.shut(&g) {
                holds.push(HumanHold { gate: g, shut: false, direct: vec![], below: vec![], around: vec![] });
                continue;
            }
            let direct: Vec<String> = {
                let mut stmt = self.conn().prepare_cached(
                    "SELECT d.issue_id FROM dependencies d
                     CROSS JOIN issues w INDEXED BY sqlite_autoindex_issues_1 ON w.id = d.issue_id
                     WHERE d.depends_on_id = ?1 AND d.dep_type = 'blocks' AND w.status NOT IN ('closed','pinned')
                     ORDER BY d.issue_id",
                )?;
                stmt.query_map([&g.id], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
            };
            let mut below = Vec::new();
            for w in &direct {
                for d in issues::descendants(self.conn(), w)?.into_iter().filter(|d| !d.status.is_terminal()) {
                    below.push((d.id, w.clone()));
                }
            }
            let mut around = Vec::new();
            for x in std::iter::once(&g.id).chain(&direct) {
                for a in graph::ancestors(self.conn(), x)? {
                    if issues::get(self.conn(), &a)?.is_some_and(|i| !i.status.is_terminal()) {
                        around.push((x.clone(), a));
                    }
                }
            }
            holds.push(HumanHold { gate: g, shut: true, direct, below, around });
        }
        Ok(Some(HumanHolds(holds)))
    }

    /// Refuse when a human gate from `before` shut to the caller was opened,
    /// changed or deleted, or work it held back got past it; or when the
    /// approvers of any of them changed and the caller may not change them.
    pub(crate) fn check_human_holds(&self, before: &HumanHolds) -> Result<()> {
        let Some(policy) = self.policy() else { return Ok(()) };
        for HumanHold { gate: old, shut, direct, below, around } in &before.0 {
            let gate = &old.id;
            // Worded from the gate as it was: the import may have changed or deleted it.
            let refuse = |id: &str, hold: &Hold, what: &str| gate_refusal_for(Some(policy), id, hold, what, Some(old));
            let now = issues::get(self.conn(), gate)?;
            if *shut {
                if !now.as_ref().is_some_and(is_open_human_gate) {
                    return Err(refuse(gate, &Hold::Is, "open, change or delete it"));
                }
                for w in direct {
                    let still_held =
                        graph::load_edge(self.conn(), w, gate)?.is_some_and(|e| e.dep_type == DepType::Blocks);
                    let live = issues::get(self.conn(), w)?.is_some_and(|i| !i.status.is_terminal());
                    if !still_held || !live {
                        return Err(refuse(w, &Hold::HeldBy(gate.clone()), "close it or remove that edge"));
                    }
                }
                for (w, held) in below {
                    let live = issues::get(self.conn(), w)?.is_some_and(|i| !i.status.is_terminal());
                    // Retyping a parent-child edge on the way up would move it out from under `held`.
                    if !live || !graph::ancestors(self.conn(), w)?.contains(held) {
                        return Err(refuse(w, &Hold::HeldBy(gate.clone()), "close it or move it out of its parent"));
                    }
                }
                // The containers around them may not close, or lose them, either.
                for (x, container) in around {
                    let live = issues::get(self.conn(), container)?.is_some_and(|i| !i.status.is_terminal());
                    if !live || !graph::ancestors(self.conn(), x)?.contains(container) {
                        let hold = Hold::Contains(gate.clone());
                        return Err(refuse(container, &hold, &format!("close it or move {x} out of it")));
                    }
                }
            }
            if let Some(now) = &now
                && raw_approvers(now) != raw_approvers(old)
                && !may_edit_approvers(policy, old)
            {
                return Err(approvers_edit(policy, old));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_are_the_actor_or_its_sub_actors() {
        let p = Policy { actor: "alice".into(), ..Default::default() };
        for ok in ["alice", "alice/agent-1", "alice/ci/run-7"] {
            assert!(p.owns(ok), "{ok}");
        }
        for bad in ["bob", "alice2", "alicex/agent", "alice/", "alice/ ", "", "ALICE"] {
            assert!(!p.owns(bad), "{bad}");
        }
        assert!(!Policy::default().owns("/x"), "an empty actor owns nothing");
    }

    #[test]
    fn approvers_match_themselves_and_their_sub_actors_ignoring_case() {
        for (approver, actor) in [("carol", "carol"), ("carol", "CAROL"), ("Carol", "carol/laptop"), ("a/b", "A/B/c")] {
            assert!(approves(approver, actor), "{approver} {actor}");
        }
        for (approver, actor) in [
            ("carol", "carolx"),
            ("carol", "carol/"),
            ("carol", "carol/ "),
            ("carol", "dave"),
            ("", ""),
            ("carol/x", "carol"),
        ] {
            assert!(!approves(approver, actor), "{approver} {actor}");
        }
        assert!(!approves("a", "\u{e9}/x"), "no panic off a char boundary");
    }

    #[test]
    fn actors_never_match_identity_references() {
        let r = gates::oidc_approver("https://login.example.com", "248289761001");
        let upper = r.to_ascii_uppercase();
        let mixed = format!("OIDC:SHA256:{}", &r[gates::OIDC_APPROVER_PREFIX.len()..]);
        for approver in [r.as_str(), upper.as_str(), mixed.as_str(), "oidc:sha256:", "Oidc:Sha256:x"] {
            for actor in [approver.to_string(), approver.to_ascii_lowercase(), format!("{approver}/x")] {
                assert!(!approves(approver, &actor), "{approver} {actor}");
            }
        }
        assert!(approves("oidc:sha25", "oidc:sha25"), "only the whole prefix is reserved");
    }

    #[test]
    fn verified_references_and_actors_each_match_only_their_own_approvers() {
        let iss = "https://login.example.com";
        let r = gates::oidc_approver(iss, "248289761001");
        let list = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let legacy = list(&["corp:alice"]);
        assert!(!approved_by(&legacy, "corp:alice", Some(&r)), "an OIDC caller never matches an actor");
        assert!(!approved_by(&legacy, "corp:alice/laptop", Some(&r)));
        assert!(approved_by(&legacy, "corp:alice", None));
        assert!(approved_by(&legacy, "corp:alice/laptop", None));
        let refs = list(&[&r]);
        assert!(!approved_by(&refs, &r, None), "an actor spelled as the reference");
        assert!(!approved_by(&refs, &format!("{r}/x"), None));
        assert!(!approved_by(&refs, &r.to_ascii_uppercase(), None));
        for actor in ["corp:alice", "anyone", ""] {
            assert!(approved_by(&refs, actor, Some(&r)), "the right reference under {actor:?}");
        }
        for other in [
            gates::oidc_approver("https://login.example.org", "248289761001"),
            gates::oidc_approver(&format!("{iss}/"), "248289761001"),
            gates::oidc_approver(iss, "248289761002"),
            gates::oidc_approver(iss, "Alice"),
        ] {
            assert!(!approved_by(&refs, "corp:alice", Some(&other)), "{other}");
        }
        let case = list(&[&gates::oidc_approver(iss, "alice")]);
        assert!(!approved_by(&case, "corp:alice", Some(&gates::oidc_approver(iss, "Alice"))), "subjects keep case");
        let mixed = list(&["carol", &r]);
        assert!(approved_by(&mixed, "carol", None));
        assert!(approved_by(&mixed, "carol/laptop", None));
        assert!(!approved_by(&mixed, "carol", Some(&gates::oidc_approver(iss, "carol"))));
        assert!(approved_by(&mixed, "dave", Some(&r)));
        assert!(!approved_by(&mixed, "dave", None));
        for bad in
            [r.to_ascii_uppercase(), r[..r.len() - 1].to_string(), format!("{r}0"), String::new(), "carol".into()]
        {
            let stored = list(&[&bad, "carol"]);
            assert!(!approved_by(&stored, "carol", Some(&bad)), "a malformed reference matches nothing: {bad:?}");
        }
        assert!(!approved_by(&[], "carol", Some(&r)));
        assert!(!approved_by(&[], "carol", None));
    }

    #[test]
    fn only_people_open_gates_and_by_the_shared_rule() {
        let r = gates::oidc_approver("https://login.example.com", "248289761001");
        let gate = |approvers: &[&str]| -> Issue {
            serde_json::from_value(serde_json::json!({
                "id": "t-1", "title": "Approve", "status": "open", "priority": 2, "issue_type": "gate",
                "metadata": { "gate": { "type": "human", "approvers": approvers } }, "created_at": 0, "updated_at": 0,
            }))
            .unwrap()
        };
        let person = |actor: &str, oidc: Option<&str>| Policy {
            actor: actor.into(),
            human: true,
            oidc_approver: oidc.map(String::from),
            ..Default::default()
        };
        assert!(may_open(&person("corp:alice", Some(&r)), &gate(&[&r])));
        assert!(!may_open(&person("corp:alice", Some(&r)), &gate(&["corp:alice"])));
        assert!(may_open(&person("corp:alice", None), &gate(&["corp:alice"])));
        assert!(!may_open(&person(&r, None), &gate(&[&r])));
        let agent = Policy { human: false, ..person("corp:alice", Some(&r)) };
        assert!(!may_open(&agent, &gate(&[&r])), "a policy that is not a person's");
        let admin = Policy { admin: true, ..person("ops", Some(&gates::oidc_approver("https://x.example", "1"))) };
        assert!(!may_open(&admin, &gate(&[&r])), "admins are not implicit approvers");
        assert!(may_edit_approvers(&admin, &gate(&[&r])), "but may replace the list");
    }

    #[test]
    fn human_gates_are_recognized_by_their_condition_type() {
        let mut i: Issue = serde_json::from_value(serde_json::json!({
            "id": "t-1", "title": "Approve", "status": "open", "priority": 2, "issue_type": "gate",
            "metadata": { "gate": { "type": " Human " } }, "created_at": 0, "updated_at": 0,
        }))
        .unwrap();
        assert!(is_open_human_gate(&i));
        i.status = Status::Pinned;
        assert!(!is_open_human_gate(&i), "pinned gates are open for good");
        i.status = Status::InProgress;
        i.metadata = serde_json::json!({ "gate": { "type": "timer", "timeout": "1h" } });
        assert!(!is_open_human_gate(&i));
        i.metadata = serde_json::json!({ "gate": { "type": "human", "repo": "not/valid/for/human" } });
        assert!(is_open_human_gate(&i), "an invalid condition does not make it any less human");
        i.issue_type = "task".into();
        assert!(!is_open_human_gate(&i));
    }
}
