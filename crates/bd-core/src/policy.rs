//! Limits on what the caller of a write transaction may override.
//!
//! The CLI and the library run without a policy: whoever holds the database
//! may do anything. `bd serve` sets one for each request from its access
//! token ([`WriteCtx::set_policy`]), and the engine enforces it where the
//! override happens, so a command gets the same answer however it reaches
//! the engine (on its own, in a `bd batch`, or through a playbook):
//!
//! * **Claims** need [`Policy::admin`] to end or take over a live claim (an
//!   `in_progress` issue) held by an actor other than the policy's actor and
//!   its sub-actors (`<actor>/<agent>`): releasing it, closing it,
//!   reassigning it or moving it out of `in_progress`, and deleting it.
//!   Expired leases stay reclaimable by anyone (`reclaim`), and reserving
//!   or reassigning work nobody has claimed is not limited.
//! * **Human gates** need [`Policy::human`] to be opened (closed or pinned),
//!   retyped, given another condition, or deleted while open, and for the
//!   work they hold back to get past them early: removing its `blocks` edge
//!   to the gate, closing it with `force`, pinning or deleting it (or a
//!   container holding it), or moving it, or the gate, out of a live parent.
//!   A playbook run or group whose last open step closes is refused too when
//!   a human gate holds it; one claimed by another actor just stays open. An
//!   import may not do any of that either.
//! * **`metadata.playbook`**, which makes runs and groups close themselves,
//!   is written by playbook runs; other callers need [`Policy::admin`] to
//!   change it on an existing issue (by update or import).
//!
//! Gates are never claims: an issue cannot be a gate and `in_progress`.
//!
//! Which repositories GitHub gates may watch is a workspace setting rather
//! than a token's: see [`crate::gates::GateRepos`].

use serde_json::Value;

use crate::error::{Error, Result};
use crate::gates::GateKind;
use crate::graph;
use crate::issues::{self, ISSUE_COLUMNS, issue_from_row};
use crate::model::{DepType, GATE_TYPE, Issue, Status};
use crate::store::WriteCtx;

/// What the caller of a write transaction may override.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The caller's own actor: claims held by it or its sub-actors
    /// (`<actor>/<agent>`) are the caller's own.
    pub actor: String,
    /// May end or take over anyone's claims.
    pub admin: bool,
    /// A person: may open human gates and move work past them.
    pub human: bool,
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

/// Open human gates `id` depends on through its own `blocks` edges.
fn human_gates_on(conn: &rusqlite::Connection, id: &str) -> Result<Option<String>> {
    let sql = format!(
        "SELECT {ISSUE_COLUMNS} FROM dependencies d JOIN issues i ON i.id = d.depends_on_id
         WHERE d.issue_id = ?1 AND d.dep_type = 'blocks' AND i.issue_type = 'gate'
           AND i.status NOT IN ('closed','pinned')
         ORDER BY i.id"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let gates = stmt.query_map([id], issue_from_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(gates.into_iter().find(is_open_human_gate).map(|g| g.id))
}

/// The open human gate holding `id` back: through `id`'s own `blocks` edges,
/// or an ancestor's (up to a closed one, below which nothing is blocked).
fn holding_gate(conn: &rusqlite::Connection, id: &str) -> Result<Option<String>> {
    if let Some(g) = human_gates_on(conn, id)? {
        return Ok(Some(g));
    }
    for a in graph::ancestors(conn, id)? {
        if issues::get(conn, &a)?.is_none_or(|i| i.status.is_terminal()) {
            break;
        }
        if let Some(g) = human_gates_on(conn, &a)? {
            return Ok(Some(g));
        }
    }
    Ok(None)
}

/// An open human gate below `id` in the hierarchy, or one holding back live work below it.
fn gate_below(conn: &rusqlite::Connection, id: &str) -> Result<Option<String>> {
    for d in issues::descendants(conn, id)? {
        if is_open_human_gate(&d) {
            return Ok(Some(d.id));
        }
        if !d.status.is_terminal() {
            if let Some(g) = human_gates_on(conn, &d.id)? {
                return Ok(Some(g));
            }
        }
    }
    Ok(None)
}

fn human_hold(conn: &rusqlite::Connection, issue: &Issue) -> Result<Option<Hold>> {
    if issue.status.is_terminal() {
        return Ok(None);
    }
    if is_open_human_gate(issue) {
        return Ok(Some(Hold::Is));
    }
    if let Some(g) = holding_gate(conn, &issue.id)? {
        return Ok(Some(Hold::HeldBy(g)));
    }
    Ok(gate_below(conn, &issue.id)?.map(Hold::Contains))
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
    Error::Unauthorized(match hold {
        Hold::Is => format!("{id} is a human gate: only a person can {what} (with a human access token)"),
        Hold::HeldBy(g) => format!(
            "{id} waits for human gate {g}: only a person can {what} before {g} is resolved (with a human access token)"
        ),
        Hold::Contains(g) => format!(
            "{id} holds work that waits for human gate {g}: only a person can {what} before {g} is resolved \
             (with a human access token)"
        ),
    })
}

/// One open human gate and the live work it holds back.
struct HumanHold {
    gate: String,
    /// Work that depends on the gate through a `blocks` edge.
    direct: Vec<String>,
    /// Work below that in the hierarchy, each with the directly held issue above it.
    below: Vec<(String, String)>,
    /// The gate and the directly held work, each with a live container above it.
    around: Vec<(String, String)>,
}

/// What a restricted import must leave be: every open human gate, still
/// holding back the same work.
pub(crate) struct HumanHolds(Vec<HumanHold>);

impl WriteCtx<'_> {
    /// Limits on claim overrides, unless the caller is an admin (or unlimited).
    fn claim_limits(&self) -> Option<&Policy> {
        self.policy().filter(|p| !p.admin)
    }

    /// Whether human gates are protected from this caller.
    fn gates_limited(&self) -> bool {
        self.policy().is_some_and(|p| !p.human)
    }

    /// Refuse ending or taking over `issue`'s live claim when another actor holds it.
    pub(crate) fn check_claim_override(&self, issue: &Issue) -> Result<()> {
        let Some(policy) = self.claim_limits() else { return Ok(()) };
        match &issue.assignee {
            Some(holder) if issue.status == Status::InProgress && holder != self.actor() && !policy.owns(holder) => {
                Err(Error::Unauthorized(format!(
                    "{} is claimed by {holder}: ending or taking over another actor's claim needs an admin access token",
                    issue.id
                )))
            }
            _ => Ok(()),
        }
    }

    /// Closing `issue` (with `force`: despite blockers or open children).
    pub(crate) fn check_close(&self, issue: &Issue, force: bool) -> Result<()> {
        self.check_claim_override(issue)?;
        if !self.gates_limited() {
            return Ok(());
        }
        if is_open_human_gate(issue) {
            return Err(human_only(&issue.id, &Hold::Is, "open it"));
        }
        // Without force, a close that gets here is not held back by anything.
        if force {
            if let Some(hold) = human_hold(self.conn(), issue)? {
                return Err(human_only(&issue.id, &hold, "close it"));
            }
        }
        Ok(())
    }

    /// Updating `old` to `new`, moving it out from under `moved_from` (its
    /// parent until now) if set. `playbook`: a run's own bookkeeping.
    pub(crate) fn check_update(
        &self,
        old: &Issue,
        new: &Issue,
        moved_from: Option<&str>,
        playbook: bool,
    ) -> Result<()> {
        let claimed = old.status == Status::InProgress;
        if claimed && (new.status != Status::InProgress || new.assignee != old.assignee) {
            self.check_claim_override(old)?;
        }
        if self.gates_limited() && !old.status.is_terminal() {
            if is_open_human_gate(old) && !is_open_human_gate(new) {
                let what = if new.status.is_terminal() { "open it" } else { "change its type or condition" };
                return Err(human_only(&old.id, &Hold::Is, what));
            }
            if new.status.is_terminal() {
                if let Some(hold) = human_hold(self.conn(), old)? {
                    return Err(human_only(&old.id, &hold, "pin it"));
                }
            }
            if let Some(parent) = moved_from {
                self.check_move_out(old, parent)?;
            }
        }
        if let Some(policy) = self.policy().filter(|_| !playbook) {
            check_playbook_metadata(policy, old, &new.metadata)?;
        }
        Ok(())
    }

    /// Moving live `issue` out from under `parent`: if it is a human gate,
    /// waits for one, or holds work that does, the parent could then close
    /// (or be closed, pinned or deleted) with that gate still shut.
    fn check_move_out(&self, issue: &Issue, parent: &str) -> Result<()> {
        if issues::require(self.conn(), parent)?.status.is_terminal() {
            return Ok(());
        }
        match human_hold(self.conn(), issue)? {
            Some(hold) => Err(human_only(&issue.id, &hold, &format!("move it out of {parent}"))),
            None => Ok(()),
        }
    }

    /// Before closing container `c` because its last open step closed: a
    /// claim of another actor stays (the container stays open, as if it had
    /// work left), and a container a human gate holds is refused as if
    /// closed by hand. Returns whether it may close.
    pub(crate) fn check_auto_close(&self, c: &Issue) -> Result<bool> {
        if self.check_claim_override(c).is_err() {
            return Ok(false);
        }
        if self.gates_limited() {
            if let Some(hold) = human_hold(self.conn(), c)? {
                return Err(human_only(&c.id, &hold, "close it (its last open step just closed)"));
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
            if is_open_human_gate(&issues::require(self.conn(), target)?) {
                return Err(human_only(issue, &Hold::HeldBy(target.to_string()), "remove that edge"));
            }
            return Ok(());
        }
        self.check_move_out(&issues::require(self.conn(), issue)?, target)
    }

    /// Deleting every issue in `ids` at once.
    pub(crate) fn check_removal<'a>(&self, ids: impl IntoIterator<Item = &'a String>) -> Result<()> {
        if self.policy().is_none() {
            return Ok(());
        }
        for id in ids {
            let Some(issue) = issues::get(self.conn(), id)? else { continue };
            self.check_claim_override(&issue)?;
            if self.gates_limited() {
                if let Some(hold) = human_hold(self.conn(), &issue)? {
                    return Err(human_only(id, &hold, "delete it"));
                }
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

    /// Snapshot of the human gates a restricted caller must leave be (`None`
    /// when gates are not protected from it).
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
            let direct: Vec<String> = {
                let mut stmt = self.conn().prepare_cached(
                    "SELECT d.issue_id FROM dependencies d JOIN issues w ON w.id = d.issue_id
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
            holds.push(HumanHold { gate: g.id, direct, below, around });
        }
        Ok(Some(HumanHolds(holds)))
    }

    /// Refuse when a human gate from `before` was opened, changed or deleted,
    /// or work it held back got past it.
    pub(crate) fn check_human_holds(&self, before: &HumanHolds) -> Result<()> {
        for HumanHold { gate, direct, below, around } in &before.0 {
            if !issues::get(self.conn(), gate)?.as_ref().is_some_and(is_open_human_gate) {
                return Err(human_only(gate, &Hold::Is, "open, change or delete it"));
            }
            for w in direct {
                let still_held = graph::load_edge(self.conn(), w, gate)?.is_some_and(|e| e.dep_type == DepType::Blocks);
                let live = issues::get(self.conn(), w)?.is_some_and(|i| !i.status.is_terminal());
                if !still_held || !live {
                    return Err(human_only(w, &Hold::HeldBy(gate.clone()), "close it or remove that edge"));
                }
            }
            for (w, held) in below {
                let live = issues::get(self.conn(), w)?.is_some_and(|i| !i.status.is_terminal());
                // Retyping a parent-child edge on the way up would move it out from under `held`.
                if !live || !graph::ancestors(self.conn(), w)?.contains(held) {
                    return Err(human_only(w, &Hold::HeldBy(gate.clone()), "close it or move it out of its parent"));
                }
            }
            // The containers around them may not close, or lose them, either.
            for (x, container) in around {
                let live = issues::get(self.conn(), container)?.is_some_and(|i| !i.status.is_terminal());
                if !live || !graph::ancestors(self.conn(), x)?.contains(container) {
                    let hold = Hold::Contains(gate.clone());
                    return Err(human_only(container, &hold, &format!("close it or move {x} out of it")));
                }
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
