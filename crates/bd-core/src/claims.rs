//! Leased atomic claiming and dead-worker recovery.
//!
//! A claim moves an issue `open -> in_progress`, sets the assignee, and grants
//! a lease that expires after a TTL. Workers renew it with [`WriteCtx::heartbeat`].
//! A worker that dies stops heartbeating; once its lease has been expired for
//! longer than the grace window, [`WriteCtx::reclaim_expired`] reverts the
//! issue to `open` so another worker can take it.
//!
//! Every lease carries a fencing token (the sequence number of the event that
//! granted it). Passing the token to claim/heartbeat/close/release proves the
//! caller still holds *that* grant, not merely the same actor name.
//!
//! A claim is *live* until `reclaim` could take it back: while its lease has
//! not been expired for `lease.grace`. A live claim is its holder's alone: a
//! second claim of it fails even for the same actor, unless it passes the
//! lease's token (an idempotent renew), and ending or taking it over needs
//! `take_over` (see [`crate::policy`]); so does reclaiming it early, with a
//! grace shorter than `lease.grace`. A claim past that point is anyone's to
//! reclaim, claim, close or release.
//!
//! Invariant (checked by `doctor`): a lease row exists iff its issue is
//! `in_progress`, and the lease holder equals the issue's assignee.

use std::collections::BTreeMap;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::Serialize;
use serde_json::{Value, json};

use crate::config;
use crate::error::{Error, Result};
use crate::filter::{QueryParts, apply_work_filter};
use crate::issues;
use crate::model::{GATE_TYPE, Guard, Issue, Lease, ReadyQuery, Status, WorkFilter};
use crate::ready;
use crate::store::WriteCtx;
use crate::time::{Timestamp, duration_ms, format_duration_ms};

const LEASE_COLUMNS: &str = "issue_id, holder, token, granted_at, expires_at, heartbeat_at, renewals";

fn lease_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        issue_id: r.get(0)?,
        holder: r.get(1)?,
        token: r.get(2)?,
        granted_at: r.get(3)?,
        expires_at: r.get(4)?,
        heartbeat_at: r.get(5)?,
        renewals: r.get(6)?,
    })
}

pub fn get_lease(conn: &Connection, id: &str) -> Result<Option<Lease>> {
    let sql = format!("SELECT {LEASE_COLUMNS} FROM leases WHERE issue_id = ?1");
    Ok(conn.prepare_cached(&sql)?.query_row([id], lease_from_row).optional()?)
}

pub(crate) fn delete_lease(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn.prepare_cached("DELETE FROM leases WHERE issue_id = ?1")?.execute([id])? > 0)
}

pub(crate) fn upsert_lease(
    conn: &Connection,
    id: &str,
    holder: &str,
    token: i64,
    now: Timestamp,
    ttl: Duration,
) -> Result<Lease> {
    conn.prepare_cached(
        "INSERT INTO leases (issue_id, holder, token, granted_at, expires_at, heartbeat_at, renewals)
         VALUES (?1, ?2, ?3, ?4, ?5, ?4, 0)
         ON CONFLICT(issue_id) DO UPDATE SET holder = excluded.holder, token = excluded.token,
             granted_at = excluded.granted_at, expires_at = excluded.expires_at,
             heartbeat_at = excluded.heartbeat_at, renewals = 0",
    )?
    .execute(params![id, holder, token, now, now.plus(ttl)])?;
    get_lease(conn, id)?.ok_or_else(|| Error::not_found("lease", id))
}

fn renew_lease(conn: &Connection, id: &str, now: Timestamp, ttl: Duration) -> Result<Lease> {
    conn.prepare_cached(
        "UPDATE leases SET expires_at = ?1, heartbeat_at = ?2, renewals = renewals + 1 WHERE issue_id = ?3",
    )?
    .execute(params![now.plus(ttl), now, id])?;
    get_lease(conn, id)?.ok_or_else(|| Error::not_found("lease", id))
}

/// Verify that `token` names the live lease on `id`.
pub(crate) fn check_token(conn: &Connection, id: &str, _actor: &str, token: i64) -> Result<()> {
    match get_lease(conn, id)? {
        Some(l) if l.token == token => Ok(()),
        Some(l) => Err(Error::LeaseLost {
            id: id.to_string(),
            detail: format!("token {token} is stale; current lease (token {}) is held by {}", l.token, l.holder),
        }),
        None => Err(Error::LeaseLost {
            id: id.to_string(),
            detail: format!("no live lease; token {token} was released or reclaimed"),
        }),
    }
}

/// Whether `lease` has been expired for at least `lease.grace`, so that
/// `reclaim` would take it back: its claim is no longer live.
pub(crate) fn is_reclaimable(conn: &Connection, lease: &Lease, now: Timestamp) -> Result<bool> {
    if !lease.is_expired(now) {
        return Ok(false);
    }
    Ok(lease.expires_at <= now.minus(config::lease_grace(conn)?))
}

fn validate_ttl(ttl: Duration) -> Result<Duration> {
    if ttl < Duration::from_secs(1) {
        return Err(Error::invalid("lease ttl must be at least 1s"));
    }
    Ok(ttl)
}

#[derive(Clone, Debug, Default)]
pub struct ClaimOptions {
    /// Lease duration; defaults to the `lease.ttl` config.
    pub ttl: Option<Duration>,
    /// Claim even if the issue is blocked or deferred (by explicit id only).
    pub allow_blocked: bool,
    pub guard: Guard,
    /// Fencing token of a claim the caller already holds: claiming it again
    /// with this token renews the lease (an idempotent retry). Without it, a
    /// live claim cannot be claimed again, even by the same actor.
    pub token: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Claim {
    pub issue: Issue,
    pub lease: Lease,
    /// The caller already held this claim (it passed the lease's token, or
    /// the lease was missing); the lease was refreshed.
    pub already_held: bool,
    /// A dead claim (lease expired for `lease.grace`) this claim took back first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimed: Option<Reclaimed>,
}

#[derive(Clone, Debug, Default)]
pub struct ReleaseOptions {
    pub reason: Option<String>,
    /// Release another actor's live claim or assignment (a live claim's
    /// takeover is recorded in the `released` event; through `bd serve` it
    /// also needs an admin token unless the caller's token owns it).
    pub take_over: bool,
    pub guard: Guard,
    pub token: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct ReclaimOptions {
    /// How long past expiry a lease must be; defaults to `lease.grace`.
    /// Shorter, it may end claims that are still live: other actors' need
    /// `take_over`.
    pub grace: Option<Duration>,
    pub filter: WorkFilter,
    pub dry_run: bool,
    /// Reclaim other actors' leases inside `lease.grace` (a takeover,
    /// recorded in each `reclaimed` event; see [`crate::policy`]).
    pub take_over: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Reclaimed {
    pub issue_id: String,
    pub previous_holder: String,
    pub token: i64,
    pub expired_at: Timestamp,
    pub heartbeat_at: Timestamp,
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaseView {
    #[serde(flatten)]
    pub lease: Lease,
    pub title: String,
    pub status: Status,
    pub expired: bool,
    pub remaining_ms: i64,
}

pub fn leases(conn: &Connection, now: Timestamp) -> Result<Vec<LeaseView>> {
    let mut stmt = conn.prepare_cached(
        "SELECT l.issue_id, l.holder, l.token, l.granted_at, l.expires_at, l.heartbeat_at, l.renewals, i.title, i.status
         FROM leases l JOIN issues i ON i.id = l.issue_id ORDER BY l.expires_at, l.issue_id",
    )?;
    let rows = stmt.query_map([], |r| {
        let lease = lease_from_row(r)?;
        Ok(LeaseView {
            expired: lease.is_expired(now),
            remaining_ms: lease.remaining_ms(now),
            title: r.get(7)?,
            status: r.get(8)?,
            lease,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

impl WriteCtx<'_> {
    fn lease_ttl(&self, requested: Option<Duration>) -> Result<Duration> {
        match requested {
            Some(t) => validate_ttl(t),
            None => config::lease_ttl(self.conn()),
        }
    }

    /// Atomically claim one issue for the transaction's actor.
    ///
    /// Claimable means: status `open`, unassigned / reserved for the actor /
    /// held by a `claim.pools` alias, and (unless `allow_blocked`) ready. A
    /// dead claim (lease expired for `lease.grace`) is reclaimed first, as
    /// `reclaim` would. A live claim is refused, even to its own actor (two
    /// sessions sharing an actor name must not both hold it), unless
    /// `opts.token` names its lease: then the claim is renewed.
    pub fn claim(&mut self, id: &str, opts: &ClaimOptions) -> Result<Claim> {
        self.claim_checked(id, opts, false)
    }

    /// `ready_verified`: the caller just selected `id` from the ready queue
    /// inside this transaction, so the readiness re-check can be skipped.
    fn claim_checked(&mut self, id: &str, opts: &ClaimOptions, ready_verified: bool) -> Result<Claim> {
        let mut issue = issues::require(self.conn(), id)?;
        opts.guard.check(&issue)?;
        if issue.issue_type == GATE_TYPE {
            return Err(Error::Refused(format!(
                "{id} is a gate: it opens through `bd gate check` or `bd gate resolve {id}`, not a claim"
            )));
        }
        let actor = self.actor().to_string();
        let ttl = self.lease_ttl(opts.ttl)?;
        let now = self.now();

        let mut reclaimed = None;
        if issue.status == Status::InProgress {
            let holder = issue.assignee.clone().unwrap_or_default();
            let lease = get_lease(self.conn(), id)?;
            if let Some(t) = opts.token {
                if lease.as_ref().is_some_and(|l| l.token == t) && holder == actor {
                    let lease = renew_lease(self.conn(), id, now, ttl)?;
                    return Ok(Claim { issue, lease, already_held: true, reclaimed: None });
                }
                check_token(self.conn(), id, &actor, t)?;
            }
            match lease {
                Some(l) if is_reclaimable(self.conn(), &l, now)? => {
                    reclaimed = Some(self.reclaim_one(&l, config::lease_grace(self.conn())?)?);
                    issue = issues::require(self.conn(), id)?;
                }
                // A claim whose lease is missing: its holder gets one back.
                None if holder == actor => {
                    let seq = self.emit(
                        "lease_granted",
                        Some(id),
                        json!({ "reason": "regrant", "ttl_ms": duration_ms(ttl) }),
                    )?;
                    let lease = upsert_lease(self.conn(), id, &actor, seq, now, ttl)?;
                    return Ok(Claim { issue, lease, already_held: true, reclaimed: None });
                }
                _ => return Err(Error::AlreadyClaimed { id: id.to_string(), holder }),
            }
        } else if let Some(t) = opts.token {
            check_token(self.conn(), id, &actor, t)?;
        }
        if issue.status != Status::Open {
            return Err(Error::NotClaimable { id: id.to_string(), status: issue.status });
        }
        if let Some(holder) = &issue.assignee {
            if *holder != actor && !config::claim_pools(self.conn())?.contains(holder) {
                return Err(Error::AlreadyClaimed { id: id.to_string(), holder: holder.clone() });
            }
        }
        if !opts.allow_blocked && !ready_verified {
            let reasons = ready::not_ready_reasons(self.conn(), &issue, now)?;
            if !reasons.is_empty() {
                return Err(Error::NotReady { id: id.to_string(), reasons });
            }
        }
        self.conn()
            .prepare_cached(
                "UPDATE issues SET status = 'in_progress', assignee = ?1, started_at = COALESCE(started_at, ?2),
                    updated_at = ?2, revision = revision + 1
                 WHERE id = ?3 AND status = 'open'",
            )?
            .execute(params![actor, now, id])?;
        let seq = self.emit(
            "claimed",
            Some(id),
            json!({
                "ttl_ms": duration_ms(ttl),
                "expires_at": now.plus(ttl),
                "previous_assignee": issue.assignee,
            }),
        )?;
        let lease = upsert_lease(self.conn(), id, &actor, seq, now, ttl)?;
        Ok(Claim { issue: issues::require(self.conn(), id)?, lease, already_held: false, reclaimed })
    }

    /// Atomically claim the first ready issue (in queue order) the actor may
    /// take. Runs entirely under the write lock, so the head of the queue
    /// cannot be taken by anyone else between the read and the claim.
    /// Stale leases past their grace window are reclaimed first when
    /// `lease.auto_reclaim` is on.
    pub fn claim_next(&mut self, query: &ReadyQuery, opts: &ClaimOptions) -> Result<Option<Claim>> {
        if config::auto_reclaim(self.conn())? {
            self.reclaim_expired(&ReclaimOptions::default())?;
        }
        let pools = config::claim_pools(self.conn())?;
        let actor = self.actor().to_string();
        let mut q = query.clone();
        q.limit = Some(1);
        let head = ready::ready_for(self.conn(), &q, self.now(), Some((&actor, &pools)))?;
        match head.into_iter().next() {
            None => Ok(None),
            Some(issue) => {
                let claim_opts = ClaimOptions { ttl: opts.ttl, ..Default::default() };
                self.claim_checked(&issue.id, &claim_opts, true).map(Some)
            }
        }
    }

    /// Extend the actor's lease on `id`. Fails with `LeaseLost` if the claim
    /// was released, reclaimed, or taken over, so a worker learns to stop.
    pub fn heartbeat(&mut self, id: &str, token: Option<i64>, ttl: Option<Duration>) -> Result<Lease> {
        let issue = issues::require(self.conn(), id)?;
        let actor = self.actor().to_string();
        let ttl = self.lease_ttl(ttl)?;
        let now = self.now();
        match get_lease(self.conn(), id)? {
            Some(lease) => {
                if lease.holder != actor {
                    return Err(Error::LeaseLost {
                        id: id.to_string(),
                        detail: format!("now held by {}", lease.holder),
                    });
                }
                if let Some(t) = token {
                    if t != lease.token {
                        return Err(Error::LeaseLost {
                            id: id.to_string(),
                            detail: format!("token {t} is stale (current token {})", lease.token),
                        });
                    }
                }
                renew_lease(self.conn(), id, now, ttl)
            }
            None if issue.status == Status::InProgress
                && issue.assignee.as_deref() == Some(actor.as_str())
                && token.is_none() =>
            {
                let seq =
                    self.emit("lease_granted", Some(id), json!({ "reason": "regrant", "ttl_ms": duration_ms(ttl) }))?;
                upsert_lease(self.conn(), id, &actor, seq, now, ttl)
            }
            None => {
                let detail = match (&issue.status, &issue.assignee) {
                    (Status::InProgress, Some(h)) if *h != actor => format!("claimed by {h}"),
                    (s, _) => format!("issue is {s}; the claim was released or reclaimed"),
                };
                Err(Error::LeaseLost { id: id.to_string(), detail })
            }
        }
    }

    /// Give up a claim (or an assignment): clears the assignee and returns an
    /// in-progress issue to `open`.
    pub fn release(&mut self, id: &str, opts: &ReleaseOptions) -> Result<Issue> {
        let issue = issues::require(self.conn(), id)?;
        opts.guard.check(&issue)?;
        if issue.status == Status::Closed {
            return Err(Error::invalid(format!("{id} is closed")));
        }
        let Some(holder) = issue.assignee.clone() else {
            return Err(Error::invalid(format!("{id} is not claimed or assigned")));
        };
        let actor = self.actor().to_string();
        let claimed = issue.status == Status::InProgress;
        // Assignments and live claims are their holder's to give up; a dead
        // claim is anyone's, as for `reclaim`.
        if holder != actor && !opts.take_over && (!claimed || self.others_live_claim(&issue)?.is_some()) {
            return Err(Error::NotOwner { id: id.to_string(), holder: Some(holder), actor });
        }
        if let Some(t) = opts.token {
            check_token(self.conn(), id, &actor, t)?;
        }
        let claim_override = if claimed { self.check_claim_override(&issue, opts.take_over)? } else { None };
        let (status, started_at) =
            if issue.status == Status::InProgress { (Status::Open, None) } else { (issue.status, issue.started_at) };
        self.conn()
            .prepare_cached(
                "UPDATE issues SET status = ?1, assignee = NULL, started_at = ?2, updated_at = ?3,
                    revision = revision + 1
                 WHERE id = ?4",
            )?
            .execute(params![status, started_at, self.now(), id])?;
        let lease = get_lease(self.conn(), id)?;
        delete_lease(self.conn(), id)?;
        let reason = opts.reason.as_deref().map(str::trim).filter(|r| !r.is_empty());
        let mut data = json!({
            "previous_holder": holder,
            "previous_status": issue.status,
            "reason": reason,
            "forced": holder != actor,
            "token": lease.map(|l| l.token),
        });
        if let Some(o) = claim_override {
            data["claim_override"] = o;
        }
        self.emit("released", Some(id), data)?;
        issues::require(self.conn(), id)
    }

    /// Crash recovery: revert in-progress issues whose lease expired at least
    /// `grace` ago back to `open`, clearing the assignee. A grace shorter than
    /// `lease.grace` reaches claims that are still live: other actors' are
    /// taken over only with `opts.take_over` (and the policy's leave).
    pub fn reclaim_expired(&mut self, opts: &ReclaimOptions) -> Result<Vec<Reclaimed>> {
        let lease_grace = config::lease_grace(self.conn())?;
        let grace = opts.grace.unwrap_or(lease_grace);
        let now = self.now();
        let cutoff = now.minus(grace);
        let mut parts = QueryParts::default();
        parts.cond("i.status = 'in_progress'", []);
        parts.cond("l.expires_at <= ?", [rusqlite::types::Value::Integer(cutoff.millis())]);
        apply_work_filter(&mut parts, &opts.filter);
        let (sql, params) = parts.build(
            "SELECT l.issue_id, l.holder, l.token, l.expires_at, l.heartbeat_at FROM leases l JOIN issues i ON i.id = l.issue_id",
            "ORDER BY l.expires_at, l.issue_id",
            Vec::new(),
        );
        let stale: Vec<Reclaimed> = {
            let mut stmt = self.conn().prepare_cached(&sql)?;
            let rows = stmt.query_map(params_from_iter(params), |r| {
                Ok(Reclaimed {
                    issue_id: r.get(0)?,
                    previous_holder: r.get(1)?,
                    token: r.get(2)?,
                    expired_at: r.get(3)?,
                    heartbeat_at: r.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut overrides = BTreeMap::new();
        if grace < lease_grace {
            let mut held = Vec::new();
            for r in &stale {
                held.extend(issues::get(self.conn(), &r.issue_id)?);
            }
            let what = format!(
                "reclaiming leases expired less than lease.grace ({}) ago",
                format_duration_ms(duration_ms(lease_grace))
            );
            overrides = self.check_claim_overrides(held, opts.take_over, &what)?;
        }
        if opts.dry_run {
            return Ok(stale);
        }
        for r in &stale {
            self.revert_reclaimed(r, grace, overrides.remove(&r.issue_id))?;
        }
        Ok(stale)
    }

    /// Reclaim the dead claim holding `lease` (see [`is_reclaimable`]).
    fn reclaim_one(&mut self, lease: &Lease, grace: Duration) -> Result<Reclaimed> {
        let r = Reclaimed {
            issue_id: lease.issue_id.clone(),
            previous_holder: lease.holder.clone(),
            token: lease.token,
            expired_at: lease.expires_at,
            heartbeat_at: lease.heartbeat_at,
        };
        self.revert_reclaimed(&r, grace, None)?;
        Ok(r)
    }

    /// `claim_override`: the live claim this ended (a reclaim inside `lease.grace`).
    fn revert_reclaimed(&mut self, r: &Reclaimed, grace: Duration, claim_override: Option<Value>) -> Result<()> {
        delete_lease(self.conn(), &r.issue_id)?;
        self.conn()
            .prepare_cached(
                "UPDATE issues SET status = 'open', assignee = NULL, started_at = NULL, updated_at = ?1,
                    revision = revision + 1
                 WHERE id = ?2 AND status = 'in_progress'",
            )?
            .execute(params![self.now(), r.issue_id])?;
        let mut data = json!({
            "previous_holder": r.previous_holder,
            "token": r.token,
            "expired_at": r.expired_at,
            "last_heartbeat_at": r.heartbeat_at,
            "grace_ms": duration_ms(grace),
        });
        if let Some(o) = claim_override {
            data["claim_override"] = o;
        }
        self.emit("reclaimed", Some(&r.issue_id), data)?;
        self.bump_counter("reclaims", 1)
    }
}
