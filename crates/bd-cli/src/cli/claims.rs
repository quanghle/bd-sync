//! Claims and leases: claim, heartbeat, release, reclaim, leases.

use clap::Args;

use super::*;

pub const CLAIM_LONG_ABOUT: &str = "\
Claim an issue, or the next ready one, under a lease

By id, claims an issue that is open, ready (unless --allow-blocked) and
unassigned, reserved for the actor or held by a claim.pools alias; a dead claim
on it is reclaimed first. With --next, claims the head of the ready queue among
the issues the actor may claim, in --sort order and narrowed by the filter
flags. --ttl applies to both; --allow-blocked, --if-revision and --token apply
only by id. A live claim is refused (exit 4), even to its own actor, unless
--token names its lease: then the claim is renewed. The claim prints its lease
token: pass it to `bd heartbeat`, `bd close` and `bd release`.";

const CLAIM_EXAMPLES: &str = "\
Examples:
  bd claim --next
  bd claim --next --parent bd-7 -l backend
  bd claim bd-12 --ttl 30m
  bd claim bd-12 --token 41          # renew the claim held";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = CLAIM_EXAMPLES)]
pub struct ClaimArgs {
    /// Issue to claim (omit with --next)
    #[arg(required_unless_present = "next", conflicts_with = "next")]
    pub id: Option<String>,
    /// Claim the head of the ready queue; the filter flags apply only with --next
    #[arg(long)]
    pub next: bool,
    #[command(flatten)]
    pub filter: FilterArgs,
    /// Queue order with --next: priority, hybrid or oldest
    #[arg(long, default_value = "priority")]
    pub sort: String,
    #[arg(long, value_name = "DURATION", help = TTL_HELP)]
    pub ttl: Option<String>,
    /// Claim an open issue despite readiness checks (blockers, deferral, open children; by id only)
    #[arg(long)]
    pub allow_blocked: bool,
    #[arg(long, value_name = "N", help = concat!(if_revision_help!(), if_revision_by_id_suffix!()))]
    pub if_revision: Option<i64>,
    /// Fencing token of a claim held: renew it (by id only; a live claim is refused without it, even to its own
    /// actor)
    #[arg(long, conflicts_with = "next")]
    pub token: Option<i64>,
}

pub const HEARTBEAT_LONG_ABOUT: &str = "\
Renew the lease on claimed issues

Extends the actor's lease on each issue by --ttl from now. Renew well within
the lease while working. It fails (exit 4) once the claim was released,
reclaimed or taken over, or, with --token, once the lease was granted again:
then stop working on that issue.";

const HEARTBEAT_EXAMPLES: &str = "\
Examples:
  bd heartbeat bd-12 --token 41
  bd heartbeat bd-12 bd-13 --ttl 30m";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = HEARTBEAT_EXAMPLES)]
pub struct HeartbeatArgs {
    /// Issues to renew
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(long, help = FENCING_TOKEN_HELP)]
    pub token: Option<i64>,
    #[arg(long, value_name = "DURATION", help = TTL_HELP)]
    pub ttl: Option<String>,
}

pub const RELEASE_LONG_ABOUT: &str = "\
Give up a claim or an assignment

Clears the assignee; a claimed issue goes back to open. Use it when work stops
before it is done, so another actor can take it. The actor's own claims and
assignments, and dead claims, need nothing more; another actor's assignment or
live claim needs --take-over. --token releases only while that lease is held.";

const RELEASE_EXAMPLES: &str = "\
Examples:
  bd release bd-12 --token 41 -r \"blocked on review\"
  bd release bd-12 --take-over --if-assignee alice";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = RELEASE_EXAMPLES)]
pub struct ReleaseArgs {
    /// Issues to release
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Reason recorded in the event
    #[arg(short, long)]
    pub reason: Option<String>,
    #[arg(
        long,
        help = concat!(
            "Release another actor's assignment or live claim; a dead claim needs no --take-over",
            take_over_suffix!()
        )
    )]
    pub take_over: bool,
    /// Release only if the assignee is still ACTOR; another actor's assignment or live claim also needs --take-over
    #[arg(long, value_name = "ACTOR")]
    pub if_assignee: Option<String>,
    #[arg(long, help = FENCING_TOKEN_HELP)]
    pub token: Option<i64>,
}

pub const RECLAIM_LONG_ABOUT: &str = "\
Revert expired claims of dead workers (past the grace period)

Returns to open, unassigned, every claimed issue whose lease expired at least
--grace ago (default: config lease.grace); it is the recovery for workers that
died. Until then a claim is live and only its holder may end it: a --grace
shorter than lease.grace reaches other actors' live claims, which needs
--take-over. -a, -l and --id narrow the leases looked at.";

const RECLAIM_EXAMPLES: &str = "\
Examples:
  bd reclaim --dry-run
  bd reclaim --id bd-12 --grace 0s --take-over";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = RECLAIM_EXAMPLES)]
pub struct ReclaimArgs {
    /// Only leases expired at least this long ago, e.g. 15m (default: config lease.grace)
    #[arg(long, value_name = "DURATION")]
    pub grace: Option<String>,
    /// Only leases held by this actor
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Only issues with all these labels (repeatable or comma separated)
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    /// Only these issues (repeatable or comma separated)
    #[arg(long = "id", value_name = "ID", value_delimiter = ',')]
    pub ids: Vec<String>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
    #[arg(
        long,
        help = concat!(
            "Reclaim other actors' leases still inside lease.grace, with a shorter --grace",
            take_over_suffix!()
        )
    )]
    pub take_over: bool,
}

#[derive(Args, Debug, Clone)]
pub struct LeasesArgs {
    /// Only expired leases
    #[arg(long)]
    pub expired: bool,
}
