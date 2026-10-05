//! Claims and leases: claim, heartbeat, release, reclaim, leases.

use clap::Args;

use super::*;

#[derive(Args, Debug, Clone)]
pub struct ClaimArgs {
    /// Issue to claim (omit with --next)
    #[arg(required_unless_present = "next", conflicts_with = "next")]
    pub id: Option<String>,
    /// Claim the head of the ready queue (filters apply)
    #[arg(long)]
    pub next: bool,
    #[command(flatten)]
    pub filter: FilterArgs,
    /// priority | hybrid | oldest (with --next)
    #[arg(long, default_value = "priority")]
    pub sort: String,
    /// Lease duration (default: lease.ttl)
    #[arg(long)]
    pub ttl: Option<String>,
    /// Claim even if blocked, deferred, or with open children (by id only)
    #[arg(long)]
    pub allow_blocked: bool,
    #[arg(long, value_name = "N")]
    pub if_revision: Option<i64>,
    /// Fencing token of your claim: renew it (by id only). A live claim is refused without it, even to its own actor
    #[arg(long, conflicts_with = "next")]
    pub token: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct HeartbeatArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Fencing token from `claim` (fails if the lease was re-granted)
    #[arg(long)]
    pub token: Option<i64>,
    #[arg(long)]
    pub ttl: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ReleaseArgs {
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    #[arg(short, long)]
    pub reason: Option<String>,
    /// Release another actor's live claim or assignment (recorded in the event; through bd serve, an admin token
    /// unless the token's actor owns the claim)
    #[arg(long)]
    pub take_over: bool,
    /// Release only if still held by this actor (compare-and-swap); another actor's live claim also needs --take-over
    #[arg(long, value_name = "ACTOR")]
    pub if_assignee: Option<String>,
    /// Fencing token from `claim`: release only while that lease is held
    #[arg(long)]
    pub token: Option<i64>,
}

#[derive(Args, Debug, Clone)]
pub struct ReclaimArgs {
    /// Only leases expired at least this long ago (default: lease.grace). Shorter than lease.grace, other actors'
    /// claims are still live: reclaiming them needs --take-over
    #[arg(long)]
    pub grace: Option<String>,
    /// Only these holders
    #[arg(short, long)]
    pub assignee: Option<String>,
    #[arg(short, long = "label", value_delimiter = ',')]
    pub labels: Vec<String>,
    #[arg(long = "id", value_delimiter = ',')]
    pub ids: Vec<String>,
    #[arg(long)]
    pub dry_run: bool,
    /// Reclaim other actors' leases inside lease.grace, with a shorter --grace (recorded in the events; through bd
    /// serve, an admin token unless the token's actor owns the claims)
    #[arg(long)]
    pub take_over: bool,
}

#[derive(Args, Debug, Clone)]
pub struct LeasesArgs {
    /// Only expired leases
    #[arg(long)]
    pub expired: bool,
}
