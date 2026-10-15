//! # bd-core
//!
//! A coordination engine for humans and AI agents sharing a task graph,
//! modelled on [beads](https://github.com/gastownhall/beads) and backed by
//! SQLite in WAL mode.
//!
//! * **Task lifecycle**: `open -> in_progress -> closed`, plus `blocked`,
//!   `deferred` and `pinned`, with validated transitions.
//! * **Typed dependency graph**: `blocks`, `conditional-blocks`,
//!   `parent-child`, `waits-for` gate readiness; informational types
//!   (`related`, `discovered-from`, ...) do not. Cycles and hierarchy
//!   deadlocks are rejected at write time.
//! * **Deterministic ready work**: a materialized, transactionally maintained
//!   blocked flag plus a total order (policy, then id).
//! * **Leased atomic claiming**: claims run under SQLite's write lock and
//!   grant a lease with a fencing token; heartbeats renew it.
//! * **Crash recovery**: expired leases are reclaimed after a grace window;
//!   SQLite's WAL makes every transaction atomic and durable.
//! * **Optimistic concurrency**: per-issue revisions and guards
//!   (`if_revision`, `if_status`, `if_assignee`).
//! * **Comments, durable memory, and a transactional event history** with
//!   gapless, commit-ordered sequence numbers.
//! * **Playbooks and gates** ([`playbook`], [`gates`]): repeatable multi-step
//!   work declared in TOML and run atomically as `<run>.<step>` issues, with
//!   wait conditions that arm when their step could start.
//! * **Write policies** ([`policy`]): what a transaction's caller may
//!   override (other actors' claims, human gates), enforced where it happens.
//! * **Agent assets** ([`agents`]): the skills and MCP server definitions a
//!   workspace serves to each agent harness, read strictly and hashed.
//!
//! ```no_run
//! use bd_core::{ClaimOptions, InitOptions, NewIssue, OpenOptions, Queries, ReadyQuery, Store};
//!
//! let mut store = Store::init(
//!     std::path::Path::new(".bd/bd.db"),
//!     InitOptions { prefix: "demo".into(), id_mode: Default::default() },
//!     OpenOptions::default(),
//! )?;
//! let issue = store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled("Write docs")))?;
//! let claim = store.write("claim", "agent-7", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))?;
//! assert_eq!(claim.unwrap().issue.id, issue.id);
//! let ready = store.read(|r| r.ready(&ReadyQuery::default()))?;
//! assert!(ready.is_empty());
//! # Ok::<(), bd_core::Error>(())
//! ```

pub mod agents;
pub mod asof;
pub mod claims;
pub mod comments;
pub mod compaction;
pub mod config;
pub mod doctor;
pub mod duplicates;
pub mod error;
pub mod events;
mod filter;
pub mod gates;
pub mod github;
pub mod graph;
pub mod hierarchy;
mod ids;
pub mod issues;
pub mod memory;
pub mod metrics;
pub mod model;
pub mod playbook;
pub mod policy;
pub mod queries;
pub mod query;
pub mod ready;
pub mod rename;
pub mod requests;
mod schema;
pub mod store;
pub mod subgraph;
pub mod time;
pub mod transfer;

pub use asof::{IssueAsOf, Point};
pub use claims::{Claim, ClaimOptions, LeaseView, NextFrom, ReclaimOptions, Reclaimed, ReleaseOptions};
pub use compaction::{Candidate, CompactIssueOutcome, CompactStats};
pub use config::IdMode;
pub use duplicates::{CloseAsOptions, CloseAsOutcome, Replacement, SimilarPair, similar_pairs};
pub use error::{Error, Result};
pub use events::{EventPage, EventQuery, PruneOptions, PruneOutcome};
pub use graph::{BlockChange, DepChange, Direction, TreeNode};
pub use issues::{
    CloseOptions, CloseOutcome, DeleteOptions, DeleteOutcome, PurgeOutcome, ReopenOutcome, UpdateOutcome,
};
pub use memory::{MemoryAction, MemoryWrite};
pub use model::*;
pub use policy::Policy;
pub use queries::Queries;
pub use ready::{BlockedIssue, ExplainOptions, NotReady, OpenChild, Readiness, RootCause};
pub use rename::{RenamePrefixOptions, RenamePrefixOutcome};
pub use requests::RequestRecord;
pub use schema::LATEST_VERSION as SCHEMA_VERSION;
pub use store::{Durability, InitOptions, OpenOptions, ReadCtx, Store, TxStats, WriteCtx};
pub use time::{Clock, ManualClock, SystemClock, Timestamp};
