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

pub mod claims;
pub mod comments;
pub mod config;
pub mod doctor;
pub mod error;
pub mod events;
mod filter;
pub mod graph;
mod ids;
pub mod issues;
pub mod memory;
pub mod metrics;
pub mod model;
pub mod queries;
pub mod ready;
mod schema;
pub mod store;
pub mod time;
pub mod transfer;

pub use claims::{Claim, ClaimOptions, LeaseView, ReclaimOptions, Reclaimed, ReleaseOptions};
pub use config::IdMode;
pub use error::{Error, Result};
pub use events::{EventPage, EventQuery, PruneOptions, PruneOutcome};
pub use graph::{BlockChange, DepChange, Direction, TreeNode};
pub use issues::{CloseOptions, CloseOutcome, DeleteOptions, DeleteOutcome, ReopenOutcome, UpdateOutcome};
pub use memory::{MemoryAction, MemoryWrite};
pub use model::*;
pub use queries::Queries;
pub use ready::BlockedIssue;
pub use schema::LATEST_VERSION as SCHEMA_VERSION;
pub use store::{Durability, InitOptions, OpenOptions, ReadCtx, Store, TxStats, WriteCtx};
pub use time::{Clock, ManualClock, SystemClock, Timestamp};
