use serde::{Deserialize, Serialize};

use crate::model::Status;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A right a refused operation needs that the caller's access token lacks:
/// an admin token, or a person's (human-kind) one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Need {
    Admin,
    Human,
}

/// Every failure the engine can report. Each variant maps to a stable
/// machine-readable [`Error::code`] and a process [`Error::exit_code`].
#[derive(Debug)]
pub enum Error {
    Invalid(String),

    NotFound {
        kind: &'static str,
        id: String,
    },

    AlreadyClaimed {
        id: String,
        holder: String,
    },

    NotClaimable {
        id: String,
        status: Status,
    },

    NotReady {
        id: String,
        reasons: Vec<String>,
    },

    NotOwner {
        id: String,
        holder: Option<String>,
        actor: String,
    },

    /// One operation would end several live claims of other actors (a run's
    /// steps, a delete, a reclaim inside `lease.grace`): `held` lists each
    /// issue with its holder.
    ClaimsHeld {
        what: String,
        held: Vec<(String, String)>,
    },

    /// `holder` is whoever holds the claim now, if anyone does.
    LeaseLost {
        id: String,
        detail: String,
        holder: Option<String>,
    },

    /// An optimistic-concurrency guard (`if_revision`, `if_status`,
    /// `if_assignee`) no longer holds. Nothing was written.
    Conflict {
        id: String,
        field: &'static str,
        expected: String,
        actual: String,
    },

    Cycle {
        path: Vec<String>,
    },

    /// A policy refusal (closing an issue with open children, deleting an
    /// issue other issues depend on, ...). Usually overridable with `force`.
    Refused(String),

    EventsTruncated {
        since: i64,
        floor: i64,
    },

    /// `show --as-of` a point before the retained history of the issue:
    /// events older than `floor` (recorded at `floor_ts`) were pruned.
    HistoryPruned {
        id: String,
        floor: i64,
        floor_ts: Option<crate::time::Timestamp>,
    },

    Busy(String),

    /// Something other than a workspace's database is busy past the wait:
    /// another bd process holds a lock file or `bd serve`'s `server.db`, or
    /// `bd serve`'s sign-in has no secrets to use yet or no answer from its
    /// authorizer. The message says what, and what to do; trying again
    /// later may succeed.
    Locked(String),

    SchemaTooNew {
        found: i64,
        supported: i64,
    },

    NoWorkspace(String),

    /// A bd server rejected the access token, or the token's role,
    /// workspaces or actor do not allow the operation.
    Unauthorized(String),

    /// An [`Error::Unauthorized`] refusal that a token with the rights in
    /// `needs` (sorted, without duplicates) would get past: same code, exit
    /// code and text. Built by [`Error::with_needs`], read by [`Error::needs`].
    Needs {
        message: String,
        needs: Vec<Need>,
        /// The human gate a person must open to get past this refusal, set
        /// by the policy's human-gate refusals ([`Error::with_gate`]).
        gate: Option<String>,
    },

    /// A bd server could not be reached, refused the request, or answered
    /// unexpectedly, and the command did not take effect: it is safe to run
    /// again.
    Remote(String),

    /// A write reached a bd server, but its answer was lost: it may have
    /// taken effect, so running it again could apply it twice.
    AnswerLost(String),

    Sqlite(rusqlite::Error),

    Json(serde_json::Error),

    Io(std::io::Error),

    /// A refusal a person could approve in a browser: one that only open
    /// human gates shut to the caller stand in the way of, each naming a
    /// valid approver list (see [`crate::policy`]). Text, code, exit code,
    /// needs and gate are the inner error's. Built by [`Error::approvable`],
    /// read by [`Error::is_approvable`].
    Approvable(Box<Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(msg)
            | Error::Refused(msg)
            | Error::Locked(msg)
            | Error::NoWorkspace(msg)
            | Error::Unauthorized(msg)
            | Error::Remote(msg)
            | Error::AnswerLost(msg)
            | Error::Needs { message: msg, .. } => f.write_str(msg),
            Error::NotFound { kind, id } => write!(f, "{kind} not found: {id}"),
            Error::AlreadyClaimed { id, holder } => write!(f, "{id} is already claimed by {holder}"),
            Error::NotClaimable { id, status } => write!(f, "{id} is not claimable (status {status})"),
            Error::NotReady { id, reasons } => write!(f, "{id} is not ready: {}", reasons.join("; ")),
            Error::NotOwner { id, holder, actor } => {
                write!(f, "{id} is held by {}, not {actor}", holder.as_deref().unwrap_or("nobody"))
            }
            Error::ClaimsHeld { what, held } => write!(
                f,
                "{what} would end live claims of other actors: {}",
                held.iter().map(|(id, holder)| format!("{id} (held by {holder})")).collect::<Vec<_>>().join(", ")
            ),
            Error::LeaseLost { id, detail, .. } => write!(f, "lease lost on {id}: {detail}"),
            Error::Conflict { id, field, expected, actual } => {
                write!(f, "precondition failed on {id}: expected {field} {expected}, found {actual}")
            }
            Error::Cycle { path } => write!(f, "dependency cycle: {}", path.join(" -> ")),
            Error::EventsTruncated { since, floor } => write!(
                f,
                "event cursor {since} is behind retained history (oldest retained seq is {floor}); re-baseline from an export"
            ),
            Error::HistoryPruned { id, floor, floor_ts } => write!(
                f,
                "history of {id} before seq {floor} ({}) was pruned (events.retain_days/retain_rows, events prune)",
                floor_ts.map(|t| t.to_rfc3339()).unwrap_or_else(|| "no events retained".into())
            ),
            Error::Busy(msg) => write!(f, "database is busy: {msg}"),
            Error::SchemaTooNew { found, supported } => {
                write!(f, "database schema v{found} is newer than this binary supports (v{supported}); upgrade bd")
            }
            Error::Sqlite(e) => write!(f, "sqlite: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Approvable(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Approvable(e) => e.source(),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy) | Some(rusqlite::ErrorCode::DatabaseLocked) => {
                Error::Busy(e.to_string())
            }
            _ => Error::Sqlite(e),
        }
    }
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }

    pub fn not_found(kind: &'static str, id: impl Into<String>) -> Self {
        Error::NotFound { kind, id: id.into() }
    }

    /// An access refusal that a token with the `needs` rights would get past.
    pub fn with_needs(needs: &[Need], message: impl Into<String>) -> Self {
        let mut needs = needs.to_vec();
        needs.sort_unstable();
        needs.dedup();
        Error::Needs { message: message.into(), needs, gate: None }
    }

    /// Names the human gate a person must open to get past this refusal;
    /// a no-op on every error but [`Error::Needs`].
    pub fn with_gate(mut self, gate: impl Into<String>) -> Self {
        match &mut self {
            Error::Needs { gate: g, .. } => *g = Some(gate.into()),
            Error::Approvable(e) => {
                if let Error::Needs { gate: g, .. } = e.as_mut() {
                    *g = Some(gate.into());
                }
            }
            _ => {}
        }
        self
    }

    /// The human gate named by [`Error::with_gate`], if any.
    pub fn gate(&self) -> Option<&str> {
        match self.unmarked() {
            Error::Needs { gate, .. } => gate.as_deref(),
            _ => None,
        }
    }

    /// The rights that would get past this refusal; empty for every other error.
    pub fn needs(&self) -> &[Need] {
        match self.unmarked() {
            Error::Needs { needs, .. } => needs,
            _ => &[],
        }
    }

    /// Marks this refusal as one a person could approve in a browser
    /// ([`Error::Approvable`]); never wraps twice.
    pub fn approvable(self) -> Error {
        match self {
            e @ Error::Approvable(_) => e,
            e => Error::Approvable(Box::new(e)),
        }
    }

    /// Whether this refusal is marked by [`Error::approvable`].
    pub fn is_approvable(&self) -> bool {
        matches!(self, Error::Approvable(_))
    }

    /// The error without the [`Error::Approvable`] mark.
    pub fn unmarked(&self) -> &Error {
        match self {
            Error::Approvable(e) => e,
            e => e,
        }
    }

    /// [`Error::unmarked`], by value.
    pub fn into_unmarked(self) -> Error {
        match self {
            Error::Approvable(e) => *e,
            e => e,
        }
    }

    /// Stable machine-readable error code (used in JSON error output).
    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "invalid",
            Error::NotFound { .. } => "not_found",
            Error::AlreadyClaimed { .. } => "already_claimed",
            Error::NotClaimable { .. } => "not_claimable",
            Error::NotReady { .. } => "not_ready",
            Error::NotOwner { .. } | Error::ClaimsHeld { .. } => "not_owner",
            Error::LeaseLost { .. } => "lease_lost",
            Error::Conflict { .. } => "conflict",
            Error::Cycle { .. } => "cycle",
            Error::Refused(_) => "refused",
            Error::EventsTruncated { .. } => "events_truncated",
            Error::HistoryPruned { .. } => "history_pruned",
            Error::Busy(_) | Error::Locked(_) => "busy",
            Error::SchemaTooNew { .. } => "schema_too_new",
            Error::NoWorkspace(_) => "no_workspace",
            Error::Unauthorized(_) | Error::Needs { .. } => "unauthorized",
            Error::Remote(_) => "remote",
            Error::AnswerLost(_) => "answer_lost",
            Error::Sqlite(_) => "sqlite",
            Error::Json(_) => "json",
            Error::Io(_) => "io",
            Error::Approvable(e) => e.code(),
        }
    }

    /// Process exit code. 13 matches beads' "stale guard" code so scripts
    /// can tell "another actor won the race" apart from other failures.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Invalid(_) | Error::Cycle { .. } | Error::Refused(_) => 2,
            Error::NotFound { .. } | Error::NoWorkspace(_) => 3,
            Error::AlreadyClaimed { .. }
            | Error::NotClaimable { .. }
            | Error::NotReady { .. }
            | Error::NotOwner { .. }
            | Error::ClaimsHeld { .. }
            | Error::LeaseLost { .. } => 4,
            Error::Busy(_) | Error::Locked(_) => 5,
            Error::EventsTruncated { .. } | Error::HistoryPruned { .. } => 6,
            Error::Unauthorized(_) | Error::Needs { .. } => 7,
            Error::Remote(_) => 8,
            Error::AnswerLost(_) => 9,
            Error::Conflict { .. } => 13,
            Error::SchemaTooNew { .. } | Error::Sqlite(_) | Error::Json(_) | Error::Io(_) => 1,
            Error::Approvable(e) => e.exit_code(),
        }
    }

    /// True for errors that mean "another actor changed shared state first".
    pub fn is_contention(&self) -> bool {
        matches!(
            self.unmarked(),
            Error::AlreadyClaimed { .. }
                | Error::NotClaimable { .. }
                | Error::Conflict { .. }
                | Error::LeaseLost { .. }
                | Error::NotOwner { .. }
                | Error::ClaimsHeld { .. }
        )
    }
}
