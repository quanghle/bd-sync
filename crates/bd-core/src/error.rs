use crate::model::Status;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every failure the engine can report. Each variant maps to a stable
/// machine-readable [`Error::code`] and a process [`Error::exit_code`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),

    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },

    #[error("{id} is already claimed by {holder}")]
    AlreadyClaimed { id: String, holder: String },

    #[error("{id} is not claimable (status {status})")]
    NotClaimable { id: String, status: Status },

    #[error("{id} is not ready: {}", reasons.join("; "))]
    NotReady { id: String, reasons: Vec<String> },

    #[error("{id} is held by {}, not {actor}", holder.as_deref().unwrap_or("nobody"))]
    NotOwner { id: String, holder: Option<String>, actor: String },

    /// One operation would end several live claims of other actors (a run's
    /// steps, a delete, a reclaim inside `lease.grace`): `held` lists each
    /// issue with its holder.
    #[error(
        "{what} would end live claims of other actors: {}",
        held.iter().map(|(id, holder)| format!("{id} (held by {holder})")).collect::<Vec<_>>().join(", ")
    )]
    ClaimsHeld { what: String, held: Vec<(String, String)> },

    /// `holder` is whoever holds the claim now, if anyone does.
    #[error("lease lost on {id}: {detail}")]
    LeaseLost { id: String, detail: String, holder: Option<String> },

    /// An optimistic-concurrency guard (`if_revision`, `if_status`,
    /// `if_assignee`) no longer holds. Nothing was written.
    #[error("precondition failed on {id}: expected {field} {expected}, found {actual}")]
    Conflict { id: String, field: &'static str, expected: String, actual: String },

    #[error("dependency cycle: {}", path.join(" -> "))]
    Cycle { path: Vec<String> },

    /// A policy refusal (closing an issue with open children, deleting an
    /// issue other issues depend on, ...). Usually overridable with `force`.
    #[error("{0}")]
    Refused(String),

    #[error(
        "event cursor {since} is behind retained history (oldest retained seq is {floor}); re-baseline from an export"
    )]
    EventsTruncated { since: i64, floor: i64 },

    #[error("database is busy: {0}")]
    Busy(String),

    /// Another bd process holds a lock file (not the database) past the
    /// wait: the message names the file and says what to do.
    #[error("{0}")]
    Locked(String),

    #[error("database schema v{found} is newer than this binary supports (v{supported}); upgrade bd")]
    SchemaTooNew { found: i64, supported: i64 },

    #[error("{0}")]
    NoWorkspace(String),

    /// A bd server rejected the access token, or the token's role,
    /// workspaces or actor do not allow the operation.
    #[error("{0}")]
    Unauthorized(String),

    /// A bd server could not be reached, refused the request, or answered
    /// unexpectedly, and the command did not take effect: it is safe to run
    /// again.
    #[error("{0}")]
    Remote(String),

    /// A write reached a bd server, but its answer was lost: it may have
    /// taken effect, so running it again could apply it twice.
    #[error("{0}")]
    AnswerLost(String),

    #[error("sqlite: {0}")]
    Sqlite(rusqlite::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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
            Error::Busy(_) | Error::Locked(_) => "busy",
            Error::SchemaTooNew { .. } => "schema_too_new",
            Error::NoWorkspace(_) => "no_workspace",
            Error::Unauthorized(_) => "unauthorized",
            Error::Remote(_) => "remote",
            Error::AnswerLost(_) => "answer_lost",
            Error::Sqlite(_) => "sqlite",
            Error::Json(_) => "json",
            Error::Io(_) => "io",
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
            Error::EventsTruncated { .. } => 6,
            Error::Unauthorized(_) => 7,
            Error::Remote(_) => 8,
            Error::AnswerLost(_) => 9,
            Error::Conflict { .. } => 13,
            Error::SchemaTooNew { .. } | Error::Sqlite(_) | Error::Json(_) | Error::Io(_) => 1,
        }
    }

    /// True for errors that mean "another actor changed shared state first".
    pub fn is_contention(&self) -> bool {
        matches!(
            self,
            Error::AlreadyClaimed { .. }
                | Error::NotClaimable { .. }
                | Error::Conflict { .. }
                | Error::LeaseLost { .. }
                | Error::NotOwner { .. }
                | Error::ClaimsHeld { .. }
        )
    }
}
