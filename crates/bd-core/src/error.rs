use crate::model::Status;

pub type Result<T, E = Error> = std::result::Result<T, E>;

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

    Busy(String),

    /// Another bd process holds a lock file (not the database) past the
    /// wait: the message names the file and says what to do.
    Locked(String),

    SchemaTooNew {
        found: i64,
        supported: i64,
    },

    NoWorkspace(String),

    /// A bd server rejected the access token, or the token's role,
    /// workspaces or actor do not allow the operation.
    Unauthorized(String),

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
            | Error::AnswerLost(msg) => f.write_str(msg),
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
            Error::Busy(msg) => write!(f, "database is busy: {msg}"),
            Error::SchemaTooNew { found, supported } => {
                write!(f, "database schema v{found} is newer than this binary supports (v{supported}); upgrade bd")
            }
            Error::Sqlite(e) => write!(f, "sqlite: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            Error::Io(e) => Some(e),
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
