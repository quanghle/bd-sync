//! The wire format between `bd` clients and `bd serve`.
//!
//! One endpoint, `POST /w/<workspace>/v1/exec`, runs one bd command line in
//! the workspace and answers with what the command printed and its exit code.
//! Transport and access failures answer with a non-200 status and an
//! [`ErrorBody`], shaped like the CLI's `--json` errors.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Request body of `POST /w/<workspace>/v1/exec`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command line after the program name, exactly as typed.
    pub argv: Vec<String>,
    /// Actor named by the client's environment (`$BD_ACTOR`, `$BEADS_ACTOR`);
    /// an `--actor` flag travels in `argv`. Must be allowed by the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Idempotency key: every retry of one invocation sends the same id, and
    /// a write is applied once however many attempts reach the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The client's stdin, for commands that read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    /// Input files named on the command line, keyed by the path as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// How the client names the workspace (its URL), shown by `prime` and `info`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Response body of a 200 from `exec`: the command ran (it may have failed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    /// Output files for the client to write, keyed by the path as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// This is the stored response of an earlier attempt with the same request id.
    #[serde(default)]
    pub replayed: bool,
}

/// Body of every non-200 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Same codes as the CLI's JSON errors (`unauthorized`, `not_found`, ...).
    pub code: String,
    pub message: String,
    pub exit_code: i32,
}

/// Workspace names: a letter or digit, then letters, digits, `.`, `_`, `-`
/// (at most 100). They name a directory under the server root.
pub fn valid_workspace_name(name: &str) -> bool {
    name.len() <= 100
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_names_cannot_escape_the_root() {
        for ok in ["bd-sync", "a", "proj_1.v2"] {
            assert!(valid_workspace_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "-x", "über", &"x".repeat(101)] {
            assert!(!valid_workspace_name(bad), "{bad}");
        }
    }
}
