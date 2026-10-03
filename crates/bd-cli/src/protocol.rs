//! The wire format between `bd` clients and `bd serve` (protocol 2).
//!
//! One endpoint, `POST /w/<workspace>/v2/exec`, runs one bd command line in
//! the workspace; the request body is an [`ExecRequest`]. A 200 answer
//! (`Content-Type: application/x-ndjson`) carries the command's output as a
//! stream of JSON [`Frame`]s, one per line, in the order the command wrote
//! them, and always ends with an exit frame:
//!
//! ```text
//! {"file":{"path":"snap.jsonl","data":"{\"_type\":\"header\",...}\n"}}
//! {"stdout":"✓ Exported 3 issues, ...\n"}
//! {"exit":{"exit_code":0,"stderr":"","replayed":false}}
//! ```
//!
//! Blank lines are keep-alives. A stream that ends without an exit frame was
//! cut off: the command's outcome is unknown. Small answers arrive whole
//! (with a `Content-Length`) once the command finishes; larger ones are sent
//! while it runs, so neither side holds a whole export in memory. An event
//! listing (`events`) also carries a cursor frame, `{"cursor":1234}`, before
//! its exit frame: the `--since` value that continues after it, past events
//! its filters skipped.
//!
//! `events --since N --wait DURATION` is a long poll: the server waits,
//! without holding a command slot, until an event matching the filters
//! follows `N` (or up to its `--max-wait`, 25 s by default), then answers like
//! `events --since N`. Remote `events --follow` asks this way in a loop.
//!
//! Failures before the command runs (transport, access) answer with a
//! non-200 status and an [`ErrorBody`], shaped like the CLI's `--json`
//! errors. Every answer carries the [`PROTOCOL_HEADER`], which tells bd
//! serve's own answers apart from a proxy's.
//!
//! GitHub sign-in (`bd remote login --github`, see `oauth.rs`) has two
//! endpoints of its own on the server, outside any workspace and without a
//! token: `POST <server>/v2/auth/github/device` ([`SignInStart`] ->
//! [`SignInCode`]) and `POST <server>/v2/auth/github/token`, polled
//! ([`SignInPoll`] -> [`SignInAnswer`]). Their answers are JSON, and their
//! failures [`ErrorBody`]s. `POST <server>/v2/auth/revoke`, sent with a
//! token as its bearer token, revokes that token if it came from GitHub
//! sign-in ([`RevokeAnswer`]; `bd remote logout`); sent with a sign-in's
//! refresh token (and `{"request_id"}` of a refresh whose answer was lost),
//! it revokes the sign-in. `POST
//! <server>/v2/auth/refresh`, sent with a sign-in's refresh token as its
//! bearer token ([`RefreshRequest`] -> [`Issued`]), gives the sign-in new
//! access and refresh tokens; the refresh token sent is spent.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The protocol version in the endpoint path (`/v2/exec`) and the [`PROTOCOL_HEADER`].
pub const PROTOCOL: u32 = 2;
/// Response header naming the server's protocol version.
pub const PROTOCOL_HEADER: &str = "bd-protocol";
/// Content type of a 200 answer: newline-delimited [`Frame`]s.
pub const FRAMES_CONTENT_TYPE: &str = "application/x-ndjson";

/// Request body of `POST /w/<workspace>/v2/exec`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command line after the program name, exactly as typed, except
    /// that a client running a playbook from its checkout puts
    /// `--playbook-bundle <file>` in front and sends that file.
    pub argv: Vec<String>,
    /// Actor named by the client's environment (`$BD_ACTOR`, `$BEADS_ACTOR`);
    /// an `--actor` flag travels in `argv`. Must be allowed by the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The client's agent session (`$BD_SESSION`, or one its agent harness
    /// names), sent when it names no actor: the request then runs as
    /// `<token actor>/<session>`. Servers that predate it ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
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
    /// A model's tool call (`bd mcp`): it runs with the actor's own rights
    /// only, never the token's admin or human ones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tool_call: bool,
}

/// One line of a 200 answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frame<'a> {
    /// The next text the command printed on stdout.
    Stdout(Cow<'a, str>),
    /// The next part of an output file named on the command line (`export
    /// -o`), keyed by the path as given; the client writes it locally.
    File { path: Cow<'a, str>, data: Cow<'a, str> },
    /// Where an event listing (`bd events`) ends: the `--since` value that
    /// continues after it. Sent before the exit frame of such answers only.
    Cursor(i64),
    /// The command finished: always the last frame.
    Exit(Exit),
}

/// How the command ended.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exit {
    pub exit_code: i32,
    /// What the command printed on stderr (errors and warnings; long output is cut).
    #[serde(default)]
    pub stderr: String,
    /// The answer of an earlier attempt with the same request id, replayed.
    #[serde(default)]
    pub replayed: bool,
}

/// A whole answer, gathered from its frames: what `bd serve` stores to
/// replay a write's answer to retries, and what the client collects for its
/// own small requests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    /// Output files, keyed by the path as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// The cursor frame of an event listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<i64>,
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

/// Body of `POST <server>/v2/auth/github/device`: start a GitHub sign-in.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignInStart {
    /// The workspace the client signs in for: it must exist on the server.
    pub workspace: String,
}

/// Answer of `POST <server>/v2/auth/github/device`: the code a person
/// enters at GitHub, and how often to ask whether they did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignInCode {
    /// Sent back with each poll: whoever holds it gets the sign-in's token.
    pub device_code: String,
    /// The one-time code to enter at `verification_uri`.
    pub user_code: String,
    pub verification_uri: String,
    /// Seconds until the codes expire.
    pub expires_in: u64,
    /// Seconds to wait between polls.
    pub interval: u64,
}

/// Body of `POST <server>/v2/auth/github/token`: was the code entered yet?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignInPoll {
    pub device_code: String,
    /// The workspace the client signs in for: the token must allow it.
    pub workspace: String,
}

/// Answer of `POST <server>/v2/auth/github/token`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignInAnswer {
    /// Not entered yet: ask again after the same interval.
    Pending,
    /// Not entered yet, and asked too often: ask again after a longer
    /// interval, at least `interval` seconds (0 when GitHub gave none).
    SlowDown { interval: u64 },
    /// Entered, and the account may sign in: its new access token.
    Issued(Box<Issued>),
}

/// Answer of `POST <server>/v2/auth/revoke`, sent with the token to revoke as
/// its bearer token. A token unknown to the server (revoked before, say) is
/// answered 401, like any request with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAnswer {
    /// The token's name.
    pub name: String,
    /// Revoked now: it came from GitHub sign-in. A token the server's admin
    /// created is kept (it may serve elsewhere too): only the admin revokes it.
    pub revoked: bool,
}

/// Body of `POST <server>/v2/auth/refresh`, sent with the refresh token as
/// its bearer token.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// Every retry of one refresh sends the same id: the server answers it
    /// again with the tokens it issued, where another request with the same
    /// refresh token revokes the sign-in.
    pub request_id: String,
}

/// An access token issued by GitHub sign-in, or by a refresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    /// The secret: saved by the client, never shown.
    pub token: String,
    /// The refresh secret, where the server refreshes tokens: saved by the
    /// client, never shown, and sent only to `/v2/auth/refresh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub name: String,
    pub actor: String,
    pub role: String,
    pub kind: String,
    pub workspaces: Vec<String>,
    /// The most issues its actor and sub-actors may hold, claimed or reserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<u32>,
    pub expires_at: String,
    /// Seconds until it expires: what the client plans its refresh by, on its own clock.
    #[serde(default)]
    pub expires_in: u64,
    /// Until when it may be refreshed, as of now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshable_until: Option<String>,
    /// The GitHub login that signed in.
    pub login: String,
    /// What let the account in: `GitHub user alice`, `member of acme`, `member of team acme/bd`.
    pub via: String,
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
