//! Agent assets: the skills and MCP server definitions a workspace serves to
//! the agent harnesses of its bd clients, one set per harness.
//!
//! A set lives in `<db dir>/agents/<harness>/`, next to the database as the
//! playbooks are (`.bd/agents/<harness>/`; under bd serve,
//! `<root>/<ws>/.bd/agents/<harness>/`), and a client places it in its
//! harness's own project locations:
//!
//! | harness   | on the server                  | in a client checkout                    |
//! |-----------|--------------------------------|-----------------------------------------|
//! | `claude`  | `skills/<name>/**`, `mcp.json` | `.claude/skills/`, `.mcp.json`          |
//! | `codex`   | `skills/<name>/**`, `mcp.toml` | `.agents/skills/`, `.codex/config.toml` |
//! | `copilot` | `skills/<name>/**`, `mcp.json` | `.github/skills/`, `.github/mcp.json`   |
//!
//! Each set is served as it is, to its own harness only: nothing is
//! translated between harnesses or shared by them, and a harness without a
//! set gets an empty one. The server only provides definitions: MCP servers
//! run on the client and authenticate there (`${VAR}` references, OAuth in
//! the harness), and bd never handles their credentials.
//!
//! Sets are read strictly ([`AgentSet::load`]): an MCP file holds MCP server
//! entries only (no settings, hooks or permissions); each skill is a
//! directory holding a [`SKILL_FILE`], named as [`check_skill_name`] allows;
//! file paths are portable and ASCII ([`check_skill_path`]); a symlink may
//! only lead to somewhere else inside the agents directory; files are UTF-8
//! text; and a set stays within the `MAX_*` limits. Hidden entries (names
//! starting with `.`) are ignored, and so is anything in the agents
//! directory besides the harness directories, except where a symlink in a
//! set leads (to share a file between sets, say). Errors name the file.
//!
//! Hashes are SHA-256, in lowercase hex: a skill file's over its bytes, an
//! MCP server entry's over the canonical JSON of its definition
//! ([`mcp_digest`]), so reformatting an MCP file changes no hash. A set's
//! revision is the hash of the canonical JSON of its [`Manifest`]'s
//! `skills` and `mcp_servers`.
//!
//! `bd serve` records each set's revision and appends an
//! [`AGENTS_CHANGED`] event when it changes ([`record_revisions`]).

mod changes;
mod mcp;
mod set;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub use changes::{AGENTS_CHANGED, AgentsChanged, record_revisions};
pub use mcp::{
    MAX_FIELD_NAME, McpServer, canonical_json, check_definition, check_field_name, check_server_name, mcp_digest,
    parse_mcp, toml_definition,
};
pub use set::{AgentSet, FileDigest, Manifest, McpDigest, SkillFile, check_skill_name, check_skill_path};

/// The directory next to the database that holds the sets, one per harness.
pub const AGENTS_DIR: &str = "agents";
/// The directory of a set that holds its skills, one directory each.
pub const SKILLS_DIR: &str = "skills";
/// The file every skill directory holds.
pub const SKILL_FILE: &str = "SKILL.md";

/// Most files in one set: skill files and the MCP file.
pub const MAX_SET_FILES: usize = 256;
/// Most directories in one set's skills, below the skill directories.
pub const MAX_SET_DIRS: usize = 256;
/// Largest file in a set.
pub const MAX_FILE_BYTES: usize = 512 << 10;
/// Most text in one set, all files together.
pub const MAX_SET_BYTES: usize = 8 << 20;
/// Most MCP server entries in one set.
pub const MAX_MCP_SERVERS: usize = 64;
/// Longest skill or MCP server name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// Longest path of a file within its skill, in bytes.
pub const MAX_PATH_BYTES: usize = 200;
/// Most components in the path of a file within its skill.
pub const MAX_PATH_DEPTH: usize = 8;

/// An agent harness a set is served to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Harness {
    /// Claude Code.
    Claude,
    /// OpenAI Codex.
    Codex,
    /// GitHub Copilot CLI.
    Copilot,
}

/// How a harness's MCP file is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpFormat {
    /// `{"mcpServers": {"<name>": {...}}}`.
    Json,
    /// `[mcp_servers.<name>]` tables.
    Toml,
}

impl Harness {
    pub const ALL: [Harness; 3] = [Harness::Claude, Harness::Codex, Harness::Copilot];

    /// Its name, which is also its set's directory.
    pub fn name(self) -> &'static str {
        match self {
            Harness::Claude => "claude",
            Harness::Codex => "codex",
            Harness::Copilot => "copilot",
        }
    }

    /// Its set's MCP file, in its set's directory.
    pub fn mcp_file(self) -> &'static str {
        match self.mcp_format() {
            McpFormat::Json => "mcp.json",
            McpFormat::Toml => "mcp.toml",
        }
    }

    pub fn mcp_format(self) -> McpFormat {
        match self {
            Harness::Claude | Harness::Copilot => McpFormat::Json,
            Harness::Codex => McpFormat::Toml,
        }
    }

    /// The key holding the MCP server entries, in its MCP file and in the
    /// client's ([`Harness::mcp_dest`]).
    pub fn mcp_key(self) -> &'static str {
        match self.mcp_format() {
            McpFormat::Json => "mcpServers",
            McpFormat::Toml => "mcp_servers",
        }
    }

    /// Where a client places the set's skills, relative to its project root
    /// (`/`-separated; see [`under`]).
    pub fn skills_dest(self) -> &'static str {
        match self {
            Harness::Claude => ".claude/skills",
            Harness::Codex => ".agents/skills",
            Harness::Copilot => ".github/skills",
        }
    }

    /// The file a client merges the set's MCP server entries into, relative
    /// to its project root (`/`-separated; see [`under`]).
    pub fn mcp_dest(self) -> &'static str {
        match self {
            Harness::Claude => ".mcp.json",
            Harness::Codex => ".codex/config.toml",
            Harness::Copilot => ".github/mcp.json",
        }
    }
}

impl std::fmt::Display for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Harness {
    type Err = Error;

    fn from_str(s: &str) -> Result<Harness> {
        Harness::ALL
            .into_iter()
            .find(|h| h.name() == s)
            .ok_or_else(|| Error::invalid(format!("unknown agent harness {s:?} (claude, codex or copilot)")))
    }
}

/// `rel`, a `/`-separated relative path, under `root`.
pub fn under(root: &Path, rel: &str) -> PathBuf {
    rel.split('/').filter(|c| !c.is_empty()).fold(root.to_path_buf(), |p, c| p.join(c))
}

/// SHA-256 of `bytes`, in lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of `text` with each CRLF line ending as LF, in lowercase hex;
/// `None` if it has no CRLF (it is then [`sha256_hex`] of `text`). Two texts
/// that differ only in LF and CRLF line endings have the same, as when git
/// (`core.autocrlf`) checks a text file out with CRLF ones on Windows.
pub fn lf_sha256(text: &str) -> Option<String> {
    text.contains("\r\n").then(|| sha256_hex(text.replace("\r\n", "\n").as_bytes()))
}

/// Check that `s` is a SHA-256 in lowercase hex, as [`sha256_hex`] gives it.
pub fn check_sha256(s: &str) -> Result<()> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Ok(());
    }
    let shown: String = s.chars().take(64).flat_map(char::escape_default).collect();
    let more = if s.chars().count() > 64 { "..." } else { "" };
    Err(invalid(format!("\"{shown}\"{more} is not a SHA-256 in lowercase hex")))
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::invalid(msg)
}

/// `e` as an error about `origin` (a file, an entry).
fn context(origin: &str, e: Error) -> Error {
    match e {
        Error::Invalid(m) => invalid(format!("{origin}: {m}")),
        e => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harnesses_have_their_own_files_and_destinations() {
        let rows: Vec<_> =
            Harness::ALL.iter().map(|h| (h.name(), h.mcp_file(), h.mcp_key(), h.skills_dest(), h.mcp_dest())).collect();
        assert_eq!(
            rows,
            [
                ("claude", "mcp.json", "mcpServers", ".claude/skills", ".mcp.json"),
                ("codex", "mcp.toml", "mcp_servers", ".agents/skills", ".codex/config.toml"),
                ("copilot", "mcp.json", "mcpServers", ".github/skills", ".github/mcp.json"),
            ]
        );
        for h in Harness::ALL {
            assert_eq!(h.name().parse::<Harness>().unwrap(), h);
            assert_eq!(serde_json::to_value(h).unwrap(), h.name());
        }
        assert!("Claude".parse::<Harness>().is_err());
        assert!("cursor".parse::<Harness>().unwrap_err().to_string().contains("claude, codex or copilot"));
    }

    #[test]
    fn texts_that_differ_only_in_line_endings_hash_alike() {
        assert_eq!(lf_sha256("a\nb\n"), None, "LF already");
        assert_eq!(lf_sha256("a\r\nb\n"), Some(sha256_hex(b"a\nb\n")));
        assert_eq!(lf_sha256("a\r\nb\r\n"), lf_sha256("a\r\nb\n"));
        // A CR that ends no line is text, and stays.
        assert_eq!(lf_sha256("a\r\r\n"), Some(sha256_hex(b"a\r\n")));
        assert_eq!(lf_sha256("a\rb"), None);
    }

    #[test]
    fn relative_paths_join_per_component() {
        let root = Path::new("root");
        assert_eq!(under(root, ".codex/config.toml"), root.join(".codex").join("config.toml"));
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
