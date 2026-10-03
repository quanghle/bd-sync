//! `.bd/agents.lock`: what `bd agents pull` placed in a checkout, so that
//! later pulls tell bd's own files and MCP server entries from the user's.
//!
//! ```json
//! {
//!   "version": 1,
//!   "harnesses": {
//!     "claude": {
//!       "revision": "<the server revision last pulled>",
//!       "skills": {
//!         ".claude/skills/deploy/SKILL.md": {"sha256": "<sha256>"},
//!         ".claude/skills/deploy/notes.md": {"sha256": "<sha256>", "lf_sha256": "<sha256>"},
//!         ".claude/skills/deploy/scripts/run.sh": {"sha256": "<sha256>", "executable": true},
//!         ".claude/skills/deploy/check.sh": {"sha256": "<sha256>", "executable": true, "executable_not_kept": true}
//!       },
//!       "mcp_servers": {
//!         "github": {"sha256": "<sha256>", "definition": {"command": "npx", "args": ["-y", "server-github"]}}
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Per harness, `skills` holds every skill file bd wrote or adopted (so
//! approved), by its `/`-separated path in the checkout, with the digests
//! of the bytes bd wrote, or found here when it adopted the file or changed
//! its executable bit (and `lf_sha256` for a text with CRLF line endings:
//! see [`FileDigest::lf_sha256`]), and `mcp_servers` every MCP server entry bd
//! wrote or adopted (so approved), with its definition as approved
//! (canonical JSON; codex: its table as JSON), to show what a newer version
//! changes. Only applied and approved state is recorded: skill and MCP
//! changes that wait for approval are worked out from the server each time.
//!
//! `executable_not_kept` marks an executable file whose executable bit the
//! file system did not keep when bd set it (vfat, an SMB mount whose fmask
//! clears it): with the text recorded, it counts as up to date without the
//! bit, rather than as a mode to fix on every pull. bd sets the bit again
//! when the server's set changes, or with `bd agents pull --force`, and
//! drops the mark once the file has it.

use std::collections::BTreeMap;

use bd_core::agents::{
    FileDigest, Harness, check_server_name, check_sha256, check_skill_name, check_skill_path, mcp_digest,
};
use bd_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The lock file, in the checkout's `.bd` directory.
pub const LOCK_FILE: &str = "agents.lock";
/// The lock file's format version.
pub const VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockFile {
    pub version: u32,
    pub harnesses: BTreeMap<Harness, Applied>,
}

impl Default for LockFile {
    fn default() -> LockFile {
        LockFile { version: VERSION, harnesses: BTreeMap::new() }
    }
}

/// What a checkout holds of one harness's set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    /// The server revision last pulled; empty if none was, as when `bd
    /// agents approve` wrote skills or MCP entries first.
    pub revision: String,
    /// The skill files bd wrote or adopted, by checkout-relative path.
    #[serde(default)]
    pub skills: BTreeMap<String, OwnedFile>,
    /// The MCP server entries bd wrote or adopted, by name.
    #[serde(default)]
    pub mcp_servers: BTreeMap<String, OwnedMcp>,
}

/// A skill file as bd wrote or adopted it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedFile {
    pub sha256: String,
    /// [`bd_core::agents::lf_sha256`] of the text recorded, if it has CRLF line endings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lf_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
    /// The file system did not keep the executable bit bd set on it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable_not_kept: bool,
}

impl OwnedFile {
    /// A file with the digest `digest`, as bd placed or found it: the
    /// server's file once written, else the bytes here (see `plan_skills`);
    /// `not_kept` if the file system did not keep its executable bit (only
    /// an executable file's counts).
    pub fn of(digest: &FileDigest, not_kept: bool) -> OwnedFile {
        OwnedFile {
            sha256: digest.sha256.clone(),
            lf_sha256: digest.lf_sha256.clone(),
            executable: digest.executable,
            executable_not_kept: digest.executable && not_kept,
        }
    }

    /// Whether the server's file `digest` has the text recorded, line endings aside.
    pub fn same_text(&self, digest: &FileDigest) -> bool {
        self.sha256 == digest.sha256
            || self.lf_sha256.as_ref().unwrap_or(&self.sha256) == digest.lf_sha256.as_ref().unwrap_or(&digest.sha256)
    }
}

/// An MCP server entry as bd wrote or adopted it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedMcp {
    /// [`mcp_digest`] of `definition`.
    pub sha256: String,
    pub definition: Value,
}

impl LockFile {
    /// Check a lock file read from disk: its version, and every path and
    /// name in it, as bd would have written them. Paths matter most: a pull
    /// deletes recorded files the server no longer serves.
    pub fn check(&self) -> Result<()> {
        if self.version != VERSION {
            return Err(Error::invalid(format!("format version {}, not {VERSION}", self.version)));
        }
        for (h, applied) in &self.harnesses {
            for (path, file) in &applied.skills {
                if skill_of(*h, path).is_none() {
                    return Err(Error::invalid(format!(
                        "{h}: {path:?} is not the path of a skill file in {}/",
                        h.skills_dest()
                    )));
                }
                check_sha256(&file.sha256).map_err(|e| Error::invalid(format!("{h}: {path}: {e}")))?;
                if let Some(lf) = &file.lf_sha256 {
                    check_sha256(lf).map_err(|e| Error::invalid(format!("{h}: {path}: lf_sha256: {e}")))?;
                }
                if file.executable_not_kept && !file.executable {
                    return Err(Error::invalid(format!("{h}: {path}: executable_not_kept, and not executable")));
                }
            }
            for (name, entry) in &applied.mcp_servers {
                check_server_name(name).map_err(|e| Error::invalid(format!("{h}: {e}")))?;
                if mcp_digest(&entry.definition) != entry.sha256 {
                    return Err(Error::invalid(format!(
                        "{h}: MCP server {name}: its definition does not match its sha256"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The checkout-relative path of file `rel` of skill `name` of `harness`.
pub fn skill_path(harness: Harness, name: &str, rel: &str) -> String {
    format!("{}/{name}/{rel}", harness.skills_dest())
}

/// The skill and the path within it of `path`, the checkout-relative path
/// of a skill file of `harness`; `None` if `path` is not one.
pub fn skill_of(harness: Harness, path: &str) -> Option<(&str, &str)> {
    let (name, rel) = path.strip_prefix(harness.skills_dest())?.strip_prefix('/')?.split_once('/')?;
    (check_skill_name(name).is_ok() && check_skill_path(rel).is_ok()).then_some((name, rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn skill_paths_split_back_into_skill_and_path() {
        let path = skill_path(Harness::Codex, "deploy", "scripts/run.sh");
        assert_eq!(path, ".agents/skills/deploy/scripts/run.sh");
        assert_eq!(skill_of(Harness::Codex, &path), Some(("deploy", "scripts/run.sh")));
        for bad in [
            ".claude/skills/deploy/SKILL.md",
            ".agents/skills/deploy",
            ".agents/skills/../etc/passwd",
            ".agents/skills/deploy/../../x",
            ".agents/skills/Deploy/SKILL.md",
            ".agents/skillsx/deploy/SKILL.md",
            "/etc/passwd",
        ] {
            assert_eq!(skill_of(Harness::Codex, bad), None, "{bad}");
        }
    }

    #[test]
    fn lock_files_are_checked_before_use() {
        let definition = json!({"command": "npx"});
        let good = json!({
            "version": 1,
            "harnesses": {"claude": {
                "revision": "r",
                "skills": {
                    ".claude/skills/deploy/SKILL.md": {"sha256": SHA},
                    ".claude/skills/deploy/notes.md": {"sha256": SHA, "lf_sha256": SHA},
                    ".claude/skills/deploy/run.sh": {"sha256": SHA, "executable": true, "executable_not_kept": true}
                },
                "mcp_servers": {"github": {"sha256": mcp_digest(&definition), "definition": definition}}
            }}
        });
        let lock: LockFile = serde_json::from_value(good.clone()).unwrap();
        lock.check().unwrap();
        assert_eq!(serde_json::to_value(&lock).unwrap(), good, "written as read");

        let mut bad = good.clone();
        bad["harnesses"]["claude"]["skills"] = json!({"../../.bashrc": {"sha256": SHA}});
        let e = serde_json::from_value::<LockFile>(bad).unwrap().check().unwrap_err().to_string();
        assert!(e.contains("not the path of a skill file"), "{e}");
        let mut bad = good.clone();
        bad["harnesses"]["claude"]["skills"] = json!({".claude/skills/deploy/SKILL.md": {"sha256": "x"}});
        assert!(serde_json::from_value::<LockFile>(bad).unwrap().check().is_err());
        let mut bad = good.clone();
        bad["harnesses"]["claude"]["skills"][".claude/skills/deploy/notes.md"]["lf_sha256"] = json!("x");
        let e = serde_json::from_value::<LockFile>(bad).unwrap().check().unwrap_err().to_string();
        assert!(e.contains("lf_sha256: \"x\" is not a SHA-256"), "{e}");
        let mut bad = good.clone();
        bad["harnesses"]["claude"]["skills"][".claude/skills/deploy/run.sh"]["executable"] = json!(false);
        let e = serde_json::from_value::<LockFile>(bad).unwrap().check().unwrap_err().to_string();
        assert!(e.contains("not executable"), "{e}");
        let mut bad = good.clone();
        bad["harnesses"]["claude"]["mcp_servers"]["github"]["definition"] = json!({"command": "uvx"});
        let e = serde_json::from_value::<LockFile>(bad).unwrap().check().unwrap_err().to_string();
        assert!(e.contains("does not match its sha256"), "{e}");
        let mut bad = good.clone();
        bad["version"] = json!(2);
        assert!(serde_json::from_value::<LockFile>(bad).unwrap().check().is_err());
        let mut bad = good;
        bad["harnesses"]["claude"]["pending"] = json!({});
        assert!(serde_json::from_value::<LockFile>(bad).is_err(), "unknown fields are refused");
    }
}
