//! Access tokens as clients and commands see them: what a token may do
//! (`Role`, `Kind`), how its summary reads, and the random hex its secrets
//! (and request ids) are made of. The tokens themselves live in the server's
//! `server.db`.

use bd_core::{Error, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// What a token may do. Each role includes the ones before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only commands; the database connection is query-only.
    Read,
    /// Every command a local user runs, except admin ones.
    Write,
    /// Also `config set/unset`, `import`, `events prune`, `doctor`.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Write => "write",
            Role::Admin => "admin",
        }
    }
}

/// Who holds a token, independent of its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A person: may also resolve human gates and move work past them.
    Human,
    /// A program (the default of `bd serve token create`).
    Agent,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Human => "human",
            Kind::Agent => "agent",
        }
    }
}

/// How messages name the account `login` of `provider`.
pub fn who(provider: &str, login: &str) -> String {
    match provider {
        "github" => format!("GitHub user {login}"),
        provider => format!("{provider} account {login}"),
    }
}

pub fn workspaces_text(workspaces: &[String]) -> String {
    if workspaces.iter().any(|w| w == "*") { "all".to_string() } else { workspaces.join(",") }
}

/// A token as one line, from its `Token::summary` (maybe a server's):
/// `role write, kind human, workspaces all; token <name>, expires <time>,
/// GitHub user <login>`.
pub fn access_line(summary: &serde_json::Value) -> String {
    let text = |k: &str| summary[k].as_str().unwrap_or("?").to_string();
    let workspaces: Vec<String> = summary["workspaces"]
        .as_array()
        .map(|list| list.iter().filter_map(|w| w.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut line = format!(
        "role {}, kind {}, workspaces {}; token {}",
        text("role"),
        text("kind"),
        workspaces_text(&workspaces),
        text("name")
    );
    if let Some(n) = summary["max_claims"].as_u64() {
        line.push_str(&format!(", at most {n} claims"));
    }
    if let Some(at) = summary["expires_at"].as_str() {
        line.push_str(&format!(", expires {at}"));
    }
    if let Some(at) = summary["refreshable_until"].as_str() {
        line.push_str(&format!(", refreshed until {at}"));
    }
    if let Some(login) = summary["account"]["login"].as_str() {
        line.push_str(&format!(", {}", who(summary["account"]["provider"].as_str().unwrap_or_default(), login)));
    }
    line
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex of `n` random bytes from the operating system.
pub fn random_hex(n: usize) -> Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(hex(&buf))
}
