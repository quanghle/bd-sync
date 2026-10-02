//! A checkout's MCP file, in its harness's own format.
//!
//! `.mcp.json` (claude) and `.github/mcp.json` (copilot) hold
//! `{"mcpServers": {...}}`: bd keeps every other key and server, and writes
//! the file pretty-printed (keys sorted, a final newline) when it changes an
//! entry. `.codex/config.toml` holds Codex's own settings besides its
//! `[mcp_servers.<name>]` tables: bd inserts, replaces or removes those
//! tables only, and keeps everything else as it is, comments and formatting
//! included. A file bd cannot read in its format, a JSON file holding
//! servers outside `mcpServers` (Copilot's bare form), and a symlink (whose
//! write, a temp file renamed into place, would replace the link) are never
//! written; nor is a file whose content would not change.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::Permissions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use bd_core::agents::{Harness, McpFormat, McpServer, canonical_json, mcp_digest, toml_definition, under};
use bd_core::{Error, Result};
use serde_json::{Map, Value};
use toml_edit::{DocumentMut, Item};

use super::checkout::write_atomically;

/// A harness's MCP file in a checkout, as read.
pub struct McpFile {
    pub harness: Harness,
    path: PathBuf,
    /// The file's MCP server entries, by name: their definitions as JSON
    /// (codex: each table as JSON, `null` for one without a JSON form).
    pub entries: Entries,
    /// Why bd can use nothing in the file, if so: its entries are unknown.
    pub unusable: Option<String>,
    /// Why bd does not write the file, if so; its entries are read.
    pub read_only: Option<String>,
    doc: Doc,
    perms: Option<Permissions>,
}

enum Doc {
    Missing,
    Unusable,
    Json(Map<String, Value>),
    Toml { text: String, doc: DocumentMut },
}

/// A change to an MCP file.
#[derive(Clone, Copy, Debug)]
pub enum Change<'a> {
    /// Add or replace entry `name` with the server's.
    Put(&'a str, &'a McpServer),
    Remove(&'a str),
}

fn path_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

impl McpFile {
    /// `harness`'s MCP file in the checkout at `root`.
    pub fn read(root: &Path, harness: Harness) -> Result<McpFile> {
        let mut file = McpFile {
            harness,
            path: under(root, harness.mcp_dest()),
            entries: BTreeMap::new(),
            unusable: None,
            read_only: None,
            doc: Doc::Missing,
            perms: None,
        };
        match std::fs::symlink_metadata(&file.path) {
            Ok(m) if m.file_type().is_symlink() => {
                file.read_only = Some(
                    "a symlink, which bd does not write through: its write (a temp file renamed into place) would \
                     replace the link"
                        .into(),
                );
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(file),
            Err(e) => return Err(path_error(&file.path, e)),
        }
        let meta = match std::fs::metadata(&file.path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(file.unusable("a symlink to nothing".into())),
            Err(e) => return Err(path_error(&file.path, e)),
        };
        if !meta.is_file() {
            return Ok(file.unusable("not a regular file".into()));
        }
        file.perms = Some(meta.permissions());
        let text = match std::fs::read_to_string(&file.path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::InvalidData => return Ok(file.unusable("not UTF-8 text".into())),
            Err(e) => return Err(path_error(&file.path, e)),
        };
        let key = harness.mcp_key();
        match harness.mcp_format() {
            McpFormat::Json => match parse_json(&text, key) {
                Ok((map, entries)) => (file.doc, file.entries) = (Doc::Json(map), entries),
                Err(why) => return Ok(file.unusable(why)),
            },
            McpFormat::Toml => match parse_toml(&text, key) {
                Ok((doc, entries, read_only)) => {
                    (file.doc, file.entries) = (Doc::Toml { text, doc }, entries);
                    file.read_only = file.read_only.or(read_only);
                }
                Err(why) => return Ok(file.unusable(why)),
            },
        }
        Ok(file)
    }

    fn unusable(mut self, why: String) -> McpFile {
        self.unusable = Some(why);
        self.doc = Doc::Unusable;
        self
    }

    /// Make `changes` to the file and write it at once (a temp file, with
    /// the file's permissions, renamed over it), creating it if needed. A
    /// file the changes leave as it was is not written. Returns whether the
    /// file was written.
    pub fn apply(&mut self, changes: &[Change<'_>]) -> Result<bool> {
        let rel = self.harness.mcp_dest();
        if let Some(why) = self.unusable.as_ref().or(self.read_only.as_ref()) {
            return Err(Error::Refused(format!("{rel}: {why}")));
        }
        let key = self.harness.mcp_key();
        let (text, doc) = match self.harness.mcp_format() {
            McpFormat::Json => {
                let before = match &self.doc {
                    Doc::Json(map) => map.clone(),
                    _ => Map::new(),
                };
                let mut map = before.clone();
                for change in changes {
                    match *change {
                        Change::Put(name, server) => {
                            let servers = map.entry(key).or_insert_with(|| Value::Object(Map::new()));
                            let Value::Object(servers) = servers else { unreachable!("checked when read") };
                            servers.insert(name.to_string(), server.definition.clone());
                        }
                        Change::Remove(name) => {
                            if let Some(Value::Object(servers)) = map.get_mut(key) {
                                servers.remove(name);
                            }
                        }
                    }
                }
                if map == before {
                    return Ok(false);
                }
                (format!("{}\n", serde_json::to_string_pretty(&map)?), Doc::Json(map))
            }
            McpFormat::Toml => {
                let (before, mut doc) = match &self.doc {
                    Doc::Toml { text, doc } => (text.clone(), doc.clone()),
                    _ => (String::new(), DocumentMut::new()),
                };
                for change in changes {
                    match *change {
                        // The same definition, written otherwise: left as it is.
                        Change::Put(name, server)
                            if self.entries.get(name).map(mcp_digest).as_ref() == Some(&server.sha256) => {}
                        Change::Put(name, server) => toml_put(&mut doc, name, server)?,
                        Change::Remove(name) => {
                            if let Some(servers) = doc.as_table_mut().get_mut(key).and_then(Item::as_table_mut) {
                                servers.remove(name);
                            }
                        }
                    }
                }
                let after = doc.to_string();
                if after == before {
                    return Ok(false);
                }
                check_toml_edit(&before, &after, changes).map_err(|e| {
                    Error::invalid(format!("{rel}: bd could not edit it safely ({e}); edit its MCP servers by hand"))
                })?;
                (after.clone(), Doc::Toml { text: after, doc })
            }
        };
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| path_error(dir, e))?;
        }
        let perms = self.perms.clone();
        write_atomically(&self.path, text.as_bytes(), true, |f| match perms {
            Some(p) => f.set_permissions(p),
            None => Ok(()),
        })?;
        self.doc = doc;
        for change in changes {
            match *change {
                Change::Put(name, server) => self.entries.insert(name.to_string(), server.definition.clone()),
                Change::Remove(name) => self.entries.remove(name),
            };
        }
        Ok(true)
    }
}

/// An MCP file's entries, by name, as JSON.
type Entries = BTreeMap<String, Value>;

/// A JSON MCP file's top-level object and its entries, or why bd cannot use it.
fn parse_json(text: &str, key: &str) -> std::result::Result<(Map<String, Value>, Entries), String> {
    let shape = format!("bd edits only the {{\"{key}\": {{\"<name>\": {{...}}}}}} form");
    let value: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    let Value::Object(map) = value else { return Err(format!("not a JSON object; {shape}")) };
    let entries = match map.get(key) {
        Some(Value::Object(servers)) => servers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(_) => return Err(format!("{key} is not an object of MCP servers; {shape}")),
        None if map.values().any(looks_like_server) => {
            return Err(format!("holds MCP servers at its top level, not under {key}; {shape}"));
        }
        None => BTreeMap::new(),
    };
    Ok((map, entries))
}

fn looks_like_server(v: &Value) -> bool {
    ["command", "url"].iter().any(|f| v.get(f).is_some_and(Value::is_string))
}

/// A TOML MCP file, its entries, and why bd does not write it (if so); or
/// why bd cannot use it.
fn parse_toml(text: &str, key: &str) -> std::result::Result<(DocumentMut, Entries, Option<String>), String> {
    let doc: DocumentMut = text.parse().map_err(|e| format!("not valid TOML ({})", one_line(&e)))?;
    let table: toml::Table = toml::from_str(text).map_err(|e| format!("not valid TOML ({})", one_line(&e)))?;
    let entries = match table.get(key) {
        None => BTreeMap::new(),
        Some(toml::Value::Table(servers)) => {
            servers.iter().map(|(k, v)| (k.clone(), toml_definition(v).unwrap_or(Value::Null))).collect()
        }
        Some(_) => return Err(format!("{key} is not a table of MCP servers")),
    };
    let read_only = match doc.get(key) {
        None | Some(Item::Table(_)) => None,
        Some(_) => Some(format!("{key} is written inline, and bd edits only [{key}.<name>] tables")),
    };
    Ok((doc, entries, read_only))
}

/// A parse error on one line: its location and message, without the
/// excerpt of the file.
fn one_line(e: &dyn std::fmt::Display) -> String {
    let text = e.to_string();
    let excerpt = |l: &str| l.starts_with('|') || l.split_once(" | ").is_some_and(|(n, _)| n.parse::<u64>().is_ok());
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !excerpt(l)).collect();
    lines.join(": ")
}

/// Put the server's `[mcp_servers.<name>]` table into `doc`: in place of
/// the entry it replaces (its place and the comments before it), else after
/// the other MCP servers.
fn toml_put(doc: &mut DocumentMut, name: &str, server: &McpServer) -> Result<()> {
    let key = Harness::Codex.mcp_key();
    let bad = |why: String| Error::invalid(format!("MCP server {name}: {why}"));
    let text = server.toml.as_deref().ok_or_else(|| bad("no TOML table".into()))?;
    let source: DocumentMut = text.parse().map_err(|e| bad(one_line(&e)))?;
    let mut item = source.get(key).and_then(|s| s.get(name)).cloned().ok_or_else(|| bad("no TOML table".into()))?;
    forget_positions(&mut item);
    let root = doc.as_table_mut();
    if !root.contains_key(key) {
        let mut servers = toml_edit::Table::new();
        servers.set_implicit(true);
        root.insert(key, Item::Table(servers));
    }
    let servers = root.get_mut(key).and_then(Item::as_table_mut).ok_or_else(|| bad(format!("{key} is not a table")))?;
    let old = servers.get(name).and_then(Item::as_table).map(|t| (t.position(), t.decor().clone()));
    if let Some(table) = item.as_table_mut() {
        match old {
            Some((position, decor)) => {
                table.set_position(position);
                *table.decor_mut() = decor;
            }
            None => table.decor_mut().clear(),
        }
    }
    servers.insert(name, item);
    Ok(())
}

/// Tables parsed from another document carry their places in it: drop them.
fn forget_positions(item: &mut Item) {
    let tables: Vec<&mut toml_edit::Table> = match item {
        Item::Table(t) => vec![t],
        Item::ArrayOfTables(a) => a.iter_mut().collect(),
        _ => return,
    };
    for table in tables {
        table.set_position(None);
        for (_, value) in table.iter_mut() {
            forget_positions(value);
        }
    }
}

/// Check that the TOML `after` is `before` with `changes` made, and with
/// every other setting and MCP server as it was.
fn check_toml_edit(before: &str, after: &str, changes: &[Change<'_>]) -> Result<()> {
    let key = Harness::Codex.mcp_key();
    let parse = |text: &str| toml::from_str::<toml::Table>(text).map_err(|e| Error::invalid(one_line(&e)));
    let (mut want, mut got) = (parse(before)?, parse(after)?);
    let servers = want.entry(key).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let toml::Value::Table(servers) = servers else { return Err(Error::invalid(format!("{key} is not a table"))) };
    for change in changes {
        match *change {
            Change::Put(name, server) => {
                let mut table = parse(server.toml.as_deref().unwrap_or_default())?;
                let entry = match table.remove(key) {
                    Some(toml::Value::Table(mut t)) => t.remove(name),
                    _ => None,
                };
                servers.insert(name.to_string(), entry.ok_or_else(|| Error::invalid("no TOML table"))?);
            }
            Change::Remove(name) => {
                servers.remove(name);
            }
        }
    }
    for t in [&mut want, &mut got] {
        if t.get(key).and_then(toml::Value::as_table).is_some_and(toml::Table::is_empty) {
            t.remove(key);
        }
    }
    if want != got {
        return Err(Error::invalid("the result differs beyond the MCP servers changed"));
    }
    Ok(())
}

/// The environment variables MCP server definition `def` of `harness`
/// takes values from, added to `names`. Claude Code and Copilot expand
/// `${VAR}` and `$VAR` in `command`, `args`, `env`, `url` and `headers`
/// (`${VAR:-default}` has a default, so it is left out); Codex reads the
/// variables `env_vars` names (except those with `source = "remote"`),
/// `bearer_token_env_var`, and the values of `env_http_headers`.
pub fn env_refs(harness: Harness, def: &Value, names: &mut BTreeSet<String>) {
    let strings = |v: Option<&Value>| -> Vec<String> {
        match v {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(String::from).collect(),
            Some(Value::Object(map)) => map.values().filter_map(Value::as_str).map(String::from).collect(),
            _ => Vec::new(),
        }
    };
    match harness.mcp_format() {
        McpFormat::Json => {
            for field in ["command", "args", "env", "url", "headers"] {
                for s in strings(def.get(field)) {
                    expanded_vars(&s, names);
                }
            }
        }
        McpFormat::Toml => {
            for var in def.get("env_vars").and_then(Value::as_array).into_iter().flatten() {
                let name = match var {
                    Value::String(name) => Some(name.as_str()),
                    Value::Object(o) if o.get("source").and_then(Value::as_str) != Some("remote") => {
                        o.get("name").and_then(Value::as_str)
                    }
                    _ => None,
                };
                names.extend(name.filter(|n| is_var_name(n)).map(String::from));
            }
            let named =
                strings(def.get("bearer_token_env_var")).into_iter().chain(strings(def.get("env_http_headers")));
            names.extend(named.filter(|n| is_var_name(n)));
        }
    }
}

/// The `${VAR}` and `$VAR` references in `s`, without those with a
/// default (`${VAR:-default}`).
fn expanded_vars(s: &str, names: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        rest = &rest[i + 1..];
        if let Some(braced) = rest.strip_prefix('{') {
            let Some(end) = braced.find('}') else { return };
            let inner = &braced[..end];
            if is_var_name(inner) {
                names.insert(inner.to_string());
            }
            rest = &braced[end + 1..];
        } else {
            let len = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
            if is_var_name(&rest[..len]) {
                names.insert(rest[..len].to_string());
            }
            rest = &rest[len..];
        }
    }
}

fn is_var_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The top-level fields of an MCP server definition that differ between
/// `old` and `new`, added or removed ones included, sorted.
pub fn changed_fields(old: &Value, new: &Value) -> Vec<String> {
    let none = Map::new();
    let (old, new) = (old.as_object().unwrap_or(&none), new.as_object().unwrap_or(&none));
    let fields: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    fields.into_iter().filter(|f| old.get(*f).map(canonical_json) != new.get(*f).map(canonical_json)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bd_core::agents::parse_mcp;
    use serde_json::json;

    fn server(harness: Harness, text: &str, name: &str) -> McpServer {
        parse_mcp(harness, text, "server").unwrap().remove(name).unwrap()
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = under(root, rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn json_files_keep_everything_else() {
        let root = tempfile::tempdir().unwrap();
        let github =
            server(Harness::Claude, r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y"]}}}"#, "github");

        let mut file = McpFile::read(root.path(), Harness::Claude).unwrap();
        assert!(file.entries.is_empty() && file.unusable.is_none());
        assert!(!file.apply(&[Change::Remove("github")]).unwrap(), "nothing to remove: nothing written");
        assert!(!root.path().join(".mcp.json").exists());
        assert!(file.apply(&[Change::Put("github", &github)]).unwrap());
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(root.path().join(".mcp.json")).unwrap()).unwrap();
        assert_eq!(written, json!({"mcpServers": {"github": {"command": "npx", "args": ["-y"]}}}));

        let mine = r#"{"theirs": [1, 2], "mcpServers": {"mine": {"url": "https://example.com/mcp"}, "github": {"args": ["-y"], "command": "npx"}}}"#;
        write(root.path(), ".mcp.json", mine);
        let mut file = McpFile::read(root.path(), Harness::Claude).unwrap();
        assert_eq!(mcp_digest(&file.entries["github"]), github.sha256);
        assert!(!file.apply(&[Change::Put("github", &github)]).unwrap(), "the same entry: not rewritten");
        assert_eq!(std::fs::read_to_string(root.path().join(".mcp.json")).unwrap(), mine);
        assert!(file.apply(&[Change::Remove("github")]).unwrap());
        let text = std::fs::read_to_string(root.path().join(".mcp.json")).unwrap();
        assert!(text.ends_with("}\n"), "{text}");
        let written: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(written, json!({"theirs": [1, 2], "mcpServers": {"mine": {"url": "https://example.com/mcp"}}}));
        assert!(!file.entries.contains_key("github"));
    }

    #[test]
    fn json_files_bd_cannot_use_are_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let github = server(Harness::Copilot, r#"{"mcpServers": {"github": {"command": "npx"}}}"#, "github");
        for (text, why) in [
            ("{\"mcpServers\": {", "not valid JSON"),
            ("[]", "not a JSON object"),
            (r#"{"mcpServers": []}"#, "mcpServers is not an object"),
            (r#"{"github": {"command": "npx"}}"#, "holds MCP servers at its top level"),
        ] {
            write(root.path(), ".github/mcp.json", text);
            let mut file = McpFile::read(root.path(), Harness::Copilot).unwrap();
            assert!(file.unusable.as_deref().is_some_and(|u| u.contains(why)), "{text}: {:?}", file.unusable);
            assert!(file.apply(&[Change::Put("github", &github)]).is_err());
            assert_eq!(std::fs::read_to_string(root.path().join(".github/mcp.json")).unwrap(), text);
        }
        write(root.path(), ".github/mcp.json", r#"{"inputs": [], "other": {"x": 1}}"#);
        let file = McpFile::read(root.path(), Harness::Copilot).unwrap();
        assert!(file.unusable.is_none(), "other keys are not servers");
    }

    const CONFIG_HEAD: &str = "# Codex settings\nmodel = \"o3\" # the model\napproval_policy = \"on-request\"\n\n\
                               [mcp_servers.mine]\ncommand = \"mine\"   # my own server\n";
    const CONFIG_DOCS: &str = "\n# from bd\n[mcp_servers.docs]\nurl = \"https://example.com/mcp\"\n\
                               bearer_token_env_var = \"DOCS_TOKEN\"\n\n[mcp_servers.docs.env]\nLOG = \"1\"\n";
    const CONFIG_TAIL: &str = "\n[profiles.fast]\nmodel = \"o4\"   # quick\n\n# the end\n";

    #[test]
    fn toml_files_change_only_the_tables_bd_edits() {
        let root = tempfile::tempdir().unwrap();
        let config = format!("{CONFIG_HEAD}{CONFIG_DOCS}{CONFIG_TAIL}");
        write(root.path(), ".codex/config.toml", &config);
        let docs = server(Harness::Codex, CONFIG_DOCS, "docs");
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert_eq!(file.entries.keys().collect::<Vec<_>>(), ["docs", "mine"]);
        assert_eq!(mcp_digest(&file.entries["docs"]), docs.sha256);
        assert!(!file.apply(&[Change::Put("docs", &docs)]).unwrap(), "unchanged: not rewritten");

        assert!(file.apply(&[Change::Remove("docs")]).unwrap());
        let read = || std::fs::read_to_string(root.path().join(".codex/config.toml")).unwrap();
        assert_eq!(read(), format!("{CONFIG_HEAD}{CONFIG_TAIL}"), "the rest, byte for byte");

        assert!(file.apply(&[Change::Put("docs", &docs)]).unwrap());
        let text = read();
        assert!(text.starts_with(CONFIG_HEAD) && text.ends_with(CONFIG_TAIL), "{text}");
        let again = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert_eq!(mcp_digest(&again.entries["docs"]), docs.sha256);

        // A replaced table keeps its place and the comments before it.
        write(root.path(), ".codex/config.toml", &config);
        let newer = server(Harness::Codex, "[mcp_servers.docs]\nurl = \"https://example.com/v2\"\n", "docs");
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert!(file.apply(&[Change::Put("docs", &newer)]).unwrap());
        let text = read();
        assert!(text.starts_with(&format!("{CONFIG_HEAD}\n# from bd\n[mcp_servers.docs]\n")), "{text}");
        assert!(text.ends_with(CONFIG_TAIL) && !text.contains("LOG"), "{text}");

        // A new file holds the tables only.
        std::fs::remove_file(root.path().join(".codex/config.toml")).unwrap();
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert!(file.apply(&[Change::Put("docs", &docs)]).unwrap());
        assert_eq!(read(), docs.toml.clone().unwrap());
    }

    #[test]
    fn toml_files_bd_cannot_edit_are_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let docs = server(Harness::Codex, "[mcp_servers.docs]\nurl = \"https://example.com/mcp\"\n", "docs");
        write(root.path(), ".codex/config.toml", "model = \"o3\"\n[mcp_servers.docs\n");
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        let why = file.unusable.clone().unwrap();
        assert!(why.starts_with("not valid TOML (TOML parse error at line 2") && !why.contains('\n'), "{why}");
        assert!(file.apply(&[Change::Put("docs", &docs)]).is_err());

        let inline = "mcp_servers = { docs = { url = \"https://example.com/mcp\" } }\n";
        write(root.path(), ".codex/config.toml", inline);
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert_eq!(mcp_digest(&file.entries["docs"]), docs.sha256, "read");
        assert!(file.read_only.as_deref().unwrap().contains("written inline"));
        assert!(file.apply(&[Change::Remove("docs")]).is_err(), "not written");
        assert_eq!(std::fs::read_to_string(root.path().join(".codex/config.toml")).unwrap(), inline);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_mcp_files_are_read_but_never_written() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("shared.json");
        std::fs::write(&target, r#"{"mcpServers": {"github": {"command": "npx"}}}"#).unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(".mcp.json")).unwrap();
        let mut file = McpFile::read(root.path(), Harness::Claude).unwrap();
        assert_eq!(file.entries.keys().collect::<Vec<_>>(), ["github"]);
        assert!(file.read_only.as_deref().unwrap().contains("symlink"));
        assert!(file.apply(&[Change::Remove("github")]).is_err());
        assert!(std::fs::symlink_metadata(root.path().join(".mcp.json")).unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn rewritten_files_keep_their_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        if !super::super::checkout::modes_stick(root.path()) {
            return; // Modes set here do not stick.
        }
        write(root.path(), ".codex/config.toml", "model = \"o3\"\n[mcp_servers.docs]\nurl = \"https://x\"\n");
        let path = root.path().join(".codex/config.toml");
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let mut file = McpFile::read(root.path(), Harness::Codex).unwrap();
        assert!(file.apply(&[Change::Remove("docs")]).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "model = \"o3\"\n");
    }

    #[test]
    fn environment_references_are_found_per_harness() {
        let mut names = BTreeSet::new();
        let def = json!({
            "command": "${BIN_DIR}/server", "args": ["--token=$API_TOKEN", "${OPTIONAL:-x}", "$", "${", "$1"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "PLAIN": "value"}, "url": "https://${HOST}/mcp",
            "headers": {"Authorization": "Bearer ${AUTH}"}, "other": "${NOT_READ}"
        });
        env_refs(Harness::Claude, &def, &mut names);
        assert_eq!(names.iter().collect::<Vec<_>>(), ["API_TOKEN", "AUTH", "BIN_DIR", "GITHUB_TOKEN", "HOST"]);

        let mut names = BTreeSet::new();
        let def = json!({
            "command": "${NOT_EXPANDED}", "env_vars": ["GITHUB_TOKEN", {"name": "LOCAL", "source": "local"},
            {"name": "REMOTE", "source": "remote"}, {"name": "PLAIN"}], "bearer_token_env_var": "DOCS_TOKEN",
            "env_http_headers": {"X-Team": "TEAM_ID"}
        });
        env_refs(Harness::Codex, &def, &mut names);
        assert_eq!(names.iter().collect::<Vec<_>>(), ["DOCS_TOKEN", "GITHUB_TOKEN", "LOCAL", "PLAIN", "TEAM_ID"]);
    }

    #[test]
    fn changed_fields_name_what_differs() {
        let old = json!({"command": "npx", "args": ["-y", "a"], "env": {"A": "1"}});
        let new = json!({"command": "npx", "args": ["-y", "b"], "url": "x", "env": {"A": "1"}});
        assert_eq!(changed_fields(&old, &new), ["args", "url"]);
        assert_eq!(changed_fields(&old, &old), Vec::<String>::new());
        assert_eq!(changed_fields(&json!({"command": "npx"}), &json!({"url": "x"})), ["command", "url"]);
    }
}
