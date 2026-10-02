//! MCP server definitions: strict parsing, canonical form and hashes.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

use super::{Harness, MAX_MCP_SERVERS, MAX_NAME_BYTES, McpFormat, context, invalid, sha256_hex};
use crate::error::Result;

/// One MCP server entry of a set, as `bd agents fetch` sends it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServer {
    /// [`mcp_digest`] of `definition`.
    pub sha256: String,
    /// The entry as JSON: as written for claude and copilot; for codex, its
    /// TOML table as JSON ([`toml_definition`]).
    pub definition: Value,
    /// codex only: the entry in its native form, a TOML document holding
    /// the one table `[mcp_servers.<name>]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toml: Option<String>,
}

/// The MCP server entries of a harness's MCP file (`origin` names it in
/// errors), by name. JSON files hold `{"mcpServers": {...}}` and TOML files
/// `[mcp_servers.<name>]` tables, and nothing else; each entry is checked by
/// [`check_definition`].
pub fn parse_mcp(harness: Harness, text: &str, origin: &str) -> Result<BTreeMap<String, McpServer>> {
    let key = harness.mcp_key();
    let entries: Vec<(String, Value, Option<String>)> = match harness.mcp_format() {
        McpFormat::Json => {
            let StrictJson(doc) = serde_json::from_str(text).map_err(|e| invalid(format!("{origin}: {e}")))?;
            let Value::Object(mut doc) = doc else {
                return Err(invalid(format!("{origin}: expected {{\"{key}\": {{\"<name>\": {{...}}}}}}")));
            };
            only_key(doc.keys(), key, origin)?;
            match doc.remove(key) {
                None => Vec::new(),
                Some(Value::Object(servers)) => servers.into_iter().map(|(name, def)| (name, def, None)).collect(),
                Some(_) => return Err(invalid(format!("{origin}: {key} must map server names to their settings"))),
            }
        }
        McpFormat::Toml => {
            let mut doc: toml::Table = toml::from_str(text).map_err(|e| invalid(format!("{origin}: {e}")))?;
            only_key(doc.keys(), key, origin)?;
            match doc.remove(key) {
                None => Vec::new(),
                Some(toml::Value::Table(servers)) => servers
                    .into_iter()
                    .map(|(name, table)| {
                        let entry = format!("{origin}: {key}.{name}");
                        let def = toml_definition(&table).map_err(|e| context(&entry, e))?;
                        Ok((name.clone(), def, Some(toml_entry(&name, table).map_err(|e| context(&entry, e))?)))
                    })
                    .collect::<Result<_>>()?,
                Some(_) => return Err(invalid(format!("{origin}: {key} must hold one table per server"))),
            }
        }
    };
    if entries.len() > MAX_MCP_SERVERS {
        return Err(invalid(format!(
            "{origin}: {} MCP servers is more than the {MAX_MCP_SERVERS} a set may hold",
            entries.len()
        )));
    }
    let mut servers = BTreeMap::new();
    for (name, definition, toml) in entries {
        check_server_name(&name).map_err(|e| context(origin, e))?;
        check_definition(&definition).map_err(|e| context(&format!("{origin}: {key}.{name}"), e))?;
        servers.insert(name, McpServer { sha256: mcp_digest(&definition), definition, toml });
    }
    Ok(servers)
}

fn only_key<'a>(mut keys: impl Iterator<Item = &'a String>, allowed: &str, origin: &str) -> Result<()> {
    match keys.find(|k| *k != allowed) {
        Some(k) => Err(invalid(format!(
            "{origin}: unknown key {k:?}: an MCP file holds only {allowed:?}, the MCP server entries (no settings, \
             hooks or permissions)"
        ))),
        None => Ok(()),
    }
}

/// An MCP server name: letters, digits, `-` and `_`, as every harness
/// accepts them (and as a TOML key needs no quotes).
pub fn check_server_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(invalid(format!(
            "invalid MCP server name {name:?}: letters, digits, '-' and '_', at most {MAX_NAME_BYTES} characters"
        )));
    }
    Ok(())
}

/// Longest name of a top-level field of an MCP server definition.
pub const MAX_FIELD_NAME: usize = 64;

/// The name of a top-level field of an MCP server definition: letters,
/// digits, `_`, `.` and `-`, starting with a letter or `_`. Every harness's
/// fields fit, and so a field name is safe to show anywhere as it is.
pub fn check_field_name(name: &str) -> Result<()> {
    let ok = (1..=MAX_FIELD_NAME).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        return Ok(());
    }
    // ASCII only, everything else escaped: the name is the server's, and may hold anything.
    let shown: String = name.chars().take(MAX_FIELD_NAME).flat_map(char::escape_default).collect();
    let more = if name.chars().count() > MAX_FIELD_NAME { "..." } else { "" };
    Err(invalid(format!(
        "invalid field name \"{shown}\"{more}: a field of an MCP server is 1 to {MAX_FIELD_NAME} characters, \
         letters, digits, '_', '.' and '-', starting with a letter or '_'"
    )))
}

/// One server's settings: an object with a `command` (a server the client
/// starts) or a `url` (a remote server), whose top-level fields have names
/// [`check_field_name`] accepts. The fields every harness shares must have
/// their type (`command` and `url` strings, `args` strings, `env` names to
/// strings); other fields are the harness's own and pass as they are.
pub fn check_definition(def: &Value) -> Result<()> {
    let Value::Object(fields) = def else {
        return Err(invalid("expected the server's settings as an object (a table in TOML)"));
    };
    for name in fields.keys() {
        check_field_name(name)?;
    }
    let present = |field: &str| match fields.get(field) {
        None => Ok(false),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(true),
        Some(_) => Err(invalid(format!("{field} must be a non-empty string"))),
    };
    let (command, url) = (present("command")?, present("url")?);
    if fields.get("args").is_some_and(|a| !matches!(a, Value::Array(a) if a.iter().all(Value::is_string))) {
        return Err(invalid("args must be an array of strings"));
    }
    if fields.get("env").is_some_and(|e| !matches!(e, Value::Object(m) if m.values().all(Value::is_string))) {
        return Err(invalid("env must map variable names to strings"));
    }
    if !command && !url {
        return Err(invalid("no command (a server the client starts) or url (a remote server)"));
    }
    Ok(())
}

/// A TOML value as JSON, for hashing and display. Datetimes have no JSON
/// form and no use in an MCP definition, so they are refused.
pub fn toml_definition(value: &toml::Value) -> Result<Value> {
    Ok(match value {
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => {
            Value::Number(Number::from_f64(*f).ok_or_else(|| invalid(format!("{f} has no JSON form")))?)
        }
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Datetime(d) => return Err(invalid(format!("datetime {d}: MCP definitions hold no datetimes"))),
        toml::Value::Array(items) => Value::Array(items.iter().map(toml_definition).collect::<Result<_>>()?),
        toml::Value::Table(table) => Value::Object(
            table.iter().map(|(k, v)| Ok((k.clone(), toml_definition(v)?))).collect::<Result<Map<_, _>>>()?,
        ),
    })
}

/// `[mcp_servers.<name>]`, holding `table`, as a TOML document.
fn toml_entry(name: &str, table: toml::Value) -> Result<String> {
    let servers = toml::Table::from_iter([(name.to_string(), table)]);
    let doc = toml::Table::from_iter([(Harness::Codex.mcp_key().to_string(), toml::Value::Table(servers))]);
    toml::to_string(&doc).map_err(|e| invalid(e.to_string()))
}

/// JSON with object keys sorted (by their UTF-8 bytes) and no whitespace:
/// two values that parse the same have the same canonical JSON.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// An MCP server entry's hash: SHA-256 of the [`canonical_json`] of its
/// definition (for codex, of [`toml_definition`] of its table).
pub fn mcp_digest(definition: &Value) -> String {
    sha256_hex(canonical_json(definition).as_bytes())
}

/// A JSON value whose objects hold each key once: a duplicate is an error
/// rather than a silent overwrite.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<StrictJson, D::Error> {
        d.deserialize_any(StrictVisitor).map(StrictJson)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom(format!("{v} is not a JSON number")))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictJson(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key:?}")));
            }
            let StrictJson(v) = map.next_value()?;
            object.insert(key, v);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORIGIN: &str = ".bd/agents/claude/mcp.json";

    fn err(harness: Harness, text: &str) -> String {
        parse_mcp(harness, text, ORIGIN).unwrap_err().to_string()
    }

    #[test]
    fn json_entries_parse_with_canonical_hashes() {
        let a = r#"{"mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                       "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
            "linear": {"type": "http", "url": "https://mcp.linear.app/mcp", "headers": {"X-Team": "${TEAM:-core}"}}
        }}"#;
        // The same definitions, reformatted: other key order, other spacing, escaped characters.
        let b = "{\"mcpServers\":{\"linear\":{\"headers\":{\"X-Team\":\"${TEAM:-core}\"},\"url\":\"https://mcp.linear.app/mcp\",\
                 \"type\":\"http\"},\"github\":{\"env\":{\"GITHUB_TOKEN\":\"${GITHUB_TOKEN}\"},\"args\":[\"-y\",\
                 \"@modelcontextprotocol/server-github\"],\"command\":\"\\u006epx\"}}}";
        let (a, b) = (parse_mcp(Harness::Claude, a, ORIGIN).unwrap(), parse_mcp(Harness::Copilot, b, ORIGIN).unwrap());
        assert_eq!(a.keys().collect::<Vec<_>>(), ["github", "linear"]);
        assert_eq!(a, b, "formatting changes no hash");
        assert_eq!(a["github"].definition["env"]["GITHUB_TOKEN"], "${GITHUB_TOKEN}", "references stay as written");
        assert_eq!(a["github"].toml, None);
        assert_eq!(a["github"].sha256, mcp_digest(&a["github"].definition));

        let changed = r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github@2"]}}}"#;
        let changed = parse_mcp(Harness::Claude, changed, ORIGIN).unwrap();
        assert_ne!(changed["github"].sha256, a["github"].sha256);
        assert!(parse_mcp(Harness::Claude, "{}", ORIGIN).unwrap().is_empty());
        assert!(parse_mcp(Harness::Claude, r#"{"mcpServers": {}}"#, ORIGIN).unwrap().is_empty());
    }

    #[test]
    fn json_files_hold_server_entries_only() {
        for (text, want) in [
            (r#"{"mcpServers": {}, "hooks": {}}"#, "unknown key \"hooks\""),
            (r#"{"permissions": {"allow": ["Bash"]}}"#, "unknown key \"permissions\""),
            (r#"{"github": {"command": "npx"}}"#, "unknown key \"github\""),
            (r#"["mcpServers"]"#, "expected {\"mcpServers\""),
            (r#"{"mcpServers": []}"#, "must map server names"),
            (r#"{"mcpServers": {"a": {"command": "x"}, "a": {"command": "y"}}}"#, "duplicate key \"a\""),
            (r#"{"mcpServers": {"a": {"command": "x", "command": "y"}}}"#, "duplicate key \"command\""),
            (r#"{"mcpServers": {"a": {"command": "x"}}} trailing"#, "trailing characters"),
            (r#"{"mcpServers": {"a": "npx"}}"#, "mcpServers.a: expected the server's settings as an object"),
            (r#"{"mcpServers": {"a": {"args": ["x"]}}}"#, "mcpServers.a: no command"),
            (r#"{"mcpServers": {"a": {"command": ""}}}"#, "command must be a non-empty string"),
            (r#"{"mcpServers": {"a": {"command": ["npx"]}}}"#, "command must be a non-empty string"),
            (r#"{"mcpServers": {"a": {"command": "x", "args": "-y"}}}"#, "args must be an array of strings"),
            (r#"{"mcpServers": {"a": {"command": "x", "args": [1]}}}"#, "args must be an array of strings"),
            (r#"{"mcpServers": {"a": {"command": "x", "env": {"A": 1}}}}"#, "env must map variable names"),
            (r#"{"mcpServers": {"a b": {"command": "x"}}}"#, "invalid MCP server name \"a b\""),
            (r#"{"mcpServers": {"": {"command": "x"}}}"#, "invalid MCP server name \"\""),
        ] {
            let e = err(Harness::Claude, text);
            assert!(e.starts_with(ORIGIN), "names the file: {e}");
            assert!(e.contains(want), "{text}: {e}");
        }
        let many: Map<String, Value> =
            (0..=MAX_MCP_SERVERS).map(|i| (format!("s{i}"), json!({"command": "x"}))).collect();
        let e = err(Harness::Claude, &json!({ "mcpServers": many }).to_string());
        assert!(e.contains(&format!("more than the {MAX_MCP_SERVERS}")), "{e}");
    }

    #[test]
    fn toml_entries_keep_their_hash_across_formatting() {
        let a = "# Servers for Codex\n[mcp_servers.github]\ncommand = \"npx\"\nargs = [\"-y\", \"server-github\"]\n\
                 env_vars = [\"GITHUB_TOKEN\"]\nstartup_timeout_sec = 20.0\n\n[mcp_servers.github.env]\nLOG = \"1\"\n\n\
                 [mcp_servers.docs]\nurl = \"https://example.com/mcp\"\nbearer_token_env_var = \"DOCS_TOKEN\"\n";
        let b = "mcp_servers.docs = { bearer_token_env_var = 'DOCS_TOKEN', url = \"https://example.com/mcp\" }\n\
                 [mcp_servers.\"github\"]\nenv = { LOG = \"1\" }\nstartup_timeout_sec = 2e1\n\
                 env_vars = [ \"GITHUB_TOKEN\", ]\nargs = [\n  \"-y\",\n  \"server-github\",\n]\ncommand = \"npx\" # runs locally\n";
        let (a, b) = (parse_mcp(Harness::Codex, a, ORIGIN).unwrap(), parse_mcp(Harness::Codex, b, ORIGIN).unwrap());
        assert_eq!(a, b, "formatting changes neither the hash nor the rendered table");
        let github = &a["github"];
        assert_eq!(
            github.definition,
            json!({"command": "npx", "args": ["-y", "server-github"], "env_vars": ["GITHUB_TOKEN"],
                   "startup_timeout_sec": 20.0, "env": {"LOG": "1"}})
        );
        // The native form: one [mcp_servers.<name>] table, which parses back to the same definition.
        let text = github.toml.as_deref().unwrap();
        assert!(text.contains("[mcp_servers.github]"), "{text}");
        let back = parse_mcp(Harness::Codex, text, "rendered").unwrap();
        assert_eq!(back.keys().collect::<Vec<_>>(), ["github"]);
        assert_eq!(&back["github"], github);

        let changed = parse_mcp(Harness::Codex, "[mcp_servers.github]\ncommand = \"uvx\"\n", ORIGIN).unwrap();
        assert_ne!(changed["github"].sha256, github.sha256);
        assert!(parse_mcp(Harness::Codex, "", ORIGIN).unwrap().is_empty());
    }

    #[test]
    fn toml_files_hold_server_tables_only() {
        for (text, want) in [
            ("model = \"o3\"\n[mcp_servers.a]\ncommand = \"x\"\n", "unknown key \"model\""),
            ("[profiles.fast]\nmodel = \"o3\"\n", "unknown key \"profiles\""),
            ("[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a]\ncommand = \"y\"\n", "duplicate"),
            ("mcp_servers = [\"a\"]\n", "must hold one table per server"),
            ("[mcp_servers]\na = \"npx\"\n", "mcp_servers.a: expected the server's settings"),
            ("[mcp_servers.a]\nargs = [\"x\"]\n", "mcp_servers.a: no command"),
            ("[mcp_servers.a]\ncommand = \"x\"\nsince = 2024-01-01\n", "MCP definitions hold no datetimes"),
            ("[mcp_servers.a]\ncommand = \"x\"\ntimeout = nan\n", "has no JSON form"),
            ("[mcp_servers.\"a.b\"]\ncommand = \"x\"\n", "invalid MCP server name \"a.b\""),
            ("[mcp_servers.a\ncommand = \"x\"\n", ""),
        ] {
            let e = err(Harness::Codex, text);
            assert!(e.starts_with(ORIGIN), "names the file: {e}");
            assert!(e.contains(want), "{text}: {e}");
        }
    }

    #[test]
    fn top_level_field_names_are_restricted() {
        for name in [
            "type",
            "command",
            "args",
            "env",
            "url",
            "headers",
            "tools",
            "timeout",
            "cwd",
            "env_vars",
            "bearer_token_env_var",
            "startup_timeout_sec",
            "tool_timeout_sec",
            "enabled",
            "enabled_tools",
            "disabled_tools",
            "oauth",
            "env_http_headers",
            "http_headers",
            "_private",
            "x.y-z",
            &"a".repeat(64),
        ] {
            check_field_name(name).unwrap();
            if !["command", "args", "env", "url"].contains(&name) {
                check_definition(&json!({"command": "x", name: 1})).unwrap();
            }
        }
        for (name, shown) in [
            ("a\nb", r#""a\nb""#),
            ("\u{1b}[2K", r#""\u{1b}[2K""#),
            ("two words", r#""two words""#),
            ("1st", r#""1st""#),
            ("-x", r#""-x""#),
            ("", r#""""#),
            ("café", r#""caf\u{e9}""#),
            ("x\u{202e}y", r#""x\u{202e}y""#),
            (&"b".repeat(65), &format!("\"{}\"...", "b".repeat(64))),
        ] {
            let e = check_field_name(name).unwrap_err().to_string();
            assert!(e.starts_with(&format!("invalid field name {shown}: ")), "{name:?}: {e}");
            assert!(e.is_ascii() && !e.contains('\n'), "{e:?}");
        }
        // Nested keys are the harness's own.
        check_definition(&json!({"command": "x", "env": {"odd key\n": "v"}, "headers": {"X Y": "z"}})).unwrap();

        let e = err(Harness::Claude, r#"{"mcpServers": {"github": {"command": "npx", "a\nb": 1}}}"#);
        assert!(e.starts_with(&format!(r#"{ORIGIN}: mcpServers.github: invalid field name "a\nb""#)), "{e}");
        let e = err(Harness::Codex, "[mcp_servers.docs]\nurl = \"https://x\"\n\"\\u001b[2K\" = 1\n");
        assert!(e.starts_with(&format!(r#"{ORIGIN}: mcp_servers.docs: invalid field name "\u{{1b}}[2K""#)), "{e}");
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let v = json!({"b": [{"z": 1, "a": null}, "x\"y"], "a": {"d": true, "c": 1.5}, "é": "\u{1F600}"});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":1.5,"d":true},"b":[{"a":null,"z":1},"x\"y"],"é":"😀"}"#);
        assert_eq!(mcp_digest(&v), sha256_hex(canonical_json(&v).as_bytes()));
    }
}
