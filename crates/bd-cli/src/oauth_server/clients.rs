//! The clients of `bd serve`'s authorization server: public clients (no
//! secret; PKCE protects their codes), each known either by a client ID
//! metadata document (`cimd.rs`) or by registering here (RFC 7591).
//!
//! Registration takes no token, so what it can do is bounded: every
//! redirect URI must be one `[oauth]` allows, a client never used within
//! [`UNUSED_FOR`] of registering or unused for [`IDLE_FOR`] is dropped, and
//! at most [`MAX_CLIENTS`] are kept (a full registry drops its oldest
//! never-used client). Registered clients live in `<root>/server.db`
//! (`server_db.rs`), a row each.

use std::path::Path;
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::cimd::{self, Documents};
use crate::auth;
use crate::oauth::OauthConfig;
use crate::server_db;

pub const MAX_CLIENTS: usize = 500;
pub const UNUSED_FOR: Duration = Duration::from_secs(24 * 3600);
pub const IDLE_FOR: Duration = Duration::from_secs(90 * 24 * 3600);
/// The most redirect URIs a client registers.
pub const MAX_REDIRECTS: usize = 8;
/// The longest redirect URI: with [`MAX_REDIRECTS`] and [`MAX_CLIENTS`],
/// the registry stays a couple of megabytes.
const MAX_REDIRECT_URI: usize = 512;
const MAX_NAME: usize = 100;
/// What registered client IDs start with; never `https://`.
const ID_PREFIX: &str = "bdc_";

/// A client as authorization sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    /// What it calls itself (`client_name`), which no one checked: escape
    /// it wherever it is shown.
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// Whether `id` is the URL of its metadata document, rather than
    /// registered here.
    pub document: bool,
    /// The logo its metadata document names, which the document's site
    /// vouches for, fetched with the document as a `data:` URL; never a
    /// registered client's, which anyone may claim. Shared, not copied, by
    /// every authorization under way for the client: anyone may start many.
    pub logo: Option<std::sync::Arc<str>>,
    /// Whether its document may be kept: its host did not say `no-store`
    /// or `no-cache` (always, for a registered client).
    pub cacheable: bool,
}

impl Client {
    /// Whether an authorization may send its answer to `uri`: one of the
    /// client's redirect URIs exactly (on any port of this machine's, which
    /// native clients choose as they listen: RFC 8252 section 7.3), and one
    /// `[oauth]` allows.
    pub fn redirects_to(&self, uri: &str, oauth: &OauthConfig) -> bool {
        let wanted = without_loopback_port(uri);
        self.redirect_uris.iter().any(|r| without_loopback_port(r) == wanted) && oauth.allows_redirect(uri)
    }
}

/// The client `id` names: fetched from its metadata document, or
/// registered here. An invalid error when there is no such client.
pub fn lookup(root: &Path, documents: &Documents, id: &str) -> Result<Client> {
    if cimd::is_document_url(id) {
        return documents.client(id);
    }
    let found = match server_db::open_existing(root)? {
        Some(conn) => find(&conn, id)?,
        None => None,
    };
    match found {
        Some(c) => Ok(Client {
            id: c.client_id,
            name: c.client_name,
            redirect_uris: c.redirect_uris,
            document: false,
            logo: None,
            cacheable: true,
        }),
        None => Err(Error::invalid(format!("no such client: {id:?} (registrations unused for a while are dropped)"))),
    }
}

/// Record that the registered client `id` was used (an authorization or a
/// token), so it is kept; nothing for clients with a metadata document.
pub fn touch(root: &Path, id: &str) -> Result<()> {
    if cimd::is_document_url(id) {
        return Ok(());
    }
    let now = Timestamp::now();
    // Once an hour is enough to keep it, and saves a write per request.
    let recent = |c: &Registered| c.used_at.is_some_and(|at| now.since(at) < 3_600_000);
    let Some(conn) = server_db::open_existing(root)? else { return Ok(()) };
    if find(&conn, id)?.is_none_or(|c| recent(&c)) {
        return Ok(());
    }
    change(root, |clients| {
        if let Some(client) = clients.iter_mut().find(|c| c.client_id == id) {
            client.used_at = Some(now);
        }
        Ok(())
    })
}

/// Whether `uri` sends the browser to this machine (`http` on 127.0.0.1,
/// [::1] or localhost), where any program may be listening.
pub fn is_loopback(uri: &str) -> bool {
    matches!(without_loopback_port(uri), std::borrow::Cow::Owned(_))
}

/// `uri` without its port if it is a loopback one, owned only then.
fn without_loopback_port(uri: &str) -> std::borrow::Cow<'_, str> {
    let Some(rest) = uri.strip_prefix("http://") else { return uri.into() };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => &authority[..i],
        _ => authority,
    };
    if matches!(host.to_ascii_lowercase().as_str(), "127.0.0.1" | "[::1]" | "localhost") {
        format!("http://{host}{tail}").into()
    } else {
        uri.into()
    }
}

/// Why a registration was refused: its RFC 7591 error code and why.
pub type Refusal = (&'static str, String);

/// Register a client with the metadata `request` (RFC 7591 section 3.1),
/// as a public client: the answer, or why not. Fields bd does not use are
/// ignored; any `token_endpoint_auth_method` is answered with `none`.
pub fn register(root: &Path, oauth: &OauthConfig, request: &[u8]) -> Result<std::result::Result<Value, Refusal>> {
    let request: Value = match serde_json::from_slice(request) {
        Ok(Value::Object(o)) => Value::Object(o),
        Ok(_) => return Ok(Err(("invalid_client_metadata", "the request is not a JSON object".into()))),
        Err(e) => return Ok(Err(("invalid_client_metadata", format!("the request is not JSON: {e}")))),
    };
    let request = request.as_object().expect("an object");
    let checked = (|| {
        let types = check_types(request, false)?;
        let redirect_uris = string_list(request.get("redirect_uris"), "redirect_uris", MAX_REDIRECTS)?;
        if let Some(uri) = redirect_uris.iter().find(|u| !oauth.allows_redirect(u)) {
            let why = format!(
                "redirect URI {uri:?} is not allowed: https to a host in this server's [oauth] redirect_hosts, or \
                 http to this machine if it allows loopback_redirects"
            );
            return Err(("invalid_redirect_uri", why));
        }
        Ok((types, redirect_uris, client_name(request.get("client_name"))?))
    })();
    let ((grant_types, response_types), redirect_uris, name) = match checked {
        Ok(c) => c,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let now = Timestamp::now();
    let client = Registered {
        client_id: format!("{ID_PREFIX}{}", auth::random_hex(16)?),
        client_name: name,
        redirect_uris,
        issued_at: now,
        used_at: None,
    };
    let event = server_db::AuthEvent {
        kind: "client_registered",
        client: Some(client.client_id.clone()),
        detail: client.client_name.clone(),
        ..server_db::AuthEvent::default()
    };
    change_noting(root, Some(event), |clients| {
        clients.retain(|c| match c.used_at {
            Some(at) => now.since(at) < millis(IDLE_FOR),
            None => now.since(c.issued_at) < millis(UNUSED_FOR),
        });
        if clients.len() >= MAX_CLIENTS {
            let unused = clients.iter().enumerate().filter(|(_, c)| c.used_at.is_none());
            match unused.min_by_key(|(_, c)| c.issued_at).map(|(i, _)| i) {
                Some(oldest) => drop(clients.remove(oldest)),
                None => return Err(Error::Busy(format!("{MAX_CLIENTS} clients are registered and in use"))),
            }
        }
        let mut answer = json!({
            "client_id": client.client_id,
            "client_id_issued_at": now.millis() / 1000,
            "redirect_uris": client.redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "token_endpoint_auth_method": "none",
        });
        if let Some(name) = &client.client_name {
            answer["client_name"] = name.clone().into();
        }
        clients.push(client);
        Ok(Ok(answer))
    })
}

/// `grant_types` and `response_types`, which may be left out: with
/// authorization codes, and of the ones bd supports. A client metadata
/// document serves every server its client uses, so with `others_ignored`
/// types bd does not support are left out rather than refused.
pub fn check_types(
    meta: &Map<String, Value>,
    others_ignored: bool,
) -> std::result::Result<(Vec<String>, Vec<String>), Refusal> {
    let list = |field: &str, supported: &[&str], needed: &str, default: &[&str]| {
        let Some(value) = meta.get(field) else { return Ok(default.iter().map(|s| s.to_string()).collect()) };
        let mut list = string_list(Some(value), field, 8)?;
        if others_ignored {
            list.retain(|t| supported.contains(&t.as_str()));
        }
        match list.iter().find(|t| !supported.contains(&t.as_str())) {
            Some(t) => Err(("invalid_client_metadata", format!("{field} {t:?} is not supported: {supported:?} are"))),
            None if !list.iter().any(|t| t == needed) => {
                Err(("invalid_client_metadata", format!("{field} does not have {needed:?}")))
            }
            None => Ok(list),
        }
    };
    let grants = ["authorization_code", "refresh_token"];
    Ok((list("grant_types", &grants, grants[0], &grants)?, list("response_types", &["code"], "code", &["code"])?))
}

/// A list of one to `max` strings (such as `redirect_uris`), each one
/// printable and of reasonable length.
pub fn string_list(value: Option<&Value>, field: &str, max: usize) -> std::result::Result<Vec<String>, Refusal> {
    let code = if field == "redirect_uris" { "invalid_redirect_uri" } else { "invalid_client_metadata" };
    let refuse = |why: String| Err((code, why));
    let Some(Value::Array(items)) = value else { return refuse(format!("{field} is not a list of strings")) };
    if items.is_empty() || items.len() > max {
        return refuse(format!("{field} has {} entries, not 1 to {max}", items.len()));
    }
    let mut list = Vec::with_capacity(items.len());
    for item in items {
        match item.as_str() {
            Some(s) if !s.is_empty() && s.len() <= MAX_REDIRECT_URI && !s.chars().any(char::is_control) => {
                list.push(s.to_string());
            }
            _ => return refuse(format!("{field} has an entry that is not a printable string of reasonable length")),
        }
    }
    Ok(list)
}

/// Whether `name` holds something that changes how it looks without being
/// seen itself, which could make one client's name pass for another's:
/// text direction controls (which reorder what follows, as in "Trojan
/// Source"), invisible and blank characters, and spaces other than the
/// ASCII one. Joiners (ZWJ, ZWNJ) are let through between two visible
/// characters, where Persian, Indic scripts and emoji sequences need them,
/// and emoji presentation selectors (VS15, VS16) after one.
fn hides_something(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    let visible = |i: Option<usize>| i.and_then(|i| chars.get(i)).is_some_and(|&c| c != ' ' && !hidden(c));
    chars.iter().enumerate().any(|(i, &c)| match c {
        '\u{200C}' | '\u{200D}' => !(visible(i.checked_sub(1)) && visible(Some(i + 1))),
        '\u{FE0E}' | '\u{FE0F}' => !visible(i.checked_sub(1)),
        c => c.is_control() || hidden(c),
    })
}

/// Whether `text` may be shown on a page as given: not empty once trimmed,
/// at most `max` characters, hiding nothing ([`hides_something`]).
pub(crate) fn shows_plainly(text: &str, max: usize) -> bool {
    let text = text.trim();
    !text.is_empty() && text.chars().count() <= max && !hides_something(text)
}

/// Whether `c` is never shown in a name: see [`hides_something`].
fn hidden(c: char) -> bool {
    (c.is_whitespace() && c != ' ')
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1345F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D159}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// `client_name`, if any: printable, trimmed, at most [`MAX_NAME`]
/// characters, hiding nothing ([`hides_something`]).
pub fn client_name(value: Option<&Value>) -> std::result::Result<Option<String>, Refusal> {
    let name = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.trim(),
        Some(_) => return Err(("invalid_client_metadata", "client_name is not a string".into())),
    };
    if name.chars().count() > MAX_NAME || hides_something(name) {
        let why = format!("client_name is longer than {MAX_NAME} characters, or not printable");
        return Err(("invalid_client_metadata", why));
    }
    Ok((!name.is_empty()).then(|| name.to_string()))
}

#[derive(Clone, Serialize, Deserialize)]
struct Registered {
    client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    issued_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    used_at: Option<Timestamp>,
}

/// The registered client `id`.
fn find(conn: &rusqlite::Connection, id: &str) -> Result<Option<Registered>> {
    let mut stmt = conn.prepare_cached("SELECT data FROM oauth_clients WHERE client_id = ?1")?;
    let data: Option<String> = stmt.query_map([id], |r| r.get(0))?.next().transpose()?;
    data.map(|d| parse(&d)).transpose()
}

fn parse(data: &str) -> Result<Registered> {
    serde_json::from_str(data).map_err(|e| Error::invalid(format!("server.db: an OAuth client: {e}")))
}

/// The registered clients, in the order they registered.
fn load(conn: &rusqlite::Connection) -> Result<Vec<Registered>> {
    let mut stmt = conn.prepare_cached("SELECT data FROM oauth_clients ORDER BY seq")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    rows.iter().map(|d| parse(d)).collect()
}

/// Change the registered clients with `f`, in one transaction: the rows it
/// added, changed or dropped are written if it succeeds, nothing if not.
fn change<T>(root: &Path, f: impl FnOnce(&mut Vec<Registered>) -> Result<T>) -> Result<T> {
    change_noting(root, None, f)
}

/// [`change`], recording `event` for the audit trail with it.
fn change_noting<T>(
    root: &Path,
    event: Option<server_db::AuthEvent>,
    f: impl FnOnce(&mut Vec<Registered>) -> Result<T>,
) -> Result<T> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        if let Some(event) = &event {
            server_db::record(tx, event)?;
        }
        let before = load(tx)?;
        let mut clients = before.clone();
        let out = f(&mut clients)?;
        server_db::sync_rows(
            &before,
            &clients,
            |c| c.client_id.clone(),
            |id| {
                tx.execute("DELETE FROM oauth_clients WHERE client_id = ?1", [id])?;
                Ok(())
            },
            |c, data| {
                tx.execute(
                    "INSERT INTO oauth_clients (client_id, data) VALUES (?1, ?2) ON CONFLICT (client_id) DO UPDATE \
                     SET data = excluded.data",
                    [c.client_id.as_str(), data],
                )?;
                Ok(())
            },
        )?;
        Ok(out)
    })
}

fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_may_be_in_any_script_but_hide_nothing() {
        let shown = [
            "Café Ünïcode",
            "日本語クライアント",
            "Клиент",
            "عميل",
            "Claude ✨",
            "Notes ✍\u{FE0F}",
            "I \u{2764}\u{FE0F} bd",
            "\u{1F469}\u{200D}\u{1F4BB} Dev",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
            "\u{0915}\u{094D}\u{200D}\u{0937}",
        ];
        for shown in shown {
            assert_eq!(client_name(Some(&json!(shown))).unwrap().as_deref(), Some(shown));
        }
        let hidden = [
            "a\u{2066}b",
            "a\u{FEFF}",
            "a\u{E0041}",
            "a\u{3000}b",
            "a\u{2028}b",
            "\u{200F}",
            "\u{2800}",
            "a\u{0600}b",
            "Chat\u{200D}",
            "\u{200C}GPT",
            "Chat \u{200D}GPT",
            "Chat\u{200D}\u{200D}GPT",
            "\u{FE0F}GPT",
            "Chat \u{FE0F}",
            "Chat\u{FE01}GPT",
        ];
        for hidden in hidden {
            assert!(client_name(Some(&json!(hidden))).is_err(), "{hidden:?}");
        }
    }

    fn oauth() -> OauthConfig {
        OauthConfig {
            redirect_hosts: vec!["chatgpt.com".into(), "claude.ai".into()],
            redirect_uris: vec![],
            loopback_redirects: true,
            registration: true,
        }
    }

    fn register_json(root: &Path, request: Value) -> std::result::Result<Value, Refusal> {
        register(root, &oauth(), request.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn public_clients_register_with_allowed_redirects() {
        let root = tempfile::tempdir().unwrap();
        let answer = register_json(
            root.path(),
            json!({
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1:33418/cb"],
                "client_name": "  Claude  ", "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": ["authorization_code", "refresh_token"], "scope": "ignored", "logo_uri": "https://x/l.png",
            }),
        )
        .unwrap();
        let id = answer["client_id"].as_str().unwrap().to_string();
        assert!(id.starts_with("bdc_") && id.len() == 36, "{id}");
        assert_eq!(answer["client_name"], "Claude");
        assert_eq!(answer["token_endpoint_auth_method"], "none", "public, whatever it asked");
        assert_eq!(answer["response_types"], json!(["code"]));
        assert!(answer.get("client_secret").is_none() && answer["client_id_issued_at"].as_i64().unwrap() > 0);

        let documents = Documents::new();
        let client = lookup(root.path(), &documents, &id).unwrap();
        assert_eq!(client.name.as_deref(), Some("Claude"));
        assert!(!client.document);
        assert!(client.redirects_to("https://claude.ai/api/mcp/auth_callback", &oauth()));
        assert!(!client.redirects_to("https://claude.ai/api/mcp/auth_callback/", &oauth()), "exactly");
        assert!(client.redirects_to("http://127.0.0.1:33418/cb", &oauth()));
        assert!(client.redirects_to("http://127.0.0.1:51000/cb", &oauth()), "any port of this machine");
        assert!(client.redirects_to("http://127.0.0.1/cb", &oauth()));
        assert!(!client.redirects_to("http://127.0.0.1:51000/cb2", &oauth()), "the path exactly");
        assert!(!client.redirects_to("http://localhost:33418/cb", &oauth()), "the host exactly");
        assert!(!client.redirects_to("https://chatgpt.com/connector_platform_oauth_redirect", &oauth()), "its own");
        let narrower = OauthConfig {
            redirect_hosts: vec!["chatgpt.com".into()],
            redirect_uris: vec![],
            loopback_redirects: false,
            registration: true,
        };
        assert!(!client.redirects_to("https://claude.ai/api/mcp/auth_callback", &narrower), "as auth.toml is now");
        let e = lookup(root.path(), &documents, "bdc_nope").unwrap_err().to_string();
        assert!(e.contains("no such client"), "{e}");

        let second = register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap();
        assert_ne!(second["client_id"], answer["client_id"]);
        assert_eq!(second.get("client_name"), None);
        assert_eq!(second["grant_types"], json!(["authorization_code", "refresh_token"]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // While a connection is open, its write-ahead log is there too.
            let conn = server_db::open(root.path()).unwrap();
            conn.query_row("SELECT count(*) FROM oauth_clients", [], |r| r.get::<_, i64>(0)).unwrap();
            let db = server_db::path(root.path());
            let wal = db.with_extension("db-wal");
            for file in [&db, &wal] {
                let mode = std::fs::metadata(file).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{}", file.display());
            }
        }
    }

    #[test]
    fn registrations_are_refused_with_the_rfc_7591_errors() {
        let root = tempfile::tempdir().unwrap();
        for (request, code, says) in [
            (json!({}), "invalid_redirect_uri", "redirect_uris"),
            (json!({ "redirect_uris": [] }), "invalid_redirect_uri", "not 1 to 8"),
            (json!({ "redirect_uris": "https://chatgpt.com/cb" }), "invalid_redirect_uri", "list"),
            (json!({ "redirect_uris": ["https://evil.example/cb"] }), "invalid_redirect_uri", "evil.example"),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb", "http://10.0.0.1/cb"] }),
                "invalid_redirect_uri",
                "10.0.0.1",
            ),
            (json!({ "redirect_uris": ["https://chatgpt.com/cb#f"] }), "invalid_redirect_uri", "not allowed"),
            (json!({ "redirect_uris": ["https://chatgpt.com/\u{7}"] }), "invalid_redirect_uri", "printable"),
            (json!({ "redirect_uris": vec!["https://chatgpt.com/cb"; 9] }), "invalid_redirect_uri", "not 1 to 8"),
            (
                json!({ "redirect_uris": [format!("https://chatgpt.com/{}", "x".repeat(500))] }),
                "invalid_redirect_uri",
                "reasonable length",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "grant_types": ["client_credentials"] }),
                "invalid_client_metadata",
                "client_credentials",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "grant_types": ["refresh_token"] }),
                "invalid_client_metadata",
                "authorization_code",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "response_types": ["token"] }),
                "invalid_client_metadata",
                "token",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "client_name": "x".repeat(101) }),
                "invalid_client_metadata",
                "client_name",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "client_name": "Chat\u{202E}TPG" }),
                "invalid_client_metadata",
                "client_name",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "client_name": "Chat\u{200B}GPT" }),
                "invalid_client_metadata",
                "client_name",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "client_name": "Chat\u{00A0}GPT" }),
                "invalid_client_metadata",
                "client_name",
            ),
            (
                json!({ "redirect_uris": ["https://chatgpt.com/cb"], "client_name": 1 }),
                "invalid_client_metadata",
                "string",
            ),
            (json!(["https://chatgpt.com/cb"]), "invalid_client_metadata", "object"),
        ] {
            let (got, why) = register_json(root.path(), request.clone()).unwrap_err();
            assert_eq!(got, code, "{request}: {why}");
            assert!(why.contains(says), "{request}: {why}");
        }
        let (code, _) = register(root.path(), &oauth(), b"{").unwrap().unwrap_err();
        assert_eq!(code, "invalid_client_metadata");
        assert!(all(root.path()).is_empty(), "nothing registered");
    }

    fn all(root: &Path) -> Vec<Registered> {
        load(&server_db::open(root).unwrap()).unwrap()
    }

    /// Exactly these clients registered.
    fn put(root: &Path, clients: Vec<Registered>) {
        change(root, |all| {
            *all = clients;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unused_clients_are_dropped_and_a_full_registry_drops_the_oldest_unused() {
        let root = tempfile::tempdir().unwrap();
        let now = Timestamp::now();
        let at = |ago: Duration| Some(now.minus(ago));
        let client = |id: &str, issued: Duration, used: Option<Duration>| Registered {
            client_id: id.into(),
            client_name: None,
            redirect_uris: vec!["https://chatgpt.com/cb".into()],
            issued_at: now.minus(issued),
            used_at: used.and_then(at),
        };
        let hour = Duration::from_secs(3600);
        let mut clients = vec![
            client("bdc_stale", UNUSED_FOR + hour, None),
            client("bdc_idle", IDLE_FOR * 2, Some(IDLE_FOR + hour)),
            client("bdc_used", IDLE_FOR * 2, Some(IDLE_FOR - hour)),
            client("bdc_new", hour, None),
        ];
        put(root.path(), clients.clone());
        register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap();
        let kept: Vec<String> = all(root.path()).into_iter().map(|c| c.client_id).collect();
        assert_eq!(&kept[..2], ["bdc_used", "bdc_new"]);
        assert_eq!(kept.len(), 3);

        // Full: the oldest never-used client makes room; none, and registration waits.
        clients.clear();
        for i in 0..MAX_CLIENTS {
            let used = (i != 7 && i != 9).then_some(hour);
            clients.push(client(&format!("bdc_{i}"), hour - Duration::from_secs(i as u64), used));
        }
        put(root.path(), clients.clone());
        register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap();
        let ids: Vec<String> = all(root.path()).into_iter().map(|c| c.client_id).collect();
        assert_eq!(ids.len(), MAX_CLIENTS);
        assert!(!ids.contains(&"bdc_7".to_string()) && ids.contains(&"bdc_9".to_string()), "bdc_7 was older");

        for c in &mut clients {
            c.used_at = at(hour);
        }
        put(root.path(), clients);
        let full = register(root.path(), &oauth(), br#"{"redirect_uris":["https://chatgpt.com/cb"]}"#);
        assert!(matches!(full, Err(Error::Busy(_))));
    }

    #[test]
    fn using_a_client_keeps_it() {
        let root = tempfile::tempdir().unwrap();
        let id =
            register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap()["client_id"]
                .as_str()
                .unwrap()
                .to_string();
        assert_eq!(all(root.path())[0].used_at, None);
        touch(root.path(), &id).unwrap();
        let used = all(root.path())[0].used_at.unwrap();
        touch(root.path(), &id).unwrap();
        assert_eq!(all(root.path())[0].used_at, Some(used), "not written again so soon");
        touch(root.path(), "bdc_gone").unwrap();
        touch(root.path(), "https://chatgpt.com/oauth/client.json").unwrap();
    }
}
