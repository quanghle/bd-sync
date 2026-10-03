//! The clients of `bd serve`'s authorization server: public clients (no
//! secret; PKCE protects their codes), each known either by a client ID
//! metadata document (`cimd.rs`) or by registering here (RFC 7591).
//!
//! Registration takes no token, so what it can do is bounded: every
//! redirect URI must be one `[oauth]` allows, a client never used within
//! [`UNUSED_FOR`] of registering or unused for [`IDLE_FOR`] is dropped, and
//! at most [`MAX_CLIENTS`] are kept (a full registry drops its oldest
//! never-used client). Registered clients live in `<root>/oauth-clients.json`,
//! changed under `<root>/oauth-clients.lock`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::cimd::{self, Documents};
use crate::auth;
use crate::oauth::OauthConfig;

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
    let file = load(&path(root))?;
    match file.clients.into_iter().find(|c| c.client_id == id) {
        Some(c) => Ok(Client { id: c.client_id, name: c.client_name, redirect_uris: c.redirect_uris, document: false }),
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
    let path = path(root);
    // Once an hour is enough to keep it, and saves a write per request.
    let recent = |c: &Registered| c.used_at.is_some_and(|at| now.since(at) < 3_600_000);
    if load(&path)?.clients.iter().any(|c| c.client_id == id && recent(c)) {
        return Ok(());
    }
    let _lock = lock(root)?;
    let mut file = load(&path)?;
    let Some(client) = file.clients.iter_mut().find(|c| c.client_id == id) else { return Ok(()) };
    client.used_at = Some(now);
    auth::save_json(&path, &file)
}

/// `uri` without its port if it is an http URI to this machine.
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
        let types = check_types(request)?;
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
    let path = path(root);
    let _lock = lock(root)?;
    let mut file = load(&path)?;
    file.clients.retain(|c| match c.used_at {
        Some(at) => now.since(at) < millis(IDLE_FOR),
        None => now.since(c.issued_at) < millis(UNUSED_FOR),
    });
    if file.clients.len() >= MAX_CLIENTS {
        let unused = file.clients.iter().enumerate().filter(|(_, c)| c.used_at.is_none());
        match unused.min_by_key(|(_, c)| c.issued_at).map(|(i, _)| i) {
            Some(oldest) => drop(file.clients.remove(oldest)),
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
    file.clients.push(client);
    auth::save_json(&path, &file)?;
    Ok(Ok(answer))
}

/// `grant_types` and `response_types`, which may be left out: of the ones
/// bd supports, with authorization codes.
pub fn check_types(meta: &Map<String, Value>) -> std::result::Result<(Vec<String>, Vec<String>), Refusal> {
    let list = |field: &str, supported: &[&str], needed: &str, default: &[&str]| {
        let Some(value) = meta.get(field) else { return Ok(default.iter().map(|s| s.to_string()).collect()) };
        let list = string_list(Some(value), field, 8)?;
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

/// `client_name`, if any: printable, trimmed, at most [`MAX_NAME`] characters.
pub fn client_name(value: Option<&Value>) -> std::result::Result<Option<String>, Refusal> {
    let name = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.trim(),
        Some(_) => return Err(("invalid_client_metadata", "client_name is not a string".into())),
    };
    if name.chars().count() > MAX_NAME || name.chars().any(char::is_control) {
        let why = format!("client_name is longer than {MAX_NAME} characters, or not printable");
        return Err(("invalid_client_metadata", why));
    }
    Ok((!name.is_empty()).then(|| name.to_string()))
}

#[derive(Serialize, Deserialize)]
struct ClientFile {
    version: u32,
    clients: Vec<Registered>,
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

fn path(root: &Path) -> PathBuf {
    root.join("oauth-clients.json")
}

fn lock(root: &Path) -> Result<auth::FileLock> {
    auth::lock_file(&root.join("oauth-clients.lock"), "the registered OAuth clients")
}

fn load(path: &Path) -> Result<ClientFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| Error::invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ClientFile { version: 1, clients: Vec::new() }),
        Err(e) => Err(Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))),
    }
}

fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth() -> OauthConfig {
        OauthConfig { redirect_hosts: vec!["chatgpt.com".into(), "claude.ai".into()], loopback_redirects: true }
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
        let narrower = OauthConfig { redirect_hosts: vec!["chatgpt.com".into()], loopback_redirects: false };
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
            let mode = std::fs::metadata(path(root.path())).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
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
        assert!(!path(root.path()).exists(), "nothing registered");
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
        auth::save_json(&path(root.path()), &ClientFile { version: 1, clients: clients.clone() }).unwrap();
        register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap();
        let kept: Vec<String> = load(&path(root.path())).unwrap().clients.into_iter().map(|c| c.client_id).collect();
        assert_eq!(&kept[..2], ["bdc_used", "bdc_new"]);
        assert_eq!(kept.len(), 3);

        // Full: the oldest never-used client makes room; none, and registration waits.
        clients.clear();
        for i in 0..MAX_CLIENTS {
            let used = (i != 7 && i != 9).then_some(hour);
            clients.push(client(&format!("bdc_{i}"), hour - Duration::from_secs(i as u64), used));
        }
        auth::save_json(&path(root.path()), &ClientFile { version: 1, clients: clients.clone() }).unwrap();
        register_json(root.path(), json!({ "redirect_uris": ["https://chatgpt.com/cb"] })).unwrap();
        let ids: Vec<String> = load(&path(root.path())).unwrap().clients.into_iter().map(|c| c.client_id).collect();
        assert_eq!(ids.len(), MAX_CLIENTS);
        assert!(!ids.contains(&"bdc_7".to_string()) && ids.contains(&"bdc_9".to_string()), "bdc_7 was older");

        for c in &mut clients {
            c.used_at = at(hour);
        }
        auth::save_json(&path(root.path()), &ClientFile { version: 1, clients }).unwrap();
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
        assert_eq!(load(&path(root.path())).unwrap().clients[0].used_at, None);
        touch(root.path(), &id).unwrap();
        let used = load(&path(root.path())).unwrap().clients[0].used_at.unwrap();
        touch(root.path(), &id).unwrap();
        assert_eq!(load(&path(root.path())).unwrap().clients[0].used_at, Some(used), "not written again so soon");
        touch(root.path(), "bdc_gone").unwrap();
        touch(root.path(), "https://chatgpt.com/oauth/client.json").unwrap();
    }
}
