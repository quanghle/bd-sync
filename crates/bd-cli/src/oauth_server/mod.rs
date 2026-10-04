//! `bd serve`'s OAuth authorization server for MCP clients, which `[oauth]`
//! in `auth.toml` turns on (`oauth.rs`): its metadata (RFC 8414) and
//! endpoints. Its issuer is the server's `--public-url`, the very string
//! clients compare with the metadata's `issuer` and with the `iss` of
//! authorization responses (RFC 9207), and the protected resource metadata
//! of every MCP endpoint names it (`mcp/http.rs`).

use serde_json::{Value, json};

pub mod authorize;
pub mod cimd;
pub mod clients;
pub mod form;
pub mod pages;
pub mod token;

/// Where the metadata is served: this, then the issuer's path (RFC 8414
/// section 3.1).
pub const WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";
/// The endpoints, under the issuer.
pub const AUTHORIZE: &str = "/oauth/authorize";
pub const TOKEN: &str = "/oauth/token";
pub const REGISTER: &str = "/oauth/register";
pub const REVOKE: &str = "/oauth/revoke";
/// Where GitHub sends people back to after its web sign-in: the callback
/// URL of the GitHub App. Each provider has its own: [`callback`].
pub const CALLBACK: &str = "/oauth/github/callback";
/// Where the page offering several providers sends the person's choice.
pub const CHOOSE: &str = "/oauth/choose";

/// Where `provider` sends people back to after signing in, under the
/// issuer: its client's redirect URI there (`/oauth/github/callback` for
/// the GitHub App).
pub fn callback(provider: &str) -> String {
    format!("/oauth/{provider}/callback")
}

/// The provider whose callback `path` (under the issuer) is, if it is one.
pub fn callback_provider(path: &str) -> Option<&str> {
    let name = path.strip_prefix("/oauth/")?.strip_suffix("/callback")?;
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    (!name.is_empty() && name.len() <= 32 && name.chars().all(plain)).then_some(name)
}
/// Where providers post their account notifications (Apple's server-to-server
/// notifications): `/oauth/<provider>/events`, all routed here.
pub const EVENTS: &str = "/oauth/events";

/// The provider whose account notifications `path` (under the issuer) takes, if it does.
pub fn events_provider(path: &str) -> Option<&str> {
    let name = path.strip_prefix("/oauth/")?.strip_suffix("/events")?;
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    (!name.is_empty() && name.len() <= 32 && name.chars().all(plain)).then_some(name)
}

/// Where the consent page posts its decision.
pub const CONSENT: &str = "/oauth/consent";

/// The issuer of a server whose public URL is `public_url` (normalized by
/// `mcp::http::public_url`): https, or http to this machine.
pub fn issuer(public_url: Option<&str>) -> Result<String, String> {
    let Some(url) = public_url else {
        return Err("[oauth] needs bd serve --public-url (or BD_SERVE_PUBLIC_URL): the issuer MCP clients check".into());
    };
    let authority = url.split_once("://").map_or("", |(_, rest)| rest.split('/').next().unwrap_or_default());
    if url.starts_with("https://") || url.starts_with("http://") && crate::remote::is_loopback(authority) {
        Ok(url.to_string())
    } else {
        Err(format!("[oauth] needs an https --public-url, the issuer MCP clients check: not {url}"))
    }
}

/// The path of `issuer`'s metadata.
pub fn metadata_path(issuer: &str) -> String {
    let rest = issuer.split_once("://").map_or("", |(_, rest)| rest);
    format!("{WELL_KNOWN}{}", rest.find('/').map_or("", |i| &rest[i..]))
}

/// The authorization server metadata of `issuer`: authorization code with
/// PKCE (S256) for public clients, identified by a client ID metadata
/// document or registered (RFC 7591), with rotating refresh tokens.
pub fn metadata(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}{AUTHORIZE}"),
        "token_endpoint": format!("{issuer}{TOKEN}"),
        "registration_endpoint": format!("{issuer}{REGISTER}"),
        "revocation_endpoint": format!("{issuer}{REVOKE}"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_issuer_is_the_public_url() {
        assert_eq!(issuer(Some("https://bd.example.com")).unwrap(), "https://bd.example.com");
        assert_eq!(issuer(Some("https://example.com/bd")).unwrap(), "https://example.com/bd");
        assert_eq!(issuer(Some("http://127.0.0.1:7420")).unwrap(), "http://127.0.0.1:7420", "this machine");
        assert!(issuer(None).unwrap_err().contains("--public-url"));
        assert!(issuer(Some("http://bd.example.com")).unwrap_err().contains("https"));
    }

    #[test]
    fn metadata_is_served_under_the_issuers_path() {
        assert_eq!(metadata_path("https://bd.example.com"), "/.well-known/oauth-authorization-server");
        assert_eq!(metadata_path("https://example.com/bd"), "/.well-known/oauth-authorization-server/bd");
        assert_eq!(metadata_path("http://127.0.0.1:7420/a/b"), "/.well-known/oauth-authorization-server/a/b");
        let m = metadata("https://example.com/bd");
        assert_eq!(m["issuer"], "https://example.com/bd");
        assert_eq!(m["authorization_endpoint"], "https://example.com/bd/oauth/authorize");
        assert_eq!(m["token_endpoint"], "https://example.com/bd/oauth/token");
        assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(m["authorization_response_iss_parameter_supported"], true);
        assert_eq!(m["client_id_metadata_document_supported"], true);
    }
}
