//! `<root>/auth.toml`, as written and checked: the tables, their fields,
//! and the rules about them (`parse`).

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    #[serde(default)]
    pub(super) sign_in: Option<SignInDoc>,
    #[serde(default)]
    pub(super) github: Option<GithubDoc>,
    #[serde(default)]
    pub(super) oidc: std::collections::BTreeMap<String, crate::oidc::OidcDoc>,
    #[serde(default)]
    pub(super) oauth: Option<OauthDoc>,
    #[serde(default)]
    pub(super) authorizer: Option<crate::authorizer::AuthorizerDoc>,
}

/// `[sign_in]`: how long the tokens of any provider's sign-ins last.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInDoc {
    #[serde(default)]
    pub(super) token_ttl: Option<String>,
    #[serde(default)]
    pub(super) refresh_limit: Option<String>,
    #[serde(default)]
    pub(super) refresh_idle: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthDoc {
    #[serde(default)]
    pub(super) redirect_hosts: Vec<String>,
    #[serde(default)]
    pub(super) redirect_uris: Vec<String>,
    #[serde(default)]
    pub(super) loopback_redirects: bool,
    #[serde(default)]
    pub(super) registration: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GithubDoc {
    pub(super) client_id: String,
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) api_url: Option<String>,
    #[serde(default)]
    pub(super) private_key: Option<PathBuf>,
    #[serde(default)]
    pub(super) ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub(super) client_secret_file: Option<PathBuf>,
    #[serde(default)]
    pub(super) deny: Vec<String>,
    #[serde(default)]
    pub(super) allow: Vec<RuleDoc>,
}

/// `[oauth]`: where the authorization server may send people back to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OauthConfig {
    /// Hosts of https redirect URIs, lowercased: any path on them.
    pub redirect_hosts: Vec<String>,
    /// https redirect URIs allowed exactly as written.
    pub redirect_uris: Vec<String>,
    /// Whether http redirect URIs to this machine are allowed (desktop clients).
    pub loopback_redirects: bool,
    /// Whether clients may register (RFC 7591); clients with a metadata
    /// document need not.
    pub registration: bool,
}

impl OauthConfig {
    /// Whether a client may be sent back to `uri`: one of `redirect_uris`
    /// exactly, https on one of `redirect_hosts` without a port, or, with
    /// `loopback_redirects`, http to 127.0.0.1, [::1] or localhost on any
    /// port (RFC 8252). Never with user info or a fragment.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        let Some((scheme, rest)) = uri.split_once("://") else { return false };
        if uri.contains('#') || uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return false;
        }
        let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
        if !authority.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
            return false;
        }
        let (host, port) = match authority.rfind(':') {
            Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(&authority[i + 1..])),
            _ => (authority, None),
        };
        let host = host.to_ascii_lowercase();
        match scheme {
            "https" if self.redirect_uris.iter().any(|r| r == uri) => true,
            "https" => port.is_none() && self.redirect_hosts.contains(&host),
            "http" => {
                self.loopback_redirects
                    && matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost")
                    && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
            }
            _ => false,
        }
    }
}

/// A host name as `redirect_hosts` takes it: a DNS name of two labels or
/// more, lowercased; no IP address, port or wildcard.
pub(crate) fn dns_name(raw: &str) -> Option<String> {
    let host = raw.trim().to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let label = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let numeric = labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    (host.len() <= 253 && labels.len() >= 2 && labels.iter().all(label) && !numeric).then_some(host)
}

fn oauth_config(o: OauthDoc) -> std::result::Result<OauthConfig, String> {
    let mut redirect_hosts = Vec::new();
    for raw in &o.redirect_hosts {
        let Some(host) = dns_name(raw) else {
            return Err(format!(
                "oauth.redirect_hosts {raw:?} is not a host name such as chatgpt.com (loopback_redirects = true \
                 allows this machine)"
            ));
        };
        if !redirect_hosts.contains(&host) {
            redirect_hosts.push(host);
        }
    }
    let mut redirect_uris = Vec::new();
    for uri in &o.redirect_uris {
        // As any redirect URI must be: https, a host name, no port, user info or fragment.
        let host = uri
            .strip_prefix("https://")
            .and_then(|rest| dns_name(&rest[..rest.find(['/', '?']).unwrap_or(rest.len())]));
        let shaped = OauthConfig {
            redirect_hosts: host.into_iter().collect(),
            redirect_uris: Vec::new(),
            loopback_redirects: false,
            registration: false,
        };
        if !shaped.allows_redirect(uri) {
            return Err(format!(
                "oauth.redirect_uris {uri:?} is not an https URL of a host name, without a port, user \
                                information or fragment"
            ));
        }
        if !redirect_uris.contains(uri) {
            redirect_uris.push(uri.clone());
        }
    }
    if redirect_hosts.is_empty() && redirect_uris.is_empty() && !o.loopback_redirects {
        return Err("[oauth] allows no redirect URIs, so no client may sign anyone in: name redirect_uris or \
                    redirect_hosts, or set loopback_redirects = true"
            .into());
    }
    let registration = o.registration.unwrap_or(true);
    Ok(OauthConfig { redirect_hosts, redirect_uris, loopback_redirects: o.loopback_redirects, registration })
}

pub(super) fn parse(text: &str) -> std::result::Result<Option<SignIn>, String> {
    let doc: Doc = toml::from_str(text).map_err(|e| {
        // The parser's own text quotes the file, which may hold what should not be shown: name the line only.
        let line = e.span().map(|s| text.as_bytes()[..s.start.min(text.len())].iter().filter(|&&b| b == b'\n').count());
        let message = e.message().trim_end();
        let moved = ["token_ttl", "refresh_limit", "refresh_idle"]
            .iter()
            .any(|f| message.contains(&format!("unknown field `{f}`")));
        let hint = if moved { " (token_ttl, refresh_limit and refresh_idle are in [sign_in] now)" } else { "" };
        format!("{}{message}{hint}", line.map(|n| format!("line {}: ", n + 1)).unwrap_or_default())
    })?;
    if doc.github.is_none() && doc.oidc.is_empty() {
        return match doc.oauth.is_some() || doc.authorizer.is_some() || doc.sign_in.is_some() {
            true => {
                Err("[sign_in], [authorizer] and [oauth] need a provider to sign in with: [github] or [oidc.<name>]"
                    .into())
            }
            false => Ok(None),
        };
    }
    let times = doc.sign_in.unwrap_or_default();
    let duration = |field: &str, raw: &Option<String>, default: Duration| {
        let Some(raw) = raw else { return Ok(default) };
        let d = bd_core::time::parse_duration(raw).map_err(|e| format!("sign_in.{field}: {e}"))?;
        match (TTL_RANGE.0..=TTL_RANGE.1).contains(&d) {
            true => Ok(d),
            false => Err(format!("sign_in.{field} {raw:?}: use 5m to 366d")),
        }
    };
    let token_ttl = duration("token_ttl", &times.token_ttl, DEFAULT_TTL)?;
    let refresh_limit = duration("refresh_limit", &times.refresh_limit, DEFAULT_REFRESH_LIMIT)?;
    let refresh_idle = duration("refresh_idle", &times.refresh_idle, DEFAULT_REFRESH_IDLE)?;
    if !(token_ttl <= refresh_idle && refresh_idle <= refresh_limit) {
        return Err("sign_in.token_ttl, refresh_idle and refresh_limit must each be at most the next (by default \
                    1h, 7d and 30d)"
            .into());
    }
    let authorizer = doc.authorizer.map(crate::authorizer::parse).transpose()?;
    if let Some(grace) = authorizer.as_ref().and_then(|a| a.refresh_grace)
        && !(token_ttl <= grace && grace <= refresh_idle)
    {
        return Err("authorizer.refresh_grace must be at least sign_in.token_ttl (or no refresh is ever within \
                        it) and at most sign_in.refresh_idle"
            .into());
    }
    let github = doc.github.map(|g| github(g, authorizer.is_some())).transpose()?;
    let mut oidc = Vec::new();
    for (name, o) in doc.oidc {
        let parsed = crate::oidc::parse(&name, o)?;
        // Accounts are an issuer's: two names for one would let a login given up under one be taken under the other.
        if let Some(other) = oidc.iter().find(|o: &&crate::oidc::Oidc| o.issuer == parsed.issuer) {
            return Err(format!(
                "[oidc.{}] and [oidc.{}] name the same issuer {}: one table per provider",
                other.name, parsed.name, parsed.issuer
            ));
        }
        oidc.push(parsed);
    }
    for o in &oidc {
        match (o.allow.is_empty(), &authorizer) {
            (true, None) => {
                return Err(format!(
                    "[oidc.{}] lets nobody in: add [[oidc.{}.allow]] rules, or an [authorizer]",
                    o.name, o.name
                ));
            }
            (false, Some(_)) => {
                return Err(format!(
                    "[authorizer] decides who may sign in instead of [[oidc.{}.allow]] rules: keep one of them",
                    o.name
                ));
            }
            _ => {}
        }
    }
    let oauth = doc.oauth.map(oauth_config).transpose()?;
    let sign_in = SignIn { github, oidc, token_ttl, refresh_limit, refresh_idle, authorizer, oauth };
    let secret = sign_in.github.as_ref().is_some_and(|g| g.client_secret_file.is_some());
    if sign_in.oauth.is_some() && sign_in.browser_providers().is_empty() {
        return Err("[oauth] needs a provider people sign in with in a browser: github.client_secret_file (GitHub's \
                    web flow gives tokens only with a client secret of the GitHub App), or an [oidc.<name>]"
            .into());
    }
    if sign_in.oauth.is_none() && secret {
        return Err("github.client_secret_file serves [oauth]'s web sign-in only: add [oauth], or leave it out".into());
    }
    Ok(Some(sign_in))
}

/// `[github]`, decided by its rules unless `authorized` (an `[authorizer]`).
pub(super) fn github(g: GithubDoc, authorized: bool) -> std::result::Result<Github, String> {
    let client_id = g.client_id.trim().to_string();
    if client_id.is_empty() || client_id.len() > 100 || !client_id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "github.client_id {:?} is not the client ID of a GitHub OAuth app or GitHub App",
            g.client_id
        ));
    }
    let url = base_url("url", g.url.as_deref().unwrap_or("https://github.com"))?;
    let api_url = match &g.api_url {
        Some(raw) => base_url("api_url", raw)?,
        None if url.eq_ignore_ascii_case("https://github.com") => "https://api.github.com".to_string(),
        None => format!("{url}/api/v3"),
    };
    if g.private_key.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        return Err("github.private_key is empty: name the GitHub App's private key file, or leave it out".into());
    }
    let private_key = g.private_key;
    if g.ca_cert.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        return Err("github.ca_cert is empty: name the file of the CA certificates GitHub's are checked against, or \
                    leave it out"
            .into());
    }
    let client_secret_file = g.client_secret_file;
    if client_secret_file.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        return Err("github.client_secret_file is empty: name the file holding a client secret of the GitHub App, \
                    or leave it out"
            .into());
    }
    match (g.allow.is_empty(), authorized) {
        (true, false) => {
            return Err("[github] has no [[github.allow]] rules, so no GitHub account may sign in: add rules, or an \
                        [authorizer], or remove [github]"
                .into());
        }
        (false, true) => {
            return Err(
                "[authorizer] decides who may sign in instead of [[github.allow]] rules: keep one of them".into()
            );
        }
        _ => {}
    }
    let allow = rules("github", g.allow, Proves::Github)?;
    let deny = deny_list("github", g.deny, Proves::Github)?;
    let (ca_cert, roots) = (g.ca_cert, None);
    Ok(Github {
        client_id,
        url,
        api_url,
        private_key,
        app: None,
        ca_cert,
        roots,
        client_secret_file,
        client_secret: None,
        deny,
        allow,
    })
}

/// `https://host[:port][/path]`, without a trailing slash; `http` only to
/// this machine (a stand-in for GitHub).
fn base_url(field: &str, raw: &str) -> std::result::Result<String, String> {
    let url = raw.trim().trim_end_matches('/');
    // A URL with credentials in it is not repeated.
    let shown = if raw.contains('@') { String::new() } else { format!(" {raw:?}") };
    let bad = |why: &str| format!("github.{field}{shown} {why}");
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad("has no scheme"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || url.contains(['?', '#'])
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(bad("needs a host, and no credentials, query or fragment"));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(url.to_string()),
        "http" if bd_cli::remote::is_loopback(authority) => Ok(url.to_string()),
        _ => Err(bad("must use https")),
    }
}

/// A login, organization or team slug, as it may stand in a URL path:
/// letters, digits, `-`, `_` and `.`, from a letter or digit on.
pub(super) fn github_name(s: &str) -> bool {
    s.len() <= 100
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
