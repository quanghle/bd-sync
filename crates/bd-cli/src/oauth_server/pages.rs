//! The pages people see during an authorization (`authorize.rs`): the
//! consent page and refusals. Every value shown is escaped, and each page
//! comes with the Content-Security-Policy it needs: its inline style, and
//! forms posting only where the consent goes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

/// An HTML page, its status, and its Content-Security-Policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub status: u16,
    pub html: String,
    pub csp: String,
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;\
line-height:1.5;color:#1f2328}dt{font-weight:600}dd{margin:0 0 .6rem}\
button{font-size:1rem;padding:.4rem 1.2rem;margin-right:.6rem}.note{color:#59636e}";

/// What the consent page shows.
pub struct Consent<'a> {
    /// The client's name, or what identifies it.
    pub client: &'a str,
    /// Where that name comes from.
    pub client_note: &'a str,
    /// The host the browser returns to with the authorization.
    pub returns_to: &'a str,
    pub workspace: &'a str,
    pub login: &'a str,
    pub actor: &'a str,
    pub role: &'a str,
    pub kind: &'a str,
    /// What let the account in.
    pub via: &'a str,
    /// The consent's id, posted back with the decision.
    pub id: &'a str,
    /// Where the decision is posted.
    pub action: &'a str,
    /// Origins the form may post to, and be redirected to after.
    pub form_origins: &'a [&'a str],
}

/// The page asking whether a client may use a workspace for an account.
pub fn consent(c: &Consent<'_>) -> Page {
    let body = format!(
        "<h1>Allow access to bd workspace {workspace}?</h1>\n\
<p><b>{client}</b> asks to use workspace <b>{workspace}</b> for GitHub user <b>{login}</b>.</p>\n\
<dl>\n\
<dt>Application</dt><dd>{client} <span class=\"note\">({client_note})</span></dd>\n\
<dt>Returns to</dt><dd>{returns_to}</dd>\n\
<dt>Acts as</dt><dd>{actor}</dd>\n\
<dt>Access</dt><dd>role {role}, kind {kind}</dd>\n\
<dt>Granted by</dt><dd>{via}</dd>\n\
</dl>\n\
<p class=\"note\">Approve only an application started moments ago from this browser. \
The access lasts until revoked on the bd server.</p>\n\
<form method=\"post\" action=\"{action}\">\n\
<input type=\"hidden\" name=\"consent\" value=\"{id}\">\n\
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>\n\
<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\n\
</form>\n",
        workspace = escape(c.workspace),
        client = escape(c.client),
        client_note = escape(c.client_note),
        login = escape(c.login),
        returns_to = escape(c.returns_to),
        actor = escape(c.actor),
        role = escape(c.role),
        kind = escape(c.kind),
        via = escape(c.via),
        action = escape(c.action),
        id = escape(c.id),
    );
    let mut origins: Vec<&str> = Vec::new();
    for o in c.form_origins {
        if !origins.contains(o) {
            origins.push(o);
        }
    }
    page(200, "Allow access to bd", &body, &origins.join(" "))
}

/// A page saying why an authorization cannot go on, with a link back to
/// the application if it may be told.
pub fn refusal(status: u16, title: &str, why: &str, back: Option<&str>) -> Page {
    let mut body = format!("<h1>{}</h1>\n<p>{}</p>\n", escape(title), escape(why));
    if let Some(url) = back {
        body.push_str(&format!("<p><a href=\"{}\">Return to the application</a></p>\n", escape(url)));
    }
    page(status, title, &body, "'none'")
}

fn page(status: u16, title: &str, body: &str, form_action: &str) -> Page {
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n{body}</body>\n</html>\n",
        escape(title)
    );
    let csp = format!(
        "default-src 'none'; style-src 'sha256-{}'; form-action {form_action}; frame-ancestors 'none'; base-uri 'none'",
        STANDARD.encode(Sha256::digest(STYLE.as_bytes()))
    );
    Page { status, html, csp }
}

/// `s` as HTML text or attribute value.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_escape_what_they_show() {
        assert_eq!(escape(r#"<a href="x">'&'</a>"#), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
        let evil = "<script>alert(1)</script>\"";
        let page = consent(&Consent {
            client: evil,
            client_note: evil,
            returns_to: evil,
            workspace: evil,
            login: evil,
            actor: evil,
            role: "write",
            kind: "agent",
            via: evil,
            id: evil,
            action: "https://bd.example.com/oauth/consent",
            form_origins: &["https://bd.example.com", "https://app.example", "https://bd.example.com"],
        });
        assert_eq!(page.status, 200);
        assert!(!page.html.contains("<script>"), "{}", page.html);
        assert!(page.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;"));
        assert!(page.html.contains("action=\"https://bd.example.com/oauth/consent\""));
        assert!(page.csp.contains("form-action https://bd.example.com https://app.example;"), "{}", page.csp);
        assert!(page.csp.starts_with("default-src 'none'; style-src 'sha256-"));
        assert!(page.csp.ends_with("frame-ancestors 'none'; base-uri 'none'"));

        let page = refusal(403, "Not <allowed>", "because & why", Some("https://app.example/cb?error=x&state=y"));
        assert_eq!(page.status, 403);
        assert!(page.html.contains("<title>Not &lt;allowed&gt;</title>"));
        assert!(page.html.contains("<p>because &amp; why</p>"));
        assert!(page.html.contains("href=\"https://app.example/cb?error=x&amp;state=y\""));
        assert!(page.csp.contains("form-action 'none';"));
        assert!(!refusal(400, "t", "w", None).html.contains("<a "));
    }

    #[test]
    fn the_policy_allows_the_inline_style() {
        let page = refusal(400, "t", "w", None);
        let start = page.html.find("<style>").unwrap() + "<style>".len();
        let end = page.html.find("</style>").unwrap();
        let hash = STANDARD.encode(Sha256::digest(&page.html.as_bytes()[start..end]));
        assert!(page.csp.contains(&format!("style-src 'sha256-{hash}'")));
    }
}
