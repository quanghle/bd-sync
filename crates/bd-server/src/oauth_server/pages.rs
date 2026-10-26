//! The pages people see during an authorization (`authorize/`): the
//! consent page, refusals, and the page sending the browser on; and those
//! of a human gate's approval in the browser: the approval page and its
//! notices. Every value shown is escaped, and each page comes with the
//! Content-Security-Policy it needs: its inline style, and forms posting
//! only where the consent or the approval goes. The pages fetch nothing:
//! icons are inline SVG drawn with presentation attributes, which the
//! policy's `style-src` does not cover, and a client's logo comes inside
//! the page, as a `data:` URL.
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

/// The pages' style: black and white, no boxes, lines or shadows, set
/// apart by space alone; black on white or white on black as the browser
/// prefers. The policy allows it by its hash, so any change here is picked
/// up by `page`.
const STYLE: &str = r#"
:root{color-scheme:light dark;--bg:#fff;--fg:#000}
@media (prefers-color-scheme:dark){:root{--bg:#000;--fg:#fff}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0 auto;max-width:560px;min-height:100vh;padding:48px 24px;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
-webkit-font-smoothing:antialiased}
@media (max-width:480px){body{padding:32px 20px}}
.choices{display:grid;gap:10px;margin:8px 0 16px}
.bar{display:flex;flex-wrap:wrap;align-items:center;gap:12px 24px;margin:8px 0 0}
.brand{display:flex;align-items:center;gap:8px;margin-left:auto;font-weight:600}
.brand small{font-size:inherit;font-weight:400;opacity:.55}
.mark{width:20px;height:20px;flex:none}
.mark rect{fill:var(--fg)}.mark circle{fill:var(--bg)}.mark path{stroke:var(--bg)}
main{display:block}
h1{margin:0 0 8px;font-size:28px;line-height:1.2;font-weight:600;letter-spacing:-.03em;text-wrap:balance}
@media (max-width:480px){h1{font-size:24px}}
p{margin:0 0 16px}
.lead{opacity:.7;text-wrap:pretty}
.lead b{opacity:1}
b{font-weight:600}
a{color:inherit;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:4px}
code{font:.92em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.link{display:flex;align-items:center;justify-content:center;gap:10px;margin:0 0 20px}
.avatar{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;flex:none;
font-size:17px;font-weight:600;background:var(--fg);color:var(--bg)}
.avatar .mark{width:40px;height:40px}
.avatar.logo{background:#fff}
.avatar.logo img{max-width:28px;max-height:28px}
.dots{display:flex;gap:4px}
.dots i{width:3px;height:3px;border-radius:50%;background:var(--fg)}
.facts{margin:20px 0;display:grid;gap:8px}
.facts div{display:grid;grid-template-columns:7rem 1fr;gap:16px}
@media (max-width:480px){.facts div{grid-template-columns:1fr;gap:0}}
dt{opacity:.55}
dd{margin:0;min-width:0;overflow-wrap:break-word}
.note{display:block;opacity:.55;font-size:.88em}
.note-line{display:block}
.note-line .note{display:inline}
.callout{display:flex;gap:10px;align-items:flex-start;margin:0 0 20px}
.callout svg{width:18px;height:18px;flex:none;margin-top:2px}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px 24px;margin:0}
button,.button{appearance:none;border:0;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;
height:40px;padding:0 20px;background:transparent;color:var(--fg);font:inherit;font-weight:600;text-decoration:none;
cursor:pointer;transition:opacity .15s}
button:hover,.button:hover{opacity:.7}
button.primary,.button{background:var(--fg);color:var(--bg)}
.actions button:not(.primary){padding:0;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:4px}
button:focus-visible,.button:focus-visible,a:focus-visible{outline:2px solid var(--fg);outline-offset:4px}
@media (prefers-reduced-motion:reduce){button,.button{transition:none}}
"#;

/// bd's mark: three beads on a thread.
const MARK: &str = "<svg class=\"mark\" viewBox=\"0 0 32 32\" aria-hidden=\"true\">\
<rect width=\"32\" height=\"32\" rx=\"9\" fill=\"currentColor\"/>\
<path d=\"M9.5 22.5 22.5 9.5\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" opacity=\".5\"/>\
<circle cx=\"9.5\" cy=\"22.5\" r=\"3.6\" fill=\"#fff\"/><circle cx=\"16\" cy=\"16\" r=\"3.6\" fill=\"#fff\"/>\
<circle cx=\"22.5\" cy=\"9.5\" r=\"3.6\" fill=\"#fff\"/></svg>";

/// A shield, for the consent page's warning.
const SHIELD: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" \
stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">\
<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/><path d=\"M12 8v4\"/><path d=\"M12 16h.01\"/></svg>";

/// The consent page's script, against DoubleClickjacking: a page asks for a
/// double click, closes itself on the first, and the second lands on a
/// consent page left behind it, which framing rules do not stop. The form
/// is not sent unless the window has had focus for 600 ms: the second click
/// of a double click comes sooner. The buttons themselves stay enabled, so
/// that screen readers and voice control, which press them without moving
/// a pointer or a key, work. Without scripts the form is sent as it is.
const ARMING: &str = "(function(){\
var since=document.hasFocus()?Date.now():0;\
addEventListener('focus',function(){since=Date.now();});\
addEventListener('blur',function(){since=0;});\
document.addEventListener('visibilitychange',function(){\
since=!document.hidden&&document.hasFocus()?Date.now():0;});\
document.querySelector('form.actions').addEventListener('submit',function(e){\
if(!since||Date.now()-since<600)e.preventDefault();});\
})();";

/// What vouches for a client being who it says.
pub enum Identity<'a> {
    /// Its metadata document, served at `url` on `host`. Anyone who can
    /// serve a file there can publish one: the page names the address, and
    /// vouches for nothing more.
    Document { url: &'a str, host: &'a str },
    /// Nothing: it registered itself with this server as `client_id`.
    Registered { client_id: &'a str },
}

/// What the consent page shows.
pub struct Consent<'a> {
    /// The client's name, or what identifies it.
    pub client: &'a str,
    pub identity: Identity<'a>,
    /// The client's logo, from its metadata document only, as the `data:`
    /// URL of an image `bd serve` fetched (`cimd`).
    pub logo: Option<&'a str>,
    /// Where the browser returns with the authorization.
    pub redirect_uri: &'a str,
    /// Whether that is this machine, where any program may be listening.
    pub loopback: bool,
    /// The host the browser returns to, when it is not the host of the
    /// client's metadata document (nor this machine).
    pub elsewhere: Option<&'a str>,
    /// How long access lasts, as words following "Access lasts".
    pub lasts: &'a str,
    pub workspace: &'a str,
    /// The provider the person signed in with, as the page names it.
    pub provider: &'a str,
    pub login: &'a str,
    pub actor: &'a str,
    /// What the access allows, in words.
    pub access: &'a str,
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
/// Deny comes first, so neither keyboard order nor habit lands on Allow.
pub fn consent(c: &Consent<'_>) -> Page {
    let initial: String = c.client.chars().find(|c| c.is_alphanumeric()).unwrap_or('?').to_uppercase().collect();
    // A logo has no size of its own here, so one that does not load takes
    // no room (and shows no broken-image icon).
    let avatar = match c.logo {
        Some(logo) => format!(
            "<div class=\"avatar logo\"><img src=\"{}\" alt=\"\" referrerpolicy=\"no-referrer\"></div>",
            escape(logo)
        ),
        None => format!("<div class=\"avatar\">{}</div>", escape(&initial)),
    };
    let client = escape(c.client);
    let (from, details) = match c.identity {
        Identity::Document { url, host } => {
            let what = if c.logo.is_some() { "Its name and logo come" } else { "Its name comes" };
            (
                format!(" ({})", escape(host)),
                format!("<code>{}</code><span class=\"note\">{what} from this address</span>", escape(url)),
            )
        }
        Identity::Registered { client_id } => (
            String::new(),
            format!(
                "The application itself<span class=\"note\">Not verified: it registered with this server as \
client <code>{}</code></span>",
                escape(client_id)
            ),
        ),
    };
    let mut warnings = String::new();
    if let Identity::Registered { .. } = c.identity {
        warnings.push_str(&format!(
            "<p class=\"callout\">{SHIELD}<span><b>Unverified application.</b> {client} registered itself with \
this server, so its name is not verified: anyone can register under any name.</span></p>\n"
        ));
    }
    if let (Some(elsewhere), Identity::Document { host, .. }) = (c.elsewhere, &c.identity) {
        warnings.push_str(&format!(
            "<p class=\"callout\">{SHIELD}<span><b>Returns to another site.</b> The answer goes to <b>{}</b>, \
not {}, where the application's details are published. Allow only if you expect {client} there.</span></p>\n",
            escape(elsewhere),
            escape(host)
        ));
    }
    if c.loopback {
        warnings.push_str(&format!(
            "<p class=\"callout\">{SHIELD}<span><b>Returns to this computer.</b> The answer goes to a program on \
this computer, and any program running here could be posing as {client}.</span></p>\n"
        ));
    }
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\">{avatar}\
<div class=\"dots\"><i></i><i></i><i></i></div><div class=\"avatar\">{MARK}</div></div>\n\
<h1>Connect {client} to {workspace}?</h1>\n\
<p class=\"lead\">You're signed in to {provider} as <b>{login}</b>. \
<b>{client}</b>{from} wants to work in the workspace <b>{workspace}</b> for you.</p>\n\
<dl class=\"facts\">\n\
<div><dt>Application</dt><dd>{client}</dd></div>\n\
<div><dt>Details from</dt><dd>{details}</dd></div>\n\
<div><dt>Sends you to</dt><dd><code>{redirect_uri}</code></dd></div>\n\
<div><dt>Works as</dt><dd>{actor}</dd></div>\n\
<div><dt>Access</dt><dd>{access}</dd></div>\n\
<div><dt>Allowed as</dt><dd>{via}</dd></div>\n\
</dl>\n\
{warnings}<p class=\"callout\">{SHIELD}<span>Only allow this if you started connecting just now, in this browser. \
Access lasts {lasts}.</span></p>\n",
        workspace = escape(c.workspace),
        provider = escape(c.provider),
        login = escape(c.login),
        redirect_uri = escape(c.redirect_uri),
        actor = escape(c.actor),
        access = escape(c.access),
        via = escape(c.via),
        lasts = escape(c.lasts),
    );
    let actions = format!(
        "<form method=\"post\" action=\"{action}\" class=\"actions\">\n\
<input type=\"hidden\" name=\"consent\" value=\"{id}\">\n\
<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\n\
<button type=\"submit\" name=\"decision\" value=\"approve\" class=\"primary\">Allow</button>\n\
</form>\n",
        action = escape(c.action),
        id = escape(c.id),
    );
    let mut origins: Vec<&str> = Vec::new();
    for o in c.form_origins {
        if !origins.contains(o) {
            origins.push(o);
        }
    }
    let images = c.logo.map(|_| "data:");
    let form_action = origins.join(" ");
    let parts =
        Parts { actions: &actions, form_action: &form_action, images, script: Some(ARMING), ..Parts::default() };
    page(200, "Connect to bd", &body, parts)
}

/// The most characters of a title the approval page shows.
const MAX_TITLE: usize = 200;

/// The most issues the approval page lists as held back.
const MAX_HOLDS: usize = 20;

/// What the gate approval page shows.
pub struct ApproveGate<'a> {
    pub workspace: &'a str,
    /// The gate's id and title.
    pub gate: &'a str,
    pub title: &'a str,
    /// The issues the gate holds back: id, title and status.
    pub holds: &'a [(String, String, String)],
    /// The run or parent the gate belongs to: id and title.
    pub part_of: Option<(&'a str, &'a str)>,
    /// The gate's approvers, if it names any (an empty list: a stored list
    /// that is not valid, which matches nobody).
    pub approvers: Option<&'a [String]>,
    /// The provider the person signed in with, as the page names it.
    pub provider: &'a str,
    /// The actor the approval is recorded as.
    pub actor: &'a str,
    /// The approval's id, posted back with it.
    pub id: &'a str,
    /// Where the approval is posted.
    pub action: &'a str,
}

/// The page asking a person to approve a human gate: what the gate is,
/// what it holds back, and who the approval is recorded as, with one
/// button. Its form posts only to this server (`'self'`), and the consent
/// page's script ([`ARMING`]) keeps a double click from sending it.
/// Titles come from whoever may write to the workspace, agents included,
/// so every value is shown escaped ([`shown`]): nothing in them can pass
/// for the page's own text.
pub fn approve_gate(a: &ApproveGate<'_>) -> Page {
    let title = shown(a.title, MAX_TITLE);
    let actor = shown(a.actor, MAX_TITLE);
    let workspace = shown(a.workspace, MAX_TITLE);
    let mut holds = String::new();
    for (id, title, status) in a.holds.iter().take(MAX_HOLDS) {
        holds.push_str(&format!(
            "<span class=\"note-line\"><code>{}</code> {} <span class=\"note\">{}</span></span>",
            shown(id, MAX_TITLE),
            shown(title, MAX_TITLE),
            shown(status, MAX_TITLE)
        ));
    }
    if a.holds.len() > MAX_HOLDS {
        holds.push_str(&format!("<span class=\"note\">and {} more</span>", a.holds.len() - MAX_HOLDS));
    }
    if a.holds.is_empty() {
        holds.push_str("Nothing");
    }
    let part_of = a.part_of.map_or(String::new(), |(id, title)| {
        format!(
            "<div><dt>Part of</dt><dd><code>{}</code> {}</dd></div>\n",
            shown(id, MAX_TITLE),
            shown(title, MAX_TITLE)
        )
    });
    let approvers = match a.approvers {
        None => String::new(),
        Some([]) => "<div><dt>Approvers</dt><dd>None valid: nobody may approve</dd></div>\n".to_string(),
        Some(list) => format!(
            "<div><dt>Approvers</dt><dd>{}</dd></div>\n",
            list.iter().map(|a| shown(a, MAX_TITLE)).collect::<Vec<_>>().join(", ")
        ),
    };
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\"><div class=\"avatar\">{MARK}</div></div>\n\
<h1>Approve {title}?</h1>\n\
<p class=\"lead\">You're signed in to {provider} as <b>{actor}</b>.</p>\n\
<dl class=\"facts\">\n\
<div><dt>Workspace</dt><dd>{workspace}</dd></div>\n\
<div><dt>Gate</dt><dd><code>{gate}</code> {title}</dd></div>\n\
<div><dt>Holds back</dt><dd>{holds}</dd></div>\n\
{part_of}{approvers}</dl>\n\
<p class=\"callout\">{SHIELD}<span>Approving resolves this gate, so the work it holds back can go ahead. \
It is recorded in {workspace} as approved by <b>{actor}</b>. Only approve if you opened this link just now, \
in this browser.</span></p>\n",
        provider = shown(a.provider, MAX_TITLE),
        gate = shown(a.gate, MAX_TITLE),
    );
    let actions = format!(
        "<form method=\"post\" action=\"{action}\" class=\"actions\">\n\
<input type=\"hidden\" name=\"approval\" value=\"{id}\">\n\
<button type=\"submit\" class=\"primary\">Approve</button>\n\
</form>\n",
        action = escape(a.action),
        id = escape(a.id),
    );
    let parts = Parts { actions: &actions, form_action: "'self'", script: Some(ARMING), ..Parts::default() };
    page(200, "Approve a gate", &body, parts)
}

/// A page telling why there is nothing to approve, or why it cannot be: a
/// refusal with no way back, since no application waits.
pub fn notice(status: u16, title: &str, why: &str) -> Page {
    refusal(status, title, why, None)
}

/// `text` as HTML, at most `max` characters of it (then '…'), with what a
/// terminal or a page would not show plainly escaped as `\uXXXX`: control
/// characters and text direction controls ([`bd_cli::io::printable`]), and
/// invisible and blank characters ([`hidden`](super::clients::hidden)).
fn shown(text: &str, max: usize) -> String {
    let cut: String = if text.chars().count() > max {
        text.chars().take(max).chain(std::iter::once('…')).collect()
    } else {
        text.to_string()
    };
    let printable = bd_cli::io::printable(&cut);
    let mut out = String::with_capacity(printable.len());
    for c in printable.chars() {
        if super::clients::hidden(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    escape(&out)
}

/// The page asking which provider to sign in with, under `heading` (what
/// the sign-in is for): each option a label and the link that starts its
/// sign-in.
pub fn choose(heading: &str, options: &[(String, String)]) -> Page {
    let mut body = format!(
        "<h1>{}</h1>\n<p class=\"lead\">Choose how to sign in.</p>\n<div class=\"choices\">\n",
        escape(heading)
    );
    for (label, href) in options {
        body.push_str(&format!("<a class=\"button\" href=\"{}\">Continue with {}</a>\n", escape(href), escape(label)));
    }
    body.push_str("</div>\n");
    page(200, "Sign in", &body, Parts::default())
}

/// A page saying why an authorization cannot go on, with a link back to
/// the application if it may be told.
pub fn refusal(status: u16, title: &str, why: &str, back: Option<&str>) -> Page {
    let body = format!("<h1>{}</h1>\n<p class=\"lead\">{}</p>\n", escape(title), escape(why));
    let actions = back.map_or(String::new(), |url| {
        format!("<a class=\"button\" href=\"{}\">Back to the application</a>\n", escape(url))
    });
    page(status, title, &body, Parts { actions: &actions, ..Parts::default() })
}

/// A page sending the browser on to `url`, the client's redirect URI with
/// the answer, where a redirect after the consent form cannot: the
/// Content-Security-Policy `form-action` that would allow it has no syntax
/// for an IPv6 address (`http://[::1]:8080`). A link and a refresh are not
/// form submissions.
pub fn onward(url: &str) -> Page {
    let url = escape(url);
    let body = format!(
        "<h1>Back to the application</h1>\n\
<p class=\"lead\">Taking you there now. You can close this tab once it opens. \
Nothing happening? <a href=\"{url}\">Open the application</a>.</p>\n"
    );
    let refresh = format!("<meta http-equiv=\"refresh\" content=\"0; url={url}\">\n");
    page(200, "Back to the application", &body, Parts { head: &refresh, ..Parts::default() })
}

/// What a page has besides its title and body.
struct Parts<'a> {
    /// Added to the document's head.
    head: &'a str,
    /// The page's buttons, if any: on the left of the row under the body,
    /// with the brand on the right.
    actions: &'a str,
    /// Where forms may post, as a policy source list.
    form_action: &'a str,
    /// Where images may come from, if anywhere.
    images: Option<&'a str>,
    /// A script at the end of the body, allowed by its hash.
    script: Option<&'a str>,
}

impl Default for Parts<'_> {
    fn default() -> Self {
        Parts { head: "", actions: "", form_action: "'none'", images: None, script: None }
    }
}

/// The page around `body`, with its [`Parts`], and the policy allowing
/// exactly them.
fn page(status: u16, title: &str, body: &str, parts: Parts<'_>) -> Page {
    let Parts { head, actions, form_action, images, script } = parts;
    let script_tag = script.map(|js| format!("<script>{js}</script>\n")).unwrap_or_default();
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"robots\" content=\"noindex\">\n{head}\
<title>{} · bd</title>\n<style>{STYLE}</style>\n</head>\n<body>\n\
<main>\n{body}<div class=\"bar\">\n{actions}\
<span class=\"brand\">{MARK}<span>bd <small>authorization</small></span></span>\n</div>\n</main>\n\
{script_tag}</body>\n</html>\n",
        escape(title)
    );
    let hash = |text: &str| STANDARD.encode(Sha256::digest(text.as_bytes()));
    let images = images.map(|src| format!("img-src {src}; ")).unwrap_or_default();
    let scripts = script.map(|js| format!("script-src 'sha256-{}'; ", hash(js))).unwrap_or_default();
    let csp = format!(
        "default-src 'none'; style-src 'sha256-{}'; {scripts}{images}form-action {form_action}; \
frame-ancestors 'none'; base-uri 'none'",
        hash(STYLE)
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
            identity: Identity::Registered { client_id: evil },
            logo: None,
            redirect_uri: evil,
            loopback: false,
            elsewhere: None,
            lasts: "at most 30 days, and ends after 7 days unused or when revoked",
            workspace: evil,
            provider: evil,
            login: evil,
            actor: evil,
            access: "Read and write",
            via: evil,
            id: evil,
            action: "https://bd.example.com/oauth/consent",
            form_origins: &["https://bd.example.com", "https://app.example", "https://bd.example.com"],
        });
        assert_eq!(page.status, 200);
        assert!(!page.html.contains("<script>alert"), "{}", page.html);
        assert!(page.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;"));
        assert!(page.html.contains("action=\"https://bd.example.com/oauth/consent\""));
        assert!(page.csp.contains("form-action https://bd.example.com https://app.example;"), "{}", page.csp);
        assert!(!page.html.contains("<img") && !page.csp.contains("img-src"), "no logo, no image allowed");
        assert!(page.csp.starts_with("default-src 'none'; style-src 'sha256-"));
        assert!(page.csp.ends_with("frame-ancestors 'none'; base-uri 'none'"));

        let page = refusal(403, "Not <allowed>", "because & why", Some("https://app.example/cb?error=x&state=y"));
        assert_eq!(page.status, 403);
        assert!(page.html.contains("<title>Not &lt;allowed&gt; · bd</title>"));
        assert!(page.html.contains("<p class=\"lead\">because &amp; why</p>"));
        assert!(page.html.contains("href=\"https://app.example/cb?error=x&amp;state=y\""));
        assert!(page.csp.contains("form-action 'none';"));
        assert!(!refusal(400, "t", "w", None).html.contains("<a "));
    }

    #[test]
    fn the_consent_page_warns_of_what_cannot_be_trusted() {
        let page = |identity, redirect_uri, loopback, elsewhere| {
            consent(&Consent {
                client: "App",
                identity,
                logo: None,
                redirect_uri,
                loopback,
                elsewhere,
                lasts: "at most 30 days",
                workspace: "proj",
                provider: "GitHub",
                login: "octocat",
                actor: "octocat",
                access: "Read only",
                via: "GitHub user octocat",
                id: "c0ffee",
                action: "https://bd.example.com/oauth/consent",
                form_origins: &["'self'"],
            })
            .html
        };
        let unverified = "<b>Unverified application.</b>";
        let local = "<b>Returns to this computer.</b>";
        let other = "<b>Returns to another site.</b>";
        let document = Identity::Document { url: "https://app.example/client.json", host: "app.example" };

        let html = page(document, "https://app.example/cb?x=1", false, None);
        assert!(html.contains("<b>App</b> (app.example) wants"), "{html}");
        assert!(html.contains("<dt>Details from</dt><dd><code>https://app.example/client.json</code>"), "{html}");
        assert!(html.contains("<dt>Sends you to</dt><dd><code>https://app.example/cb?x=1</code>"), "{html}");
        assert!(html.contains("Access lasts at most 30 days."), "{html}");
        assert!(!html.contains(unverified) && !html.contains(local) && !html.contains(other), "{html}");

        let document = Identity::Document { url: "https://app.example/client.json", host: "app.example" };
        let html = page(document, "https://cdn.example/cb", false, Some("cdn.example"));
        assert!(html.contains(other) && html.contains("goes to <b>cdn.example</b>, not app.example"), "{html}");

        let html = page(Identity::Registered { client_id: "bdc_1" }, "http://127.0.0.1:9/cb", true, None);
        assert!(html.contains("<b>App</b> wants"), "{html}");
        assert!(html.contains("as client <code>bdc_1</code>"), "{html}");
        assert!(html.contains(unverified) && html.contains(local) && !html.contains(other), "{html}");
    }

    #[test]
    fn a_logo_comes_inside_the_page() {
        let page = consent(&Consent {
            client: "ChatGPT",
            identity: Identity::Document { url: "https://chatgpt.com/oauth/client.json", host: "chatgpt.com" },
            logo: Some("data:image/png;base64,iVBORw0KGgo="),
            redirect_uri: "https://chatgpt.com/cb",
            loopback: false,
            elsewhere: None,
            lasts: "at most 30 days, and ends after 7 days unused or when revoked",
            workspace: "proj",
            provider: "GitHub",
            login: "octocat",
            actor: "octocat",
            access: "Read and write",
            via: "GitHub user octocat",
            id: "c0ffee",
            action: "https://bd.example.com/oauth/consent",
            form_origins: &["'self'"],
        });
        assert!(
            page.html
                .contains("<img src=\"data:image/png;base64,iVBORw0KGgo=\" alt=\"\" referrerpolicy=\"no-referrer\">"),
            "{}",
            page.html
        );
        assert!(page.csp.contains("; img-src data:; form-action 'self';"), "{}", page.csp);
        assert!(page.csp.starts_with("default-src 'none';"));
    }

    #[test]
    fn a_page_sends_the_browser_on_where_a_redirect_cannot() {
        let page = onward("http://[::1]:8080/cb?code=c&state=a\"b");
        assert_eq!(page.status, 200);
        let url = "http://[::1]:8080/cb?code=c&amp;state=a&quot;b";
        assert!(
            page.html.contains(&format!("<meta http-equiv=\"refresh\" content=\"0; url={url}\">")),
            "{}",
            page.html
        );
        assert!(page.html.contains(&format!("<a href=\"{url}\">")), "{}", page.html);
        assert!(page.csp.contains("form-action 'none';"));
    }

    /// Write every page to `$BD_PAGES_DIR` (default `<temp>/bd-pages`) to
    /// look at in a browser, each with its policy in a `<meta>` (which
    /// browsers apply, but for `frame-ancestors`):
    /// `cargo test -p bd --bin bd preview_pages -- --ignored --nocapture`.
    /// A logo for the preview: a green disc.
    const PREVIEW_LOGO: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'%3E\
%3Ccircle cx='5' cy='5' r='5' fill='%2310a37f'/%3E%3C/svg%3E";

    #[test]
    #[ignore = "writes files to look at"]
    fn preview_pages() {
        let dir = std::env::var_os("BD_PAGES_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("bd-pages"));
        std::fs::create_dir_all(&dir).unwrap();
        let back = "https://chatgpt.com/connector_platform_oauth_redirect?error=access_denied&state=s";
        let pages = [
            (
                "consent",
                "Consent, with the logo of a metadata document",
                consent(&Consent {
                    client: "ChatGPT",
                    identity: Identity::Document { url: "https://chatgpt.com/oauth/client.json", host: "chatgpt.com" },
                    // A stand-in: bd serve shows a PNG, JPEG, GIF or WebP logo it fetched.
                    logo: Some(PREVIEW_LOGO),
                    redirect_uri: "https://chatgpt.com/connector_platform_oauth_redirect",
                    loopback: false,
                    elsewhere: None,
                    lasts: "at most 30 days, and ends after 7 days unused or when revoked",
                    workspace: "proj",
                    provider: "GitHub",
                    login: "octocat",
                    actor: "octocat",
                    access: "Read and write",
                    via: "GitHub user octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/oauth/consent",
                    form_origins: &["'self'", "https://chatgpt.com"],
                }),
            ),
            (
                "consent-registered",
                "Consent, for a registered client returning to this computer",
                consent(&Consent {
                    client: "Cursor",
                    identity: Identity::Registered { client_id: "bdc_7f3a9c" },
                    logo: None,
                    redirect_uri: "http://127.0.0.1:52187/callback",
                    loopback: true,
                    elsewhere: None,
                    lasts: "at most 30 days, and ends after 7 days unused or when revoked",
                    workspace: "proj",
                    provider: "GitHub",
                    login: "octocat",
                    actor: "octocat",
                    access: "Read only",
                    via: "member of acme",
                    id: "c0ffee",
                    action: "https://bd.example.com/oauth/consent",
                    form_origins: &["'self'"],
                }),
            ),
            (
                "choose",
                "Choosing a provider",
                choose(
                    "Sign in to connect ChatGPT",
                    &[
                        (
                            "GitHub".to_string(),
                            "https://bd.example.com/oauth/choose?flow=f&provider=github".to_string(),
                        ),
                        (
                            "Acme SSO".to_string(),
                            "https://bd.example.com/oauth/choose?flow=f&provider=acme".to_string(),
                        ),
                    ],
                ),
            ),
            (
                "refused",
                "Refused, with a way back",
                refusal(
                    403,
                    "Access denied",
                    "Your GitHub account doesn't have access to this workspace. Ask the server's admin for access.",
                    Some(back),
                ),
            ),
            (
                "failed",
                "Failed, with no way back",
                refusal(
                    400,
                    "Couldn't connect the application",
                    "This sign-in has expired. Start again from the application.",
                    None,
                ),
            ),
            ("onward", "Onward (refresh left out)", onward("http://[::1]:8080/callback?code=c&state=s")),
            (
                "approve-gate",
                "Approving a human gate",
                approve_gate(&ApproveGate {
                    workspace: "proj",
                    gate: "proj-a1b2",
                    title: "Release sign-off",
                    holds: &[
                        ("proj-c3d4".to_string(), "Deploy to production".to_string(), "open".to_string()),
                        ("proj-e5f6".to_string(), "Announce the release".to_string(), "open".to_string()),
                    ],
                    part_of: Some(("proj-r1", "release 1.4")),
                    approvers: Some(&["github:octocat".to_string(), "github:hubot".to_string()]),
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/gates/proj-a1b2",
                }),
            ),
            (
                "gate-notice",
                "A gate already resolved",
                notice(200, "Already resolved", "This gate was resolved already: there is nothing to approve."),
            ),
        ];
        let mut index = String::from("<h1>bd authorization pages</h1>\n<ul>\n");
        let write = |name: &str, page: &Page| {
            let meta =
                format!("<head>\n<meta http-equiv=\"Content-Security-Policy\" content=\"{}\">", escape(&page.csp));
            let html = page.html.replacen("<head>", &meta, 1);
            let html: String =
                html.lines().filter(|l| !l.contains("http-equiv=\"refresh\"")).map(|l| format!("{l}\n")).collect();
            std::fs::write(dir.join(format!("{name}.html")), html).unwrap();
        };
        for (name, what, page) in &pages {
            write(name, page);
            index.push_str(&format!("<li><a href=\"{name}.html\">{}</a> ({})</li>\n", escape(what), page.status));
        }
        index.push_str("</ul>\n");
        write("index", &page(200, "bd authorization pages", &index, Parts::default()));
        println!("{}", dir.join("index.html").display());
    }

    /// Where [`gate_page`]'s form posts: a URL with markup in it.
    const GATE_ACTION: &str = "https://bd.example.com/w/proj/gates/g\"><x>";

    /// An approval page for a gate titled `title`, every other value shown
    /// `other`.
    fn gate_page(title: &str, other: &str) -> Page {
        let holds = [(other.to_string(), title.to_string(), other.to_string())];
        let approvers = [other.to_string()];
        approve_gate(&ApproveGate {
            workspace: other,
            gate: other,
            title,
            holds: &holds,
            part_of: Some((other, title)),
            approvers: Some(&approvers),
            provider: other,
            actor: other,
            id: "c0ffee",
            action: GATE_ACTION,
        })
    }

    /// The text of the page's only script.
    fn script_of(page: &Page) -> &str {
        let start = page.html.find("<script>").unwrap() + "<script>".len();
        let end = page.html.find("</script>").unwrap();
        &page.html[start..end]
    }

    #[test]
    fn only_the_consent_page_runs_a_script_and_only_its_own() {
        let page = consent(&Consent {
            client: "App",
            identity: Identity::Registered { client_id: "bdc_1" },
            logo: None,
            redirect_uri: "https://app.example/cb",
            loopback: false,
            elsewhere: None,
            lasts: "at most 30 days, and ends after 7 days unused or when revoked",
            workspace: "proj",
            provider: "GitHub",
            login: "octocat",
            actor: "octocat",
            access: "Read only",
            via: "GitHub user octocat",
            id: "c0ffee",
            action: "https://bd.example.com/oauth/consent",
            form_origins: &["'self'"],
        });
        let hash = STANDARD.encode(Sha256::digest(script_of(&page).as_bytes()));
        assert!(page.csp.contains(&format!("; script-src 'sha256-{hash}';")), "{}", page.csp);
        assert_eq!(page.html.matches("<script").count(), 1);

        // The approval page runs the same script, and only it.
        let page = gate_page("Ship it", "proj");
        assert_eq!(page.html.matches("<script").count(), 1);
        assert_eq!(script_of(&page), ARMING);
        let arming = STANDARD.encode(Sha256::digest(ARMING.as_bytes()));
        assert!(page.csp.contains(&format!("; script-src 'sha256-{arming}';")), "{}", page.csp);
        let form = "<form method=\"post\" action=\"https://bd.example.com/w/proj/gates/g&quot;&gt;&lt;x&gt;\" \
class=\"actions\">\n<input type=\"hidden\" name=\"approval\" value=\"c0ffee\">";
        assert!(page.html.contains(form), "{}", page.html);

        let options = [("GitHub".to_string(), "https://bd.example.com/oauth/choose?flow=f".to_string())];
        for other in [
            refusal(403, "t", "w", Some("https://app.example/cb")),
            onward("https://app.example/cb"),
            notice(404, "t", "w"),
            choose("Sign in to approve gate g in proj", &options),
        ] {
            assert!(!other.html.contains("<script") && !other.csp.contains("script-src"), "{}", other.csp);
        }
    }

    #[test]
    fn the_policy_allows_the_inline_style() {
        for page in [refusal(400, "t", "w", None), gate_page("Ship it", "proj"), notice(409, "t", "w")] {
            let start = page.html.find("<style>").unwrap() + "<style>".len();
            let end = page.html.find("</style>").unwrap();
            let hash = STANDARD.encode(Sha256::digest(&page.html.as_bytes()[start..end]));
            assert!(page.csp.contains(&format!("style-src 'sha256-{hash}'")));
        }
    }

    #[test]
    fn the_approval_page_shows_hostile_titles_escaped() {
        for title in ["<script>alert(1)</script>", "\u{202E}evil", "a\u{200B}b"] {
            let page = gate_page(title, "<b>\"x\"</b>\u{202E}");
            assert!(!page.html.contains("<script>alert"), "{}", page.html);
            assert!(!page.html.contains('\u{202E}') && !page.html.contains('\u{200B}'), "{}", page.html);
            assert!(!page.html.contains("<b>\"x\"</b>"), "{}", page.html);
            assert!(!page.html.contains(GATE_ACTION), "{}", page.html);
            assert!(page.html.contains("<dd>&lt;b&gt;&quot;x&quot;&lt;/b&gt;\\u202e</dd>"), "{}", page.html);
            assert!(page.csp.contains("form-action 'self';"), "{}", page.csp);
        }
        let html = gate_page("<script>alert(1)</script>", "proj").html;
        assert!(html.contains("<h1>Approve &lt;script&gt;alert(1)&lt;/script&gt;?</h1>"), "{html}");
        let html = gate_page("\u{202E}evil", "proj").html;
        assert!(html.contains("<h1>Approve \\u202eevil?</h1>"), "{html}");
        let html = gate_page("a\u{200B}b", "proj").html;
        assert!(html.contains("<h1>Approve a\\u200bb?</h1>"), "{html}");

        // Long titles are cut; the actor shows, an email never comes into it.
        let long = "x".repeat(MAX_TITLE + 50);
        let html = gate_page(&long, "proj").html;
        assert!(html.contains(&format!("<h1>Approve {}…?</h1>", "x".repeat(MAX_TITLE))), "{html}");
        assert!(html.contains("You're signed in to proj as <b>proj</b>."), "{html}");

        // A list of approvers that is not valid matches nobody, and says so.
        let page = approve_gate(&ApproveGate {
            workspace: "proj",
            gate: "g",
            title: "t",
            holds: &[],
            part_of: None,
            approvers: Some(&[]),
            provider: "GitHub",
            actor: "github:alice",
            id: "i",
            action: "a",
        });
        assert!(page.html.contains("<dt>Approvers</dt><dd>None valid"), "{}", page.html);
        assert!(page.html.contains("<dt>Holds back</dt><dd>Nothing</dd>"), "{}", page.html);
        assert!(!page.html.contains("<dt>Part of</dt>"), "{}", page.html);
    }
}
