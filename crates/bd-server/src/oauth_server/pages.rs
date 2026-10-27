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
use bd_core::gates::packet::{MAX_EDGES, MAX_RECORDS, MAX_SOURCE_BYTES, Note, Packet, Role, Source, Text, Walk};
use sha2::{Digest, Sha256};

use super::markdown;

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
.reason{margin:0;padding:0 0 0 12px;white-space:pre-wrap;overflow-wrap:anywhere}
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
.packet{margin:24px 0}
.packet h2{margin:0 0 8px;font-size:20px;line-height:1.3;font-weight:600;letter-spacing:-.02em}
.packet h3{margin:16px 0 4px;font-size:1em;font-weight:600}
.packet .notice{opacity:.7;font-size:.88em;margin:4px 0 12px}
.packet details.src{margin:12px 0}
.packet summary{cursor:pointer;overflow-wrap:anywhere}
.packet summary .note{display:inline}
.packet .src-role{font-weight:600}
.packet .src-body{padding:4px 0 0 16px;min-width:0}
.packet .md,.packet code{overflow-wrap:anywhere}
.packet .md :is(h4,h5,h6){margin:16px 0 4px;font-size:1em;font-weight:600}
.packet .md :is(ul,ol){margin:0 0 16px;padding-left:24px}
.packet .md pre{overflow:auto;white-space:pre;max-width:100%;margin:0 0 16px}
.packet .md-table{overflow-x:auto;max-width:100%;margin:0 0 16px}
.packet .md table{border-collapse:collapse}
.packet .md :is(th,td){padding:4px 8px;text-align:left;border:1px solid color-mix(in srgb,currentColor 30%,transparent)}
.packet .md blockquote{margin:0 0 16px;padding:0 0 0 12px;opacity:.8}
.packet :is(.md-raw,.md-dest,.md-inert){opacity:.7}
.packet .md input[type=checkbox]{margin:0 6px 0 0}
.packet .comment{margin:8px 0 12px}
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
    /// The gate's approval packet, shown below the facts when there is one
    /// ([`packet_section`]).
    pub packet: Option<&'a Packet>,
}

/// The page asking a person to approve a human gate: what the gate is,
/// what it holds back, and who the approval is recorded as, with one
/// button. Its form posts only to this server (`'self'`), and the consent
/// page's script ([`ARMING`]) keeps a double click from sending it.
/// Titles come from whoever may write to the workspace, agents included,
/// so every value is shown escaped ([`shown`]): nothing in them can pass
/// for the page's own text. The approval packet, workspace-authored too,
/// sits between the facts and the callout, in a section of its own.
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
    let packet = a.packet.map(packet_section).unwrap_or_default();
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\"><div class=\"avatar\">{MARK}</div></div>\n\
<h1>Approve {title}?</h1>\n\
<p class=\"lead\">You're signed in to {provider} as <b>{actor}</b>.</p>\n\
<dl class=\"facts\">\n\
<div><dt>Workspace</dt><dd>{workspace}</dd></div>\n\
<div><dt>Gate</dt><dd><code>{gate}</code> {title}</dd></div>\n\
<div><dt>Holds back</dt><dd>{holds}</dd></div>\n\
{part_of}{approvers}</dl>\n\
{packet}<p class=\"callout\">{SHIELD}<span>Approving resolves this gate, so the work it holds back can go ahead. \
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

/// The most issues the operation approval page lists as deleted by a discard.
pub const MAX_DELETES: usize = 50;

/// What the approval page of a close or discard that human gates refused shows.
pub struct ApproveOperation<'a> {
    pub workspace: &'a str,
    /// The operation, as the page names it: `close` or `discard`.
    pub op_label: &'a str,
    /// The issue closed, or the run discarded: its id, title and status.
    pub issue: &'a str,
    pub title: &'a str,
    pub status: &'a str,
    /// The run or parent the issue belongs to: id and title.
    pub part_of: Option<(&'a str, &'a str)>,
    /// The reason the requester gave, as sealed: shown with its whitespace.
    pub reason: Option<&'a str>,
    /// Who asked for it (the actor `bd serve` resolved), and when
    /// (milliseconds since the epoch).
    pub requester: &'a str,
    pub at: i64,
    /// The close's outcome is failed; the operation was forced.
    pub failed: bool,
    pub force: bool,
    /// The open human gates it gets past: id, title and approvers (None:
    /// any person; an empty list: a stored list that is not valid).
    pub gates: &'a [(String, String, Option<Vec<String>>)],
    /// For a discard, the issues it deletes (id and title, at most
    /// [`MAX_DELETES`] shown) and how many there are in all.
    pub deletes: Option<(&'a [(String, String)], usize)>,
    /// The provider the person signed in with, as the page names it.
    pub provider: &'a str,
    /// The actor the operation is recorded as done by.
    pub actor: &'a str,
    /// The approval's id, posted back with it.
    pub id: &'a str,
    /// Where the approval is posted: the link's path, without its query.
    pub action: &'a str,
}

/// The page asking a person to approve a close or discard that open human
/// gates refused: what it does, to what, at whose request and for what
/// reason, and the gates it gets past, with one button. As on the gate
/// approval page, every value is shown escaped, the form posts only to this
/// server and [`ARMING`] keeps a double click from sending it.
pub fn approve_operation(a: &ApproveOperation<'_>) -> Page {
    let op = shown(a.op_label, MAX_TITLE);
    let issue = shown_id(a.issue);
    let title = shown(a.title, MAX_TITLE);
    let actor = shown(a.actor, MAX_TITLE);
    let requester = shown(a.requester, MAX_TITLE);
    let workspace = shown(a.workspace, MAX_TITLE);
    let part_of = a.part_of.map_or(String::new(), |(id, title)| {
        format!("<div><dt>Part of</dt><dd><code>{}</code> {}</dd></div>\n", shown_id(id), shown(title, MAX_TITLE))
    });
    let reason = match a.reason {
        Some(reason) => format!("<blockquote class=\"reason\">{}</blockquote>", shown_reason(reason)),
        None => "No reason given".to_string(),
    };
    let discard = a.deletes.is_some();
    let mut options = Vec::new();
    if a.force {
        options.push(if discard {
            "Forced: the run need not be finished"
        } else {
            "Forced past open work and blockers"
        });
    }
    if a.failed {
        options.push("Closed as failed");
    }
    let options = if options.is_empty() { "None".to_string() } else { options.join("; ") };
    let mut gates = String::new();
    for (id, title, approvers) in a.gates {
        let approvers = match approvers.as_deref() {
            None => "any person".to_string(),
            Some([]) => "no valid approvers".to_string(),
            Some(list) => list.iter().map(|a| shown(a, MAX_TITLE)).collect::<Vec<_>>().join(", "),
        };
        gates.push_str(&format!(
            "<span class=\"note-line\"><code>{}</code> {} <span class=\"note\">approvers: {approvers}</span></span>",
            shown_id(id),
            shown(title, MAX_TITLE),
        ));
    }
    if a.gates.is_empty() {
        gates.push_str("None");
    }
    let deletes = a.deletes.map_or(String::new(), |(listed, total)| {
        let mut out = format!(
            "<div><dt>Deletes</dt><dd>Deletes {total} issue{}, with no undo",
            if total == 1 { "" } else { "s" }
        );
        let listed = &listed[..listed.len().min(MAX_DELETES)];
        for (id, title) in listed {
            out.push_str(&format!(
                "<span class=\"note-line\"><code>{}</code> {}</span>",
                shown_id(id),
                shown(title, MAX_TITLE)
            ));
        }
        if total > listed.len() {
            out.push_str(&format!("<span class=\"note\">and {} more</span>", total - listed.len()));
        }
        out.push_str("</dd></div>\n");
        out
    });
    let what = if discard {
        "It deletes the run and every issue in it, and cannot be undone"
    } else {
        "It closes nothing else: not the issue's open children, nor a run's steps"
    };
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\"><div class=\"avatar\">{MARK}</div></div>\n\
<h1>Approve the {op} of {issue}?</h1>\n\
<p class=\"lead\">You're signed in to {provider} as <b>{actor}</b>. <b>{requester}</b> asked for this, and open human \
gates refused it.</p>\n\
<dl class=\"facts\">\n\
<div><dt>Workspace</dt><dd>{workspace}</dd></div>\n\
<div><dt>Operation</dt><dd>{op}</dd></div>\n\
<div><dt>Issue</dt><dd><code>{issue}</code> {title} <span class=\"note\">{status}</span></dd></div>\n\
{part_of}<div><dt>Reason</dt><dd>{reason}</dd></div>\n\
<div><dt>Requested by</dt><dd>{requester}</dd></div>\n\
<div><dt>Requested at</dt><dd>{at}</dd></div>\n\
<div><dt>Options</dt><dd>{options}</dd></div>\n\
<div><dt>Gets past</dt><dd>{gates}</dd></div>\n\
{deletes}</dl>\n\
<p class=\"callout\">{SHIELD}<span>Approving performs exactly this {op}, recorded in {workspace} as done by \
<b>{actor}</b> at {requester}'s request. It does not resolve the gates. {what}. Work another actor has claimed must \
be released first. Only approve if you opened this link just now, in this browser.</span></p>\n",
        provider = shown(a.provider, MAX_TITLE),
        status = shown(a.status, MAX_TITLE),
        at = escape(&bd_core::Timestamp(a.at).to_rfc3339()),
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
    page(200, "Approve an operation", &body, parts)
}

/// A reason as HTML, escaped as [`shown`] escapes text but whole, with its
/// newlines and tabs kept (the page shows it pre-wrapped), so that what is
/// shown is what is recorded.
fn shown_reason(text: &str) -> String {
    let printable = bd_cli::io::printable(text);
    let mut out = String::with_capacity(printable.len());
    for c in printable.chars() {
        if super::clients::hidden(c) && c != '\n' && c != '\t' {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    escape(&out)
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
    shown_id(&cut)
}

/// An id as HTML, escaped as [`shown`] escapes text but never shortened, so
/// that `bd show <id>` stays a command that works. A valid id is at most
/// 255 ASCII bytes.
fn shown_id(text: &str) -> String {
    let printable = bd_cli::io::printable(text);
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

/// The most bytes of HTML an approval packet takes on the page.
const MAX_PACKET_HTML: usize = 512 * 1024;

/// The end of the packet's section.
const PACKET_CLOSE: &str = "</section>\n";

/// The end of one source of the packet.
const SOURCE_END: &str = "</div>\n</details>\n";

/// The approval packet as a section of the approval page, within
/// [`MAX_PACKET_HTML`] bytes.
fn packet_section(p: &Packet) -> String {
    packet_section_within(p, MAX_PACKET_HTML)
}

/// The approval packet's section, at most `max` bytes of HTML.
///
/// Everything in the packet is workspace-authored, so every value is
/// escaped ([`shown`], [`shown_id`]) and every text rendered by
/// [`markdown::render`], confined to the section. The section's header and
/// the packet's notes come first; then each source in order, whole if it
/// fits. Room for every source's stub ([`stub`]: its role, full id, title,
/// status and the commands showing it in full) is set aside before any
/// Markdown is rendered, so a source that does not fit is still named, and
/// a field or comment that does not fit is replaced whole by a notice.
/// Generated HTML is never cut, so the section always nests.
fn packet_section_within(p: &Packet, max: usize) -> String {
    let mut out = String::from(
        "<section class=\"packet\" aria-labelledby=\"packet-h\">\n<h2 id=\"packet-h\">Approval packet</h2>\n\
<p class=\"note\">Workspace-authored material, shown as stored when this page loaded. It is not the server's own \
text, is not a signed record of what is approved, and can change before approval. Full records: \
<code>bd show &lt;id&gt;</code>.</p>\n",
    );
    for note in &p.notes {
        out.push_str(&note_html(note));
    }
    let stubs: Vec<String> = p.sources.iter().map(stub).collect();
    let mut reserved: usize = stubs.iter().map(String::len).sum();
    if out.len() + reserved + PACKET_CLOSE.len() > max {
        debug_assert!(max < MAX_PACKET_HTML, "an approval packet's stubs always fit on the page");
        return stubs_within(out, &stubs, max);
    }
    for (s, stub) in p.sources.iter().zip(&stubs) {
        // What is left once every later source's stub is set aside: at
        // least this source's own stub.
        reserved -= stub.len();
        let available = max - out.len() - reserved - PACKET_CLOSE.len();
        match source_html(s, available) {
            Some(html) if html.len() <= available => out.push_str(&html),
            _ => out.push_str(stub),
        }
    }
    out.push_str(PACKET_CLOSE);
    out
}

/// The section with as many `stubs` as fit in `max` after `out`, then a
/// notice of how many did not. Only for a `max` too small for every stub,
/// which [`MAX_PACKET_HTML`] never is.
fn stubs_within(mut out: String, stubs: &[String], max: usize) -> String {
    let notice = |n: usize| {
        format!(
            "<p class=\"notice\">Display limit reached: {n} more record{} not shown. Full records: \
<code>bd show &lt;id&gt;</code>.</p>\n",
            if n == 1 { "" } else { "s" }
        )
    };
    let mut left = stubs.len();
    for stub in stubs {
        let after = if left > 1 { notice(left - 1).len() } else { 0 };
        if out.len() + stub.len() + after + PACKET_CLOSE.len() > max {
            break;
        }
        out.push_str(stub);
        left -= 1;
    }
    if left > 0 {
        out.push_str(&notice(left));
    }
    out.push_str(PACKET_CLOSE);
    out
}

/// A packet note as a notice naming the record it is about.
fn note_html(note: &Note) -> String {
    let body = match note {
        Note::HeldLimit { gate, more } => format!(
            "{more} more held issue{} not included. Full list: <code>bd show {}</code>.",
            if *more == 1 { "" } else { "s" },
            shown_id(gate)
        ),
        Note::Unavailable { id } => {
            let id = shown_id(id);
            format!("Record <code>{id}</code> unavailable. Full record: <code>bd show {id}</code>.")
        }
        Note::EdgeLimit { at, during } => {
            let at = shown_id(at);
            let what = match during {
                Walk::Run => format!(
                    "while looking up the run or parent of <code>{at}</code>: run, prerequisite and decision \
records not shown"
                ),
                Walk::Prerequisites => format!(
                    "while reading the prerequisites of <code>{at}</code>: further prerequisite records not shown"
                ),
                Walk::Decisions => format!(
                    "while reading the child records of <code>{at}</code>: its decision records and later records \
not shown"
                ),
            };
            format!("Dependency read limit reached ({MAX_EDGES} rows) {what}. Full record: <code>bd show {at}</code>.")
        }
        Note::RecordLimit { at, during } => {
            let at = shown_id(at);
            let what = match during {
                Walk::Run => "the run or parent",
                Walk::Prerequisites => "the prerequisites",
                Walk::Decisions => "the decision records",
            };
            format!(
                "Record limit reached ({MAX_RECORDS} records) at {what} of <code>{at}</code>: further records not \
shown. Full record: <code>bd show {at}</code>."
            )
        }
    };
    format!("<p class=\"notice\">{body}</p>\n")
}

/// The start of a source: its details, summary and body, open for the gate
/// and the work it holds back.
fn source_head(s: &Source) -> String {
    let open = if matches!(s.role, Role::Gate | Role::Held) { " open" } else { "" };
    let under = s
        .under
        .as_deref()
        .map(|u| format!(" <span class=\"note\">under <code>{}</code></span>", shown_id(u)))
        .unwrap_or_default();
    format!(
        "<details class=\"src\"{open}><summary><span class=\"src-role\">{}</span> <code>{}</code> {} \
<span class=\"note\">{}</span>{under}</summary>\n<div class=\"src-body\">\n",
        escape(s.role.label()),
        shown_id(&s.id),
        shown(&s.title, MAX_TITLE),
        escape(s.status.as_str()),
    )
}

/// A source shown by what identifies it only, with the commands showing it
/// in full.
fn stub(s: &Source) -> String {
    let id = shown_id(&s.id);
    format!(
        "{}<p class=\"notice\">Not shown: the page's display limit was reached. Full record: \
<code>bd show {id}</code>. Comments: <code>bd comment list {id}</code>.</p>\n{SOURCE_END}",
        source_head(s)
    )
}

/// A size in words, rounded down or `up`.
fn size(bytes: u64, up: bool) -> String {
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let kib = if up { bytes.div_ceil(1024) } else { bytes / 1024 };
    format!("{kib} KiB")
}

/// What a source's text leaves out, if anything, and where to read it all.
fn text_notice(text: &Text, command: &str) -> String {
    match text {
        Text::Full(_) => String::new(),
        Text::Truncated { text, total_bytes } => format!(
            "<p class=\"notice\">Shown: the first {} of {}. Full text: <code>{command}</code>.</p>\n",
            size(text.len() as u64, false),
            size(*total_bytes, true)
        ),
        Text::Omitted { .. } => format!(
            "<p class=\"notice\">Not shown: the packet's {} KiB source limit was reached. Full text: \
<code>{command}</code>.</p>\n",
            MAX_SOURCE_BYTES / 1024
        ),
    }
}

/// A part of a source: `before` and `after` around its Markdown `text`, or
/// `instead` when the text does not fit.
struct Piece<'a> {
    before: String,
    text: Option<&'a str>,
    after: String,
    instead: String,
}

/// Source `s` in full, as far as it fits in `available` bytes: a field or
/// comment that does not fit is replaced by a notice, and once not even
/// that fits, one notice names what is left out. None when not even the
/// source's summary and its first part fit: its stub says more then.
fn source_html(s: &Source, available: usize) -> Option<String> {
    let id = shown_id(&s.id);
    let show = format!("bd show {id}");
    let list = format!("bd comment list {id}");
    let further = format!(
        "<p class=\"notice\">Further fields and comments not shown: <code>{show}</code>, <code>{list}</code>.</p>\n"
    );
    let mut html = source_head(s);
    let limit = available.checked_sub(further.len() + SOURCE_END.len())?;
    if html.len() > limit {
        return None;
    }
    let too_big = |command: &str| {
        format!(
            "<p class=\"notice\">Not shown: the rendered text exceeds the page's display limit. Full text: \
<code>{command}</code>.</p>\n"
        )
    };
    let mut pieces = Vec::new();
    if s.fields.is_empty() && s.comments.is_empty() && s.earlier_comments == 0 {
        pieces.push(Piece {
            before: "<p class=\"note\">No fields or comments.</p>\n".to_string(),
            text: None,
            after: String::new(),
            instead: String::new(),
        });
    }
    for f in &s.fields {
        let label = format!("<h3>{}</h3>\n", escape(f.kind.label()));
        let notice = text_notice(&f.text, &show);
        pieces.push(match &f.text {
            Text::Full(text) | Text::Truncated { text, .. } => Piece {
                before: format!("{label}<div class=\"md\">"),
                text: Some(text),
                after: format!("</div>\n{notice}"),
                instead: format!("{label}{}", too_big(&show)),
            },
            Text::Omitted { .. } => {
                Piece { before: format!("{label}{notice}"), text: None, after: String::new(), instead: String::new() }
            }
        });
    }
    if !s.comments.is_empty() || s.earlier_comments > 0 {
        let earlier = match s.earlier_comments {
            0 => String::new(),
            n => format!(
                "<p class=\"notice\">{n} earlier comment{} not shown: <code>{list}</code>.</p>\n",
                if n == 1 { "" } else { "s" }
            ),
        };
        pieces.push(Piece {
            before: format!("<h3>Comments</h3>\n{earlier}"),
            text: None,
            after: String::new(),
            instead: String::new(),
        });
    }
    for c in &s.comments {
        let by = format!(
            "<div class=\"comment\"><p class=\"note\">{} · {}</p>\n",
            shown(&c.author, MAX_TITLE),
            escape(&c.created_at.to_rfc3339())
        );
        let notice = text_notice(&c.text, &list);
        pieces.push(match &c.text {
            Text::Full(text) | Text::Truncated { text, .. } => Piece {
                before: format!("{by}<div class=\"md\">"),
                text: Some(text),
                after: format!("</div>\n{notice}</div>\n"),
                instead: format!("{by}{}</div>\n", too_big(&list)),
            },
            Text::Omitted { .. } => Piece {
                before: format!("{by}{notice}</div>\n"),
                text: None,
                after: String::new(),
                instead: String::new(),
            },
        });
    }
    for (i, piece) in pieces.into_iter().enumerate() {
        let frame = html.len() + piece.before.len() + piece.after.len();
        let whole = if frame > limit {
            None
        } else {
            match piece.text {
                None => Some(String::new()),
                Some(text) => markdown::render(text, limit - frame),
            }
        };
        match whole {
            Some(md) => {
                html.push_str(&piece.before);
                html.push_str(&md);
                html.push_str(&piece.after);
            }
            None if !piece.instead.is_empty() && html.len() + piece.instead.len() <= limit => {
                html.push_str(&piece.instead)
            }
            None if i == 0 => return None,
            None => {
                html.push_str(&further);
                break;
            }
        }
    }
    html.push_str(SOURCE_END);
    Some(html)
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
    /// `cargo test -p bd-server preview_pages -- --ignored --nocapture`.
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
        let packet = preview_packet();
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
                    packet: None,
                }),
            ),
            (
                "approve-gate-packet",
                "Approving a playbook gate, with its approval packet",
                approve_gate(&ApproveGate {
                    workspace: "proj",
                    gate: "proj-r1.gate-build",
                    title: "Approve the build",
                    holds: &[("proj-r1.build".to_string(), "Build".to_string(), "open".to_string())],
                    part_of: Some(("proj-r1", "Release <b>1.4</b>")),
                    approvers: Some(&["github:octocat".to_string()]),
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/gates/proj-r1.gate-build",
                    packet: Some(&packet),
                }),
            ),
            (
                "approve-close",
                "Approving a close that human gates refused",
                approve_operation(&ApproveOperation {
                    workspace: "proj",
                    op_label: "close",
                    issue: "proj-r1",
                    title: "Release 1.4",
                    status: "in_progress",
                    part_of: None,
                    reason: Some("  abandoned: superseded by 1.5\n  (see proj-r2)"),
                    requester: "alice/copilot-1",
                    at: 1_790_000_000_000,
                    failed: true,
                    force: true,
                    gates: &[(
                        "proj-r1.gate-ship".to_string(),
                        "Approve the release".to_string(),
                        Some(vec!["github:octocat".to_string()]),
                    )],
                    deletes: None,
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/close/proj-r1",
                }),
            ),
            (
                "approve-discard",
                "Approving a discard that human gates refused",
                approve_operation(&ApproveOperation {
                    workspace: "proj",
                    op_label: "discard",
                    issue: "proj-r1",
                    title: "Release 1.4",
                    status: "closed",
                    part_of: None,
                    reason: None,
                    requester: "alice/copilot-1",
                    at: 1_790_000_000_000,
                    failed: false,
                    force: false,
                    gates: &[("proj-r1.gate-ship".to_string(), "Approve the release".to_string(), None)],
                    deletes: Some((
                        &[
                            ("proj-r1".to_string(), "Release 1.4".to_string()),
                            ("proj-r1.build".to_string(), "Build".to_string()),
                            ("proj-r1.gate-ship".to_string(), "Approve the release".to_string()),
                        ],
                        3,
                    )),
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/discard/proj-r1",
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

    /// A made-up approval packet for the preview: rich Markdown, hostile
    /// samples, a truncated field, a graph-limit notice, and collapsed
    /// prerequisites and decision records.
    fn preview_packet() -> Packet {
        let mut gate = source(Role::Gate, "proj-r1.gate-build", "Approve the build");
        gate.fields = vec![full(
            FieldKind::Description,
            "Approve once the design below is settled. [Back to the top of the packet](#packet-h).",
        )];
        let mut held = source(Role::Held, "proj-r1.build", "Build");
        held.fields = vec![
            full(
                FieldKind::Description,
                "## Plan\n\nBuild the **release** artifacts:\n\n\
                 1. Compile with `cargo build --release`.\n2. Sign the archives.\n\n\
                 | Target | Archive |\n|---|---|\n| Linux | `bd-linux.tar.gz` |\n| macOS | `bd-macos.tar.gz` |\n\n\
                 > Keep the old archives until the new ones are verified.\n\n\
                 ```sh\nmake release\t# tabs and newlines kept\n```\n\n\
                 See [the release notes](https://example.com/releases/1.4) and ~~the old plan~~.",
            ),
            full(FieldKind::AcceptanceCriteria, "- [x] Archives built\n- [ ] Archives signed"),
            Field {
                kind: FieldKind::Notes,
                text: Text::Truncated {
                    text: "Build log excerpt: ".to_string() + &"ok ".repeat(40),
                    total_bytes: 40_000,
                },
            },
        ];
        held.comments =
            vec![comment("github:hubot", Text::Full("Built on the *second* try; the first timed out.".into()))];
        held.earlier_comments = 2;
        let mut held_adr = source(Role::Decision, "proj-r1.build.1", "Use reproducible builds");
        held_adr.under = Some("proj-r1.build".into());
        held_adr.fields = vec![full(FieldKind::Design, "Pin the toolchain and set `SOURCE_DATE_EPOCH`.")];
        let mut run = source(Role::Run, "proj-r1", "Release <b>1.4</b>");
        run.status = Status::InProgress;
        run.comments = vec![comment("judge", Text::Full("Score draft: correctness 4, scope 5.".into()))];
        let mut requirements = source(Role::Prerequisite, "proj-r1.requirements", "Requirements");
        requirements.status = Status::Closed;
        requirements.fields = vec![full(
            FieldKind::Description,
            "Hostile samples, shown as text:\n\n<script>alert(1)</script>\n\n\
             Inline <img src=x onerror=alert(1)> and <form action=https://evil.example><button>Approve</button></form>.\n\n\
             [a script link](javascript:alert(1)), ![a pixel](https://evil.example/p.png), \
             a direction override \u{202E}reversed\u{202C} and a zero-width\u{200B}space.",
        )];
        let mut decide = source(Role::Prerequisite, "proj-r1.decide", "Decide");
        decide.status = Status::Closed;
        decide.fields = vec![full(FieldKind::Design, "Ship static binaries for every target.")];
        let mut adr = source(Role::Decision, "proj-r1.decide.1", "ADR: static binaries");
        adr.status = Status::Closed;
        adr.under = Some("proj-r1.decide".into());
        adr.fields = vec![full(FieldKind::Design, "Static binaries avoid glibc version drift.")];
        Packet {
            playbook: true,
            sources: vec![gate, held, held_adr, run, requirements, decide, adr],
            notes: vec![Note::EdgeLimit { at: "proj-r1.decide".into(), during: Walk::Prerequisites }],
        }
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
            packet: None,
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
            packet: None,
        });
        assert!(page.html.contains("<dt>Approvers</dt><dd>None valid"), "{}", page.html);
        assert!(page.html.contains("<dt>Holds back</dt><dd>Nothing</dd>"), "{}", page.html);
        assert!(!page.html.contains("<dt>Part of</dt>"), "{}", page.html);
    }

    /// An operation approval page, every value shown `other`, with `gates`
    /// and `deletes`.
    fn operation_page(
        other: &str,
        reason: Option<&str>,
        gates: &[(String, String, Option<Vec<String>>)],
        deletes: Option<(&[(String, String)], usize)>,
    ) -> Page {
        approve_operation(&ApproveOperation {
            workspace: other,
            op_label: if deletes.is_some() { "discard" } else { "close" },
            issue: other,
            title: other,
            status: other,
            part_of: Some((other, other)),
            reason,
            requester: other,
            at: 0,
            failed: true,
            force: true,
            gates,
            deletes,
            provider: other,
            actor: other,
            id: "c0ffee",
            action: GATE_ACTION,
        })
    }

    #[test]
    fn the_operation_page_shows_hostile_values_escaped() {
        let evil = "<script>alert(1)</script>\"'\u{202E}\u{200B}";
        let gates = [
            (evil.to_string(), evil.to_string(), Some(vec![evil.to_string(), "github:carol".to_string()])),
            ("g-2".to_string(), "t".to_string(), Some(vec![])),
            ("g-3".to_string(), "t".to_string(), None),
        ];
        let reason = format!("  {evil}\n\tsecond line  ");
        let page = operation_page(evil, Some(&reason), &gates, None);
        assert_eq!(page.status, 200);
        assert!(!page.html.contains("<script>alert"), "{}", page.html);
        assert!(!page.html.contains('\u{202E}') && !page.html.contains('\u{200B}'), "{}", page.html);
        assert!(!page.html.contains(GATE_ACTION), "{}", page.html);
        let shown = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;\\u202e\\u200b";
        assert!(page.html.contains(&format!("<h1>Approve the close of {shown}?</h1>")), "{}", page.html);
        // The reason keeps its whitespace, in a block that shows it.
        let quote = format!("<blockquote class=\"reason\">  {shown}\n\tsecond line  </blockquote>");
        assert!(page.html.contains(&quote), "{}", page.html);
        assert!(page.html.contains(&format!("approvers: {shown}, github:carol")), "{}", page.html);
        assert!(page.html.contains("<code>g-2</code> t <span class=\"note\">approvers: no valid approvers"));
        assert!(page.html.contains("<code>g-3</code> t <span class=\"note\">approvers: any person"));
        assert!(page.html.contains("Forced past open work and blockers; Closed as failed"), "{}", page.html);
        assert!(page.html.contains("<dt>Requested at</dt><dd>1970-01-01T00:00:00.000Z</dd>"), "{}", page.html);
        assert!(page.html.contains("It does not resolve the gates."), "{}", page.html);
        assert!(!page.html.contains("<dt>Deletes</dt>"), "{}", page.html);
        // The policy: no framing, a form posting here only, and the one script.
        assert!(page.csp.contains("frame-ancestors 'none'"), "{}", page.csp);
        assert!(page.csp.contains("form-action 'self';"), "{}", page.csp);
        assert_eq!(page.html.matches("<script").count(), 1);
        assert_eq!(script_of(&page), ARMING);
        let arming = STANDARD.encode(Sha256::digest(ARMING.as_bytes()));
        assert!(page.csp.contains(&format!("; script-src 'sha256-{arming}';")), "{}", page.csp);
        let form = "<form method=\"post\" action=\"https://bd.example.com/w/proj/gates/g&quot;&gt;&lt;x&gt;\" \
class=\"actions\">\n<input type=\"hidden\" name=\"approval\" value=\"c0ffee\">";
        assert!(page.html.contains(form), "{}", page.html);
        let start = page.html.find("<style>").unwrap() + "<style>".len();
        let end = page.html.find("</style>").unwrap();
        let hash = STANDARD.encode(Sha256::digest(&page.html.as_bytes()[start..end]));
        assert!(page.csp.contains(&format!("style-src 'sha256-{hash}'")));

        let page = operation_page("proj", None, &[], None);
        assert!(page.html.contains("<dt>Reason</dt><dd>No reason given</dd>"), "{}", page.html);
        assert!(page.html.contains("<dt>Gets past</dt><dd>None</dd>"), "{}", page.html);
    }

    #[test]
    fn a_discard_lists_what_it_deletes_up_to_a_cap() {
        let deleted: Vec<(String, String)> =
            (0..MAX_DELETES + 7).map(|i| (format!("r-{i}"), format!("<i>step {i}</i>"))).collect();
        let page = operation_page("proj", Some("cleanup"), &[], Some((&deleted, deleted.len() + 3)));
        let html = &page.html;
        assert!(html.contains("<h1>Approve the discard of proj?</h1>"), "{html}");
        assert!(html.contains(&format!("Deletes {} issues, with no undo", MAX_DELETES + 10)), "{html}");
        assert!(html.contains(&format!("<code>r-{}</code>", MAX_DELETES - 1)), "{html}");
        assert!(!html.contains(&format!("<code>r-{}</code>", MAX_DELETES)), "{html}");
        assert!(html.contains("&lt;i&gt;step 0&lt;/i&gt;"), "{html}");
        assert!(html.contains("<span class=\"note\">and 10 more</span>"), "{html}");
        assert!(html.contains("Forced: the run need not be finished"), "{html}");
        assert!(html.contains("cannot be undone"), "{html}");
        let one = [("r-1".to_string(), "t".to_string())];
        let html = operation_page("proj", None, &[], Some((&one, 1))).html;
        assert!(html.contains("Deletes 1 issue, with no undo") && !html.contains("more</span>"), "{html}");
    }

    use bd_core::gates::packet::{Field, FieldKind, MAX_HELD, PacketComment};
    use bd_core::model::Status;
    use bd_core::time::Timestamp;

    use super::super::markdown::balanced;

    fn source(role: Role, id: &str, title: &str) -> Source {
        Source {
            role,
            id: id.to_string(),
            title: title.to_string(),
            status: Status::Open,
            under: None,
            fields: Vec::new(),
            comments: Vec::new(),
            earlier_comments: 0,
        }
    }

    fn full(kind: FieldKind, text: &str) -> Field {
        Field { kind, text: Text::Full(text.to_string()) }
    }

    fn comment(author: &str, text: Text) -> PacketComment {
        PacketComment { author: author.to_string(), created_at: Timestamp(1_700_000_000_000), text }
    }

    /// The approval page for gate `g` with `packet`.
    fn packet_page(packet: Option<&Packet>) -> Page {
        approve_gate(&ApproveGate {
            workspace: "proj",
            gate: "g",
            title: "Ship it",
            holds: &[("h".to_string(), "Deploy".to_string(), "open".to_string())],
            part_of: None,
            approvers: None,
            provider: "GitHub",
            actor: "github:alice",
            id: "c0ffee",
            action: "https://bd.example.com/w/proj/gates/g",
            packet,
        })
    }

    /// The packet's section of `html`.
    fn section_of(html: &str) -> &str {
        let start = html.find("<section class=\"packet\"").expect("a packet section");
        let end = html.find(PACKET_CLOSE).expect("the section's end") + PACKET_CLOSE.len();
        &html[start..end]
    }

    /// The tags of `html`, between `<` and `>`.
    fn tags(html: &str) -> Vec<&str> {
        html.split('<').skip(1).map(|t| t.split('>').next().unwrap_or("")).collect()
    }

    #[test]
    fn the_approval_packet_is_confined_and_escaped() {
        let markdown = "# AUTHORED head\n\n<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n\
<form action=//evil><button>Approve</button></form>\n\n- [x] done\n- [ ] todo\n\n\
[top](#packet-h) [x](javascript:alert(1)) ![PIX](https://evil.example/p.png) AUTHORED\n\n\
| a | b |\n|---|---|\n| 1 | AUTHORED |\n\n```\"><script>\n<script>alert(2)</script>\n```\n\n\u{202E}rtl AUTHORED\n";
        let mut gate = source(Role::Gate, "g\"<x>\u{202E}", "<script>alert(1)</script>\u{202E}");
        gate.fields = vec![full(FieldKind::Description, markdown), full(FieldKind::Notes, "<b>AUTHORED</b>")];
        gate.comments = vec![comment("<b>mallory</b>\u{200B}", Text::Full("<script>bad()</script> AUTHORED".into()))];
        let mut held = source(Role::Held, "h", "Deploy <i>prod</i>");
        held.fields = vec![full(FieldKind::AcceptanceCriteria, "- [ ] AUTHORED")];
        let packet = Packet { playbook: false, sources: vec![gate, held], notes: Vec::new() };
        let page = packet_page(Some(&packet));
        let html = &page.html;

        let dl = html.find("</dl>").unwrap();
        let start = html.find("<section class=\"packet\"").unwrap();
        let end = html.find(PACKET_CLOSE).unwrap();
        let callout = html.find("<p class=\"callout\">").unwrap();
        assert!(dl < start && start < end && end < callout, "{html}");
        let section = section_of(html);
        assert!(balanced(section), "{section}");
        assert_eq!(html.matches("AUTHORED").count(), section.matches("AUTHORED").count(), "{html}");
        assert_eq!(section.matches("AUTHORED").count(), 7, "{section}");
        assert!(section.contains("<h2 id=\"packet-h\">Approval packet</h2>"), "{section}");

        // The page's own controls, once each; authored markup is text.
        assert_eq!(html.matches("<form").count(), 1, "{html}");
        assert_eq!(html.matches("<button").count(), 1, "{html}");
        assert_eq!(html.matches("name=\"approval\"").count(), 1, "{html}");
        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert_eq!(script_of(&page), ARMING);
        for tag in tags(html) {
            if tag.starts_with("input") {
                assert!(
                    tag == "input type=\"hidden\" name=\"approval\" value=\"c0ffee\""
                        || tag.starts_with("input type=\"checkbox\" disabled"),
                    "{tag}"
                );
            }
            assert!(!tag.split_whitespace().skip(1).any(|a| a.to_ascii_lowercase().starts_with("on")), "{tag}");
            assert!(!tag.starts_with("img") && !tag.contains("src="), "{tag}");
        }
        assert!(section.contains("<input type=\"checkbox\" disabled checked>"), "{section}");
        assert!(section.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{section}");
        assert!(section.contains("&lt;script&gt;alert(2)&lt;/script&gt;"), "{section}");
        assert!(section.contains("&lt;form action=//evil&gt;&lt;button&gt;Approve"), "{section}");
        assert!(section.contains("&lt;b&gt;mallory&lt;/b&gt;\\u200b"), "{section}");
        assert!(section.contains("<code>g&quot;&lt;x&gt;\\u202e</code> &lt;script&gt;"), "{section}");
        assert!(section.contains("\\u202ertl"), "{section}");
        assert!(section.contains("[image: PIX]") && !html.contains("evil.example/p.png\""), "{section}");
        assert!(!html.contains("href=\"javascript"), "{section}");
        assert!(section.contains("<div class=\"md-table\"><table>"), "{section}");
        assert!(section.contains("<h4>AUTHORED head</h4>"), "{section}");
        assert!(!html.contains('\u{202E}') && !html.contains('\u{200B}'), "{html}");
        // A jump to the server's own heading stays on the page.
        assert!(section.contains("<a href=\"#packet-h\">top</a>"), "{section}");

        // The policy is the page's without a packet.
        assert_eq!(page.csp, packet_page(None).csp);
        assert!(page.csp.contains("form-action 'self';") && !page.csp.contains("img-src"), "{}", page.csp);
        assert!(!packet_page(None).html.contains("class=\"packet\""));
    }

    #[test]
    fn sources_show_their_role_and_place() {
        let mut decision = source(Role::Decision, "d", "ADR");
        decision.under = Some("p<1>".into());
        decision.status = Status::Closed;
        let packet = Packet {
            playbook: true,
            sources: vec![
                source(Role::Gate, "g", "Gate"),
                source(Role::Held, "h", "Held"),
                source(Role::Run, "r", "Run"),
                source(Role::Prerequisite, "p<1>", "Prereq"),
                decision,
                source(Role::Parent, "pa", "Parent"),
            ],
            notes: Vec::new(),
        };
        let section = packet_section(&packet);
        assert!(balanced(&section), "{section}");
        for (open, role, id) in [
            (true, "Gate", "g"),
            (true, "Held work", "h"),
            (false, "Run", "r"),
            (false, "Prerequisite", "p&lt;1&gt;"),
            (false, "Decision record", "d"),
            (false, "Parent", "pa"),
        ] {
            let open = if open { " open" } else { "" };
            let head = format!(
                "<details class=\"src\"{open}><summary><span class=\"src-role\">{role}</span> <code>{id}</code> "
            );
            assert!(section.contains(&head), "{head} in {section}");
        }
        assert!(
            section.contains(
                "<code>d</code> ADR <span class=\"note\">closed</span> <span class=\"note\">under \
<code>p&lt;1&gt;</code></span></summary>"
            ),
            "{section}"
        );
        assert_eq!(section.matches("<p class=\"note\">No fields or comments.</p>").count(), 6, "{section}");
    }

    #[test]
    fn notices_name_the_record_and_how_to_read_it() {
        let notes = [
            (
                Note::HeldLimit { gate: "g<1>".into(), more: 1 },
                "1 more held issue not included. Full list: <code>bd show g&lt;1&gt;</code>.",
            ),
            (
                Note::HeldLimit { gate: "g<1>".into(), more: 3 },
                "3 more held issues not included. Full list: <code>bd show g&lt;1&gt;</code>.",
            ),
            (
                Note::Unavailable { id: "u<1>".into() },
                "Record <code>u&lt;1&gt;</code> unavailable. Full record: <code>bd show u&lt;1&gt;</code>.",
            ),
            (
                Note::EdgeLimit { at: "g".into(), during: Walk::Run },
                "Dependency read limit reached (256 rows) while looking up the run or parent of <code>g</code>: run, \
prerequisite and decision records not shown. Full record: <code>bd show g</code>.",
            ),
            (
                Note::EdgeLimit { at: "x".into(), during: Walk::Prerequisites },
                "Dependency read limit reached (256 rows) while reading the prerequisites of <code>x</code>: further \
prerequisite records not shown. Full record: <code>bd show x</code>.",
            ),
            (
                Note::EdgeLimit { at: "y".into(), during: Walk::Decisions },
                "Dependency read limit reached (256 rows) while reading the child records of <code>y</code>: its \
decision records and later records not shown. Full record: <code>bd show y</code>.",
            ),
            (
                Note::RecordLimit { at: "x".into(), during: Walk::Prerequisites },
                "Record limit reached (32 records) at the prerequisites of <code>x</code>: further records not shown. \
Full record: <code>bd show x</code>.",
            ),
            (
                Note::RecordLimit { at: "y".into(), during: Walk::Decisions },
                "Record limit reached (32 records) at the decision records of <code>y</code>: further records not \
shown. Full record: <code>bd show y</code>.",
            ),
        ];
        for (note, text) in &notes {
            assert_eq!(note_html(note), format!("<p class=\"notice\">{text}</p>\n"));
        }
        let packet = Packet {
            playbook: true,
            sources: vec![source(Role::Gate, "g", "Gate")],
            notes: notes.iter().map(|(n, _)| n.clone()).collect(),
        };
        let section = packet_section(&packet);
        assert!(balanced(&section), "{section}");
        assert!(notes.iter().all(|(_, text)| section.contains(text)), "{section}");

        let mut held = source(Role::Held, "h", "Held");
        held.fields = vec![
            Field {
                kind: FieldKind::Description,
                text: Text::Truncated { text: "a".repeat(16 * 1024), total_bytes: 21_000 },
            },
            Field { kind: FieldKind::Design, text: Text::Omitted { total_bytes: 5 } },
        ];
        held.comments = vec![
            comment("bob", Text::Truncated { text: "c".repeat(100), total_bytes: 2000 }),
            comment("bob", Text::Omitted { total_bytes: 2000 }),
        ];
        held.earlier_comments = 1;
        let section = packet_section(&Packet { playbook: false, sources: vec![held], notes: Vec::new() });
        for text in [
            "Shown: the first 16 KiB of 21 KiB. Full text: <code>bd show h</code>.",
            "<h3>Design</h3>\n<p class=\"notice\">Not shown: the packet's 128 KiB source limit was reached. Full text: \
<code>bd show h</code>.</p>",
            "1 earlier comment not shown: <code>bd comment list h</code>.",
            "Shown: the first 100 bytes of 2 KiB. Full text: <code>bd comment list h</code>.",
            "Not shown: the packet's 128 KiB source limit was reached. Full text: <code>bd comment list h</code>.",
            "<p class=\"note\">bob · 2023-11-14T22:13:20.000Z</p>",
        ] {
            assert!(section.contains(text), "{text} in {section}");
        }
        assert!(balanced(&section), "{section}");
    }

    #[test]
    fn long_ids_are_shown_whole() {
        let id = format!("proj-{}", "a".repeat(250));
        let decision_id = format!("proj-{}", "d".repeat(250));
        assert_eq!(id.len(), 255);
        let mut held = source(Role::Held, &id, "Held");
        held.fields = vec![
            Field { kind: FieldKind::Description, text: Text::Truncated { text: "x".into(), total_bytes: 20_000 } },
            Field { kind: FieldKind::Notes, text: Text::Omitted { total_bytes: 20_000 } },
        ];
        held.comments = vec![comment("bob", Text::Truncated { text: "y".into(), total_bytes: 20_000 })];
        held.earlier_comments = 3;
        let mut decision = source(Role::Decision, &decision_id, "ADR");
        decision.under = Some(id.clone());
        decision.fields = vec![full(FieldKind::Design, &"z".repeat(1000))];
        let packet = Packet { playbook: true, sources: vec![held, decision], notes: Vec::new() };
        let section = packet_section(&packet);
        assert!(balanced(&section), "{section}");
        assert!(!section.contains('…'), "{section}");
        assert!(section.contains(&format!("<code>{id}</code> Held")), "{section}");
        assert!(section.contains(&format!("under <code>{id}</code>")), "{section}");
        assert!(section.contains(&format!("<code>{decision_id}</code> ADR")), "{section}");
        assert_eq!(section.matches(&format!("<code>bd show {id}</code>")).count(), 2, "{section}");
        assert_eq!(section.matches(&format!("<code>bd comment list {id}</code>")).count(), 2, "{section}");

        // Its stub too, when the page has no room for more.
        let small = packet_section_within(&packet, 3500);
        assert!(balanced(&small) && small.len() <= 3500, "{small}");
        for id in [&id, &decision_id] {
            assert!(small.contains(&format!("<code>bd show {id}</code>")), "{small}");
            assert!(small.contains(&format!("<code>bd comment list {id}</code>")), "{small}");
        }
    }

    /// Text that is 1 byte stored and 6 shown, `n` times.
    fn expanding(n: usize) -> String {
        "\u{1}".repeat(n)
    }

    #[test]
    fn the_packet_stays_within_its_budget() {
        let big = 16 * 1024;
        let sources: Vec<Source> = (0..MAX_RECORDS)
            .map(|i| {
                let mut s = source(if i == 0 { Role::Gate } else { Role::Prerequisite }, &format!("proj-s{i:02}"), "t");
                s.fields = FieldKind::ALL.iter().map(|k| full(*k, &expanding(big))).collect();
                s.comments = (0..8).map(|_| comment("bob", Text::Full(expanding(big)))).collect();
                s.earlier_comments = 2;
                s
            })
            .collect();
        let packet = Packet { playbook: true, sources, notes: Vec::new() };
        let section = packet_section(&packet);
        assert!(section.len() <= MAX_PACKET_HTML, "{}", section.len());
        assert!(balanced(&section));
        // The first source's text took what room there was, piece by
        // piece; every later one still names itself and how to read it.
        assert!(section.contains("<h3>Notes</h3>\n<div class=\"md\"><p>\\u0001"), "rendered");
        assert!(section.contains(
            "Not shown: the rendered text exceeds the page's display limit. Full text: <code>bd comment list proj-s00</code>"
        ));
        for i in 1..MAX_RECORDS {
            let id = format!("proj-s{i:02}");
            assert!(section.contains(&format!("<code>bd show {id}</code>")), "{id}");
            assert!(section.contains(&format!("<code>bd comment list {id}</code>")), "{id}");
            assert!(section.contains(&format!("<code>{id}</code> t <span class=\"note\">open</span>")), "{id}");
        }

        // A fragment that does not fit is replaced whole.
        let table: String = std::iter::once("| a | b |\n|---|---|\n".to_string())
            .chain((0..200).map(|_| format!("| {} | x |\n", expanding(20))))
            .collect();
        let mut gate = source(Role::Gate, "g", "Gate");
        gate.fields = vec![full(FieldKind::Description, &table), full(FieldKind::Notes, "short NOTES")];
        let packet = Packet { playbook: false, sources: vec![gate], notes: Vec::new() };
        assert!(packet_section(&packet).contains("<table>"));
        let section = packet_section_within(&packet, 8 * 1024);
        assert!(section.len() <= 8 * 1024 && balanced(&section), "{section}");
        assert!(!section.contains("<table") && !section.contains("md-table"), "{section}");
        assert!(
            section.contains(
                "<h3>Description</h3>\n<p class=\"notice\">Not shown: the rendered text exceeds the page's display \
limit. Full text: <code>bd show g</code>.</p>"
            ),
            "{section}"
        );
        assert!(section.contains("short NOTES"), "{section}");

        // Too small for every stub (never so at MAX_PACKET_HTML): those that
        // fit, and how many did not.
        let packet = Packet {
            playbook: true,
            sources: (0..4).map(|i| source(Role::Prerequisite, &format!("p{i}"), "t")).collect(),
            notes: Vec::new(),
        };
        let section = packet_section_within(&packet, 1500);
        assert!(section.len() <= 1500 && balanced(&section), "{section}");
        assert!(section.contains("<code>bd show p0</code>"), "{section}");
        assert!(section.contains("Display limit reached: 1 more record not shown."), "{section}");
        let section = packet_section_within(&packet, 1200);
        assert!(section.len() <= 1200 && balanced(&section), "{section}");
        assert!(section.contains("Display limit reached: 2 more records not shown."), "{section}");
    }

    #[test]
    fn exhausted_budget_keeps_each_source_identifiable() {
        let mut gate = source(Role::Gate, "proj-gate", "Gate");
        gate.fields = vec![full(FieldKind::Description, &"g".repeat(3000))];
        let mut held = source(Role::Held, "proj-held", "Held");
        held.fields = FieldKind::ALL.iter().map(|k| full(*k, &"h".repeat(3000))).collect();
        held.comments = (0..8).map(|_| comment("bob", Text::Full("c".repeat(40)))).collect();
        let mut prereq = source(Role::Prerequisite, "proj-run.requirements", "Requirements <x>");
        prereq.fields = vec![full(FieldKind::Description, &format!("PREREQ-TEXT {}", "p".repeat(2000)))];
        prereq.comments = vec![comment("bob", Text::Full("PREREQ-COMMENT".into()))];
        prereq.status = Status::Closed;
        let mut decision = source(Role::Decision, "proj-run.requirements.adr", "ADR");
        decision.fields = vec![full(FieldKind::Design, &format!("DECISION-TEXT {}", "d".repeat(2000)))];
        decision.comments = vec![comment("bob", Text::Full("DECISION-COMMENT".into()))];
        decision.under = Some("proj-run.requirements".into());
        let packet = Packet { playbook: true, sources: vec![gate, held, prereq, decision], notes: Vec::new() };
        let max = 12 * 1024;
        let section = packet_section_within(&packet, max);
        assert!(section.len() <= max && balanced(&section), "{section}");
        assert!(section.contains(&"g".repeat(3000)), "the gate in full");
        assert!(section.contains(&"h".repeat(3000)), "the held work's first field");
        assert!(!section.contains("PREREQ-TEXT") && !section.contains("DECISION-TEXT"), "{section}");
        assert!(
            section.contains(
                "<summary><span class=\"src-role\">Prerequisite</span> <code>proj-run.requirements</code> \
Requirements &lt;x&gt; <span class=\"note\">closed</span></summary>"
            ),
            "{section}"
        );
        assert!(
            section.contains(
                "<summary><span class=\"src-role\">Decision record</span> <code>proj-run.requirements.adr</code> ADR \
<span class=\"note\">open</span> <span class=\"note\">under <code>proj-run.requirements</code></span></summary>"
            ),
            "{section}"
        );
        for id in ["proj-run.requirements", "proj-run.requirements.adr"] {
            assert!(section.contains(&format!("<code>bd show {id}</code>")), "{id} in {section}");
            assert!(section.contains(&format!("<code>bd comment list {id}</code>")), "{id} in {section}");
        }
        assert!(section.contains("Not shown: the page's display limit was reached."), "{section}");
        // With room, they show in full.
        let section = packet_section(&packet);
        assert!(section.contains("PREREQ-TEXT") && section.contains("DECISION-TEXT"), "{section}");
    }

    #[test]
    fn worst_case_stubs_fit() {
        let ids: Vec<String> = (0..MAX_RECORDS).map(|i| format!("{i:02}-{}", "z".repeat(252))).collect();
        // The title that comes out longest, cut to 500 characters as SQL cuts it.
        let title = ['\u{1}', '&', '"', '\u{202E}', '\u{FEFF}', '\u{E0001}', '\u{10FFFF}']
            .iter()
            .map(|c| c.to_string().repeat(500))
            .max_by_key(|t| shown(t, MAX_TITLE).len())
            .unwrap();
        let sources: Vec<Source> = ids
            .iter()
            .map(|id| {
                let mut s = source(Role::Decision, id, &title);
                s.under = Some(ids[0].clone());
                s
            })
            .collect();
        let mut notes = vec![Note::HeldLimit { gate: ids[0].clone(), more: usize::MAX }];
        notes.extend(ids.iter().take(MAX_HELD).map(|id| Note::Unavailable { id: id.clone() }));
        for during in [Walk::Run, Walk::Prerequisites, Walk::Decisions] {
            notes.push(Note::EdgeLimit { at: ids[1].clone(), during });
            notes.push(Note::RecordLimit { at: ids[1].clone(), during });
        }
        let header = packet_section(&Packet { playbook: true, sources: Vec::new(), notes: notes.clone() });
        let stubs: usize = sources.iter().map(|s| stub(s).len()).sum();
        let total = header.len() + stubs;
        assert!(total < MAX_PACKET_HTML / 4, "{total}");
        let section = packet_section(&Packet { playbook: true, sources, notes });
        assert!(balanced(&section) && section.len() <= total, "{}", section.len());
        assert!(!section.contains("Display limit reached"));
    }

    #[test]
    fn packet_styles_are_scoped() {
        let lines: Vec<&str> = STYLE.lines().skip_while(|l| !l.starts_with(".packet")).collect();
        assert!(lines.len() > 10);
        for line in lines.iter().filter(|l| !l.is_empty()) {
            let selectors = line.split('{').next().unwrap();
            // Commas outside parentheses separate selectors.
            let mut depth = 0;
            let top = selectors.char_indices().filter(|&(_, c)| {
                depth += (c == '(') as i32 - (c == ')') as i32;
                c == ',' && depth == 0
            });
            let mut from = 0;
            for (at, _) in top.chain(std::iter::once((selectors.len(), ','))) {
                assert!(selectors[from..at].starts_with(".packet"), "{line}");
                from = at + 1;
            }
            assert!(!line.contains("url("), "{line}");
        }
    }
}
