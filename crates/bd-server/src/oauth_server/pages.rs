//! The pages people see during an authorization (`authorize/`): the
//! consent page, refusals, and the page sending the browser on; and those
//! of a human gate's approval in the browser: the approval page and its
//! notices; and those of a one-time passkey link: the answer showing it, the
//! page it opens, its registration and the one notice a dead link gets. Every
//! value shown is escaped, and each page comes with the Content-Security-Policy
//! it needs: its inline style, and forms posting only where the consent or the
//! approval goes. The pages fetch nothing:
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
[hidden]{display:none!important}
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

/// The approval pages' script: [`ARMING`]'s focus rule, and the passkey
/// ceremony every Approve needs (`authorize::passkey`). It reads what the
/// server gave it only from the form's escaped `data-` attributes (the
/// ceremony) and the status line's (its messages), and writes messages
/// with `textContent` alone. The button is rendered disabled, and enabled
/// once the browser has what the ceremony needs (`getPublicKey` too, to
/// register a passkey). A submit asks for the passkey (`create()` for the
/// account's first, `get()` after), fills in the hidden fields and posts
/// the form; a cancelled or failed ceremony posts nothing, so the same page
/// can try again.
///
/// Where the page offers to add a passkey (`data-add-challenge`) and the
/// browser can register one, ticking the unnamed checkbox makes Approve stop
/// after `get()`, its fields filled, and show the second button: under the
/// same focus rule it runs `create()` with the add challenge, the account's
/// user handle and name, and its passkeys as `excludeCredentials`, then
/// enables and fills the five `new_*` fields (rendered disabled, so an
/// approval without adding never sends them) and posts both ceremonies'
/// fields. A cancelled `create()` disables them again and posts nothing.
/// Where the browser cannot register a passkey, the offer is hidden and the
/// page works as one without it.
pub(crate) const APPROVE: &str = "(function(){\
var since=document.hasFocus()?Date.now():0;\
addEventListener('focus',function(){since=Date.now();});\
addEventListener('blur',function(){since=0;});\
document.addEventListener('visibilitychange',function(){\
since=!document.hidden&&document.hasFocus()?Date.now():0;});\
var form=document.querySelector('form.actions');\
var status=document.querySelector('p[role=status]');\
if(!form||!status)return;\
var button=form.querySelector('button');\
var d=form.dataset,m=status.dataset,create=d.passkey==='create';\
var add=!!d.addChallenge&&!create,box=form.querySelector('input[type=checkbox]'),next=form.querySelectorAll('button')[1];\
var news=['new_credential','new_client_data','new_authenticator_data','new_public_key','new_algorithm'];\
function say(t){status.textContent=t||'';}\
function bytes(s){s=(s||'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';\
var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}\
function text(buf){var u=new Uint8Array(buf),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);\
return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}\
function put(name,value){form.elements[name].value=value;}\
function known(){return(d.credentials||'').split(' ').filter(Boolean).map(function(c){return{type:'public-key',id:bytes(c)};});}\
function hide(){if(box&&box.parentNode)box.parentNode.hidden=true;if(next){next.hidden=true;next.disabled=true;}}\
function quiet(){for(var i=0;i<news.length;i++)form.elements[news[i]].disabled=true;}\
var registers=window.AuthenticatorAttestationResponse&&\
typeof AuthenticatorAttestationResponse.prototype.getPublicKey==='function';\
var able=window.PublicKeyCredential&&navigator.credentials&&(!create||registers);\
if(!able){hide();say(m.unsupported);return;}\
if(add&&!registers)add=false;\
if(!add)hide();\
button.disabled=false;\
var busy=false;\
form.addEventListener('submit',function(e){\
e.preventDefault();\
if(busy||!since||Date.now()-since<600)return;\
busy=true;button.disabled=true;if(next)next.disabled=true;say(m.waiting);\
var challenge=bytes(d.challenge),asked;\
if(create){asked=navigator.credentials.create({publicKey:{rp:{id:d.rp,name:'bd'},\
user:{id:bytes(d.user),name:d.name,displayName:d.name},challenge:challenge,\
pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],\
authenticatorSelection:{userVerification:'required',residentKey:'preferred'},\
attestation:'none',timeout:300000}});}\
else{asked=navigator.credentials.get({publicKey:{rpId:d.rp,challenge:challenge,\
allowCredentials:known(),userVerification:'required',timeout:300000}});}\
asked.then(function(c){\
var r=c.response;\
put('credential',text(c.rawId));\
put('client_data',text(r.clientDataJSON));\
if(create){var k=r.getPublicKey();if(!k)throw new Error('no public key');\
put('authenticator_data',text(r.getAuthenticatorData()));\
put('public_key',text(k));put('algorithm',String(r.getPublicKeyAlgorithm()));}\
else{put('authenticator_data',text(r.authenticatorData));put('signature',text(r.signature));}\
if(add&&box&&box.checked){busy=false;button.disabled=false;next.hidden=false;next.disabled=false;say(m.added);return;}\
form.submit();\
}).catch(function(){busy=false;button.disabled=false;if(next&&!next.hidden)next.disabled=false;say(m.cancelled);});\
});\
if(add&&box&&next){\
box.addEventListener('change',function(){if(!box.checked){next.hidden=true;next.disabled=true;}});\
next.addEventListener('click',function(){\
if(busy||!box.checked||!since||Date.now()-since<600)return;\
busy=true;button.disabled=true;next.disabled=true;say(m.waiting);\
navigator.credentials.create({publicKey:{rp:{id:d.rp,name:'bd'},\
user:{id:bytes(d.user),name:d.name,displayName:d.name},challenge:bytes(d.addChallenge),\
pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],excludeCredentials:known(),\
authenticatorSelection:{userVerification:'required',residentKey:'preferred'},\
attestation:'none',timeout:300000}}).then(function(c){\
var r=c.response,k=r.getPublicKey();if(!k)throw new Error('no public key');\
var v=[text(c.rawId),text(r.clientDataJSON),text(r.getAuthenticatorData()),text(k),String(r.getPublicKeyAlgorithm())];\
for(var i=0;i<news.length;i++){var f=form.elements[news[i]];f.disabled=false;f.value=v[i];}\
form.submit();\
}).catch(function(){quiet();busy=false;button.disabled=false;next.disabled=false;say(m.cancelled);});\
});\
}\
})();";

/// The approval pages' script under a live allowance, used only for
/// [`PasskeyAsk::Allow`], so that [`APPROVE`] and every other page stay as
/// they are: [`ARMING`]'s focus rule on both buttons, what the server gave it
/// read only from the form's and the status line's escaped `data-` attributes,
/// and messages written with `textContent` alone. Both buttons are rendered
/// disabled.
///
/// Approve runs `create()` with the allowance's challenge, the account's user
/// handle and name, and its passkeys as `excludeCredentials`, then enables and
/// fills the five `allow_*` fields (rendered disabled, so that nothing else
/// sends them) and posts them. The second button runs `get()` with the
/// assertion's challenge and posts the assertion, the `allow_*` fields left
/// disabled, so nothing is spent. Where the browser cannot register a passkey
/// (no `getPublicKey`) the second button is hidden, the page says so, and
/// Approve runs that `get()`. A `create()` that failed disables the `allow_*`
/// fields again and posts nothing, so the same page can try again; one
/// refused because this device holds a passkey of the account
/// (`InvalidStateError`) points at the second button, and never starts `get()`
/// by itself: a new prompt needs its own click.
pub(crate) const APPROVE_ALLOWANCE: &str = "(function(){\
var since=document.hasFocus()?Date.now():0;\
addEventListener('focus',function(){since=Date.now();});\
addEventListener('blur',function(){since=0;});\
document.addEventListener('visibilitychange',function(){\
since=!document.hidden&&document.hasFocus()?Date.now():0;});\
var form=document.querySelector('form.actions');\
var status=document.querySelector('p[role=status]');\
if(!form||!status)return;\
var buttons=form.querySelectorAll('button'),button=buttons[0],other=buttons[1];\
var d=form.dataset,m=status.dataset;\
var allows=['allow_credential','allow_client_data','allow_authenticator_data','allow_public_key','allow_algorithm'];\
function say(t){status.textContent=t||'';}\
function bytes(s){s=(s||'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';\
var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}\
function text(buf){var u=new Uint8Array(buf),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);\
return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}\
function put(name,value){form.elements[name].value=value;}\
function known(){return(d.credentials||'').split(' ').filter(Boolean).map(function(c){return{type:'public-key',id:bytes(c)};});}\
function quiet(){for(var i=0;i<allows.length;i++)form.elements[allows[i]].disabled=true;}\
function asking(){busy=true;button.disabled=true;other.disabled=true;say(m.waiting);}\
function done(){busy=false;button.disabled=false;if(!other.hidden)other.disabled=false;}\
function existing(){\
navigator.credentials.get({publicKey:{rpId:d.rp,challenge:bytes(d.challenge),\
allowCredentials:known(),userVerification:'required',timeout:300000}}).then(function(c){\
var r=c.response;\
put('credential',text(c.rawId));\
put('client_data',text(r.clientDataJSON));\
put('authenticator_data',text(r.authenticatorData));\
put('signature',text(r.signature));\
form.submit();\
}).catch(function(){done();say(m.cancelled);});\
}\
var registers=window.AuthenticatorAttestationResponse&&\
typeof AuthenticatorAttestationResponse.prototype.getPublicKey==='function';\
if(!window.PublicKeyCredential||!navigator.credentials){other.hidden=true;say(m.unsupported);return;}\
var busy=false;\
button.disabled=false;\
if(registers)other.disabled=false;\
else{other.hidden=true;say(m.noRegister);}\
form.addEventListener('submit',function(e){\
e.preventDefault();\
if(busy||!since||Date.now()-since<600)return;\
asking();\
if(!registers){existing();return;}\
navigator.credentials.create({publicKey:{rp:{id:d.rp,name:'bd'},\
user:{id:bytes(d.user),name:d.name,displayName:d.name},challenge:bytes(d.allowChallenge),\
pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],excludeCredentials:known(),\
authenticatorSelection:{userVerification:'required',residentKey:'preferred'},\
attestation:'none',timeout:300000}}).then(function(c){\
var r=c.response,k=r.getPublicKey();if(!k)throw new Error('no public key');\
var v=[text(c.rawId),text(r.clientDataJSON),text(r.getAuthenticatorData()),text(k),String(r.getPublicKeyAlgorithm())];\
for(var i=0;i<allows.length;i++){var f=form.elements[allows[i]];f.disabled=false;f.value=v[i];}\
form.submit();\
}).catch(function(e){quiet();done();say(e&&e.name==='InvalidStateError'?m.held:m.cancelled);});\
});\
other.addEventListener('click',function(){\
if(busy||!since||Date.now()-since<600)return;\
asking();\
existing();\
});\
})();";

/// The script of the page a passkey link opens ([`landing_link`]): it moves
/// the link's secret from the URL's fragment, which no server is sent, into
/// the form's field, and takes it out of the address bar. It sends nothing:
/// only the person's press of the button does, so a scanner running scripts
/// starts no sign-in. A second link opened over this page differs from it only
/// in the fragment, so no page loads: it is taken from `hashchange`.
const OPEN_LINK: &str = "(function(){\
var form=document.querySelector('form.actions');\
function take(){\
if(form&&location.hash.length>1)form.elements.link.value=location.hash.slice(1);\
history.replaceState(null,'',location.pathname);\
}\
take();\
addEventListener('hashchange',take);\
})();";

/// The script of the page registering a passkey through a link
/// ([`register_link`]): [`ARMING`]'s focus rule and a `create()` with the
/// page's challenge, the account's user handle and name, and its passkeys as
/// `excludeCredentials`. As in [`APPROVE`], what the server gave it is read
/// only from the form's and the status line's escaped `data-` attributes,
/// messages are written with `textContent` alone, and the button, rendered
/// disabled, is enabled only where the browser can register a passkey
/// (`getPublicKey`). It has no `get()`, and nothing of an approval: a
/// cancelled or failed `create()` posts nothing, so the same page can try
/// again, and one refused because this device holds a passkey of the account
/// (`InvalidStateError`) says so.
const REGISTER_LINK: &str = "(function(){\
var since=document.hasFocus()?Date.now():0;\
addEventListener('focus',function(){since=Date.now();});\
addEventListener('blur',function(){since=0;});\
document.addEventListener('visibilitychange',function(){\
since=!document.hidden&&document.hasFocus()?Date.now():0;});\
var form=document.querySelector('form.actions');\
var status=document.querySelector('p[role=status]');\
if(!form||!status)return;\
var button=form.querySelector('button');\
var d=form.dataset,m=status.dataset;\
function say(t){status.textContent=t||'';}\
function bytes(s){s=(s||'').replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';\
var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}\
function text(buf){var u=new Uint8Array(buf),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);\
return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}\
function put(name,value){form.elements[name].value=value;}\
function known(){return(d.credentials||'').split(' ').filter(Boolean).map(function(c){return{type:'public-key',id:bytes(c)};});}\
var able=window.PublicKeyCredential&&navigator.credentials&&window.AuthenticatorAttestationResponse&&\
typeof AuthenticatorAttestationResponse.prototype.getPublicKey==='function';\
if(!able){say(m.unsupported);return;}\
button.disabled=false;\
var busy=false;\
form.addEventListener('submit',function(e){\
e.preventDefault();\
if(busy||!since||Date.now()-since<600)return;\
busy=true;button.disabled=true;say(m.waiting);\
navigator.credentials.create({publicKey:{rp:{id:d.rp,name:'bd'},\
user:{id:bytes(d.user),name:d.name,displayName:d.name},challenge:bytes(d.challenge),\
pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],excludeCredentials:known(),\
authenticatorSelection:{userVerification:'required',residentKey:'preferred'},\
attestation:'none',timeout:300000}}).then(function(c){\
var r=c.response,k=r.getPublicKey();if(!k)throw new Error('no public key');\
put('credential',text(c.rawId));\
put('client_data',text(r.clientDataJSON));\
put('authenticator_data',text(r.getAuthenticatorData()));\
put('public_key',text(k));\
put('algorithm',String(r.getPublicKeyAlgorithm()));\
form.submit();\
}).catch(function(e){busy=false;button.disabled=false;say(e&&e.name==='InvalidStateError'?m.held:m.cancelled);});\
});\
})();";

/// The script of an answer page showing a link ([`with_link`]): its button
/// copies the field's value, and where the browser will not, selects it to
/// copy by hand. Messages come from the status line's escaped `data-`
/// attributes, written with `textContent` alone. Without scripts the link
/// stays in its field, to select by hand.
const COPY_LINK: &str = "(function(){\
var field=document.querySelector('input[readonly]');\
var button=document.querySelector('button[type=button]');\
var status=document.querySelector('p[role=status]');\
if(!field||!button||!status)return;\
function pick(){field.focus();field.select();status.textContent=status.dataset.select;}\
button.addEventListener('click',function(){\
if(!navigator.clipboard||!navigator.clipboard.writeText){pick();return;}\
navigator.clipboard.writeText(field.value).then(function(){status.textContent=status.dataset.copied;},pick);\
});\
})();";

/// What the approval pages say about the passkey every approval needs. No
/// copy here names a person (`a_passkeys_copy_names_no_one`).
pub const PASSKEY_ENROLL: &str = "Approving first registers a passkey for this account: the browser asks for a \
fingerprint, face or device PIN. Later approvals ask for the same passkey.";
pub const PASSKEY_ASSERT: &str =
    "Approving asks for this account's passkey, unlocked with a fingerprint, face or device PIN.";
pub const PASSKEY_NO_SCRIPT: &str =
    "Approving needs a passkey, and passkeys need scripts: turn them on in this browser, then open the link again.";
pub const PASSKEY_UNSUPPORTED: &str = "This browser can't use passkeys here, so nothing can be approved from it. \
Open the link in a current browser.";
pub const PASSKEY_WAITING: &str = "Waiting for the passkey…";
pub const PASSKEY_CANCELLED: &str =
    "The passkey check was cancelled or didn't complete, so nothing was approved. Press Approve to try again.";
pub const PASSKEY_UNAVAILABLE_HOST: &str = "Approvals need a passkey, and passkeys work only at an https address \
with a host name. This server's address is an IP address, so nothing can be approved here. Ask the server's admin \
to serve bd at a host name.";
pub const PASSKEY_UNAVAILABLE_HTTPS: &str = "Approvals need a passkey, and passkeys work only at an https address \
with a host name (or http://localhost). This server's address is plain http, so nothing can be approved here. Ask \
the server's admin to serve bd over https.";
pub const PASSKEY_FAILED_GATE: &str =
    "The passkey check failed, so the gate was not approved. Open the gate's link again to try again.";
pub const PASSKEY_FAILED_OP: &str =
    "The passkey check failed, so nothing was changed. Open the approval link again to try again.";
pub const PASSKEY_ADD_OPTION: &str = "Also add a passkey on this device";
pub const PASSKEY_ADD_NEXT: &str = "The passkey was checked. Press Add the passkey and approve to register a passkey \
on this device and approve.";
pub const PASSKEY_ADD_BUTTON: &str = "Add the passkey and approve";
pub const PASSKEY_ALLOW: &str = "An admin allowed this account to add a passkey: approving registers a new passkey on \
this device, and the browser asks for a fingerprint, face or device PIN. Anyone who did not ask for this should use \
an existing passkey instead, and tell the admin.";
pub const PASSKEY_ALLOW_EXISTING: &str = "Use an existing passkey instead";
pub const PASSKEY_ALLOW_NO_REGISTER: &str = "This browser can't register a passkey, so the admin's allowance can't be \
used from it. Approving asks for a passkey this account already has.";
pub const PASSKEY_ALLOW_HELD: &str = "This device already has a passkey for this account, so a new one can't be \
registered on it. Press Use an existing passkey instead.";
pub const PASSKEY_ALLOW_ENDED: &str = "The admin's allowance has ended, so no passkey was registered and nothing was \
approved. Ask the admin again, or open the link again to use an existing passkey.";

/// The box on an approval page that makes a link for another device: named,
/// so that the browser's own submit sends it, and after the add box, which
/// [`APPROVE`] takes as the first checkbox.
const LINK_BOX: &str = "<label class=\"note\"><input type=\"checkbox\" name=\"make_link\" value=\"1\"> Also make a link to add a passkey \
on another device</label>";

/// What the answer page showing a link says, word for word as agreed: the
/// one copy that speaks to the person, as a warning has to
/// (`the_links_warning_is_the_agreed_text_and_is_filled_with_no_name`). The
/// warning ends with its expiry, which [`with_link`] adds.
pub const PASSKEY_LINK_SHOWN: &str = "You also have a link for another device:";
pub const PASSKEY_LINK_WARNING: &str = "Open this on your own new device. Don't send it to anyone else, whoever asks: \
anyone with this link and your sign-in can add a passkey to your account.";
pub const PASSKEY_LINK_STILL_WORKS: &str = "The link still works. You can try the approval again.";

/// The rest of what the link's pages say. No copy here names a person
/// (`a_passkeys_copy_names_no_one`).
pub const PASSKEY_LINK_FULL: &str =
    "This account now holds the most passkeys it can, so this link can't add another until one is removed.";
pub const PASSKEY_LINK_FIELD: &str = "Link for another device";
pub const PASSKEY_LINK_COPY: &str = "Copy the link";
pub const PASSKEY_LINK_COPIED: &str = "Copied.";
pub const PASSKEY_LINK_SELECT: &str = "The browser didn't copy it. The link is selected: copy it from the field.";
pub const PASSKEY_LINK_TITLE: &str = "Add a passkey";
pub const PASSKEY_LINK_LANDING: &str =
    "This link adds a passkey on this device, after a sign-in with the account that made it. It approves nothing.";
pub const PASSKEY_LINK_CONTINUE: &str = "Continue to sign in";
pub const PASSKEY_LINK_ONWARD: &str = "Going to sign in now.";
pub const PASSKEY_LINK_NO_SCRIPT: &str =
    "Adding a passkey needs scripts: turn them on in this browser, then open the link again.";
pub const PASSKEY_LINK_UNUSABLE_TITLE: &str = "Link not usable";
pub const PASSKEY_LINK_UNUSABLE: &str = "This link can't be used. Links work once, for a short time. Make a new one \
at an approval on a device that holds a passkey.";
pub const PASSKEY_LINK_LIMIT_TITLE: &str = "No room for a passkey";
pub const PASSKEY_LINK_LIMIT: &str = "This account holds the most passkeys it can, so this link can't add another. \
Ask the server's admin to remove one, then open the link again.";
pub const PASSKEY_LINK_FAILED_TITLE: &str = "Passkey not added";
pub const PASSKEY_LINK_FAILED: &str = "The passkey couldn't be added. Open the link again to try again.";
pub const PASSKEY_LINK_ADDED_TITLE: &str = "Passkey added";
pub const PASSKEY_LINK_ADDED: &str = "This device now holds a passkey for this account. Adding it approved nothing: \
an approval still asks for a passkey on its own page.";
pub const PASSKEY_LINK_ADD: &str = "Add the passkey";
pub const PASSKEY_LINK_UNSUPPORTED: &str = "This browser can't register a passkey, so none can be added from it. Open \
the link in a current browser.";
pub const PASSKEY_LINK_CANCELLED: &str =
    "The passkey check was cancelled or didn't complete, so no passkey was added. Press Add the passkey to try again.";
pub const PASSKEY_LINK_HELD: &str = "This device already has a passkey for this account, so a new one can't be \
registered on it.";

/// The passkey ceremony an approval page asks for.
#[derive(Clone, Debug)]
pub enum PasskeyAsk<'a> {
    /// The account's first approval: register a passkey (`create()`).
    Enroll {
        /// The challenge and the user handle, base64url.
        challenge: String,
        rp_id: &'a str,
        user: String,
        /// The account's actor, as the passkey is named.
        name: &'a str,
    },
    /// Use one of the account's passkeys (`get()`), by credential id
    /// (base64url); with `add`, also offer to add a passkey on this device,
    /// and with `link` too, to make a link for another device ([`LINK_BOX`]).
    /// The two go together: [`APPROVE`] would take a box alone for the add box.
    Assert { challenge: String, rp_id: &'a str, credentials: &'a [String], add: Option<PasskeyAdd<'a>>, link: bool },
    /// A live allowance: register a passkey on this device with no existing
    /// one (`create()` with `excludeCredentials`), `register` holding its
    /// challenge, or, the secondary path, use one of the account's passkeys
    /// (`get()`) as [`PasskeyAsk::Assert`] does. Nothing here names the
    /// allowance.
    Allow { challenge: String, rp_id: &'a str, credentials: &'a [String], register: PasskeyAdd<'a> },
    /// The server's address cannot be a relying party: no form, a notice.
    Unavailable { why: crate::webauthn::NoRp },
}

/// What an approval page offers for adding a passkey on this device
/// (`create()` with `excludeCredentials`): after one of the account's
/// passkeys was used, or under an allowance.
#[derive(Clone, Debug)]
pub struct PasskeyAdd<'a> {
    /// Its own challenge and the account's user handle, base64url.
    pub challenge: String,
    pub user: String,
    /// The account's actor, as the passkey is named.
    pub name: &'a str,
}

/// An approval page's form, posting `id` to `action` with the fields the
/// ceremony fills in, and what goes with it in the body (the status line,
/// the notes); or, where passkeys cannot be used, no form and a notice.
/// Every value is escaped. Returns the actions, the body's addition, and
/// the script to run.
fn approval_form(action: &str, id: &str, ask: &PasskeyAsk<'_>) -> (String, String, Option<&'static str>) {
    let (mode, data, note, add) = match ask {
        PasskeyAsk::Enroll { challenge, rp_id, user, name } => (
            "create",
            format!(
                " data-challenge=\"{}\" data-rp=\"{}\" data-user=\"{}\" data-name=\"{}\"",
                escape(challenge),
                escape(rp_id),
                escape(user),
                escape(name)
            ),
            PASSKEY_ENROLL,
            None,
        ),
        PasskeyAsk::Assert { challenge, rp_id, credentials, add, .. } => {
            let mut data = format!(
                " data-challenge=\"{}\" data-rp=\"{}\" data-credentials=\"{}\"",
                escape(challenge),
                escape(rp_id),
                escape(&credentials.join(" "))
            );
            if let Some(add) = add {
                data.push_str(&format!(
                    " data-add-challenge=\"{}\" data-user=\"{}\" data-name=\"{}\"",
                    escape(&add.challenge),
                    escape(&add.user),
                    escape(add.name)
                ));
            }
            ("get", data, PASSKEY_ASSERT, add.as_ref())
        }
        PasskeyAsk::Allow { challenge, rp_id, credentials, register } => (
            "allow",
            format!(
                " data-challenge=\"{}\" data-rp=\"{}\" data-credentials=\"{}\" data-allow-challenge=\"{}\" \
data-user=\"{}\" data-name=\"{}\"",
                escape(challenge),
                escape(rp_id),
                escape(&credentials.join(" ")),
                escape(&register.challenge),
                escape(&register.user),
                escape(register.name)
            ),
            PASSKEY_ALLOW,
            None,
        ),
        PasskeyAsk::Unavailable { why } => {
            let why = match why {
                crate::webauthn::NoRp::IpLiteral => PASSKEY_UNAVAILABLE_HOST,
                crate::webauthn::NoRp::NotSecure => PASSKEY_UNAVAILABLE_HTTPS,
            };
            return (String::new(), format!("<p class=\"lead\">{}</p>\n", escape(why)), None);
        }
    };
    let mut fields = format!("<input type=\"hidden\" name=\"approval\" value=\"{}\">\n", escape(id));
    for name in ["credential", "client_data", "authenticator_data", "signature", "public_key", "algorithm"] {
        fields.push_str(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\">\n"));
    }
    // Adding a passkey: its fields rendered disabled, so that only the
    // script's add, enabling them, sends them; an unnamed checkbox; and the
    // second button, hidden until the passkey in use was checked.
    let mut adding = String::new();
    let mut added = String::new();
    if add.is_some() {
        for name in ["new_credential", "new_client_data", "new_authenticator_data", "new_public_key", "new_algorithm"] {
            fields.push_str(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\" disabled>\n"));
        }
        adding = format!(
            "<label class=\"note\"><input type=\"checkbox\"> {}</label>\n\
<button type=\"button\" class=\"primary\" hidden disabled>{}</button>\n",
            escape(PASSKEY_ADD_OPTION),
            escape(PASSKEY_ADD_BUTTON)
        );
        if matches!(ask, PasskeyAsk::Assert { link: true, .. }) {
            adding.push_str(LINK_BOX);
            adding.push('\n');
        }
        added = format!(" data-added=\"{}\"", escape(PASSKEY_ADD_NEXT));
    }
    // Under an allowance: its fields rendered disabled, so that only the
    // script's registration, enabling them, sends them, and the second
    // button; the status line's two messages of its own.
    let mut script = APPROVE;
    if matches!(ask, PasskeyAsk::Allow { .. }) {
        for name in
            ["allow_credential", "allow_client_data", "allow_authenticator_data", "allow_public_key", "allow_algorithm"]
        {
            fields.push_str(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\" disabled>\n"));
        }
        adding = format!("<button type=\"button\" disabled>{}</button>\n", escape(PASSKEY_ALLOW_EXISTING));
        added = format!(
            " data-held=\"{}\" data-no-register=\"{}\"",
            escape(PASSKEY_ALLOW_HELD),
            escape(PASSKEY_ALLOW_NO_REGISTER)
        );
        script = APPROVE_ALLOWANCE;
    }
    let actions = format!(
        "<form method=\"post\" action=\"{action}\" class=\"actions\" data-passkey=\"{mode}\"{data}>\n\
{fields}<button type=\"submit\" class=\"primary\" disabled>Approve</button>\n\
{adding}</form>\n",
        action = escape(action),
    );
    let body = format!(
        "<p class=\"note\">{}</p>\n<noscript><p class=\"lead\">{}</p></noscript>\n\
<p class=\"lead\" role=\"status\" aria-live=\"polite\" data-unsupported=\"{}\" data-waiting=\"{}\" \
data-cancelled=\"{}\"{added}></p>\n",
        escape(note),
        escape(PASSKEY_NO_SCRIPT),
        escape(PASSKEY_UNSUPPORTED),
        escape(PASSKEY_WAITING),
        escape(PASSKEY_CANCELLED),
    );
    (actions, body, Some(script))
}

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
    /// The passkey ceremony the approval needs.
    pub passkey: PasskeyAsk<'a>,
}

/// The page asking a person to approve a human gate: what the gate is,
/// what it holds back, and who the approval is recorded as, with one
/// button. Its form posts only to this server (`'self'`), and its script
/// ([`APPROVE`]) keeps a double click from sending it and asks for the
/// passkey the approval needs ([`PasskeyAsk`]); where passkeys cannot be
/// used, the page has a notice and no form.
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
    let (actions, passkey, script) = approval_form(a.action, a.id, &a.passkey);
    let body = body + &passkey;
    let status = if script.is_some() { 200 } else { 403 };
    let parts = Parts { actions: &actions, form_action: "'self'", script, ..Parts::default() };
    page(status, "Approve a gate", &body, parts)
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
    /// The passkey ceremony the approval needs.
    pub passkey: PasskeyAsk<'a>,
}

/// The page asking a person to approve a close or discard that open human
/// gates refused: what it does, to what, at whose request and for what
/// reason, and the gates it gets past, with one button. As on the gate
/// approval page, every value is shown escaped, the form posts only to this
/// server and [`APPROVE`] keeps a double click from sending it and asks for
/// the passkey.
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
    let (actions, passkey, script) = approval_form(a.action, a.id, &a.passkey);
    let body = body + &passkey;
    let status = if script.is_some() { 200 } else { 403 };
    let parts = Parts { actions: &actions, form_action: "'self'", script, ..Parts::default() };
    page(status, "Approve an operation", &body, parts)
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

/// The page a passkey link opens: the same bytes for every link, live or
/// dead, as the secret is in the URL's fragment, which only [`OPEN_LINK`]
/// sees. A press of its button posts the secret to `action`, the link's
/// address with no fragment, with a query the POST never reads: the notice
/// answering a dead link sits at that URL, so a new link opened in its tab,
/// as the notice tells the person to, loads rather than being taken for a
/// move within the notice.
pub fn landing_link(action: &str) -> Page {
    let actions = format!(
        "<form method=\"post\" action=\"{}?open\" class=\"actions\">\n\
<input type=\"hidden\" name=\"link\" value=\"\">\n\
<button type=\"submit\" class=\"primary\">{}</button>\n</form>\n",
        escape(action),
        escape(PASSKEY_LINK_CONTINUE)
    );
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\"><div class=\"avatar\">{MARK}</div></div>\n\
<h1>{}</h1>\n<p class=\"lead\">{}</p>\n<noscript><p class=\"lead\">{}</p></noscript>\n",
        escape(PASSKEY_LINK_TITLE),
        escape(PASSKEY_LINK_LANDING),
        escape(PASSKEY_LINK_NO_SCRIPT)
    );
    let parts = Parts { actions: &actions, form_action: "'self'", script: Some(OPEN_LINK), ..Parts::default() };
    page(200, PASSKEY_LINK_TITLE, &body, parts)
}

/// A page sending the browser on to sign in at `url` after a live link's
/// POST. It is no redirect, for [`onward`]'s reason: the way to the provider
/// follows, and a redirect after a form would be under that form's
/// `form-action`.
pub fn sign_in_onward(url: &str) -> Page {
    let url = escape(url);
    let body = format!(
        "<h1>{continuing}</h1>\n<p class=\"lead\">{}\
 Nothing happening? <a href=\"{url}\">{continuing}</a>.</p>\n",
        escape(PASSKEY_LINK_ONWARD),
        continuing = escape(PASSKEY_LINK_CONTINUE),
    );
    let refresh = format!("<meta http-equiv=\"refresh\" content=\"0; url={url}\">\n");
    page(200, PASSKEY_LINK_CONTINUE, &body, Parts { head: &refresh, ..Parts::default() })
}

/// The one notice of a link that cannot be used, for whatever reason: it
/// takes no parameter, so that it can say none.
pub fn link_unusable() -> Page {
    notice(404, PASSKEY_LINK_UNUSABLE_TITLE, PASSKEY_LINK_UNUSABLE)
}

/// The notice of a link opened for an account with no room for a passkey.
/// Only the account's owner, signed in, sees it, and nothing was spent.
pub fn link_limit() -> Page {
    notice(409, PASSKEY_LINK_LIMIT_TITLE, PASSKEY_LINK_LIMIT)
}

/// The notice of a registration refused while its link lives on.
pub fn link_failed() -> Page {
    notice(403, PASSKEY_LINK_FAILED_TITLE, PASSKEY_LINK_FAILED)
}

/// The notice of a passkey added through a link, which approved nothing.
pub fn link_added() -> Page {
    notice(200, PASSKEY_LINK_ADDED_TITLE, PASSKEY_LINK_ADDED)
}

/// The notice of a link opened at an address passkeys can't be used at: it
/// says so as an approval's page does, and offers no form.
pub fn link_unavailable(why: crate::webauthn::NoRp) -> Page {
    let why = match why {
        crate::webauthn::NoRp::IpLiteral => PASSKEY_UNAVAILABLE_HOST,
        crate::webauthn::NoRp::NotSecure => PASSKEY_UNAVAILABLE_HTTPS,
    };
    notice(409, PASSKEY_LINK_FAILED_TITLE, why)
}

/// The passkey ceremony of a link's registration page: `create()` with the
/// account's passkeys excluded.
#[derive(Clone, Debug)]
pub struct LinkAsk<'a> {
    /// The challenge and the user handle, base64url.
    pub challenge: String,
    pub rp_id: &'a str,
    pub user_handle: String,
    /// The account's actor, as the passkey is named.
    pub user_name: &'a str,
    /// The account's passkeys, by credential id (base64url).
    pub excluded: &'a [String],
}

/// The page registering a passkey on this device for `actor`, after a link
/// and its sign-in. Its form posts `id`, the page's one-time id, to `action`
/// with the registration's five fields, which [`REGISTER_LINK`] fills in. It
/// shares no field that means anything at an approval's POST, and says that
/// it approves nothing.
pub fn register_link(action: &str, id: &str, actor: &str, ask: &LinkAsk<'_>) -> Page {
    let mut fields = format!("<input type=\"hidden\" name=\"id\" value=\"{}\">\n", escape(id));
    for name in ["credential", "client_data", "authenticator_data", "public_key", "algorithm"] {
        fields.push_str(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\">\n"));
    }
    let actions = format!(
        "<form method=\"post\" action=\"{}\" class=\"actions\" data-passkey=\"create\" data-challenge=\"{}\" \
data-rp=\"{}\" data-user=\"{}\" data-name=\"{}\" data-credentials=\"{}\">\n\
{fields}<button type=\"submit\" class=\"primary\" disabled>{}</button>\n</form>\n",
        escape(action),
        escape(&ask.challenge),
        escape(ask.rp_id),
        escape(&ask.user_handle),
        escape(ask.user_name),
        escape(&ask.excluded.join(" ")),
        escape(PASSKEY_LINK_ADD)
    );
    let body = format!(
        "<div class=\"link\" aria-hidden=\"true\"><div class=\"avatar\">{MARK}</div></div>\n\
<h1>{}</h1>\n<p class=\"lead\">Add a passkey on this device for {}. This approves nothing.</p>\n\
<noscript><p class=\"lead\">{}</p></noscript>\n\
<p class=\"lead\" role=\"status\" aria-live=\"polite\" data-unsupported=\"{}\" data-waiting=\"{}\" \
data-cancelled=\"{}\" data-held=\"{}\"></p>\n",
        escape(PASSKEY_LINK_TITLE),
        shown(actor, MAX_TITLE),
        escape(PASSKEY_LINK_NO_SCRIPT),
        escape(PASSKEY_LINK_UNSUPPORTED),
        escape(PASSKEY_WAITING),
        escape(PASSKEY_LINK_CANCELLED),
        escape(PASSKEY_LINK_HELD),
    );
    let parts = Parts { actions: &actions, form_action: "'self'", script: Some(REGISTER_LINK), ..Parts::default() };
    page(200, PASSKEY_LINK_TITLE, &body, parts)
}

/// A link just made, as its answer page shows it. It holds the link's secret,
/// so it derives nothing: not even `Debug` can print it.
pub struct LinkShown<'a> {
    /// The link, the one place a person is ever given it.
    pub url: &'a str,
    /// When it ends, as words followed by `UTC`.
    pub until: &'a str,
    /// Whether the approval it came with went through.
    pub approved: bool,
    /// Whether the approval left the account with no room for the link's
    /// passkey.
    pub full: bool,
}

/// `page`, an approval's answer of any status, with the link just made shown
/// under the outcome's own text: the link in a field to copy, the warning,
/// and whether it outlives an approval that did not go through. The page
/// keeps its status. Answer pages run no script, so [`COPY_LINK`] is the only
/// one its policy allows.
pub fn with_link(page: Page, link: &LinkShown<'_>) -> Page {
    let Page { status, html, csp } = page;
    debug_assert!(!csp.contains("script-src"), "an answer page runs no script: {csp}");
    let mut block = format!(
        "<p class=\"lead\">{}</p>\n\
<div class=\"actions\"><input type=\"text\" readonly size=\"32\" aria-label=\"{}\" value=\"{}\">\
<button type=\"button\" class=\"primary\">{}</button></div>\n\
<p class=\"note\" role=\"status\" aria-live=\"polite\" data-copied=\"{}\" data-select=\"{}\"></p>\n\
<p class=\"callout\">{SHIELD}<span>{} It works once, until {} UTC.</span></p>\n",
        escape(PASSKEY_LINK_SHOWN),
        escape(PASSKEY_LINK_FIELD),
        escape(link.url),
        escape(PASSKEY_LINK_COPY),
        escape(PASSKEY_LINK_COPIED),
        escape(PASSKEY_LINK_SELECT),
        escape(PASSKEY_LINK_WARNING),
        escape(link.until),
    );
    if !link.approved {
        block.push_str(&format!("<p class=\"lead\">{}</p>\n", escape(PASSKEY_LINK_STILL_WORKS)));
    }
    if link.full {
        block.push_str(&format!("<p class=\"lead\">{}</p>\n", escape(PASSKEY_LINK_FULL)));
    }
    // Every value on a page is escaped, so neither tag can come from one.
    let bar = "<div class=\"bar\">";
    let html = html.replacen(bar, &format!("{block}{bar}"), 1).replacen(
        "</body>",
        &format!("<script>{COPY_LINK}</script>\n</body>"),
        1,
    );
    let hash = STANDARD.encode(Sha256::digest(COPY_LINK.as_bytes()));
    let csp = csp.replacen("form-action ", &format!("script-src 'sha256-{hash}'; form-action "), 1);
    Page { status, html, csp }
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

    /// The ceremony of an account's first approval, as the tests show it.
    fn enroll() -> PasskeyAsk<'static> {
        PasskeyAsk::Enroll {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            user: "dXNlcg".into(),
            name: "github:octocat",
        }
    }

    /// The ceremony of a later approval, with the account's `credentials`.
    fn assert_with(credentials: &[String]) -> PasskeyAsk<'_> {
        PasskeyAsk::Assert {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            credentials,
            add: None,
            link: false,
        }
    }

    /// The ceremony of a later approval, with the account's `credentials`,
    /// offering to add a passkey with `add`.
    fn assert_adding<'a>(credentials: &'a [String], add: PasskeyAdd<'a>) -> PasskeyAsk<'a> {
        PasskeyAsk::Assert {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            credentials,
            add: Some(add),
            link: false,
        }
    }

    /// As [`assert_adding`], offering a link for another device too: the
    /// page of an account with 1 to 98 passkeys.
    fn assert_linking<'a>(credentials: &'a [String], add: PasskeyAdd<'a>) -> PasskeyAsk<'a> {
        PasskeyAsk::Assert {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            credentials,
            add: Some(add),
            link: true,
        }
    }

    /// The ceremony under a live allowance, with the account's `credentials`,
    /// registering with `register`.
    fn allow_with<'a>(credentials: &'a [String], register: PasskeyAdd<'a>) -> PasskeyAsk<'a> {
        PasskeyAsk::Allow { challenge: "Y2hhbGxlbmdl".into(), rp_id: "bd.example.com", credentials, register }
    }

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
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string(), "AAAAAAAAAAAAy2zQ".to_string()];
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
                    passkey: enroll(),
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
                    passkey: assert_with(&credentials),
                }),
            ),
            (
                "approve-gate-adding",
                "Approving a human gate, offering to add a passkey on this device",
                approve_gate(&ApproveGate {
                    workspace: "proj",
                    gate: "proj-a1b2",
                    title: "Release sign-off",
                    holds: &[("proj-c3d4".to_string(), "Deploy to production".to_string(), "open".to_string())],
                    part_of: None,
                    approvers: Some(&["github:octocat".to_string()]),
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/gates/proj-a1b2",
                    packet: None,
                    passkey: assert_adding(
                        &credentials,
                        PasskeyAdd {
                            challenge: "YWRkLWNoYWxsZW5nZQ".into(),
                            user: "dXNlcg".into(),
                            name: "github:octocat",
                        },
                    ),
                }),
            ),
            (
                "approve-gate-allowance",
                "Approving a human gate under an admin's allowance to register a passkey",
                approve_gate(&ApproveGate {
                    workspace: "proj",
                    gate: "proj-a1b2",
                    title: "Release sign-off",
                    holds: &[("proj-c3d4".to_string(), "Deploy to production".to_string(), "open".to_string())],
                    part_of: None,
                    approvers: Some(&["github:octocat".to_string()]),
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "c0ffee",
                    action: "https://bd.example.com/w/proj/gates/proj-a1b2",
                    packet: None,
                    passkey: allow_with(
                        &credentials,
                        PasskeyAdd {
                            challenge: "YWxsb3ctY2hhbGxlbmdl".into(),
                            user: "dXNlcg".into(),
                            name: "github:octocat",
                        },
                    ),
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
                    passkey: assert_with(&credentials),
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
                    passkey: enroll(),
                }),
            ),
            (
                "approve-gate-unavailable",
                "Approving a human gate at an IP address: no passkeys, no form",
                approve_gate(&ApproveGate {
                    workspace: "proj",
                    gate: "proj-a1b2",
                    title: "Release sign-off",
                    holds: &[],
                    part_of: None,
                    approvers: None,
                    provider: "GitHub",
                    actor: "github:octocat",
                    id: "",
                    action: "",
                    packet: None,
                    passkey: PasskeyAsk::Unavailable { why: crate::webauthn::NoRp::IpLiteral },
                }),
            ),
            (
                "gate-notice",
                "A gate already resolved",
                notice(200, "Already resolved", "This gate was resolved already: there is nothing to approve."),
            ),
            ("link-box", "An approval page offering a link for another device", {
                let adding = PasskeyAdd { challenge: "YWRk".into(), user: "dXNlcg".into(), name: "github:octocat" };
                gate_asking(assert_linking(&credentials, adding))
            }),
            (
                "link-shown",
                "The answer to an approval that made a link",
                with_link(
                    notice(
                        200,
                        "Approved",
                        "Gate proj-a1b2 in proj is resolved, recorded as approved by github:octocat.",
                    ),
                    &preview_link(true, false),
                ),
            ),
            (
                "link-shown-refused",
                "An approval refused after it made a link, with the account now full",
                with_link(
                    refusal(403, "Not approved", "The gate's approvers do not include this account.", None),
                    &preview_link(false, true),
                ),
            ),
            ("link-landing", "The page a link opens", landing_link("https://bd.example.com/oauth/passkey-link")),
            (
                "link-onward",
                "On to sign in, from a live link",
                sign_in_onward("https://bd.example.com/oauth/choose?flow=sealed"),
            ),
            ("link-unusable", "A link that cannot be used", link_unusable()),
            ("link-limit", "A link for an account with no room for a passkey", link_limit()),
            ("link-failed", "A link's registration refused", link_failed()),
            ("link-added", "A passkey added through a link", link_added()),
            (
                "link-unavailable",
                "A link opened where passkeys cannot be used",
                link_unavailable(crate::webauthn::NoRp::NotSecure),
            ),
            (
                "link-register",
                "Registering a passkey through a link",
                register_link(
                    "https://bd.example.com/oauth/passkey-link/register",
                    "c0ffee",
                    "github:octocat",
                    &link_ask(&credentials),
                ),
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
            passkey: enroll(),
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

        assert_eq!(script_of(&page), ARMING, "the consent page keeps its own");

        // The approval pages run their own script, and only it.
        let page = gate_page("Ship it", "proj");
        assert_eq!(page.html.matches("<script").count(), 1);
        assert_eq!(script_of(&page), APPROVE);
        let approve = STANDARD.encode(Sha256::digest(APPROVE.as_bytes()));
        assert!(page.csp.contains(&format!("; script-src 'sha256-{approve}';")), "{}", page.csp);
        let form = "<form method=\"post\" action=\"https://bd.example.com/w/proj/gates/g&quot;&gt;&lt;x&gt;\" \
class=\"actions\" data-passkey=\"create\" data-challenge=\"Y2hhbGxlbmdl\" data-rp=\"bd.example.com\" \
data-user=\"dXNlcg\" data-name=\"github:octocat\">\n<input type=\"hidden\" name=\"approval\" value=\"c0ffee\">";
        assert!(page.html.contains(form), "{}", page.html);

        let options = [("GitHub".to_string(), "https://bd.example.com/oauth/choose?flow=f".to_string())];
        for other in [
            refusal(403, "t", "w", Some("https://app.example/cb")),
            onward("https://app.example/cb"),
            notice(404, "t", "w"),
            choose("Sign in to approve gate g in proj", &options),
            sign_in_onward("https://bd.example.com/oauth/choose?flow=f"),
            link_unusable(),
            link_limit(),
            link_failed(),
            link_added(),
            link_unavailable(crate::webauthn::NoRp::IpLiteral),
        ] {
            assert!(!other.html.contains("<script") && !other.csp.contains("script-src"), "{}", other.csp);
        }
    }

    /// The gate approval page asking for `passkey`.
    fn gate_asking(passkey: PasskeyAsk<'_>) -> Page {
        approve_gate(&ApproveGate {
            workspace: "proj",
            gate: "g",
            title: "Ship it",
            holds: &[],
            part_of: None,
            approvers: None,
            provider: "GitHub",
            actor: "github:octocat",
            id: "c0ffee",
            action: "https://bd.example.com/w/proj/gates/g",
            packet: None,
            passkey,
        })
    }

    #[test]
    fn the_approval_pages_ask_for_a_passkey_with_their_one_script() {
        let approve = STANDARD.encode(Sha256::digest(APPROVE.as_bytes()));
        let evil = "\"><script>alert(1)</script>";
        let credentials = [evil.to_string(), "AAAAAAAAAAAAx1zQ".to_string()];
        let hostile_enroll = PasskeyAsk::Enroll { challenge: evil.into(), rp_id: evil, user: evil.into(), name: evil };
        let pages = [
            ("enroll", gate_asking(enroll()), "create"),
            ("assert", gate_asking(assert_with(&credentials)), "get"),
            ("hostile", gate_asking(hostile_enroll), "create"),
            ("operation", operation_page("proj", None, &[], None), "create"),
        ];
        for (what, page, mode) in &pages {
            let html = &page.html;
            assert_eq!(page.status, 200, "{what}");
            assert_eq!(html.matches("<script").count(), 1, "{what}: {html}");
            assert_eq!(script_of(page), APPROVE, "{what}");
            assert!(page.csp.contains(&format!("; script-src 'sha256-{approve}';")), "{what}: {}", page.csp);
            assert!(html.contains(&format!("data-passkey=\"{mode}\"")), "{what}: {html}");
            // Rendered disabled: only the script, once it found what the ceremony needs, enables it.
            assert_eq!(html.matches("<button").count(), 1, "{what}: {html}");
            assert!(html.contains("<button type=\"submit\" class=\"primary\" disabled>Approve</button>"), "{what}");
            assert!(
                html.contains(&format!("<noscript><p class=\"lead\">{}</p></noscript>", escape(PASSKEY_NO_SCRIPT)))
            );
            assert!(html.contains("role=\"status\" aria-live=\"polite\""), "{what}: {html}");
            let note = if *mode == "create" { PASSKEY_ENROLL } else { PASSKEY_ASSERT };
            assert!(html.contains(&escape(note)), "{what}: {html}");
            assert!(!html.contains("<script>alert"), "{what}: {html}");
            for tag in tags(html) {
                assert!(!tag.split_whitespace().skip(1).any(|a| a.to_ascii_lowercase().starts_with("on")), "{tag}");
            }
        }
        let html = &pages[1].1.html;
        assert!(
            html.contains("data-credentials=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt; AAAAAAAAAAAAx1zQ\""),
            "{html}"
        );
        let html = &pages[2].1.html;
        let shown = "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
        for attribute in ["data-challenge", "data-rp", "data-user", "data-name"] {
            assert!(html.contains(&format!("{attribute}=\"{shown}\"")), "{attribute}: {html}");
        }
        // The script writes messages as text, runs nothing it is given, and has no handlers in the page.
        for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function(", "document.write"] {
            assert!(!APPROVE.contains(banned), "{banned}");
        }
        assert!(APPROVE.contains("textContent") && APPROVE.contains("userVerification:'required'"));
        assert!(APPROVE.contains("alg:-7") && APPROVE.contains("alg:-257") && APPROVE.contains("timeout:300000"));
        assert!(APPROVE.contains("attestation:'none'") && APPROVE.contains("residentKey:'preferred'"));
        assert!(APPROVE.contains("getPublicKey") && APPROVE.contains("Date.now()-since<600"));
        // Adding a passkey: a second create(), with its own challenge, never one of the account's passkeys again.
        assert_eq!(APPROVE.matches("navigator.credentials.create(").count(), 2);
        assert!(APPROVE.contains("excludeCredentials:known()") && APPROVE.contains("challenge:bytes(d.addChallenge)"));
        assert!(APPROVE.contains("allowCredentials:known()") && APPROVE.contains("say(m.added)"));
        assert_eq!(APPROVE.matches("userVerification:'required'").count(), 3);
        assert_eq!(APPROVE.matches("attestation:'none'").count(), 2);
        assert_eq!(APPROVE.matches("alg:-7}").count(), 2);
        assert_eq!(APPROVE.matches("alg:-257}").count(), 2);
        assert!(APPROVE.contains("next.addEventListener('click'"));

        // Where passkeys cannot be used: the facts and a notice, no form, button or script.
        for (why, notice) in [
            (crate::webauthn::NoRp::IpLiteral, PASSKEY_UNAVAILABLE_HOST),
            (crate::webauthn::NoRp::NotSecure, PASSKEY_UNAVAILABLE_HTTPS),
        ] {
            let page = gate_asking(PasskeyAsk::Unavailable { why });
            assert_eq!(page.status, 403);
            assert!(page.html.contains("<h1>Approve Ship it?</h1>"), "{}", page.html);
            assert!(page.html.contains(&escape(notice)), "{}", page.html);
            assert!(!page.html.contains("<form") && !page.html.contains("<button"), "{}", page.html);
            assert!(!page.html.contains("<script") && !page.csp.contains("script-src"), "{}", page.csp);
            assert!(!page.html.contains(">Approve<"), "{}", page.html);
        }
        let mut page = operation_page("proj", None, &[], None);
        assert!(page.html.contains("<form"));
        page = approve_operation(&ApproveOperation {
            workspace: "proj",
            op_label: "close",
            issue: "bd-1",
            title: "t",
            status: "open",
            part_of: None,
            reason: None,
            requester: "alice",
            at: 0,
            failed: false,
            force: false,
            gates: &[],
            deletes: None,
            provider: "GitHub",
            actor: "github:octocat",
            id: "",
            action: "",
            passkey: PasskeyAsk::Unavailable { why: crate::webauthn::NoRp::IpLiteral },
        });
        assert_eq!(page.status, 403);
        assert!(!page.html.contains("<form") && !page.html.contains("<script"), "{}", page.html);
        assert!(page.html.contains(&escape(PASSKEY_UNAVAILABLE_HOST)), "{}", page.html);
    }

    #[test]
    fn the_add_option_is_offered_only_with_its_part() {
        let approve = STANDARD.encode(Sha256::digest(APPROVE.as_bytes()));
        let evil = "\"><script>alert(1)</script>";
        let shown = "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
        let credentials = [evil.to_string(), "AAAAAAAAAAAAx1zQ".to_string()];
        let adding = PasskeyAdd { challenge: evil.into(), user: evil.into(), name: evil };
        let page = gate_asking(assert_adding(&credentials, adding));
        let html = &page.html;
        assert_eq!(page.status, 200);
        assert!(html.contains("data-passkey=\"get\""), "{html}");
        assert_eq!(html.matches("<button").count(), 2, "{html}");
        assert!(html.contains("<button type=\"submit\" class=\"primary\" disabled>Approve</button>"), "{html}");
        let second = html.match_indices("<button").nth(1).map(|(at, _)| &html[at..]).unwrap();
        let second = &second[..second.find("</button>").unwrap() + "</button>".len()];
        assert_eq!(
            second,
            "<button type=\"button\" class=\"primary\" hidden disabled>Add the passkey and approve</button>"
        );
        assert_eq!(html.matches("<input type=\"checkbox\"").count(), 1, "{html}");
        assert!(
            html.contains(&format!(
                "<label class=\"note\"><input type=\"checkbox\"> {}</label>",
                escape(PASSKEY_ADD_OPTION)
            )),
            "{html}"
        );
        let checkbox = tags(html).into_iter().find(|t| t.contains("checkbox")).unwrap();
        assert!(
            !checkbox.contains("name=") && !checkbox.contains("checked") && !checkbox.contains("id="),
            "{checkbox}"
        );
        for name in ["new_credential", "new_client_data", "new_authenticator_data", "new_public_key", "new_algorithm"] {
            assert!(html.contains(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\" disabled>")), "{name}");
        }
        assert_eq!(html.matches("name=\"new_").count(), 5, "{html}");
        assert!(html.contains(&format!("data-added=\"{}\"", escape(PASSKEY_ADD_NEXT))), "{html}");
        for attribute in ["data-add-challenge", "data-user", "data-name"] {
            assert!(html.contains(&format!("{attribute}=\"{shown}\"")), "{attribute}: {html}");
        }
        assert!(html.contains(&format!("data-credentials=\"{shown} AAAAAAAAAAAAx1zQ\"")), "{html}");
        assert!(!html.contains("<script>alert"), "{html}");
        assert_eq!(html.matches("<script").count(), 1, "{html}");
        assert_eq!(script_of(&page), APPROVE);
        assert!(page.csp.contains(&format!("; script-src 'sha256-{approve}';")), "{}", page.csp);
        // No handlers: attribute names only, as the copy in values says "on this device".
        for tag in tags(html) {
            let names = tag.split('"').step_by(2).collect::<Vec<_>>().join(" ");
            assert!(!names.split_whitespace().skip(1).any(|a| a.to_ascii_lowercase().starts_with("on")), "{tag}");
        }
        assert!(
            html.contains(&format!("<noscript><p class=\"lead\">{}</p></noscript>", escape(PASSKEY_NO_SCRIPT))),
            "{html}"
        );

        // Without its part: the page as it was, nothing of adding.
        let plain = gate_asking(assert_with(&credentials));
        for absent in ["name=\"new_", "type=\"checkbox\"", "data-add-challenge", "data-added", "data-user", "data-name"]
        {
            assert!(!plain.html.contains(absent), "{absent}: {}", plain.html);
        }
        assert_eq!(plain.html.matches("<button").count(), 1, "{}", plain.html);
        // And an enrollment never offers it.
        let enrolling = gate_asking(enroll());
        assert!(!enrolling.html.contains("data-add-challenge") && !enrolling.html.contains("type=\"checkbox\""));
    }

    #[test]
    fn the_allowance_page_registers_with_its_own_script_and_keeps_the_assertion() {
        let script = STANDARD.encode(Sha256::digest(APPROVE_ALLOWANCE.as_bytes()));
        let evil = "\"><script>alert(1)</script>";
        let shown = "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
        let credentials = [evil.to_string(), "AAAAAAAAAAAAx1zQ".to_string()];
        let register = || PasskeyAdd { challenge: evil.into(), user: evil.into(), name: evil };
        let hostile = || PasskeyAsk::Allow {
            challenge: evil.into(),
            rp_id: evil,
            credentials: &credentials,
            register: register(),
        };
        for page in [gate_asking(hostile()), operation_asking(hostile())] {
            let html = &page.html;
            assert_eq!(page.status, 200);
            assert!(html.contains("data-passkey=\"allow\""), "{html}");
            for attribute in ["data-challenge", "data-rp", "data-allow-challenge", "data-user", "data-name"] {
                assert!(html.contains(&format!("{attribute}=\"{shown}\"")), "{attribute}: {html}");
            }
            assert!(html.contains(&format!("data-credentials=\"{shown} AAAAAAAAAAAAx1zQ\"")), "{html}");
            assert!(!html.contains("<script>alert"), "{html}");
            // Its own script, under its own hash: not APPROVE's.
            assert_eq!(html.matches("<script").count(), 1, "{html}");
            assert_eq!(script_of(&page), APPROVE_ALLOWANCE);
            assert!(page.csp.contains(&format!("; script-src 'sha256-{script}';")), "{}", page.csp);
            assert_eq!(page.csp.matches("sha256-").count(), 2, "the style and this script: {}", page.csp);
            // Both buttons rendered disabled; the second no primary action, and it posts nothing by itself.
            assert_eq!(html.matches("<button").count(), 2, "{html}");
            assert!(html.contains("<button type=\"submit\" class=\"primary\" disabled>Approve</button>"), "{html}");
            let second = format!("<button type=\"button\" disabled>{}</button>", escape(PASSKEY_ALLOW_EXISTING));
            assert!(html.contains(&second), "{html}");
            // The six hidden fields as ever, the five of its own disabled, nothing of adding.
            for name in ["credential", "client_data", "authenticator_data", "signature", "public_key", "algorithm"] {
                assert!(html.contains(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\">")), "{name}");
            }
            for name in [
                "allow_credential",
                "allow_client_data",
                "allow_authenticator_data",
                "allow_public_key",
                "allow_algorithm",
            ] {
                assert!(
                    html.contains(&format!("<input type=\"hidden\" name=\"{name}\" value=\"\" disabled>")),
                    "{name}"
                );
            }
            assert_eq!(html.matches("name=\"allow_").count(), 5, "{html}");
            for absent in ["name=\"new_", "data-add-challenge", "data-added", "type=\"checkbox\""] {
                assert!(!html.contains(absent), "{absent}: {html}");
            }
            // Its copy, and the status line's two messages of its own.
            assert!(html.contains(&format!("<p class=\"note\">{}</p>", escape(PASSKEY_ALLOW))), "{html}");
            assert!(html.contains(&format!("data-held=\"{}\"", escape(PASSKEY_ALLOW_HELD))), "{html}");
            assert!(html.contains(&format!("data-no-register=\"{}\"", escape(PASSKEY_ALLOW_NO_REGISTER))), "{html}");
            assert!(
                html.contains(&format!("<noscript><p class=\"lead\">{}</p></noscript>", escape(PASSKEY_NO_SCRIPT))),
                "{html}"
            );
            assert!(html.contains("role=\"status\" aria-live=\"polite\""), "{html}");
            // No handlers: attribute names only, as the copy in values says "on this device".
            for tag in tags(html) {
                let names = tag.split('"').step_by(2).collect::<Vec<_>>().join(" ");
                assert!(!names.split_whitespace().skip(1).any(|a| a.to_ascii_lowercase().starts_with("on")), "{tag}");
            }
        }

        // Every other page has nothing of it, and keeps APPROVE.
        let adding = PasskeyAdd { challenge: "YWRk".into(), user: "dXNlcg".into(), name: "github:octocat" };
        for page in [
            gate_asking(enroll()),
            gate_asking(assert_with(&credentials)),
            gate_asking(assert_adding(&credentials, adding.clone())),
            operation_asking(assert_adding(&credentials, adding)),
        ] {
            assert_eq!(script_of(&page), APPROVE);
            for absent in ["allow_", "data-allow-challenge", "data-held", "data-no-register", "data-passkey=\"allow\""]
            {
                assert!(!page.html.contains(absent), "{absent}: {}", page.html);
            }
            assert!(!page.html.contains(&escape(PASSKEY_ALLOW_EXISTING)), "{}", page.html);
        }
    }

    /// The part of `script` from `from` up to the `end` after it.
    fn between<'a>(script: &'a str, from: &str, end: &str) -> &'a str {
        let start = script.find(from).unwrap_or_else(|| panic!("{from} in {script}"));
        let rest = &script[start..];
        &rest[..rest.find(end).unwrap_or_else(|| panic!("{end} after {from} in {script}"))]
    }

    #[test]
    fn the_allowance_script_runs_what_it_may_and_nothing_else() {
        let script = APPROVE_ALLOWANCE;
        // As APPROVE's: messages as text, nothing it is given run, no handlers in the page.
        for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function(", "document.write"] {
            assert!(!script.contains(banned), "{banned}");
        }
        assert!(script.contains("status.textContent=t||''"));
        assert!(script.contains("alg:-7") && script.contains("alg:-257") && script.contains("timeout:300000"));
        assert!(script.contains("attestation:'none'") && script.contains("residentKey:'preferred'"));
        // One create(), one get(), each requiring user verification.
        assert_eq!(script.matches("navigator.credentials.create(").count(), 1);
        assert_eq!(script.matches("navigator.credentials.get(").count(), 1);
        assert_eq!(script.matches("userVerification:'required'").count(), 2);
        // The registration: the allowance's challenge alone, the account's passkeys excluded.
        let create = between(script, "navigator.credentials.create(", ".then(");
        assert!(create.contains("challenge:bytes(d.allowChallenge)") && create.contains("excludeCredentials:known()"));
        assert!(!create.contains("d.challenge") && !create.contains("allowCredentials"));
        assert!(script.contains("user:{id:bytes(d.user),name:d.name,displayName:d.name}"));
        // The assertion: the page's challenge alone, and it never touches the allowance's fields.
        let get = between(script, "function existing(){", "var registers=");
        assert!(get.contains("challenge:bytes(d.challenge)") && get.contains("allowCredentials:known()"));
        assert!(!get.contains("allowChallenge") && !get.contains("allows"), "{get}");
        // The allowance's fields are enabled in one place, right before they are posted, and disabled on any failure.
        assert_eq!(script.matches("f.disabled=false").count(), 1);
        let filled = between(script, "for(var i=0;i<allows.length;i++){var f=", "}).catch(");
        assert!(filled.contains("f.value=v[i];") && filled.contains("form.submit();"));
        assert!(
            script
                .contains("function quiet(){for(var i=0;i<allows.length;i++)form.elements[allows[i]].disabled=true;}")
        );
        // A device that holds a passkey is told so, and a new prompt takes its own click.
        let caught = between(script, ".catch(function(e){", "other.addEventListener");
        assert!(caught.contains("quiet();") && caught.contains("e.name==='InvalidStateError'?m.held:m.cancelled"));
        assert!(!caught.contains("existing("), "{caught}");
        // The focus rule on both buttons, and neither starts a ceremony while another runs.
        assert_eq!(script.matches("if(busy||!since||Date.now()-since<600)return;").count(), 2);
        let click = between(script, "other.addEventListener('click',", "})();");
        assert!(click.contains("if(busy||!since||Date.now()-since<600)return;") && click.contains("existing();"));
        assert!(!click.contains("navigator.credentials.create"), "{click}");
    }

    #[test]
    fn a_browser_that_cannot_register_is_told_so_and_can_still_assert() {
        let script = APPROVE_ALLOWANCE;
        assert!(script.contains(
            "var registers=window.AuthenticatorAttestationResponse&&\
typeof AuthenticatorAttestationResponse.prototype.getPublicKey==='function';"
        ));
        // No passkeys at all: the second button hidden, the unsupported message, Approve left disabled.
        let unusable = "if(!window.PublicKeyCredential||!navigator.credentials){other.hidden=true;say(m.unsupported);\
return;}";
        assert!(script.contains(unusable));
        assert!(script.find(unusable).unwrap() < script.find("var busy=false;button.disabled=false;").unwrap());
        // Passkeys but no registering: the second button hidden, the notice said, Approve running get() alone.
        assert!(script.contains("if(registers)other.disabled=false;else{other.hidden=true;say(m.noRegister);}"));
        let submit = between(script, "form.addEventListener('submit',", "navigator.credentials.create(");
        assert!(submit.contains("if(!registers){existing();return;}"), "{submit}");
        // Disabled only until the page's own failure gives both back, a hidden button staying out of it.
        assert!(script.contains("if(!other.hidden)other.disabled=false;"));
    }

    #[test]
    fn a_passkeys_copy_names_no_one() {
        const PRONOUNS: [&str; 10] = ["i", "me", "my", "we", "our", "us", "you", "your", "yours", "you're"];
        for copy in [
            PASSKEY_ENROLL,
            PASSKEY_ASSERT,
            PASSKEY_NO_SCRIPT,
            PASSKEY_UNSUPPORTED,
            PASSKEY_WAITING,
            PASSKEY_CANCELLED,
            PASSKEY_UNAVAILABLE_HOST,
            PASSKEY_UNAVAILABLE_HTTPS,
            PASSKEY_FAILED_GATE,
            PASSKEY_FAILED_OP,
            PASSKEY_ADD_OPTION,
            PASSKEY_ADD_NEXT,
            PASSKEY_ADD_BUTTON,
            PASSKEY_ALLOW,
            PASSKEY_ALLOW_EXISTING,
            PASSKEY_ALLOW_NO_REGISTER,
            PASSKEY_ALLOW_HELD,
            PASSKEY_ALLOW_ENDED,
            LINK_BOX,
            PASSKEY_LINK_FULL,
            PASSKEY_LINK_FIELD,
            PASSKEY_LINK_COPY,
            PASSKEY_LINK_COPIED,
            PASSKEY_LINK_SELECT,
            PASSKEY_LINK_TITLE,
            PASSKEY_LINK_LANDING,
            PASSKEY_LINK_CONTINUE,
            PASSKEY_LINK_ONWARD,
            PASSKEY_LINK_NO_SCRIPT,
            PASSKEY_LINK_UNUSABLE_TITLE,
            PASSKEY_LINK_UNUSABLE,
            PASSKEY_LINK_LIMIT_TITLE,
            PASSKEY_LINK_LIMIT,
            PASSKEY_LINK_FAILED_TITLE,
            PASSKEY_LINK_FAILED,
            PASSKEY_LINK_ADDED_TITLE,
            PASSKEY_LINK_ADDED,
            PASSKEY_LINK_ADD,
            PASSKEY_LINK_UNSUPPORTED,
            PASSKEY_LINK_CANCELLED,
            PASSKEY_LINK_HELD,
        ] {
            for word in copy.split(|c: char| !c.is_alphanumeric() && c != '\'').filter(|w| !w.is_empty()) {
                let word = word.to_lowercase().replace('\u{2019}', "'");
                assert!(!PRONOUNS.contains(&word.as_str()), "{word:?} in {copy:?}");
            }
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
            passkey: enroll(),
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
            passkey: enroll(),
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
        assert_eq!(script_of(&page), APPROVE);
        let approve = STANDARD.encode(Sha256::digest(APPROVE.as_bytes()));
        assert!(page.csp.contains(&format!("; script-src 'sha256-{approve}';")), "{}", page.csp);
        let form = "<form method=\"post\" action=\"https://bd.example.com/w/proj/gates/g&quot;&gt;&lt;x&gt;\" \
class=\"actions\" data-passkey=\"create\"";
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

    /// A link's address, as a page shows it.
    const LINK_ACTION: &str = "https://bd.example.com/oauth/passkey-link";

    /// A link as [`preview_pages`] and the tests show it.
    fn preview_link(approved: bool, full: bool) -> LinkShown<'static> {
        LinkShown {
            url: "https://bd.example.com/oauth/passkey-link#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            until: "2026-11-02 01:45",
            approved,
            full,
        }
    }

    /// A registration's ceremony, with the account's `credentials` excluded.
    fn link_ask(credentials: &[String]) -> LinkAsk<'_> {
        LinkAsk {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            user_handle: "dXNlcg".into(),
            user_name: "github:octocat",
            excluded: credentials,
        }
    }

    /// The registration page of a link, as a test shows it.
    fn register_page(credentials: &[String]) -> Page {
        register_link(
            "https://bd.example.com/oauth/passkey-link/register",
            "c0ffee",
            "github:octocat",
            &link_ask(credentials),
        )
    }

    #[test]
    fn the_link_box_is_offered_only_with_the_add_part_and_unticked() {
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string()];
        let adding = || PasskeyAdd { challenge: "YWRk".into(), user: "dXNlcg".into(), name: "github:octocat" };
        for page in [
            gate_asking(assert_linking(&credentials, adding())),
            operation_asking(assert_linking(&credentials, adding())),
        ] {
            assert_eq!(page.html.matches(LINK_BOX).count(), 1, "{}", page.html);
            let tag = tags(&page.html).into_iter().find(|t| t.contains("make_link")).unwrap();
            assert_eq!(tag, "input type=\"checkbox\" name=\"make_link\" value=\"1\"");
            // After the add box, which APPROVE takes as the first checkbox, and still inside the form.
            let html = &page.html;
            assert!(html.find("<input type=\"checkbox\">").unwrap() < html.find(LINK_BOX).unwrap(), "{html}");
            assert!(html.find(LINK_BOX).unwrap() < html.find("</form>").unwrap(), "{html}");
        }
        // Everywhere else, none: a first passkey, a full account, an allowance, no passkeys here at all.
        let unavailable = || PasskeyAsk::Unavailable { why: crate::webauthn::NoRp::IpLiteral };
        for page in [
            gate_asking(enroll()),
            operation_asking(enroll()),
            gate_asking(assert_with(&credentials)),
            operation_asking(assert_with(&credentials)),
            gate_asking(assert_adding(&credentials, adding())),
            operation_asking(assert_adding(&credentials, adding())),
            gate_asking(allow_with(&credentials, adding())),
            operation_asking(allow_with(&credentials, adding())),
            gate_asking(unavailable()),
            operation_asking(unavailable()),
        ] {
            assert!(!page.html.contains("make_link"), "{}", page.html);
        }
        // Without the add part it would pass for the add box in APPROVE, so `link` alone adds nothing.
        let alone = PasskeyAsk::Assert {
            challenge: "Y2hhbGxlbmdl".into(),
            rp_id: "bd.example.com",
            credentials: &credentials,
            add: None,
            link: true,
        };
        let page = gate_asking(alone);
        assert_eq!(page, gate_asking(assert_with(&credentials)));
    }

    #[test]
    fn the_link_box_is_the_only_difference_from_the_pinned_pages() {
        // The block below `the_pages_without_an_allowance_are_pinned` is never edited, so its values are repeated.
        const APPROVE_SCRIPT: &str = "FthMszPRPfefvNe8/2nrVx7xAc3V330zjaEmTszzZ1Q=";
        const GATE_ADD_HTML: &str = "JWYNr7VhF5OhfpDEx8EPrqSKP1oBuWF8OVPmjgamoYs=";
        const OPERATION_ADD_HTML: &str = "M5TKM+Jk/WRbNCrELKPcHbscJXkWSbGhy1SZiTh/YRk=";
        const ADD_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        // The pages production renders for 1 to 98 passkeys.
        const GATE_LINK_HTML: &str = "ILT3YwXuD8rSVPPGVFJBfgg34I5SvOaGHqFV4sGo/7A=";
        const OPERATION_LINK_HTML: &str = "rYyC6Ge33Q3UwiNtrVtdgepRlsDG3WRCMG+xKsJIsjM=";

        let hash = |text: &str| STANDARD.encode(Sha256::digest(text.as_bytes()));
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string(), "AAAAAAAAAAAAy2zQ".to_string()];
        let adding =
            || PasskeyAdd { challenge: "YWRkLWNoYWxsZW5nZQ".into(), user: "dXNlcg".into(), name: "github:octocat" };
        assert_eq!(hash(APPROVE), APPROVE_SCRIPT, "APPROVE");
        let box_line = format!("{LINK_BOX}\n");
        for (what, page, pinned, golden) in [
            ("gate", gate_asking(assert_linking(&credentials, adding())), GATE_ADD_HTML, GATE_LINK_HTML),
            (
                "operation",
                operation_asking(assert_linking(&credentials, adding())),
                OPERATION_ADD_HTML,
                OPERATION_LINK_HTML,
            ),
        ] {
            assert_eq!(page.status, 200, "{what}");
            assert_eq!(page.html.matches(LINK_BOX).count(), 1, "{what}: {}", page.html);
            assert_eq!(hash(&page.html.replacen(&box_line, "", 1)), pinned, "{what}: {}", page.html);
            assert_eq!(hash(&page.csp), ADD_CSP, "{what}: {}", page.csp);
            assert_eq!(script_of(&page), APPROVE, "{what}");
            assert_eq!(hash(&page.html), golden, "{what}: {}", page.html);
        }
    }

    /// `page` runs `script` alone, by its hash, and its forms post to
    /// `form_action` alone.
    fn runs_only(what: &str, page: &Page, script: &str, form_action: &str) {
        let hash = STANDARD.encode(Sha256::digest(script.as_bytes()));
        assert_eq!(page.html.matches("<script").count(), 1, "{what}: {}", page.html);
        assert_eq!(script_of(page), script, "{what}");
        assert_eq!(page.csp.matches("script-src").count(), 1, "{what}: {}", page.csp);
        assert_eq!(page.csp.matches("sha256-").count(), 2, "{what}, the style and the script: {}", page.csp);
        let allowed = format!("; script-src 'sha256-{hash}'; form-action {form_action}; frame-ancestors 'none';");
        assert!(page.csp.contains(&allowed), "{what}: {}", page.csp);
        assert!(page.csp.starts_with("default-src 'none'; style-src 'sha256-"), "{what}: {}", page.csp);
        assert!(!page.csp.contains("unsafe-"), "{what}: {}", page.csp);
        for tag in tags(&page.html) {
            let names = tag.split('"').step_by(2).collect::<Vec<_>>().join(" ");
            assert!(!names.split_whitespace().skip(1).any(|a| a.to_ascii_lowercase().starts_with("on")), "{tag}");
        }
    }

    #[test]
    fn the_link_pages_run_one_script_each_by_its_hash() {
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string()];
        let back = "https://app.example/cb";
        let answers = [
            ("a notice", notice(200, "Approved", "It went through."), 200),
            ("a refused notice", notice(409, "Not ready", "Not yet."), 409),
            ("a refusal", refusal(403, "Not approved", "No.", None), 403),
            ("a refusal with a way back", refusal(503, "Busy", "Later.", Some(back)), 503),
        ];
        runs_only("landing", &landing_link(LINK_ACTION), OPEN_LINK, "'self'");
        runs_only("registration", &register_page(&credentials), REGISTER_LINK, "'self'");
        for (what, answer, status) in answers {
            for (approved, full) in [(true, false), (false, false), (true, true), (false, true)] {
                let page = with_link(answer.clone(), &preview_link(approved, full));
                assert_eq!(page.status, status, "{what}");
                runs_only(what, &page, COPY_LINK, "'none'");
            }
        }
        // Nothing here but the policy's script moves: the rest of an answer's policy stays as it was.
        let answer = notice(200, "Approved", "It went through.");
        let hash = STANDARD.encode(Sha256::digest(COPY_LINK.as_bytes()));
        let linked = with_link(answer.clone(), &preview_link(true, false));
        assert_eq!(linked.csp.replacen(&format!("script-src 'sha256-{hash}'; "), "", 1), answer.csp);
        // Those three scripts keep off what no page may do.
        for script in [OPEN_LINK, REGISTER_LINK, COPY_LINK] {
            for banned in ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function(", "document.write"] {
                assert!(!script.contains(banned), "{banned}: {script}");
            }
        }
    }

    #[test]
    fn the_landing_page_is_the_same_for_every_link_and_holds_none() {
        let page = landing_link(LINK_ACTION);
        assert_eq!(page.status, 200);
        assert_eq!(page, landing_link(LINK_ACTION), "the same bytes every time");
        // The form posts to the address with no fragment: a redirect would keep one.
        // Its query keeps the answer's URL apart from the link's: only a fragment between two equal URLs loads nothing.
        let action = format!("action=\"{LINK_ACTION}?open\"");
        assert!(page.html.contains(&action), "{}", page.html);
        let form = tags(&page.html).into_iter().find(|t| t.starts_with("form ")).unwrap();
        assert!(!form.contains('#'), "{form}");
        assert!(page.html.contains("<input type=\"hidden\" name=\"link\" value=\"\">"), "{}", page.html);
        assert!(
            page.html.contains(&format!("<button type=\"submit\" class=\"primary\">{PASSKEY_LINK_CONTINUE}</button>"))
        );
        assert!(!page.html.contains(" disabled"), "a press of the button is what sends it: {}", page.html);
        assert!(
            page.html
                .contains(&format!("<noscript><p class=\"lead\">{}</p></noscript>", escape(PASSKEY_LINK_NO_SCRIPT)))
        );
        // The script moves the fragment and clears it, and leaves sending it to the person's press.
        assert!(OPEN_LINK.contains("form.elements.link.value=location.hash.slice(1);"));
        assert!(OPEN_LINK.contains("addEventListener('hashchange',take);"), "a second link: {OPEN_LINK}");
        assert!(OPEN_LINK.contains("history.replaceState(null,'',location.pathname);"));
        assert!(!OPEN_LINK.contains("submit") && !OPEN_LINK.contains("click"), "{OPEN_LINK}");
        for read in ["search", "href", "fetch", "XMLHttpRequest", "cookie", "Storage"] {
            assert!(!OPEN_LINK.contains(read), "{read}: {OPEN_LINK}");
        }
    }

    #[test]
    fn a_live_link_goes_on_to_sign_in_by_a_refresh_and_a_link() {
        let page = sign_in_onward("https://bd.example.com/oauth/choose?flow=a\"b&c=d");
        let url = "https://bd.example.com/oauth/choose?flow=a&quot;b&amp;c=d";
        assert_eq!(page.status, 200);
        let refresh = format!("<meta http-equiv=\"refresh\" content=\"0; url={url}\">");
        assert!(page.html.contains(&refresh), "{}", page.html);
        assert!(page.html.contains(&format!("<a href=\"{url}\">{PASSKEY_LINK_CONTINUE}</a>")), "{}", page.html);
        assert!(!page.html.contains("<form") && !page.html.contains("<script"), "{}", page.html);
        assert!(page.csp.contains("form-action 'none';") && !page.csp.contains("script-src"), "{}", page.csp);
    }

    #[test]
    fn the_notices_of_a_link_tell_nothing_of_why() {
        assert_eq!(link_unusable(), link_unusable());
        let page = link_unusable();
        assert_eq!(page.status, 404);
        assert_eq!(
            PASSKEY_LINK_UNUSABLE,
            "This link can't be used. Links work once, for a short time. Make a new one at an approval on a device \
that holds a passkey."
        );
        assert!(
            page.html.contains(&format!("<p class=\"lead\">{}</p>", escape(PASSKEY_LINK_UNUSABLE))),
            "{}",
            page.html
        );
        assert!(!page.html.contains("<form") && !page.html.contains("<a "), "{}", page.html);
        for reason in ["expired", "replaced", "cancelled", "unknown", "wrong", "account", "used up", "already"] {
            for copy in [PASSKEY_LINK_UNUSABLE_TITLE, PASSKEY_LINK_UNUSABLE] {
                assert!(!copy.to_lowercase().contains(reason), "{reason} in {copy}");
            }
        }
        for (page, status, copy) in [(link_limit(), 409, PASSKEY_LINK_LIMIT), (link_failed(), 403, PASSKEY_LINK_FAILED)]
        {
            assert_eq!(page.status, status);
            assert!(page.html.contains(&escape(copy)), "{}", page.html);
            assert!(!page.html.contains("<form") && !page.csp.contains("script-src"), "{}", page.html);
        }
    }

    #[test]
    fn a_links_page_registers_a_passkey_and_approves_nothing() {
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string(), "AAAAAAAAAAAAy2zQ".to_string()];
        let page = register_page(&credentials);
        let html = &page.html;
        assert_eq!(page.status, 200);
        // The names the approval pages' create() uses, and every passkey the account holds.
        let form = "<form method=\"post\" action=\"https://bd.example.com/oauth/passkey-link/register\" class=\"actions\" \
data-passkey=\"create\" data-challenge=\"Y2hhbGxlbmdl\" data-rp=\"bd.example.com\" data-user=\"dXNlcg\" \
data-name=\"github:octocat\" data-credentials=\"AAAAAAAAAAAAx1zQ AAAAAAAAAAAAy2zQ\">";
        assert!(html.contains(form), "{html}");
        // The page's id and a registration's five fields: none an approval's POST would take.
        let names: Vec<&str> =
            html.match_indices(" name=\"").map(|(at, _)| html[at + 7..].split('"').next().unwrap()).collect();
        assert_eq!(
            names,
            ["viewport", "robots", "id", "credential", "client_data", "authenticator_data", "public_key", "algorithm"]
        );
        assert!(html.contains("<input type=\"hidden\" name=\"id\" value=\"c0ffee\">"), "{html}");
        // Rendered disabled, as the script enables it only where a passkey can be registered.
        assert_eq!(html.matches("<button").count(), 1, "{html}");
        assert!(html.contains("<button type=\"submit\" class=\"primary\" disabled>Add the passkey</button>"), "{html}");
        assert!(
            html.contains(
                "<p class=\"lead\">Add a passkey on this device for github:octocat. This approves nothing.</p>"
            )
        );
        assert!(html.contains("role=\"status\" aria-live=\"polite\""), "{html}");
        for (attribute, copy) in [
            ("data-unsupported", PASSKEY_LINK_UNSUPPORTED),
            ("data-waiting", PASSKEY_WAITING),
            ("data-cancelled", PASSKEY_LINK_CANCELLED),
            ("data-held", PASSKEY_LINK_HELD),
        ] {
            assert!(html.contains(&format!("{attribute}=\"{}\"", escape(copy))), "{attribute}: {html}");
        }
        assert!(
            html.contains(&format!("<noscript><p class=\"lead\">{}</p></noscript>", escape(PASSKEY_LINK_NO_SCRIPT)))
        );
        // It speaks of an approval once, to say there is none.
        assert_eq!(html.to_lowercase().matches("approv").count(), 1, "{html}");
        assert!(html.contains("This approves nothing"), "{html}");

        // Every value escaped.
        let evil = "\"><script>alert(1)</script>\u{202E}";
        let shown = "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
        let excluded = [evil.to_string()];
        let hostile = LinkAsk {
            challenge: evil.into(),
            rp_id: evil,
            user_handle: evil.into(),
            user_name: evil,
            excluded: &excluded,
        };
        let page = register_link(evil, evil, evil, &hostile);
        assert!(!page.html.contains("<script>alert"), "{}", page.html);
        for attribute in ["action", "data-challenge", "data-rp", "data-user", "data-name", "data-credentials"] {
            assert!(page.html.contains(&format!("{attribute}=\"{shown}")), "{attribute}: {}", page.html);
        }
        assert!(page.html.contains(&format!("name=\"id\" value=\"{shown}")), "{}", page.html);
        assert!(page.html.contains(&format!("for {shown}\\u202e. This approves")), "{}", page.html);
    }

    #[test]
    fn a_links_script_runs_a_registration_and_nothing_else() {
        let script = REGISTER_LINK;
        assert_eq!(script.matches("navigator.credentials.create(").count(), 1);
        assert!(!script.contains("navigator.credentials.get("), "{script}");
        assert_eq!(script.matches("userVerification:'required'").count(), 1);
        assert_eq!(script.matches("attestation:'none'").count(), 1);
        assert!(script.contains("alg:-7}") && script.contains("alg:-257}") && script.contains("timeout:300000"));
        assert!(script.contains("excludeCredentials:known()") && script.contains("challenge:bytes(d.challenge)"));
        assert!(script.contains("user:{id:bytes(d.user),name:d.name,displayName:d.name}"));
        assert!(script.contains("status.textContent=t||''"));
        // Fills the five fields the server reads, and no field of an assertion.
        for name in ["credential", "client_data", "authenticator_data", "public_key", "algorithm"] {
            assert_eq!(script.matches(&format!("put('{name}',")).count(), 1, "{name}");
        }
        assert!(!script.contains("signature") && !script.to_lowercase().contains("approv"), "{script}");
        // ARMING's focus rule, and one ceremony at a time.
        assert!(script.contains("if(busy||!since||Date.now()-since<600)return;"));
        assert!(script.contains("addEventListener('blur',function(){since=0;});"));
        // Only a browser that can register enables the button.
        let able = between(script, "var able=", "button.disabled=false;");
        assert!(able.contains("typeof AuthenticatorAttestationResponse.prototype.getPublicKey==='function'"), "{able}");
        assert!(able.contains("if(!able){say(m.unsupported);return;}"), "{able}");
        // A cancelled or failed create() posts nothing and can be tried again; a device holding a passkey is told so.
        assert_eq!(script.matches("form.submit();").count(), 1);
        let caught = between(script, ".catch(function(e){", "});");
        assert!(caught.contains("busy=false;button.disabled=false;"), "{caught}");
        assert!(caught.contains("e.name==='InvalidStateError'?m.held:m.cancelled"), "{caught}");
        assert!(!caught.contains("form.submit"), "{caught}");
    }

    #[test]
    fn an_answer_shows_the_link_under_the_outcome() {
        let answer = notice(200, "Approved", "It went through.");
        let page = with_link(answer.clone(), &preview_link(true, false));
        let html = &page.html;
        let url = preview_link(true, false).url;
        assert_eq!(html.matches(url).count(), 1, "{html}");
        assert!(
            html.contains(&format!("readonly size=\"32\" aria-label=\"{PASSKEY_LINK_FIELD}\" value=\"{url}\">")),
            "{html}"
        );
        assert!(
            html.contains(&format!("<button type=\"button\" class=\"primary\">{PASSKEY_LINK_COPY}</button>")),
            "{html}"
        );
        assert!(html.contains("until 2026-11-02 01:45 UTC."), "{html}");
        // The outcome first, then the link, then the brand's row.
        let outcome = html.find("It went through.").unwrap();
        let shown = html.find(PASSKEY_LINK_SHOWN).unwrap();
        let bar = html.find("<div class=\"bar\">").unwrap();
        assert!(outcome < shown && shown < bar, "{html}");
        assert_eq!(html.matches("<div class=\"bar\">").count(), 1, "{html}");
        // No more than the block and its script over the page it was.
        let script = format!("<script>{COPY_LINK}</script>\n");
        let start = html.find("<p class=\"lead\">You also").unwrap();
        let without = format!("{}{}", &html[..start], &html[bar..]).replacen(&script, "", 1);
        assert_eq!(without, answer.html);
        assert!(html.find(&script).unwrap() < html.find("</body>").unwrap(), "{html}");

        // What is said changes with the outcome.
        let still = escape(PASSKEY_LINK_STILL_WORKS);
        let full = escape(PASSKEY_LINK_FULL);
        for (approved, room, says_still, says_full) in [
            (true, true, false, false),
            (false, true, true, false),
            (true, false, false, true),
            (false, false, true, true),
        ] {
            let html = with_link(answer.clone(), &preview_link(approved, !room)).html;
            assert_eq!(html.contains(&still), says_still, "{html}");
            assert_eq!(html.contains(&full), says_full, "{html}");
        }

        // The values go in escaped, and a page's own text never comes into it.
        let page = with_link(
            answer.clone(),
            &LinkShown { url: "https://x/\"><script>a</script>", until: "<b>", approved: true, full: false },
        );
        assert!(!page.html.contains("<script>a") && !page.html.contains("<b>"), "{}", page.html);
        assert!(page.html.contains("value=\"https://x/&quot;&gt;&lt;script&gt;a&lt;/script&gt;\""), "{}", page.html);

        // The script copies the field, or selects it where the browser will not, and says so as text.
        assert!(COPY_LINK.contains("navigator.clipboard.writeText(field.value)"));
        assert!(COPY_LINK.contains("field.select();") && COPY_LINK.contains(",pick);"));
        assert!(COPY_LINK.contains("status.textContent=status.dataset.copied;"));
        assert!(COPY_LINK.contains("status.textContent=status.dataset.select;"));
        for (attribute, copy) in [("data-copied", PASSKEY_LINK_COPIED), ("data-select", PASSKEY_LINK_SELECT)] {
            assert!(html.contains(&format!("{attribute}=\"{}\"", escape(copy))), "{attribute}: {html}");
        }
    }

    #[test]
    fn the_links_warning_is_the_agreed_text_and_is_filled_with_no_name() {
        assert_eq!(PASSKEY_LINK_SHOWN, "You also have a link for another device:");
        assert_eq!(
            PASSKEY_LINK_WARNING,
            "Open this on your own new device. Don't send it to anyone else, whoever asks: anyone with this link and \
your sign-in can add a passkey to your account."
        );
        assert_eq!(PASSKEY_LINK_STILL_WORKS, "The link still works. You can try the approval again.");
        assert_eq!(
            PASSKEY_LINK_FULL,
            "This account now holds the most passkeys it can, so this link can't add another until one is removed."
        );

        // Whatever the answer names, the link's block names no one: it takes the link and its end, no more.
        let answer = notice(200, "Approved", "Gate g in proj is recorded as approved by github:octocat.");
        let html = with_link(answer, &preview_link(false, true)).html;
        let warning =
            format!("<span>{} It works once, until 2026-11-02 01:45 UTC.</span>", escape(PASSKEY_LINK_WARNING));
        assert!(html.contains(&warning), "{html}");
        let block = between(&html, PASSKEY_LINK_SHOWN, "<div class=\"bar\">");
        assert!(block.contains(&warning) && !block.contains("octocat") && !block.contains("proj"), "{block}");
    }

    #[test]
    fn the_link_pages_are_pinned() {
        const OPEN_LINK_SCRIPT: &str = "C2RUVNYngwNjr60N8ek+YGAj3QnkqKWeBSP5km839Yk=";
        const REGISTER_LINK_SCRIPT: &str = "qiWLnlXtnw/o/4NyeH5DKn+wFHTOLrxEoo52vovFQ9g=";
        const COPY_LINK_SCRIPT: &str = "ilTopjb6cxwOIxr7CZ6XhvBHZ0XWP2jLQRhGQDqvfCg=";
        const LANDING_HTML: &str = "BKFgoGuo16Om/Sm+SrXxDdmN+clGY1MPKyc7wAX1wis=";
        const LANDING_CSP: &str = "zqHfpP1cslkEGi8FSWuDU0xq/0MLE9GB8t+DytERosc=";
        const REGISTER_HTML: &str = "Ajs+v+0qj+MT71iieUj5ccKBPFFgUr4iwtu7mqO497g=";
        const REGISTER_CSP: &str = "0Ujx/gDRHROs6bhXb+18bcG711K285XFxbhyzU7Qixo=";
        const SHOWN_HTML: &str = "CX77W5EhTTeZuZAM2t9D7c1SE6kNn/VDBpGo7Cv4Wi8=";
        const SHOWN_CSP: &str = "I9bSIleKkqHo1w9QdmWHEMvsHE/3O5N226Sg9Q66w3w=";

        let hash = |text: &str| STANDARD.encode(Sha256::digest(text.as_bytes()));
        assert_eq!(hash(OPEN_LINK), OPEN_LINK_SCRIPT, "OPEN_LINK");
        assert_eq!(hash(REGISTER_LINK), REGISTER_LINK_SCRIPT, "REGISTER_LINK");
        assert_eq!(hash(COPY_LINK), COPY_LINK_SCRIPT, "COPY_LINK");
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string(), "AAAAAAAAAAAAy2zQ".to_string()];
        let answer = notice(409, "Not ready", "This gate isn't ready to approve yet.");
        for (what, page, html, csp) in [
            ("landing", landing_link(LINK_ACTION), LANDING_HTML, LANDING_CSP),
            ("registration", register_page(&credentials), REGISTER_HTML, REGISTER_CSP),
            ("shown", with_link(answer, &preview_link(false, true)), SHOWN_HTML, SHOWN_CSP),
        ] {
            assert_eq!(hash(&page.html), html, "{what}: html: {}", page.html);
            assert_eq!(hash(&page.csp), csp, "{what}: csp: {}", page.csp);
        }
    }

    // pinned-goldens:begin bd-h6q45.1 S1: never edit; a failure here means production output changed
    /// An operation approval page with fixed values, asking for `passkey`.
    fn operation_asking(passkey: PasskeyAsk<'_>) -> Page {
        approve_operation(&ApproveOperation {
            workspace: "proj",
            op_label: "close",
            issue: "t-1",
            title: "Ship it",
            status: "open",
            part_of: None,
            reason: Some("Blocked past its gate, on purpose"),
            requester: "github:hubot",
            at: 0,
            failed: false,
            force: true,
            gates: &[],
            deletes: None,
            provider: "GitHub",
            actor: "github:octocat",
            id: "c0ffee",
            action: "https://bd.example.com/w/proj/close/t-1",
            passkey,
        })
    }

    #[test]
    fn the_pages_without_an_allowance_are_pinned() {
        const APPROVE_SCRIPT: &str = "FthMszPRPfefvNe8/2nrVx7xAc3V330zjaEmTszzZ1Q=";
        const GATE_ENROLL_HTML: &str = "Wd7s2mCcgrdvdn6iURTGseXRa55XLX3a6VurQzAuDBM=";
        const GATE_ENROLL_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        const GATE_ASSERT_HTML: &str = "gtYqKkkBPz2XC3VKttZxXAjNsA2rc/HpQQkCLBlR94o=";
        const GATE_ASSERT_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        const GATE_ADD_HTML: &str = "JWYNr7VhF5OhfpDEx8EPrqSKP1oBuWF8OVPmjgamoYs=";
        const GATE_ADD_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        const OPERATION_ENROLL_HTML: &str = "1LNZYrIY9DK9jXoG0siwX/RhR7L2UeHdCqOtuHjnnbY=";
        const OPERATION_ENROLL_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        const OPERATION_ASSERT_HTML: &str = "BLmrOa+t25+lpzoOjbEdIhxdM7zY1Bj9L4RRYkC/bns=";
        const OPERATION_ASSERT_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";
        const OPERATION_ADD_HTML: &str = "M5TKM+Jk/WRbNCrELKPcHbscJXkWSbGhy1SZiTh/YRk=";
        const OPERATION_ADD_CSP: &str = "k2Xtfe+SqoPZy7TXCh+6nOascBm01lrJndgtfTYfIfc=";

        let hash = |text: &str| STANDARD.encode(Sha256::digest(text.as_bytes()));
        let credentials = ["AAAAAAAAAAAAx1zQ".to_string(), "AAAAAAAAAAAAy2zQ".to_string()];
        let adding =
            || PasskeyAdd { challenge: "YWRkLWNoYWxsZW5nZQ".into(), user: "dXNlcg".into(), name: "github:octocat" };
        assert_eq!(hash(APPROVE), APPROVE_SCRIPT, "APPROVE");
        let pages = [
            ("gate enroll", gate_asking(enroll()), GATE_ENROLL_HTML, GATE_ENROLL_CSP),
            ("gate assert", gate_asking(assert_with(&credentials)), GATE_ASSERT_HTML, GATE_ASSERT_CSP),
            ("gate add", gate_asking(assert_adding(&credentials, adding())), GATE_ADD_HTML, GATE_ADD_CSP),
            ("operation enroll", operation_asking(enroll()), OPERATION_ENROLL_HTML, OPERATION_ENROLL_CSP),
            (
                "operation assert",
                operation_asking(assert_with(&credentials)),
                OPERATION_ASSERT_HTML,
                OPERATION_ASSERT_CSP,
            ),
            (
                "operation add",
                operation_asking(assert_adding(&credentials, adding())),
                OPERATION_ADD_HTML,
                OPERATION_ADD_CSP,
            ),
        ];
        for (what, page, html, csp) in &pages {
            assert_eq!(page.status, 200, "{what}");
            assert_eq!(hash(&page.html), *html, "{what}: html: {}", page.html);
            assert_eq!(hash(&page.csp), *csp, "{what}: csp: {}", page.csp);
        }
    }
    // pinned-goldens:end

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
            passkey: enroll(),
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
        assert_eq!(script_of(&page), APPROVE);
        let hidden: Vec<String> =
            ["credential", "client_data", "authenticator_data", "signature", "public_key", "algorithm"]
                .iter()
                .map(|name| format!("input type=\"hidden\" name=\"{name}\" value=\"\""))
                .collect();
        for tag in tags(html) {
            if tag.starts_with("input") {
                assert!(
                    tag == "input type=\"hidden\" name=\"approval\" value=\"c0ffee\""
                        || hidden.iter().any(|h| h == tag)
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
