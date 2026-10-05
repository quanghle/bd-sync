//! `POST <issuer>/oauth/consent`: back to the client with a code, or `access_denied`.

use super::super::form;
use super::super::pages::{self};
use crate::auth;
use crate::oauth::{self};

use super::*;

/// `POST <issuer>/oauth/consent` with `consent=<id>&decision=approve|deny`:
/// send the browser back to the client with a code, or `access_denied`.
pub fn decide(cx: &Ctx<'_>, body: &str, cookies: &str) -> Answer {
    let pairs = form::decode(body).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    // Taken only by the browser it is bound to: another one that learned its id must not end it.
    let key = get("consent").map(auth::hash);
    let consent = {
        let mut flows = lock(cx.flows);
        let bound = |c: &Consent| {
            consent_cookie(cx.issuer, cookies, &c.cookie).map(auth::hash).as_deref() == Some(c.browser.as_str())
        };
        match key.as_ref().and_then(|k| flows.consents.get_mut(k).map(|c| bound(c))) {
            None => None,
            Some(false) => {
                return refused(400, "This request started in a different browser. Start again from the application.");
            }
            Some(true) => key.as_ref().and_then(|k| flows.consents.take(k)),
        }
    };
    let Some(Consent { request, admitted, actor, .. }) = consent else {
        return refused(400, "This request has expired. Start again from the application.");
    };
    // `[oauth]` may have changed since the request was checked: the browser
    // goes back only where it allows now (RFC 9700 section 4.11).
    match oauth::load(cx.root) {
        Ok(Some(g)) => match g.oauth {
            Some(o) if o.allows_redirect(&request.redirect_uri) => {}
            Some(_) => {
                tracing::info!(target: "bd::serve", redirect_uri = %request.redirect_uri, "OAuth redirect no longer allowed");
                let why = "The application asked to send you somewhere this server no longer allows.";
                return refused(400, why);
            }
            None => return refused(404, NO_APPS),
        },
        Ok(None) => return refused(404, NO_APPS),
        Err(e) => return internal(&e, "reading auth.toml for a consent"),
    }
    let log = |decision: &str| {
        tracing::info!(
            target: "bd::serve",
            client = %request.client.id,
            login = %admitted.user.login,
            subject = %admitted.user.subject,
            %actor,
            workspace = %request.workspace,
            "OAuth authorization {decision}"
        );
    };
    match get("decision") {
        Some("approve") => {}
        Some("deny") => {
            log("denied");
            return back_to(request.error_url(cx.issuer, "access_denied", "the authorization was denied"));
        }
        _ => return refused(400, "The form arrived incomplete. Start again from the application."),
    }
    let code = match auth::random_hex(32) {
        Ok(c) => c,
        Err(e) => return internal(&e, "issuing an authorization code"),
    };
    log("approved");
    if request.client.document {
        cx.documents.keep(&request.client);
    }
    let url = answer_url(&request.redirect_uri, request.state.as_deref(), cx.issuer, &[("code", &code)]);
    let issued = Code {
        client_id: request.client.id,
        redirect_uri: request.redirect_uri,
        challenge: request.challenge,
        resource: request.resource,
        admitted,
        actor,
    };
    lock(cx.flows).codes.put(auth::hash(&code), issued);
    back_to(url)
}

/// Whether `url`'s host is an IPv6 address (`http://[::1]:8080/cb`).
fn ipv6_host(url: &str) -> bool {
    host_of(url).starts_with('[')
}

/// Where the consent form may post, and be redirected after: the page's
/// own origin (`'self'`, which unlike a source naming it matches an IPv6
/// host), and the client's redirect URI, which a policy can name unless its
/// host is an IPv6 address ([`back_to`]).
pub(super) fn form_origins(redirect_uri: &str) -> Vec<&str> {
    let mut origins = vec!["'self'"];
    if !ipv6_host(redirect_uri) {
        origins.push(origin(redirect_uri));
    }
    origins
}

/// Send the browser back to the client after the consent form, at `url`:
/// redirected, or by a page where the form's policy cannot allow it.
pub(super) fn back_to(url: String) -> Answer {
    if ipv6_host(&url) { Answer::Page(pages::onward(&url)) } else { Answer::Redirect(url) }
}
