//! `GET <issuer>/oauth/authorize` and `/oauth/choose`: on to a provider to sign in.

use bd_core::Error;

use super::super::pages::{self};
use super::super::{CHOOSE, form};
use crate::auth;
use crate::oauth::{self};

use super::*;

/// `GET <issuer>/oauth/authorize?<query>`: check the request, and send the
/// browser to the provider to sign in, or to a page choosing one. `browser`
/// is its cookie, if it has one; the `Set-Cookie` values to answer with
/// come back with the answer.
pub fn begin(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> (Answer, Vec<String>) {
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let request = match request_of(cx, &oauth_config, query) {
        Ok(r) => r,
        Err(answer) => return (answer, Vec::new()),
    };
    let browser = match browser {
        Some(b) => b.to_string(),
        None => match auth::random_hex(32) {
            Ok(b) => b,
            Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
        },
    };
    let providers = sign_in.browser_providers();
    match providers.as_slice() {
        [] => (refused(404, NO_APPS), Vec::new()),
        [(provider, _)] => start(cx, &sign_in, authorize(query), provider, &browser, Some(&request)),
        several => {
            let pending = Pending { then: authorize(query), browser: auth::hash(&browser), until: until(), at: None };
            let flow = match lock(cx.flows).sealer.seal(CHOOSING, &pending) {
                Ok(f) => f,
                Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
            };
            let client = client_name(&request.client);
            let options: Vec<(String, String)> = several
                .iter()
                .map(|(name, label)| {
                    let query = form::encode(&[("flow", flow.as_str()), ("provider", name)]);
                    (label.to_string(), format!("{}{CHOOSE}?{query}", cx.issuer))
                })
                .collect();
            (
                Answer::Page(pages::choose(&format!("Sign in to connect {client}"), &options)),
                vec![set_cookie(cx.issuer, &browser)],
            )
        }
    }
}

/// `GET <issuer>/oauth/choose?flow=<sealed>&provider=<name>`: the person
/// chose a provider on the page [`begin`] (or a gate's flow) showed; on to
/// it. A flow from a gate's page comes here first, without a provider
/// ([`super::gate::begun`]).
pub fn choose(cx: &Ctx<'_>, query: &str, browser: Option<&str>) -> (Answer, Vec<String>) {
    let pairs = form::decode(query).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let pending = get("flow").and_then(|flow| lock(cx.flows).sealer.open(CHOOSING, flow));
    // From a gate's page: not bound to a browser yet, which happens here, where its cookie is seen.
    if pending.is_none()
        && let Some(begun) = get("flow").and_then(|flow| lock(cx.flows).sealer.open(GATE_BEGIN, flow))
    {
        return super::gate::begun(cx, begun, get("provider"), browser);
    }
    let Some(pending) = pending.filter(|p| p.until > now_millis()) else {
        return (refused(400, "This sign-in has expired. Start again from the application."), Vec::new());
    };
    let Some(browser) = browser.filter(|b| auth::hash(b) == pending.browser) else {
        return (
            refused(400, "This sign-in started in a different browser. Start again from the application."),
            Vec::new(),
        );
    };
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return (answer, Vec::new()),
    };
    let offered = sign_in.browser_providers();
    let Some((provider, _)) = offered.iter().find(|(name, _)| Some(*name) == get("provider")) else {
        return (refused(400, MALFORMED), Vec::new());
    };
    match pending.then {
        Then::Authorize { query } => {
            let request = match request_of(cx, &oauth_config, &query) {
                Ok(r) => r,
                Err(answer) => return (answer, Vec::new()),
            };
            start(cx, &sign_in, Then::Authorize { query }, provider, browser, Some(&request))
        }
        then @ Then::Gate { .. } => start(cx, &sign_in, then, provider, browser, None),
    }
}

fn authorize(query: &str) -> Then {
    Then::Authorize { query: query.to_string() }
}

/// Send the browser to `provider` to sign in for what comes `then`, binding
/// the sign-in to `browser` (the cookie's value): what it comes back for is
/// sealed into a cookie of the flow's own. `back` is the authorization
/// request whose client the pages link back to with an error, if there is one.
pub(super) fn start(
    cx: &Ctx<'_>,
    sign_in: &oauth::SignIn,
    then: Then,
    provider: &str,
    browser: &str,
    back: Option<&Authorization>,
) -> (Answer, Vec<String>) {
    let link = |description: &str| back.map(|r| r.error_url(cx.issuer, "temporarily_unavailable", description));
    // Before the browser goes to the provider: a secret the sign-in will need and does not have now.
    if sign_in.ready_for(provider, true).is_err() {
        let link = link("sign-in is unavailable just now");
        let why = "Signing in isn't available just now. Try again in a moment.";
        return (Answer::Page(pages::refusal(503, "Try again in a moment", why, link.as_deref())), Vec::new());
    }
    let secrets = (|| Ok::<_, Error>((auth::random_hex(16)?, auth::random_hex(32)?, auth::random_hex(16)?)))();
    let (state, verifier, nonce) = match secrets {
        Ok(s) => s,
        Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
    };
    let callback = format!("{}{}", cx.issuer, super::super::callback(provider));
    let url = match (provider, &sign_in.github, sign_in.oidc(provider)) {
        ("github", Some(github), _) => oauth::web_sign_in_url(github, &callback, &state, &s256(&verifier)),
        (_, _, Some(oidc)) => match oidc.metadata() {
            Ok(md) => oidc.authorization_url(&md, &callback, &state, &nonce, &s256(&verifier)),
            Err(e) => {
                tracing::warn!(target: "bd::serve", %provider, error = %e, "OAuth sign-in could not start");
                let link = link("the provider could not be reached");
                let why = "It didn't respond as expected. Try again in a moment.";
                let title = format!("Couldn't reach {}", oidc.label);
                return (Answer::Page(pages::refusal(502, &title, why, link.as_deref())), Vec::new());
            }
        },
        _ => return (refused(404, NO_APPS), Vec::new()),
    };
    let at = AtProvider { provider: provider.to_string(), state: state.clone(), verifier, nonce };
    let pending = Pending { then, browser: auth::hash(browser), until: until(), at: Some(at) };
    let sealed = match lock(cx.flows).sealer.seal(AT_PROVIDER, &pending) {
        Ok(s) => s,
        Err(e) => return (internal(&e, "starting an authorization"), Vec::new()),
    };
    if sealed.len() > MAX_SEALED {
        match &pending.then {
            Then::Authorize { .. } => {
                let client = back.map_or("", |r| r.client.id.as_str());
                tracing::info!(target: "bd::serve", %client, "OAuth sign-in refused: its request is too long to carry");
            }
            Then::Gate { .. } => {
                tracing::info!(target: "bd::serve", "gate sign-in refused: its flow is too long to carry")
            }
        }
        return (refused(400, MALFORMED), Vec::new());
    }
    let cookies = vec![set_cookie(cx.issuer, browser), set_flow_cookie(cx.issuer, &state, &sealed, STEP_TTL)];
    (Answer::Redirect(url), cookies)
}
