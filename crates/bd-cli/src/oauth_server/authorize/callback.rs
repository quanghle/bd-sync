//! Back from the provider: `/oauth/<provider>/callback` (relayed first when posted), then the consent page.

use std::time::Duration;

use bd_core::Error;

use super::super::clients::{self};
use super::super::pages::{self};
use super::super::{CONSENT, form};
use crate::auth;
use crate::oauth::{self};

use super::*;

/// `POST <issuer>/oauth/<provider>/callback`: the provider's answer as a
/// form the browser posted (`response_mode=form_post`). Another site's POST
/// carries no `SameSite=Lax` cookie, so the step cannot tell the browser
/// here: the answer goes on to [`callback`] as the GET it would otherwise
/// have been, a top-level navigation the cookie goes with. Only what the
/// callback reads goes on (not an ID token or the user's name). Only a
/// provider configured to post its answers is relayed.
pub fn relay(cx: &Ctx<'_>, provider: &str, body: &str) -> Answer {
    let posts = match oauth::load(cx.root) {
        Ok(Some(s)) => s.oauth.is_some() && s.oidc(provider).is_some_and(|o| o.form_post),
        Ok(None) => false,
        Err(e) => return internal(&e, "reading auth.toml for a posted sign-in answer"),
    };
    if !posts {
        return refused(400, "This sign-in came back in a way it shouldn't. Start again from the application.");
    }
    let Some(pairs) = form::decode(body) else {
        return refused(400, "The sign-in came back unreadable. Start again from the application.");
    };
    let kept: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(k, _)| matches!(k.as_str(), "state" | "code" | "error" | "iss"))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if !kept.iter().any(|(k, _)| *k == "state") {
        return refused(400, "This sign-in has expired. Start again from the application.");
    }
    Answer::Redirect(format!("{}{}?{}", cx.issuer, super::super::callback(provider), form::encode(&kept)))
}

/// `GET <issuer>/oauth/<provider>/callback?<query>`: the provider sent the
/// browser back. Find out who signed in and what the rules or the
/// authorizer let the account do in the workspace, and ask whether the
/// client may.
pub fn callback(
    cx: &Ctx<'_>,
    provider: &str,
    query: &str,
    browser: Option<&str>,
    cookies: &str,
) -> (Answer, Vec<String>) {
    let mut fresh = None;
    let answer = signed_in(cx, provider, query, browser, cookies, &mut fresh);
    // The flow's cookie has served: gone, whatever came of it.
    let state = form::decode(query).unwrap_or_default().into_iter().find(|(k, _)| k == "state").map(|(_, v)| v);
    let gone = state.map(|state| set_flow_cookie(cx.issuer, &state, "", Duration::ZERO));
    (answer, fresh.into_iter().chain(gone).collect())
}

/// [`callback`]'s answer. Once the person signed in, the browser gets a
/// cookie of the consent's own (`fresh`, its `Set-Cookie`), which the
/// consent is bound to: a cookie known or planted before the sign-in is good
/// for nothing after it, and other sign-ins under way in the same browser
/// keep theirs.
fn signed_in(
    cx: &Ctx<'_>,
    provider: &str,
    query: &str,
    browser: Option<&str>,
    cookies: &str,
    fresh: &mut Option<String>,
) -> Answer {
    let pairs = form::decode(query).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    // The flow the browser carries for the state the provider sent back; a provider's code is used once, so a
    // flow brought back twice gets no second account.
    let state = get("state").unwrap_or_default();
    let pending =
        flow_cookie(cx.issuer, cookies, state).and_then(|sealed| lock(cx.flows).sealer.open(AT_PROVIDER, sealed));
    let pending = pending.filter(|p| p.until > now_millis() && p.at.as_ref().is_some_and(|at| at.state == state));
    let Some(Pending { query: requested, browser: started_in, at: Some(at), .. }) = pending else {
        return refused(400, "This sign-in has expired. Start again from the application.");
    };
    let AtProvider { provider: started_with, verifier, nonce, .. } = at;
    if browser.map(auth::hash).as_deref() != Some(started_in.as_str()) {
        return refused(400, "This sign-in started in a different browser. Start again from the application.");
    }
    if started_with != provider {
        return refused(400, "This sign-in came back from another provider. Start again from the application.");
    }
    let (sign_in, oauth_config) = match oauth_settings(cx) {
        Ok(s) => s,
        Err(answer) => return answer,
    };
    let request = match request_of(cx, &oauth_config, &requested) {
        Ok(r) => r,
        Err(answer) => return answer,
    };
    let label = match (provider, sign_in.oidc(provider)) {
        ("github", _) => "GitHub".to_string(),
        (_, Some(oidc)) => oidc.label.clone(),
        _ => return refused(404, NO_APPS),
    };
    // Mix-up: an OIDC provider's answer names it (RFC 9207), where it says it does, and never another one.
    if let Some(oidc) = sign_in.oidc(provider) {
        let required = oidc.metadata().is_ok_and(|md| md.iss_parameter);
        let ok = match get("iss") {
            Some(iss) => iss == oidc.issuer,
            None => !required,
        };
        if !ok {
            tracing::warn!(target: "bd::serve", %provider, iss = ?get("iss"), "a sign-in came back naming another issuer");
            return refused(400, "This sign-in came back from another provider. Start again from the application.");
        }
    }
    let back = |error: &str, description: &str| request.error_url(cx.issuer, error, description);
    if let Some(error) = get("error") {
        let (error, description) = match error {
            // Apple says `user_cancelled_authorize`.
            "access_denied" | "user_cancelled_authorize" => {
                ("access_denied", "the sign-in was cancelled at the provider")
            }
            _ => ("server_error", "the provider did not complete the sign-in"),
        };
        return Answer::Redirect(back(error, description));
    }
    let Some(code) = get("code").filter(|c| !c.is_empty()) else {
        let why = format!("{label} didn't return a sign-in code. Start again from the application.");
        return refused(400, &why);
    };
    let callback_url = format!("{}{}", cx.issuer, super::super::callback(provider));
    let workspace = &request.workspace;
    let client = &request.client.id;
    // Who signed in, once the provider said: named on the page if the account is refused.
    let mut signed_in_as = None;
    let admitted = match sign_in.oidc(provider) {
        None => {
            let as_who = &mut signed_in_as;
            oauth::web_sign_in(cx.root, &sign_in, code, &callback_url, &verifier, workspace, client, as_who)
        }
        Some(oidc) => oidc
            .metadata()
            .and_then(|md| oidc.sign_in(&md, code, &callback_url, &verifier, &nonce))
            .and_then(|claims| {
                signed_in_as = Some(claims.login.clone());
                oauth::admit_oidc(cx.root, &sign_in, oidc, &claims, workspace, Some(client))
            }),
    };
    let found = admitted.and_then(|a| Ok((auth::preview_actor(cx.root, &a.user, a.by_login)?, a)));
    let (actor, admitted) = match found {
        Ok(found) => found,
        Err(Error::Unauthorized(why)) => {
            tracing::info!(target: "bd::serve", %provider, %workspace, error = %why, "web sign-in refused");
            let link = back("access_denied", "the account may not use this workspace");
            let account = signed_in_as.map_or(String::new(), |login| format!(" ({login})"));
            let why = format!(
                "Your {label} account{account} doesn't have access to this workspace. Ask the server's admin for \
                 access, or sign in with another account."
            );
            return Answer::Page(pages::refusal(403, "Access denied", &why, Some(&link)));
        }
        Err(Error::Invalid(why)) => {
            tracing::info!(target: "bd::serve", %provider, error = %why, "web sign-in did not complete");
            let link = back("access_denied", "the sign-in did not complete");
            let why = format!("{label} didn't finish signing you in. Start again from the application.");
            return Answer::Page(pages::refusal(400, "Sign-in didn't finish", &why, Some(&link)));
        }
        Err(Error::Remote(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "web sign-in failed");
            let link = back("temporarily_unavailable", "the provider could not be reached");
            let why = format!("{label} didn't respond as expected. Try again in a moment.");
            return Answer::Page(pages::refusal(502, &format!("Couldn't reach {label}"), &why, Some(&link)));
        }
        Err(Error::Busy(why) | Error::Locked(why)) => {
            tracing::warn!(target: "bd::serve", %provider, error = %why, "web sign-in could not be decided");
            let link = back("temporarily_unavailable", "the server could not check access");
            let why = "The server couldn't check your access just now. Try again in a moment.";
            return Answer::Page(pages::refusal(503, "Couldn't check your access", why, Some(&link)));
        }
        Err(e) => return internal(&e, "finishing a web sign-in"),
    };
    if !(cx.workspace_exists)(&request.workspace) {
        return Answer::Redirect(back("invalid_target", "resource is not an MCP endpoint of this bd server"));
    }
    let id = match auth::random_hex(32) {
        Ok(id) => id,
        Err(e) => return internal(&e, "asking for consent"),
    };
    let client = &request.client;
    let name = client_name(client);
    let identity = if client.document {
        pages::Identity::Document { url: &client.id, host: host_of(&client.id) }
    } else {
        pages::Identity::Registered { client_id: &client.id }
    };
    let loopback = clients::is_loopback(&request.redirect_uri);
    let returns_to = host_of(&request.redirect_uri);
    let elsewhere = (client.document && !loopback && returns_to != host_of(&client.id)).then_some(returns_to);
    let lasts = match sign_in.refreshes(&admitted.user.provider) {
        true => format!(
            "at most {}, and ends after {} unused or when revoked",
            in_words(sign_in.refresh_limit),
            in_words(sign_in.refresh_idle)
        ),
        false => format!("{}, or until revoked", in_words(sign_in.token_ttl)),
    };
    let action = format!("{}{CONSENT}", cx.issuer);
    let page = pages::consent(&pages::Consent {
        client: &name,
        identity,
        logo: client.logo.as_deref().filter(|_| client.document),
        redirect_uri: &request.redirect_uri,
        loopback,
        elsewhere,
        lasts: &lasts,
        workspace: &request.workspace,
        provider: &label,
        // The email the person knows the account by, where the provider gave one: on this page only.
        login: admitted.email.as_deref().unwrap_or(&admitted.user.login),
        actor: &actor,
        access: match admitted.grant.role {
            auth::Role::Read => "Read only",
            auth::Role::Write => "Read and write",
            auth::Role::Admin => "Full, including administration",
        },
        via: &admitted.via,
        id: &id,
        action: &action,
        form_origins: &form_origins(&request.redirect_uri),
    });
    let (value, suffix) = match (auth::random_hex(32), auth::random_hex(4)) {
        (Ok(v), Ok(s)) => (v, s),
        (Err(e), _) | (_, Err(e)) => return internal(&e, "asking for consent"),
    };
    *fresh = Some(set_consent_cookie(cx.issuer, &suffix, &value));
    let consent = Consent { request, admitted, actor, browser: auth::hash(&value), cookie: suffix };
    lock(cx.flows).consents.put(auth::hash(&id), consent);
    Answer::Page(page)
}
