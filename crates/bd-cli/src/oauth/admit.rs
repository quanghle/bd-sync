//! Sign-in at the server: the device flow (`bd remote login --provider`),
//! admitting an account by the rules or the authorizer, and providers'
//! account notifications.

use super::*;

/// Start a sign-in: the one-time code the provider gives for it.
pub fn start(root: &Path, provider: &str) -> Result<SignInCode> {
    let sign_in = enabled(root)?;
    if provider != "github" {
        return start_oidc(&sign_in, provider);
    }
    let github = github_of(&sign_in)?;
    let api = Api::new(github);
    let mut form = vec![("client_id", github.client_id.as_str())];
    if github.reads_orgs() {
        form.push(("scope", "read:org"));
    }
    let (status, body) = api.form("/login/device/code", &form)?;
    let text = |k: &str| body[k].as_str().map(str::to_string);
    match (status, text("device_code"), text("user_code"), text("verification_uri")) {
        (200, Some(device_code), Some(user_code), Some(verification_uri)) if body.get("error").is_none() => {
            Ok(SignInCode {
                device_code,
                user_code,
                verification_uri,
                expires_in: body["expires_in"].as_u64().unwrap_or(900),
                interval: body["interval"].as_u64().unwrap_or(5),
                provider: "GitHub".into(),
            })
        }
        _ => Err(refused(github, "start a sign-in", status, &body)),
    }
}

/// [`start`] with an OIDC provider's device flow.
fn start_oidc(sign_in: &SignIn, provider: &str) -> Result<SignInCode> {
    let oidc = oidc_of(sign_in, provider)?;
    let md = oidc.metadata()?;
    let body = oidc.device(&md)?;
    let text = |k: &str| body[k].as_str().map(str::to_string);
    // Google names it verification_url.
    let uri = text("verification_uri").or_else(|| text("verification_url"));
    match (text("device_code"), text("user_code"), uri) {
        (Some(device_code), Some(user_code), Some(verification_uri)) => Ok(SignInCode {
            device_code,
            user_code,
            verification_uri,
            expires_in: body["expires_in"].as_u64().unwrap_or(600),
            interval: body["interval"].as_u64().unwrap_or(5),
            provider: oidc.label.clone(),
        }),
        _ => Err(Error::Remote(format!("{} did not start a sign-in as expected; try again later", oidc.label))),
    }
}

/// [`poll`] with an OIDC provider's device flow.
fn poll_oidc(root: &Path, sign_in: &SignIn, provider: &str, poll: &SignInPoll) -> Result<SignInAnswer> {
    let oidc = oidc_of(sign_in, provider)?;
    let md = oidc.metadata()?;
    let form = [("grant_type", DEVICE_GRANT), ("device_code", poll.device_code.as_str())];
    let body = oidc.token(&md, &form)?;
    match body["error"].as_str() {
        Some("authorization_pending") => return Ok(SignInAnswer::Pending),
        Some("slow_down") => return Ok(SignInAnswer::SlowDown { interval: 0 }),
        Some("expired_token") => {
            return Err(Error::Unauthorized(format!(
                "the one-time code expired before it was entered at {}: sign in again",
                oidc.label
            )));
        }
        Some("access_denied") => {
            return Err(Error::Unauthorized(format!("the sign-in was cancelled at {}", oidc.label)));
        }
        Some(error) => {
            let error = crate::oidc::error_code(error);
            return Err(Error::invalid(format!("{} ended the sign-in ({error}): sign in again", oidc.label)));
        }
        None => {}
    }
    let Some(id_token) = body["id_token"].as_str() else {
        return Err(Error::Remote(format!("{} gave no ID token; the server's admin finds why in its log", oidc.label)));
    };
    // The device flow sends no nonce: the token comes straight from the provider, to this server.
    let claims = oidc.verify(&md, id_token, None)?;
    // The provider gives a code's token once, so a poll sent again would find it gone: not busy, ended.
    let admitted = admit_oidc(root, sign_in, oidc, &claims, &poll.workspace, None).map_err(|e| match e {
        Error::Busy(why) | Error::Locked(why) => Error::Remote(why),
        e => e,
    })?;
    let Admitted { user, grant, via, by_login, rule, .. } = admitted;
    let life = auth::Lifetime { rule, ..sign_in.lifetime(Timestamp::now(), &user.provider) };
    let issued = auth::issue_sign_in_token(root, &user, grant, life, &poll.workspace, by_login)?;
    tracing::info!(
        target: "bd::serve",
        %provider,
        login = %user.login,
        subject = %user.subject,
        actor = %issued.token.actor,
        token = %issued.token.name,
        %via,
        "sign-in issued an access token"
    );
    Ok(SignInAnswer::Issued(Box::new(answer_of(issued, user.login, via))))
}

/// Whether `code` may be a provider's device code (some are long, JWT-like):
/// checked before anything is spent on it.
pub fn device_code_ok(code: &str) -> bool {
    !code.is_empty() && code.len() <= 2048 && code.bytes().all(|b| b.is_ascii_graphic())
}

/// What became of a sign-in: still waiting for its code, or the access
/// token issued to the account that signed in.
pub fn poll(root: &Path, provider: &str, poll: &SignInPoll) -> Result<SignInAnswer> {
    let code = poll.device_code.as_str();
    if !device_code_ok(code) {
        return Err(Error::invalid("not a sign-in's device code"));
    }
    if !crate::protocol::valid_workspace_name(&poll.workspace) {
        return Err(Error::invalid(format!("invalid workspace name {:?}", poll.workspace)));
    }
    let sign_in = enabled(root)?;
    if provider != "github" {
        return poll_oidc(root, &sign_in, provider, poll);
    }
    let github = github_of(&sign_in)?;
    let api = Api::new(github);
    let form = [("client_id", github.client_id.as_str()), ("device_code", code), ("grant_type", DEVICE_GRANT)];
    let (status, body) = api.form("/login/oauth/access_token", &form)?;
    match body["error"].as_str() {
        Some("authorization_pending") => return Ok(SignInAnswer::Pending),
        Some("slow_down") => return Ok(SignInAnswer::SlowDown { interval: body["interval"].as_u64().unwrap_or(0) }),
        Some("expired_token" | "token_expired") => {
            return Err(Error::Unauthorized(
                "the one-time code expired before it was entered at GitHub: sign in again".into(),
            ));
        }
        Some("access_denied") => return Err(Error::Unauthorized("the sign-in was cancelled at GitHub".into())),
        Some("incorrect_device_code") => {
            return Err(Error::invalid(
                "GitHub does not know this sign-in (it ended, or never started): sign in again",
            ));
        }
        Some(_) => return Err(refused(github, "finish a sign-in", status, &body)),
        None => {}
    }
    let Some(access) = body["access_token"].as_str().filter(|t| !t.is_empty()) else {
        return Err(refused(github, "finish a sign-in", status, &body));
    };
    // GitHub gave the code's token once, so a poll sent again would find the sign-in gone: not busy, ended.
    let admitted = admit(root, &sign_in, &api, access, &poll.workspace, None, &mut None).map_err(|e| match e {
        Error::Busy(why) | Error::Locked(why) => Error::Remote(why),
        e => e,
    });
    let Admitted { user, grant, via, by_login, unknown, rule, .. } = admitted?;
    let life = auth::Lifetime { rule, ..sign_in.lifetime(Timestamp::now(), &user.provider) };
    let issued = auth::issue_sign_in_token(root, &user, grant, life, &poll.workspace, by_login)?;
    let token = &issued.token;
    tracing::info!(
        target: "bd::serve",
        login = %user.login,
        subject = %user.subject,
        actor = %token.actor,
        token = %token.name,
        role = token.role.as_str(),
        kind = token.kind.as_str(),
        refreshed = token.refresh.is_some(),
        %via,
        ?unknown,
        "GitHub sign-in issued an access token"
    );
    Ok(SignInAnswer::Issued(Box::new(answer_of(issued, user.login, via))))
}

/// An account notification `provider` posted (`body`, at
/// `<issuer>/oauth/<provider>/events`): an account that revoked its consent
/// has its sign-ins from before ended, and a deleted one is forgotten. A
/// provider without `account_events` takes none (`NotFound`).
pub fn account_event(root: &Path, provider: &str, body: &[u8]) -> Result<()> {
    let sign_in = load(root)?;
    let oidc = sign_in.as_ref().and_then(|s| s.oidc(provider)).filter(|o| !o.account_events.is_empty());
    let Some(oidc) = oidc else { return Err(Error::not_found("provider taking account notifications", provider)) };
    let md = oidc.metadata()?;
    let event = oidc.account_event(&md, body)?;
    let subject = event.subject.as_str();
    match &event.kind {
        crate::oidc::AccountChange::ConsentRevoked => {
            let revoked = auth::end_sign_ins_before(root, &oidc.issuer, subject, event.at)?;
            tracing::info!(target: "bd::serve", %provider, %subject, revoked = revoked.len(), "an account revoked its consent: its sign-ins ended");
        }
        crate::oidc::AccountChange::Deleted => {
            let known = auth::forget_account(root, &oidc.issuer, subject)?;
            tracing::info!(target: "bd::serve", %provider, %subject, known, "an account was deleted at its provider: forgotten");
        }
        crate::oidc::AccountChange::Other(kind) => {
            tracing::debug!(target: "bd::serve", %provider, %subject, %kind, "an account notification needs nothing done");
        }
    }
    Ok(())
}

/// What the rules, or the authorizer, let the account whose GitHub token
/// `access` is do in `workspace` (for OAuth `client`, if any), asking GitHub
/// with that token ([`judge`]). `signed_in_as` gets the account's login
/// once GitHub named it.
pub(super) fn admit(
    root: &Path,
    sign_in: &SignIn,
    api: &Api,
    access: &str,
    workspace: &str,
    client: Option<&str>,
    signed_in_as: &mut Option<String>,
) -> Result<Admitted> {
    let (user, created) = account(api, access)?;
    *signed_in_as = Some(user.login.clone());
    let asked = Asked { api, token: access, login: &user.login, seen: HashMap::new() };
    let mut facts = GithubFacts { user: &user, created, asked };
    judge(root, sign_in, &mut facts, created, None, workspace, client)
}

/// What the account `facts` tell of may do in `workspace` (for OAuth
/// `client`, if any), for any provider: never if its provider's `deny`
/// names it; else as the authorizer decides, or the provider's rules.
/// `Error::Unauthorized` (said to the person signing in) if they do not let
/// it in, `Error::Busy` if the authorizer could not say, `Error::Remote` if
/// the provider would not tell what a rule needs.
pub(super) fn judge(
    root: &Path,
    sign_in: &SignIn,
    facts: &mut dyn Facts,
    created: Option<Timestamp>,
    claims: Option<&crate::oidc::Claims>,
    workspace: &str,
    client: Option<&str>,
) -> Result<Admitted> {
    let user = facts.identity().clone();
    let email = facts.email().map(str::to_string);
    let (provider, login, subject) = (&user.provider, &user.login, &user.subject);
    if sign_in.denies(&user) {
        tracing::info!(target: "bd::serve", %provider, %login, %subject, "sign-in refused: the account is denied");
        return Err(Error::Unauthorized(format!("{} may not sign in to this bd server", user.who())));
    }
    if let Some(authorizer) = &sign_in.authorizer {
        let request = crate::authorizer::request("sign_in", workspace, &user, created, client, None, claims);
        let (grant, via) = ask(root, authorizer, &request)?;
        // The authorizer may match logins, so the login is held to its own account as a rule's would be.
        return Ok(Admitted { user, grant, via, by_login: true, unknown: Vec::new(), email, rule: None });
    }
    let Decided { decision, rule, unknown } = decide(sign_in.allow(provider), facts, None, workspace)?;
    let who = user.who();
    match decision {
        Decision::In { grant, via, by_login } => Ok(Admitted { user, grant, via, by_login, unknown, email, rule }),
        Decision::TooNew(min) => {
            tracing::info!(target: "bd::serve", %provider, %login, %subject, %workspace, "sign-in refused: the account is too new");
            Err(Error::Unauthorized(format!(
                "{who} may not sign in to this bd server yet: the account must be at least {} old",
                bd_core::time::format_duration_ms(i64::try_from(min.as_millis()).unwrap_or(i64::MAX))
            )))
        }
        Decision::Elsewhere(workspaces) => {
            tracing::info!(target: "bd::serve", %provider, %login, %subject, %workspace, ?unknown, "sign-in refused: workspace not allowed");
            Err(Error::Unauthorized(format!(
                "{who} may sign in to this bd server, but not use workspace {workspace} (only {})",
                workspaces.join(", ")
            )))
        }
        Decision::Unknown => {
            tracing::warn!(target: "bd::serve", %provider, %login, %subject, %workspace, ?unknown, "sign-in not decided: memberships unknown");
            Err(Error::Remote(format!(
                "{} would not tell this bd server whether {who} may use workspace {workspace}; try again later, or \
                 ask the server's admin",
                sign_in.label(provider)
            )))
        }
        Decision::Out => {
            tracing::info!(target: "bd::serve", %provider, %login, %subject, ?unknown, "sign-in refused: no rule lets the account in");
            Err(Error::Unauthorized(format!(
                "{who} may not sign in to this bd server: no rule of its auth.toml lets the account in"
            )))
        }
    }
}

/// What `authorizer` grants the account `request` is about, or why not:
/// `Unauthorized` (for the person) when it refuses, `Busy` when it cannot
/// say. Its reasons go to the log only.
pub(super) fn ask(
    root: &Path,
    authorizer: &crate::authorizer::Authorizer,
    request: &crate::authorizer::Request<'_>,
) -> Result<(Grant, String)> {
    let (provider, login, subject, workspace) = (request.provider, request.login, &request.subject, request.workspace);
    match authorizer.ask(root, request) {
        // The authorizer may match logins, so the login is held to its own account as a rule's would be (by_login).
        crate::authorizer::Outcome::Allow { grant, via } => Ok((grant, via)),
        crate::authorizer::Outcome::Deny { reason } => {
            tracing::info!(target: "bd::serve", %provider, %login, %subject, %workspace, %reason, "sign-in refused by the authorizer");
            Err(crate::authorizer::refused(&auth::who(provider, login), workspace))
        }
        crate::authorizer::Outcome::Unavailable { why } => {
            tracing::warn!(target: "bd::serve", %provider, %login, %subject, %workspace, %why, "sign-in failed: the authorizer did not decide");
            Err(crate::authorizer::unavailable())
        }
    }
}

/// What the rules, or the authorizer, let the account an OIDC provider
/// vouched for (`claims`, verified) do in `workspace`, for OAuth `client`
/// if any ([`judge`]).
pub fn admit_oidc(
    root: &Path,
    sign_in: &SignIn,
    oidc: &crate::oidc::Oidc,
    claims: &crate::oidc::Claims,
    workspace: &str,
    client: Option<&str>,
) -> Result<Admitted> {
    let user = oidc.identity(claims);
    let mut facts = oidc.facts(&user, claims);
    judge(root, sign_in, &mut facts, None, Some(claims), workspace, client)
}

/// What the client gets of a token issued or refreshed.
pub(super) fn answer_of(issued: auth::Issued, login: String, via: String) -> Issued {
    let t = issued.token;
    let expires_in = t.expires_at.map_or(0, |at| u64::try_from(at.since(Timestamp::now()) / 1000).unwrap_or(0));
    Issued {
        token: issued.secret,
        refresh_token: issued.refresh_secret,
        name: t.name,
        actor: t.actor,
        role: t.role.as_str().to_string(),
        kind: t.kind.as_str().to_string(),
        workspaces: t.workspaces,
        max_claims: t.max_claims,
        expires_at: t.expires_at.map(|at| at.to_rfc3339()).unwrap_or_default(),
        expires_in,
        refreshable_until: t.refresh.map(|r| r.until.to_rfc3339()),
        login,
        via,
    }
}
