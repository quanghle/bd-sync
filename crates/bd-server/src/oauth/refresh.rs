//! Refreshing sign-ins (`/v2/auth/refresh`, and the OAuth token
//! endpoint's refresh grant): deciding again, then rotating the secrets.

use super::*;

/// Refresh the sign-in whose refresh secret this is (`POST
/// /v2/auth/refresh`, request `request_id`): new secrets, with what the
/// rules or the authorizer grant its account now (GitHub asked as the App). The secret
/// spent by the latest refresh, sent again with its request id (a client
/// whose answer was lost), refreshes again. A refusal is
/// `Error::Unauthorized`, and revokes the sign-in when the rules no longer
/// let the account in, or the secret was spent already; GitHub's failures,
/// and memberships it would not tell, are `Error::Remote`, and change nothing.
/// `client` is the OAuth client refreshing at the authorization server's
/// token endpoint (`oauth_server/token.rs`), which only refreshes the
/// tokens issued to it, as `/v2/auth/refresh` only refreshes those issued
/// to no client.
pub fn refresh(root: &Path, secret: &str, request_id: &str, client: Option<&str>) -> Result<Issued> {
    refresh_found(root, auth::find_refresh(root, secret)?, secret, request_id, client)
}

/// [`refresh`] of the sign-in `found` (`auth::find_refresh` of `secret`)
/// by a caller that looked it up already.
pub fn refresh_found(
    root: &Path,
    found: Option<(auth::Token, bool)>,
    secret: &str,
    request_id: &str,
    client: Option<&str>,
) -> Result<Issued> {
    let refused =
        |why: String| Error::Unauthorized(format!("{why}; sign in again: `bd remote login --provider <name>`"));
    let sign_in = enabled(root)?;
    let Some((token, current)) = found else {
        return Err(refused("this bd server does not know the sign-in (it was revoked, or has ended)".into()));
    };
    let (Some(user), Some(state)) = (token.identity.clone(), token.refresh.clone()) else {
        return Err(refused("not a sign-in's refresh token".into()));
    };
    // Its provider known, the way back is exact.
    let provider = user.provider.clone();
    let refused = move |why: String| {
        Error::Unauthorized(format!("{why}; sign in again: `bd remote login --provider {provider}`"))
    };
    if token.client.as_deref() != client {
        return Err(refused(match &token.client {
            Some(_) if client.is_none() => {
                "this refresh token is an OAuth client's, refreshed at its token endpoint".into()
            }
            _ => "this refresh token was issued to another client".into(),
        }));
    }
    let revoke = |why: &str| -> Result<()> {
        auth::revoke_by_id(root, &token.id, why)?;
        tracing::warn!(target: "bd::serve", provider = %user.provider, login = %user.login, subject = %user.subject, token = %token.name, "sign-in revoked at refresh: {why}");
        Ok(())
    };
    if !current && !state.retries_last(secret, request_id) {
        revoke("its refresh token was used twice")?;
        return Err(refused(
            "this refresh token was used already, so the sign-in was revoked: someone else may hold a copy of it"
                .into(),
        ));
    }
    if !sign_in.provides(&user) {
        tracing::warn!(target: "bd::serve", provider = %user.provider, issuer = %user.issuer, login = %user.login, "sign-in not refreshed: its provider is no longer configured");
        return Err(refused(format!("this bd server no longer signs people in with {}", user.provider)));
    }
    if !sign_in.refreshes(&user.provider) {
        return Err(refused("this bd server no longer refreshes these sign-ins".into()));
    }
    let now = Timestamp::now();
    let signed_in = Timestamp::parse_rfc3339(&token.created_at)?;
    let limit = signed_in.plus(sign_in.refresh_limit);
    if now >= limit.min(state.refreshed_at.plus(sign_in.refresh_idle)) {
        let why = match now >= limit {
            true => format!("the sign-in of {signed_in} is older than the server lets it be refreshed"),
            false => format!("the sign-in was last refreshed at {}, too long ago", state.refreshed_at),
        };
        return Err(refused(why));
    }
    if sign_in.denies(&user) {
        revoke("the account is denied")?;
        return Err(refused(format!("{} may not use this bd server", user.who())));
    }
    // A provider that can be asked again (GitHub, through its App) proves the account afresh: as it is named now,
    // and with the memberships rules ask. Otherwise the sign-in is decided on what bd kept of it.
    let github = match user.provider.as_str() {
        "github" => github_of(&sign_in).ok().and_then(|g| g.app.as_ref().map(|key| (g, key))),
        _ => None,
    };
    // All of a refresh's calls to GitHub end within one budget, as it holds a refresh slot meanwhile and its client
    // waits: one that gives up and sends its refresh token again would find it spent.
    let api = github.map(|(g, _)| Api::within(g, REFRESH_BUDGET));
    let app = github.zip(api.as_ref()).map(|((github, key), api)| AppApi { api, github, key });
    let (mut now_user, mut created, mut fresh) = (user.clone(), None, false);
    if let Some(app) = &app {
        let Some(id) = github_id(&user) else {
            return Err(refused("not a GitHub sign-in".into()));
        };
        let Some((named, made)) = app.user(id)? else {
            revoke("the GitHub account no longer exists")?;
            return Err(refused(format!("GitHub has no account {} any more", user.login)));
        };
        // Its issuer is the GitHub the App asks, the one the sign-in was at: `provides` refused any other above.
        (now_user, created, fresh) = (named, made, true);
    }
    let mut unknown = Vec::new();
    let mut rule = None;
    let (grant, via, by_login, decided) = match &sign_in.authorizer {
        Some(authorizer) => {
            let current = crate::authorizer::Current {
                role: token.role,
                kind: token.kind,
                max_claims: token.max_claims,
                signed_in_at: signed_in.to_string(),
            };
            let request = crate::authorizer::request(
                "refresh",
                &state.workspace,
                &now_user,
                created,
                token.client.as_deref(),
                Some(current),
                None,
            );
            match authorizer.ask(root, &request) {
                crate::authorizer::Outcome::Allow { grant, via } => (grant, via, true, true),
                crate::authorizer::Outcome::Deny { reason } => {
                    revoke(&format!("the authorizer refused it: {reason}"))?;
                    return Err(refused(format!(
                        "{} may no longer use workspace {} on this bd server",
                        now_user.who(),
                        state.workspace
                    )));
                }
                // The sign-in stays: within the grace, this refresh keeps its access; past it, only this refresh fails.
                crate::authorizer::Outcome::Unavailable { why } => {
                    // Since the last decision, not the last refresh: refreshes kept meanwhile do not extend it.
                    let within = authorizer.refresh_grace.is_some_and(|grace| now < state.decided_at.plus(grace));
                    if !within {
                        tracing::warn!(target: "bd::serve", login = %now_user.login, %why, "sign-in not refreshed: the authorizer did not decide");
                        return Err(Error::Remote(
                            "this bd server could not check the account's access just now; try again later".into(),
                        ));
                    }
                    tracing::warn!(target: "bd::serve", login = %now_user.login, %why, "sign-in refreshed with its last access: the authorizer did not decide");
                    (authorizer.kept(&token), "the server's last decision".to_string(), true, false)
                }
            }
        }
        // The provider's rules: on facts asked afresh, or else as the rule that let the sign-in in (`state.rule`).
        None => {
            let (rules, kept, workspace) = (sign_in.allow(&user.provider), state.rule.as_deref(), &state.workspace);
            let d = match &app {
                Some(app) => {
                    let asked = Installed { app, login: &now_user.login, seen: HashMap::new() };
                    decide(rules, &mut GithubFacts { user: &now_user, created, asked }, kept, workspace)?
                }
                None => decide(rules, &mut Listed::kept(&now_user), kept, workspace)?,
            };
            unknown = d.unknown;
            match d.decision {
                Decision::In { mut grant, via, by_login } => {
                    rule = d.rule;
                    // Without fresh facts, rules before the kept one that need them were not applied: one may have
                    // narrowed the sign-in to its workspace. So a refresh keeps the workspaces it had, at most.
                    if app.is_none() {
                        grant.workspaces = within(&grant.workspaces, &token.workspaces);
                    }
                    (grant, via, by_login, true)
                }
                out => {
                    // Memberships the provider would not tell may come back: the sign-in stays, and only this
                    // refresh fails.
                    if matches!(out, Decision::Unknown) || !unknown.is_empty() {
                        tracing::warn!(target: "bd::serve", provider = %now_user.provider, login = %now_user.login, ?unknown, "sign-in not refreshed: memberships unknown");
                        return Err(Error::Remote(format!(
                            "{} would not tell this bd server the memberships of {} ({}); try again later",
                            sign_in.label(&now_user.provider),
                            now_user.who(),
                            unknown.join("; ")
                        )));
                    }
                    let why = match out {
                        Decision::TooNew(_) => "the account is too new for the rules".to_string(),
                        Decision::Elsewhere(_) => format!("the rules no longer let it into workspace {workspace}"),
                        _ => "no rule of the server's auth.toml lets the account in any more".to_string(),
                    };
                    revoke(&why)?;
                    return Err(refused(format!("{}: {why}", now_user.who())));
                }
            }
        }
    };
    let until = limit.min(now.plus(sign_in.refresh_idle));
    let expires_at = now.plus(sign_in.token_ttl);
    let last = auth::LastRefresh { spent: auth::hash(secret), request: auth::hash(request_id) };
    let rotation = auth::Rotation { last, user: &now_user, fresh, grant, by_login, decided, rule, expires_at, until };
    let rotated = auth::rotate(root, &token.id, &state.sha256, rotation)?;
    let Some(issued) = rotated else {
        revoke("its refresh token was used twice")?;
        return Err(refused(
            "this refresh token was used already, so the sign-in was revoked: someone else may hold a copy of it"
                .into(),
        ));
    };
    tracing::info!(
        target: "bd::serve",
        login = %now_user.login,
        subject = %now_user.subject,
        actor = %issued.token.actor,
        token = %issued.token.name,
        role = issued.token.role.as_str(),
        kind = issued.token.kind.as_str(),
        provider = %now_user.provider,
        %via,
        ?unknown,
        "sign-in refreshed"
    );
    Ok(answer_of(issued, now_user.login, via))
}

/// The workspaces of `granted` that `had` covers too (`*`: every one).
fn within(granted: &[String], had: &[String]) -> Vec<String> {
    let all = |w: &[String]| w.iter().any(|w| w == "*");
    match (all(granted), all(had)) {
        (_, true) => granted.to_vec(),
        (true, false) => had.to_vec(),
        (false, false) => granted.iter().filter(|w| had.contains(w)).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACME: &str =
        "[oidc.acme]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\nclient_secret_file = \"secret\"\n";

    /// Write `auth.toml` with `rules`, as a change the next load sees.
    fn configure(root: &Path, rules: &str) {
        let file = root.join(FILE);
        let stamp = std::fs::metadata(&file).ok().and_then(|m| m.modified().ok());
        std::fs::write(&file, format!("{ACME}{rules}")).unwrap();
        if let Some(before) = stamp {
            let f = std::fs::OpenOptions::new().write(true).open(&file).unwrap();
            f.set_modified(before + Duration::from_secs(1)).unwrap();
        }
    }

    fn root(rules: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret"), "s3cret").unwrap();
        configure(dir.path(), rules);
        dir
    }

    /// Sign `subject` in to `workspace` as poll_oidc does; the refresh secret.
    fn sign_in(root: &Path, subject: &str, workspace: &str) -> Result<String> {
        sign_in_with(root, subject, workspace, serde_json::json!({}))
    }

    /// [`sign_in`] with these ID token claims.
    fn sign_in_with(root: &Path, subject: &str, workspace: &str, all: Value) -> Result<String> {
        let s = load(root)?.unwrap();
        let oidc = s.oidc("acme").unwrap();
        let claims =
            crate::oidc::Claims { subject: subject.into(), login: format!("user-{subject}"), email: None, all };
        let Admitted { user, grant, by_login, rule, .. } = admit_oidc(root, &s, oidc, &claims, workspace, None)?;
        let life = auth::Lifetime { rule, ..s.lifetime(Timestamp::now(), &user.provider) };
        let issued = auth::issue_sign_in_token(root, &user, grant, life, workspace, by_login)?;
        Ok(issued.refresh_secret.unwrap())
    }

    fn live(root: &Path) -> usize {
        let conn = crate::server_db::open(root).unwrap();
        let sql = "SELECT count(*) FROM tokens WHERE json_extract(data, '$.revoked_at') IS NULL";
        conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap() as usize
    }

    #[test]
    fn rules_admit_by_subject_and_workspace() {
        let dir = root("[[oidc.acme.allow]]\nsubjects = [\"s-1\"]\nworkspaces = [\"proj\"]\n");
        assert!(sign_in(dir.path(), "s-1", "proj").is_ok());
        for (subject, workspace) in [("s-1", "ops"), ("s-2", "proj")] {
            let e = sign_in(dir.path(), subject, workspace).unwrap_err();
            assert!(matches!(e, Error::Unauthorized(_)), "{subject} {workspace}: {e}");
            let says = match subject {
                "s-1" => format!("but not use workspace {workspace} (only proj)"),
                _ => "no rule of its auth.toml lets the account in".into(),
            };
            assert!(e.to_string().contains(&says), "{e}");
        }
    }

    #[test]
    fn denied_subjects_never_sign_in_and_their_sign_ins_end_at_refresh() {
        let dir = root("[[oidc.acme.allow]]\nanyone = true\n");
        let secret = sign_in(dir.path(), "s-1", "proj").unwrap();
        configure(dir.path(), "deny = [\"s-1\"]\n[[oidc.acme.allow]]\nanyone = true\n");
        let e = sign_in(dir.path(), "s-1", "proj").unwrap_err();
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("may not sign in"), "{e}");
        assert!(sign_in(dir.path(), "s-2", "proj").is_ok(), "others still do");
        let e = refresh(dir.path(), &secret, "r-1", None).unwrap_err();
        assert!(e.to_string().contains("may not use this bd server"), "{e}");
        assert_eq!(live(dir.path()), 1, "s-1's sign-in was revoked");
    }

    #[test]
    fn a_refresh_never_widens_a_sign_in_an_earlier_rule_narrowed() {
        // Contractors read `secret`; everyone in acme writes everywhere else. Carol is both: her sign-in for proj is
        // narrowed to proj, never write in secret. A refresh cannot apply the contractors rule (no claims) and must
        // not lose that.
        let dir = root(
            "[[oidc.acme.allow]]\ngroups = [\"contractors\"]\nrole = \"read\"\nworkspaces = [\"secret\"]\n\
             [[oidc.acme.allow]]\ngroups = [\"acme\"]\n",
        );
        let carol = sign_in_with(dir.path(), "s-1", "proj", serde_json::json!({ "groups": ["contractors", "acme"] }));
        let refreshed = refresh(dir.path(), &carol.unwrap(), "r-1", None).unwrap();
        assert_eq!(refreshed.workspaces, ["proj"], "still narrowed");
        // Bob, in acme only, keeps every workspace.
        let bob = sign_in_with(dir.path(), "s-2", "proj", serde_json::json!({ "groups": ["acme"] })).unwrap();
        assert_eq!(refresh(dir.path(), &bob, "r-2", None).unwrap().workspaces, ["*"]);
        assert_eq!(within(&["*".into()], &["proj".into()]), ["proj"]);
        assert_eq!(within(&["a".into(), "b".into()], &["b".into(), "c".into()]), ["b"]);
    }

    #[test]
    fn a_refresh_that_loses_a_race_revokes_the_sign_in() {
        // Two refreshes with one secret: the second found it current, but another rotated it meanwhile.
        let dir = root("[[oidc.acme.allow]]\nsubjects = [\"s-1\"]\n");
        let secret = sign_in(dir.path(), "s-1", "proj").unwrap();
        let found = auth::find_refresh(dir.path(), &secret).unwrap();
        assert!(found.as_ref().is_some_and(|(_, current)| *current));
        refresh(dir.path(), &secret, "r-1", None).unwrap();
        let e = refresh_found(dir.path(), found, &secret, "r-2", None).unwrap_err();
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("used already"), "{e}");
        assert_eq!(live(dir.path()), 0);
    }

    #[test]
    fn refreshes_rotate_once_and_a_spent_secret_revokes_the_sign_in() {
        let dir = root("[[oidc.acme.allow]]\nsubjects = [\"s-1\"]\n");
        let first = sign_in(dir.path(), "s-1", "proj").unwrap();
        let second = refresh(dir.path(), &first, "r-1", None).unwrap();
        // The answer was lost: the same secret and request again refreshes again.
        let again = refresh(dir.path(), &first, "r-1", None).unwrap();
        assert_ne!(second.refresh_token, again.refresh_token);
        // Under another request it is a copy's: the sign-in ends.
        let e = refresh(dir.path(), &first, "r-2", None).unwrap_err();
        assert!(e.to_string().contains("used already") && e.to_string().contains("--provider acme"), "{e}");
        assert_eq!(live(dir.path()), 0);
        assert!(refresh(dir.path(), again.refresh_token.as_deref().unwrap(), "r-3", None).is_err(), "revoked");
    }

    #[test]
    fn refreshes_are_refused_to_other_clients_and_after_the_rules_change() {
        let dir = root("[[oidc.acme.allow]]\nsubjects = [\"s-1\"]\n");
        let secret = sign_in(dir.path(), "s-1", "proj").unwrap();
        let e = refresh(dir.path(), &secret, "r-1", Some("https://client.example")).unwrap_err();
        assert!(e.to_string().contains("issued to another client"), "{e}");
        assert_eq!(live(dir.path()), 1, "a client's mistake ends nothing");
        let unknown = refresh(dir.path(), "bdr_x", "r-1", None).unwrap_err();
        assert!(unknown.to_string().contains("--provider <name>"), "{unknown}");
        // The rule that let it in is gone: refused, and revoked.
        configure(dir.path(), "[[oidc.acme.allow]]\nsubjects = [\"s-2\"]\n");
        let e = refresh(dir.path(), &secret, "r-1", None).unwrap_err();
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("lets the account in any more"), "{e}");
        assert_eq!(live(dir.path()), 0);
    }

    #[test]
    fn sign_ins_unused_too_long_or_too_old_are_not_refreshed() {
        let dir = root("[[oidc.acme.allow]]\nsubjects = [\"s-1\"]\n");
        let age = |path: &str| {
            let conn = crate::server_db::open(dir.path()).unwrap();
            let sql = format!("UPDATE tokens SET data = json_set(data, '{path}', '2020-01-01T00:00:00.000Z')");
            conn.execute(&sql, []).unwrap();
        };
        let secret = sign_in(dir.path(), "s-1", "proj").unwrap();
        age("$.refresh.refreshed_at");
        let e = refresh(dir.path(), &secret, "r-1", None).unwrap_err();
        assert!(e.to_string().contains("too long ago"), "{e}");
        let secret = sign_in(dir.path(), "s-1", "proj").unwrap();
        age("$.created_at");
        let e = refresh(dir.path(), &secret, "r-1", None).unwrap_err();
        assert!(e.to_string().contains("older than the server lets it be refreshed"), "{e}");
    }
}
