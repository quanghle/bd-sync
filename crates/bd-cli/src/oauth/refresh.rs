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
    let refused =
        |why: String| Error::Unauthorized(format!("{why}; sign in again: `bd remote login --provider <name>`"));
    let sign_in = enabled(root)?;
    let Some((token, current)) = auth::find_refresh(root, secret)? else {
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
    if sign_in.oidc(&user.provider).is_some_and(|o| o.deny.contains(&user.subject)) {
        revoke("the account is denied")?;
        return Err(refused(format!("{} may not use this bd server", user.who())));
    }
    // A GitHub account is never one denied, and, with the GitHub App, is taken as GitHub names it now. Without
    // the App (and for other providers), the authorizer decides on the identity of the sign-in.
    let (mut now_user, mut created, mut fresh) = (user.clone(), None, false);
    if user.provider == "github" {
        let github =
            github_of(&sign_in).map_err(|_| refused("this bd server no longer signs people in with GitHub".into()))?;
        if github_id(&user).is_some_and(|id| github.deny.contains(&id)) {
            revoke("the account is denied")?;
            return Err(refused(format!("{} may not use this bd server", user.who())));
        }
        if let Some(key) = &github.app {
            let api = Api::new(github);
            let app = AppApi { api: &api, github, key };
            let Some(id) = github_id(&user) else {
                return Err(refused("not a GitHub sign-in".into()));
            };
            let Some((named, made)) = app.user(id)? else {
                revoke("the GitHub account no longer exists")?;
                return Err(refused(format!("GitHub has no account {} any more", user.login)));
            };
            if named.issuer != user.issuer {
                return Err(refused(format!("{} signed in at another GitHub than the server's now", user.who())));
            }
            (now_user, created, fresh) = (named, made, true);
        }
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
        // [[oidc.<name>.allow]] rules: by what bd keeps of the account, and the rule it signed in by.
        None if user.provider != "github" => {
            let oidc = sign_in.oidc(&user.provider).ok_or_else(|| refused("not a sign-in of this server's".into()))?;
            let kept = state.rule.as_deref();
            let (decided, matched) =
                crate::oidc::decide(&oidc.allow, &user.subject, None, &oidc.groups_claim, kept, &state.workspace);
            match decided {
                Decision::In { grant, via, by_login } => {
                    rule = matched;
                    (grant, via, by_login, true)
                }
                _ => {
                    let why = format!("the rules no longer let it into workspace {}", state.workspace);
                    revoke(&why)?;
                    return Err(refused(format!("{}: {why}", user.who())));
                }
            }
        }
        // [[github.allow]] rules, through the GitHub App, which refreshes() found.
        None => {
            let github = github_of(&sign_in)?;
            let Some(key) = &github.app else {
                return Err(refused("this bd server no longer refreshes these sign-ins".into()));
            };
            let api = Api::new(github);
            let app = AppApi { api: &api, github, key };
            let age = created.map(|at| Duration::from_millis(now.since(at).max(0) as u64));
            let mut asked = Installed { app: &app, login: &now_user.login, seen: HashMap::new() };
            match decide(github, &now_user.login, age, &state.workspace, &mut asked, &mut unknown)? {
                Decision::In { grant, via, by_login } => (grant, via, by_login, true),
                out => {
                    let why = match out {
                        Decision::TooNew(_) => "its GitHub account is too new for the rules".to_string(),
                        Decision::Elsewhere(_) => {
                            format!("the rules no longer let it into workspace {}", state.workspace)
                        }
                        _ => "no rule of the server's auth.toml lets the account in any more".to_string(),
                    };
                    // Memberships GitHub would not tell may come back: the sign-in stays, and only this refresh fails.
                    if matches!(out, Decision::Unknown) || !unknown.is_empty() {
                        tracing::warn!(target: "bd::serve", login = %now_user.login, ?unknown, "GitHub sign-in not refreshed: memberships unknown");
                        return Err(Error::Remote(format!(
                            "GitHub would not tell this bd server the memberships of GitHub user {} ({}); try again later",
                            now_user.login,
                            unknown.join("; ")
                        )));
                    }
                    revoke(&why)?;
                    return Err(refused(format!("GitHub user {}: {why}", now_user.login)));
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
        let s = load(root)?.unwrap();
        let oidc = s.oidc("acme").unwrap();
        let claims = crate::oidc::Claims {
            subject: subject.into(),
            login: format!("user-{subject}"),
            email: None,
            all: serde_json::json!({}),
        };
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
            assert!(e.to_string().contains(&format!("may not use workspace {workspace}")), "{e}");
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
        assert!(matches!(e, Error::Unauthorized(_)) && e.to_string().contains("no longer let it into"), "{e}");
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
