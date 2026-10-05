//! Issuing tokens (an admin's, a sign-in's, an OAuth client's), finding
//! them by their secrets, and refreshing sign-ins (`rotate`).

use super::*;

/// Add an access token to `<root>/server.db`. Returns it with its secret,
/// which is not stored anywhere.
pub fn issue_token(
    root: &Path,
    name: &str,
    actor: &str,
    role: Role,
    kind: Kind,
    workspaces: &[String],
) -> Result<(Token, String)> {
    let grant = Grant { role, kind, workspaces: workspaces.to_vec(), max_claims: None };
    add_token(root, Holder::Admin { name: name.trim(), actor: actor.trim(), resource: None }, grant)
        .map(|issued| (issued.token, issued.secret))
}

/// A token just issued or refreshed, with its secrets, which are not
/// stored anywhere.
pub struct Issued {
    pub token: Token,
    pub secret: String,
    /// The refresh secret, for a token that is refreshed.
    pub refresh_secret: Option<String>,
}

/// How long a sign-in's tokens last.
#[derive(Clone, Debug)]
pub struct Lifetime {
    /// How long each access token works.
    pub ttl: Duration,
    /// Until when its refreshes may renew it, if it is refreshed: they
    /// decide again, by the workspace it signed in for.
    pub refresh: Option<(Timestamp, Duration)>,
    /// The fingerprint of the `[[<provider>.allow]]` rule that let it in,
    /// kept for its refreshes (`oauth::decide`).
    pub rule: Option<String>,
}

/// Add an access token for an account that signed in for
/// `workspace`. It acts as the account's actor: the one bound to it at an
/// earlier sign-in, else its login, bound to it now. It is named
/// `<provider>:<login>-<random>` from its actor (cut to 55 characters), and expires
/// after `life.ttl`; with `life.refresh`, `(limit, idle)`, it may be
/// refreshed until the earlier of `limit` and `idle` after each refresh.
pub fn issue_sign_in_token(
    root: &Path,
    user: &Identity,
    grant: Grant,
    life: Lifetime,
    workspace: &str,
    by_login: bool,
) -> Result<Issued> {
    let now = Timestamp::now();
    let refresh = life.refresh.map(|(limit, idle)| (workspace, limit.min(now.plus(idle))));
    let expires_at = now.plus(life.ttl).min(refresh.map_or(Timestamp(i64::MAX), |(_, until)| until));
    let rule = life.rule.as_deref();
    add_token(root, Holder::SignIn { user, expires_at, by_login, refresh, client: None, rule }, grant)
}

/// The OAuth client a token is issued to, and the MCP endpoint it is bound to.
#[derive(Clone, Copy, Debug)]
pub struct ForClient<'a> {
    pub id: &'a str,
    pub resource: &'a str,
}

/// [`issue_sign_in_token`] for an OAuth `client` an account authorized
/// (`oauth_server/token.rs`): bound to its MCP endpoint (and so to that
/// workspace only), and named `oauth-<client>-<actor>-<random>`.
pub fn issue_client_token(
    root: &Path,
    user: &Identity,
    grant: Grant,
    life: Lifetime,
    client: ForClient<'_>,
    by_login: bool,
) -> Result<Issued> {
    let (_, workspace) = crate::mcp_http::resource_url(client.resource).map_err(Error::invalid)?;
    let now = Timestamp::now();
    let refresh = life.refresh.map(|(limit, idle)| (workspace.as_str(), limit.min(now.plus(idle))));
    let expires_at = now.plus(life.ttl).min(refresh.map_or(Timestamp(i64::MAX), |(_, until)| until));
    let rule = life.rule.as_deref();
    add_token(root, Holder::SignIn { user, expires_at, by_login, refresh, client: Some(client), rule }, grant)
}

/// `text` as part of a token name: letters, digits, `.`, `_` and `-`
/// (anything else becomes `-`), at most `max` characters.
fn name_part(text: &str, max: usize) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    text.chars().map(|c| if plain(c) { c } else { '-' }).take(max).collect()
}

/// What names a client in its tokens' names: the host of its metadata
/// document, or its registered ID; letters, digits, `.`, `_` and `-` only.
fn client_label(id: &str) -> String {
    let id = id.strip_prefix("https://").map_or(id, |rest| rest.split(['/', ':', '?', '#']).next().unwrap_or_default());
    let label: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(20)
        .collect::<String>()
        .to_ascii_lowercase();
    if label.is_empty() { "client".into() } else { label }
}

/// The sign-in whose refresh secret this is, unless revoked: its token, and
/// whether the secret is its current one (else it is spent, or forged).
pub fn find_refresh(root: &Path, secret: &str) -> Result<Option<(Token, bool)>> {
    let Some(family) = refresh_family(secret) else { return Ok(None) };
    let Some(conn) = server_db::open_existing(root)? else { return Ok(None) };
    let found = live_where(&conn, "family", &family.to_ascii_lowercase())?.into_iter().next();
    Ok(found.map(|t| {
        let current = t.refresh.as_ref().is_some_and(|r| r.sha256 == hash(secret));
        (t, current)
    }))
}

/// The token that is not revoked with this secret, or with this refresh
/// secret (its current one, or one spent): what a revocation names.
pub fn find_by_secret(root: &Path, secret: &str) -> Result<Option<Token>> {
    if refresh_family(secret).is_some() {
        return Ok(find_refresh(root, secret)?.map(|(t, _)| t));
    }
    let sha = hash(secret);
    let Some(conn) = server_db::open_existing(root)? else { return Ok(None) };
    Ok(live_where(&conn, "sha256", &sha)?.into_iter().next())
}

/// Refresh the sign-in `id`, whose current refresh secret hashes to
/// `current`, for the request `last` (the secret it presents, and its
/// request id): new secrets, the account as `user` (as its provider names
/// it now when `fresh`, else as it signed in), what the rules grant it now,
/// expiring at `expires_at` and refreshed until `until`. `None` when `current` is no longer the sign-in's (another
/// refresh changed it meanwhile), or the sign-in was revoked.
pub fn rotate(root: &Path, id: &str, current: &str, rotation: Rotation<'_>) -> Result<Option<Issued>> {
    let Rotation { last, user, fresh, grant, by_login, decided, rule, expires_at, until } = rotation;
    let workspaces = workspace_list(&grant.workspaces)?;
    let scope = Scope { ids: &[id], user: Some(user), ..Scope::default() };
    change_scoped(root, &scope, |_, file| {
        let now = Timestamp::now();
        let live =
            |t: &Token| t.id == id && t.revoked_at.is_none() && t.refresh.as_ref().is_some_and(|r| r.sha256 == current);
        let Some(i) = file.tokens.iter().position(live) else { return Ok(None) };
        // A token bound to an MCP endpoint keeps to its workspace, which the rules were just applied for.
        let workspaces = match (&file.tokens[i].resource, &file.tokens[i].refresh) {
            (Some(_), Some(r)) => vec![r.workspace.clone()],
            _ => workspaces,
        };
        let actor = bind(&mut file.accounts, user, now, by_login, fresh)?;
        if actor != file.tokens[i].actor {
            return Err(Error::Unauthorized(format!(
                "{} now acts as {actor}, not {}: sign in again (`bd remote login --provider {}`)",
                user.who(),
                file.tokens[i].actor,
                user.provider
            )));
        }
        if by_login
            && !related(&actor, &user.actor())
            && let Some(other) = actor_conflict(&file.tokens, &user.actor(), Some(user), Some(&actor), now)
        {
            return Err(conflict_error(&user.actor(), Some(user), other));
        }
        if let Some(other) = actor_conflict(&file.tokens, &actor, Some(user), Some(&actor), now) {
            return Err(conflict_error(&actor, Some(user), other));
        }
        let secret = format!("bdt_{}", random_hex(32)?);
        let t = &mut file.tokens[i];
        let refresh = t.refresh.as_mut().expect("found by its refresh state");
        let refresh_secret = refresh_secret(&refresh.family)?;
        refresh.sha256 = hash(&refresh_secret);
        refresh.refreshed_at = now;
        if decided {
            refresh.decided_at = now;
        }
        refresh.rule = rule;
        refresh.until = until;
        refresh.last = Some(last);
        t.sha256 = hash(&secret);
        t.expires_at = Some(expires_at.min(until));
        t.role = grant.role;
        t.kind = grant.kind;
        t.workspaces = workspaces;
        t.max_claims = grant.max_claims;
        t.identity = Some(user.clone());
        let token = t.clone();
        file.events.push(token.event("refreshed", None));
        Ok(Some(Issued { token, secret, refresh_secret: Some(refresh_secret) }))
    })
}

/// What a refresh renews a sign-in with ([`rotate`]).
pub struct Rotation<'a> {
    /// The refresh it answers: the secret spent and its request id, hashed.
    pub last: LastRefresh,
    /// The account as its provider names it now (`fresh`), or as it signed in.
    pub user: &'a Identity,
    pub fresh: bool,
    /// What the rules or the authorizer grant it now, and whether a rule let
    /// it in by its login.
    pub grant: Grant,
    pub by_login: bool,
    /// Whether they decided now (not a grant kept while the authorizer could not answer).
    pub decided: bool,
    /// The OIDC rule that let it in (its fingerprint), if one did.
    pub rule: Option<String>,
    /// When the new access token expires, and until when it may be refreshed.
    pub expires_at: Timestamp,
    pub until: Timestamp,
}

/// Whom a new token is for.
pub(super) enum Holder<'a> {
    /// An admin names it, its actor, and maybe the MCP endpoint it is bound to.
    Admin { name: &'a str, actor: &'a str, resource: Option<&'a str> },
    /// An account that signed in; `by_login` when a rule let it in by
    /// its login; `refresh`, the workspace it signed in for and until when
    /// it may be refreshed, if it may; `client`, the OAuth client it
    /// authorized, if it did.
    SignIn {
        user: &'a Identity,
        expires_at: Timestamp,
        by_login: bool,
        refresh: Option<(&'a str, Timestamp)>,
        client: Option<ForClient<'a>>,
        /// The fingerprint of the OIDC rule that let it in, for its refreshes.
        rule: Option<&'a str>,
    },
}

fn check_name(name: &str) -> Result<()> {
    let ok = name.len() <= 64
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    match ok {
        true => Ok(()),
        false => Err(Error::invalid(format!(
            "invalid token name {name:?}: a letter or digit, then letters, digits, '.', '_' or '-' (at most 64)"
        ))),
    }
}

pub(super) fn check_actor(actor: &str) -> Result<()> {
    bd_core::store::validate_actor(actor)?;
    if actor.starts_with('/') || actor.ends_with('/') || actor.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "invalid actor {actor:?}: no control characters, and no '/' at either end"
        )));
    }
    Ok(())
}

pub(super) fn add_token(root: &Path, holder: Holder, grant: Grant) -> Result<Issued> {
    let mut workspaces = workspace_list(&grant.workspaces)?;
    let mut resource = None;
    let bound = match &holder {
        Holder::Admin { resource: Some(url), .. } => {
            Some(crate::mcp_http::resource_url(url).map_err(|e| Error::invalid(format!("--resource {e}")))?)
        }
        Holder::SignIn { client: Some(client), .. } => {
            Some(crate::mcp_http::resource_url(client.resource).map_err(Error::invalid)?)
        }
        _ => None,
    };
    if let Some((url, workspace)) = bound {
        if !workspaces.iter().any(|w| w == "*" || *w == workspace) {
            return Err(Error::invalid(format!(
                "--resource {url} is workspace {workspace}'s, which the token may not use"
            )));
        }
        // A bound token works at that workspace only.
        workspaces = vec![workspace];
        resource = Some(url);
    }
    if let Holder::Admin { name, actor, .. } = &holder {
        check_name(name)?;
        check_actor(actor)?;
        if is_reserved_actor(actor) {
            return Err(Error::invalid(format!(
                "actor {actor} is reserved for bd serve's background writes: pick another actor"
            )));
        }
        // `<provider>:<login>` is the accounts' who sign in: an admin's token there would keep that account out.
        if actor.split('/').next().is_some_and(|root| root.contains(':')) {
            return Err(Error::invalid(format!(
                "actor {actor} names a provider's account (<provider>:<login>), which signs in for its own tokens: \
                 pick an actor without ':'"
            )));
        }
    }
    let scope = match &holder {
        Holder::Admin { actor, .. } => Scope { actors: vec![actor.to_string()], ..Scope::default() },
        Holder::SignIn { user, .. } => Scope { user: Some(*user), ..Scope::default() },
    };
    change_scoped(root, &scope, |tx, file| {
        let now = Timestamp::now();
        let (name, actor, expires_at, identity, refresh, client, rule) = match holder {
            Holder::Admin { name, actor, .. } => {
                if let Some(account) = file.accounts.iter().find(|a| related(&a.actor, actor)) {
                    return Err(Error::Refused(format!(
                        "actor {actor} would share actor {} with {}, who signed in: pick another actor, or release that \
                     one first (`bd serve token revoke --account {} --forget`)",
                        account.actor,
                        account.who(),
                        account.actor
                    )));
                }
                (name.to_string(), actor.to_string(), None, None, None, None, None)
            }
            Holder::SignIn { user, expires_at, by_login, refresh, client, rule } => {
                let actor = account_actor(file, user, now, by_login)?;
                let name = match client {
                    Some(c) => format!("oauth-{}-{}-{}", client_label(c.id), name_part(&actor, 24), random_hex(4)?),
                    None => {
                        // `github-alice-…`, `google-alice-acme.com-…`: the provider once.
                        let named = match actor.contains(':') {
                            true => actor.clone(),
                            false => format!("{}:{actor}", user.provider),
                        };
                        format!("{}-{}", name_part(&named, 55), random_hex(4)?)
                    }
                };
                check_name(&name)?;
                check_actor(&actor)?;
                let client = client.map(|c| c.id.to_string());
                (name, actor, Some(expires_at), Some(user.clone()), refresh, client, rule.map(str::to_string))
            }
        };
        if !live_where(tx, "name", &name)?.is_empty() {
            return Err(Error::Refused(format!("access token {name} already exists; revoke it first")));
        }
        let principal = identity.as_ref().map(|_| actor.as_str());
        if let Some(other) = actor_conflict(&file.tokens, &actor, identity.as_ref(), principal, now) {
            return Err(conflict_error(&actor, identity.as_ref(), other));
        }
        let secret = format!("bdt_{}", random_hex(32)?);
        let (refresh, refresh_secret) = match refresh {
            Some((workspace, until)) => {
                let family = random_hex(16)?;
                let secret = refresh_secret(&family)?;
                let state = Refresh {
                    family,
                    sha256: hash(&secret),
                    workspace: workspace.to_string(),
                    refreshed_at: now,
                    decided_at: now,
                    until,
                    last: None,
                    rule,
                };
                (Some(state), Some(secret))
            }
            None => (None, None),
        };
        let token = Token {
            id: random_hex(8)?,
            name,
            actor,
            role: grant.role,
            kind: grant.kind,
            workspaces,
            sha256: hash(&secret),
            created_at: now.to_rfc3339(),
            revoked_at: None,
            expires_at,
            identity,
            max_claims: grant.max_claims,
            refresh,
            resource,
            client,
        };
        file.tokens.push(token.clone());
        let kind = if token.identity.is_some() { "signed_in" } else { "token_created" };
        file.events.push(token.event(kind, None));
        if let Some(user) = &token.identity {
            // Newest first (tokens are in the order they were added): this account's live sign-ins at this
            // client past the first MAX_SIGN_INS.
            let older: Vec<String> = file
                .tokens
                .iter()
                .rev()
                .filter(|t| !t.ended(now) && t.client == token.client)
                .filter(|t| t.identity.as_ref().is_some_and(|other| other.same(user)))
                .skip(MAX_SIGN_INS)
                .map(|t| t.id.clone())
                .collect();
            if !older.is_empty() {
                file.revoke("superseded by newer sign-ins of the account", |t| older.contains(&t.id));
            }
        }
        Ok(Issued { token, secret, refresh_secret })
    })
}
