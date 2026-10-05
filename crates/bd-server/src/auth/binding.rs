//! Accounts and the actors they are bound to: binding at sign-in (`bind`),
//! who else acts as an actor (`actor_conflict`), linking and naming accounts,
//! revoking and forgetting them.

use super::*;

/// The actor a sign-in of `user` gets, bound to its account in `file`, or
/// why it may not sign in for its actor's sake.
pub(super) fn account_actor(file: &mut TokenFile, user: &Identity, now: Timestamp, by_login: bool) -> Result<String> {
    let actor = bind(&mut file.accounts, user, now, by_login, true)?;
    if is_reserved_actor(&actor) {
        return Err(Error::Unauthorized(format!(
            "{} may not sign in to this bd server: its actor {actor} is bd serve's own",
            user.who()
        )));
    }
    // A renamed account let in by a login that names another principal's actor must not pass for it.
    if by_login
        && !related(&actor, &user.actor())
        && let Some(other) = actor_conflict(&file.tokens, &user.actor(), Some(user), Some(&actor), now)
    {
        return Err(conflict_error(&user.actor(), Some(user), other));
    }
    if let Some(other) = actor_conflict(&file.tokens, &actor, Some(user), Some(&actor), now) {
        return Err(conflict_error(&actor, Some(user), other));
    }
    Ok(actor)
}

/// The actor a sign-in of `user` would get now, binding nothing: what
/// [`issue_sign_in_token`] would refuse for its actor's sake is refused
/// before anyone is asked to approve a client (`oauth_server/authorize/`).
/// Issuing the token checks again.
pub fn preview_actor(root: &Path, user: &Identity, by_login: bool) -> Result<String> {
    let mut file = read_scoped(root, Some(&Scope { user: Some(user), ..Scope::default() }))?;
    let actor = account_actor(&mut file, user, Timestamp::now(), by_login)?;
    check_actor(&actor)?;
    Ok(actor)
}

/// The actor of `user`'s tokens: the one bound to its account, else its
/// login, bound to it now. Refused while the login would bind another
/// account's actor; and, when a rule let the account in `by_login`, while
/// another account's actor or latest login is related to it, even for an
/// account bound before: one that took a login given up must not pass for
/// its previous holder, whom rules name by it.
pub(super) fn bind(
    accounts: &mut Vec<Account>,
    user: &Identity,
    now: Timestamp,
    by_login: bool,
    fresh: bool,
) -> Result<String> {
    let own = accounts.iter().find(|a| a.is(user)).map(|a| server_db::key(&a.actor));
    let bound = own.is_some();
    let wanted = user.actor();
    let taken = |a: &Account| {
        let actor = related(&a.actor, &wanted) && (!bound || by_login);
        // A login names an account at its own provider only.
        let login = by_login && a.issuer == user.issuer && related(&a.login, &user.login);
        // An account an admin linked to this one's actor is the same principal.
        let linked = own.as_deref() == Some(server_db::key(&a.actor).as_str());
        !a.is(user) && !linked && (actor || login)
    };
    if let Some(other) = accounts.iter().find(|a| taken(a)) {
        tracing::info!(
            target: "bd::serve",
            login = %user.login,
            subject = %user.subject,
            actor = %other.actor,
            bound_to = %other.subject,
            "sign-in refused: the login's actor belongs to another account"
        );
        let whose = match related(&other.actor, &wanted) {
            true => format!("actor {} belongs to another account, which had that login before", other.actor),
            // That account's actor is its own business (it is in the log).
            false => format!("login {} was that of another account before", other.login),
        };
        return Err(Error::Unauthorized(format!(
            "{} may not sign in to this bd server: {whose}; the server's admin resolves that (`bd serve token \
             accounts`)",
            user.who()
        )));
    }
    if let Some(account) = accounts.iter_mut().find(|a| a.is(user)) {
        // Only a login the provider just gave is the account's latest: a refresh replaying the one a sign-in kept
        // would turn a renamed account's back.
        if fresh {
            account.login = user.login.clone();
        }
        account.last_seen = now;
        return Ok(account.actor.clone());
    }
    accounts.push(Account {
        provider: user.provider.clone(),
        issuer: user.issuer.clone(),
        subject: user.subject.clone(),
        actor: wanted.clone(),
        login: user.login.clone(),
        first_seen: now,
        last_seen: now,
        name: None,
    });
    Ok(wanted)
}

/// A live token of another principal whose actor a new token's would share,
/// or cover with sub-actors: an account's against an admin's or
/// another account's, and the other way round. Tokens an admin creates may
/// share actors among themselves.
pub(super) fn actor_conflict<'a>(
    tokens: &'a [Token],
    actor: &str,
    identity: Option<&Identity>,
    principal: Option<&str>,
    now: Timestamp,
) -> Option<&'a Token> {
    // Accounts an admin linked to one actor (`link`) are one principal: their tokens act as it alike. No other
    // account's token acts as an account's own actor, as a binding is never given twice otherwise.
    let ours = |t: &Token| principal.is_some_and(|p| server_db::key(p) == server_db::key(&t.actor));
    tokens.iter().filter(|t| t.revoked_at.is_none() && !t.expired(now)).find(|t| match (identity, &t.identity) {
        (None, None) => false,
        (Some(user), Some(other)) => related(actor, &t.actor) && !(other.same(user)) && !ours(t),
        _ => related(actor, &t.actor),
    })
}

pub(super) fn conflict_error(actor: &str, identity: Option<&Identity>, other: &Token) -> Error {
    match (identity, &other.identity) {
        (Some(user), _) => {
            tracing::info!(
                target: "bd::serve",
                login = %user.login,
                subject = %user.subject,
                token = %other.name,
                actor = %other.actor,
                "sign-in refused: another token's actor"
            );
            // Another account's actor stays in the log: the person signing in learns only that theirs is taken.
            Error::Unauthorized(format!(
                "{} may not sign in to this bd server as actor {actor}: another access token acts as it, or as an \
                 actor related to it; the server's admin resolves that (`bd serve token list`)",
                user.who()
            ))
        }
        (None, Some(owner)) => Error::Refused(format!(
            "actor {actor} would share actor {} with {}, who signed in: pick another actor, or release that one \
             first (`bd serve token revoke --account {} --forget`)",
            other.actor,
            owner.who(),
            other.actor
        )),
        (None, None) => Error::Refused(format!("actor {actor} is taken by access token {}", other.name)),
    }
}

/// Revoke the token with this id (not its name, which a later token may
/// reuse): whether it was revoked now.
pub fn revoke_by_id(root: &Path, id: &str, why: &str) -> Result<bool> {
    change_scoped(root, &Scope { ids: &[id], ..Scope::default() }, |_, file| {
        Ok(!file.revoke(why, |t| t.id == id).is_empty())
    })
}

/// Revoke the tokens `pick` selects: how many it selects, and the names of
/// those revoked now (the others already were).
pub(super) fn revoke_where(root: &Path, why: &str, pick: impl Fn(&Token) -> bool) -> Result<(usize, Vec<String>)> {
    change(root, |file| {
        let known = file.tokens.iter().filter(|t| pick(t)).count();
        Ok((known, file.revoke(why, pick)))
    })
}

/// End the sign-ins of the account with this issuer and subject made
/// before `at`, as its provider says it revoked its consent then: the names
/// of the tokens revoked. One signed in since is the account's new consent.
pub fn end_sign_ins_before(root: &Path, issuer: &str, subject: &str, at: Timestamp) -> Result<Vec<String>> {
    change_scoped(root, &Scope { account: Some((issuer, subject)), ..Scope::default() }, |_, file| {
        Ok(file.revoke("its consent was revoked at its provider", |t| {
            let theirs = t.identity.as_ref().is_some_and(|g| g.issuer == issuer && g.subject == subject);
            theirs && Timestamp::parse_rfc3339(&t.created_at).is_ok_and(|created| created < at)
        }))
    })
}

/// Forget the account with this issuer and subject, as its provider says it
/// was deleted: the account and every token of it, erased as `revoke
/// --account --forget` does. Whether there was one. Over every row, as
/// `revoke --account --forget` is: an account's tokens may act as an actor it
/// no longer has (linked since), which a load by its actor would not find.
pub fn forget_account(root: &Path, issuer: &str, subject: &str) -> Result<bool> {
    let found = change(root, |file| {
        let theirs = |g: &Identity| g.issuer == issuer && g.subject == subject;
        let before = (file.accounts.len(), file.tokens.len());
        let provider =
            file.accounts.iter().find(|a| a.issuer == issuer && a.subject == subject).map(|a| a.provider.clone());
        file.accounts.retain(|a| !(a.issuer == issuer && a.subject == subject));
        file.tokens.retain(|t| !t.identity.as_ref().is_some_and(theirs));
        let found = before != (file.accounts.len(), file.tokens.len());
        if found {
            file.erased.push((issuer.to_string(), subject.to_string()));
            file.events.push(forgotten(provider, "deleted at its provider"));
        }
        Ok(found)
    })?;
    if found {
        server_db::scrub(root)?;
    }
    Ok(found)
}

/// The one account `name` names: its actor (unless linked accounts share
/// it), else its latest login at one provider.
fn one_account<'a>(accounts: &'a [Account], name: &str) -> Result<&'a Account> {
    let named = |s: &str| s.eq_ignore_ascii_case(name);
    let by_actor: Vec<&Account> = accounts.iter().filter(|a| named(&a.actor)).collect();
    let found = match by_actor.is_empty() {
        false => by_actor,
        true => accounts.iter().filter(|a| named(&a.login)).collect(),
    };
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(Error::not_found("account", name)),
        several => Err(Error::invalid(format!(
            "{name} names {} accounts ({}): name one by its login",
            several.len(),
            several.iter().map(|a| a.who()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// Name the account `account` names `name` (`None`: no name), for admins:
/// the account as it is now.
pub(super) fn set_name(root: &Path, account: &str, name: Option<&str>) -> Result<Account> {
    if let Some(name) = name
        && !crate::oauth_server::clients::shows_plainly(name, 64)
    {
        return Err(Error::invalid("a name is 1 to 64 characters of plain text"));
    }
    change(root, |file| {
        let found = one_account(&file.accounts, account)?.clone();
        let bound = file.accounts.iter_mut().find(|a| a.is_same(&found)).expect("found above");
        bound.name = name.map(str::to_string);
        let named = bound.clone();
        file.events.push(AuthEvent {
            kind: "named",
            actor: Some(named.actor.clone()),
            provider: Some(named.provider.clone()),
            issuer: Some(named.issuer.clone()),
            subject: Some(named.subject.clone()),
            detail: Some(match name {
                Some(n) => format!("an admin named it {n}"),
                None => "an admin removed its name".into(),
            }),
            ..AuthEvent::default()
        });
        Ok(named)
    })
}

/// What [`link`] did.
#[derive(Debug)]
pub(super) struct Linked {
    pub(super) account: Account,
    /// The actor it was bound to.
    pub(super) was: String,
    /// Names of its tokens revoked: they acted as that actor.
    pub(super) revoked: Vec<String>,
}

/// Bind the account `name` names to `to`, the actor of another account, so
/// that one person signing in with several providers is one actor: an
/// admin's decision, as it lets that account act as the other's actor. Its
/// tokens are revoked (they act as its former actor, which it gives up);
/// its next sign-in acts as `to`.
pub(super) fn link(root: &Path, name: &str, to: &str) -> Result<Linked> {
    change(root, |file| {
        let account = one_account(&file.accounts, name)?.clone();
        let target = file
            .accounts
            .iter()
            .find(|a| !a.is_same(&account) && a.actor.eq_ignore_ascii_case(to))
            .map(|a| a.actor.clone())
            .ok_or_else(|| Error::not_found("account bound to actor", to))?;
        if account.actor == target {
            return Err(Error::invalid(format!("{} acts as {target} already", account.who())));
        }
        let why = format!("an admin linked its account to {target}");
        let revoked = file.revoke(&why, |t| t.identity.as_ref().is_some_and(|g| account.is(g)));
        let bound = file.accounts.iter_mut().find(|a| a.is_same(&account)).expect("found above");
        bound.actor = target.clone();
        let now_bound = bound.clone();
        file.events.push(AuthEvent {
            kind: "linked",
            actor: Some(target),
            provider: Some(account.provider.clone()),
            issuer: Some(account.issuer.clone()),
            subject: Some(account.subject.clone()),
            detail: Some(format!("an admin linked it; it acted as {}", account.actor)),
            ..AuthEvent::default()
        });
        Ok(Linked { was: account.actor, account: now_bound, revoked })
    })
}

/// The event of an account forgotten: which provider's, and why, and no
/// more: nothing of the account outlives it, in the audit trail either.
pub(super) fn forgotten(provider: Option<String>, why: &str) -> AuthEvent {
    AuthEvent { kind: "forgotten", provider, detail: Some(why.to_string()), ..AuthEvent::default() }
}

/// What `revoke --account` did.
#[derive(Debug)]
pub(super) struct AccountRevoked {
    /// The accounts known by the login: their latest login, or their actor.
    pub(super) accounts: Vec<Account>,
    /// Names of the tokens revoked now (the others already were).
    pub(super) revoked: Vec<String>,
    /// With `--forget`: whether what was deleted is gone from the
    /// database's files too, or stays in its write-ahead log until the
    /// server's next checkpoint.
    pub(super) erased: Option<bool>,
}

/// Revoke every token of the accounts known by `login` (their latest
/// login, or their actor), and any token that signed in as it, so that the
/// tokens from before a rename go too; with `forget`, also release those
/// accounts' actors.
pub(super) fn revoke_account(root: &Path, login: &str, forget: bool) -> Result<AccountRevoked> {
    change(root, |file| {
        let named = |s: &str| s.eq_ignore_ascii_case(login);
        // An actor names its account alone; else a login names the accounts it is (or, renamed, was) the login of,
        // at one provider: at several, their actors tell them apart.
        let by_actor: Vec<Account> = file.accounts.iter().filter(|a| named(&a.actor)).cloned().collect();
        let accounts = match by_actor.is_empty() {
            false => by_actor,
            true => file.accounts.iter().filter(|a| named(&a.login)).cloned().collect(),
        };
        let by_actor = accounts.iter().any(|a| named(&a.actor));
        let mut providers: Vec<&str> = accounts.iter().map(|a| a.provider.as_str()).collect();
        providers.sort_unstable();
        providers.dedup();
        // An actor names every account linked to it, whatever their providers; a login, one provider's.
        if providers.len() > 1 && !by_actor {
            let actors: Vec<&str> = accounts.iter().map(|a| a.actor.as_str()).collect();
            return Err(Error::invalid(format!(
                "{login} is the login of accounts at {}: name the one to revoke by its actor ({})",
                providers.join(" and "),
                actors.join(", ")
            )));
        }
        // Their tokens, and tokens signed in as the login at the same provider (from before a rename).
        let theirs = |t: &Token| {
            t.identity.as_ref().is_some_and(|g| {
                accounts.iter().any(|a| a.is(g))
                    || (named(&g.login) && (accounts.is_empty() || providers.contains(&g.provider.as_str())))
            })
        };
        if accounts.is_empty() && !file.tokens.iter().any(&theirs) {
            return Err(Error::not_found("account with access tokens", login));
        }
        let revoked = file.revoke("an admin revoked the account's tokens", theirs);
        if forget {
            // Erased, not kept until pruned: the account and every record of its tokens.
            file.accounts.retain(|a| !accounts.contains(a));
            file.tokens.retain(|t| !theirs(t));
            for a in &accounts {
                file.erased.push((a.issuer.clone(), a.subject.clone()));
                file.events.push(forgotten(Some(a.provider.clone()), "an admin released its actor"));
            }
        }
        Ok(AccountRevoked { accounts, revoked, erased: None })
    })
    .and_then(|mut done| {
        if forget {
            done.erased = Some(server_db::scrub(root)?);
        }
        Ok(done)
    })
}
