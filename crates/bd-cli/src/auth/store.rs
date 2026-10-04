//! Accounts and tokens in `<root>/server.db`: each change one transaction
//! (`change`, `change_scoped` loading only the rows its checks look at), its
//! rows and audit events written back (`save`), tokens pruned (`prune`).

use super::*;

/// The accounts and tokens of `<root>/server.db`, in the order they were added.
#[derive(Clone, Debug, Default)]
pub(super) struct TokenFile {
    pub(super) tokens: Vec<Token>,
    /// Accounts that signed in: never dropped, so an actor never passes
    /// from one account to another.
    pub(super) accounts: Vec<Account>,
    /// What the change did, for the audit trail: recorded with its rows.
    pub(super) events: Vec<AuthEvent>,
    /// Accounts (issuer, subject) forgotten: their events are erased, after
    /// this change's own are recorded.
    pub(super) erased: Vec<(String, String)>,
}

/// The records of a table's `data` column, in the order they were added.
pub(super) fn records<T: serde::de::DeserializeOwned>(conn: &rusqlite::Connection, sql: &str) -> Result<Vec<T>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let texts = stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    texts.iter().map(|t| serde_json::from_str(t).map_err(|e| Error::invalid(format!("server.db: {e}")))).collect()
}

pub(super) fn load(conn: &rusqlite::Connection) -> Result<TokenFile> {
    Ok(TokenFile {
        tokens: records(conn, "SELECT data FROM tokens ORDER BY seq")?,
        accounts: records(conn, "SELECT data FROM accounts ORDER BY seq")?,
        events: Vec::new(),
        erased: Vec::new(),
    })
}

/// All the accounts and tokens, as they are now (none if there is no `server.db`).
pub(super) fn read(root: &Path) -> Result<TokenFile> {
    read_scoped(root, None)
}

/// The accounts and tokens `scope` names (all of them for `None`), read at one moment.
pub(super) fn read_scoped(root: &Path, scope: Option<&Scope>) -> Result<TokenFile> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(TokenFile::default()) };
    server_db::read(root, &mut conn, |tx| match scope {
        Some(scope) => scoped(tx, scope),
        None => load(tx),
    })
}

/// Change all the accounts and tokens with `f`, in one transaction: the
/// rows it added, changed or dropped are written if it succeeds, nothing if
/// not. For an admin's changes; the server's go through [`change_scoped`].
pub(super) fn change<T>(root: &Path, f: impl FnOnce(&mut TokenFile) -> Result<T>) -> Result<T> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        prune(tx)?;
        let before = load(tx)?;
        let mut file = before.clone();
        let out = f(&mut file)?;
        save(tx, &before, &file)?;
        Ok(out)
    })
}

/// [`change`], with only the rows `scope` names loaded: all that a sign-in,
/// a refresh or a revocation by id looks at, so that each costs what its
/// own rows do, however many others there are. `f` gets the transaction too.
pub(super) fn change_scoped<T>(
    root: &Path,
    scope: &Scope,
    f: impl FnOnce(&rusqlite::Transaction, &mut TokenFile) -> Result<T>,
) -> Result<T> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        prune(tx)?;
        let before = scoped(tx, scope)?;
        let mut file = before.clone();
        let out = f(tx, &mut file)?;
        save(tx, &before, &file)?;
        Ok(out)
    })
}

/// Delete the tokens that ended [`PRUNE_AFTER`] ago: revoked, or a
/// sign-in's that expired and could no longer be refreshed (`ended_at`).
pub(super) fn prune(tx: &rusqlite::Transaction) -> Result<()> {
    tx.execute("DELETE FROM tokens WHERE ended_at <= ?1", [Timestamp::now().minus(PRUNE_AFTER).millis()])?;
    server_db::prune_events(tx)
}

/// Which rows a change or a read looks at.
#[derive(Default)]
pub(super) struct Scope<'a> {
    /// Tokens by id; their actors' tokens and accounts too.
    pub(super) ids: &'a [&'a str],
    /// The tokens and accounts of actors related to these.
    pub(super) actors: Vec<String>,
    /// The account of this identity, and every account and token that
    /// [`bind`] and [`actor_conflict`] would look at for it: those related
    /// to its actor, to the actor its account is bound to, and to its login.
    pub(super) user: Option<&'a Identity>,
    /// The account with this issuer and subject, and the tokens of its actor.
    pub(super) account: Option<(&'a str, &'a str)>,
}

/// The rows a change or read for `scope` loads.
pub(super) fn scoped(conn: &rusqlite::Connection, scope: &Scope) -> Result<TokenFile> {
    #[cfg(test)]
    if WHOLE.get() {
        return load(conn);
    }
    load_scope(conn, scope)
}

/// The rows `scope` names, in the order they were added: a superset of
/// what the checks of a change for it look at, so they decide as they
/// would over every row.
pub(super) fn load_scope(conn: &rusqlite::Connection, scope: &Scope) -> Result<TokenFile> {
    use std::collections::BTreeMap;
    let mut tokens: BTreeMap<i64, String> = BTreeMap::new();
    let mut accounts: BTreeMap<i64, String> = BTreeMap::new();
    let add = |into: &mut BTreeMap<i64, String>, sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<()> {
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(args, |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (seq, data) = row?;
            into.insert(seq, data);
        }
        Ok(())
    };
    // Every key related to `key` in `column`: itself, its ancestors, its descendants.
    let related = |into: &mut BTreeMap<i64, String>, table: &str, column: &str, key: &str| -> Result<()> {
        let (exact, (low, high)) = server_db::related_keys(key);
        for k in &exact {
            add(into, &format!("SELECT seq, data FROM {table} WHERE {column} = ?1"), &[k])?;
        }
        add(into, &format!("SELECT seq, data FROM {table} WHERE {column} > ?1 AND {column} < ?2"), &[&low, &high])
    };
    let actor_of = |data: &str| -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(data)?;
        Ok(v["actor"].as_str().unwrap_or_default().to_string())
    };
    let mut actors = scope.actors.clone();
    for id in scope.ids {
        add(&mut tokens, "SELECT seq, data FROM tokens WHERE id = ?1", &[id])?;
    }
    for data in tokens.values() {
        actors.push(actor_of(data)?);
    }
    if let Some((issuer, subject)) = scope.account {
        let sql = "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2";
        add(&mut accounts, sql, &[&issuer, &subject])?;
        for data in accounts.values() {
            actors.push(actor_of(data)?);
        }
    }
    if let Some(user) = scope.user {
        let sql = "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2";
        add(&mut accounts, sql, &[&user.issuer, &user.subject])?;
        for data in accounts.values() {
            actors.push(actor_of(data)?);
        }
        actors.push(user.actor());
        related(&mut accounts, "accounts", "login_key", &server_db::key(&user.login))?;
    }
    for actor in &actors {
        let key = server_db::key(actor);
        related(&mut accounts, "accounts", "actor_key", &key)?;
        related(&mut tokens, "tokens", "actor_key", &key)?;
    }
    pub(super) fn parse<T: serde::de::DeserializeOwned>(what: &str, data: &str) -> Result<T> {
        serde_json::from_str(data).map_err(|e| Error::invalid(format!("server.db: {what}: {e}")))
    }
    Ok(TokenFile {
        tokens: tokens.values().map(|d| parse("a token", d)).collect::<Result<_>>()?,
        accounts: accounts.values().map(|d| parse("an account", d)).collect::<Result<_>>()?,
        events: Vec::new(),
        erased: Vec::new(),
    })
}

/// Write the rows of `after` that are not as in `before`, and drop those it
/// no longer has; record its events.
pub(super) fn save(tx: &rusqlite::Transaction, before: &TokenFile, after: &TokenFile) -> Result<()> {
    for event in &after.events {
        server_db::record(tx, event)?;
    }
    for (issuer, subject) in &after.erased {
        server_db::erase_events(tx, issuer, subject)?;
    }
    let was: HashMap<&str, String> =
        before.tokens.iter().map(|t| Ok((t.id.as_str(), serde_json::to_string(t)?))).collect::<Result<_>>()?;
    let ids: std::collections::HashSet<&str> = after.tokens.iter().map(|t| t.id.as_str()).collect();
    for gone in was.keys().filter(|id| !ids.contains(*id)) {
        tx.execute("DELETE FROM tokens WHERE id = ?1", [gone])?;
    }
    for t in &after.tokens {
        let data = serde_json::to_string(t)?;
        if was.get(t.id.as_str()) != Some(&data) {
            let family = t.refresh.as_ref().map(|r| r.family.to_ascii_lowercase());
            let (actor_key, name, ended_at) = server_db::token_keys(&serde_json::to_value(t)?);
            tx.execute(
                "INSERT INTO tokens (id, sha256, family, actor_key, name, ended_at, data) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (id) DO UPDATE SET sha256 = excluded.sha256, \
                 family = excluded.family, actor_key = excluded.actor_key, name = excluded.name, \
                 ended_at = excluded.ended_at, data = excluded.data",
                rusqlite::params![t.id, t.sha256, family, actor_key, name, ended_at, data],
            )?;
        }
    }
    let key = |a: &Account| (a.issuer.clone(), a.subject.clone());
    let was: HashMap<(String, String), String> =
        before.accounts.iter().map(|a| Ok((key(a), serde_json::to_string(a)?))).collect::<Result<_>>()?;
    let keys: std::collections::HashSet<(String, String)> = after.accounts.iter().map(key).collect();
    for (issuer, subject) in was.keys().filter(|k| !keys.contains(*k)) {
        tx.execute("DELETE FROM accounts WHERE issuer = ?1 AND subject = ?2", [issuer, subject])?;
    }
    for a in &after.accounts {
        let data = serde_json::to_string(a)?;
        if was.get(&key(a)) != Some(&data) {
            let (actor_key, login_key) = server_db::account_keys(&serde_json::to_value(a)?);
            tx.execute(
                "INSERT INTO accounts (issuer, subject, actor_key, login_key, data) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (issuer, subject) DO UPDATE SET actor_key = excluded.actor_key, \
                 login_key = excluded.login_key, data = excluded.data",
                [&a.issuer, &a.subject, &actor_key, &login_key, &data],
            )?;
        }
    }
    Ok(())
}

/// The tokens that are not revoked whose `column` is `value`.
pub(super) fn live_where(conn: &rusqlite::Connection, column: &str, value: &str) -> Result<Vec<Token>> {
    let sql = format!("SELECT data FROM tokens WHERE {column} = ?1 ORDER BY seq");
    let mut stmt = conn.prepare_cached(&sql)?;
    let texts = stmt.query_map([value], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    let tokens = texts
        .iter()
        .map(|t| serde_json::from_str::<Token>(t).map_err(|e| Error::invalid(format!("server.db: {e}"))))
        .collect::<Result<Vec<_>>>()?;
    Ok(tokens.into_iter().filter(|t| t.revoked_at.is_none()).collect())
}
