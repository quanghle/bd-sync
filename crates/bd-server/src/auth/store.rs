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

impl TokenFile {
    /// Revoke the tokens `pick` selects that are not revoked yet, with
    /// `why` for the audit trail: the names of those revoked now.
    pub(super) fn revoke(&mut self, why: &str, pick: impl Fn(&Token) -> bool) -> Vec<String> {
        let now = Timestamp::now().to_rfc3339();
        let mut revoked = Vec::new();
        for t in self.tokens.iter_mut().filter(|t| t.revoked_at.is_none() && pick(t)) {
            t.revoked_at = Some(now.clone());
            revoked.push(t.name.clone());
            self.events.push(t.event("revoked", Some(why)));
        }
        revoked
    }
}

/// A record as `server.db` keeps it (`what` it is, for the error).
fn parse<T: serde::de::DeserializeOwned>(what: &str, data: &str) -> Result<T> {
    serde_json::from_str(data).map_err(|e| Error::invalid(format!("server.db: {what}: {e}")))
}

/// The records (`what` they are) of the `data` column `sql` selects, with `args`.
fn records<T: serde::de::DeserializeOwned>(
    conn: &rusqlite::Connection,
    what: &str,
    sql: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<T>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let texts = stmt.query_map(args, |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
    texts.iter().map(|t| parse(what, t)).collect()
}

fn load(conn: &rusqlite::Connection) -> Result<TokenFile> {
    Ok(TokenFile {
        tokens: records(conn, "a token", "SELECT data FROM tokens ORDER BY seq", &[])?,
        accounts: records(conn, "an account", "SELECT data FROM accounts ORDER BY seq", &[])?,
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
/// At most [`server_db::PRUNE_BATCH`] each write, so that one write never
/// pays for a long backlog while others wait; the next writes go on.
pub(super) fn prune(tx: &rusqlite::Transaction) -> Result<()> {
    tx.execute(
        "DELETE FROM tokens WHERE id IN (SELECT id FROM tokens WHERE ended_at <= ?1 LIMIT ?2)",
        rusqlite::params![Timestamp::now().minus(PRUNE_AFTER).millis(), server_db::PRUNE_BATCH],
    )?;
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
fn load_scope(conn: &rusqlite::Connection, scope: &Scope) -> Result<TokenFile> {
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
    // By key, each once: the actor of the tokens, the account and the user are usually one and the same.
    let mut actors: std::collections::BTreeSet<String> = scope.actors.iter().map(|a| server_db::key(a)).collect();
    for id in scope.ids {
        add(&mut tokens, "SELECT seq, data FROM tokens WHERE id = ?1", &[id])?;
    }
    for data in tokens.values() {
        actors.insert(server_db::key(&actor_of(data)?));
    }
    // The accounts named by issuer and subject, and the actors they are bound to.
    let named = scope.account.into_iter().chain(scope.user.map(|u| (u.issuer.as_str(), u.subject.as_str())));
    for (issuer, subject) in named {
        add(&mut accounts, "SELECT seq, data FROM accounts WHERE issuer = ?1 AND subject = ?2", &[&issuer, &subject])?;
    }
    for data in accounts.values() {
        actors.insert(server_db::key(&actor_of(data)?));
    }
    if let Some(user) = scope.user {
        actors.insert(server_db::key(&user.actor()));
        related(&mut accounts, "accounts", "login_key", &server_db::key(&user.login))?;
    }
    // Every key related to one of them, and every range of descendants, asked once.
    let (mut exact, mut ranges) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
    for key in &actors {
        let (keys, range) = server_db::related_keys(key);
        exact.extend(keys);
        ranges.insert(range);
    }
    for (table, into) in [("accounts", &mut accounts), ("tokens", &mut tokens)] {
        for k in &exact {
            add(into, &format!("SELECT seq, data FROM {table} WHERE actor_key = ?1"), &[k])?;
        }
        for (low, high) in &ranges {
            add(into, &format!("SELECT seq, data FROM {table} WHERE actor_key > ?1 AND actor_key < ?2"), &[low, high])?;
        }
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
    server_db::sync_rows(
        &before.tokens,
        &after.tokens,
        |t| t.id.clone(),
        |id| {
            tx.execute("DELETE FROM tokens WHERE id = ?1", [id])?;
            Ok(())
        },
        |was, t, data| {
            let columns = |t: &Token, data: Option<&str>| -> Result<server_db::Columns> {
                use rusqlite::types::Value as V;
                let family = t.refresh.as_ref().map(|r| r.family.to_ascii_lowercase());
                let (actor_key, name, ended_at) = server_db::token_keys(&serde_json::to_value(t)?);
                let mut c: server_db::Columns = vec![
                    ("sha256", V::Text(t.sha256.clone())),
                    ("family", family.map_or(V::Null, V::Text)),
                    ("actor_key", V::Text(actor_key)),
                    ("name", V::Text(name)),
                    ("ended_at", ended_at.map_or(V::Null, V::Integer)),
                ];
                c.extend(data.map(|d| ("data", V::Text(d.to_string()))));
                Ok(c)
            };
            let was = was.map(|w| columns(w, None)).transpose()?;
            let keys = vec![("id", rusqlite::types::Value::Text(t.id.clone()))];
            server_db::put_row(tx, "tokens", &keys, &columns(t, Some(data))?, was.as_ref())
        },
    )?;
    server_db::sync_rows(
        &before.accounts,
        &after.accounts,
        |a| (a.issuer.clone(), a.subject.clone()),
        |(issuer, subject)| {
            tx.execute("DELETE FROM accounts WHERE issuer = ?1 AND subject = ?2", [issuer, subject])?;
            Ok(())
        },
        |was, a, data| {
            let columns = |a: &Account, data: Option<&str>| -> Result<server_db::Columns> {
                use rusqlite::types::Value as V;
                let (actor_key, login_key) = server_db::account_keys(&serde_json::to_value(a)?);
                let mut c: server_db::Columns =
                    vec![("actor_key", V::Text(actor_key)), ("login_key", V::Text(login_key))];
                c.extend(data.map(|d| ("data", V::Text(d.to_string()))));
                Ok(c)
            };
            let was = was.map(|w| columns(w, None)).transpose()?;
            let keys = vec![
                ("issuer", rusqlite::types::Value::Text(a.issuer.clone())),
                ("subject", rusqlite::types::Value::Text(a.subject.clone())),
            ];
            server_db::put_row(tx, "accounts", &keys, &columns(a, Some(data))?, was.as_ref())
        },
    )
}

/// The tokens that are not revoked whose `column` is `value`.
pub(super) fn live_where(conn: &rusqlite::Connection, column: &str, value: &str) -> Result<Vec<Token>> {
    let sql = format!("SELECT data FROM tokens WHERE {column} = ?1 ORDER BY seq");
    let tokens: Vec<Token> = records(conn, "a token", &sql, &[&value])?;
    Ok(tokens.into_iter().filter(|t| t.revoked_at.is_none()).collect())
}
