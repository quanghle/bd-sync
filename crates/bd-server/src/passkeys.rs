//! The passkeys accounts approve with on the browser approval pages, in
//! `<root>/server.db`'s `passkeys` table: one per account, registered at its
//! first approval (`insert_first`), its counter moved on by each approval
//! (`use_counter`), removed by an admin (`remove`), and erased with a
//! forgotten account (`server_db::erase_passkeys`). Registrations and
//! removals are recorded in the audit trail by the credential id's first
//! [`PREFIX`] characters and the algorithm, never the key. `bd serve passkey
//! list|remove` is the admin's command over them (`cmd_passkey`).

use std::path::Path;

use bd_cli::app::{App, Out};
use bd_cli::cli::PasskeyCommand;
use bd_core::{Error, Result, Timestamp};
use serde_json::json;

use crate::auth::{self, Account};
use crate::server_db::{self, AuthEvent};
use crate::webauthn::Alg;

/// How many characters of a credential id (base64url) logs, events and
/// listings show.
pub const PREFIX: usize = 12;

/// The first [`PREFIX`] characters of `credential`.
pub fn prefix(credential: &str) -> &str {
    credential.char_indices().nth(PREFIX).map_or(credential, |(at, _)| &credential[..at])
}

/// A passkey as kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passkey {
    /// The credential id, base64url without padding.
    pub credential: String,
    /// The account's, as in [`crate::auth::Identity`].
    pub issuer: String,
    pub subject: String,
    /// The COSE algorithm identifier.
    pub algorithm: i64,
    /// SPKI DER.
    pub public_key: Vec<u8>,
    /// The signature counter last seen.
    pub counter: u32,
    /// Milliseconds.
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl Passkey {
    /// The first [`PREFIX`] characters of its credential id.
    pub fn prefix(&self) -> &str {
        prefix(&self.credential)
    }

    /// Its algorithm's name (`ES256`, `RS256`).
    pub fn alg_name(&self) -> &'static str {
        Alg::from_cose(self.algorithm).map_or("unknown", Alg::name)
    }
}

pub(crate) const BY_ACCOUNT: &str = "SELECT credential, issuer, subject, algorithm, public_key, counter, created_at, \
                                     last_used_at FROM passkeys WHERE issuer = ?1 AND subject = ?2 ORDER BY seq";
pub(crate) const BY_CREDENTIAL: &str = "SELECT credential, issuer, subject, algorithm, public_key, counter, \
                                        created_at, last_used_at FROM passkeys WHERE credential = ?1";
pub(crate) const ACCOUNT_EXISTS: &str = "SELECT 1 FROM accounts WHERE issuer = ?1 AND subject = ?2";
pub(crate) const ENROLLED: &str = "SELECT 1 FROM passkeys WHERE issuer = ?1 AND subject = ?2 LIMIT 1";
pub(crate) const TAKEN: &str = "SELECT 1 FROM passkeys WHERE credential = ?1";
pub(crate) const INSERT: &str = "INSERT INTO passkeys (credential, issuer, subject, actor_key, algorithm, public_key, \
                                 counter, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
pub(crate) const USE_COUNTER: &str =
    "UPDATE passkeys SET counter = ?1, last_used_at = ?2 WHERE credential = ?3 AND counter = ?4";
pub(crate) const DELETE: &str = "DELETE FROM passkeys WHERE credential = ?1";

fn select(tx: &rusqlite::Transaction, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<Passkey>> {
    let mut stmt = tx.prepare_cached(sql)?;
    let rows = stmt.query_map(args, |r| {
        Ok(Passkey {
            credential: r.get(0)?,
            issuer: r.get(1)?,
            subject: r.get(2)?,
            algorithm: r.get(3)?,
            public_key: r.get(4)?,
            counter: r.get(5)?,
            created_at: r.get(6)?,
            last_used_at: r.get(7)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The passkeys of the account with this issuer and subject, oldest first
/// (none if there is no `server.db`).
pub fn for_account(root: &Path, issuer: &str, subject: &str) -> Result<Vec<Passkey>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(Vec::new()) };
    server_db::read(root, &mut conn, |tx| select(tx, BY_ACCOUNT, &[&issuer, &subject]))
}

/// The passkey with this credential id (base64url), if any.
pub fn by_credential(root: &Path, credential: &str) -> Result<Option<Passkey>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(None) };
    server_db::read(root, &mut conn, |tx| Ok(select(tx, BY_CREDENTIAL, &[&credential])?.into_iter().next()))
}

/// A passkey to register.
#[derive(Clone, Debug)]
pub struct NewRow<'a> {
    /// The credential id, base64url without padding.
    pub credential: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub provider: &'a str,
    /// The account's actor.
    pub actor: &'a str,
    pub alg: Alg,
    /// SPKI DER.
    pub public_key: &'a [u8],
    pub counter: u32,
}

/// What [`insert_first`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted {
    Inserted,
    /// The account has a passkey already.
    AlreadyEnrolled,
    /// Another passkey has this credential id.
    CredentialTaken,
    /// The account is not there (any more).
    NoAccount,
}

/// Register `row` as its account's first passkey, with a
/// `passkey_registered` event, in one transaction: only if the account is
/// there, has no passkey yet, and no passkey has its credential id.
pub fn insert_first(root: &Path, row: &NewRow) -> Result<Inserted> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let exists =
            |sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<bool> { Ok(tx.prepare_cached(sql)?.exists(args)?) };
        if !exists(ACCOUNT_EXISTS, &[&row.issuer, &row.subject])? {
            return Ok(Inserted::NoAccount);
        }
        if exists(ENROLLED, &[&row.issuer, &row.subject])? {
            return Ok(Inserted::AlreadyEnrolled);
        }
        if exists(TAKEN, &[&row.credential])? {
            return Ok(Inserted::CredentialTaken);
        }
        tx.prepare_cached(INSERT)?.execute(rusqlite::params![
            row.credential,
            row.issuer,
            row.subject,
            server_db::key(row.actor),
            row.alg.cose(),
            row.public_key,
            row.counter,
            Timestamp::now().millis(),
        ])?;
        server_db::record(
            tx,
            &AuthEvent {
                kind: "passkey_registered",
                actor: Some(row.actor.to_string()),
                provider: Some(row.provider.to_string()),
                issuer: Some(row.issuer.to_string()),
                subject: Some(row.subject.to_string()),
                detail: Some(format!(
                    "credential {} ({}), registered at a browser approval",
                    prefix(row.credential),
                    row.alg.name()
                )),
                ..AuthEvent::default()
            },
        )?;
        server_db::prune_events(tx)?;
        Ok(Inserted::Inserted)
    })
}

/// Move the counter of the passkey with this credential id from `read` to
/// `new` and note it used now: whether it still was at `read` (if not,
/// another approval used it meanwhile, and nothing changed).
pub fn use_counter(root: &Path, credential: &str, read: u32, new: u32) -> Result<bool> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let changed = tx.prepare_cached(USE_COUNTER)?.execute(rusqlite::params![
            new,
            Timestamp::now().millis(),
            credential,
            read
        ])?;
        Ok(changed == 1)
    })
}

/// Remove `account`'s passkeys, for an admin: the one whose credential id
/// starts with `prefix`, or, without one, every one of them; each removal
/// recorded as a `passkey_removed` event. The passkeys removed. Refused,
/// with nothing removed, when there is none, or when `prefix` names several.
pub fn remove(root: &Path, account: &Account, prefix: Option<&str>) -> Result<Vec<Passkey>> {
    let none = || Error::not_found("passkey", prefix.unwrap_or(&account.actor));
    let Some(mut conn) = server_db::open_existing(root)? else { return Err(none()) };
    server_db::write(root, &mut conn, |tx| {
        let mut chosen = select(tx, BY_ACCOUNT, &[&account.issuer, &account.subject])?;
        if let Some(prefix) = prefix {
            chosen.retain(|p| p.credential.starts_with(prefix));
        }
        if chosen.is_empty() {
            return Err(none());
        }
        if let (Some(prefix), several @ 2..) = (prefix, chosen.len()) {
            return Err(Error::invalid(format!(
                "{prefix} names {several} passkeys of {}: give a longer prefix",
                account.actor
            )));
        }
        for passkey in &chosen {
            tx.prepare_cached(DELETE)?.execute([&passkey.credential])?;
            server_db::record(
                tx,
                &AuthEvent {
                    kind: "passkey_removed",
                    actor: Some(account.actor.clone()),
                    provider: Some(account.provider.clone()),
                    issuer: Some(account.issuer.clone()),
                    subject: Some(account.subject.clone()),
                    detail: Some(format!(
                        "credential {} ({}), removed by an admin",
                        passkey.prefix(),
                        passkey.alg_name()
                    )),
                    ..AuthEvent::default()
                },
            )?;
        }
        server_db::prune_events(tx)?;
        Ok(chosen)
    })
}

/// `bd serve passkey list|remove`: an admin's commands, on this machine.
pub fn cmd_passkey(app: &mut App, cmd: &PasskeyCommand) -> Result<()> {
    match cmd {
        PasskeyCommand::List(a) => {
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let passkeys = for_account(&root, &account.issuer, &account.subject)?;
            let views: Vec<_> = passkeys.iter().map(view).collect();
            let mut out = Out::new(json!(views));
            if passkeys.is_empty() {
                out = out.line(format!("No passkeys for {}: its next browser approval registers one.", account.actor));
            }
            for p in &passkeys {
                let last = p.last_used_at.map_or_else(|| "never".to_string(), |t| time(t).to_string());
                out = out
                    .line(format!(
                        "{}  {}  created {}, last used {last}, counter {}",
                        p.prefix(),
                        p.alg_name(),
                        time(p.created_at),
                        p.counter
                    ))
                    .id(p.prefix().to_string());
            }
            app.print(out);
        }
        PasskeyCommand::Remove(a) => {
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let removed = remove(&root, &account, a.credential.as_deref().map(str::trim))?;
            let prefixes: Vec<&str> = removed.iter().map(Passkey::prefix).collect();
            let out = Out::new(json!({ "account": account.actor, "removed": prefixes })).line(format!(
                "✓ Removed {} passkey{} of {}: its next browser approval registers a new one",
                removed.len(),
                if removed.len() == 1 { "" } else { "s" },
                account.actor
            ));
            app.print(prefixes.iter().fold(out, |out, p| out.id(p.to_string())));
        }
    }
    Ok(())
}

fn time(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

/// What `bd serve passkey list --json` shows of a passkey: never its key or
/// its whole credential id.
fn view(p: &Passkey) -> serde_json::Value {
    json!({
        "credential_prefix": p.prefix(),
        "algorithm": p.alg_name(),
        "created_at": time(p.created_at).to_rfc3339(),
        "last_used_at": p.last_used_at.map(|t| time(t).to_rfc3339()),
        "counter": p.counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{self, Identity};
    use crate::webauthn::testkit::SoftKey;
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    fn user(login: &str, subject: &str) -> Identity {
        Identity {
            provider: "corp".into(),
            issuer: "https://idp.example".into(),
            subject: subject.into(),
            login: login.into(),
        }
    }

    /// `user`'s account, bound as a browser sign-in binds it.
    fn account(root: &Path, user: &Identity) -> Account {
        let actor = auth::bind_account(root, user, false, "test").unwrap();
        let now = Timestamp::now();
        Account {
            provider: user.provider.clone(),
            issuer: user.issuer.clone(),
            subject: user.subject.clone(),
            actor,
            login: user.login.clone(),
            first_seen: now,
            last_seen: now,
            name: None,
        }
    }

    fn row<'a>(account: &'a Account, credential: &'a str, key: &'a [u8], alg: Alg) -> NewRow<'a> {
        NewRow {
            credential,
            issuer: &account.issuer,
            subject: &account.subject,
            provider: &account.provider,
            actor: &account.actor,
            alg,
            public_key: key,
            counter: 0,
        }
    }

    fn kept(root: &Path, kind: &str) -> Vec<AuthEvent> {
        server_db::events(root, 0, None, &[kind.to_string()], 100).unwrap().into_iter().map(|e| e.event).collect()
    }

    /// Put a passkey in as it is kept, beside insert_first's one per account.
    fn put(root: &Path, account: &Account, credential: &str, alg: Alg, key: &[u8]) {
        let conn = server_db::open(root).unwrap();
        conn.execute(
            INSERT,
            rusqlite::params![
                credential,
                account.issuer,
                account.subject,
                server_db::key(&account.actor),
                alg.cose(),
                key,
                0,
                1
            ],
        )
        .unwrap();
    }

    #[test]
    fn the_first_passkey_is_registered_once_for_an_account_that_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let (alice, bob) = (account(root, &user("alice", "s1")), account(root, &user("bob", "s2")));
        let key = SoftKey::es256().spki();
        assert!(for_account(root, &alice.issuer, &alice.subject).unwrap().is_empty());
        assert_eq!(insert_first(root, &row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256)).unwrap(), Inserted::Inserted);
        let kept_now = for_account(root, &alice.issuer, &alice.subject).unwrap();
        assert_eq!(kept_now.len(), 1);
        let p = &kept_now[0];
        assert_eq!((p.prefix(), p.alg_name(), p.counter, p.last_used_at), ("AAAAAAAAAAAA", "ES256", 0, None));
        assert_eq!(p.public_key, key);
        assert_eq!(by_credential(root, "AAAAAAAAAAAAx1").unwrap().as_ref(), Some(p));
        assert_eq!(by_credential(root, "AAAAAAAAAAAAx2").unwrap(), None);
        assert_eq!(
            insert_first(root, &row(&alice, "BBBBBBBBBBBBx1", &key, Alg::Es256)).unwrap(),
            Inserted::AlreadyEnrolled
        );
        assert_eq!(
            insert_first(root, &row(&bob, "AAAAAAAAAAAAx1", &key, Alg::Es256)).unwrap(),
            Inserted::CredentialTaken,
            "another account's credential id"
        );
        let gone = Account { subject: "s9".into(), ..bob.clone() };
        assert_eq!(insert_first(root, &row(&gone, "CCCCCCCCCCCCx1", &key, Alg::Es256)).unwrap(), Inserted::NoAccount);
        assert!(for_account(root, &bob.issuer, &bob.subject).unwrap().is_empty());
        assert!(for_account(root, &gone.issuer, &gone.subject).unwrap().is_empty());
        assert_eq!(kept(root, "passkey_registered").len(), 1, "only the one registered");
    }

    #[test]
    fn reads_of_a_root_without_server_db_find_nothing_and_create_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(for_account(dir.path(), "i", "s").unwrap().is_empty());
        assert_eq!(by_credential(dir.path(), "x").unwrap(), None);
        assert!(!server_db::path(dir.path()).exists());
    }

    #[test]
    fn the_counter_moves_only_from_the_value_read() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = account(root, &user("alice", "s1"));
        insert_first(root, &row(&alice, "AAAAAAAAAAAAx1", b"key", Alg::Es256)).unwrap();
        assert!(use_counter(root, "AAAAAAAAAAAAx1", 0, 7).unwrap());
        let p = by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap();
        assert_eq!(p.counter, 7);
        assert!(p.last_used_at.is_some());
        assert!(!use_counter(root, "AAAAAAAAAAAAx1", 0, 8).unwrap(), "read before the change above");
        assert_eq!(by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap().counter, 7);
        assert!(!use_counter(root, "unknown", 7, 8).unwrap());
    }

    #[test]
    fn an_admin_removes_one_passkey_by_prefix_or_all_of_them() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = account(root, &user("alice", "s1"));
        let bob = account(root, &user("bob", "s2"));
        let (es, rs) = (SoftKey::es256().spki(), SoftKey::rs256().spki());
        put(root, &alice, "AAAAAAAAAAAAx1", Alg::Es256, &es);
        put(root, &alice, "AAAAAAAAAAAAy2", Alg::Rs256, &rs);
        put(root, &alice, "AAAAAAAAAAAAy3", Alg::Es256, &es);
        put(root, &bob, "AAAAAAAAAAAAz9", Alg::Es256, &es);
        let left = |a: &Account| -> Vec<String> {
            for_account(root, &a.issuer, &a.subject).unwrap().into_iter().map(|p| p.credential).collect()
        };

        let e = remove(root, &alice, Some("AAAAAAAAAAAA")).unwrap_err();
        assert!(matches!(e, Error::Invalid(_)) && e.to_string().contains("give a longer prefix"), "{e}");
        assert!(e.to_string().contains("3 passkeys"), "{e}");
        assert_eq!(left(&alice).len(), 3, "nothing removed");
        let e = remove(root, &alice, Some("AAAAAAAAAAAAz")).unwrap_err();
        assert!(matches!(e, Error::NotFound { .. }), "bob's is not alice's: {e}");

        let removed = remove(root, &alice, Some("AAAAAAAAAAAAy2")).unwrap();
        assert_eq!(removed.iter().map(|p| p.credential.as_str()).collect::<Vec<_>>(), ["AAAAAAAAAAAAy2"]);
        assert_eq!(left(&alice), ["AAAAAAAAAAAAx1", "AAAAAAAAAAAAy3"]);

        let removed = remove(root, &alice, None).unwrap();
        assert_eq!(removed.len(), 2, "every one of them, however many");
        assert!(left(&alice).is_empty());
        assert_eq!(left(&bob), ["AAAAAAAAAAAAz9"], "another account's stays");
        let e = remove(root, &alice, None).unwrap_err();
        assert!(matches!(e, Error::NotFound { .. }) && e.to_string().contains(&alice.actor), "{e}");

        let events = kept(root, "passkey_removed");
        assert_eq!(events.len(), 3);
        for event in &events {
            assert_eq!(event.actor.as_deref(), Some(alice.actor.as_str()));
            assert_eq!(
                (event.provider.as_deref(), event.issuer.as_deref(), event.subject.as_deref()),
                (Some("corp"), Some("https://idp.example"), Some("s1"))
            );
        }
        let details: Vec<&str> = events.iter().map(|e| e.detail.as_deref().unwrap()).collect();
        assert_eq!(
            details,
            [
                "credential AAAAAAAAAAAA (RS256), removed by an admin",
                "credential AAAAAAAAAAAA (ES256), removed by an admin",
                "credential AAAAAAAAAAAA (ES256), removed by an admin",
            ]
        );
    }

    #[test]
    fn events_name_the_prefix_and_algorithm_never_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (n, key) in [SoftKey::es256(), SoftKey::rs256()].into_iter().enumerate() {
            let a = account(root, &user(&format!("u{n}"), &format!("s{n}")));
            let credential = URL_SAFE_NO_PAD.encode(&key.credential);
            let spki = key.spki();
            assert_eq!(insert_first(root, &row(&a, &credential, &spki, key.alg())).unwrap(), Inserted::Inserted);
            remove(root, &a, Some(prefix(&credential))).unwrap();
            let events = server_db::events(root, 0, Some(&a.actor), &[], 100).unwrap();
            let details: Vec<(&str, &str)> =
                events.iter().filter_map(|e| Some((e.event.kind, e.event.detail.as_deref()?))).collect();
            let (registered, removed) = (details[details.len() - 2], details[details.len() - 1]);
            assert_eq!((registered.0, removed.0), ("passkey_registered", "passkey_removed"));
            for (_, detail) in [registered, removed] {
                assert!(detail.contains(prefix(&credential)) && detail.contains(key.alg().name()), "{detail}");
                assert!(!detail.contains(&credential), "{detail}");
                for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                    let encoded = engine.encode(&spki);
                    let tail = &encoded[encoded.len() - 16..];
                    assert!(!detail.contains(&encoded) && !detail.contains(tail), "{detail}");
                }
            }
        }
    }
}
