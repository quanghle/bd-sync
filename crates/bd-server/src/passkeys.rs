//! The passkeys accounts approve with on the browser approval pages, in
//! `<root>/server.db`'s `passkeys` table: several per account, at most
//! [`MAX_PER_ACCOUNT`]. The first is registered at the account's first
//! approval (`insert_first`); more are added at an approval vouched for by a
//! verified assertion of one the account has (`add`), or, for someone without
//! one at hand, under an allowance (`insert_allowed`): a window of at most
//! [`ALLOWANCE_MAX`] an admin opens on the server host (`grant`, ended early
//! by `cancel`), one per account, in the `passkey_allowances` table, spent by
//! the one registration it lets in. Each approval moves its passkey's counter
//! on (`use_counter`, or `add` for the vouching one); an admin removes them
//! (`remove`, which ends the allowance of an account it leaves with none, so
//! a live allowance always means a passkey), and they are erased with a
//! forgotten account (`server_db::erase_passkeys`,
//! `server_db::erase_allowance`). Registrations, removals and what happens to
//! allowances are recorded in the audit trail, by the credential id's first
//! [`PREFIX`] characters, the algorithm and an allowance's id, never the key.
//! `bd serve passkey list|remove|allow-add` is the admin's command over them
//! (`cmd_passkey`).

use std::path::Path;
use std::time::Duration;

use bd_cli::app::{App, Out};
use bd_cli::cli::PasskeyCommand;
use bd_cli::io;
use bd_core::{Error, Result, Timestamp};
use rusqlite::OptionalExtension;
use serde_json::json;

use crate::auth::{self, Account};
use crate::server_db::{self, AuthEvent};
use crate::webauthn::Alg;

/// The most passkeys an account may hold: an approval offers to add one only
/// below it, and [`add`] refuses past it.
pub const MAX_PER_ACCOUNT: usize = 99;

/// The longest an allowance lasts.
pub const ALLOWANCE_MAX: Duration = Duration::from_secs(3600);

/// How long an allowance lasts unless the admin says.
pub const ALLOWANCE_DEFAULT: Duration = Duration::from_secs(15 * 60);

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

/// An allowance as kept: its account's one window to register a passkey with
/// no existing one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    /// 8 random bytes in hex, not a secret: what tells this allowance from
    /// one that replaced it, for a page opened under it and in the events.
    pub id: String,
    /// Milliseconds.
    pub created_at: i64,
    pub expires_at: i64,
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
pub(crate) const COUNT_BY_ACCOUNT: &str = "SELECT COUNT(*) FROM passkeys WHERE issuer = ?1 AND subject = ?2";
pub(crate) const OWNED: &str = "SELECT 1 FROM passkeys WHERE credential = ?1 AND issuer = ?2 AND subject = ?3";
pub(crate) const USE_COUNTER_OWNED: &str = "UPDATE passkeys SET counter = ?1, last_used_at = ?2 WHERE credential = ?3 \
                                            AND issuer = ?4 AND subject = ?5 AND counter = ?6";
pub(crate) const ALLOWANCE_LIVE: &str = "SELECT id, created_at, expires_at FROM passkey_allowances WHERE issuer = ?1 \
                                         AND subject = ?2 AND expires_at > ?3";
pub(crate) const ALLOWANCE_ROW: &str =
    "SELECT id, created_at, expires_at FROM passkey_allowances WHERE issuer = ?1 AND subject = ?2";
pub(crate) const ALLOWANCE_MATCH: &str =
    "SELECT 1 FROM passkey_allowances WHERE issuer = ?1 AND subject = ?2 AND id = ?3 AND expires_at > ?4";
pub(crate) const ALLOWANCE_DELETE: &str =
    "DELETE FROM passkey_allowances WHERE issuer = ?1 AND subject = ?2 AND id = ?3";
pub(crate) const ALLOWANCE_PUT: &str = "INSERT INTO passkey_allowances (issuer, subject, id, created_at, expires_at) \
                                        VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (issuer, subject) DO UPDATE SET \
                                        id = excluded.id, created_at = excluded.created_at, \
                                        expires_at = excluded.expires_at";

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

fn allowance(tx: &rusqlite::Transaction, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Option<Allowance>> {
    let found = tx
        .prepare_cached(sql)?
        .query_row(args, |r| Ok(Allowance { id: r.get(0)?, created_at: r.get(1)?, expires_at: r.get(2)? }));
    Ok(found.optional()?)
}

fn count(tx: &rusqlite::Transaction, issuer: &str, subject: &str) -> Result<usize> {
    let count: i64 = tx.prepare_cached(COUNT_BY_ACCOUNT)?.query_row([issuer, subject], |r| r.get(0))?;
    Ok(usize::try_from(count).unwrap_or(0))
}

/// `kind`, of `account`, for the audit trail.
fn event_of(kind: &'static str, account: &Account, detail: String) -> AuthEvent {
    AuthEvent {
        kind,
        actor: Some(account.actor.clone()),
        provider: Some(account.provider.clone()),
        issuer: Some(account.issuer.clone()),
        subject: Some(account.subject.clone()),
        detail: Some(detail),
        ..AuthEvent::default()
    }
}

/// The passkeys of the account with this issuer and subject, oldest first
/// (none if there is no `server.db`).
pub fn for_account(root: &Path, issuer: &str, subject: &str) -> Result<Vec<Passkey>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(Vec::new()) };
    server_db::read(root, &mut conn, |tx| select(tx, BY_ACCOUNT, &[&issuer, &subject]))
}

/// The passkeys of the account with this issuer and subject, oldest first,
/// and its live allowance if it has one, as of one moment (nothing if there
/// is no `server.db`).
pub fn account_state(root: &Path, issuer: &str, subject: &str) -> Result<(Vec<Passkey>, Option<Allowance>)> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok((Vec::new(), None)) };
    server_db::read(root, &mut conn, |tx| {
        let passkeys = select(tx, BY_ACCOUNT, &[&issuer, &subject])?;
        let live = allowance(tx, ALLOWANCE_LIVE, &[&issuer, &subject, &Timestamp::now().millis()])?;
        Ok((passkeys, live))
    })
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
        server_db::prune_allowances(tx)?;
        Ok(Inserted::Inserted)
    })
}

/// What [`add`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Added,
    /// The account is not there (any more).
    NoAccount,
    /// The account has [`MAX_PER_ACCOUNT`] passkeys already.
    LimitReached,
    /// Another passkey has the new credential id.
    CredentialTaken,
    /// The vouching passkey is no longer the account's, or its counter moved
    /// since it was read: another approval or an admin changed it meanwhile.
    Raced,
}

/// Add `row` to its account's passkeys at an approval vouched for by the
/// account's passkey `asserted`, whose counter was `read` and moves to
/// `new`, in one transaction: only if the account is there, `asserted` is
/// still one of its passkeys, it has fewer than [`MAX_PER_ACCOUNT`], no
/// passkey has the new credential id, and `asserted`'s counter is still at
/// `read`. Every check runs before the first change, so a refusal changes
/// nothing; otherwise the counter moves, the row goes in, and a
/// `passkey_registered` event names both credentials' prefixes.
pub fn add(root: &Path, row: &NewRow, asserted: &str, read: u32, new: u32) -> Result<Added> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let exists =
            |sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<bool> { Ok(tx.prepare_cached(sql)?.exists(args)?) };
        if !exists(ACCOUNT_EXISTS, &[&row.issuer, &row.subject])? {
            return Ok(Added::NoAccount);
        }
        if !exists(OWNED, &[&asserted, &row.issuer, &row.subject])? {
            return Ok(Added::Raced);
        }
        let count: i64 =
            tx.prepare_cached(COUNT_BY_ACCOUNT)?.query_row(rusqlite::params![row.issuer, row.subject], |r| r.get(0))?;
        if count >= MAX_PER_ACCOUNT as i64 {
            return Ok(Added::LimitReached);
        }
        if exists(TAKEN, &[&row.credential])? {
            return Ok(Added::CredentialTaken);
        }
        let moved = tx.prepare_cached(USE_COUNTER_OWNED)?.execute(rusqlite::params![
            new,
            Timestamp::now().millis(),
            asserted,
            row.issuer,
            row.subject,
            read
        ])?;
        if moved != 1 {
            return Ok(Added::Raced);
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
                    "credential {} ({}), added at a browser approval with credential {}",
                    prefix(row.credential),
                    row.alg.name(),
                    prefix(asserted)
                )),
                ..AuthEvent::default()
            },
        )?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        Ok(Added::Added)
    })
}

/// What [`grant`] opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    /// The allowance's id.
    pub id: String,
    /// Milliseconds.
    pub expires_at: i64,
    /// The live allowance it took the place of, if any.
    pub replaced: Option<String>,
}

/// Allow `account` to register one passkey with no existing one for
/// `length` from now, in place of any allowance it had, with a
/// `passkey_add_allowed` event, in one transaction: only if the account is
/// there and has a passkey, and fewer than [`MAX_PER_ACCOUNT`]. Refused, with
/// nothing changed, otherwise: without a `server.db` too, which is never
/// created, so that a mistaken `--root` is not left with one.
pub fn grant(root: &Path, account: &Account, length: Duration) -> Result<Granted> {
    let none = || Error::not_found("account", account.actor.as_str());
    let Some(mut conn) = server_db::open_existing(root)? else { return Err(none()) };
    server_db::write(root, &mut conn, |tx| {
        if !tx.prepare_cached(ACCOUNT_EXISTS)?.exists([&account.issuer, &account.subject])? {
            return Err(none());
        }
        let passkeys = count(tx, &account.issuer, &account.subject)?;
        if passkeys == 0 {
            return Err(Error::invalid(format!(
                "{} has no passkeys: its next browser approval registers one anyway",
                account.actor
            )));
        }
        if passkeys >= MAX_PER_ACCOUNT {
            return Err(Error::invalid(format!(
                "{} has {passkeys} passkeys, the most an account may have: remove one first",
                account.actor
            )));
        }
        let now = Timestamp::now();
        let earlier = allowance(tx, ALLOWANCE_ROW, &[&account.issuer, &account.subject])?;
        let replaced = earlier.filter(|a| a.expires_at > now.millis()).map(|a| a.id);
        let id = auth::random_hex(8)?;
        let expires_at = now.plus(length).millis();
        tx.prepare_cached(ALLOWANCE_PUT)?.execute(rusqlite::params![
            account.issuer,
            account.subject,
            id,
            now.millis(),
            expires_at
        ])?;
        let mut detail = format!("allowance {id}, until {}, by an admin", time(expires_at).to_rfc3339());
        if let Some(replaced) = &replaced {
            detail.push_str(&format!(", replacing allowance {replaced}"));
        }
        server_db::record(tx, &event_of("passkey_add_allowed", account, detail))?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        Ok(Granted { id, expires_at, replaced })
    })
}

/// End `live`, `account`'s allowance, with a `passkey_add_cancelled` event
/// saying `how`.
fn end_allowance(tx: &rusqlite::Transaction, account: &Account, live: &Allowance, how: &str) -> Result<()> {
    tx.prepare_cached(ALLOWANCE_DELETE)?.execute([&account.issuer, &account.subject, &live.id])?;
    let detail = format!("allowance {}, until {}, {how}", live.id, time(live.expires_at).to_rfc3339());
    server_db::record(tx, &event_of("passkey_add_cancelled", account, detail))
}

/// End `account`'s live allowance, for an admin: whether it had one. With
/// none, nothing is written, an allowance that ran out left as it is.
pub fn cancel(root: &Path, account: &Account) -> Result<bool> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(false) };
    server_db::write(root, &mut conn, |tx| {
        let now = Timestamp::now().millis();
        let Some(live) = allowance(tx, ALLOWANCE_LIVE, &[&account.issuer, &account.subject, &now])? else {
            return Ok(false);
        };
        end_allowance(tx, account, &live, "cancelled by an admin")?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        Ok(true)
    })
}

/// What [`insert_allowed`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowedAdd {
    Added,
    /// The account is not there (any more).
    NoAccount,
    /// The allowance is not live any more: spent, cancelled, replaced, or
    /// past its expiry.
    Ended,
    /// The account has [`MAX_PER_ACCOUNT`] passkeys already.
    LimitReached,
    /// Another passkey has the new credential id.
    CredentialTaken,
}

/// Register `row` under its account's allowance `allowance_id`, the very one
/// its page was opened under, in one transaction: only if the account is
/// there, that allowance is live and the account's, it has fewer than
/// [`MAX_PER_ACCOUNT`] passkeys and no passkey has the new credential id.
/// Every check runs before the first change, so a refusal changes nothing;
/// otherwise the allowance goes, the row goes in, and a `passkey_registered`
/// event names the allowance. Writers run one at a time, so of several
/// registrations under one allowance one gets in and the rest find it ended.
pub fn insert_allowed(root: &Path, row: &NewRow, allowance_id: &str) -> Result<AllowedAdd> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let exists =
            |sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<bool> { Ok(tx.prepare_cached(sql)?.exists(args)?) };
        if !exists(ACCOUNT_EXISTS, &[&row.issuer, &row.subject])? {
            return Ok(AllowedAdd::NoAccount);
        }
        let now = Timestamp::now().millis();
        if !exists(ALLOWANCE_MATCH, &[&row.issuer, &row.subject, &allowance_id, &now])? {
            return Ok(AllowedAdd::Ended);
        }
        if count(tx, row.issuer, row.subject)? >= MAX_PER_ACCOUNT {
            return Ok(AllowedAdd::LimitReached);
        }
        if exists(TAKEN, &[&row.credential])? {
            return Ok(AllowedAdd::CredentialTaken);
        }
        if tx.prepare_cached(ALLOWANCE_DELETE)?.execute([row.issuer, row.subject, allowance_id])? != 1 {
            return Ok(AllowedAdd::Ended);
        }
        tx.prepare_cached(INSERT)?.execute(rusqlite::params![
            row.credential,
            row.issuer,
            row.subject,
            server_db::key(row.actor),
            row.alg.cose(),
            row.public_key,
            row.counter,
            now,
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
                    "credential {} ({}), registered at a browser approval under allowance {allowance_id}",
                    prefix(row.credential),
                    row.alg.name()
                )),
                ..AuthEvent::default()
            },
        )?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        Ok(AllowedAdd::Added)
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
/// recorded as a `passkey_removed` event. Leaving it with none ends its live
/// allowance too, in the same transaction, so that no allowance outlives the
/// account's last passkey. The passkeys removed. Refused, with nothing
/// removed, when there is none, or when `prefix` names several.
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
        if count(tx, &account.issuer, &account.subject)? == 0 {
            let now = Timestamp::now().millis();
            if let Some(live) = allowance(tx, ALLOWANCE_LIVE, &[&account.issuer, &account.subject, &now])? {
                end_allowance(tx, account, &live, "ended: the account's last passkey was removed")?;
            }
        }
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        Ok(chosen)
    })
}

/// How long the allowance `--for` asks for lasts: refused, before anything
/// else is looked at, unless it is more than nothing and at most
/// [`ALLOWANCE_MAX`].
fn allowance_length(asked: Option<&str>) -> Result<Duration> {
    let Some(asked) = asked else { return Ok(ALLOWANCE_DEFAULT) };
    let length = bd_core::time::parse_duration(asked)?;
    if length.is_zero() || length > ALLOWANCE_MAX {
        return Err(Error::invalid("--for must be more than zero and at most 1h"));
    }
    Ok(length)
}

/// `bd serve passkey list|remove|allow-add`: an admin's commands, on this
/// machine.
pub fn cmd_passkey(app: &mut App, cmd: &PasskeyCommand) -> Result<()> {
    match cmd {
        PasskeyCommand::List(a) => {
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let (passkeys, allowance) = account_state(&root, &account.issuer, &account.subject)?;
            let until = allowance.map(|a| time(a.expires_at).to_rfc3339());
            let views: Vec<_> = passkeys
                .iter()
                .map(|p| {
                    let mut row = view(p);
                    if let Some(until) = &until {
                        row["add_allowed_until"] = json!(until);
                    }
                    row
                })
                .collect();
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
            if let Some(until) = until {
                out = out
                    .line(format!("Add allowed: one passkey may be registered without an existing one until {until}"));
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
        PasskeyCommand::AllowAdd(a) => {
            let length = if a.cancel { None } else { Some(allowance_length(a.for_.as_deref())?) };
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let who = io::printable(&account.actor);
            app.print(match length {
                Some(length) => {
                    let granted = grant(&root, &account, length)?;
                    let until = time(granted.expires_at).to_rfc3339();
                    let replacing = if granted.replaced.is_some() { ", replacing the one before" } else { "" };
                    Out::new(json!({
                        "account": account.actor,
                        "expires_at": until,
                        "replaced": granted.replaced.is_some(),
                    }))
                    .line(format!("✓ {who} may register one passkey without an existing one until {until}{replacing}"))
                }
                None => {
                    let cancelled = cancel(&root, &account)?;
                    Out::new(json!({ "account": account.actor, "cancelled": cancelled })).line(if cancelled {
                        format!("✓ Cancelled the allowance of {who}")
                    } else {
                        format!("{who} has no allowance to cancel")
                    })
                }
            });
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

    /// Put a passkey in as it is kept, without insert_first's or add's checks
    /// and event.
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

    #[test]
    fn adding_a_passkey_moves_the_vouching_counter_and_records_both_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = account(root, &user("alice", "s1"));
        let (first, second) = (SoftKey::es256(), SoftKey::rs256());
        let (asserted, added) = (URL_SAFE_NO_PAD.encode(&first.credential), URL_SAFE_NO_PAD.encode(&second.credential));
        let (first_key, second_key) = (first.spki(), second.spki());
        assert_eq!(insert_first(root, &row(&alice, &asserted, &first_key, Alg::Es256)).unwrap(), Inserted::Inserted);
        let before = kept(root, "passkey_registered").len();

        let new = NewRow { counter: 3, ..row(&alice, &added, &second_key, second.alg()) };
        assert_eq!(add(root, &new, &asserted, 0, 5).unwrap(), Added::Added);

        let now = for_account(root, &alice.issuer, &alice.subject).unwrap();
        let credentials: Vec<&str> = now.iter().map(|p| p.credential.as_str()).collect();
        assert_eq!(credentials, [asserted.as_str(), added.as_str()], "in the order they came");
        assert_eq!((now[0].counter, now[0].last_used_at.is_some()), (5, true), "the vouching one moved on");
        assert_eq!((now[1].counter, now[1].last_used_at, now[1].alg_name()), (3, None, "RS256"));
        assert_eq!(now[1].public_key, second_key);

        let events = kept(root, "passkey_registered");
        assert_eq!(events.len(), before + 1);
        let event = events.iter().find(|e| e.detail.as_deref().is_some_and(|d| d.contains("added"))).unwrap();
        assert_eq!(event.actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (event.provider.as_deref(), event.issuer.as_deref(), event.subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        let detail = event.detail.as_deref().unwrap();
        assert_eq!(
            detail,
            format!(
                "credential {} (RS256), added at a browser approval with credential {}",
                prefix(&added),
                prefix(&asserted)
            )
        );
        assert!(!detail.contains(&added) && !detail.contains(&asserted), "{detail}");
        for spki in [&first_key, &second_key] {
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                let encoded = engine.encode(spki);
                let tail = &encoded[encoded.len() - 16..];
                assert!(!detail.contains(&encoded) && !detail.contains(tail), "{detail}");
            }
        }
    }

    /// A passkey's credential id, counter and last use.
    type Kept = (String, u32, Option<i64>);

    /// The accounts' passkeys with their counters and use, and how many
    /// passkey events the root has: what a refused add must leave as it was.
    fn snapshot(root: &Path, accounts: &[&Account]) -> (Vec<Vec<Kept>>, usize) {
        let rows = accounts
            .iter()
            .map(|a| {
                for_account(root, &a.issuer, &a.subject)
                    .unwrap()
                    .into_iter()
                    .map(|p| (p.credential, p.counter, p.last_used_at))
                    .collect()
            })
            .collect();
        let events = server_db::events(root, 0, None, &[], 10_000)
            .unwrap()
            .into_iter()
            .filter(|e| e.event.kind.starts_with("passkey_"))
            .count();
        (rows, events)
    }

    #[test]
    fn an_add_refused_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = account(root, &user("alice", "s1"));
        let bob = account(root, &user("bob", "s2"));
        let key = SoftKey::es256().spki();
        let asserted = "AAAAAAAAAAAAx1";
        insert_first(root, &row(&alice, asserted, &key, Alg::Es256)).unwrap();
        insert_first(root, &row(&bob, "BBBBBBBBBBBBx1", &key, Alg::Es256)).unwrap();
        let refused = |new: &NewRow, asserted: &str, read: u32, expected: Added| {
            let before = snapshot(root, &[&alice, &bob]);
            assert_eq!(add(root, new, asserted, read, read + 1).unwrap(), expected, "{}", new.credential);
            assert_eq!(snapshot(root, &[&alice, &bob]), before, "{expected:?} changed something");
        };

        refused(&row(&alice, asserted, &key, Alg::Es256), asserted, 0, Added::CredentialTaken);
        refused(&row(&alice, "BBBBBBBBBBBBx1", &key, Alg::Es256), asserted, 0, Added::CredentialTaken);
        let gone = Account { subject: "s9".into(), ..alice.clone() };
        refused(&row(&gone, "CCCCCCCCCCCCx1", &key, Alg::Es256), asserted, 0, Added::NoAccount);
        assert!(use_counter(root, asserted, 0, 4).unwrap());
        refused(&row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256), asserted, 0, Added::Raced);
        refused(&row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256), "BBBBBBBBBBBBx1", 0, Added::Raced);
        put(root, &alice, "DDDDDDDDDDDDx1", Alg::Es256, &key);
        remove(root, &alice, Some("DDDDDDDDDDDDx1")).unwrap();
        refused(&row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256), "DDDDDDDDDDDDx1", 0, Added::Raced);

        for n in 2..MAX_PER_ACCOUNT {
            put(root, &alice, &format!("EEEEEEEEEEEE{n:02}"), Alg::Es256, &key);
        }
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), MAX_PER_ACCOUNT - 1);
        assert_eq!(
            add(root, &row(&alice, "FFFFFFFFFFFFx1", &key, Alg::Es256), asserted, 4, 5).unwrap(),
            Added::Added,
            "the 99th"
        );
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), MAX_PER_ACCOUNT);
        refused(&row(&alice, "FFFFFFFFFFFFx2", &key, Alg::Es256), asserted, 5, Added::LimitReached);
        refused(&row(&alice, asserted, &key, Alg::Es256), asserted, 5, Added::LimitReached);
    }

    /// An allowance, every column.
    type AllowanceRow = (String, String, String, i64, i64);

    /// Every allowance of the root, those past their expiry too.
    fn allowance_rows(root: &Path) -> Vec<AllowanceRow> {
        let conn = server_db::open(root).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT issuer, subject, id, created_at, expires_at FROM passkey_allowances ORDER BY issuer, subject",
            )
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// [`snapshot`] and every allowance: what a refused grant or registration
    /// must leave as it was.
    type Everything = ((Vec<Vec<Kept>>, usize), Vec<AllowanceRow>);

    fn everything(root: &Path, accounts: &[&Account]) -> Everything {
        (snapshot(root, accounts), allowance_rows(root))
    }

    /// `user`'s account with a passkey of this credential id.
    fn enrolled(root: &Path, user: &Identity, credential: &str) -> Account {
        let account = account(root, user);
        put(root, &account, credential, Alg::Es256, b"spki");
        account
    }

    /// Put an allowance in as it is kept, without grant's checks and event.
    fn put_allowance(root: &Path, account: &Account, id: &str, expires_at: i64) {
        let conn = server_db::open(root).unwrap();
        let args = rusqlite::params![account.issuer, account.subject, id, 0, expires_at];
        conn.execute(ALLOWANCE_PUT, args).unwrap();
    }

    /// Run `account`'s allowance out, as time would.
    fn expire(root: &Path, account: &Account) {
        let conn = server_db::open(root).unwrap();
        let args = rusqlite::params![account.issuer, account.subject];
        let sql = "UPDATE passkey_allowances SET expires_at = 1 WHERE issuer = ?1 AND subject = ?2";
        assert_eq!(conn.execute(sql, args).unwrap(), 1);
    }

    fn live(root: &Path, account: &Account) -> Option<Allowance> {
        account_state(root, &account.issuer, &account.subject).unwrap().1
    }

    fn details(root: &Path, kind: &str) -> Vec<String> {
        kept(root, kind).into_iter().map(|e| e.detail.unwrap()).collect()
    }

    fn until(expires_at: i64) -> String {
        time(expires_at).to_rfc3339()
    }

    #[test]
    fn the_durations_are_as_documented() {
        assert_eq!(ALLOWANCE_DEFAULT, Duration::from_secs(15 * 60));
        assert_eq!(ALLOWANCE_MAX, Duration::from_secs(60 * 60));
    }

    #[test]
    fn a_grant_opens_one_window_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        assert_eq!(live(root, &alice), None);

        let before = Timestamp::now();
        let granted = grant(root, &alice, Duration::from_secs(90)).unwrap();
        let after = Timestamp::now();

        assert_eq!(granted.replaced, None);
        assert_eq!(granted.id.len(), 16, "8 bytes in hex: {}", granted.id);
        assert!(granted.id.bytes().all(|b| b.is_ascii_hexdigit()), "{}", granted.id);
        assert!(
            (before.plus(Duration::from_secs(90)).millis()..=after.plus(Duration::from_secs(90)).millis())
                .contains(&granted.expires_at)
        );
        let (passkeys, state) = account_state(root, &alice.issuer, &alice.subject).unwrap();
        assert_eq!(passkeys.len(), 1);
        let state = state.unwrap();
        assert_eq!((&state.id, state.expires_at), (&granted.id, granted.expires_at));
        assert!((before.millis()..=after.millis()).contains(&state.created_at));

        let events = kept(root, "passkey_add_allowed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "passkey_add_allowed", "a kind the trail reads back as itself");
        assert_eq!(events[0].actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (events[0].provider.as_deref(), events[0].issuer.as_deref(), events[0].subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        assert_eq!(
            events[0].detail.as_deref(),
            Some(format!("allowance {}, until {}, by an admin", granted.id, until(granted.expires_at)).as_str())
        );

        expire(root, &alice);
        assert_eq!(live(root, &alice), None, "past its expiry it is not read");
        assert_eq!(allowance_rows(root).len(), 1, "though nothing removed it yet");
        assert_eq!(kept(root, "passkey_add_cancelled").len(), 0, "and running out records nothing");
    }

    #[test]
    fn a_grant_refused_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = account(root, &user("alice", "s1"));
        let refused = |who: &Account| -> Error {
            let before = everything(root, &[&alice]);
            let e = grant(root, who, ALLOWANCE_DEFAULT).unwrap_err();
            assert_eq!(everything(root, &[&alice]), before, "{e}");
            e
        };

        let e = refused(&Account { subject: "s9".into(), ..alice.clone() });
        assert!(matches!(e, Error::NotFound { .. }), "{e}");
        assert_eq!(e.exit_code(), 3);

        let e = refused(&alice);
        assert!(matches!(e, Error::Invalid(_)), "{e}");
        assert_eq!(e.exit_code(), 2);
        assert_eq!(
            e.to_string(),
            format!("{} has no passkeys: its next browser approval registers one anyway", alice.actor)
        );

        for n in 0..MAX_PER_ACCOUNT - 1 {
            put(root, &alice, &format!("EEEEEEEEEEEE{n:02}"), Alg::Es256, b"spki");
        }
        assert_eq!(grant(root, &alice, ALLOWANCE_DEFAULT).unwrap().replaced, None, "98 is under the limit");
        assert!(cancel(root, &alice).unwrap());
        put(root, &alice, "EEEEEEEEEEEE98", Alg::Es256, b"spki");
        let e = refused(&alice);
        assert!(matches!(e, Error::Invalid(_)) && e.to_string().contains("99 passkeys"), "{e}");
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn a_mistaken_root_is_not_left_with_a_database() {
        let (dir, mistaken) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = enrolled(dir.path(), &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let root = mistaken.path();
        let e = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap_err();
        assert!(matches!(e, Error::NotFound { .. }) && e.to_string().contains(&alice.actor), "{e}");
        assert!(!cancel(root, &alice).unwrap());
        assert_eq!(account_state(root, &alice.issuer, &alice.subject).unwrap(), (Vec::new(), None));
        assert!(!server_db::path(root).exists());
    }

    #[test]
    fn a_second_grant_replaces_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let bobs = grant(root, &bob, ALLOWANCE_DEFAULT).unwrap();
        let first = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        assert_eq!(first.replaced, None, "bob's is another account's");

        let second = grant(root, &alice, ALLOWANCE_MAX).unwrap();
        assert_ne!(second.id, first.id);
        assert_eq!(second.replaced.as_deref(), Some(first.id.as_str()));
        assert!(second.expires_at > first.expires_at);
        let rows = allowance_rows(root);
        let ids: Vec<&str> = rows.iter().map(|r| r.2.as_str()).collect();
        assert_eq!(ids, [second.id.as_str(), bobs.id.as_str()], "one each");
        assert_eq!(live(root, &alice).unwrap().expires_at, second.expires_at);
        assert_eq!(details(root, "passkey_add_allowed").len(), 3);
        assert_eq!(
            details(root, "passkey_add_allowed")[2],
            format!(
                "allowance {}, until {}, by an admin, replacing allowance {}",
                second.id,
                until(second.expires_at),
                first.id
            )
        );
        assert!(details(root, "passkey_add_cancelled").is_empty(), "a replace is the one event");

        expire(root, &alice);
        let third = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        assert_eq!(third.replaced, None, "one past its expiry is overwritten, not replaced");
        assert_eq!(live(root, &alice).unwrap().id, third.id);
        assert_eq!(allowance_rows(root).len(), 2);
        assert_eq!(
            details(root, "passkey_add_allowed")[3],
            format!("allowance {}, until {}, by an admin", third.id, until(third.expires_at))
        );
    }

    #[test]
    fn cancelling_ends_a_live_allowance_and_writes_nothing_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let bobs = grant(root, &bob, ALLOWANCE_DEFAULT).unwrap();
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();

        assert!(cancel(root, &alice).unwrap());
        assert_eq!(live(root, &alice), None);
        assert_eq!(live(root, &bob).unwrap().id, bobs.id, "another account's stays");
        let events = kept(root, "passkey_add_cancelled");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "passkey_add_cancelled", "a kind the trail reads back as itself");
        assert_eq!(events[0].actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (events[0].provider.as_deref(), events[0].issuer.as_deref(), events[0].subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        assert_eq!(
            events[0].detail.as_deref(),
            Some(
                format!("allowance {}, until {}, cancelled by an admin", granted.id, until(granted.expires_at))
                    .as_str()
            )
        );

        let before = everything(root, &[&alice, &bob]);
        assert!(!cancel(root, &alice).unwrap(), "none to cancel");
        assert_eq!(everything(root, &[&alice, &bob]), before);

        grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        expire(root, &alice);
        let before = everything(root, &[&alice, &bob]);
        assert!(!cancel(root, &alice).unwrap(), "one past its expiry is none");
        assert_eq!(everything(root, &[&alice, &bob]), before, "and is not even pruned: nothing is written");
    }

    #[test]
    fn a_registration_spends_the_allowance_and_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let key = SoftKey::rs256();
        let (credential, spki) = (URL_SAFE_NO_PAD.encode(&key.credential), key.spki());
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();

        let new = NewRow { counter: 3, ..row(&alice, &credential, &spki, key.alg()) };
        assert_eq!(insert_allowed(root, &new, &granted.id).unwrap(), AllowedAdd::Added);

        assert!(allowance_rows(root).is_empty(), "spent");
        let now = for_account(root, &alice.issuer, &alice.subject).unwrap();
        let credentials: Vec<&str> = now.iter().map(|p| p.credential.as_str()).collect();
        assert_eq!(credentials, ["AAAAAAAAAAAAx1", credential.as_str()]);
        assert_eq!((now[0].counter, now[0].last_used_at), (0, None), "no existing passkey was asserted");
        assert_eq!((now[1].counter, now[1].last_used_at, now[1].alg_name()), (3, None, "RS256"));
        assert_eq!(now[1].public_key, spki);

        let events = kept(root, "passkey_registered");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (events[0].provider.as_deref(), events[0].issuer.as_deref(), events[0].subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        assert_eq!(
            events[0].detail.as_deref(),
            Some(
                format!(
                    "credential {} (RS256), registered at a browser approval under allowance {}",
                    prefix(&credential),
                    granted.id
                )
                .as_str()
            )
        );

        let before = everything(root, &[&alice]);
        let again = row(&alice, "CCCCCCCCCCCCx1", &spki, key.alg());
        assert_eq!(insert_allowed(root, &again, &granted.id).unwrap(), AllowedAdd::Ended, "single use");
        assert_eq!(everything(root, &[&alice]), before);
    }

    #[test]
    fn a_registration_refused_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let key = SoftKey::es256().spki();
        let new = row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256);
        let refused = |new: &NewRow, id: &str, expected: AllowedAdd| {
            let before = everything(root, &[&alice, &bob]);
            assert_eq!(insert_allowed(root, new, id).unwrap(), expected, "{}", new.credential);
            assert_eq!(everything(root, &[&alice, &bob]), before, "{expected:?} changed something");
        };
        let bobs = grant(root, &bob, ALLOWANCE_DEFAULT).unwrap();

        refused(&new, &bobs.id, AllowedAdd::Ended);
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        refused(&new, &bobs.id, AllowedAdd::Ended);
        refused(&new, "0123456789abcdef", AllowedAdd::Ended);
        refused(&new, "", AllowedAdd::Ended);
        refused(&row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256), &granted.id, AllowedAdd::CredentialTaken);
        refused(&row(&alice, "BBBBBBBBBBBBx1", &key, Alg::Es256), &granted.id, AllowedAdd::CredentialTaken);
        refused(&row(&alice, "BBBBBBBBBBBBx1", &key, Alg::Es256), "0123456789abcdef", AllowedAdd::Ended);

        let gone = Account { subject: "s9".into(), ..alice.clone() };
        put_allowance(root, &gone, "gone's", i64::MAX);
        refused(&row(&gone, "CCCCCCCCCCCCx1", &key, Alg::Es256), "gone's", AllowedAdd::NoAccount);

        expire(root, &alice);
        refused(&new, &granted.id, AllowedAdd::Ended);

        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        for n in 1..MAX_PER_ACCOUNT {
            put(root, &alice, &format!("EEEEEEEEEEEE{n:02}"), Alg::Es256, &key);
        }
        refused(&new, &granted.id, AllowedAdd::LimitReached);
        refused(&row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256), &granted.id, AllowedAdd::LimitReached);
    }

    #[test]
    fn concurrent_registrations_under_one_allowance_register_one() {
        const THREADS: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        let barrier = std::sync::Barrier::new(THREADS);
        let outcomes: Vec<AllowedAdd> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..THREADS)
                .map(|n| {
                    let (alice, granted, barrier) = (&alice, &granted, &barrier);
                    s.spawn(move || {
                        let credential = format!("CCCCCCCCCCCC{n:02}");
                        barrier.wait();
                        insert_allowed(root, &row(alice, &credential, b"spki", Alg::Es256), &granted.id).unwrap()
                    })
                })
                .collect();
            racers.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert_eq!(outcomes.iter().filter(|o| **o == AllowedAdd::Added).count(), 1, "{outcomes:?}");
        assert_eq!(outcomes.iter().filter(|o| **o == AllowedAdd::Ended).count(), THREADS - 1, "{outcomes:?}");
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), 2);
        assert!(allowance_rows(root).is_empty());
        assert_eq!(kept(root, "passkey_registered").len(), 1);
    }

    #[test]
    fn removing_the_last_passkey_ends_the_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "AAAAAAAAAAAAy2", Alg::Es256, b"spki");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        put(root, &bob, "BBBBBBBBBBBBy2", Alg::Es256, b"spki");
        let carol = enrolled(root, &user("carol", "s3"), "CCCCCCCCCCCCx1");
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        grant(root, &bob, ALLOWANCE_DEFAULT).unwrap();
        grant(root, &carol, ALLOWANCE_DEFAULT).unwrap();

        let removed = remove(root, &alice, Some("AAAAAAAAAAAAx")).unwrap();
        assert_eq!(removed.iter().map(Passkey::prefix).collect::<Vec<_>>(), ["AAAAAAAAAAAA"]);
        assert_eq!(live(root, &alice).unwrap().id, granted.id, "one passkey is left");
        assert!(details(root, "passkey_add_cancelled").is_empty());

        let removed = remove(root, &alice, Some("AAAAAAAAAAAAy")).unwrap();
        assert_eq!(removed.iter().map(Passkey::prefix).collect::<Vec<_>>(), ["AAAAAAAAAAAA"], "as without one");
        assert_eq!(live(root, &alice), None);
        assert_eq!(
            details(root, "passkey_add_cancelled"),
            [format!(
                "allowance {}, until {}, ended: the account's last passkey was removed",
                granted.id,
                until(granted.expires_at)
            )]
        );
        assert_eq!(
            kept(root, "passkey_add_cancelled")[0].actor.as_deref(),
            Some(alice.actor.as_str()),
            "the account's, erased with it"
        );
        assert_eq!(details(root, "passkey_removed").len(), 2, "beside each removal");
        let page = row(&alice, "DDDDDDDDDDDDx1", b"spki", Alg::Es256);
        assert_eq!(insert_allowed(root, &page, &granted.id).unwrap(), AllowedAdd::Ended, "a page opened before");

        assert_eq!(remove(root, &bob, None).unwrap().len(), 2, "every one at once");
        assert_eq!(live(root, &bob), None);
        assert_eq!(details(root, "passkey_add_cancelled").len(), 2);
        assert!(live(root, &carol).is_some(), "another account's stays");

        expire(root, &carol);
        remove(root, &carol, None).unwrap();
        assert_eq!(details(root, "passkey_add_cancelled").len(), 2, "one past its expiry ended by itself");
        assert!(allowance_rows(root).is_empty(), "and is pruned with the write");
    }

    #[test]
    fn allowance_events_carry_no_key_or_email() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let key = SoftKey::es256();
        let (credential, spki) = (URL_SAFE_NO_PAD.encode(&key.credential), key.spki());
        grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        cancel(root, &alice).unwrap();
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        insert_allowed(root, &row(&alice, &credential, &spki, key.alg()), &granted.id).unwrap();
        grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        remove(root, &alice, None).unwrap();

        let details: Vec<String> = server_db::events(root, 0, None, &[], 100)
            .unwrap()
            .into_iter()
            .filter(|e| e.event.kind.starts_with("passkey_"))
            .map(|e| e.event.detail.unwrap())
            .collect();
        assert_eq!(details.len(), 9, "{details:?}");
        for detail in &details {
            assert!(!detail.contains(&credential) && !detail.contains('@'), "{detail}");
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                let encoded = engine.encode(&spki);
                let tail = &encoded[encoded.len() - 16..];
                assert!(!detail.contains(&encoded) && !detail.contains(tail), "{detail}");
            }
        }
    }

    #[test]
    fn a_passkey_registered_under_an_allowance_reads_after_a_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        let spki = SoftKey::es256().spki();
        let new = row(&alice, "CCCCCCCCCCCCx1", &spki, Alg::Es256);
        assert_eq!(insert_allowed(root, &new, &granted.id).unwrap(), AllowedAdd::Added);
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        grant(root, &bob, ALLOWANCE_DEFAULT).unwrap();

        // Read as a bd of version 4 reads it: nothing here brings it back to 5.
        let path = server_db::path(root);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(server_db::ROLLBACK_V5).unwrap();
        assert_eq!(conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 4);
        let mut stmt = conn.prepare(BY_ACCOUNT).unwrap();
        let args = rusqlite::params![alice.issuer, alice.subject];
        let rows: Vec<(String, Vec<u8>)> =
            stmt.query_map(args, |r| Ok((r.get(0)?, r.get(4)?))).unwrap().map(Result::unwrap).collect();
        assert_eq!(rows[1], ("CCCCCCCCCCCCx1".to_string(), spki.clone()));
        drop(stmt);
        drop(conn);

        // The next open brings the table back with no allowance, and the passkey stays usable.
        assert_eq!(live(root, &bob), None);
        assert!(use_counter(root, "CCCCCCCCCCCCx1", 0, 1).unwrap());
    }

    #[test]
    fn every_write_prunes_the_allowances_that_ran_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = account(root, &user("bob", "s2"));
        let carol = account(root, &user("carol", "s3"));
        let ran_out = || {
            put_allowance(root, &carol, "ran-out", 1);
            assert_eq!(allowance_rows(root).iter().filter(|r| r.2 == "ran-out").count(), 1);
        };
        let pruned = |after: &str| {
            assert_eq!(allowance_rows(root).iter().filter(|r| r.2 == "ran-out").count(), 0, "{after}");
        };
        let (spki, other) = (SoftKey::es256().spki(), SoftKey::es256().spki());

        ran_out();
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        pruned("grant");
        ran_out();
        assert!(cancel(root, &alice).unwrap());
        pruned("cancel");
        let granted_again = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        assert_ne!(granted.id, granted_again.id);
        ran_out();
        let spend = row(&alice, "CCCCCCCCCCCCx1", &spki, Alg::Es256);
        assert_eq!(insert_allowed(root, &spend, &granted_again.id).unwrap(), AllowedAdd::Added);
        pruned("spend");
        ran_out();
        assert_eq!(insert_first(root, &row(&bob, "BBBBBBBBBBBBx1", &other, Alg::Es256)).unwrap(), Inserted::Inserted);
        pruned("insert_first");
        ran_out();
        let added = row(&bob, "BBBBBBBBBBBBx2", &other, Alg::Es256);
        assert_eq!(add(root, &added, "BBBBBBBBBBBBx1", 0, 1).unwrap(), Added::Added);
        pruned("add");
        ran_out();
        remove(root, &bob, Some("BBBBBBBBBBBBx2")).unwrap();
        pruned("remove");

        ran_out();
        assert!(!cancel(root, &alice).unwrap());
        assert_eq!(allowance_rows(root).len(), 1, "a cancel that finds none writes nothing");
        let refused = row(&alice, "DDDDDDDDDDDDx1", &spki, Alg::Es256);
        assert_eq!(insert_allowed(root, &refused, "0123456789abcdef").unwrap(), AllowedAdd::Ended);
        assert_eq!(allowance_rows(root).len(), 1, "nor does a refusal");
        assert_eq!(kept(root, "passkey_add_cancelled").len(), 1, "only the cancel above: pruning records nothing");
    }
}
