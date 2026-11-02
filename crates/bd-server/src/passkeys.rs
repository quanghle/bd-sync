//! The passkeys accounts approve with on the browser approval pages, in
//! `<root>/server.db`'s `passkeys` table: several per account, at most
//! [`MAX_PER_ACCOUNT`]. The first is registered at the account's first
//! approval (`insert_first`); more are added at an approval vouched for by a
//! verified assertion of one the account has (`add`), or, for someone without
//! one at hand, under an allowance (`insert_allowed`): a window of at most
//! [`ALLOWANCE_MAX`] an admin opens on the server host (`grant`, ended early
//! by `cancel`), one per account, in the `passkey_allowances` table, spent by
//! the one registration it lets in; or through a link: a verified assertion
//! at an approval vouches for a secret shown once (`vouch_link`), which lets
//! the very account register one passkey on another device for [`LINK_TTL`]
//! (`insert_linked`, ended early by `cancel_link`), one per account, in the
//! `passkey_links` table, only the secret's hash kept. Each approval moves
//! its passkey's counter on (`use_counter`, or `add` or `vouch_link` for the
//! vouching one); an admin removes them (`remove`, which ends the allowance
//! of an account it leaves with none, so a live allowance always means a
//! passkey, and the link it leaves with none or without the passkey that
//! vouched for it, so a live link always means that passkey), and they are
//! erased with a forgotten account (`server_db::erase_passkeys`,
//! `server_db::erase_allowance`, `server_db::erase_link`). Registrations,
//! removals and what happens to allowances and links are recorded in the
//! audit trail, by the credential id's first [`PREFIX`] characters, the
//! algorithm and an allowance's id or a link's first [`PREFIX`], never the
//! key, a link's secret or its hash. `bd serve passkey
//! list|remove|allow-add|cancel-link` is the admin's command over them
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

/// How long a link lasts: always this, whoever makes it.
pub const LINK_TTL: Duration = Duration::from_secs(15 * 60);

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

/// A link as kept, its secret's hash left out: what an account may register a
/// passkey through while it is live, strictly before `expires_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// 16 random bytes in hex, not a secret: what names this link in sealed
    /// flows, and, cut to [`PREFIX`], in logs and events.
    pub id: String,
    /// The account's, as in [`crate::auth::Identity`].
    pub issuer: String,
    pub subject: String,
    /// The whole credential id of the passkey that vouched for it.
    pub vouched_by: String,
    /// The approval's workspace: only ever an input to `oauth::judge`.
    pub workspace: String,
    /// Milliseconds.
    pub created_at: i64,
    pub expires_at: i64,
}

/// A link to make, with its account's fields for the events.
#[derive(Clone)]
pub struct NewLink {
    /// 16 random bytes in hex.
    pub id: String,
    /// `auth::hash` of the secret.
    pub secret_hash: String,
    pub issuer: String,
    pub subject: String,
    pub provider: String,
    /// The account's actor.
    pub actor: String,
    /// The whole credential id of the passkey that vouches for it.
    pub vouched_by: String,
    pub workspace: String,
    /// Milliseconds.
    pub created_at: i64,
    pub expires_at: i64,
}

/// By hand, so that `secret_hash` is printed nowhere.
impl std::fmt::Debug for NewLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewLink")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("provider", &self.provider)
            .field("actor", &self.actor)
            .field("vouched_by", &self.vouched_by)
            .field("workspace", &self.workspace)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
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
pub(crate) const LINK_BY_ACCOUNT: &str = "SELECT id, issuer, subject, vouched_by, workspace, created_at, expires_at \
                                          FROM passkey_links WHERE issuer = ?1 AND subject = ?2 AND expires_at > ?3";
pub(crate) const LINK_BY_ID: &str = "SELECT id, issuer, subject, vouched_by, workspace, created_at, expires_at FROM \
                                     passkey_links WHERE id = ?1 AND expires_at > ?2";
pub(crate) const LINK_BY_SECRET: &str = "SELECT id, issuer, subject, vouched_by, workspace, created_at, expires_at \
                                         FROM passkey_links WHERE secret_hash = ?1 AND expires_at > ?2";
pub(crate) const LINK_ROW: &str = "SELECT id, issuer, subject, vouched_by, workspace, created_at, expires_at FROM \
                                   passkey_links WHERE issuer = ?1 AND subject = ?2";
pub(crate) const LINK_DELETE: &str = "DELETE FROM passkey_links WHERE issuer = ?1 AND subject = ?2 AND id = ?3";
pub(crate) const LINK_PUT: &str = "INSERT INTO passkey_links (issuer, subject, id, secret_hash, vouched_by, \
                                   workspace, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON \
                                   CONFLICT (issuer, subject) DO UPDATE SET id = excluded.id, secret_hash = \
                                   excluded.secret_hash, vouched_by = excluded.vouched_by, workspace = \
                                   excluded.workspace, created_at = excluded.created_at, expires_at = \
                                   excluded.expires_at";

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

fn one_link(tx: &rusqlite::Transaction, sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Option<Link>> {
    let found = tx.prepare_cached(sql)?.query_row(args, |r| {
        Ok(Link {
            id: r.get(0)?,
            issuer: r.get(1)?,
            subject: r.get(2)?,
            vouched_by: r.get(3)?,
            workspace: r.get(4)?,
            created_at: r.get(5)?,
            expires_at: r.get(6)?,
        })
    });
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
        server_db::prune_links(tx)?;
        Ok(Inserted::Inserted)
    })
}

/// What [`add`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Added,
    /// Added, with the link it was asked to make: only ever with a link.
    Linked {
        /// The link took the place of a live one.
        replaced: bool,
        /// The new passkey brought the account to [`MAX_PER_ACCOUNT`], so the
        /// link can add nothing until one is removed.
        full: bool,
    },
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
/// `passkey_registered` event names both credentials' prefixes. With `link`,
/// the same transaction makes it ([`put_link`]), so the counter, the passkey
/// and the link commit together or not at all.
pub fn add(root: &Path, row: &NewRow, asserted: &str, read: u32, new: u32, link: Option<&NewLink>) -> Result<Added> {
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
        let replaced = link.map(|link| put_link(tx, link)).transpose()?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        server_db::prune_links(tx)?;
        Ok(match replaced {
            None => Added::Added,
            Some(replaced) => Added::Linked { replaced, full: count + 1 >= MAX_PER_ACCOUNT as i64 },
        })
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
        server_db::prune_links(tx)?;
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
        server_db::prune_links(tx)?;
        Ok(true)
    })
}

/// How the audit trail names a link: by prefixes, of its id and of the
/// passkey that vouched for it.
fn link_named(id: &str, vouched_by: &str) -> String {
    format!("link {} vouched by {}", prefix(id), prefix(vouched_by))
}

/// `kind`, of `link`'s account, for the audit trail.
fn link_event(kind: &'static str, link: &NewLink, detail: String) -> AuthEvent {
    AuthEvent {
        kind,
        actor: Some(link.actor.clone()),
        provider: Some(link.provider.clone()),
        issuer: Some(link.issuer.clone()),
        subject: Some(link.subject.clone()),
        detail: Some(detail),
        ..AuthEvent::default()
    }
}

/// The account's link in place of any it had, with a `passkey_link_made`
/// event, after a `passkey_link_ended` one if a live link was replaced:
/// whether one was. One past its expiry is overwritten with no event, as
/// running out records none.
fn put_link(tx: &rusqlite::Transaction, link: &NewLink) -> Result<bool> {
    let now = Timestamp::now().millis();
    let earlier = one_link(tx, LINK_ROW, &[&link.issuer, &link.subject])?.filter(|l| l.expires_at > now);
    if let Some(earlier) = &earlier {
        let detail = format!("{}: replaced", link_named(&earlier.id, &earlier.vouched_by));
        server_db::record(tx, &link_event("passkey_link_ended", link, detail))?;
    }
    tx.prepare_cached(LINK_PUT)?.execute(rusqlite::params![
        link.issuer,
        link.subject,
        link.id,
        link.secret_hash,
        link.vouched_by,
        link.workspace,
        link.created_at,
        link.expires_at
    ])?;
    let detail = format!("{}, until {}", link_named(&link.id, &link.vouched_by), time(link.expires_at).to_rfc3339());
    server_db::record(tx, &link_event("passkey_link_made", link, detail))?;
    Ok(earlier.is_some())
}

/// [`put_link`] alone, for tests that need a live link and no approval.
#[cfg(test)]
pub(crate) fn test_put_link(root: &Path, link: &NewLink) -> Result<bool> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| put_link(tx, link))
}

/// What [`vouch_link`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vouched {
    Made {
        /// It took the place of a live link.
        replaced: bool,
    },
    /// The vouching passkey is no longer the account's, or its counter moved
    /// since it was read: another approval or an admin changed it meanwhile.
    Raced,
}

/// Make `link` at an approval vouched for by the account's passkey
/// `asserted`, whose counter was `read` and moves to `new`, in one
/// transaction: the counter and the link commit together or not at all. If
/// the counter did not move, nothing is written.
pub fn vouch_link(root: &Path, link: &NewLink, asserted: &str, read: u32, new: u32) -> Result<Vouched> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let moved = tx.prepare_cached(USE_COUNTER_OWNED)?.execute(rusqlite::params![
            new,
            Timestamp::now().millis(),
            asserted,
            link.issuer,
            link.subject,
            read
        ])?;
        if moved != 1 {
            return Ok(Vouched::Raced);
        }
        let replaced = put_link(tx, link)?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        server_db::prune_links(tx)?;
        Ok(Vouched::Made { replaced })
    })
}

/// The live link of the account with this issuer and subject, if any (none if
/// there is no `server.db`).
pub fn live_link(root: &Path, issuer: &str, subject: &str) -> Result<Option<Link>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(None) };
    server_db::read(root, &mut conn, |tx| {
        one_link(tx, LINK_BY_ACCOUNT, &[&issuer, &subject, &Timestamp::now().millis()])
    })
}

/// The live link with this id, if any.
pub fn link_by_id(root: &Path, id: &str) -> Result<Option<Link>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(None) };
    server_db::read(root, &mut conn, |tx| one_link(tx, LINK_BY_ID, &[&id, &Timestamp::now().millis()]))
}

/// The live link whose secret has this `auth::hash`, if any.
pub fn link_by_secret(root: &Path, hash: &str) -> Result<Option<Link>> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(None) };
    server_db::read(root, &mut conn, |tx| one_link(tx, LINK_BY_SECRET, &[&hash, &Timestamp::now().millis()]))
}

/// End `live`, `account`'s link, with a `passkey_link_ended` event saying
/// `how`.
fn end_link(tx: &rusqlite::Transaction, account: &Account, live: &Link, how: &str) -> Result<()> {
    tx.prepare_cached(LINK_DELETE)?.execute([&account.issuer, &account.subject, &live.id])?;
    let detail = format!("{}: {how}", link_named(&live.id, &live.vouched_by));
    server_db::record(tx, &event_of("passkey_link_ended", account, detail))
}

/// End `account`'s live link, for an admin: whether it had one. With none,
/// nothing is written, a link that ran out left as it is.
pub fn cancel_link(root: &Path, account: &Account) -> Result<bool> {
    let Some(mut conn) = server_db::open_existing(root)? else { return Ok(false) };
    server_db::write(root, &mut conn, |tx| {
        let now = Timestamp::now().millis();
        let Some(live) = one_link(tx, LINK_BY_ACCOUNT, &[&account.issuer, &account.subject, &now])? else {
            return Ok(false);
        };
        end_link(tx, account, &live, "cancelled")?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        server_db::prune_links(tx)?;
        Ok(true)
    })
}

/// What [`insert_linked`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Linked {
    Inserted {
        /// The whole credential id of the passkey that vouched for the link.
        vouched_by: String,
    },
    /// The link is not live any more or not the account's (spent, cancelled,
    /// replaced, or past its expiry), or the account is not there.
    LinkGone,
    /// The passkey that vouched for the link is no longer the account's.
    VouchGone,
    /// The account has [`MAX_PER_ACCOUNT`] passkeys already.
    LimitReached,
    /// Another passkey has the new credential id.
    CredentialTaken,
}

/// Register `row` through the link `link_id`, the very one its page was
/// opened under, in one transaction: only if that link is live and the
/// account's, the account is there, still holds the passkey that vouched for
/// the link and fewer than [`MAX_PER_ACCOUNT`] passkeys, and no passkey has
/// the new credential id. Every check runs before the first change, so a
/// refusal changes nothing; otherwise the link goes, the row goes in, and a
/// `passkey_registered` event names the new passkey, the link and the one
/// that vouched for it. Writers run one at a time, so of several
/// registrations through one link one gets in and the rest find it gone.
pub fn insert_linked(root: &Path, link_id: &str, row: &NewRow) -> Result<Linked> {
    let mut conn = server_db::open(root)?;
    server_db::write(root, &mut conn, |tx| {
        let exists =
            |sql: &str, args: &[&dyn rusqlite::ToSql]| -> Result<bool> { Ok(tx.prepare_cached(sql)?.exists(args)?) };
        let now = Timestamp::now().millis();
        let Some(link) =
            one_link(tx, LINK_BY_ID, &[&link_id, &now])?.filter(|l| l.issuer == row.issuer && l.subject == row.subject)
        else {
            return Ok(Linked::LinkGone);
        };
        if !exists(ACCOUNT_EXISTS, &[&row.issuer, &row.subject])? {
            return Ok(Linked::LinkGone);
        }
        if !exists(OWNED, &[&link.vouched_by, &row.issuer, &row.subject])? {
            return Ok(Linked::VouchGone);
        }
        if count(tx, row.issuer, row.subject)? >= MAX_PER_ACCOUNT {
            return Ok(Linked::LimitReached);
        }
        if exists(TAKEN, &[&row.credential])? {
            return Ok(Linked::CredentialTaken);
        }
        tx.prepare_cached(LINK_DELETE)?.execute([row.issuer, row.subject, link_id])?;
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
                    "credential {} ({}), through {}",
                    prefix(row.credential),
                    row.alg.name(),
                    link_named(&link.id, &link.vouched_by)
                )),
                ..AuthEvent::default()
            },
        )?;
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        server_db::prune_links(tx)?;
        Ok(Linked::Inserted { vouched_by: link.vouched_by })
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
        server_db::prune_links(tx)?;
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
/// account's last passkey, and so does its live link, as does removing the
/// passkey that vouched for that link, so that no link outlives its voucher.
/// The passkeys removed. Refused, with nothing removed, when there is none,
/// or when `prefix` names several.
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
        let now = Timestamp::now().millis();
        let none_left = count(tx, &account.issuer, &account.subject)? == 0;
        if none_left && let Some(live) = allowance(tx, ALLOWANCE_LIVE, &[&account.issuer, &account.subject, &now])? {
            end_allowance(tx, account, &live, "ended: the account's last passkey was removed")?;
        }
        if let Some(live) = one_link(tx, LINK_BY_ACCOUNT, &[&account.issuer, &account.subject, &now])? {
            if none_left {
                end_link(tx, account, &live, "last passkey removed")?;
            } else if !tx.prepare_cached(OWNED)?.exists([&live.vouched_by, &account.issuer, &account.subject])? {
                end_link(tx, account, &live, "vouching passkey removed")?;
            }
        }
        server_db::prune_events(tx)?;
        server_db::prune_allowances(tx)?;
        server_db::prune_links(tx)?;
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

/// `bd serve passkey list|remove|allow-add|cancel-link`: an admin's commands,
/// on this machine. What `list` says of a link is its end and the prefix of
/// the passkey that vouched for it, nothing that could open it.
pub fn cmd_passkey(app: &mut App, cmd: &PasskeyCommand) -> Result<()> {
    match cmd {
        PasskeyCommand::List(a) => {
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let (passkeys, allowance) = account_state(&root, &account.issuer, &account.subject)?;
            let link = live_link(&root, &account.issuer, &account.subject)?;
            let until = allowance.map(|a| time(a.expires_at).to_rfc3339());
            let link = link.map(|l| (time(l.expires_at).to_rfc3339(), prefix(&l.vouched_by).to_string()));
            let views: Vec<_> = passkeys
                .iter()
                .map(|p| {
                    let mut row = view(p);
                    if let Some(until) = &until {
                        row["add_allowed_until"] = json!(until);
                    }
                    if let Some((until, vouched_by)) = &link {
                        row["link_until"] = json!(until);
                        row["link_vouched_by"] = json!(vouched_by);
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
            if let Some((until, vouched_by)) = link {
                out = out.line(format!("link until {until} (vouched by {vouched_by})"));
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
        PasskeyCommand::CancelLink(a) => {
            let root = auth::root_dir(&a.root)?;
            let account = auth::account_named(&root, a.account.trim())?;
            let who = io::printable(&account.actor);
            let cancelled = cancel_link(&root, &account)?;
            app.print(Out::new(json!({ "account": account.actor, "cancelled": cancelled })).line(if cancelled {
                format!("✓ Cancelled the link of {who}")
            } else {
                format!("{who} has no link to cancel")
            }));
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
        assert_eq!(add(root, &new, &asserted, 0, 5, None).unwrap(), Added::Added);

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
            assert_eq!(add(root, new, asserted, read, read + 1, None).unwrap(), expected, "{}", new.credential);
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
            add(root, &row(&alice, "FFFFFFFFFFFFx1", &key, Alg::Es256), asserted, 4, 5, None).unwrap(),
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

        // Read as a bd of version 4 reads it: nothing here migrates it again.
        let path = server_db::path(root);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(server_db::ROLLBACK_V6).unwrap();
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
        assert_eq!(add(root, &added, "BBBBBBBBBBBBx1", 0, 1, None).unwrap(), Added::Added);
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

    /// Whether the link `every_write_prunes_the_links_that_ran_out` put in is there.
    fn ran_out_link(root: &Path) -> bool {
        let conn = server_db::open(root).unwrap();
        conn.query_row("SELECT count(*) FROM passkey_links WHERE id = 'ran-out'", [], |r| r.get::<_, i64>(0)).unwrap()
            == 1
    }

    #[test]
    fn every_write_prunes_the_links_that_ran_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = account(root, &user("bob", "s2"));
        let ran_out = || {
            let conn = server_db::open(root).unwrap();
            conn.execute(
                "INSERT INTO passkey_links \
                 (issuer, subject, id, secret_hash, vouched_by, workspace, created_at, expires_at) \
                 VALUES ('https://carol', 's3', 'ran-out', 'h', 'c', 'w', 0, 1)",
                [],
            )
            .unwrap();
            assert!(ran_out_link(root));
        };
        let pruned = |after: &str| assert!(!ran_out_link(root), "{after}");
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
        assert_eq!(add(root, &added, "BBBBBBBBBBBBx1", 0, 1, None).unwrap(), Added::Added);
        pruned("add");
        ran_out();
        remove(root, &bob, Some("BBBBBBBBBBBBx2")).unwrap();
        pruned("remove");
        assert!(kept(root, "passkey_link_ended").is_empty(), "pruning records nothing");
    }

    /// Every row of `table` of the root, as kept, in the order of its rowids.
    fn rows_of(root: &Path, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let conn = server_db::open(root).unwrap();
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid")).unwrap();
        let columns = stmt.column_count();
        stmt.query_map([], |r| (0..columns).map(|n| r.get(n)).collect()).unwrap().map(Result::unwrap).collect()
    }

    /// The three tables a link's writes touch, whole: what a refusal must
    /// leave as it was.
    fn tables(root: &Path) -> [Vec<Vec<rusqlite::types::Value>>; 3] {
        ["passkeys", "passkey_links", "auth_events"].map(|table| rows_of(root, table))
    }

    /// The events of the root, their kinds and details, oldest first.
    fn trail(root: &Path) -> Vec<(String, String)> {
        server_db::events(root, 0, None, &[], 10_000)
            .unwrap()
            .into_iter()
            .map(|e| (e.event.kind.to_string(), e.event.detail.unwrap_or_default()))
            .collect()
    }

    const LINK_ID: &str = "aaaaaaaaaaaa11112222333344445555";
    const OTHER_LINK_ID: &str = "bbbbbbbbbbbb11112222333344445555";

    /// A link of `account` vouched for by `vouched_by`, as an approval makes it.
    fn new_link(account: &Account, id: &str, vouched_by: &str) -> NewLink {
        let now = Timestamp::now();
        NewLink {
            id: id.into(),
            secret_hash: auth::hash(&format!("the secret of {id}")),
            issuer: account.issuer.clone(),
            subject: account.subject.clone(),
            provider: account.provider.clone(),
            actor: account.actor.clone(),
            vouched_by: vouched_by.into(),
            workspace: "ws".into(),
            created_at: now.millis(),
            expires_at: now.plus(LINK_TTL).millis(),
        }
    }

    /// Run `account`'s link out, as time would.
    fn expire_link(root: &Path, account: &Account) {
        let conn = server_db::open(root).unwrap();
        let args = rusqlite::params![account.issuer, account.subject];
        let sql = "UPDATE passkey_links SET expires_at = 1 WHERE issuer = ?1 AND subject = ?2";
        assert_eq!(conn.execute(sql, args).unwrap(), 1);
    }

    fn live_of(root: &Path, account: &Account) -> Option<Link> {
        live_link(root, &account.issuer, &account.subject).unwrap()
    }

    #[test]
    fn a_link_lasts_fifteen_minutes_and_ends_at_its_expiry() {
        assert_eq!(LINK_TTL, Duration::from_secs(15 * 60));
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        assert_eq!(vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 1).unwrap(), Vouched::Made { replaced: false });
        let link = live_of(root, &alice).unwrap();
        assert_eq!(link.expires_at - link.created_at, 15 * 60 * 1000);

        let conn = server_db::open(root).unwrap();
        let expires_at = link.expires_at;
        let reads = |now: i64| -> [bool; 3] {
            [
                conn.prepare(LINK_BY_ACCOUNT)
                    .unwrap()
                    .exists(rusqlite::params![alice.issuer, alice.subject, now])
                    .unwrap(),
                conn.prepare(LINK_BY_ID).unwrap().exists(rusqlite::params![link.id, now]).unwrap(),
                conn.prepare(LINK_BY_SECRET).unwrap().exists(rusqlite::params![new.secret_hash, now]).unwrap(),
            ]
        };
        assert_eq!(reads(expires_at - 1), [true; 3], "live strictly before its expiry");
        assert_eq!(reads(expires_at), [false; 3], "not at it");
        assert_eq!(reads(expires_at + 1), [false; 3], "nor past it");
        drop(conn);

        expire_link(root, &alice);
        assert_eq!(live_of(root, &alice), None);
        assert_eq!(link_by_id(root, LINK_ID).unwrap(), None);
        assert_eq!(link_by_secret(root, &new.secret_hash).unwrap(), None);
        assert_eq!(rows_of(root, "passkey_links").len(), 1, "though nothing removed it yet");
        assert!(kept(root, "passkey_link_ended").is_empty(), "and running out records nothing");
    }

    #[test]
    fn a_link_is_read_by_account_id_and_hash_of_its_secret() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(live_link(root, "i", "s").unwrap(), None);
        assert_eq!(link_by_id(root, LINK_ID).unwrap(), None);
        assert_eq!(link_by_secret(root, "h").unwrap(), None);
        assert!(!server_db::path(root).exists(), "reads create nothing");

        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        assert!(!test_put_link(root, &new).unwrap());
        let expected = Link {
            id: new.id.clone(),
            issuer: alice.issuer.clone(),
            subject: alice.subject.clone(),
            vouched_by: "AAAAAAAAAAAAx1".into(),
            workspace: "ws".into(),
            created_at: new.created_at,
            expires_at: new.expires_at,
        };
        assert_eq!(live_of(root, &alice).as_ref(), Some(&expected));
        assert_eq!(link_by_id(root, LINK_ID).unwrap().as_ref(), Some(&expected));
        assert_eq!(link_by_secret(root, &new.secret_hash).unwrap().as_ref(), Some(&expected));
        assert_eq!(live_of(root, &bob), None, "another account's is not read");
        assert_eq!(link_by_id(root, OTHER_LINK_ID).unwrap(), None);
        assert_eq!(link_by_secret(root, &auth::hash("another secret")).unwrap(), None);
    }

    #[test]
    fn a_links_debug_prints_no_hash() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let printed = format!("{new:?}");
        assert!(!printed.contains(&new.secret_hash) && !printed.contains("secret_hash"), "{printed}");
        assert!(printed.contains(LINK_ID) && printed.contains("workspace"), "{printed}");
        test_put_link(root, &new).unwrap();
        let printed = format!("{:?}", live_of(root, &alice).unwrap());
        assert!(!printed.contains(&new.secret_hash), "{printed}");
    }

    #[test]
    fn a_verified_passkey_makes_a_link_with_its_counter_in_one_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");

        assert_eq!(vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 7).unwrap(), Vouched::Made { replaced: false });

        let passkey = by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap();
        assert_eq!(passkey.counter, 7);
        assert!(passkey.last_used_at.is_some());
        assert_eq!(live_of(root, &alice).unwrap().id, LINK_ID);
        let events = kept(root, "passkey_link_made");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "passkey_link_made", "a kind the trail reads back as itself");
        assert_eq!(events[0].actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (events[0].provider.as_deref(), events[0].issuer.as_deref(), events[0].subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        assert_eq!(
            events[0].detail.as_deref(),
            Some(format!("link aaaaaaaaaaaa vouched by AAAAAAAAAAAA, until {}", until(new.expires_at)).as_str())
        );
    }

    #[test]
    fn a_link_that_cannot_be_written_leaves_the_counter_unmoved() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let conn = server_db::open(root).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuse_links BEFORE INSERT ON passkey_links BEGIN SELECT RAISE(ABORT, 'refused'); END",
        )
        .unwrap();
        drop(conn);
        let before = tables(root);

        vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 1).unwrap_err();

        assert_eq!(tables(root), before, "the counter's move went with it");
        let passkey = by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap();
        assert_eq!((passkey.counter, passkey.last_used_at), (0, None));
    }

    #[test]
    fn a_link_that_cannot_be_written_adds_no_passkey() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let link = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let conn = server_db::open(root).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER refuse_links BEFORE INSERT ON passkey_links BEGIN SELECT RAISE(ABORT, 'refused'); END",
        )
        .unwrap();
        drop(conn);
        let before = tables(root);

        add(root, &row(&alice, "AAAAAAAAAAAAy2", b"spki", Alg::Es256), "AAAAAAAAAAAAx1", 0, 1, Some(&link))
            .unwrap_err();

        assert_eq!(tables(root), before, "the counter's move and the new passkey went with it");
        assert_eq!(by_credential(root, "AAAAAAAAAAAAy2").unwrap(), None);
        let passkey = by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap();
        assert_eq!((passkey.counter, passkey.last_used_at), (0, None));
    }

    #[test]
    fn a_passkey_added_with_a_link_is_one_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let first = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let new = row(&alice, "AAAAAAAAAAAAy2", b"spki", Alg::Es256);

        let added = add(root, &new, "AAAAAAAAAAAAx1", 0, 3, Some(&first)).unwrap();

        assert_eq!(added, Added::Linked { replaced: false, full: false });
        let passkey = by_credential(root, "AAAAAAAAAAAAx1").unwrap().unwrap();
        assert_eq!(passkey.counter, 3);
        assert!(by_credential(root, "AAAAAAAAAAAAy2").unwrap().is_some());
        assert_eq!(live_of(root, &alice).unwrap().id, LINK_ID);
        assert_eq!(kept(root, "passkey_link_made").len(), 1);
        assert!(kept(root, "passkey_link_ended").is_empty());
        let kinds: Vec<String> = trail(root).into_iter().map(|(kind, _)| kind).collect();
        assert_eq!(kinds.iter().filter(|k| *k == "passkey_registered").count(), 1, "{kinds:?}");

        // Over a live link, the next takes its place.
        let second = new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAAAx1");
        let new = row(&alice, "AAAAAAAAAAAAz3", b"spki", Alg::Es256);
        let added = add(root, &new, "AAAAAAAAAAAAx1", 3, 4, Some(&second)).unwrap();
        assert_eq!(added, Added::Linked { replaced: true, full: false });
        assert_eq!(live_of(root, &alice).unwrap().id, OTHER_LINK_ID);
        assert_eq!(kept(root, "passkey_link_ended").len(), 1);

        // Asked for none, it says so and touches none.
        let links = rows_of(root, "passkey_links");
        let new = row(&alice, "AAAAAAAAAAAAw4", b"spki", Alg::Es256);
        assert_eq!(add(root, &new, "AAAAAAAAAAAAx1", 4, 5, None).unwrap(), Added::Added);
        assert_eq!(rows_of(root, "passkey_links"), links);
    }

    #[test]
    fn a_refused_add_makes_no_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "AAAAAAAAAAAAy2", Alg::Es256, b"spki");
        let link = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let before = tables(root);

        let new = row(&alice, "AAAAAAAAAAAAz3", b"spki", Alg::Es256);
        assert_eq!(add(root, &new, "AAAAAAAAAAAAx1", 9, 10, Some(&link)).unwrap(), Added::Raced);
        let taken = row(&alice, "AAAAAAAAAAAAy2", b"spki", Alg::Es256);
        assert_eq!(add(root, &taken, "AAAAAAAAAAAAx1", 0, 1, Some(&link)).unwrap(), Added::CredentialTaken);
        assert_eq!(tables(root), before);

        for i in 2..MAX_PER_ACCOUNT {
            put(root, &alice, &format!("AAAAAAAAAAAA{i:04}"), Alg::Es256, b"spki");
        }
        let before = tables(root);
        assert_eq!(add(root, &new, "AAAAAAAAAAAAx1", 0, 1, Some(&link)).unwrap(), Added::LimitReached);
        assert_eq!(tables(root), before);
    }

    #[test]
    fn a_passkey_filling_the_account_says_its_link_has_no_room() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        for i in 1..MAX_PER_ACCOUNT - 2 {
            put(root, &alice, &format!("AAAAAAAAAAAA{i:04}"), Alg::Es256, b"spki");
        }
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), MAX_PER_ACCOUNT - 2);

        let (first, second) =
            (new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1"), new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAAAx1"));
        let new = row(&alice, "AAAAAAAAAAAAy2", b"spki", Alg::Es256);
        let added = add(root, &new, "AAAAAAAAAAAAx1", 0, 1, Some(&first)).unwrap();
        assert_eq!(added, Added::Linked { replaced: false, full: false }, "room for one more");
        let new = row(&alice, "AAAAAAAAAAAAz3", b"spki", Alg::Es256);
        let added = add(root, &new, "AAAAAAAAAAAAx1", 1, 2, Some(&second)).unwrap();
        assert_eq!(added, Added::Linked { replaced: true, full: true }, "none left");
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), MAX_PER_ACCOUNT);
    }

    #[test]
    fn a_counter_that_moved_makes_no_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        assert!(use_counter(root, "AAAAAAAAAAAAx1", 0, 4).unwrap());
        let before = tables(root);

        assert_eq!(vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 5).unwrap(), Vouched::Raced, "read before the move");
        assert_eq!(vouch_link(root, &new, "BBBBBBBBBBBBx1", 0, 5).unwrap(), Vouched::Raced, "bob's is not alice's");
        assert_eq!(vouch_link(root, &new, "CCCCCCCCCCCCx1", 0, 5).unwrap(), Vouched::Raced, "no such passkey");

        assert_eq!(tables(root), before);
        assert_eq!(live_of(root, &alice), None);
        assert_eq!(live_of(root, &bob), None);
    }

    #[test]
    fn another_link_replaces_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "AAAAAAAAAAAAy2", Alg::Es256, b"spki");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let bobs = new_link(&bob, "cccccccccccc11112222333344445555", "BBBBBBBBBBBBx1");
        assert_eq!(vouch_link(root, &bobs, "BBBBBBBBBBBBx1", 0, 1).unwrap(), Vouched::Made { replaced: false });
        let first = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let made = vouch_link(root, &first, "AAAAAAAAAAAAx1", 0, 1).unwrap();
        assert_eq!(made, Vouched::Made { replaced: false }, "bob's is another account's");

        let second = new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAAAy2");
        assert_eq!(vouch_link(root, &second, "AAAAAAAAAAAAy2", 0, 1).unwrap(), Vouched::Made { replaced: true });

        let live = live_of(root, &alice).unwrap();
        assert_eq!((live.id.as_str(), live.vouched_by.as_str()), (OTHER_LINK_ID, "AAAAAAAAAAAAy2"));
        assert_eq!(rows_of(root, "passkey_links").len(), 2, "one each");
        assert_eq!(live_of(root, &bob).unwrap().id, bobs.id, "another account's stays");
        assert_eq!(link_by_id(root, LINK_ID).unwrap(), None);
        assert_eq!(link_by_secret(root, &first.secret_hash).unwrap(), None);
        assert_eq!(link_by_secret(root, &second.secret_hash).unwrap().unwrap().id, OTHER_LINK_ID);
        assert_eq!(details(root, "passkey_link_ended"), ["link aaaaaaaaaaaa vouched by AAAAAAAAAAAA: replaced"]);
        assert_eq!(
            details(root, "passkey_link_made")[2],
            format!("link bbbbbbbbbbbb vouched by AAAAAAAAAAAA, until {}", until(second.expires_at))
        );

        expire_link(root, &alice);
        let third = new_link(&alice, "dddddddddddd11112222333344445555", "AAAAAAAAAAAAx1");
        let made = vouch_link(root, &third, "AAAAAAAAAAAAx1", 1, 2).unwrap();
        assert_eq!(made, Vouched::Made { replaced: false }, "one past its expiry is overwritten, not replaced");
        assert_eq!(details(root, "passkey_link_ended").len(), 1);
        assert_eq!(live_of(root, &alice).unwrap().id, third.id);
        assert_eq!(rows_of(root, "passkey_links").len(), 2);
    }

    #[test]
    fn a_registration_through_a_link_spends_it_and_names_all_three() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let key = SoftKey::rs256();
        let (credential, spki) = (URL_SAFE_NO_PAD.encode(&key.credential), key.spki());
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();

        let new = NewRow { counter: 3, ..row(&alice, &credential, &spki, key.alg()) };
        let linked = insert_linked(root, LINK_ID, &new).unwrap();
        assert_eq!(linked, Linked::Inserted { vouched_by: "AAAAAAAAAAAAx1".to_string() });

        assert!(rows_of(root, "passkey_links").is_empty(), "spent");
        let now = for_account(root, &alice.issuer, &alice.subject).unwrap();
        let credentials: Vec<&str> = now.iter().map(|p| p.credential.as_str()).collect();
        assert_eq!(credentials, ["AAAAAAAAAAAAx1", credential.as_str()]);
        assert_eq!((now[0].counter, now[0].last_used_at), (0, None), "the vouching one asserted nothing here");
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
                    "credential {} (RS256), through link aaaaaaaaaaaa vouched by AAAAAAAAAAAA",
                    prefix(&credential)
                )
                .as_str()
            )
        );
        assert_eq!(prefix(&credential).len(), PREFIX);
        assert!(kept(root, "passkey_link_ended").is_empty(), "spent is no ending: the registration says it");

        let before = tables(root);
        let again = row(&alice, "CCCCCCCCCCCCx1", &spki, key.alg());
        assert_eq!(insert_linked(root, LINK_ID, &again).unwrap(), Linked::LinkGone, "it works once");
        assert_eq!(tables(root), before);
    }

    #[test]
    fn a_registration_through_a_link_refused_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let key = SoftKey::es256().spki();
        let new = row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256);
        let refused = |new: &NewRow, id: &str, expected: Linked| {
            let before = tables(root);
            assert_eq!(insert_linked(root, id, new).unwrap(), expected, "{}", new.credential);
            assert_eq!(tables(root), before, "{expected:?} changed something");
        };

        refused(&new, LINK_ID, Linked::LinkGone);

        let bobs = new_link(&bob, OTHER_LINK_ID, "BBBBBBBBBBBBx1");
        test_put_link(root, &bobs).unwrap();
        refused(&new, OTHER_LINK_ID, Linked::LinkGone);

        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        refused(&new, "", Linked::LinkGone);
        refused(&new, OTHER_LINK_ID, Linked::LinkGone);
        refused(&row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256), LINK_ID, Linked::CredentialTaken);
        refused(&row(&alice, "BBBBBBBBBBBBx1", &key, Alg::Es256), LINK_ID, Linked::CredentialTaken);
        refused(&row(&bob, "CCCCCCCCCCCCx1", &key, Alg::Es256), LINK_ID, Linked::LinkGone);

        let replacing = new_link(&alice, "dddddddddddd11112222333344445555", "AAAAAAAAAAAAx1");
        assert!(test_put_link(root, &replacing).unwrap());
        refused(&new, LINK_ID, Linked::LinkGone);

        assert!(cancel_link(root, &alice).unwrap());
        refused(&new, &replacing.id, Linked::LinkGone);

        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        expire_link(root, &alice);
        refused(&new, LINK_ID, Linked::LinkGone);

        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        for n in 1..MAX_PER_ACCOUNT {
            put(root, &alice, &format!("EEEEEEEEEEEE{n:02}"), Alg::Es256, &key);
        }
        refused(&new, LINK_ID, Linked::LimitReached);
        refused(&row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256), LINK_ID, Linked::LimitReached);

        let gone = Account { subject: "s9".into(), ..alice.clone() };
        test_put_link(root, &new_link(&gone, "eeeeeeeeeeee11112222333344445555", "AAAAAAAAAAAAx1")).unwrap();
        refused(&row(&gone, "CCCCCCCCCCCCx1", &key, Alg::Es256), "eeeeeeeeeeee11112222333344445555", Linked::LinkGone);

        let carol = enrolled(root, &user("carol", "s3"), "DDDDDDDDDDDDx1");
        put(root, &carol, "DDDDDDDDDDDDy2", Alg::Es256, &key);
        let carols = new_link(&carol, "ffffffffffff11112222333344445555", "DDDDDDDDDDDDx1");
        test_put_link(root, &carols).unwrap();
        // Not through `remove`, which ends the link: the check holds if that one failed to.
        server_db::open(root).unwrap().execute(DELETE, ["DDDDDDDDDDDDx1"]).unwrap();
        refused(&row(&carol, "CCCCCCCCCCCCx1", &key, Alg::Es256), &carols.id, Linked::VouchGone);
    }

    #[test]
    fn a_refused_registration_through_a_link_leaves_it_live() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        let key = SoftKey::es256().spki();
        let taken = row(&alice, "AAAAAAAAAAAAx1", &key, Alg::Es256);
        assert_eq!(insert_linked(root, LINK_ID, &taken).unwrap(), Linked::CredentialTaken);
        let new = row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256);
        assert!(matches!(insert_linked(root, LINK_ID, &new).unwrap(), Linked::Inserted { .. }));
    }

    #[test]
    fn concurrent_registrations_through_one_link_register_one() {
        const THREADS: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        let barrier = std::sync::Barrier::new(THREADS);
        let outcomes: Vec<Linked> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..THREADS)
                .map(|n| {
                    let (alice, barrier) = (&alice, &barrier);
                    s.spawn(move || {
                        let credential = format!("CCCCCCCCCCCC{n:02}");
                        barrier.wait();
                        insert_linked(root, LINK_ID, &row(alice, &credential, b"spki", Alg::Es256)).unwrap()
                    })
                })
                .collect();
            racers.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let registered = outcomes.iter().filter(|o| matches!(o, Linked::Inserted { .. })).count();
        assert_eq!(registered, 1, "{outcomes:?}");
        assert_eq!(outcomes.iter().filter(|o| **o == Linked::LinkGone).count(), THREADS - 1, "{outcomes:?}");
        assert_eq!(for_account(root, &alice.issuer, &alice.subject).unwrap().len(), 2);
        assert!(rows_of(root, "passkey_links").is_empty());
        assert_eq!(kept(root, "passkey_registered").len(), 1);
    }

    #[test]
    fn cancelling_ends_a_live_link_and_writes_nothing_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let bobs = new_link(&bob, OTHER_LINK_ID, "BBBBBBBBBBBBx1");
        test_put_link(root, &bobs).unwrap();
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();

        assert!(cancel_link(root, &alice).unwrap());

        assert_eq!(live_of(root, &alice), None);
        assert_eq!(live_of(root, &bob).unwrap().id, bobs.id, "another account's stays");
        let events = kept(root, "passkey_link_ended");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "passkey_link_ended", "a kind the trail reads back as itself");
        assert_eq!(events[0].actor.as_deref(), Some(alice.actor.as_str()));
        assert_eq!(
            (events[0].provider.as_deref(), events[0].issuer.as_deref(), events[0].subject.as_deref()),
            (Some("corp"), Some("https://idp.example"), Some("s1"))
        );
        assert_eq!(events[0].detail.as_deref(), Some("link aaaaaaaaaaaa vouched by AAAAAAAAAAAA: cancelled"));

        let before = tables(root);
        assert!(!cancel_link(root, &alice).unwrap(), "none to cancel");
        assert_eq!(tables(root), before);

        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        expire_link(root, &alice);
        let before = tables(root);
        assert!(!cancel_link(root, &alice).unwrap(), "one past its expiry is none");
        assert_eq!(tables(root), before, "and is not even pruned: nothing is written");

        let mistaken = tempfile::tempdir().unwrap();
        assert!(!cancel_link(mistaken.path(), &alice).unwrap());
        assert!(!server_db::path(mistaken.path()).exists());
    }

    #[test]
    fn removing_the_vouching_or_the_last_passkey_ends_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "AAAAAAAAAAABy2", Alg::Es256, b"spki");
        put(root, &alice, "AAAAAAAAAAACz3", Alg::Es256, b"spki");
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();

        remove(root, &alice, Some("AAAAAAAAAAAB")).unwrap();
        assert_eq!(live_of(root, &alice).unwrap().id, LINK_ID, "removing another passkey leaves it");
        assert!(details(root, "passkey_link_ended").is_empty());

        remove(root, &alice, Some("AAAAAAAAAAAA")).unwrap();
        assert_eq!(live_of(root, &alice), None);
        assert_eq!(
            details(root, "passkey_link_ended"),
            ["link aaaaaaaaaaaa vouched by AAAAAAAAAAAA: vouching passkey removed"]
        );
        let page = row(&alice, "DDDDDDDDDDDDx1", b"spki", Alg::Es256);
        assert_eq!(insert_linked(root, LINK_ID, &page).unwrap(), Linked::LinkGone, "a page opened before");

        // The last one, the very one that vouched: the broader cause is the one said.
        test_put_link(root, &new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAACz3")).unwrap();
        remove(root, &alice, Some("AAAAAAAAAAAC")).unwrap();
        assert_eq!(live_of(root, &alice), None);
        assert_eq!(
            details(root, "passkey_link_ended")[1],
            "link bbbbbbbbbbbb vouched by AAAAAAAAAAAC: last passkey removed"
        );

        // All of them at once, the last passkey too.
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        put(root, &bob, "BBBBBBBBBBBBy2", Alg::Es256, b"spki");
        test_put_link(root, &new_link(&bob, "cccccccccccc11112222333344445555", "BBBBBBBBBBBBy2")).unwrap();
        assert_eq!(remove(root, &bob, None).unwrap().len(), 2);
        assert_eq!(live_of(root, &bob), None);
        assert_eq!(
            details(root, "passkey_link_ended")[2],
            "link cccccccccccc vouched by BBBBBBBBBBBB: last passkey removed"
        );

        // One past its expiry is no live link: nothing to end, whatever goes.
        let carol = enrolled(root, &user("carol", "s3"), "CCCCCCCCCCCCx1");
        test_put_link(root, &new_link(&carol, "dddddddddddd11112222333344445555", "CCCCCCCCCCCCx1")).unwrap();
        expire_link(root, &carol);
        remove(root, &carol, None).unwrap();
        assert_eq!(details(root, "passkey_link_ended").len(), 3, "one past its expiry ended by itself");
        assert!(rows_of(root, "passkey_links").is_empty(), "and is pruned with the write");

        for event in kept(root, "passkey_link_ended") {
            assert!(event.actor.is_some() && event.provider.is_some() && event.issuer.is_some(), "{event:?}");
        }
        assert_eq!(kept(root, "passkey_link_ended")[0].actor.as_deref(), Some(alice.actor.as_str()));
    }

    #[test]
    fn forgetting_an_account_erases_its_link_and_the_events_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = enrolled(root, &user("bob", "s2"), "BBBBBBBBBBBBx1");
        let alices = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        assert_eq!(vouch_link(root, &alices, "AAAAAAAAAAAAx1", 0, 1).unwrap(), Vouched::Made { replaced: false });
        let bobs = new_link(&bob, OTHER_LINK_ID, "BBBBBBBBBBBBx1");
        assert_eq!(vouch_link(root, &bobs, "BBBBBBBBBBBBx1", 0, 1).unwrap(), Vouched::Made { replaced: false });

        assert!(auth::forget_account(root, &alice.issuer, &alice.subject).unwrap());

        assert_eq!(live_of(root, &alice), None);
        assert_eq!(link_by_secret(root, &alices.secret_hash).unwrap(), None);
        assert_eq!(rows_of(root, "passkey_links").len(), 1, "alice's row went, bob's stayed");
        assert_eq!(live_of(root, &bob).unwrap().id, bobs.id);
        let made = kept(root, "passkey_link_made");
        assert_eq!(made.len(), 1, "alice's events went with her: {made:?}");
        assert_eq!(made[0].subject.as_deref(), Some("s2"));
        assert!(kept(root, "passkey_link_ended").is_empty(), "an erasure is no ending");
    }

    #[test]
    fn an_allowance_and_a_link_leave_each_other_alone() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let key = SoftKey::es256().spki();
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        assert_eq!(live(root, &alice).unwrap().id, granted.id, "a link leaves an allowance");

        assert!(cancel(root, &alice).unwrap());
        assert_eq!(live_of(root, &alice).unwrap().id, LINK_ID, "cancelling an allowance leaves a link");
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();
        assert_eq!(live_of(root, &alice).unwrap().id, LINK_ID, "and so does a grant");
        assert!(cancel_link(root, &alice).unwrap());
        assert_eq!(live(root, &alice).unwrap().id, granted.id, "cancelling a link leaves an allowance");

        test_put_link(root, &new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        let through = row(&alice, "CCCCCCCCCCCCx1", &key, Alg::Es256);
        assert!(matches!(insert_linked(root, LINK_ID, &through).unwrap(), Linked::Inserted { .. }));
        assert_eq!(live(root, &alice).unwrap().id, granted.id, "spending a link leaves an allowance");

        test_put_link(root, &new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        let under = row(&alice, "DDDDDDDDDDDDx1", &key, Alg::Es256);
        assert_eq!(insert_allowed(root, &under, &granted.id).unwrap(), AllowedAdd::Added);
        assert_eq!(live_of(root, &alice).unwrap().id, OTHER_LINK_ID, "spending an allowance leaves a link");
    }

    #[test]
    fn link_writes_prune_what_ran_out_and_refusals_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let bob = account(root, &user("bob", "s2"));
        let ran_out = || {
            let conn = server_db::open(root).unwrap();
            conn.execute(
                "INSERT INTO passkey_links \
                 (issuer, subject, id, secret_hash, vouched_by, workspace, created_at, expires_at) \
                 VALUES ('https://carol', 's3', 'ran-out', 'h', 'c', 'w', 0, 1)",
                [],
            )
            .unwrap();
            put_allowance(root, &bob, "ran-out", 1);
            assert!(ran_out_link(root));
        };
        let pruned = |after: &str| {
            assert!(!ran_out_link(root), "{after}");
            assert_eq!(allowance_rows(root).iter().filter(|r| r.2 == "ran-out").count(), 0, "{after}");
        };

        ran_out();
        let new = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        assert_eq!(vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 1).unwrap(), Vouched::Made { replaced: false });
        pruned("vouch_link");
        ran_out();
        let spent = row(&alice, "CCCCCCCCCCCCx1", b"spki", Alg::Es256);
        assert!(matches!(insert_linked(root, LINK_ID, &spent).unwrap(), Linked::Inserted { .. }));
        pruned("insert_linked");
        ran_out();
        test_put_link(root, &new_link(&alice, OTHER_LINK_ID, "AAAAAAAAAAAAx1")).unwrap();
        assert!(cancel_link(root, &alice).unwrap());
        pruned("cancel_link");

        ran_out();
        assert!(!cancel_link(root, &alice).unwrap());
        assert!(ran_out_link(root), "a cancel that finds none writes nothing");
        let refused = row(&alice, "DDDDDDDDDDDDx1", b"spki", Alg::Es256);
        assert_eq!(insert_linked(root, OTHER_LINK_ID, &refused).unwrap(), Linked::LinkGone);
        assert!(ran_out_link(root), "nor does a refusal");
        assert_eq!(vouch_link(root, &new, "AAAAAAAAAAAAx1", 0, 2).unwrap(), Vouched::Raced);
        assert!(ran_out_link(root), "nor does a race");
    }

    /// What `bd <args> --root <root>` printed, run through [`cmd_passkey`] as
    /// a command line would run it.
    fn passkey_command(root: &Path, args: &[&str]) -> String {
        let line = [&["bd"], args, &["--root", root.to_str().unwrap()]].concat();
        let cli = <bd_cli::cli::Cli as clap::Parser>::try_parse_from(line).unwrap();
        let bd_cli::cli::Command::Serve(serve) = &cli.command else { panic!("{args:?} is not bd serve") };
        let Some(bd_cli::cli::ServeAction::Passkey(command)) = &serve.action else { panic!("{args:?} is no passkey") };
        let mut app = App::new(cli.global.clone()).unwrap();
        let (out, capture) = io::Capture::buffered(1 << 20);
        let (done, _) = io::capture(capture, || cmd_passkey(&mut app, command));
        done.unwrap();
        let printed = out.borrow().output().unwrap().to_vec();
        String::from_utf8(printed).unwrap()
    }

    /// `bd serve passkey list` of corp:alice, as text and as JSON.
    fn listed(root: &Path) -> (String, String) {
        let list = ["serve", "passkey", "list", "--account", "corp:alice"];
        (passkey_command(root, &list), passkey_command(root, &[&["--json"], &list[..]].concat()))
    }

    #[test]
    fn the_list_shows_a_live_link_and_nothing_else_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "BBBBBBBBBBBBx2", Alg::Es256, b"spki");
        let (text, json) = listed(root);
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("link until") && !json.contains("link_"), "{text}{json}");

        let link = new_link(&alice, LINK_ID, "BBBBBBBBBBBBx2");
        test_put_link(root, &link).unwrap();
        let until = time(link.expires_at).to_rfc3339();
        let (shown, shown_json) = listed(root);
        assert_eq!(shown, format!("{text}link until {until} (vouched by BBBBBBBBBBBB)\n"));
        let rows: serde_json::Value = serde_json::from_str(&shown_json).unwrap();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 2, "{shown_json}");
        for row in rows {
            assert_eq!(row["link_until"], until.as_str(), "{row}");
            assert_eq!(row["link_vouched_by"], "BBBBBBBBBBBB", "{row}");
        }
        for leaked in [link.secret_hash.as_str(), "the secret of", link.id.as_str(), "BBBBBBBBBBBBx2", "/oauth/"] {
            assert!(!shown.contains(leaked) && !shown_json.contains(leaked), "{leaked}: {shown}{shown_json}");
        }

        // A row of the JSON holds what `view` always held, and these two.
        let passkeys = for_account(root, &alice.issuer, &alice.subject).unwrap();
        for (row, passkey) in rows.iter().zip(&passkeys) {
            let mut bare = row.as_object().unwrap().clone();
            assert!(bare.remove("link_until").is_some() && bare.remove("link_vouched_by").is_some(), "{row}");
            assert_eq!(serde_json::Value::Object(bare), view(passkey));
        }
        assert_eq!(
            view(&passkeys[0]).as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(),
            ["algorithm", "counter", "created_at", "credential_prefix", "last_used_at"]
        );

        // Ran out, then gone as a spent one is: the same bytes as before any.
        expire_link(root, &alice);
        assert_eq!(listed(root), (text.clone(), json.clone()), "a link that ran out is not shown");
        rows_cleared(root);
        assert_eq!(listed(root), (text, json));
    }

    /// Drop every link, as a spent one goes.
    fn rows_cleared(root: &Path) {
        server_db::open(root).unwrap().execute("DELETE FROM passkey_links", []).unwrap();
    }

    #[test]
    fn the_list_shows_a_link_beside_an_allowance_each_on_its_own_terms() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let link = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        test_put_link(root, &link).unwrap();
        let granted = grant(root, &alice, ALLOWANCE_DEFAULT).unwrap();

        let (text, json) = listed(root);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[1].starts_with("Add allowed: "), "{text}");
        assert_eq!(lines[2], format!("link until {} (vouched by AAAAAAAAAAAA)", until(link.expires_at)));
        let rows: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(rows[0]["add_allowed_until"], until(granted.expires_at).as_str(), "{json}");
        assert_eq!(rows[0]["link_until"], until(link.expires_at).as_str(), "{json}");
    }

    #[test]
    fn cancel_link_says_what_it_did_and_prints_nothing_of_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        let link = new_link(&alice, LINK_ID, "AAAAAAAAAAAAx1");
        let cancel = ["serve", "passkey", "cancel-link", "--account", "corp:alice"];
        let as_json = [&["--json"], &cancel[..]].concat();

        test_put_link(root, &link).unwrap();
        assert_eq!(passkey_command(root, &cancel), "✓ Cancelled the link of corp:alice\n");
        assert_eq!(live_of(root, &alice), None);
        assert_eq!(details(root, "passkey_link_ended"), ["link aaaaaaaaaaaa vouched by AAAAAAAAAAAA: cancelled"]);
        assert_eq!(passkey_command(root, &cancel), "corp:alice has no link to cancel\n");

        test_put_link(root, &link).unwrap();
        let json = passkey_command(root, &as_json);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            json!({ "account": "corp:alice", "cancelled": true })
        );
        assert!(!json.contains(&link.secret_hash) && !json.contains(&link.id), "{json}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&passkey_command(root, &as_json)).unwrap(),
            json!({ "account": "corp:alice", "cancelled": false })
        );
    }

    #[test]
    fn link_events_name_prefixes_never_a_secret_a_hash_or_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let alice = enrolled(root, &user("alice", "s1"), "AAAAAAAAAAAAx1");
        put(root, &alice, "AAAAAAAAAAABy2", Alg::Es256, b"spki");
        let key = SoftKey::es256();
        let (credential, spki) = (URL_SAFE_NO_PAD.encode(&key.credential), key.spki());
        let links = ["11", "22", "33", "44", "55"].map(|n| {
            let mut link = new_link(&alice, &format!("{n}{}", &LINK_ID[2..]), "AAAAAAAAAAAAx1");
            link.secret_hash = auth::hash(&format!("the secret {n}"));
            link
        });
        let mut counter = 0;
        let mut vouch = |link: &NewLink| {
            vouch_link(root, link, "AAAAAAAAAAAAx1", counter, counter + 1).unwrap();
            counter += 1;
        };

        vouch(&links[0]);
        vouch(&links[1]);
        insert_linked(root, &links[1].id, &row(&alice, &credential, &spki, key.alg())).unwrap();
        vouch(&links[2]);
        cancel_link(root, &alice).unwrap();
        vouch(&links[3]);
        remove(root, &alice, Some("AAAAAAAAAAAA")).unwrap();
        vouch_link(root, &NewLink { vouched_by: "AAAAAAAAAAABy2".into(), ..links[4].clone() }, "AAAAAAAAAAABy2", 0, 1)
            .unwrap();
        remove(root, &alice, None).unwrap();

        let trail: Vec<(String, String)> = trail(root).into_iter().filter(|(k, _)| k.starts_with("passkey_")).collect();
        let kinds: Vec<&str> = trail.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "passkey_link_made",
                "passkey_link_ended",
                "passkey_link_made",
                "passkey_registered",
                "passkey_link_made",
                "passkey_link_ended",
                "passkey_link_made",
                "passkey_removed",
                "passkey_link_ended",
                "passkey_link_made",
                "passkey_removed",
                "passkey_removed",
                "passkey_link_ended",
            ]
        );
        for (kind, detail) in &trail {
            assert!(!detail.contains(&credential) && !detail.contains("AAAAAAAAAAAAx1"), "{kind}: {detail}");
            for link in &links {
                assert!(!detail.contains(&link.id), "{kind}: {detail}");
                assert!(!detail.contains(&link.secret_hash[..16]), "{kind}: {detail}");
            }
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                let encoded = engine.encode(&spki);
                let tail = &encoded[encoded.len() - 16..];
                assert!(!detail.contains(&encoded) && !detail.contains(tail), "{kind}: {detail}");
            }
        }
    }
}
