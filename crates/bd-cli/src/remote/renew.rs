//! Saved sign-in tokens: renewal under the credentials file's lock, of a
//! token in the credentials file or the person's in the keychain, and
//! revocation on the server when one is taken out of the file.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use serde_json::{Value, json};

use super::{Configured, Remote, Source, Trust, config, configured, env};
use crate::app::App;
use crate::credentials::{self, Renewal};
use crate::io;
use crate::keychain::{self, Bounded};
use crate::protocol::{RefreshRequest, RevokeAnswer};
use crate::tokens::random_hex;

impl Remote {
    /// Revoke this remote's token on its server, if it came from GitHub
    /// sign-in. An `Error::Unauthorized` means the server no longer knew it.
    pub fn revoke_own_token(&self) -> Result<RevokeAnswer> {
        self.auth_request("revoke", &json!({}), Duration::ZERO)
    }

    /// Revoke the sign-in `ren` renews, with its refresh token: also when a
    /// refresh whose answer was lost (`ren.pending`) replaced this remote's
    /// access token on the server.
    fn revoke_sign_in(&self, ren: &Renewal) -> Result<RevokeAnswer> {
        let body = json!({ "request_id": ren.pending });
        self.auth_post("revoke", &ren.refresh_token, &body, Duration::ZERO, None)
    }

    /// Renew `saved`, the token this remote sends, when it is due: a sign-in
    /// token with a refresh token.
    pub fn renewing(mut self, saved: &credentials::Saved) -> Remote {
        if saved.renewal.is_some() {
            let expires_at = saved.renewal.as_ref().map_or(Timestamp(i64::MAX), |ren| ren.expires_at);
            let r = Renewing {
                place: Place::File(saved.path.clone()),
                key: saved.key.clone(),
                renewal: saved.renewal.clone(),
                expires_at,
            };
            self.renewing = Some(Mutex::new(r));
        }
        self
    }

    /// Send the person's token saved in the keychain `store` under `key`,
    /// renewing it when due as [`Remote::renewing`] does a saved one. Its
    /// item, read again under the lock, is used only while its CA trust
    /// still passes against this remote's.
    pub(super) fn renewing_keychain(self, store: Arc<Bounded>, key: String, renewal: Option<Renewal>) -> Remote {
        self.keychain_at(store, key, renewal, None)
    }

    /// [`Remote::renewing_keychain`], its lock beside the credentials file
    /// `lock` (default: the user's).
    fn keychain_at(
        mut self,
        store: Arc<Bounded>,
        key: String,
        renewal: Option<Renewal>,
        lock: Option<PathBuf>,
    ) -> Remote {
        self.human = true;
        if let Some(ren) = &renewal {
            let place = Place::Keychain { store, trust: self.trust().clone(), lock };
            let r = Renewing { place, key, expires_at: ren.expires_at, renewal };
            self.renewing = Some(Mutex::new(r));
        }
        self
    }

    /// The access token to send now. A saved sign-in token due for renewal,
    /// or with `force` (the server refused it), is renewed first. While the
    /// token still works, renewing is optional: a renewal that fails, or
    /// finds another process renewing, leaves it to work until it expires,
    /// and this process tries again a minute later. One the server refuses
    /// is not tried again.
    pub(super) fn access_token(&self, force: bool) -> Result<String> {
        let current = self.token.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(renewing) = &self.renewing else { return Ok(current) };
        let mut r = renewing.lock().unwrap_or_else(|p| p.into_inner());
        let now = Timestamp::now();
        let Some(known) = r.renewal.clone() else { return Ok(current) };
        if !force && now < known.refresh_after {
            return Ok(current);
        }
        let optional = !force && now < known.expires_at;
        let renewed = self.renew(&mut r, &current, force, optional);
        // What renew left: the token in use may be another process's, with its own expiry.
        let now = Timestamp::now();
        let works = !force && now < r.expires_at;
        match renewed {
            Ok(token) => Ok(token),
            Err(e) if works => {
                match &e {
                    Error::Unauthorized(_) => io::errln(format!("bd: {e}; it works until it expires")),
                    _ => {
                        tracing::debug!(target: "bd::remote", url = %self.url, error = %e, "access token not renewed yet")
                    }
                }
                if let Some(ren) = r.renewal.as_mut() {
                    ren.refresh_after = now.plus(RENEW_BACKOFF);
                }
                Ok(self.token.lock().unwrap_or_else(|p| p.into_inner()).clone())
            }
            Err(e) => Err(e),
        }
    }

    /// Renew the saved token, holding the credentials file's lock (tried
    /// once when `optional`): unless another process did it already, send
    /// its refresh token, and save what comes back. The refresh's request
    /// id is saved first, so that one whose answer is lost is sent again as
    /// such, never as a spent refresh token (which revokes the sign-in).
    fn renew(&self, r: &mut Renewing, current: &str, force: bool, optional: bool) -> Result<String> {
        let wait = match optional {
            true => Duration::ZERO,
            false => self.time_left().unwrap_or(RENEW_LOCK_WAIT).min(RENEW_LOCK_WAIT),
        };
        let held = r.lock(wait)?;
        // A keychain item replaced by one saved for another CA fails here, before its token is used.
        let Some((saved_token, saved_renewal)) = r.lookup(&held, &self.url)? else {
            // Logged out meanwhile: the token goes as it is.
            r.renewal = None;
            return Ok(current.to_string());
        };
        let set = |token: &str| *self.token.lock().unwrap_or_else(|p| p.into_inner()) = token.to_string();
        set(&saved_token);
        r.adopt(saved_renewal.clone());
        let now = Timestamp::now();
        // Another process renewed it, or a login replaced it.
        if saved_token != current && saved_renewal.as_ref().is_none_or(|ren| now < ren.refresh_after) {
            return Ok(saved_token);
        }
        let Some(mut ren) = saved_renewal else { return Ok(saved_token) };
        if !force && now < ren.refresh_after {
            return Ok(saved_token);
        }
        let request_id = match &ren.pending {
            Some(id) => id.clone(),
            None => {
                let id = random_hex(16)?;
                ren.pending = Some(id.clone());
                r.save(&held, &saved_token, Some(&ren))?;
                r.adopt(Some(ren.clone()));
                id
            }
        };
        let request = RefreshRequest { request_id };
        let answer = self.auth_post::<crate::protocol::Issued>(
            "refresh",
            &ren.refresh_token,
            &request,
            Duration::ZERO,
            Some(REFRESH_LIMIT),
        );
        match answer {
            Ok(issued) => {
                credentials::check_token(&issued.token).map_err(|_| {
                    Error::Remote(format!("{}: unexpected refresh answer: not an access token", self.url))
                })?;
                let renewal =
                    issued.refresh_token.map(|t| Renewal::new(t, Duration::from_secs(issued.expires_in.max(1))));
                r.save(&held, &issued.token, renewal.as_ref())?;
                tracing::debug!(target: "bd::remote", url = %self.url, "access token renewed");
                r.adopt(renewal);
                set(&issued.token);
                Ok(issued.token)
            }
            Err(Error::Unauthorized(why)) => {
                // Never again: the token works as it is until it expires.
                r.save(&held, &saved_token, None)?;
                r.renewal = None;
                let why = crate::agents::show::printable(&why);
                Err(Error::Unauthorized(format!("the access token could not be renewed: {why}")))
            }
            Err(e) => Err(e),
        }
    }
}

/// A saved sign-in token a [`Remote`] renews.
pub(super) struct Renewing {
    /// Where it is saved, and the entry or item it is saved under.
    place: Place,
    key: String,
    /// How it is renewed, as last read: `None` once it is not.
    renewal: Option<Renewal>,
    /// When the token in use expires, as far as known.
    expires_at: Timestamp,
}

/// Where a renewed token is saved.
enum Place {
    /// The credentials file.
    File(PathBuf),
    /// The person's token in the keychain, used only while its item's CA
    /// trust passes against `trust`, the remote's; `lock`: the credentials
    /// file whose lock serializes its writers (default: the user's).
    Keychain { store: Arc<Bounded>, trust: Trust, lock: Option<PathBuf> },
}

/// `credentials.lock`, held while a token is renewed.
enum Guard {
    File(credentials::Lock),
    Keychain(keychain::Held),
}

impl Renewing {
    /// Take the lock that serializes changes to the saved token, waiting up to `wait`.
    fn lock(&self, wait: Duration) -> Result<Guard> {
        match &self.place {
            Place::File(path) => Ok(Guard::File(credentials::lock(path, wait)?)),
            Place::Keychain { lock, .. } => {
                let path = match lock {
                    Some(path) => path.clone(),
                    None => credentials::default_path()?,
                };
                Ok(Guard::Keychain(keychain::lock_at(&path, wait)?))
            }
        }
    }

    /// The token saved now, and how it is renewed, read under the lock;
    /// `None` once it is gone. A keychain item saved trusting another CA
    /// than the remote's is refused, untouched.
    fn lookup(&self, held: &Guard, url: &str) -> Result<Option<(String, Option<Renewal>)>> {
        match (&self.place, held) {
            (Place::File(path), Guard::File(lock)) => {
                Ok(credentials::lookup_key(lock, path, &self.key)?.map(|saved| (saved.token, saved.renewal)))
            }
            (Place::Keychain { store, trust, .. }, Guard::Keychain(_)) => {
                let Some(found) = keychain::lookup_key(store, &self.key)? else { return Ok(None) };
                if config::saved_trust_error(url, &self.key, &found.entry.ca, trust).is_some() {
                    return Err(Error::Unauthorized(format!(
                        "the person's token in the {} was replaced by one saved trusting another CA certificate, so it \
                         was not sent; run the command again",
                        store.name()
                    )));
                }
                let renewal = found.entry.renewal();
                Ok(Some((found.entry.token, renewal)))
            }
            _ => Err(Error::Remote("renewing a token: the lock taken is not its own".into())),
        }
    }

    /// Replace the saved token, and how it is renewed, under the lock.
    fn save(&self, held: &Guard, token: &str, renewal: Option<&Renewal>) -> Result<()> {
        match (&self.place, held) {
            (Place::File(path), Guard::File(lock)) => credentials::renewed(lock, path, &self.key, token, renewal),
            (Place::Keychain { store, .. }, Guard::Keychain(lock)) => {
                keychain::renewed(lock, store, &self.key, token, renewal)
            }
            _ => Err(Error::Remote("renewing a token: the lock taken is not its own".into())),
        }
    }

    /// Use `renewal`, read with the token now in use; a token without one
    /// keeps the expiry known before.
    fn adopt(&mut self, renewal: Option<Renewal>) {
        if let Some(ren) = &renewal {
            self.expires_at = ren.expires_at;
        }
        self.renewal = renewal;
    }
}

/// How long a renewal that cannot wait (the token expired) waits for
/// another bd process renewing the same token.
const RENEW_LOCK_WAIT: Duration = Duration::from_secs(30);
/// A refresh, retries included, ends within this, so that the credentials
/// file's lock is not held longer.
const REFRESH_LIMIT: Duration = Duration::from_secs(60);
/// How long a process waits to renew again after an optional renewal failed.
const RENEW_BACKOFF: Duration = Duration::from_secs(60);

/// How long `bd remote logout` and `login` give a server to revoke a token.
const REVOKE_BUDGET: Duration = Duration::from_secs(5);

/// What became of a sign-in token, taken out of the credentials file, on its server.
pub(super) enum Revocation {
    /// Revoked now: the token's name.
    Revoked(String),
    /// The server no longer knew it: revoked or expired long before.
    Gone,
    /// The server's admin created it, so it stays valid.
    Kept,
    /// Not revoked, and why: it still works until it expires.
    NotRevoked(String),
}

impl Revocation {
    pub(super) fn line(&self) -> String {
        match self {
            Revocation::Revoked(name) => {
                format!("  revoked it on the server too ({})", crate::agents::show::printable(name))
            }
            Revocation::Gone => "  the server had already revoked it, or it had expired".into(),
            Revocation::Kept => {
                "  the server's admin created it: the server accepts it until revoked there (`bd serve token revoke`)"
                    .into()
            }
            Revocation::NotRevoked(why) => {
                format!("  not revoked on the server ({why}): it works there until it expires")
            }
        }
    }

    pub(super) fn view(&self, key: &str) -> Value {
        match self {
            Revocation::Revoked(name) => json!({ "key": key, "outcome": "revoked", "name": name }),
            Revocation::Gone => json!({ "key": key, "outcome": "gone" }),
            Revocation::Kept => json!({ "key": key, "outcome": "kept" }),
            Revocation::NotRevoked(why) => json!({ "key": key, "outcome": "not_revoked", "reason": why }),
        }
    }
}

/// Revoke `gone`, a token from GitHub sign-in taken out of the credentials
/// file, on its server: within [`REVOKE_BUDGET`], and only trusting the
/// server as when the token was saved. That is `trust`, what this command
/// trusts the server through, if it matches; else the system's certificate
/// authorities, if those were trusted then; else the token is not sent.
pub(super) fn revoke_saved(gone: &credentials::Gone, trust: Option<&Trust>) -> Revocation {
    let trust = match trust.filter(|t| t.anchor == gone.ca) {
        Some(t) => t.clone(),
        None if gone.ca == credentials::SYSTEM_CA => match Trust::load(None) {
            Ok(t) => t,
            Err(e) => return Revocation::NotRevoked(e.to_string()),
        },
        None => {
            return Revocation::NotRevoked(
                "it was saved trusting a CA certificate that is not in use here, so it was not sent".into(),
            );
        }
    };
    let c = Configured { url: gone.key.clone(), source: Source::Flag, ca_cert: trust.path.clone() };
    let remote = Remote::new(c, trust, gone.token.clone()).quick().within(REVOKE_BUDGET);
    let revoked = match &gone.renewal {
        Some(ren) => remote.revoke_sign_in(ren),
        None => remote.revoke_own_token(),
    };
    match revoked {
        Ok(answer) if answer.revoked => Revocation::Revoked(answer.name),
        Ok(_) => Revocation::Kept,
        Err(Error::Unauthorized(_)) => Revocation::Gone,
        Err(e) => Revocation::NotRevoked(crate::agents::show::printable(&e.to_string())),
    }
}

/// What a command naming `url` trusts its server through: the checkout's
/// remote workspace's CA certificate when it is on the same server, else
/// `$BD_CA_CERT`, else the system's certificate authorities.
pub(super) fn trust_for(app: &App, url: &str) -> Option<Trust> {
    let server = |u: &str| credentials::keys(u).ok().map(|k| k.server);
    let ca_cert = match configured(app).ok().flatten() {
        Some(c) if server(&c.url) == server(url) => c.ca_cert,
        _ => env("BD_CA_CERT").map(PathBuf::from),
    };
    Trust::load(ca_cert.as_deref()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Scope;
    use crate::keychain::testing::{Items, entry_for, get, memory, put};
    use crate::tokens::{Kind, Role};

    const URL: &str = "https://127.0.0.1:1/w/x";

    fn item() -> String {
        keychain::account(Scope::Workspace, URL)
    }

    fn renewal(token: &str, due: bool) -> Renewal {
        let now = Timestamp::now();
        let refresh_after = if due { now.minus(Duration::from_secs(60)) } else { now.plus(Duration::from_secs(3000)) };
        Renewal {
            refresh_token: token.into(),
            refresh_after,
            expires_at: now.plus(Duration::from_secs(3600)),
            pending: None,
        }
    }

    /// A remote sending the person's token `bdt_one` from a memory keychain
    /// holding it, due for renewal, saved trusting the system's CAs.
    fn human_remote(dir: &tempfile::TempDir) -> (Remote, Items) {
        let items = Items::default();
        let first = entry_for("bdt_one", credentials::SYSTEM_CA, Some(&renewal("bdr_one", true)));
        put(&items, &item(), &first);
        let (store, _) = memory(&items, keychain::IMPLICIT);
        let c = Configured { url: URL.into(), source: Source::Flag, ca_cert: None };
        let remote = Remote::new(c, Trust::load(None).unwrap(), "bdt_one".into())
            .within(Duration::from_secs(5))
            .keychain_at(Arc::new(store), URL.into(), first.renewal(), Some(dir.path().join("credentials.toml")));
        assert!(remote.human);
        (remote, items)
    }

    fn current(remote: &Remote) -> String {
        remote.token.lock().unwrap().clone()
    }

    #[test]
    fn a_replacement_saved_for_another_ca_is_not_adopted() {
        if env("BD_CA_CERT").is_some() {
            return; // the user's own CA setting passes any saved trust
        }
        let dir = tempfile::tempdir().unwrap();
        let (remote, items) = human_remote(&dir);
        let other = format!("sha256:{}", "00".repeat(32));
        put(&items, &item(), &entry_for("bdt_two", &other, Some(&renewal("bdr_two", false))));

        let e = remote.access_token(true).unwrap_err();
        assert_eq!(e.exit_code(), 7, "{e}");
        assert!(e.to_string().contains("saved trusting another CA certificate, so it was not sent"), "{e}");
        assert!(e.to_string().contains("memory keychain"), "{e}");
        assert!(!e.to_string().contains("bdt_") && !e.to_string().contains("bdr_"), "{e}");
        assert_eq!(current(&remote), "bdt_one", "never the replacement's token");
        let left = get(&items, &item()).unwrap();
        assert_eq!((left.token.as_str(), left.ca.as_str()), ("bdt_two", other.as_str()), "the item is untouched");
        assert!(left.refresh_request.is_none());
    }

    #[test]
    fn a_replacement_with_the_same_ca_is_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let (remote, items) = human_remote(&dir);
        put(&items, &item(), &entry_for("bdt_two", credentials::SYSTEM_CA, Some(&renewal("bdr_two", false))));

        assert_eq!(remote.access_token(true).unwrap(), "bdt_two");
        assert_eq!(current(&remote), "bdt_two");
    }

    #[test]
    fn the_pending_request_id_is_saved_before_the_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let (remote, items) = human_remote(&dir);

        let e = remote.access_token(true).unwrap_err();
        assert_eq!(e.exit_code(), 8, "nothing listens there: {e}");
        let left = get(&items, &item()).unwrap();
        assert_eq!(left.token, "bdt_one");
        let ren = left.renewal().expect("still renewed");
        assert!(ren.pending.as_deref().is_some_and(|id| id.len() == 32), "{:?}", left.refresh_request);
        assert_eq!((left.kind, left.role, left.ca.as_str()), (Kind::Human, Role::Admin, credentials::SYSTEM_CA));
    }
}
