//! Saved sign-in tokens: renewal under the credentials file's lock, and
//! revocation on the server when one is taken out of the file.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use bd_core::{Error, Result, Timestamp};
use serde_json::{Value, json};

use super::{Configured, Remote, Source, Trust, configured, env};
use crate::app::App;
use crate::credentials::{self, Renewal};
use crate::io;
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
                path: saved.path.clone(),
                key: saved.key.clone(),
                renewal: saved.renewal.clone(),
                expires_at,
            };
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
        let held = credentials::lock(&r.path, wait)?;
        let Some(saved) = credentials::lookup_key(&held, &r.path, &r.key)? else {
            // Logged out meanwhile: the token goes as it is.
            r.renewal = None;
            return Ok(current.to_string());
        };
        let set = |token: &str| *self.token.lock().unwrap_or_else(|p| p.into_inner()) = token.to_string();
        set(&saved.token);
        r.adopt(saved.renewal.clone());
        let now = Timestamp::now();
        // Another process renewed it, or a login replaced it.
        if saved.token != current && saved.renewal.as_ref().is_none_or(|ren| now < ren.refresh_after) {
            return Ok(saved.token);
        }
        let Some(mut ren) = saved.renewal.clone() else { return Ok(saved.token) };
        if !force && now < ren.refresh_after {
            return Ok(saved.token);
        }
        let request_id = match &ren.pending {
            Some(id) => id.clone(),
            None => {
                let id = random_hex(16)?;
                ren.pending = Some(id.clone());
                credentials::renewed(&held, &r.path, &r.key, &saved.token, Some(&ren))?;
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
                credentials::renewed(&held, &r.path, &r.key, &issued.token, renewal.as_ref())?;
                tracing::debug!(target: "bd::remote", url = %self.url, "access token renewed");
                r.adopt(renewal);
                set(&issued.token);
                Ok(issued.token)
            }
            Err(Error::Unauthorized(why)) => {
                // Never again: the token works as it is until it expires.
                credentials::renewed(&held, &r.path, &r.key, &saved.token, None)?;
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
    /// The credentials file, and the entry it is saved under.
    path: PathBuf,
    key: String,
    /// How it is renewed, as last read: `None` once it is not.
    renewal: Option<Renewal>,
    /// When the token in use expires, as far as known.
    expires_at: Timestamp,
}

impl Renewing {
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
