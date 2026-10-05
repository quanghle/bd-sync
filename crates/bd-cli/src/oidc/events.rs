//! Account notifications (Apple's server-to-server notifications).

use bd_core::{Error, Result, Timestamp};
use serde_json::Value;

use super::*;

/// What an account notification says happened to the account `subject`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountEvent {
    pub kind: AccountChange,
    pub subject: String,
    /// When it happened.
    pub at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountChange {
    /// It no longer lets this app sign it in: its sign-ins end.
    ConsentRevoked,
    /// It was deleted at the provider: bd forgets it.
    Deleted,
    /// Anything else (email forwarding turned on or off), named: bd keeps
    /// no email, so nothing to do.
    Other(String),
}

/// How old an account notification may be: the provider retries one it
/// could not deliver for a while; an older one is a replay.
pub(super) const MAX_EVENT_AGE: i64 = 7 * 24 * 3600;

/// The event of the account notification `token` (Apple's server-to-server
/// notifications), if a key of `keys` signed it, from `issuer`, for one of
/// `audiences`, issued within [`MAX_EVENT_AGE`] of `now` (seconds).
pub(super) fn account_event(
    token: &str,
    keys: &[Jwk],
    issuer: &str,
    audiences: &[String],
    now: i64,
) -> std::result::Result<AccountEvent, String> {
    let claims = signed_claims(token, keys)?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err(format!("its issuer is {:?}", claims["iss"]));
    }
    if !claims["aud"].as_str().is_some_and(|aud| audiences.iter().any(|a| a == aud)) {
        return Err(format!("its audience {:?} is not in account_events", claims["aud"]));
    }
    let iat = claims["iat"].as_i64().ok_or("it has no iat")?;
    if iat > now + SKEW || iat < now - MAX_EVENT_AGE {
        return Err(format!("it was issued at {iat}, too far from now"));
    }
    // A JSON object, or (as Apple sends it) a string of one.
    let events = match &claims["events"] {
        Value::String(text) => serde_json::from_str(text).map_err(|_| "its events are not JSON")?,
        other => other.clone(),
    };
    let subject = events["sub"].as_str().unwrap_or_default();
    if subject.is_empty() || subject.len() > MAX_SUBJECT || !subject.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("its subject is missing or not plain".into());
    }
    // Seconds, as Apple documents them; milliseconds read as such.
    let time = events["event_time"].as_i64().ok_or("it has no event_time")?;
    let millis = if time > 100_000_000_000 { time } else { time.saturating_mul(1000) };
    let kind = match events["type"].as_str().ok_or("it has no type")? {
        "consent-revoked" => AccountChange::ConsentRevoked,
        "account-deleted" | "account-delete" => AccountChange::Deleted,
        other => AccountChange::Other(error_code(other).to_string()),
    };
    Ok(AccountEvent { kind, subject: subject.to_string(), at: Timestamp::from_millis(millis) })
}

impl Oidc {
    /// The account notification posted as `body` (`{"payload": "<JWT>"}`),
    /// if the provider signed it, for one of `account_events`' audiences;
    /// `Invalid` with why not (logged, never shown).
    pub fn account_event(&self, md: &Metadata, body: &[u8]) -> Result<AccountEvent> {
        let refused = |why: String| {
            tracing::warn!(target: "bd::serve", provider = %self.name, %why, "an account notification was refused");
            Error::invalid(format!("not a notification of {}", self.label))
        };
        let body: Value = serde_json::from_slice(body).map_err(|_| refused("its body is not JSON".into()))?;
        let token = body["payload"].as_str().ok_or_else(|| refused("it has no payload".into()))?;
        let kid = header(token).ok().and_then(|h| h["kid"].as_str().map(str::to_string));
        let keys = self.keys(md, false)?;
        let known = kid.as_deref().is_none_or(|kid| keys.iter().any(|k| k.kid() == Some(kid)));
        let keys = if known { keys } else { self.keys(md, true)? };
        let now = Timestamp::now().millis() / 1000;
        account_event(token, &keys, &self.issuer, &self.account_events, now).map_err(refused)
    }
}
