//! The passkey ceremony behind both browser approval pages (human gates and
//! refused closes and discards): every Approve needs a WebAuthn ceremony
//! with user verification, against the relying party of the approvals
//! issuer (`webauthn::rp_id`).
//!
//! Once the person signed in and may approve, [`prepare`] reads the
//! account's passkeys and mints a single-use challenge, kept with the
//! approval ([`Ceremony`]); the page asks the browser to register the
//! account's first passkey, or to use one of its passkeys ([`ask`]). An
//! account with 1 to [`passkeys::MAX_PER_ACCOUNT`] - 1 passkeys is also
//! offered to add a passkey on this device, after the one it uses: a second
//! single-use challenge (`Ceremony.add`), minted apart from the first and
//! kept and spent with the approval. The approval's POST is taken once, as
//! before, and only then are its WebAuthn fields checked ([`verify`]): each
//! read only if it occurs exactly once, its length capped before decoding
//! and its bytes after. A registration is
//! stored only if the account still has no passkey ([`passkeys::insert_first`]);
//! an assertion moves the counter on by compare-and-set
//! ([`passkeys::use_counter`]). A POST adding a passkey sends the
//! registration's `new_*` fields beside the assertion's: refused outright
//! where the page did not offer adding, else the assertion is verified,
//! then the registration against the add challenge, and only then is the
//! new passkey stored with the counter's compare-and-set in one write
//! ([`passkeys::add`]); any refusal stores nothing.
//!
//! While an admin's allowance is live, the page of an account with 1 to
//! [`passkeys::MAX_PER_ACCOUNT`] - 1 passkeys asks instead to register a
//! passkey on this device with no existing one, against a third single-use
//! challenge (`Ceremony.allowance`, [`Offer`]), and keeps the assertion as a
//! secondary path. Only the names of the [`ALLOW_FIELDS`] in a POST select the
//! registration: refused outright where the page was not opened under an
//! allowance, else checked as a first registration is, then spending that very
//! allowance and storing the passkey in one write
//! ([`passkeys::insert_allowed`]), before the approval runs. A POST without
//! them goes down the assertion's path, which leaves the allowance live.
//!
//! The page offering to add a passkey also offers, by an unticked box
//! (`make_link`, `Ceremony.link`), to make a one-time link for another device.
//! A box ticked where the page did not offer it is refused before anything
//! else is read. Otherwise the verified assertion vouches for the link: its
//! secret is drawn here, and its hash is stored with the counter's
//! compare-and-set in one write ([`passkeys::vouch_link`], or
//! [`passkeys::add`] with the added passkey), before the approval runs. The
//! secret is kept nowhere but [`Verified`], on the stack of that POST, and
//! [`shown`] puts it on that POST's answer, whatever came of the approval.
//!
//! Opening such a link is a ceremony of its own: [`prepare_link`] offers only
//! `create()`, with the account's passkeys excluded, against one single-use
//! challenge, and [`verify_link`] checks a POST carrying nothing of an approval
//! and stores the passkey through that very link ([`passkeys::insert_linked`]).
//! The account is the link's and the actor the sign-in's: never what the form
//! names.
//!
//! What the log may show of a credential is its first
//! [`passkeys::PREFIX`] characters, once it decoded.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::{Error, Timestamp};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use super::super::{PASSKEY_LINK, form, pages};
use super::{Answer, Ceremony, Ctx, Offer, link, now_millis, origin};
use crate::passkeys::{self, Added, AllowedAdd, Inserted, LINK_TTL, Link, Linked, NewLink, NewRow, Vouched};
use crate::webauthn::{self, Alg, Assertion, Expect, Refusal, Registration, Stored};
use crate::{auth, metrics};

/// What an approval page asks for, once the person may approve.
pub(super) enum Prepared {
    /// A ceremony, and the account's credential ids (base64url; none: the
    /// page registers its first passkey).
    Ask { ceremony: Box<Ceremony>, credentials: Vec<String> },
    /// The issuer cannot be a relying party: the page shows a notice.
    Unavailable(webauthn::NoRp),
}

/// The ceremony for `user` (bound to `actor`) at this server: unavailable
/// where the issuer cannot be a relying party, else with a fresh challenge,
/// registering when the account has no passkey yet. A live allowance is
/// offered (with a challenge of its own, in place of adding a passkey beside
/// an assertion) only to an account with 1 to
/// [`passkeys::MAX_PER_ACCOUNT`] - 1 passkeys: with none it enrolls as ever,
/// and at the limit it gets the ordinary page, the allowance unspent.
pub(super) fn prepare(cx: &Ctx<'_>, user: &auth::Identity, actor: &str) -> Result<Prepared, Error> {
    let rp_id = match webauthn::rp_id(cx.issuer) {
        Ok(rp_id) => rp_id,
        Err(why) => return Ok(Prepared::Unavailable(why)),
    };
    let (held, live) = passkeys::account_state(cx.root, &user.issuer, &user.subject)?;
    let credentials: Vec<String> = held.into_iter().map(|p| p.credential).collect();
    let challenge = random()?;
    let room = (1..passkeys::MAX_PER_ACCOUNT).contains(&credentials.len());
    let allowance = match live {
        Some(live) if room => Some(Offer { challenge: random()?, id: live.id, until: live.expires_at }),
        _ => None,
    };
    let add = if room && allowance.is_none() { Some(random()?) } else { None };
    let ceremony = Ceremony {
        challenge,
        rp_id,
        origin: origin(cx.issuer).to_string(),
        issuer: user.issuer.clone(),
        subject: user.subject.clone(),
        provider: user.provider.clone(),
        actor: actor.to_string(),
        enroll: credentials.is_empty(),
        link: add.is_some(),
        add,
        allowance,
    };
    Ok(Prepared::Ask { ceremony: Box::new(ceremony), credentials })
}

/// 32 random bytes: a single-use challenge.
fn random() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Io(std::io::Error::other("the system's random number generator failed")))?;
    Ok(bytes)
}

/// What a link's registration page asks for, once its account signed in.
pub(super) enum LinkPrepared {
    /// A ceremony, and the account's credential ids (base64url), which the
    /// page excludes.
    Ask { ceremony: Box<Ceremony>, credentials: Vec<String> },
    /// The account holds [`passkeys::MAX_PER_ACCOUNT`] passkeys: nothing was
    /// spent, and the link stays live.
    Full,
    /// The issuer cannot be a relying party: the page shows a notice.
    Unavailable(webauthn::NoRp),
}

/// The ceremony registering a passkey through `link` for its account, signed
/// in as `user` (bound to `actor`): a fresh challenge, and nothing of an
/// approval's (no add, no allowance, no link).
pub(super) fn prepare_link(
    cx: &Ctx<'_>,
    user: &auth::Identity,
    actor: &str,
    link: &Link,
) -> Result<LinkPrepared, Error> {
    let rp_id = match webauthn::rp_id(cx.issuer) {
        Ok(rp_id) => rp_id,
        Err(why) => return Ok(LinkPrepared::Unavailable(why)),
    };
    let held = passkeys::for_account(cx.root, &link.issuer, &link.subject)?;
    if held.len() >= passkeys::MAX_PER_ACCOUNT {
        return Ok(LinkPrepared::Full);
    }
    let ceremony = Ceremony {
        challenge: random()?,
        rp_id,
        origin: origin(cx.issuer).to_string(),
        issuer: link.issuer.clone(),
        subject: link.subject.clone(),
        provider: user.provider.clone(),
        actor: actor.to_string(),
        enroll: false,
        add: None,
        allowance: None,
        link: false,
    };
    let credentials = held.into_iter().map(|p| p.credential).collect();
    Ok(LinkPrepared::Ask { ceremony: Box::new(ceremony), credentials })
}

/// What a link's registration page asks the browser for in `ceremony`.
pub(super) fn link_ask<'a>(ceremony: &'a Ceremony, credentials: &'a [String]) -> pages::LinkAsk<'a> {
    pages::LinkAsk {
        challenge: URL_SAFE_NO_PAD.encode(ceremony.challenge),
        rp_id: &ceremony.rp_id,
        user_handle: user_handle(&ceremony.issuer, &ceremony.subject),
        user_name: &ceremony.actor,
        excluded: credentials,
    }
}

/// The WebAuthn user handle of an account (base64url): the first 16 bytes
/// of SHA-256 of `bd-passkey`, its issuer and its subject, each on a line,
/// so it names the account without showing its subject.
pub(super) fn user_handle(issuer: &str, subject: &str) -> String {
    let digest = Sha256::digest(format!("bd-passkey\n{issuer}\n{subject}").as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// What the page asks the browser for in `ceremony`.
pub(super) fn ask<'a>(ceremony: &'a Ceremony, credentials: &'a [String]) -> pages::PasskeyAsk<'a> {
    let challenge = URL_SAFE_NO_PAD.encode(ceremony.challenge);
    if let Some(offer) = &ceremony.allowance {
        return pages::PasskeyAsk::Allow {
            challenge,
            rp_id: &ceremony.rp_id,
            credentials,
            register: pages::PasskeyAdd {
                challenge: URL_SAFE_NO_PAD.encode(offer.challenge),
                user: user_handle(&ceremony.issuer, &ceremony.subject),
                name: &ceremony.actor,
            },
        };
    }
    if ceremony.enroll {
        pages::PasskeyAsk::Enroll {
            challenge,
            rp_id: &ceremony.rp_id,
            user: user_handle(&ceremony.issuer, &ceremony.subject),
            name: &ceremony.actor,
        }
    } else {
        pages::PasskeyAsk::Assert {
            challenge,
            rp_id: &ceremony.rp_id,
            credentials,
            add: ceremony.add.map(|add| pages::PasskeyAdd {
                challenge: URL_SAFE_NO_PAD.encode(add),
                user: user_handle(&ceremony.issuer, &ceremony.subject),
                name: &ceremony.actor,
            }),
            link: ceremony.link,
        }
    }
}

/// The fields of a registration through a link.
const LINK_FIELDS: [&str; 5] = ["credential", "client_data", "authenticator_data", "public_key", "algorithm"];

/// The fields of a registration added beside an assertion. Any of them in
/// a POST means it adds a passkey, even with an empty value.
const NEW_FIELDS: [&str; 5] =
    ["new_credential", "new_client_data", "new_authenticator_data", "new_public_key", "new_algorithm"];

/// The fields of a registration under an allowance, which no assertion
/// vouches for. Any of them in a POST means it registers one, even with an
/// empty value: nothing else selects that path, and the page has to have been
/// opened under an allowance.
pub(super) const ALLOW_FIELDS: [&str; 5] =
    ["allow_credential", "allow_client_data", "allow_authenticator_data", "allow_public_key", "allow_algorithm"];

/// Why a ceremony's POST was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Why {
    /// A WebAuthn field is not there (or empty).
    Missing,
    /// A field occurs more than once, is too long, or does not decode.
    Malformed,
    /// The ceremony itself.
    Webauthn(Refusal),
    /// No passkey has this credential id.
    UnknownCredential,
    /// The passkey is another account's.
    ForeignCredential,
    /// A registration for an account that has a passkey already.
    AlreadyEnrolled,
    /// A registration of a credential id already registered.
    CredentialTaken,
    /// The account was forgotten since the page was shown.
    NoAccount,
    /// Another approval used the passkey meanwhile.
    Raced,
    /// A passkey added where the page did not offer adding.
    NotOffered,
    /// The account had [`passkeys::MAX_PER_ACCOUNT`] passkeys by the time a
    /// passkey was added.
    LimitReached,
    /// The ceremony registering the added passkey.
    New(Refusal),
    /// A registration under an allowance.
    Allowance(AllowanceWhy),
    /// A link asked for where the page did not offer one.
    LinkNotOffered,
}

/// Why a registration under an allowance was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AllowanceWhy {
    /// Its fields, where the page was not opened under an allowance.
    NotOffered,
    /// One of its fields is not there (or empty).
    MissingFields,
    /// One occurs more than once, is too long or does not decode, or the POST
    /// carries an assertion's fields too: one POST is one ceremony.
    MalformedFields,
    /// The allowance ran out after the page was shown.
    Expired,
    /// It was spent, cancelled or replaced after the page was shown.
    Ended,
    /// The account had [`passkeys::MAX_PER_ACCOUNT`] passkeys by then.
    LimitReached,
    /// A passkey has this credential id already.
    CredentialTaken,
    /// The account was forgotten since the page was shown.
    NoAccount,
    /// The registration's ceremony.
    Webauthn(Refusal),
}

/// The fixed phrases of a refused registration beside the assertion or under
/// an allowance: each's label and detail, its prefix and the refusal's label.
macro_rules! new_passkey_phrases {
    ($($variant:ident => $label:literal,)*) => {
        fn new_label(r: Refusal) -> &'static str {
            match r {
                $(Refusal::$variant => concat!("new passkey: ", $label),)*
            }
        }

        fn new_detail(r: Refusal) -> &'static str {
            match r {
                $(Refusal::$variant => concat!("passkey refused: new passkey: ", $label),)*
            }
        }

        fn allowance_label(r: Refusal) -> &'static str {
            match r {
                $(Refusal::$variant => concat!("allowance: ", $label),)*
            }
        }

        fn allowance_detail(r: Refusal) -> &'static str {
            match r {
                $(Refusal::$variant => concat!("passkey refused: allowance: ", $label),)*
            }
        }
    };
}

new_passkey_phrases! {
    ClientDataTooLong => "client data too long",
    ClientDataUnreadable => "client data unreadable",
    WrongType => "wrong ceremony type",
    WrongChallenge => "wrong challenge",
    WrongOrigin => "wrong origin",
    CrossOrigin => "cross-origin",
    TopOrigin => "top origin present",
    AuthDataMalformed => "authenticator data malformed",
    WrongRpId => "wrong relying party",
    UserNotPresent => "user not present",
    UserNotVerified => "user not verified",
    NoCredentialData => "no credential data",
    CredentialMismatch => "credential mismatch",
    UnsupportedAlgorithm => "unsupported algorithm",
    BadPublicKey => "bad public key",
    BadSignature => "bad signature",
    CounterRegression => "counter regression",
}

impl Why {
    /// Whether it is a registration under an allowance that was refused: what
    /// an operation's log line reports in `passkey`.
    pub(super) fn is_allowance(self) -> bool {
        matches!(self, Why::Allowance(_))
    }

    /// Whether it is a link that was refused: what an operation's log line
    /// reports in `passkey`, as for an allowance.
    pub(super) fn is_link(self) -> bool {
        matches!(self, Why::LinkNotOffered)
    }

    /// Whether the allowance itself is over, so the page says so: the person
    /// has to ask the admin again, or use an existing passkey.
    pub(super) fn ended(self) -> bool {
        matches!(self, Why::Allowance(AllowanceWhy::Expired | AllowanceWhy::Ended))
    }

    /// A short fixed description, for the approval logs' `passkey`.
    pub(super) fn label(self) -> &'static str {
        match self {
            Why::Missing => "missing fields",
            Why::Malformed => "malformed fields",
            Why::Webauthn(r) => r.label(),
            Why::UnknownCredential => "unknown credential",
            Why::ForeignCredential => "another account's credential",
            Why::AlreadyEnrolled => "already registered",
            Why::CredentialTaken => "credential taken",
            Why::NoAccount => "no account",
            Why::Raced => "used meanwhile",
            Why::NotOffered => "adding not offered",
            Why::LimitReached => "limit reached",
            Why::New(r) => new_label(r),
            Why::Allowance(why) => match why {
                AllowanceWhy::NotOffered => "allowance: not offered",
                AllowanceWhy::MissingFields => "allowance: missing fields",
                AllowanceWhy::MalformedFields => "allowance: malformed fields",
                AllowanceWhy::Expired => "allowance: expired",
                AllowanceWhy::Ended => "allowance: ended",
                AllowanceWhy::LimitReached => "allowance: limit reached",
                AllowanceWhy::CredentialTaken => "allowance: credential taken",
                AllowanceWhy::NoAccount => "allowance: no account",
                AllowanceWhy::Webauthn(r) => allowance_label(r),
            },
            Why::LinkNotOffered => "link not offered",
        }
    }

    /// The detail an operation's approval records: `passkey refused: `
    /// and the label.
    pub(super) fn detail(self) -> &'static str {
        match self {
            Why::Missing => "passkey refused: missing fields",
            Why::Malformed => "passkey refused: malformed fields",
            Why::Webauthn(r) => match r {
                Refusal::ClientDataTooLong => "passkey refused: client data too long",
                Refusal::ClientDataUnreadable => "passkey refused: client data unreadable",
                Refusal::WrongType => "passkey refused: wrong ceremony type",
                Refusal::WrongChallenge => "passkey refused: wrong challenge",
                Refusal::WrongOrigin => "passkey refused: wrong origin",
                Refusal::CrossOrigin => "passkey refused: cross-origin",
                Refusal::TopOrigin => "passkey refused: top origin present",
                Refusal::AuthDataMalformed => "passkey refused: authenticator data malformed",
                Refusal::WrongRpId => "passkey refused: wrong relying party",
                Refusal::UserNotPresent => "passkey refused: user not present",
                Refusal::UserNotVerified => "passkey refused: user not verified",
                Refusal::NoCredentialData => "passkey refused: no credential data",
                Refusal::CredentialMismatch => "passkey refused: credential mismatch",
                Refusal::UnsupportedAlgorithm => "passkey refused: unsupported algorithm",
                Refusal::BadPublicKey => "passkey refused: bad public key",
                Refusal::BadSignature => "passkey refused: bad signature",
                Refusal::CounterRegression => "passkey refused: counter regression",
            },
            Why::UnknownCredential => "passkey refused: unknown credential",
            Why::ForeignCredential => "passkey refused: another account's credential",
            Why::AlreadyEnrolled => "passkey refused: already registered",
            Why::CredentialTaken => "passkey refused: credential taken",
            Why::NoAccount => "passkey refused: no account",
            Why::Raced => "passkey refused: used meanwhile",
            Why::NotOffered => "passkey refused: adding not offered",
            Why::LimitReached => "passkey refused: limit reached",
            Why::New(r) => new_detail(r),
            Why::Allowance(why) => match why {
                AllowanceWhy::NotOffered => "passkey refused: allowance: not offered",
                AllowanceWhy::MissingFields => "passkey refused: allowance: missing fields",
                AllowanceWhy::MalformedFields => "passkey refused: allowance: malformed fields",
                AllowanceWhy::Expired => "passkey refused: allowance: expired",
                AllowanceWhy::Ended => "passkey refused: allowance: ended",
                AllowanceWhy::LimitReached => "passkey refused: allowance: limit reached",
                AllowanceWhy::CredentialTaken => "passkey refused: allowance: credential taken",
                AllowanceWhy::NoAccount => "passkey refused: allowance: no account",
                AllowanceWhy::Webauthn(r) => allowance_detail(r),
            },
            Why::LinkNotOffered => "passkey refused: link not offered",
        }
    }
}

/// A link's secret, on its way from [`verify`] to the one answer that shows
/// it. Nothing formats it: no `Display`, no `Serialize`, and a `Debug` that
/// prints none of it, so no log can hold it. [`LinkSecret::url`] alone reads it.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct LinkSecret(String);

impl std::fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkSecret(..)")
    }
}

impl LinkSecret {
    /// The link a person opens at `issuer`, the secret in its fragment, which
    /// no request carries to a server.
    pub(super) fn url(&self, issuer: &str) -> String {
        format!("{issuer}{PASSKEY_LINK}#{}", self.0)
    }
}

/// A link a ceremony made, committed by the time it exists: its secret, when
/// it ends (milliseconds), and whether the passkey added with it filled the
/// account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LinkMade {
    pub(super) secret: LinkSecret,
    pub(super) expires_at: i64,
    pub(super) full: bool,
}

/// A ceremony that passed: the credential's prefix, whether it registered
/// a passkey (else it used one), the prefix of the passkey it added beside
/// the one it used, if any, the id of the allowance it registered under,
/// if any, and the link it made, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Verified {
    pub(super) credential: String,
    pub(super) registered: bool,
    pub(super) added: Option<String>,
    pub(super) allowance: Option<String>,
    pub(super) link: Option<LinkMade>,
}

impl Verified {
    /// What the approval logs' `passkey` says of it: an operation's line says
    /// it only of a registration under an allowance or a link made.
    pub(super) fn label(&self) -> &'static str {
        if self.allowance.is_some() {
            "registered under allowance"
        } else if self.registered {
            "registered"
        } else if self.added.is_some() {
            if self.link.is_some() { "verified and added, link made" } else { "verified and added" }
        } else if self.link.is_some() {
            "verified, link made"
        } else {
            "verified"
        }
    }
}

/// Count a passkey registered, first or added: the one place
/// `passkeys_registered_total` moves.
fn registered() {
    metrics::PASSKEYS_REGISTERED.add();
    #[cfg(test)]
    REGISTERED.with(|n| n.set(n.get() + 1));
}

#[cfg(test)]
thread_local! {
    static REGISTERED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many passkeys [`registered`] counted on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_registered() -> u64 {
    REGISTERED.with(|n| n.replace(0))
}

/// A ceremony that did not pass. Both carry the credential's prefix: empty
/// until the credential decoded, else its first [`passkeys::PREFIX`] characters.
#[derive(Debug)]
pub(super) enum Failure {
    Refused {
        why: Why,
        credential: String,
    },
    /// `server.db` failed after the ceremony was checked as far as it could be.
    Store {
        error: Error,
        credential: String,
    },
}

/// A field's base64url `value` decoded, at most `cap` bytes: its length
/// checked before it is decoded, and its bytes after.
fn decoded(value: &str, cap: usize) -> Result<Vec<u8>, Why> {
    if value.len() > webauthn::encoded_len(cap) {
        return Err(Why::Malformed);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Why::Malformed)?;
    if bytes.len() > cap {
        return Err(Why::Malformed);
    }
    Ok(bytes)
}

/// The fields of a ceremony's POST, each present exactly once and not
/// empty: Malformed if one occurs more than once, else Missing if one is
/// not there.
fn fields<'p>(pairs: &'p [(String, String)], names: &[&str]) -> Result<Vec<&'p str>, Why> {
    let mut missing = false;
    let mut found = Vec::with_capacity(names.len());
    for name in names {
        match form::single(pairs, name) {
            Some(value) if !value.is_empty() => found.push(value),
            Some(_) => missing = true,
            None if pairs.iter().any(|(k, _)| k == name) => return Err(Why::Malformed),
            None => missing = true,
        }
    }
    if missing { Err(Why::Missing) } else { Ok(found) }
}

/// A link for the account of `c` in `workspace`, vouched for by its passkey
/// `vouched_by`, and its secret, drawn before the write that makes it. Every
/// value is the ceremony's or the approval's, never the form's.
fn new_link(c: &Ceremony, vouched_by: &str, workspace: &str) -> Result<(LinkSecret, NewLink), Error> {
    let secret = auth::random_hex(32)?;
    let id = auth::random_hex(16)?;
    let now = Timestamp::now();
    let link = NewLink {
        id,
        secret_hash: auth::hash(&secret),
        issuer: c.issuer.clone(),
        subject: c.subject.clone(),
        provider: c.provider.clone(),
        actor: c.actor.clone(),
        vouched_by: vouched_by.to_string(),
        workspace: workspace.to_string(),
        created_at: now.millis(),
        expires_at: now.plus(LINK_TTL).millis(),
    };
    Ok((LinkSecret(secret), link))
}

/// Check the WebAuthn fields of an approval's POST (`pairs`) against the
/// ceremony its page asked for: a registration is stored, an assertion's
/// counter moved on, a passkey added beside an assertion stored with that
/// move in one write, and one registered under an allowance stored as that
/// allowance is spent, in one write. With `make_link` ticked, a link for
/// `workspace`, the approval's own, is made with the assertion's move, in that
/// same write. Nothing else in the form is read.
pub(super) fn verify(
    cx: &Ctx<'_>,
    c: &Ceremony,
    pairs: &[(String, String)],
    workspace: &str,
) -> Result<Verified, Failure> {
    let refused = |why: Why, credential: &str| Failure::Refused { why, credential: credential.to_string() };
    // Before anything else is read: only a page that offered it may ask for a link.
    let ticked = pairs.iter().any(|(k, _)| k == "make_link");
    if ticked && !c.link {
        return Err(refused(Why::LinkNotOffered, ""));
    }
    if ticked && form::single(pairs, "make_link") != Some("1") {
        return Err(refused(Why::Malformed, ""));
    }
    // Before anything is read: the path with no assertion is for pages opened under an allowance alone.
    let allowing = pairs.iter().any(|(k, _)| ALLOW_FIELDS.contains(&k.as_str()));
    let offer = match (allowing, &c.allowance) {
        (false, _) => None,
        (true, Some(offer)) => Some(offer),
        (true, None) => return Err(refused(Why::Allowance(AllowanceWhy::NotOffered), "")),
    };
    let adding = pairs.iter().any(|(k, _)| NEW_FIELDS.contains(&k.as_str()));
    let add = match (adding, c.enroll, c.add) {
        (false, _, _) => None,
        (true, false, Some(add)) => Some(add),
        (true, _, _) => return Err(refused(Why::NotOffered, "")),
    };
    if let Some(offer) = offer {
        return register_allowed(cx, c, offer, pairs);
    }
    let names: &[&str] = if c.enroll {
        &["credential", "client_data", "authenticator_data", "public_key", "algorithm"]
    } else {
        &["credential", "client_data", "authenticator_data", "signature"]
    };
    let values = fields(pairs, names).map_err(|why| refused(why, ""))?;
    let credential = decoded(values[0], webauthn::MAX_CREDENTIAL).map_err(|why| refused(why, ""))?;
    let encoded = URL_SAFE_NO_PAD.encode(&credential);
    let prefix = passkeys::prefix(&encoded).to_string();
    let refused = |why: Why| refused(why, &prefix);
    let store = |error: Error| Failure::Store { error, credential: prefix.clone() };
    let client_data = decoded(values[1], webauthn::MAX_CLIENT_DATA).map_err(refused)?;
    let authenticator_data = decoded(values[2], webauthn::MAX_AUTH_DATA).map_err(refused)?;
    let expect = Expect { challenge: &c.challenge, origin: &c.origin, rp_id: &c.rp_id };
    if c.enroll {
        let public_key = decoded(values[3], webauthn::MAX_PUBLIC_KEY).map_err(refused)?;
        let algorithm: i64 = values[4].parse().map_err(|_| refused(Why::Malformed))?;
        let registration = Registration {
            credential: &credential,
            client_data: &client_data,
            authenticator_data: &authenticator_data,
            public_key: &public_key,
            algorithm,
        };
        let new = webauthn::verify_registration(&expect, &registration).map_err(|r| refused(Why::Webauthn(r)))?;
        let row = NewRow {
            credential: &encoded,
            issuer: &c.issuer,
            subject: &c.subject,
            provider: &c.provider,
            actor: &c.actor,
            alg: new.alg,
            public_key: &new.public_key,
            counter: new.counter,
        };
        return match passkeys::insert_first(cx.root, &row).map_err(store)? {
            Inserted::Inserted => {
                registered();
                Ok(Verified { credential: prefix.clone(), registered: true, added: None, allowance: None, link: None })
            }
            Inserted::AlreadyEnrolled => Err(refused(Why::AlreadyEnrolled)),
            Inserted::CredentialTaken => Err(refused(Why::CredentialTaken)),
            Inserted::NoAccount => Err(refused(Why::NoAccount)),
        };
    }
    let signature = decoded(values[3], webauthn::MAX_SIGNATURE).map_err(refused)?;
    // Every field of an added passkey is read and decoded before anything is looked up.
    let new = match add {
        None => None,
        Some(add) => {
            let values = fields(pairs, &NEW_FIELDS).map_err(refused)?;
            let credential = decoded(values[0], webauthn::MAX_CREDENTIAL).map_err(refused)?;
            let client_data = decoded(values[1], webauthn::MAX_CLIENT_DATA).map_err(refused)?;
            let authenticator_data = decoded(values[2], webauthn::MAX_AUTH_DATA).map_err(refused)?;
            let public_key = decoded(values[3], webauthn::MAX_PUBLIC_KEY).map_err(refused)?;
            let algorithm: i64 = values[4].parse().map_err(|_| refused(Why::Malformed))?;
            Some((add, credential, client_data, authenticator_data, public_key, algorithm))
        }
    };
    let passkey =
        passkeys::by_credential(cx.root, &encoded).map_err(store)?.ok_or_else(|| refused(Why::UnknownCredential))?;
    if passkey.issuer != c.issuer || passkey.subject != c.subject {
        return Err(refused(Why::ForeignCredential));
    }
    let alg = Alg::from_cose(passkey.algorithm).ok_or_else(|| refused(Why::Webauthn(Refusal::UnsupportedAlgorithm)))?;
    let stored = Stored { alg, public_key: &passkey.public_key, counter: passkey.counter };
    let assertion =
        Assertion { client_data: &client_data, authenticator_data: &authenticator_data, signature: &signature };
    let counter = webauthn::verify_assertion(&expect, &stored, &assertion).map_err(|r| refused(Why::Webauthn(r)))?;
    let Some((add, credential, client_data, authenticator_data, public_key, algorithm)) = new else {
        let verified =
            |link| Verified { credential: prefix.clone(), registered: false, added: None, allowance: None, link };
        if !ticked {
            if !passkeys::use_counter(cx.root, &encoded, passkey.counter, counter).map_err(store)? {
                return Err(refused(Why::Raced));
            }
            return Ok(verified(None));
        }
        let (secret, made) = new_link(c, &encoded, workspace).map_err(store)?;
        return match passkeys::vouch_link(cx.root, &made, &encoded, passkey.counter, counter).map_err(store)? {
            Vouched::Made { replaced } => {
                link::made(replaced);
                Ok(verified(Some(LinkMade { secret, expires_at: made.expires_at, full: false })))
            }
            Vouched::Raced => Err(refused(Why::Raced)),
        };
    };
    // The added passkey's own ceremony, against the add challenge, once the assertion vouched for it.
    let expect = Expect { challenge: &add, origin: &c.origin, rp_id: &c.rp_id };
    let registration = Registration {
        credential: &credential,
        client_data: &client_data,
        authenticator_data: &authenticator_data,
        public_key: &public_key,
        algorithm,
    };
    let new = webauthn::verify_registration(&expect, &registration).map_err(|r| refused(Why::New(r)))?;
    let added = URL_SAFE_NO_PAD.encode(&credential);
    // The account is the one the sign-in proved, kept with the approval: never one the form names.
    let row = NewRow {
        credential: &added,
        issuer: &c.issuer,
        subject: &c.subject,
        provider: &c.provider,
        actor: &c.actor,
        alg: new.alg,
        public_key: &new.public_key,
        counter: new.counter,
    };
    let made = if ticked { Some(new_link(c, &encoded, workspace).map_err(store)?) } else { None };
    let write = passkeys::add(cx.root, &row, &encoded, passkey.counter, counter, made.as_ref().map(|(_, link)| link));
    let verified = |link| Verified {
        credential: prefix.clone(),
        registered: false,
        added: Some(passkeys::prefix(&added).to_string()),
        allowance: None,
        link,
    };
    match write.map_err(store)? {
        Added::Added => {
            registered();
            Ok(verified(None))
        }
        Added::Linked { replaced, full } => {
            registered();
            link::made(replaced);
            Ok(verified(made.map(|(secret, link)| LinkMade { secret, expires_at: link.expires_at, full })))
        }
        Added::LimitReached => Err(refused(Why::LimitReached)),
        Added::CredentialTaken => Err(refused(Why::CredentialTaken)),
        Added::NoAccount => Err(refused(Why::NoAccount)),
        Added::Raced => Err(refused(Why::Raced)),
    }
}

/// The registration of a POST on a page opened under the allowance `offer`,
/// checked as a first registration is, against the offer's challenge alone.
/// The account is the one the sign-in proved and the allowance the one the
/// page was opened under, both kept with the approval: never what the form
/// names. Any refusal stores nothing and leaves the allowance as it was.
fn register_allowed(
    cx: &Ctx<'_>,
    c: &Ceremony,
    offer: &Offer,
    pairs: &[(String, String)],
) -> Result<Verified, Failure> {
    let refused = |why: AllowanceWhy, credential: &str| Failure::Refused {
        why: Why::Allowance(why),
        credential: credential.to_string(),
    };
    let unread = |why: Why| match why {
        Why::Missing => AllowanceWhy::MissingFields,
        _ => AllowanceWhy::MalformedFields,
    };
    // One POST is one ceremony. A browser sends the assertion's fields empty.
    let assertion = ["credential", "client_data", "authenticator_data", "signature"];
    if pairs.iter().any(|(k, v)| assertion.contains(&k.as_str()) && !v.is_empty()) {
        return Err(refused(AllowanceWhy::MalformedFields, ""));
    }
    let values = fields(pairs, &ALLOW_FIELDS).map_err(|why| refused(unread(why), ""))?;
    let credential = decoded(values[0], webauthn::MAX_CREDENTIAL).map_err(|why| refused(unread(why), ""))?;
    let encoded = URL_SAFE_NO_PAD.encode(&credential);
    let prefix = passkeys::prefix(&encoded).to_string();
    let refused = |why: AllowanceWhy| refused(why, &prefix);
    let malformed = |_| refused(AllowanceWhy::MalformedFields);
    let client_data = decoded(values[1], webauthn::MAX_CLIENT_DATA).map_err(malformed)?;
    let authenticator_data = decoded(values[2], webauthn::MAX_AUTH_DATA).map_err(malformed)?;
    let public_key = decoded(values[3], webauthn::MAX_PUBLIC_KEY).map_err(malformed)?;
    let algorithm: i64 = values[4].parse().map_err(|_| refused(AllowanceWhy::MalformedFields))?;
    let expect = Expect { challenge: &offer.challenge, origin: &c.origin, rp_id: &c.rp_id };
    let registration = Registration {
        credential: &credential,
        client_data: &client_data,
        authenticator_data: &authenticator_data,
        public_key: &public_key,
        algorithm,
    };
    let new = webauthn::verify_registration(&expect, &registration).map_err(|r| refused(AllowanceWhy::Webauthn(r)))?;
    let row = NewRow {
        credential: &encoded,
        issuer: &c.issuer,
        subject: &c.subject,
        provider: &c.provider,
        actor: &c.actor,
        alg: new.alg,
        public_key: &new.public_key,
        counter: new.counter,
    };
    let added = passkeys::insert_allowed(cx.root, &row, &offer.id)
        .map_err(|error| Failure::Store { error, credential: prefix.clone() })?;
    match added {
        AllowedAdd::Added => {
            registered();
            Ok(Verified {
                credential: prefix.clone(),
                registered: true,
                added: None,
                allowance: Some(offer.id.clone()),
                link: None,
            })
        }
        // One check in the store: the page's own expiry tells the log which it was.
        AllowedAdd::Ended if now_millis() >= offer.until => Err(refused(AllowanceWhy::Expired)),
        AllowedAdd::Ended => Err(refused(AllowanceWhy::Ended)),
        AllowedAdd::LimitReached => Err(refused(AllowanceWhy::LimitReached)),
        AllowedAdd::CredentialTaken => Err(refused(AllowanceWhy::CredentialTaken)),
        AllowedAdd::NoAccount => Err(refused(AllowanceWhy::NoAccount)),
    }
}

/// Check a link page's POST (`pairs`) against the ceremony the page asked for
/// and store the passkey through the link `link_id`, the one the page was
/// opened for: what came of that, and the new credential's prefix. A POST
/// naming anything of an approval is refused before any field is read.
/// `Linked` other than `Inserted` stored nothing, and neither did a refusal,
/// which leaves the link live.
pub(super) fn verify_link(
    cx: &Ctx<'_>,
    c: &Ceremony,
    link_id: &str,
    pairs: &[(String, String)],
) -> Result<(String, Linked), Failure> {
    let refused = |why: Why, credential: &str| Failure::Refused { why, credential: credential.to_string() };
    let of_an_approval = |name: &str| {
        matches!(name, "signature" | "make_link") || NEW_FIELDS.contains(&name) || ALLOW_FIELDS.contains(&name)
    };
    if pairs.iter().any(|(name, _)| of_an_approval(name)) {
        return Err(refused(Why::NotOffered, ""));
    }
    let values = fields(pairs, &LINK_FIELDS).map_err(|why| refused(why, ""))?;
    let credential = decoded(values[0], webauthn::MAX_CREDENTIAL).map_err(|why| refused(why, ""))?;
    let encoded = URL_SAFE_NO_PAD.encode(&credential);
    let prefix = passkeys::prefix(&encoded).to_string();
    let refused = |why: Why| refused(why, &prefix);
    let client_data = decoded(values[1], webauthn::MAX_CLIENT_DATA).map_err(refused)?;
    let authenticator_data = decoded(values[2], webauthn::MAX_AUTH_DATA).map_err(refused)?;
    let public_key = decoded(values[3], webauthn::MAX_PUBLIC_KEY).map_err(refused)?;
    let algorithm: i64 = values[4].parse().map_err(|_| refused(Why::Malformed))?;
    let expect = Expect { challenge: &c.challenge, origin: &c.origin, rp_id: &c.rp_id };
    let registration = Registration {
        credential: &credential,
        client_data: &client_data,
        authenticator_data: &authenticator_data,
        public_key: &public_key,
        algorithm,
    };
    let new = webauthn::verify_registration(&expect, &registration).map_err(|r| refused(Why::New(r)))?;
    let row = NewRow {
        credential: &encoded,
        issuer: &c.issuer,
        subject: &c.subject,
        provider: &c.provider,
        actor: &c.actor,
        alg: new.alg,
        public_key: &new.public_key,
        counter: new.counter,
    };
    let linked = passkeys::insert_linked(cx.root, link_id, &row)
        .map_err(|error| Failure::Store { error, credential: prefix.clone() })?;
    if matches!(linked, Linked::Inserted { .. }) {
        registered();
    }
    Ok((prefix, linked))
}

/// `answer`, an approval's, with the link its ceremony made, if any: at the
/// one point each flow's answer passes, so no way an approval ends can drop a
/// link already committed. `approved` says whether the approval went through:
/// otherwise the page says the link still works.
pub(super) fn shown(answer: Answer, made: Option<&LinkMade>, issuer: &str, approved: bool) -> Answer {
    let Some(made) = made else { return answer };
    // A page keeps its status. No approval redirects today, and one that did would lose the link: it stays here.
    let page = match answer {
        Answer::Page(page) => page,
        Answer::Redirect(_) => pages::notice(200, pages::PASSKEY_LINK_FIELD, ""),
    };
    let url = made.secret.url(issuer);
    let until = minute(made.expires_at);
    Answer::Page(pages::with_link(page, &pages::LinkShown { url: &url, until: &until, approved, full: made.full }))
}

/// The UTC minute of `millis`, as a page shows it: `2026-10-01 05:28`, at or
/// before the moment itself.
fn minute(millis: i64) -> String {
    Timestamp::from_millis(millis).to_rfc3339().chars().take(16).map(|c| if c == 'T' { ' ' } else { c }).collect()
}

#[cfg(test)]
impl Ceremony {
    /// A ceremony at the tests' issuer for the account `issuer`/`subject`.
    pub(super) fn for_test(issuer: &str, subject: &str, enroll: bool, challenge: [u8; 32]) -> Ceremony {
        let at = "https://bd.example.com/bd";
        Ceremony {
            challenge,
            rp_id: webauthn::rp_id(at).expect("a relying party"),
            origin: origin(at).to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            provider: "acme".into(),
            actor: "acme:alice".into(),
            enroll,
            add: None,
            allowance: None,
            link: false,
        }
    }

    /// The ceremony, offering to add a passkey with the challenge `add`.
    pub(super) fn with_add(mut self, add: [u8; 32]) -> Ceremony {
        self.add = Some(add);
        self
    }

    /// The ceremony, offering to make a link for another device.
    pub(super) fn with_link(mut self) -> Ceremony {
        self.link = true;
        self
    }

    /// The ceremony, as of a page opened under the allowance `id`, due to end
    /// at `until`, with a fresh challenge.
    pub(super) fn with_allowance(mut self, id: &str, until: i64) -> Ceremony {
        let mut challenge = [0u8; 32];
        SystemRandom::new().fill(&mut challenge).expect("the system's random number generator");
        self.allowance = Some(Offer { challenge, id: id.to_string(), until });
        self
    }

    /// What a software authenticator expects of it.
    pub(super) fn expect(&self) -> Expect<'_> {
        Expect { challenge: &self.challenge, origin: &self.origin, rp_id: &self.rp_id }
    }

    /// What a software authenticator adding a passkey expects of it: its
    /// add challenge, which it must offer.
    pub(super) fn expect_add(&self) -> Expect<'_> {
        let add = self.add.as_ref().expect("a ceremony offering to add a passkey");
        Expect { challenge: add, origin: &self.origin, rp_id: &self.rp_id }
    }

    /// What a software authenticator registering under its allowance expects
    /// of it: the allowance's challenge, which it must offer.
    pub(super) fn expect_allow(&self) -> Expect<'_> {
        let offer = self.allowance.as_ref().expect("a ceremony offering an allowance");
        Expect { challenge: &offer.challenge, origin: &self.origin, rp_id: &self.rp_id }
    }
}
