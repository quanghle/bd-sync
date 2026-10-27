//! The passkey ceremony behind both browser approval pages (human gates and
//! refused closes and discards): every Approve needs a WebAuthn ceremony
//! with user verification, against the relying party of the approvals
//! issuer (`webauthn::rp_id`).
//!
//! Once the person signed in and may approve, [`prepare`] reads the
//! account's passkeys and mints a single-use challenge, kept with the
//! approval ([`Ceremony`]); the page asks the browser to register the
//! account's first passkey, or to use one of its passkeys ([`ask`]). The
//! approval's POST is taken once, as before, and only then are its WebAuthn
//! fields checked ([`verify`]): each read only if it occurs exactly once,
//! its length capped before decoding and its bytes after. A registration is
//! stored only if the account still has no passkey ([`passkeys::insert_first`]);
//! an assertion moves the counter on by compare-and-set
//! ([`passkeys::use_counter`]). What the log may show of the credential is
//! its first [`passkeys::PREFIX`] characters, once it decoded.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::Error;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use super::super::{form, pages};
use super::{Ceremony, Ctx, origin};
use crate::passkeys::{self, Inserted, NewRow};
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
/// registering when the account has no passkey yet.
pub(super) fn prepare(cx: &Ctx<'_>, user: &auth::Identity, actor: &str) -> Result<Prepared, Error> {
    let rp_id = match webauthn::rp_id(cx.issuer) {
        Ok(rp_id) => rp_id,
        Err(why) => return Ok(Prepared::Unavailable(why)),
    };
    let credentials: Vec<String> =
        passkeys::for_account(cx.root, &user.issuer, &user.subject)?.into_iter().map(|p| p.credential).collect();
    let mut challenge = [0u8; 32];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| Error::Io(std::io::Error::other("the system's random number generator failed")))?;
    let ceremony = Ceremony {
        challenge,
        rp_id,
        origin: origin(cx.issuer).to_string(),
        issuer: user.issuer.clone(),
        subject: user.subject.clone(),
        provider: user.provider.clone(),
        actor: actor.to_string(),
        enroll: credentials.is_empty(),
    };
    Ok(Prepared::Ask { ceremony: Box::new(ceremony), credentials })
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
    if ceremony.enroll {
        pages::PasskeyAsk::Enroll {
            challenge,
            rp_id: &ceremony.rp_id,
            user: user_handle(&ceremony.issuer, &ceremony.subject),
            name: &ceremony.actor,
        }
    } else {
        pages::PasskeyAsk::Assert { challenge, rp_id: &ceremony.rp_id, credentials }
    }
}

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
}

impl Why {
    /// A short fixed description, for the gate approval log's `passkey`.
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
        }
    }
}

/// A ceremony that passed: the credential's prefix, and whether it
/// registered a passkey (else it used one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Verified {
    pub(super) credential: String,
    pub(super) registered: bool,
}

impl Verified {
    /// What the gate approval log's `passkey` says of it.
    pub(super) fn label(&self) -> &'static str {
        if self.registered { "registered" } else { "verified" }
    }
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

/// Check the WebAuthn fields of an approval's POST (`pairs`) against the
/// ceremony its page asked for: a registration is stored, an assertion's
/// counter moved on. Nothing else in the form is read.
pub(super) fn verify(cx: &Ctx<'_>, c: &Ceremony, pairs: &[(String, String)]) -> Result<Verified, Failure> {
    let refused = |why: Why, credential: &str| Failure::Refused { why, credential: credential.to_string() };
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
                metrics::PASSKEYS_REGISTERED.add();
                Ok(Verified { credential: prefix.clone(), registered: true })
            }
            Inserted::AlreadyEnrolled => Err(refused(Why::AlreadyEnrolled)),
            Inserted::CredentialTaken => Err(refused(Why::CredentialTaken)),
            Inserted::NoAccount => Err(refused(Why::NoAccount)),
        };
    }
    let signature = decoded(values[3], webauthn::MAX_SIGNATURE).map_err(refused)?;
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
    if !passkeys::use_counter(cx.root, &encoded, passkey.counter, counter).map_err(store)? {
        return Err(refused(Why::Raced));
    }
    Ok(Verified { credential: prefix.clone(), registered: false })
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
        }
    }

    /// What a software authenticator expects of it.
    pub(super) fn expect(&self) -> Expect<'_> {
        Expect { challenge: &self.challenge, origin: &self.origin, rp_id: &self.rp_id }
    }
}
