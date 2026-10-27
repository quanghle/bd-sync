//! What an authorization keeps between steps: sealed for the browser before a sign-in ([`Pending`], [`Sealer`]), in memory after ([`Flows`]).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bd_core::Error;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use crate::auth;
use crate::oauth::Admitted;

use super::*;

/// The steps a [`Pending`] is sealed for.
pub(super) const CHOOSING: &str = "choose";

pub(super) const AT_PROVIDER: &str = "provider";

/// The hop from a gate's page to the chooser (`/oauth/choose`), where the
/// browser's cookie is seen: a [`Then::Gate`] not yet bound to a browser.
pub(super) const GATE_BEGIN: &str = "gate-begin";

/// The hop from an operation's approval link to the chooser: a
/// [`Then::Operation`] not yet bound to a browser.
pub(super) const OP_BEGIN: &str = "op-begin";

/// What a browser sign-in goes on to once the person signed in: an
/// application's authorization, a human gate's approval, or the approval of
/// a close or discard that human gates refused. It is sealed with the flow
/// and decides its sealing's AAD ([`Sealer::seal`]), so a flow of one kind
/// never finishes as another.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "then", rename_all = "snake_case")]
pub(super) enum Then {
    /// The client's authorization request, as it sent it.
    Authorize { query: String },
    /// Approving the human gate `gate` of `workspace`.
    Gate { workspace: String, gate: String },
    /// Approving the refused `op` (`close` or `discard`) of `issue` in
    /// `workspace`. The sealed request itself rides in `parts` cookies of
    /// its own (`set_request_cookies`), too long for this flow's: `digest`
    /// is the hash of that link token, which the callback checks them against.
    Operation { workspace: String, op: String, issue: String, digest: String, parts: u8 },
}

/// The kinds of [`Then`], each sealed under an AAD of its own ([`aad`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Authorize,
    Gate,
    Operation,
}

/// What an operation's flow carries ([`Then::Operation`]), as a view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpFlow {
    pub workspace: String,
    pub op: String,
    pub issue: String,
    /// The hash of the link token the request cookies carry.
    pub digest: String,
    /// How many request cookies carry it.
    pub parts: u8,
}

impl Then {
    pub(super) fn kind(&self) -> Kind {
        match self {
            Then::Authorize { .. } => Kind::Authorize,
            Then::Gate { .. } => Kind::Gate,
            Then::Operation { .. } => Kind::Operation,
        }
    }

    /// The operation this flow approves, if it approves one.
    pub(super) fn operation(&self) -> Option<OpFlow> {
        match self {
            Then::Operation { workspace, op, issue, digest, parts } => Some(OpFlow {
                workspace: workspace.clone(),
                op: op.clone(),
                issue: issue.clone(),
                digest: digest.clone(),
                parts: *parts,
            }),
            Then::Authorize { .. } | Then::Gate { .. } => None,
        }
    }
}

/// An authorization before anyone signed in: choosing a provider, then
/// signing in there. Anyone may start one, so the server keeps none: it is
/// sealed ([`Sealer`]) into what the browser brings back, the link it
/// follows to choose, then a cookie of its own while at the provider, and
/// the client's request is checked again at each step.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Pending {
    /// What the sign-in is for.
    pub(super) then: Then,
    /// The hash of the browser's cookie.
    pub(super) browser: String,
    /// Until when it may go on (milliseconds since the epoch).
    pub(super) until: i64,
    /// At a provider: its name (`github`, or an `[oidc.<name>]`), the
    /// `state` it was sent, and this server's PKCE verifier and nonce there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) at: Option<AtProvider>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct AtProvider {
    pub(super) provider: String,
    pub(super) state: String,
    pub(super) verifier: String,
    pub(super) nonce: String,
}

/// Seals what the browser carries between steps (ChaCha20-Poly1305, a key
/// of this process's): what it brings back is what this server gave it,
/// unread and unchanged, for the step it was given for.
pub struct Sealer(ring::aead::LessSafeKey);

impl Sealer {
    pub(super) fn new() -> Sealer {
        let mut key = [0u8; 32];
        SecureRandom::fill(&SystemRandom::new(), &mut key).expect("the system's random number generator");
        let key = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).expect("a 32-byte key");
        Sealer(ring::aead::LessSafeKey::new(key))
    }

    /// `value`, sealed for `step`: base64url of a random nonce and the
    /// ciphertext. The AAD is `step` for an authorization, `gate:<step>` for
    /// a gate's approval and `op:<step>` for an operation's ([`aad`]).
    pub(super) fn seal(&self, step: &str, value: &Pending) -> Result<String, Error> {
        let mut nonce = [0u8; 12];
        SecureRandom::fill(&SystemRandom::new(), &mut nonce)
            .map_err(|_| Error::Io(std::io::Error::other("the system's random number generator failed")))?;
        let mut data = serde_json::to_vec(value)?;
        let aad = aad(step, value.then.kind());
        let aad = ring::aead::Aad::from(aad.as_bytes());
        self.0
            .seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce), aad, &mut data)
            .map_err(|_| Error::Io(std::io::Error::other("sealing a flow failed")))?;
        Ok(URL_SAFE_NO_PAD.encode([&nonce[..], &data].concat()))
    }

    /// What [`Sealer::seal`] sealed for `step`, if `sealed` is that: opened
    /// under each kind's AAD, and kept only if its kind is the one that AAD
    /// is for.
    pub(super) fn open(&self, step: &str, sealed: &str) -> Option<Pending> {
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        let (nonce, data) = bytes.split_at_checked(12)?;
        [Kind::Authorize, Kind::Gate, Kind::Operation].into_iter().find_map(|kind| {
            let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
            let mut data = data.to_vec();
            let aad = aad(step, kind);
            let plain = self.0.open_in_place(nonce, ring::aead::Aad::from(aad.as_bytes()), &mut data).ok()?;
            let pending: Pending = serde_json::from_slice(plain).ok()?;
            (pending.then.kind() == kind).then_some(pending)
        })
    }
}

/// The AAD a flow of `kind` is sealed with for `step`: the step itself for
/// an authorization (as before gates had flows), `gate:<step>` for a
/// gate's, `op:<step>` for an operation's.
fn aad(step: &str, kind: Kind) -> String {
    match kind {
        Kind::Authorize => step.to_string(),
        Kind::Gate => format!("gate:{step}"),
        Kind::Operation => format!("op:{step}"),
    }
}

pub(super) fn now_millis() -> i64 {
    bd_core::Timestamp::now().millis()
}

/// Waiting for a decision on the consent page.
pub(super) struct Consent {
    pub(super) request: Authorization,
    pub(super) admitted: Admitted,
    pub(super) actor: String,
    /// The hash of the value of its own cookie ([`consent_cookie`]).
    pub(super) browser: String,
    /// What names its cookie.
    pub(super) cookie: String,
}

/// A human gate's approval page, shown to a person the rules let in:
/// waiting for its one POST ([`super::gate::approve`]).
#[derive(Debug)]
pub(super) struct Approval {
    pub(super) workspace: String,
    pub(super) gate: String,
    /// The actor it is recorded as: the account's, bound at the sign-in.
    pub(super) actor: String,
    /// The account, for the log: its provider, login and subject (never an email).
    pub(super) provider: String,
    pub(super) login: String,
    pub(super) subject: String,
    /// The account's verified `oidc:sha256:` approver reference, from the
    /// identity its provider proved (`auth::Identity::oidc_approver`), None
    /// for a GitHub account. Never logged.
    pub(super) oidc_approver: Option<String>,
    /// The hash of the value of its own cookie ([`gate_cookie`]).
    pub(super) browser: String,
    /// What names its cookie.
    pub(super) cookie: String,
}

/// The approval page of a close or discard that human gates refused, shown
/// to a person who may approve it: waiting for its one POST
/// (`super::operation::approve`).
#[derive(Debug)]
pub(super) struct OperationApproval {
    /// The sealed request, as opened at the sign-in: what the approval performs.
    pub(super) request: bd_cli::approval_link::OperationRequest,
    /// The account, for the log: its provider, login and subject (never an email).
    pub(super) provider: String,
    pub(super) login: String,
    pub(super) subject: String,
    /// The actor it is recorded as: the account's, bound at the sign-in.
    pub(super) actor: String,
    /// The account's verified `oidc:sha256:` approver reference, None for a
    /// GitHub account. Never logged.
    pub(super) oidc_approver: Option<String>,
    /// The hash of the value of its own cookie (`op_cookie`).
    pub(super) browser: String,
    /// What names its cookie.
    pub(super) cookie: String,
}

/// Authorizations under way, by the hash of their secret at each step
/// (`state` at GitHub, the consent id, the code, the approval id, the
/// operation approval id); each taken once.
pub struct Flows {
    pub(super) sealer: Sealer,
    pub(super) consents: Kept<Consent>,
    pub(super) codes: Kept<Code>,
    /// Gate approval pages waiting for their POST, and those posted (for
    /// [`STEP_TTL`] after: one posted again is told it was used).
    pub(super) approvals: Kept<Approval>,
    pub(super) approvals_spent: Kept<()>,
    /// Operation approval pages waiting for their POST, and those posted.
    pub(super) operations: Kept<OperationApproval>,
    pub(super) operations_spent: Kept<()>,
    /// Codes redeemed, for [`CODE_TTL`] after: one sent again revokes the
    /// token it issued (RFC 6749 section 4.1.2).
    spent: Kept<Spent>,
}

/// A code redeemed.
struct Spent {
    /// Its client and PKCE challenge: only a client proving them by sending
    /// it again has its token revoked.
    client_id: String,
    challenge: String,
    /// The id of the token it issued, once issued.
    token: Option<String>,
    /// Whether it was sent again.
    again: bool,
    /// When the code would have expired, had it not been redeemed.
    until: Instant,
}

/// What a code sent to the token endpoint is.
#[derive(Debug)]
pub enum Redeemed {
    /// Not redeemed before: what it stands for.
    Fresh(Box<Code>),
    /// Redeemed already, and the id of the token it issued, if it did yet.
    Again(Option<String>),
    /// Unknown, or expired.
    Unknown,
}

impl Default for Flows {
    fn default() -> Flows {
        Flows {
            sealer: Sealer::new(),
            consents: Kept::new(STEP_TTL),
            codes: Kept::new(CODE_TTL),
            spent: Kept::new(CODE_TTL),
            approvals: Kept::new(STEP_TTL),
            approvals_spent: Kept::new(STEP_TTL),
            operations: Kept::new(STEP_TTL),
            operations_spent: Kept::new(STEP_TTL),
        }
    }
}

impl Flows {
    /// Redeem `code`: what it stands for the first time, if it has not
    /// expired; after that, the token it issued.
    pub fn redeem(&mut self, code: &str, client_id: &str, verifier: &str) -> Redeemed {
        let key = auth::hash(code);
        if let Some((until, found)) = self.codes.take_entry(&key) {
            let (client_id, challenge) = (found.client_id.clone(), found.challenge.clone());
            self.spent.put(key, Spent { client_id, challenge, token: None, again: false, until });
            return Redeemed::Fresh(Box::new(found));
        }
        match self.spent.get_mut(&key) {
            // Its own client sending it again (RFC 6749 section 4.1.2): whoever redeemed it first is not to be trusted.
            Some(spent) if spent.client_id == client_id && s256(verifier) == spent.challenge => {
                spent.again = true;
                Redeemed::Again(spent.token.clone())
            }
            // Anyone else who saw the code may not end the session it started.
            Some(_) => Redeemed::Again(None),
            None => Redeemed::Unknown,
        }
    }

    /// Undo [`Flows::redeem`] of `code`, which stands for `found`, when
    /// it issued no token: it can be redeemed again until it expires, unless
    /// it was sent again meanwhile.
    pub fn unredeem(&mut self, code: &str, found: Code) {
        let key = auth::hash(code);
        let Some(spent) = self.spent.get_mut(&key) else { return };
        if spent.again || spent.token.is_some() {
            return;
        }
        let until = spent.until;
        self.spent.map.remove(&key);
        if until > Instant::now() {
            self.codes.put_until(key, until, found);
        }
    }

    /// Record that `code` issued the token `id`: whether the code was sent
    /// again meanwhile, so that the token must go.
    pub fn issued(&mut self, code: &str, id: &str) -> bool {
        match self.spent.get_mut(&auth::hash(code)) {
            Some(spent) => {
                spent.token = Some(id.to_string());
                spent.again
            }
            None => false,
        }
    }
}

/// Values that expire, at most [`MAX_FLOWS`] of them.
pub(super) struct Kept<T> {
    ttl: Duration,
    pub(super) map: HashMap<String, (Instant, T)>,
}

impl<T> Kept<T> {
    pub(super) fn new(ttl: Duration) -> Kept<T> {
        Kept { ttl, map: HashMap::new() }
    }

    pub(super) fn put(&mut self, key: String, value: T) {
        self.put_until(key, Instant::now() + self.ttl, value);
    }

    /// [`Kept::put`], expiring at `until`.
    pub(super) fn put_until(&mut self, key: String, until: Instant, value: T) {
        let now = Instant::now();
        if self.map.len() >= MAX_FLOWS {
            self.map.retain(|_, (until, _)| *until > now);
        }
        if self.map.len() >= MAX_FLOWS {
            let oldest = self.map.iter().min_by_key(|(_, (until, _))| *until).map(|(k, _)| k.clone());
            self.map.remove(&oldest.unwrap_or_default());
        }
        self.map.insert(key, (until, value));
    }

    pub(super) fn take(&mut self, key: &str) -> Option<T> {
        self.take_entry(key).map(|(_, value)| value)
    }

    /// [`Kept::take`], with when it would have expired.
    fn take_entry(&mut self, key: &str) -> Option<(Instant, T)> {
        let (until, value) = self.map.remove(key)?;
        (until > Instant::now()).then_some((until, value))
    }

    pub(super) fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        let now = Instant::now();
        self.map.get_mut(key).filter(|(until, _)| *until > now).map(|(_, value)| value)
    }
}

pub fn lock(flows: &Mutex<Flows>) -> std::sync::MutexGuard<'_, Flows> {
    flows.lock().unwrap_or_else(|e| e.into_inner())
}

/// The S256 PKCE challenge of `verifier` (RFC 7636 section 4.2).
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
