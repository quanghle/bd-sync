//! WebAuthn passkeys for the browser approval pages, verified with `ring`
//! alone: no CBOR, no COSE keys, no attestation. Registration takes the
//! public key the browser's `getPublicKey()` gives (SPKI DER, ES256 or
//! RS256) and reads the authenticator data only up to the credential id,
//! which must equal the credential's `rawId`; whatever follows is ignored.
//! Assertions are checked against the stored SPKI. Both check the client
//! data (type, challenge, origin, `crossOrigin`, the absence of
//! `topOrigin`), the relying party's hash and the user present and user
//! verified flags. Every input is capped in decoded bytes (`MAX_*`) and read
//! without indexing, so a short or hostile one is refused, never a panic.
//! Pure: no I/O, no clock, no storage.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::signature::{ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use serde::{Deserialize, Deserializer};

/// The longest credential id accepted, in bytes (WebAuthn's limit).
pub const MAX_CREDENTIAL: usize = 1023;
/// The longest `clientDataJSON` accepted, in bytes.
pub const MAX_CLIENT_DATA: usize = 2048;
/// The longest authenticator data accepted, in bytes.
pub const MAX_AUTH_DATA: usize = 1024;
/// The longest SPKI public key accepted, in bytes (an RSA-4096 key fits).
pub const MAX_PUBLIC_KEY: usize = 600;
/// The longest signature accepted, in bytes (an RSA-4096 one fits).
pub const MAX_SIGNATURE: usize = 600;

/// The most characters `raw` bytes take in unpadded base64url.
pub const fn encoded_len(raw: usize) -> usize {
    (4 * raw).div_ceil(3)
}

/// Authenticator data flags.
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

/// A passkey's signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    Rs256,
}

impl Alg {
    /// The COSE algorithm identifier.
    pub fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::Rs256 => -257,
        }
    }

    /// The algorithm a COSE identifier names, if supported.
    pub fn from_cose(id: i64) -> Option<Alg> {
        match id {
            -7 => Some(Alg::Es256),
            -257 => Some(Alg::Rs256),
            _ => None,
        }
    }

    /// The algorithm's JOSE name, as logs and events show it.
    pub fn name(self) -> &'static str {
        match self {
            Alg::Es256 => "ES256",
            Alg::Rs256 => "RS256",
        }
    }
}

/// What a ceremony must match: the approval's challenge, the expected
/// origin (`authorize::origin` of the issuer) and the relying party id.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    pub challenge: &'a [u8],
    pub origin: &'a str,
    pub rp_id: &'a str,
}

/// A `navigator.credentials.create()` answer, decoded.
#[derive(Debug, Clone, Copy)]
pub struct Registration<'a> {
    /// The credential's `rawId`.
    pub credential: &'a [u8],
    pub client_data: &'a [u8],
    pub authenticator_data: &'a [u8],
    /// `getPublicKey()`: SPKI DER.
    pub public_key: &'a [u8],
    /// `getPublicKeyAlgorithm()`: a COSE identifier.
    pub algorithm: i64,
}

/// A registration that passed: what to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    pub credential: Vec<u8>,
    pub alg: Alg,
    /// SPKI DER.
    pub public_key: Vec<u8>,
    pub counter: u32,
}

/// A `navigator.credentials.get()` answer, decoded.
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    pub client_data: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
}

/// A stored passkey, as an assertion is checked against it.
#[derive(Debug, Clone, Copy)]
pub struct Stored<'a> {
    pub alg: Alg,
    /// SPKI DER.
    pub public_key: &'a [u8],
    pub counter: u32,
}

/// Why a ceremony was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    ClientDataTooLong,
    ClientDataUnreadable,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    CrossOrigin,
    TopOrigin,
    AuthDataMalformed,
    WrongRpId,
    UserNotPresent,
    UserNotVerified,
    NoCredentialData,
    CredentialMismatch,
    UnsupportedAlgorithm,
    BadPublicKey,
    BadSignature,
    CounterRegression,
}

impl Refusal {
    /// A short fixed description, for logs and records.
    pub fn label(self) -> &'static str {
        match self {
            Refusal::ClientDataTooLong => "client data too long",
            Refusal::ClientDataUnreadable => "client data unreadable",
            Refusal::WrongType => "wrong ceremony type",
            Refusal::WrongChallenge => "wrong challenge",
            Refusal::WrongOrigin => "wrong origin",
            Refusal::CrossOrigin => "cross-origin",
            Refusal::TopOrigin => "top origin present",
            Refusal::AuthDataMalformed => "authenticator data malformed",
            Refusal::WrongRpId => "wrong relying party",
            Refusal::UserNotPresent => "user not present",
            Refusal::UserNotVerified => "user not verified",
            Refusal::NoCredentialData => "no credential data",
            Refusal::CredentialMismatch => "credential mismatch",
            Refusal::UnsupportedAlgorithm => "unsupported algorithm",
            Refusal::BadPublicKey => "bad public key",
            Refusal::BadSignature => "bad signature",
            Refusal::CounterRegression => "counter regression",
        }
    }
}

/// Why an issuer cannot be a WebAuthn relying party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRp {
    /// The host is an IP address: browsers refuse those as RP ids.
    IpLiteral,
    /// Neither https nor http on localhost.
    NotSecure,
}

impl NoRp {
    /// A short fixed description, for logs.
    pub fn label(self) -> &'static str {
        match self {
            NoRp::IpLiteral => "ip address",
            NoRp::NotSecure => "not https",
        }
    }
}

/// The relying party id of an issuer URL: its host, lowercased, without
/// port; refused for an IP address, and for http on a host other than
/// localhost.
pub fn rp_id(issuer: &str) -> Result<String, NoRp> {
    let (scheme, rest) = issuer.split_once("://").ok_or(NoRp::NotSecure)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        return Err(NoRp::IpLiteral);
    }
    let host = authority.rsplit_once(':').map_or(authority, |(host, _)| host).to_ascii_lowercase();
    if host.is_empty() {
        return Err(NoRp::NotSecure);
    }
    if is_ip(&host) {
        return Err(NoRp::IpLiteral);
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(host),
        "http" if host == "localhost" => Ok(host),
        _ => Err(NoRp::NotSecure),
    }
}

/// Whether a host is an IPv4 address, as a URL parser reads one: its last
/// label numeric (decimal or `0x` hex) makes the whole host an address.
fn is_ip(host: &str) -> bool {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    let last = host.strip_suffix('.').unwrap_or(host).rsplit('.').next().unwrap_or_default();
    let hex = last.strip_prefix("0x").map(|h| h.chars().all(|c| c.is_ascii_hexdigit()));
    !last.is_empty() && (last.chars().all(|c| c.is_ascii_digit()) || hex == Some(true))
}

/// Checks a registration and returns the passkey to store.
pub fn verify_registration(expect: &Expect, reg: &Registration) -> Result<NewPasskey, Refusal> {
    caps(reg.client_data, reg.authenticator_data)?;
    if reg.credential.is_empty() || reg.credential.len() > MAX_CREDENTIAL {
        return Err(Refusal::CredentialMismatch);
    }
    if reg.public_key.len() > MAX_PUBLIC_KEY {
        return Err(Refusal::BadPublicKey);
    }
    client_data(reg.client_data, "webauthn.create", expect)?;
    let auth = auth_data(reg.authenticator_data)?;
    auth.check(expect.rp_id)?;
    let id = auth.credential.ok_or(Refusal::NoCredentialData)?;
    if id != reg.credential {
        return Err(Refusal::CredentialMismatch);
    }
    let alg = Alg::from_cose(reg.algorithm).ok_or(Refusal::UnsupportedAlgorithm)?;
    spki(reg.public_key, alg).ok_or(Refusal::BadPublicKey)?;
    Ok(NewPasskey { credential: id.to_vec(), alg, public_key: reg.public_key.to_vec(), counter: auth.counter })
}

/// Checks an assertion against a stored passkey and returns its new
/// signature counter.
pub fn verify_assertion(expect: &Expect, stored: &Stored, assertion: &Assertion) -> Result<u32, Refusal> {
    caps(assertion.client_data, assertion.authenticator_data)?;
    if assertion.signature.len() > MAX_SIGNATURE {
        return Err(Refusal::BadSignature);
    }
    client_data(assertion.client_data, "webauthn.get", expect)?;
    let auth = auth_data(assertion.authenticator_data)?;
    auth.check(expect.rp_id)?;
    let key = spki(stored.public_key, stored.alg).ok_or(Refusal::BadPublicKey)?;
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(assertion.authenticator_data);
    signed.extend_from_slice(digest(&SHA256, assertion.client_data).as_ref());
    let params: &dyn ring::signature::VerificationAlgorithm = match stored.alg {
        Alg::Es256 => &ECDSA_P256_SHA256_ASN1,
        Alg::Rs256 => &RSA_PKCS1_2048_8192_SHA256,
    };
    UnparsedPublicKey::new(params, key).verify(&signed, assertion.signature).map_err(|_| Refusal::BadSignature)?;
    if stored.counter != 0 && auth.counter <= stored.counter {
        return Err(Refusal::CounterRegression);
    }
    Ok(auth.counter)
}

/// The caps both ceremonies share, checked before any parsing.
fn caps(client_data: &[u8], authenticator_data: &[u8]) -> Result<(), Refusal> {
    if client_data.len() > MAX_CLIENT_DATA {
        return Err(Refusal::ClientDataTooLong);
    }
    if authenticator_data.len() > MAX_AUTH_DATA {
        return Err(Refusal::AuthDataMalformed);
    }
    Ok(())
}

/// The members of `clientDataJSON` that are checked; others are ignored, as
/// browsers add some on purpose. A known member given twice is refused.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", default, deserialize_with = "present")]
    top_origin: bool,
}

/// True for any value, `null` included: only presence counts.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d)?;
    Ok(true)
}

fn client_data(bytes: &[u8], kind: &str, expect: &Expect) -> Result<(), Refusal> {
    if bytes.len() > MAX_CLIENT_DATA {
        return Err(Refusal::ClientDataTooLong);
    }
    let data: ClientData = serde_json::from_slice(bytes).map_err(|_| Refusal::ClientDataUnreadable)?;
    if data.kind != kind {
        return Err(Refusal::WrongType);
    }
    if data.challenge != URL_SAFE_NO_PAD.encode(expect.challenge) {
        return Err(Refusal::WrongChallenge);
    }
    if data.origin != expect.origin {
        return Err(Refusal::WrongOrigin);
    }
    if data.cross_origin == Some(true) {
        return Err(Refusal::CrossOrigin);
    }
    if data.top_origin {
        return Err(Refusal::TopOrigin);
    }
    Ok(())
}

/// The parts of authenticator data that are read.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    counter: u32,
    /// The attested credential's id, when the AT flag is set.
    credential: Option<&'a [u8]>,
}

impl AuthData<'_> {
    fn check(&self, rp_id: &str) -> Result<(), Refusal> {
        if self.rp_id_hash != digest(&SHA256, rp_id.as_bytes()).as_ref() {
            return Err(Refusal::WrongRpId);
        }
        if self.flags & UP == 0 {
            return Err(Refusal::UserNotPresent);
        }
        if self.flags & UV == 0 {
            return Err(Refusal::UserNotVerified);
        }
        Ok(())
    }
}

/// Reads authenticator data up to the credential id; what follows (the
/// COSE key, extensions) is ignored.
fn auth_data(bytes: &[u8]) -> Result<AuthData<'_>, Refusal> {
    const M: Refusal = Refusal::AuthDataMalformed;
    if bytes.len() > MAX_AUTH_DATA {
        return Err(M);
    }
    let (rp_id_hash, rest) = bytes.split_at_checked(32).ok_or(M)?;
    let (&flags, rest) = rest.split_first().ok_or(M)?;
    let (counter, rest) = rest.split_first_chunk::<4>().ok_or(M)?;
    let counter = u32::from_be_bytes(*counter);
    let credential = if flags & AT != 0 {
        let (_aaguid, rest) = rest.split_at_checked(16).ok_or(M)?;
        let (len, rest) = rest.split_first_chunk::<2>().ok_or(M)?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len == 0 || len > MAX_CREDENTIAL {
            return Err(M);
        }
        let (id, _key) = rest.split_at_checked(len).ok_or(M)?;
        Some(id)
    } else {
        None
    };
    Ok(AuthData { rp_id_hash, flags, counter, credential })
}

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;
const NULL: u8 = 0x05;
const BIT_STRING: u8 = 0x03;
const INTEGER: u8 = 0x02;
/// 1.2.840.10045.2.1
const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// 1.2.840.10045.3.1.7
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// 1.2.840.113549.1.1.1
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// One DER element of `tag`: its content and what follows. Definite,
/// minimal lengths of at most two bytes only.
fn tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first()?;
            (b >= 0x80).then_some((usize::from(b), rest))?
        }
        0x82 => {
            let (b, rest) = rest.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*b));
            (len >= 0x100).then_some((len, rest))?
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}

/// The key bytes `ring` verifies with, from an SPKI of `alg`: the
/// uncompressed P-256 point, or the PKCS#1 RSAPublicKey. Nothing may trail
/// at any level.
fn spki(der: &[u8], alg: Alg) -> Option<&[u8]> {
    if der.len() > MAX_PUBLIC_KEY {
        return None;
    }
    let (spki, rest) = tlv(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (algorithm, rest) = tlv(spki, SEQUENCE)?;
    let (bits, rest) = tlv(rest, BIT_STRING)?;
    if !rest.is_empty() {
        return None;
    }
    let (oid, params) = tlv(algorithm, OID)?;
    let key = bits.strip_prefix(&[0])?;
    match alg {
        Alg::Es256 => {
            let (curve, rest) = tlv(params, OID)?;
            if oid != ID_EC_PUBLIC_KEY || curve != PRIME256V1 || !rest.is_empty() {
                return None;
            }
            (key.len() == 65 && key.first() == Some(&0x04)).then_some(key)
        }
        Alg::Rs256 => {
            let (null, rest) = tlv(params, NULL)?;
            if oid != RSA_ENCRYPTION || !null.is_empty() || !rest.is_empty() {
                return None;
            }
            let (pkcs1, rest) = tlv(key, SEQUENCE)?;
            if !rest.is_empty() {
                return None;
            }
            let (modulus, rest) = tlv(pkcs1, INTEGER)?;
            let (exponent, rest) = tlv(rest, INTEGER)?;
            let modulus = modulus.strip_prefix(&[0]).unwrap_or(modulus);
            // ring verifies 2048 to 8192 bits only: a smaller key could never approve.
            (rest.is_empty() && !exponent.is_empty() && modulus.len() >= 256).then_some(key)
        }
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A software authenticator: ES256 keys from ring, RS256 with the test
    //! fixture key, and the raw fields a browser would send.

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::digest::{SHA256, digest};
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

    use super::{Alg, Assertion, Expect, Registration};

    enum Pair {
        Es256(EcdsaKeyPair),
        Rs256(RsaKeyPair),
    }

    /// A key pair and its 32-byte credential id.
    pub(crate) struct SoftKey {
        pair: Pair,
        pub(crate) credential: Vec<u8>,
    }

    /// Changes to an otherwise valid ceremony.
    #[derive(Default, Clone)]
    pub(crate) struct Tamper {
        pub(crate) kind: Option<&'static str>,
        pub(crate) challenge: Option<Vec<u8>>,
        pub(crate) origin: Option<String>,
        pub(crate) cross_origin: Option<bool>,
        /// Raw JSON for a `topOrigin` member; none when unset.
        pub(crate) top_origin: Option<&'static str>,
        pub(crate) flags: Option<u8>,
        pub(crate) rp_id: Option<String>,
        /// A `rawId` other than the authenticator data's credential id.
        pub(crate) mismatch: bool,
        pub(crate) counter: Option<u32>,
        /// Bytes after the credential id in registration authenticator data.
        pub(crate) cose: Option<Vec<u8>>,
        /// A second `challenge` member.
        pub(crate) duplicate: bool,
    }

    /// The raw fields of a ceremony.
    #[derive(Debug, Clone)]
    pub(crate) struct Fields {
        pub(crate) credential: Vec<u8>,
        pub(crate) client_data: Vec<u8>,
        pub(crate) authenticator_data: Vec<u8>,
        pub(crate) public_key: Vec<u8>,
        pub(crate) algorithm: i64,
        pub(crate) signature: Vec<u8>,
    }

    impl Fields {
        pub(crate) fn registration(&self) -> Registration<'_> {
            Registration {
                credential: &self.credential,
                client_data: &self.client_data,
                authenticator_data: &self.authenticator_data,
                public_key: &self.public_key,
                algorithm: self.algorithm,
            }
        }

        pub(crate) fn assertion(&self) -> Assertion<'_> {
            Assertion {
                client_data: &self.client_data,
                authenticator_data: &self.authenticator_data,
                signature: &self.signature,
            }
        }
    }

    fn random(n: usize) -> Vec<u8> {
        let mut bytes = vec![0; n];
        SystemRandom::new().fill(&mut bytes).unwrap();
        bytes
    }

    /// A DER element of `tag` around `content`.
    pub(crate) fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n @ 0..=0x7f => out.push(n as u8),
            n @ 0x80..=0xff => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// An SPKI around `key` with the algorithm identifier `algorithm`.
    pub(crate) fn spki_of(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        let mut bits = vec![0];
        bits.extend_from_slice(key);
        der(0x30, &[der(0x30, algorithm), der(0x03, &bits)].concat())
    }

    pub(crate) fn ec_algorithm() -> Vec<u8> {
        [der(0x06, super::ID_EC_PUBLIC_KEY), der(0x06, super::PRIME256V1)].concat()
    }

    pub(crate) fn rsa_algorithm() -> Vec<u8> {
        [der(0x06, super::RSA_ENCRYPTION), der(0x05, &[])].concat()
    }

    /// A 77-byte COSE EC2 key for a P-256 point, as authenticators append it.
    pub(crate) fn cose_es256(point: &[u8]) -> Vec<u8> {
        let (x, y) = point[1..].split_at(32);
        [&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20][..], x, &[0x22, 0x58, 0x20], y].concat()
    }

    impl SoftKey {
        pub(crate) fn es256() -> SoftKey {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            SoftKey { pair: Pair::Es256(pair), credential: random(32) }
        }

        pub(crate) fn rs256() -> SoftKey {
            SoftKey { pair: Pair::Rs256(crate::oidc::tests::rsa()), credential: random(32) }
        }

        pub(crate) fn alg(&self) -> Alg {
            match self.pair {
                Pair::Es256(_) => Alg::Es256,
                Pair::Rs256(_) => Alg::Rs256,
            }
        }

        /// The raw public key: the P-256 point, or the PKCS#1 RSAPublicKey.
        pub(crate) fn raw_public(&self) -> Vec<u8> {
            match &self.pair {
                Pair::Es256(p) => p.public_key().as_ref().to_vec(),
                Pair::Rs256(p) => p.public_key().as_ref().to_vec(),
            }
        }

        /// The public key as `getPublicKey()` gives it.
        pub(crate) fn spki(&self) -> Vec<u8> {
            match self.pair {
                Pair::Es256(_) => spki_of(&ec_algorithm(), &self.raw_public()),
                Pair::Rs256(_) => spki_of(&rsa_algorithm(), &self.raw_public()),
            }
        }

        pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match &self.pair {
                Pair::Es256(p) => p.sign(&rng, message).unwrap().as_ref().to_vec(),
                Pair::Rs256(p) => {
                    let mut signature = vec![0; p.public().modulus_len()];
                    p.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature).unwrap();
                    signature
                }
            }
        }

        /// A registration ceremony, as `create()` answers it.
        pub(crate) fn register(&self, expect: &Expect, t: &Tamper) -> Fields {
            let client_data = client_data(expect, "webauthn.create", t);
            let mut auth = head(expect, t.flags.unwrap_or(0x45), t.counter.unwrap_or(0), t);
            auth.extend_from_slice(&[0; 16]);
            auth.extend_from_slice(&(self.credential.len() as u16).to_be_bytes());
            auth.extend_from_slice(&self.credential);
            if let Some(cose) = &t.cose {
                auth.extend_from_slice(cose);
            }
            let mut credential = self.credential.clone();
            if t.mismatch
                && let Some(last) = credential.last_mut()
            {
                *last ^= 1;
            }
            Fields {
                credential,
                client_data,
                authenticator_data: auth,
                public_key: self.spki(),
                algorithm: self.alg().cose(),
                signature: Vec::new(),
            }
        }

        /// An assertion ceremony, as `get()` answers it.
        pub(crate) fn assert(&self, expect: &Expect, counter: u32, t: &Tamper) -> Fields {
            let client_data = client_data(expect, "webauthn.get", t);
            let auth = head(expect, t.flags.unwrap_or(0x05), t.counter.unwrap_or(counter), t);
            let mut signed = auth.clone();
            signed.extend_from_slice(digest(&SHA256, &client_data).as_ref());
            Fields {
                credential: self.credential.clone(),
                signature: self.sign(&signed),
                client_data,
                authenticator_data: auth,
                public_key: Vec::new(),
                algorithm: 0,
            }
        }
    }

    fn head(expect: &Expect, flags: u8, counter: u32, t: &Tamper) -> Vec<u8> {
        let rp = t.rp_id.as_deref().unwrap_or(expect.rp_id);
        let mut auth = digest(&SHA256, rp.as_bytes()).as_ref().to_vec();
        auth.push(flags);
        auth.extend_from_slice(&counter.to_be_bytes());
        auth
    }

    fn client_data(expect: &Expect, kind: &str, t: &Tamper) -> Vec<u8> {
        let challenge = URL_SAFE_NO_PAD.encode(t.challenge.as_deref().unwrap_or(expect.challenge));
        let json = |s: &str| serde_json::Value::from(s).to_string();
        let mut out = format!(
            "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":{}",
            json(t.kind.unwrap_or(kind)),
            json(&challenge),
            json(t.origin.as_deref().unwrap_or(expect.origin)),
            t.cross_origin.unwrap_or(false),
        );
        if t.duplicate {
            out.push_str(&format!(",\"challenge\":{}", json(&URL_SAFE_NO_PAD.encode([7u8; 32]))));
        }
        if let Some(top) = t.top_origin {
            out.push_str(&format!(",\"topOrigin\":{top}"));
        }
        out.push_str(",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template\"}");
        out.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{Fields, SoftKey, Tamper, cose_es256, der, ec_algorithm, rsa_algorithm, spki_of};
    use super::*;

    const ORIGIN: &str = "https://bd.example.com";
    const RP: &str = "bd.example.com";
    const CHALLENGE: [u8; 32] = [42; 32];

    fn expect() -> Expect<'static> {
        Expect { challenge: &CHALLENGE, origin: ORIGIN, rp_id: RP }
    }

    fn register(key: &SoftKey, t: Tamper) -> Result<NewPasskey, Refusal> {
        verify_registration(&expect(), &key.register(&expect(), &t).registration())
    }

    fn assert_with(key: &SoftKey, stored: u32, counter: u32, t: Tamper) -> Result<u32, Refusal> {
        let spki = key.spki();
        let stored = Stored { alg: key.alg(), public_key: &spki, counter: stored };
        verify_assertion(&expect(), &stored, &key.assert(&expect(), counter, &t).assertion())
    }

    #[test]
    fn relying_party_ids_are_hosts_named_over_https() {
        assert_eq!(rp_id("https://bd.example.com/bd").unwrap(), "bd.example.com");
        assert_eq!(rp_id("https://BD.example.com:8443/x").unwrap(), "bd.example.com");
        assert_eq!(rp_id("http://localhost:7420").unwrap(), "localhost");
        assert_eq!(rp_id("HTTPS://bd.example.com?x#y").unwrap(), "bd.example.com");
        for ip in ["http://127.0.0.1:7420", "http://[::1]:7420", "https://10.0.0.1", "https://[2001:db8::1]/bd"] {
            assert_eq!(rp_id(ip), Err(NoRp::IpLiteral), "{ip}");
        }
        for numeric in ["https://0x7f.1", "https://2130706433", "https://example.123"] {
            assert_eq!(rp_id(numeric), Err(NoRp::IpLiteral), "{numeric}");
        }
        for insecure in ["http://bd.example.com", "ftp://bd.example.com", "bd.example.com", "https://", "https://:443"]
        {
            assert_eq!(rp_id(insecure), Err(NoRp::NotSecure), "{insecure}");
        }
        assert_ne!(NoRp::IpLiteral.label(), NoRp::NotSecure.label());
    }

    #[test]
    fn registrations_of_both_algorithms_are_accepted() {
        for key in [SoftKey::es256(), SoftKey::rs256()] {
            let passkey = register(&key, Tamper { counter: Some(3), ..Tamper::default() }).unwrap();
            assert_eq!(passkey.credential, key.credential);
            assert_eq!(passkey.alg, key.alg());
            assert_eq!(passkey.public_key, key.spki());
            assert_eq!(passkey.counter, 3);
        }
        let key = SoftKey::es256();
        let cose = cose_es256(&key.raw_public());
        assert_eq!(cose.len(), 77);
        assert!(register(&key, Tamper { cose: Some(cose), ..Tamper::default() }).is_ok());
    }

    #[test]
    fn each_tampered_registration_is_refused_for_its_reason() {
        use Refusal::*;
        let key = SoftKey::es256();
        let cases: Vec<(Tamper, Refusal)> = vec![
            (Tamper { kind: Some("webauthn.get"), ..Tamper::default() }, WrongType),
            (Tamper { challenge: Some(vec![1; 32]), ..Tamper::default() }, WrongChallenge),
            (Tamper { origin: Some("https://evil.example".into()), ..Tamper::default() }, WrongOrigin),
            (Tamper { origin: Some("https://bd.example.com:443".into()), ..Tamper::default() }, WrongOrigin),
            (Tamper { cross_origin: Some(true), ..Tamper::default() }, CrossOrigin),
            (Tamper { duplicate: true, ..Tamper::default() }, ClientDataUnreadable),
            (Tamper { rp_id: Some("example.com".into()), ..Tamper::default() }, WrongRpId),
            (Tamper { flags: Some(0x44), ..Tamper::default() }, UserNotPresent),
            (Tamper { flags: Some(0x41), ..Tamper::default() }, UserNotVerified),
            (Tamper { flags: Some(0x05), ..Tamper::default() }, NoCredentialData),
            (Tamper { mismatch: true, ..Tamper::default() }, CredentialMismatch),
        ];
        for (t, refusal) in cases {
            assert_eq!(register(&key, t), Err(refusal), "{refusal:?}");
        }
        for top in ["\"https://bd.example.com\"", "null", "1", "{}"] {
            assert_eq!(register(&key, Tamper { top_origin: Some(top), ..Tamper::default() }), Err(TopOrigin), "{top}");
        }

        let good = key.register(&expect(), &Tamper::default());
        let with = |f: &dyn Fn(&mut Fields)| {
            let mut fields = good.clone();
            f(&mut fields);
            verify_registration(&expect(), &fields.registration())
        };
        assert_eq!(with(&|f| f.algorithm = -8), Err(UnsupportedAlgorithm));
        assert_eq!(with(&|f| f.algorithm = Alg::Rs256.cose()), Err(BadPublicKey));
        assert_eq!(with(&|f| f.public_key = SoftKey::rs256().spki()), Err(BadPublicKey));
        assert_eq!(with(&|f| f.public_key.push(0)), Err(BadPublicKey));
        assert_eq!(with(&|f| f.client_data = vec![0xff, 0xfe]), Err(ClientDataUnreadable));
        assert_eq!(with(&|f| f.client_data = b"[]".to_vec()), Err(ClientDataUnreadable));
        assert_eq!(with(&|f| f.client_data = vec![b' '; MAX_CLIENT_DATA + 1]), Err(ClientDataTooLong));
        assert_eq!(with(&|f| f.authenticator_data.resize(MAX_AUTH_DATA + 1, 0)), Err(AuthDataMalformed));
        assert_eq!(with(&|f| f.credential.clear()), Err(CredentialMismatch));
        assert_eq!(with(&|f| f.credential = vec![1; MAX_CREDENTIAL + 1]), Err(CredentialMismatch));
        // A credential id length of zero in the authenticator data.
        assert_eq!(with(&|f| f.authenticator_data[53..55].copy_from_slice(&[0, 0])), Err(AuthDataMalformed));
        // A non-minimal length on the SPKI's outer SEQUENCE.
        let spki = key.spki();
        let mut long = vec![0x30, 0x81];
        long.extend_from_slice(&spki[1..]);
        assert_eq!(spki[1], 0x59);
        assert_eq!(with(&|f| f.public_key = long.clone()), Err(BadPublicKey));
    }

    #[test]
    fn an_omitted_top_origin_is_accepted_and_any_present_one_refused_in_assertions() {
        let key = SoftKey::es256();
        assert_eq!(assert_with(&key, 0, 1, Tamper::default()), Ok(1));
        for top in ["\"https://bd.example.com\"", "null", "1", "{\"a\":[]}"] {
            let t = Tamper { top_origin: Some(top), ..Tamper::default() };
            assert_eq!(assert_with(&key, 0, 1, t), Err(Refusal::TopOrigin), "{top}");
        }
    }

    #[test]
    fn der_lengths_are_definite_and_minimal() {
        assert_eq!(tlv(&[0x30, 0x01, 0xaa, 0xbb], 0x30), Some((&[0xaa][..], &[0xbb][..])));
        assert_eq!(tlv(&[0x30, 0x01, 0xaa], 0x02), None);
        assert_eq!(tlv(&[0x30, 0x80, 0xaa, 0, 0], 0x30), None);
        assert_eq!(tlv(&[0x30, 0x81, 0x7f], 0x30), None);
        assert_eq!(tlv(&[0x30, 0x82, 0x00, 0xff], 0x30), None);
        assert_eq!(tlv(&[0x30, 0x83, 0, 0, 1, 0], 0x30), None);
        assert_eq!(tlv(&[0x30, 0x02, 0xaa], 0x30), None);
        let content = vec![1; 0x80];
        let element = der(0x04, &content);
        assert_eq!(&element[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(tlv(&element, 0x04), Some((&content[..], &[][..])));
        let content = vec![1; 0x100];
        let element = der(0x04, &content);
        assert_eq!(&element[..4], &[0x04, 0x82, 0x01, 0x00]);
        assert_eq!(tlv(&element, 0x04), Some((&content[..], &[][..])));
    }

    #[test]
    fn spki_readers_take_only_their_algorithm() {
        let ec = SoftKey::es256();
        let rsa = SoftKey::rs256();
        assert_eq!(spki(&ec.spki(), Alg::Es256), Some(&ec.raw_public()[..]));
        assert_eq!(spki(&rsa.spki(), Alg::Rs256), Some(&rsa.raw_public()[..]));
        assert_eq!(spki(&ec.spki(), Alg::Rs256), None);
        assert_eq!(spki(&rsa.spki(), Alg::Es256), None);
        // Each level refuses a trailing byte.
        let point = ec.raw_public();
        let trailing_algorithm = spki_of(&[ec_algorithm(), vec![0x05, 0x00]].concat(), &point);
        assert_eq!(spki(&trailing_algorithm, Alg::Es256), None);
        let mut trailing_bits = vec![0];
        trailing_bits.extend_from_slice(&point);
        let trailing_spki =
            der(0x30, &[der(0x30, &ec_algorithm()), der(0x03, &trailing_bits), vec![0x05, 0x00]].concat());
        assert_eq!(spki(&trailing_spki, Alg::Es256), None);
        let mut long_point = point.clone();
        long_point.push(0);
        assert_eq!(spki(&spki_of(&ec_algorithm(), &long_point), Alg::Es256), None);
        let mut compressed = point.clone();
        compressed[0] = 0x02;
        assert_eq!(spki(&spki_of(&ec_algorithm(), &compressed), Alg::Es256), None);
        // RSA: NULL params only, two INTEGERs, a modulus of at least 2048 bits.
        let pkcs1 = rsa.raw_public();
        let no_null = spki_of(&der(0x06, RSA_ENCRYPTION), &pkcs1);
        assert_eq!(spki(&no_null, Alg::Rs256), None);
        let small = der(0x30, &[der(0x02, &[0x00, 0xc1].repeat(64)), der(0x02, &[1, 0, 1])].concat());
        assert_eq!(spki(&spki_of(&rsa_algorithm(), &small), Alg::Rs256), None);
        let mut three = pkcs1.clone();
        three.extend_from_slice(&[0x02, 0x01, 0x01]);
        let (content, _) = tlv(&three, 0x30).unwrap();
        let three = der(0x30, &[content, &[0x02, 0x01, 0x01][..]].concat());
        assert_eq!(spki(&spki_of(&rsa_algorithm(), &three), Alg::Rs256), None);
    }

    /// A structurally valid RSA SPKI of exactly `len` bytes.
    fn rsa_spki_of_len(len: usize) -> Vec<u8> {
        (256..len)
            .map(|m| {
                let mut modulus = vec![0x00, 0xc1];
                modulus.resize(m, 0x01);
                let pkcs1 = der(0x30, &[der(0x02, &modulus), der(0x02, &[1, 0, 1])].concat());
                spki_of(&rsa_algorithm(), &pkcs1)
            })
            .find(|spki| spki.len() == len)
            .unwrap()
    }

    #[test]
    fn public_keys_and_signatures_are_capped_at_600_bytes() {
        assert_eq!(encoded_len(512), 683);
        assert_eq!(encoded_len(600), 800);
        assert_eq!(encoded_len(1023), 1364);
        assert_eq!(encoded_len(32), 43);

        let at_cap = rsa_spki_of_len(MAX_PUBLIC_KEY);
        assert!(spki(&at_cap, Alg::Rs256).is_some());
        assert_eq!(spki(&rsa_spki_of_len(MAX_PUBLIC_KEY + 1), Alg::Rs256), None);

        // The caps are checked before the client data: a key or signature at
        // the cap gets as far as the (wrong) challenge, one byte more does not.
        let key = SoftKey::es256();
        let wrong = Tamper { challenge: Some(vec![1; 32]), ..Tamper::default() };
        let mut fields = key.register(&expect(), &wrong);
        fields.public_key = vec![0; MAX_PUBLIC_KEY];
        assert_eq!(verify_registration(&expect(), &fields.registration()), Err(Refusal::WrongChallenge));
        fields.public_key.push(0);
        assert_eq!(verify_registration(&expect(), &fields.registration()), Err(Refusal::BadPublicKey));

        let spki = key.spki();
        let stored = Stored { alg: Alg::Es256, public_key: &spki, counter: 0 };
        let mut fields = key.assert(&expect(), 1, &wrong);
        fields.signature = vec![0; MAX_SIGNATURE];
        assert_eq!(verify_assertion(&expect(), &stored, &fields.assertion()), Err(Refusal::WrongChallenge));
        fields.signature.push(0);
        assert_eq!(verify_assertion(&expect(), &stored, &fields.assertion()), Err(Refusal::BadSignature));
    }

    #[test]
    fn assertions_of_both_algorithms_are_accepted() {
        let ec = SoftKey::es256();
        assert_eq!(assert_with(&ec, 0, 0, Tamper::default()), Ok(0));
        let rsa = SoftKey::rs256();
        let fields = rsa.assert(&expect(), 9, &Tamper::default());
        assert_eq!(fields.signature.len(), 256);
        assert_eq!(URL_SAFE_NO_PAD.encode(&fields.signature).len(), 342);
        assert_eq!(assert_with(&rsa, 8, 9, Tamper::default()), Ok(9));
    }

    #[test]
    fn tampered_assertions_are_refused() {
        use Refusal::*;
        let key = SoftKey::es256();
        let spki = key.spki();
        let stored = Stored { alg: Alg::Es256, public_key: &spki, counter: 0 };
        let mut bad = key.assert(&expect(), 1, &Tamper::default());
        if let Some(last) = bad.signature.last_mut() {
            *last ^= 1;
        }
        assert_eq!(verify_assertion(&expect(), &stored, &bad.assertion()), Err(BadSignature));
        let other = SoftKey::es256().assert(&expect(), 1, &Tamper::default());
        assert_eq!(verify_assertion(&expect(), &stored, &other.assertion()), Err(BadSignature));
        let rsa = SoftKey::rs256().assert(&expect(), 1, &Tamper::default());
        assert_eq!(verify_assertion(&expect(), &stored, &rsa.assertion()), Err(BadSignature));
        let wrong_alg = Stored { alg: Alg::Rs256, ..stored };
        let good = key.assert(&expect(), 1, &Tamper::default());
        assert_eq!(verify_assertion(&expect(), &wrong_alg, &good.assertion()), Err(BadPublicKey));
        // Signed over other client data than sent.
        let mut swapped = good.clone();
        swapped.client_data = key.assert(&expect(), 1, &Tamper::default()).client_data;
        swapped.client_data.push(b' ');
        assert_eq!(verify_assertion(&expect(), &stored, &swapped.assertion()), Err(BadSignature));

        let cases: Vec<(Tamper, Refusal)> = vec![
            (Tamper { kind: Some("webauthn.create"), ..Tamper::default() }, WrongType),
            (Tamper { challenge: Some(vec![1; 32]), ..Tamper::default() }, WrongChallenge),
            (Tamper { origin: Some("https://evil.example".into()), ..Tamper::default() }, WrongOrigin),
            (Tamper { cross_origin: Some(true), ..Tamper::default() }, CrossOrigin),
            (Tamper { duplicate: true, ..Tamper::default() }, ClientDataUnreadable),
            (Tamper { rp_id: Some("evil.example".into()), ..Tamper::default() }, WrongRpId),
            (Tamper { flags: Some(0x04), ..Tamper::default() }, UserNotPresent),
            (Tamper { flags: Some(0x01), ..Tamper::default() }, UserNotVerified),
        ];
        for (t, refusal) in cases {
            assert_eq!(assert_with(&key, 0, 1, t), Err(refusal), "{refusal:?}");
        }
        let mut long = key.assert(&expect(), 1, &Tamper::default());
        long.authenticator_data.resize(MAX_AUTH_DATA + 1, 0);
        assert_eq!(verify_assertion(&expect(), &stored, &long.assertion()), Err(AuthDataMalformed));
        let mut long = key.assert(&expect(), 1, &Tamper::default());
        long.client_data = vec![b' '; MAX_CLIENT_DATA + 1];
        assert_eq!(verify_assertion(&expect(), &stored, &long.assertion()), Err(ClientDataTooLong));
    }

    #[test]
    fn counters_must_grow_once_they_are_used() {
        let key = SoftKey::es256();
        assert_eq!(assert_with(&key, 0, 0, Tamper::default()), Ok(0));
        assert_eq!(assert_with(&key, 0, 4, Tamper::default()), Ok(4));
        assert_eq!(assert_with(&key, 5, 6, Tamper::default()), Ok(6));
        for new in [5, 3, 0] {
            assert_eq!(assert_with(&key, 5, new, Tamper::default()), Err(Refusal::CounterRegression), "{new}");
        }
    }

    #[test]
    fn every_truncated_input_is_refused_without_a_panic() {
        let ec = SoftKey::es256();
        let rsa = SoftKey::rs256();
        let reg = ec.register(&expect(), &Tamper::default());
        assert_eq!(reg.authenticator_data.len(), 55 + 32);
        for n in 0..reg.client_data.len() {
            let mut f = reg.clone();
            f.client_data.truncate(n);
            assert!(verify_registration(&expect(), &f.registration()).is_err(), "client data {n}");
        }
        for n in 0..reg.authenticator_data.len() {
            let mut f = reg.clone();
            f.authenticator_data.truncate(n);
            assert!(verify_registration(&expect(), &f.registration()).is_err(), "auth data {n}");
        }
        for key in [&ec, &rsa] {
            let der = key.spki();
            for n in 0..der.len() {
                assert_eq!(spki(&der[..n], key.alg()), None, "spki {n}");
                let mut f = key.register(&expect(), &Tamper::default());
                f.public_key.truncate(n);
                assert_eq!(verify_registration(&expect(), &f.registration()), Err(Refusal::BadPublicKey));
            }
        }

        // With a COSE key after the credential id, which is never parsed.
        let cose = cose_es256(&ec.raw_public());
        let reg = ec.register(&expect(), &Tamper { cose: Some(cose), ..Tamper::default() });
        assert_eq!(reg.authenticator_data.len(), 55 + 32 + 77);
        for n in 0..=reg.authenticator_data.len() {
            let mut f = reg.clone();
            f.authenticator_data.truncate(n);
            let result = verify_registration(&expect(), &f.registration());
            if n < 55 + 32 {
                assert!(result.is_err(), "auth data with COSE {n}");
            }
        }

        for key in [&ec, &rsa] {
            let spki = key.spki();
            let stored = Stored { alg: key.alg(), public_key: &spki, counter: 0 };
            let good = key.assert(&expect(), 1, &Tamper::default());
            assert!(verify_assertion(&expect(), &stored, &good.assertion()).is_ok());
            for n in 0..good.client_data.len() {
                let mut f = good.clone();
                f.client_data.truncate(n);
                assert!(verify_assertion(&expect(), &stored, &f.assertion()).is_err(), "client data {n}");
            }
            for n in 0..good.authenticator_data.len() {
                let mut f = good.clone();
                f.authenticator_data.truncate(n);
                assert_eq!(verify_assertion(&expect(), &stored, &f.assertion()), Err(Refusal::AuthDataMalformed));
            }
            for n in 0..good.signature.len() {
                let mut f = good.clone();
                f.signature.truncate(n);
                assert_eq!(verify_assertion(&expect(), &stored, &f.assertion()), Err(Refusal::BadSignature));
            }
            for n in 0..spki.len() {
                let stored = Stored { public_key: &spki[..n], ..stored };
                assert_eq!(verify_assertion(&expect(), &stored, &good.assertion()), Err(Refusal::BadPublicKey));
            }
        }
    }

    #[test]
    fn refusal_labels_are_distinct() {
        use Refusal::*;
        let all = [
            ClientDataTooLong,
            ClientDataUnreadable,
            WrongType,
            WrongChallenge,
            WrongOrigin,
            CrossOrigin,
            TopOrigin,
            AuthDataMalformed,
            WrongRpId,
            UserNotPresent,
            UserNotVerified,
            NoCredentialData,
            CredentialMismatch,
            UnsupportedAlgorithm,
            BadPublicKey,
            BadSignature,
            CounterRegression,
        ];
        let labels: std::collections::BTreeSet<_> = all.iter().map(|r| r.label()).collect();
        assert_eq!(labels.len(), all.len());
        for alg in [Alg::Es256, Alg::Rs256] {
            assert_eq!(Alg::from_cose(alg.cose()), Some(alg));
        }
        assert_eq!((Alg::Es256.name(), Alg::Rs256.name()), ("ES256", "RS256"));
        assert_eq!(Alg::from_cose(-8), None);
    }
}
