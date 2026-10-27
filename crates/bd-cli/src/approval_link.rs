//! Sealed operation requests: what a browser approval link carries.
//!
//! A refused `bd close <id> --force` or `bd playbook discard <run>` that a
//! person could approve in a browser is offered as a link,
//! `<issuer>/w/<ws>/<op>/<issue>?request=<sealed>`. The sealed part is the
//! request itself ([`OperationRequest`]), in a strict binary encoding,
//! sealed with ChaCha20-Poly1305 under a key only the server holds
//! ([`LinkKey`]) and the AAD [`aad`] of the path it was made for, so what
//! the link names is exactly what was asked and nothing else opens it.
//!
//! The plaintext, version 1:
//!
//! | bytes | field |
//! | --- | --- |
//! | 1 | version, 1 |
//! | 1 | operation: 1 close, 2 discard |
//! | 1 | flags: bit 0 failed, bit 1 force, bit 2 a reason is present; others 0 |
//! | 8 | `at`, milliseconds, big-endian |
//! | 8 | `until`, milliseconds, big-endian |
//! | 2 + n | workspace, UTF-8, its length big-endian |
//! | 2 + n | issue |
//! | 2 + n | reason (length 0 when absent) |
//! | 2 + n | requester |
//!
//! The token is base64url without padding of the 12-byte nonce, the
//! ciphertext and the 16-byte tag. Nothing here logs or prints.

use bd_core::{Error, Result};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

/// The longest reason a link carries, in bytes.
pub const MAX_REASON: usize = 2000;
/// How long a link is good for: seven days, in milliseconds.
pub const TTL: i64 = 7 * 24 * 60 * 60 * 1000;
/// The longest query string an approval path reads.
pub const MAX_QUERY: usize = 8192;

const VERSION: u8 = 1;
const FAILED: u8 = 1;
const FORCE: u8 = 2;
const REASON: u8 = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_WORKSPACE: usize = 100;
const MAX_ISSUE: usize = 128;
/// The longest requester, in characters (and so at most four times that in bytes).
const MAX_REQUESTER: usize = 255;
/// Version, operation and flags, then `at` and `until`.
const FIXED: usize = 3 + 8 + 8;
const MAX_PLAINTEXT: usize = FIXED + 4 * 2 + MAX_WORKSPACE + MAX_ISSUE + MAX_REASON + 4 * MAX_REQUESTER;
/// The longest token [`seal`] makes: base64url, unpadded, of the largest
/// plaintext with its nonce and tag.
pub const MAX_TOKEN: usize = (4 * (NONCE_LEN + MAX_PLAINTEXT + TAG_LEN)).div_ceil(3);

/// An operation a person may approve in a browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Close,
    Discard,
}

impl Op {
    /// Its name in a path: `close` or `discard`.
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Close => "close",
            Op::Discard => "discard",
        }
    }

    /// The operation a path segment names.
    pub fn from_path(segment: &str) -> Option<Op> {
        match segment {
            "close" => Some(Op::Close),
            "discard" => Some(Op::Discard),
            _ => None,
        }
    }

    /// `the close of` or `the discard of`, followed by an issue id in text.
    pub fn phrase(self) -> &'static str {
        match self {
            Op::Close => "the close of",
            Op::Discard => "the discard of",
        }
    }

    fn code(self) -> u8 {
        match self {
            Op::Close => 1,
            Op::Discard => 2,
        }
    }

    fn from_code(code: u8) -> Option<Op> {
        match code {
            1 => Some(Op::Close),
            2 => Some(Op::Discard),
            _ => None,
        }
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused operation, as asked: what an approval performs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRequest {
    pub workspace: String,
    pub op: Op,
    pub issue: String,
    /// The reason as the requester gave it; callers pass `None` for an
    /// empty or blank one and anything else unchanged.
    pub reason: Option<String>,
    /// A close recorded as failed (`--failed`).
    pub failed: bool,
    /// Discard's `--force` (a forced close always has it).
    pub force: bool,
    /// The actor that asked.
    pub requester: String,
    /// When it was asked, in milliseconds since the epoch.
    pub at: i64,
    /// Until when it may be approved: `at` + [`TTL`].
    pub until: i64,
}

impl OperationRequest {
    /// A request made at `at`, good until `at` + [`TTL`], with no reason and
    /// no flags; set those fields as asked.
    pub fn new(workspace: String, op: Op, issue: String, requester: String, at: i64) -> OperationRequest {
        OperationRequest {
            workspace,
            op,
            issue,
            reason: None,
            failed: false,
            force: false,
            requester,
            at,
            until: at.saturating_add(TTL),
        }
    }
}

/// The server's key for approval links (ChaCha20-Poly1305). It has no
/// `Debug`, `Clone` or `Display`, so it is never shown.
pub struct LinkKey(LessSafeKey);

impl LinkKey {
    /// A key from its 32 bytes; any other length is refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<LinkKey> {
        if bytes.len() != CHACHA20_POLY1305.key_len() {
            return Err(Error::invalid(format!(
                "an approval link key is {} bytes, not {}",
                CHACHA20_POLY1305.key_len(),
                bytes.len()
            )));
        }
        let key = UnboundKey::new(&CHACHA20_POLY1305, bytes)
            .map_err(|_| Error::invalid("the approval link key could not be used"))?;
        Ok(LinkKey(LessSafeKey::new(key)))
    }
}

/// The AAD a request for `op` of `issue` in `ws` is sealed under.
pub fn aad(ws: &str, op: Op, issue: &str) -> String {
    format!("bd-op:v1:{ws}:{op}:{issue}")
}

/// Why a request was given no link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsealable {
    /// Its reason is longer than [`MAX_REASON`] bytes.
    ReasonTooLong,
    /// One of its fields is outside what a link carries.
    Invalid(&'static str),
}

impl Unsealable {
    /// Why, in words, after `no browser approval link for <op> <id>: `.
    pub fn message(self) -> &'static str {
        match self {
            Unsealable::ReasonTooLong => "the reason is longer than 2000 bytes",
            Unsealable::Invalid(why) => why,
        }
    }
}

/// `req`, sealed under `key` for its own path: the `request` value of its
/// link.
pub fn seal(key: &LinkKey, req: &OperationRequest) -> std::result::Result<String, Unsealable> {
    if req.reason.as_ref().is_some_and(|r| r.len() > MAX_REASON) {
        return Err(Unsealable::ReasonTooLong);
    }
    if !crate::protocol::valid_workspace_name(&req.workspace) {
        return Err(Unsealable::Invalid("the workspace name cannot be in a link"));
    }
    if !bd_core::gates::approval_id_ok(&req.issue) {
        return Err(Unsealable::Invalid("the issue id cannot be in a link"));
    }
    if !requester_ok(&req.requester) {
        return Err(Unsealable::Invalid("the requester cannot be in a link"));
    }
    if !span_ok(req.at, req.until) {
        return Err(Unsealable::Invalid("the request's expiry is out of range"));
    }
    let mut data = encode(req);
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Unsealable::Invalid("the system's random number generator failed"))?;
    let aad = aad(&req.workspace, req.op, &req.issue);
    key.0
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut data)
        .map_err(|_| Unsealable::Invalid("sealing the request failed"))?;
    Ok(b64url_encode(&[&nonce[..], &data].concat()))
}

/// What a link's `request` value is for the path `/w/<ws>/<op>/<issue>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opened {
    /// Not a request this server sealed for this path.
    Invalid,
    /// A genuine request for this path, past its `until`.
    Expired(Box<OperationRequest>),
    /// A genuine request for this path, still good.
    Valid(Box<OperationRequest>),
}

/// Open `sealed` as a request for `op` of `issue` in `ws` at `now_ms`.
pub fn open(key: &LinkKey, sealed: &str, ws: &str, op: Op, issue: &str, now_ms: i64) -> Opened {
    match open_request(key, sealed, ws, op, issue) {
        None => Opened::Invalid,
        Some(req) if req.until <= now_ms => Opened::Expired(Box::new(req)),
        Some(req) => Opened::Valid(Box::new(req)),
    }
}

fn open_request(key: &LinkKey, sealed: &str, ws: &str, op: Op, issue: &str) -> Option<OperationRequest> {
    if sealed.len() > MAX_TOKEN {
        return None;
    }
    let bytes = b64url_decode(sealed)?;
    let (nonce, data) = bytes.split_at_checked(NONCE_LEN)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut data = data.to_vec();
    let aad = aad(ws, op, issue);
    let plain = key.0.open_in_place(nonce, Aad::from(aad.as_bytes()), &mut data).ok()?;
    let req = decode(plain)?;
    (req.workspace == ws && req.op == op && req.issue == issue).then_some(req)
}

/// The link for `op` of `issue`: `base` is `<issuer>/w/<ws>/`.
pub fn url(base: &str, op: Op, issue: &str, sealed: &str) -> String {
    format!("{base}{op}/{issue}?request={sealed}")
}

/// Note a refused `bd close` for a link ([`crate::io::note_operation`]) and
/// return its error unchanged. Only a refusal marked approvable of one
/// issue, forced and without `--take-over`, under a `bd serve` offering
/// links, is noted.
pub fn note_close(tx: &bd_core::WriteCtx<'_>, a: &crate::cli::CloseArgs, e: Error) -> Error {
    use bd_core::Queries;
    if !e.is_approvable() || a.ids.len() != 1 || !a.force || a.take_over || !crate::io::operation_links_offered() {
        return e;
    }
    let Ok(id) = tx.resolve_id(&a.ids[0]) else { return e };
    crate::io::note_operation(Op::Close, &id, a.reason.as_deref(), a.failed, true, tx.actor(), tx.now().0);
    e
}

/// Note a refused `bd playbook discard` of the run `id` for a link and
/// return its error unchanged: only a refusal marked approvable, neither
/// `--take-over` nor `--dry-run`.
pub fn note_discard(tx: &bd_core::WriteCtx<'_>, id: &str, a: &crate::cli::DiscardArgs, e: Error) -> Error {
    if e.is_approvable() && !a.take_over && !a.dry_run {
        crate::io::note_operation(Op::Discard, id, a.reason.as_deref(), false, a.force, tx.actor(), tx.now().0);
    }
    e
}

fn requester_ok(requester: &str) -> bool {
    !requester.is_empty() && requester.chars().count() <= MAX_REQUESTER
}

fn span_ok(at: i64, until: i64) -> bool {
    at <= until && at.checked_add(TTL).is_some_and(|last| until <= last)
}

fn encode(req: &OperationRequest) -> Vec<u8> {
    let mut flags = 0;
    if req.failed {
        flags |= FAILED;
    }
    if req.force {
        flags |= FORCE;
    }
    if req.reason.is_some() {
        flags |= REASON;
    }
    let reason = req.reason.as_deref().unwrap_or("");
    let mut out =
        Vec::with_capacity(FIXED + 8 + req.workspace.len() + req.issue.len() + reason.len() + req.requester.len());
    out.extend([VERSION, req.op.code(), flags]);
    out.extend(req.at.to_be_bytes());
    out.extend(req.until.to_be_bytes());
    for field in [req.workspace.as_str(), req.issue.as_str(), reason, req.requester.as_str()] {
        // Every field is far under 64 KiB: seal checks them first.
        out.extend((field.len() as u16).to_be_bytes());
        out.extend(field.as_bytes());
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn text(&mut self, max: usize) -> Option<&'a str> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
        if len > max {
            return None;
        }
        std::str::from_utf8(self.take(len)?).ok()
    }
}

fn decode(plain: &[u8]) -> Option<OperationRequest> {
    let mut r = Reader(plain);
    if r.byte()? != VERSION {
        return None;
    }
    let op = Op::from_code(r.byte()?)?;
    let flags = r.byte()?;
    if flags & !(FAILED | FORCE | REASON) != 0 {
        return None;
    }
    let at = r.i64()?;
    let until = r.i64()?;
    let workspace = r.text(MAX_WORKSPACE)?;
    let issue = r.text(MAX_ISSUE)?;
    let reason = r.text(MAX_REASON)?;
    let requester = r.text(4 * MAX_REQUESTER)?;
    if !r.0.is_empty()
        || (flags & REASON == 0 && !reason.is_empty())
        || !crate::protocol::valid_workspace_name(workspace)
        || !bd_core::gates::approval_id_ok(issue)
        || !requester_ok(requester)
        || !span_ok(at, until)
    {
        return None;
    }
    Some(OperationRequest {
        workspace: workspace.to_string(),
        op,
        issue: issue.to_string(),
        reason: (flags & REASON != 0).then(|| reason.to_string()),
        failed: flags & FAILED != 0,
        force: flags & FORCE != 0,
        requester: requester.to_string(),
        at,
        until,
    })
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url (RFC 4648 §5) without padding.
#[doc(hidden)]
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((4 * bytes.len()).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | ((b as u32) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Strict base64url without padding: `=`, `+`, `/`, any other character, a
/// length of 1 mod 4 and non-zero trailing bits are refused.
#[doc(hidden)]
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    }
    let text = text.as_bytes();
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    for chunk in text.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        // The bits past the last whole byte must be zero.
        if n & ((1 << (24 - 8 * bytes)) - 1) != 0 {
            return None;
        }
        out.extend(&n.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    fn key() -> LinkKey {
        LinkKey::from_bytes(&[7u8; 32]).unwrap()
    }

    fn request() -> OperationRequest {
        OperationRequest {
            reason: Some("  abandoned\n".to_string()),
            force: true,
            ..OperationRequest::new("proj".into(), Op::Close, "bd-12.3".into(), "alice/agent-1".into(), NOW)
        }
    }

    fn open_req(sealed: &str, req: &OperationRequest) -> Opened {
        open(&key(), sealed, &req.workspace, req.op, &req.issue, NOW + 1)
    }

    /// `plain` sealed as [`seal`] would for `req`'s path, whatever it holds.
    fn seal_raw(plain: &[u8], req: &OperationRequest) -> String {
        let mut data = plain.to_vec();
        let aad = aad(&req.workspace, req.op, &req.issue);
        key()
            .0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key([1; 12]), Aad::from(aad.as_bytes()), &mut data)
            .unwrap();
        b64url_encode(&[&[1u8; 12][..], &data].concat())
    }

    #[test]
    fn a_sealed_request_opens_to_itself() {
        let req = request();
        let sealed = seal(&key(), &req).unwrap();
        assert_eq!(open_req(&sealed, &req), Opened::Valid(Box::new(req.clone())));
        let Opened::Valid(back) = open_req(&sealed, &req) else { unreachable!() };
        assert_eq!(back.reason.as_deref(), Some("  abandoned\n"));
        assert_eq!(back.until, NOW + TTL);

        let bare = OperationRequest::new("proj".into(), Op::Discard, "r-1".into(), "bob".into(), NOW);
        let sealed = seal(&key(), &bare).unwrap();
        assert_eq!(open_req(&sealed, &bare), Opened::Valid(Box::new(bare.clone())));

        let failed = OperationRequest { failed: true, reason: Some(String::new()), ..bare };
        let sealed = seal(&key(), &failed).unwrap();
        assert_eq!(open_req(&sealed, &failed), Opened::Valid(Box::new(failed.clone())));
    }

    #[test]
    fn any_flipped_byte_is_invalid() {
        let req = request();
        let bytes = b64url_decode(&seal(&key(), &req).unwrap()).unwrap();
        for i in 0..bytes.len() {
            for bit in [0x01, 0x80] {
                let mut changed = bytes.clone();
                changed[i] ^= bit;
                assert_eq!(open_req(&b64url_encode(&changed), &req), Opened::Invalid, "byte {i}");
            }
        }
        assert_eq!(open_req(&b64url_encode(&bytes[..bytes.len() - 1]), &req), Opened::Invalid);
        assert_eq!(open_req(&b64url_encode(&bytes[..11]), &req), Opened::Invalid);
        assert_eq!(open_req("", &req), Opened::Invalid);
    }

    #[test]
    fn a_request_opens_only_on_its_own_path() {
        let req = request();
        let sealed = seal(&key(), &req).unwrap();
        assert_eq!(open(&key(), &sealed, "other", Op::Close, &req.issue, NOW), Opened::Invalid);
        assert_eq!(open(&key(), &sealed, "proj", Op::Discard, &req.issue, NOW), Opened::Invalid);
        assert_eq!(open(&key(), &sealed, "proj", Op::Close, "bd-12.4", NOW), Opened::Invalid);
        let other = LinkKey::from_bytes(&[8u8; 32]).unwrap();
        assert_eq!(open(&other, &sealed, "proj", Op::Close, &req.issue, NOW), Opened::Invalid);
    }

    #[test]
    fn only_a_strict_plaintext_opens() {
        let req = request();
        let good = encode(&req);
        assert_eq!(open_req(&seal_raw(&good, &req), &req), Opened::Valid(Box::new(req.clone())));

        let mut v2 = good.clone();
        v2[0] = 2;
        let mut op3 = good.clone();
        op3[1] = 3;
        let mut flag = good.clone();
        flag[2] |= 8;
        let mut trailing = good.clone();
        trailing.push(0);
        let short = good[..good.len() - 1].to_vec();
        let cases: Vec<(&str, Vec<u8>)> =
            vec![("version 2", v2), ("op 3", op3), ("unknown flag", flag), ("trailing", trailing), ("short", short)];
        for (what, plain) in cases {
            assert_eq!(open_req(&seal_raw(&plain, &req), &req), Opened::Invalid, "{what}");
        }

        let mut bad_utf8 = req.clone();
        bad_utf8.reason = Some("ab".into());
        let mut plain = encode(&bad_utf8);
        let at = plain.len() - 2 - bad_utf8.requester.len() - 2;
        plain[at] = 0xff;
        assert_eq!(open_req(&seal_raw(&plain, &req), &req), Opened::Invalid, "invalid UTF-8");

        let mut no_flag = encode(&req);
        no_flag[2] &= !REASON;
        assert_eq!(open_req(&seal_raw(&no_flag, &req), &req), Opened::Invalid, "reason bytes without the flag");

        let mut bare = req.clone();
        bare.reason = None;
        let plain = encode(&bare);
        assert_eq!(open_req(&seal_raw(&plain, &bare), &bare), Opened::Valid(Box::new(bare.clone())));

        let empty_requester = OperationRequest { requester: String::new(), ..req.clone() };
        assert_eq!(open_req(&seal_raw(&encode(&empty_requester), &req), &req), Opened::Invalid, "no requester");
        let bad_ws = OperationRequest { workspace: "../x".into(), ..req.clone() };
        assert_eq!(open_req(&seal_raw(&encode(&bad_ws), &bad_ws), &bad_ws), Opened::Invalid, "workspace name");
    }

    #[test]
    fn expiry_is_checked() {
        let req = request();
        let sealed = seal(&key(), &req).unwrap();
        assert_eq!(
            open(&key(), &sealed, "proj", Op::Close, &req.issue, req.until - 1),
            Opened::Valid(Box::new(req.clone()))
        );
        assert_eq!(
            open(&key(), &sealed, "proj", Op::Close, &req.issue, req.until),
            Opened::Expired(Box::new(req.clone()))
        );

        let long = OperationRequest { until: req.at + TTL + 1, ..req.clone() };
        assert_eq!(seal(&key(), &long), Err(Unsealable::Invalid("the request's expiry is out of range")));
        assert_eq!(open_req(&seal_raw(&encode(&long), &req), &req), Opened::Invalid);
        let backwards = OperationRequest { until: req.at - 1, ..req.clone() };
        assert_eq!(open_req(&seal_raw(&encode(&backwards), &req), &req), Opened::Invalid);
    }

    #[test]
    fn reasons_up_to_2000_bytes_are_carried_whatever_they_hold() {
        let mut req = request();
        req.reason = Some("x".repeat(MAX_REASON + 1));
        assert_eq!(seal(&key(), &req), Err(Unsealable::ReasonTooLong));
        assert_eq!(Unsealable::ReasonTooLong.message(), "the reason is longer than 2000 bytes");
        for reason in ["\"".repeat(MAX_REASON), "\n\u{1b}\0\t\r".repeat(MAX_REASON / 5)] {
            req.reason = Some(reason);
            let sealed = seal(&key(), &req).unwrap();
            assert_eq!(open_req(&sealed, &req), Opened::Valid(Box::new(req.clone())));
        }
    }

    #[test]
    fn the_largest_request_fits_the_token_and_query_limits() {
        assert_eq!(MAX_TOKEN, 4404);
        assert!(MAX_TOKEN + "request=".len() <= MAX_QUERY);
        let req = OperationRequest {
            reason: Some("r".repeat(MAX_REASON)),
            failed: true,
            force: true,
            ..OperationRequest::new("w".repeat(100), Op::Discard, "i".repeat(128), "😀".repeat(255), NOW)
        };
        let sealed = seal(&key(), &req).unwrap();
        assert_eq!(sealed.len(), MAX_TOKEN);
        assert_eq!(open_req(&sealed, &req), Opened::Valid(Box::new(req.clone())));

        let too_long = OperationRequest { requester: "😀".repeat(256), ..req.clone() };
        assert_eq!(seal(&key(), &too_long), Err(Unsealable::Invalid("the requester cannot be in a link")));
        let over = format!("{sealed}AAAA");
        assert_eq!(open_req(&over, &req), Opened::Invalid);
        assert_eq!(open_req(&"A".repeat(MAX_TOKEN + 1), &req), Opened::Invalid);
    }

    #[test]
    fn seal_refuses_what_a_link_cannot_name() {
        let req = request();
        let bad = |r: OperationRequest| seal(&key(), &r).unwrap_err();
        assert!(matches!(bad(OperationRequest { workspace: "a/b".into(), ..req.clone() }), Unsealable::Invalid(_)));
        assert!(matches!(bad(OperationRequest { issue: "x?y".into(), ..req.clone() }), Unsealable::Invalid(_)));
        assert!(matches!(bad(OperationRequest { requester: String::new(), ..req.clone() }), Unsealable::Invalid(_)));
    }

    #[test]
    fn links_name_the_operation_path() {
        assert_eq!(
            url("https://bd.example/bd/w/proj/", Op::Discard, "r-1", "abc"),
            "https://bd.example/bd/w/proj/discard/r-1?request=abc"
        );
        assert_eq!(aad("proj", Op::Close, "t-1"), "bd-op:v1:proj:close:t-1");
        assert_eq!(Op::from_path("close"), Some(Op::Close));
        assert_eq!(Op::from_path("discard"), Some(Op::Discard));
        assert_eq!(Op::from_path("delete"), None);
        assert_eq!(Op::Close.phrase(), "the close of");
        assert_eq!(Op::Discard.phrase(), "the discard of");
    }

    #[test]
    fn base64url_follows_rfc_4648() {
        let vectors = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, coded) in vectors {
            assert_eq!(b64url_encode(plain.as_bytes()), coded);
            assert_eq!(b64url_decode(coded).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(b64url_decode("-_-_").unwrap(), [0xfb, 0xff, 0xbf]);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(b64url_decode(&b64url_encode(&all)).unwrap(), all);
        for bad in ["Zg==", "Zm8=", "+/+/", "Z", "Zm9vY", "Zh", "Zm9", "Zm 9", "Zm9v\n", "Zé"] {
            assert_eq!(b64url_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keys_are_32_bytes() {
        assert!(LinkKey::from_bytes(&[0; 31]).is_err());
        assert!(LinkKey::from_bytes(&[0; 33]).is_err());
        assert!(LinkKey::from_bytes(&[0; 32]).is_ok());
    }
}
