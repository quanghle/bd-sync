use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::super::clients::Client;
use super::super::form;
use super::super::pages;
use crate::auth;
use crate::oauth::OauthConfig;
use crate::passkeys;
use crate::webauthn::testkit::{Fields, SoftKey, Tamper};
use bd_cli::approval_link::{self, LinkKey, MAX_QUERY, Op, OperationRequest, TTL};

use super::*;

const ISSUER: &str = "https://bd.example.com/bd";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The verifier of [`CHALLENGE`] (RFC 7636 appendix B).
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn client() -> Client {
    Client {
        id: "bdc_1".into(),
        name: Some("App".into()),
        redirect_uris: vec!["https://app.example/cb?x=1".into()],
        document: false,
        logo: None,
        cacheable: true,
    }
}

fn oauth() -> OauthConfig {
    OauthConfig {
        redirect_hosts: vec!["app.example".into()],
        redirect_uris: vec![],
        loopback_redirects: false,
        registration: true,
    }
}

fn query(extra: &[(&str, &str)]) -> String {
    let mut q = vec![
        ("client_id", "bdc_1"),
        ("redirect_uri", "https://app.example/cb?x=1"),
        ("state", "s 1"),
        ("response_type", "code"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", "https://bd.example.com/bd/w/proj/mcp"),
    ];
    for (k, v) in extra {
        match q.iter_mut().find(|(name, _)| name == k) {
            Some(pair) if v.is_empty() => pair.0 = "dropped",
            Some(pair) => pair.1 = v,
            None => q.push((k, v)),
        }
    }
    form::encode(&q)
}

fn checked(q: &str) -> Result<Authorization, Answer> {
    check(parse(q)?, client(), &oauth(), ISSUER)
}

fn page_status(answer: Answer) -> u16 {
    match answer {
        Answer::Page(p) => p.status,
        a => panic!("not a page: {a:?}"),
    }
}

fn redirect(answer: Answer) -> Vec<(String, String)> {
    let Answer::Redirect(url) = answer else { panic!("not a redirect: {answer:?}") };
    let rest = url.strip_prefix("https://app.example/cb?x=1&").unwrap_or_else(|| panic!("{url}"));
    form::decode(rest).unwrap()
}

#[test]
fn a_valid_request_is_checked() {
    let a = checked(&query(&[("scope", "anything")])).unwrap();
    assert_eq!(a.redirect_uri, "https://app.example/cb?x=1");
    assert_eq!(a.state.as_deref(), Some("s 1"));
    assert_eq!(a.challenge, CHALLENGE);
    assert_eq!(a.workspace, "proj");
    assert_eq!(a.resource, "https://bd.example.com/bd/w/proj/mcp");
    assert_eq!(checked(&query(&[("resource", "https://BD.example.com/bd/w/proj/mcp/")])).unwrap().workspace, "proj");
    assert!(checked(&query(&[("state", "")])).unwrap().state.is_none());
}

#[test]
fn requests_the_client_cannot_be_told_about_are_refused_on_a_page() {
    for q in [
        query(&[("client_id", "")]),
        query(&[("redirect_uri", "")]),
        format!("{}&client_id=bdc_2", query(&[])),
        format!("{}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fx%3D1", query(&[])),
        format!("{}&state=again", query(&[])),
        query(&[("state", &"s".repeat(MAX_STATE + 1))]),
        query(&[("redirect_uri", "https://app.example/cb?x=2")]),
        query(&[("redirect_uri", "https://evil.example/cb?x=1")]),
        "client_id=%zz".to_string(),
    ] {
        assert_eq!(page_status(checked(&q).unwrap_err()), 400, "{q}");
    }
    let allowed =
        OauthConfig { redirect_hosts: vec![], redirect_uris: vec![], loopback_redirects: false, registration: true };
    let answer = check(parse(&query(&[])).unwrap(), client(), &allowed, ISSUER).unwrap_err();
    assert_eq!(page_status(answer), 400, "registered, but no longer allowed");
}

#[test]
fn other_errors_go_back_to_the_client() {
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[("response_type", "")], "invalid_request"),
        (&[("response_type", "token")], "unsupported_response_type"),
        (&[("code_challenge_method", "")], "invalid_request"),
        (&[("code_challenge_method", "plain")], "invalid_request"),
        (&[("code_challenge", "")], "invalid_request"),
        (&[("code_challenge", "short")], "invalid_request"),
        (&[("code_challenge", &CHALLENGE.replace('-', "+"))], "invalid_request"),
        (&[("resource", "")], "invalid_request"),
        (&[("resource", "https://elsewhere.example/bd/w/proj/mcp")], "invalid_target"),
        (&[("resource", "https://bd.example.com/w/proj/mcp")], "invalid_target"),
        (&[("resource", "https://bd.example.com/bd/w/proj")], "invalid_target"),
    ];
    for (extra, error) in cases {
        let pairs = redirect(checked(&query(extra)).unwrap_err());
        assert_eq!(pairs[0], ("error".into(), error.to_string()), "{extra:?}");
        assert_eq!(pairs[1].0, "error_description");
        assert_eq!(pairs[2], ("state".into(), "s 1".into()));
        assert_eq!(pairs[3], ("iss".into(), ISSUER.into()));
    }
    let pairs = redirect(checked(&format!("{}&scope=a&scope=b", query(&[]))).unwrap_err());
    assert_eq!(pairs[0].1, "invalid_request");
    assert!(pairs[1].1.contains("scope"));
    let pairs = redirect(checked(&query(&[("state", ""), ("response_type", "token")])).unwrap_err());
    assert_eq!(pairs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["error", "error_description", "iss"]);
}

#[test]
fn flows_are_taken_once_and_expire() {
    let mut kept = Kept::new(Duration::from_secs(60));
    kept.put("a".into(), 1);
    assert_eq!(kept.take("a"), Some(1));
    assert_eq!(kept.take("a"), None);
    let mut expired = Kept::new(Duration::ZERO);
    expired.put("a".into(), 1);
    assert_eq!(expired.take("a"), None);
    for i in 0..MAX_FLOWS + 10 {
        kept.put(i.to_string(), i);
    }
    assert_eq!(kept.map.len(), MAX_FLOWS);
    assert_eq!(kept.take("0"), None, "the oldest went first");
    assert_eq!(kept.take(&(MAX_FLOWS + 9).to_string()), Some(MAX_FLOWS + 9));
}

#[test]
fn flows_before_a_sign_in_are_sealed_for_their_step() {
    let sealer = Sealer::new();
    let at = AtProvider { provider: "github".into(), state: "s".into(), verifier: "v".into(), nonce: "n".into() };
    let then = Then::Authorize { query: "client_id=x".into() };
    let pending = Pending { then, browser: "b".into(), until: 1, at: Some(at) };
    let sealed = sealer.seal(AT_PROVIDER, &pending).unwrap();
    assert!(!sealed.contains("client_id") && !sealed.contains("github"), "unread: {sealed}");
    assert_eq!(sealer.open(AT_PROVIDER, &sealed), Some(pending));
    assert_eq!(sealer.open(CHOOSING, &sealed), None, "for its own step only");
    assert_eq!(Sealer::new().open(AT_PROVIDER, &sealed), None, "this process's key only");
    let mut changed = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(sealer.open(AT_PROVIDER, &URL_SAFE_NO_PAD.encode(changed)), None, "unchanged");
    assert_eq!(sealer.open(AT_PROVIDER, "AAAA"), None);
}

fn gate_pending() -> Pending {
    let then = Then::Gate { workspace: "proj".into(), gate: "bd-1".into() };
    Pending { then, browser: String::new(), until: 1, at: None }
}

#[test]
fn a_flow_opens_only_as_the_kind_it_was_sealed_as() {
    let sealer = Sealer::new();
    let authorize = || Pending { then: Then::Authorize { query: "q".into() }, browser: "b".into(), until: 1, at: None };
    // An authorization's AAD is its step, as before gates had flows.
    let sealed = sealer.seal(AT_PROVIDER, &authorize()).unwrap();
    assert_eq!(sealer.open(AT_PROVIDER, &sealed), Some(authorize()));
    // Sealed under a gate's AAD, it is not taken for a gate's flow.
    let forged = sealer.seal("gate:provider", &authorize()).unwrap();
    assert_eq!(sealer.open(AT_PROVIDER, &forged), None);
    // A gate's opens as a gate's, for its own step only.
    let sealed = sealer.seal(AT_PROVIDER, &gate_pending()).unwrap();
    assert_eq!(sealer.open(AT_PROVIDER, &sealed), Some(gate_pending()));
    assert_eq!(sealer.open(CHOOSING, &sealed), None);
    let sealed = sealer.seal(CHOOSING, &gate_pending()).unwrap();
    assert_eq!(sealer.open(CHOOSING, &sealed), Some(gate_pending()));
    assert_eq!(sealer.open(AT_PROVIDER, &sealed), None);
    // The hop from a gate's page goes on to the chooser only.
    let begun = sealer.seal(GATE_BEGIN, &gate_pending()).unwrap();
    assert_eq!(sealer.open(GATE_BEGIN, &begun), Some(gate_pending()));
    assert_eq!(sealer.open(CHOOSING, &begun), None);
    assert_eq!(sealer.open(AT_PROVIDER, &begun), None);
}

#[test]
fn what_comes_then_round_trips() {
    for then in [
        Then::Authorize { query: "client_id=x&state=y".into() },
        Then::Gate { workspace: "proj".into(), gate: "bd-1.2".into() },
    ] {
        let json = serde_json::to_value(&then).unwrap();
        assert!(json["then"] == "authorize" || json["then"] == "gate", "{json}");
        assert_eq!(serde_json::from_value::<Then>(json).unwrap(), then);
    }
    let pending = gate_pending();
    let json = serde_json::to_string(&pending).unwrap();
    assert_eq!(serde_json::from_str::<Pending>(&json).unwrap(), pending);
}

#[test]
fn helpers() {
    assert_eq!(in_words(Duration::from_secs(30 * 86_400)), "30 days");
    assert_eq!(in_words(Duration::from_secs(86_400)), "1 day");
    assert_eq!(in_words(Duration::from_secs(36 * 3_600)), "36 hours");
    assert_eq!(in_words(Duration::from_secs(90)), "2 minutes");
    assert_eq!(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), CHALLENGE, "RFC 7636 appendix B");
    let c = "a".repeat(64);
    let http = "http://127.0.0.1:7420";
    assert_eq!(cookie(http, &format!("x=1; {COOKIE}={c}; y=2")), Some(c.as_str()));
    assert_eq!(cookie(http, &format!("{COOKIE}={}", "A".repeat(64))), None);
    assert_eq!(cookie(http, &format!("{COOKIE}=abc")), None);
    assert_eq!(cookie(ISSUER, &format!("x=1; {SECURE_COOKIE}={c}")), Some(c.as_str()));
    assert_eq!(cookie(ISSUER, &format!("{COOKIE}={c}")), None, "unprefixed, on https: planted, maybe");
    assert_eq!(cookie(http, &format!("{SECURE_COOKIE}={c}")), None);
    assert_eq!(cookie(http, "x=1"), None);
    assert_eq!(
        set_cookie(ISSUER, &c),
        format!("{SECURE_COOKIE}={c}; Path=/bd/oauth; Max-Age=1200; HttpOnly; SameSite=Lax; Secure")
    );
    assert_eq!(
        set_cookie("http://127.0.0.1:7420", &c),
        format!("{COOKIE}={c}; Path=/oauth; Max-Age=1200; HttpOnly; SameSite=Lax")
    );
    assert_eq!(origin("https://a.example:8443/x?y#z"), "https://a.example:8443");
    assert_eq!(origin("http://127.0.0.1?x"), "http://127.0.0.1");
    assert_eq!(host_of("https://app.example/cb"), "app.example");
    let iss = "iss=https%3A%2F%2Fbd.example.com%2Fbd";
    assert_eq!(
        answer_url("https://a/cb", Some("s"), ISSUER, &[("code", "c")]),
        format!("https://a/cb?code=c&state=s&{iss}")
    );
    assert_eq!(answer_url("https://a/cb?x", None, ISSUER, &[]), format!("https://a/cb?x&{iss}"));
}

#[test]
fn the_browser_returns_by_a_page_to_an_ipv6_address() {
    assert_eq!(form_origins("https://app.example/cb"), ["'self'", "https://app.example"]);
    assert_eq!(form_origins("http://127.0.0.1:8080/cb"), ["'self'", "http://127.0.0.1:8080"]);
    assert_eq!(form_origins("http://[::1]:8080/cb"), ["'self'"]);
    assert_eq!(
        back_to("http://127.0.0.1:8080/cb?code=c".into()),
        Answer::Redirect("http://127.0.0.1:8080/cb?code=c".into())
    );
    let Answer::Page(page) = back_to("http://[::1]:8080/cb?code=c".into()) else { panic!("not a page") };
    assert!(page.html.contains("href=\"http://[::1]:8080/cb?code=c\""), "{}", page.html);
}

#[test]
fn codes_are_redeemed_once_and_a_code_sent_again_names_its_token() {
    let code = sample_code();
    let mut flows = Flows::default();
    let redeem = |flows: &mut Flows, c: &str| flows.redeem(c, "bdc_1", VERIFIER);
    flows.codes.put(auth::hash("c1"), code.clone());
    assert!(matches!(redeem(&mut flows, "c1"), Redeemed::Fresh(_)));
    assert!(!flows.issued("c1", "t1"));
    assert!(matches!(redeem(&mut flows, "c1"), Redeemed::Again(Some(t)) if t == "t1"));
    assert!(matches!(redeem(&mut flows, "c2"), Redeemed::Unknown));
    // Sent again while its token was being issued: that token must go.
    flows.codes.put(auth::hash("c3"), code.clone());
    assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Fresh(_)));
    assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Again(None)));
    assert!(flows.issued("c3", "t3"));
    // Undone, as no token was issued: good again, until it would have expired.
    flows.codes.put(auth::hash("c4"), code.clone());
    let until = flows.codes.map[&auth::hash("c4")].0;
    assert!(matches!(redeem(&mut flows, "c4"), Redeemed::Fresh(_)));
    flows.unredeem("c4", code.clone());
    assert_eq!(flows.codes.map[&auth::hash("c4")].0, until);
    assert!(matches!(redeem(&mut flows, "c4"), Redeemed::Fresh(_)));
    // Not once sent again, nor once it issued a token.
    flows.unredeem("c3", code.clone());
    assert!(matches!(redeem(&mut flows, "c3"), Redeemed::Again(Some(t)) if t == "t3"));
    flows.codes.put(auth::hash("c5"), code.clone());
    assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Fresh(_)));
    assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Again(None)));
    flows.unredeem("c5", code.clone());
    assert!(matches!(redeem(&mut flows, "c5"), Redeemed::Again(None)));
    // Sent again by someone who saw it, without its client's verifier: its token stays.
    flows.codes.put(auth::hash("c6"), code);
    assert!(matches!(redeem(&mut flows, "c6"), Redeemed::Fresh(_)));
    assert!(!flows.issued("c6", "t6"));
    let other_verifier = "x".repeat(43);
    assert!(matches!(flows.redeem("c6", "bdc_1", &other_verifier), Redeemed::Again(None)));
    assert!(matches!(flows.redeem("c6", "bdc_other", VERIFIER), Redeemed::Again(None)));
    assert!(matches!(redeem(&mut flows, "c6"), Redeemed::Again(Some(t)) if t == "t6"), "its own client: revoked");
}

/// Gates as a map, recording each approval asked for.
/// An approval [`FakeGates`] was asked for: its workspace, gate, actor and OIDC approver reference.
type Call = (String, String, String, Option<String>);

struct FakeGates {
    found: Found,
    answer: Approved,
    calls: std::sync::Mutex<Vec<Call>>,
}

impl FakeGates {
    fn answering(answer: Approved) -> FakeGates {
        FakeGates { found: Found::NoIssue, answer, calls: Default::default() }
    }

    fn calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Gates for FakeGates {
    fn find(&self, _: &str, _: &str, _: &Approver<'_>) -> Result<Found, bd_core::Error> {
        Ok(self.found.clone())
    }

    fn approve(
        &self,
        workspace: &str,
        gate: &str,
        actor: &str,
        oidc_approver: Option<&str>,
    ) -> Result<Approved, bd_core::Error> {
        let call: Call = (workspace.into(), gate.into(), actor.into(), oidc_approver.map(String::from));
        self.calls.lock().unwrap().push(call);
        Ok(self.answer.clone())
    }
}

/// A root whose auth.toml turns `[oauth]` on with GitHub's web flow, and
/// with `oidc` another provider.
fn gate_root(oidc: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("github-secret"), "s3cret\n").unwrap();
    let mut config = String::from(
        "[github]\nclient_id = \"Iv1.test\"\nclient_secret_file = \"github-secret\"\n\
         [[github.allow]]\nusers = [\"alice\"]\nrole = \"write\"\nkind = \"human\"\n",
    );
    if oidc {
        std::fs::write(root.path().join("acme-secret"), "s3cret\n").unwrap();
        config.push_str(
            "[oidc.acme]\nissuer = \"https://acme.example\"\nclient_id = \"bd-client\"\n\
             client_secret_file = \"acme-secret\"\nlabel = \"Acme SSO\"\n\
             [[oidc.acme.allow]]\nemail_domains = [\"acme.example\"]\nrole = \"write\"\n",
        );
    }
    config.push_str("[oauth]\nredirect_hosts = [\"app.example\"]\n");
    std::fs::write(root.path().join("auth.toml"), config).unwrap();
    // The OIDC account the approvals below were shown to, bound as a sign-in binds it: its passkey is kept for it.
    let actor = auth::bind_account(root.path(), &acme(), true, "to approve gates").unwrap();
    assert_eq!(actor, "acme:alice");
    root
}

/// The issuer and subject of the OIDC account [`approval`] signed in with.
const ACME_ISSUER: &str = "https://login.example.com";
const ACME_SUBJECT: &str = "00u7";

fn acme() -> auth::Identity {
    auth::Identity {
        provider: "acme".into(),
        issuer: ACME_ISSUER.into(),
        subject: ACME_SUBJECT.into(),
        login: "alice".into(),
    }
}

/// A ceremony for the acme account, with a fresh challenge: registering its
/// first passkey if `enroll`, else using one.
fn ceremony(enroll: bool) -> Ceremony {
    use ring::rand::SecureRandom;
    let mut challenge = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut challenge).unwrap();
    Ceremony::for_test(ACME_ISSUER, ACME_SUBJECT, enroll, challenge)
}

/// `fields` as an approval's form fields: a registration's if `enroll`,
/// else an assertion's.
fn webauthn_body(fields: &Fields, enroll: bool) -> String {
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    let mut pairs = vec![
        ("credential", b64(&fields.credential)),
        ("client_data", b64(&fields.client_data)),
        ("authenticator_data", b64(&fields.authenticator_data)),
    ];
    if enroll {
        pairs.push(("public_key", b64(&fields.public_key)));
        pairs.push(("algorithm", fields.algorithm.to_string()));
    } else {
        pairs.push(("signature", b64(&fields.signature)));
    }
    let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    form::encode(&pairs)
}

/// `key`'s registration in `c`, as form fields.
fn registration(key: &SoftKey, c: &Ceremony, t: &Tamper) -> String {
    webauthn_body(&key.register(&c.expect(), t), true)
}

/// `key`'s assertion in `c` at `counter`, as form fields.
fn assertion(key: &SoftKey, c: &Ceremony, counter: u32, t: &Tamper) -> String {
    webauthn_body(&key.assert(&c.expect(), counter, t), false)
}

/// The credential id of `key`, base64url, and the prefix logs show of it.
fn credential_of(key: &SoftKey) -> (String, String) {
    let id = URL_SAFE_NO_PAD.encode(&key.credential);
    let prefix = passkeys::prefix(&id).to_string();
    (id, prefix)
}

/// The acme account's passkeys.
fn kept_passkeys(root: &std::path::Path) -> Vec<passkeys::Passkey> {
    passkeys::for_account(root, ACME_ISSUER, ACME_SUBJECT).unwrap()
}

/// The `kind` events kept in `root`'s server.db.
fn events_of(root: &std::path::Path, kind: &str) -> Vec<crate::server_db::AuthEvent> {
    crate::server_db::events(root, 0, None, &[kind.to_string()], 100).unwrap().into_iter().map(|e| e.event).collect()
}

fn with_ctx<T>(root: &std::path::Path, flows: &Mutex<Flows>, gates: &FakeGates, f: impl FnOnce(&Ctx<'_>) -> T) -> T {
    let documents = super::super::cimd::Documents::new();
    let exists = |_: &str| true;
    let operations = FakeOperations::new(OpFound::NoIssue, Performed::Done);
    f(&Ctx {
        root,
        issuer: ISSUER,
        documents: &documents,
        flows,
        workspace_exists: &exists,
        gates,
        links: None,
        operations: &operations,
    })
}

fn page(answer: &Answer) -> &pages::Page {
    match answer {
        Answer::Page(p) => p,
        a => panic!("not a page: {a:?}"),
    }
}

/// The `flow` of a chooser's or a redirect's URL.
fn flow_of(url: &str) -> String {
    let query = url.split_once('?').unwrap().1.replace("&amp;", "&");
    let query = query.split('"').next().unwrap();
    form::decode(query).unwrap().into_iter().find(|(k, _)| k == "flow").unwrap().1
}

#[test]
fn a_gate_page_goes_on_to_the_chooser_telling_nothing() {
    let root = gate_root(false);
    let (flows, gates) = (Mutex::new(Flows::default()), FakeGates::answering(Approved::Resolved));
    with_ctx(root.path(), &flows, &gates, |cx| {
        for (ws, id) in [("proj", "bd-1"), ("nosuch", "bd-2.3"), ("proj", "x")] {
            let (answer, cookies) = gate::begin(cx, ws, id);
            let Answer::Redirect(url) = &answer else { panic!("{ws}/{id}: {answer:?}") };
            assert!(url.starts_with(&format!("{ISSUER}/oauth/choose?flow=")), "{url}");
            assert!(cookies.is_empty(), "no cookie yet: {cookies:?}");
            let opened = lock(&flows).sealer.open(GATE_BEGIN, &flow_of(url)).unwrap();
            assert_eq!(opened.then, Then::Gate { workspace: ws.into(), gate: id.into() });
        }
        for (ws, id) in [("a/b", "bd-1"), ("proj", "../x"), ("proj", "a/b"), ("proj", ""), ("-x", "bd-1")] {
            assert_eq!(page(&gate::begin(cx, ws, id).0).status, 404, "{ws}/{id}");
        }
    });
    assert_eq!(gates.calls(), 0);
}

#[test]
fn the_chooser_binds_a_gate_flow_to_the_browser_and_goes_on() {
    let root = gate_root(false);
    let (flows, gates) = (Mutex::new(Flows::default()), FakeGates::answering(Approved::Resolved));
    with_ctx(root.path(), &flows, &gates, |cx| {
        let Answer::Redirect(url) = gate::begin(cx, "proj", "bd-1").0 else { panic!() };
        let query = form::encode(&[("flow", flow_of(&url).as_str())]);
        let (answer, cookies) = choose(cx, &query, None);
        let Answer::Redirect(to) = answer else { panic!("{answer:?}") };
        assert!(to.starts_with("https://github.com/login/oauth/authorize?"), "{to}");
        assert!(cookies.iter().any(|c| c.starts_with(&format!("{SECURE_COOKIE}="))), "{cookies:?}");
        assert!(cookies.iter().any(|c| c.starts_with("__Secure-bd_flow_")), "{cookies:?}");
        // The hop is for the chooser alone, without a provider named.
        let with_provider = format!("{query}&provider=github");
        assert_eq!(page(&choose(cx, &with_provider, None).0).status, 400);
    });
}

#[test]
fn several_providers_are_chosen_from_for_the_gate() {
    let root = gate_root(true);
    let (flows, gates) = (Mutex::new(Flows::default()), FakeGates::answering(Approved::Resolved));
    with_ctx(root.path(), &flows, &gates, |cx| {
        let Answer::Redirect(url) = gate::begin(cx, "proj", "bd-1").0 else { panic!() };
        let browser = "b".repeat(64);
        let query = form::encode(&[("flow", flow_of(&url).as_str())]);
        let (answer, cookies) = choose(cx, &query, Some(&browser));
        let p = page(&answer);
        assert_eq!(p.status, 200);
        assert!(p.html.contains("Sign in to approve gate bd-1 in proj"), "{}", p.html);
        assert!(p.html.contains("Acme SSO") && p.html.contains("GitHub"), "{}", p.html);
        assert_eq!(cookies, vec![set_cookie(ISSUER, &browser)], "the browser's own cookie kept");
        let link = p.html.split("href=\"").nth(1).unwrap();
        let opened = lock(&flows).sealer.open(CHOOSING, &flow_of(link)).unwrap();
        assert_eq!(opened.then, Then::Gate { workspace: "proj".into(), gate: "bd-1".into() });
        assert_eq!(opened.browser, auth::hash(&browser));
    });
}

/// The reference of the OIDC account [`approval`] signed in with.
fn reference() -> String {
    bd_core::gates::oidc_approver("https://login.example.com", "00u7")
}

/// An OIDC account's approval of bd-1, bound to the cookie `cookie` of
/// value `value`, registering its first passkey: for posts refused before
/// the passkey is checked.
fn approval(cookie: &str, value: &str) -> Approval {
    approval_with(cookie, value, ceremony(true))
}

/// [`approval`], asking for the passkey ceremony `passkey`.
fn approval_with(cookie: &str, value: &str, passkey: Ceremony) -> Approval {
    Approval {
        workspace: "proj".into(),
        gate: "bd-1".into(),
        actor: "acme:alice".into(),
        provider: "acme".into(),
        login: "alice".into(),
        subject: "00u7".into(),
        oidc_approver: Some(reference()),
        browser: auth::hash(value),
        cookie: cookie.into(),
        passkey,
    }
}

#[test]
fn approvals_are_posted_once_from_their_own_browser() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let opened = Approved::Opened { unblocked: vec!["bd-2".into()], completed: vec![] };
    let gates = FakeGates::answering(opened);
    let value = "c".repeat(64);
    let cookies = format!("x=1; __Secure-bd_gate_ab12={value}");
    let key = SoftKey::es256();
    let (credential, prefix) = credential_of(&key);
    let waiting = |id: &str| lock(&flows).approvals.get_mut(&auth::hash(id)).is_some();
    let spent = |id: &str| lock(&flows).approvals_spent.get_mut(&auth::hash(id)).is_some();
    with_ctx(root.path(), &flows, &gates, |cx| {
        let post =
            |id: &str, gate: &str, cookies: &str| gate::approve(cx, "proj", gate, &format!("approval={id}"), cookies);
        let html = |answer: &(Answer, Vec<String>)| page(&answer.0).html.clone();
        // Unknown, or expired: nothing approved.
        let unknown = post("nope", "bd-1", &cookies);
        assert_eq!((page(&unknown.0).status, html(&unknown).contains("expired")), (400, true));
        lock(&flows).approvals.put_until(auth::hash("old"), std::time::Instant::now(), approval("ab12", &value));
        let expired = post("old", "bd-1", &cookies);
        assert_eq!((page(&expired.0).status, html(&expired).contains("expired")), (400, true));
        assert_eq!(gates.calls(), 0);
        let enroll = ceremony(true);
        lock(&flows).approvals.put(auth::hash("id1"), approval_with("ab12", &value, enroll.clone()));
        let fields = registration(&key, &enroll, &Tamper::default());
        // Another browser's: refused before the passkey is looked at, and the approval stays for its own.
        for other in
            ["", "__Secure-bd_gate_ab12=".to_string().as_str(), &format!("__Secure-bd_gate_ab12={}", "d".repeat(64))]
        {
            assert_eq!(page(&post("id1", "bd-1", other).0).status, 403, "{other:?}");
            let body = format!("approval=id1&{fields}");
            assert_eq!(page(&gate::approve(cx, "proj", "bd-1", &body, other).0).status, 403, "{other:?}");
        }
        assert!(waiting("id1") && kept_passkeys(root.path()).is_empty());
        // Another gate's page: refused.
        assert_eq!(page(&post("id1", "bd-2", &cookies).0).status, 400);
        assert_eq!(gates.calls(), 0);
        assert_eq!(gate::take_logged(), vec![], "nothing taken, nothing logged");

        // A registration without user verification: refused, nothing stored, nothing approved.
        let uv = ceremony(true);
        lock(&flows).approvals.put(auth::hash("idU"), approval_with("ab12", &value, uv.clone()));
        let body =
            format!("approval=idU&{}", registration(&key, &uv, &Tamper { flags: Some(0x41), ..Tamper::default() }));
        let (answer, _) = gate::approve(cx, "proj", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 403, "{}", page(&answer).html);
        assert!(page(&answer).html.contains("passkey"), "{}", page(&answer).html);
        assert!(kept_passkeys(root.path()).is_empty() && events_of(root.path(), "passkey_registered").is_empty());
        let logged = gate::take_logged();
        assert_eq!(logged.len(), 1);
        assert_eq!((logged[0].outcome, logged[0].passkey), ("passkey refused", "user not verified"));
        assert_eq!(logged[0].credential, prefix);
        // A field sent twice: malformed, refused.
        let dup = ceremony(true);
        lock(&flows).approvals.put(auth::hash("idD"), approval_with("ab12", &value, dup.clone()));
        let fields_dup = registration(&key, &dup, &Tamper::default());
        let body = format!("approval=idD&{fields_dup}&credential={credential}");
        let (answer, _) = gate::approve(cx, "proj", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 403);
        let logged = gate::take_logged();
        assert_eq!(
            (logged[0].outcome, logged[0].passkey, logged[0].credential.as_str()),
            ("passkey refused", "malformed fields", "")
        );
        assert!(kept_passkeys(root.path()).is_empty());
        assert_eq!(gates.calls(), 0);

        // The reference the sign-in proved goes with it, whatever else the form says; the passkey registered.
        let other = bd_core::gates::oidc_approver("https://login.example.com", "00u8");
        let body = format!("approval=id1&{fields}&oidc_approver={other}&actor=acme:bob&reason=x");
        let (answer, set) = gate::approve(cx, "proj", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        let call: Call = ("proj".into(), "bd-1".into(), "acme:alice".into(), Some(reference()));
        assert_eq!(*gates.calls.lock().unwrap(), [call]);
        assert_eq!(set, vec![set_gate_cookie(ISSUER, "proj", "bd-1", "ab12", "", Duration::ZERO)], "cleared");
        let kept = kept_passkeys(root.path());
        assert_eq!(kept.len(), 1);
        assert_eq!(
            (kept[0].credential.as_str(), kept[0].alg_name(), kept[0].counter),
            (credential.as_str(), "ES256", 0)
        );
        let registered = events_of(root.path(), "passkey_registered");
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].actor.as_deref(), Some("acme:alice"));
        assert!(registered[0].detail.as_deref().unwrap().contains(&format!("credential {prefix} (ES256)")));
        let again = post("id1", "bd-1", &cookies);
        assert_eq!((page(&again.0).status, html(&again).contains("already used")), (400, true));
        assert_eq!(gates.calls(), 1);

        // The approval's id alone: taken, refused at the passkey, nothing approved; then used.
        lock(&flows).approvals.put(auth::hash("idX"), approval_with("ab12", &value, ceremony(false)));
        let (answer, _) = gate::approve(cx, "proj", "bd-1", "approval=idX", &cookies);
        assert_eq!(page(&answer).status, 403);
        assert!(page(&answer).html.contains(&pages::escape(pages::PASSKEY_FAILED_GATE)), "{}", page(&answer).html);
        assert_eq!(gates.calls(), 1);
        let again = post("idX", "bd-1", &cookies);
        assert_eq!((page(&again.0).status, html(&again).contains("already used")), (400, true));

        // The approval id twice, the same or two values: incomplete, before anything is taken or checked.
        let assert_y = ceremony(false);
        lock(&flows).approvals.put(auth::hash("idY"), approval_with("ab12", &value, assert_y.clone()));
        let fields_y = assertion(&key, &assert_y, 1, &Tamper::default());
        for twice in ["approval=idY&approval=idY", "approval=idY&approval=idX"] {
            let (answer, set) = gate::approve(cx, "proj", "bd-1", &format!("{twice}&{fields_y}"), &cookies);
            assert_eq!(page(&answer).status, 400, "{twice}");
            assert!(page(&answer).html.contains("incomplete"), "{}", page(&answer).html);
            assert!(set.is_empty(), "{twice}");
            assert!(waiting("idY") && !spent("idY"), "{twice}");
        }
        let kept = kept_passkeys(root.path());
        assert_eq!((kept.len(), kept[0].counter, kept[0].last_used_at), (1, 0, None));
        assert_eq!(gates.calls(), 1);
        let (answer, _) = gate::approve(cx, "proj", "bd-1", &format!("approval=idY&{fields_y}"), &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(gates.calls(), 2);
        let kept = kept_passkeys(root.path());
        assert_eq!(kept[0].counter, 1);
        assert!(kept[0].last_used_at.is_some());

        // What was logged: the prefix once the credential decoded, never more of it, nor the key.
        let logged = gate::take_logged();
        let lines: Vec<(&str, &str, &str)> =
            logged.iter().map(|l| (l.outcome, l.credential.as_str(), l.passkey)).collect();
        assert_eq!(
            lines,
            [
                ("approved", prefix.as_str(), "registered"),
                ("passkey refused", "", "missing fields"),
                ("approved", prefix.as_str(), "verified"),
            ]
        );
        let public_key = URL_SAFE_NO_PAD.encode(key.spki());
        for l in &logged {
            assert_eq!((l.actor.as_str(), l.workspace.as_str(), l.gate.as_str()), ("acme:alice", "proj", "bd-1"));
            let line = format!("{l:?}");
            assert!(!line.contains(&credential) && !line.contains(&public_key), "{line}");
        }
    });
    let gates = FakeGates::answering(Approved::NotArmed);
    with_ctx(root.path(), &flows, &gates, |cx| {
        // id1's passkey, in a ceremony of its own: the gate is asked, and is no longer ready.
        let use_it = ceremony(false);
        lock(&flows).approvals.put(auth::hash("id2"), approval_with("ab12", &value, use_it.clone()));
        let body = format!("approval=id2&{}", assertion(&key, &use_it, 2, &Tamper::default()));
        let (answer, _) = gate::approve(cx, "proj", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 409);
        assert!(page(&answer).html.contains("not ready"), "{}", page(&answer).html);
        assert_eq!(gates.calls(), 1);
        let logged = gate::take_logged();
        assert_eq!((logged[0].outcome, logged[0].credential.as_str()), ("not ready", prefix.as_str()));
    });
    let mut flows = Flows::default();
    for i in 0..=MAX_FLOWS {
        flows.approvals.put(i.to_string(), approval("ab12", &value));
    }
    assert_eq!(flows.approvals.map.len(), MAX_FLOWS);
    assert!(flows.approvals.take("0").is_none(), "the oldest went first");
}

/// Post `fields` for a fresh approval (`id`) asking for `c`, from its own browser.
fn post_gate(cx: &Ctx<'_>, flows: &Mutex<Flows>, id: &str, c: &Ceremony, fields: &str) -> (Answer, Vec<String>) {
    let value = "c".repeat(64);
    lock(flows).approvals.put(auth::hash(id), approval_with("ab12", &value, c.clone()));
    let cookies = format!("__Secure-bd_gate_ab12={value}");
    gate::approve(cx, "proj", "bd-1", &format!("approval={id}&{fields}"), &cookies)
}

#[test]
fn an_enrolled_account_approves_with_its_passkey_only() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let key = SoftKey::es256();
    with_ctx(root.path(), &flows, &gates, |cx| {
        let enroll = ceremony(true);
        let (answer, _) = post_gate(cx, &flows, "e", &enroll, &registration(&key, &enroll, &Tamper::default()));
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        // A valid assertion approves, moving the counter on and noting the passkey used.
        let first = ceremony(false);
        let fields = assertion(&key, &first, 5, &Tamper::default());
        assert_eq!(page(&post_gate(cx, &flows, "a1", &first, &fields).0).status, 200);
        let kept = kept_passkeys(root.path());
        assert_eq!((kept[0].counter, kept[0].last_used_at.is_some()), (5, true));
        assert_eq!(gates.calls(), 2);
        // The same assertion on a fresh approval: its challenge is not this one's.
        assert_eq!(page(&post_gate(cx, &flows, "a2", &ceremony(false), &fields).0).status, 403);
        // Another account's passkey, and a counter that went back, and a credential nobody registered.
        let bob = auth::Identity { subject: "00u8".into(), login: "bob".into(), ..acme() };
        auth::bind_account(root.path(), &bob, true, "test").unwrap();
        let bobs = SoftKey::es256();
        let bob_enroll = Ceremony::for_test(ACME_ISSUER, "00u8", true, [3; 32]);
        let fields = registration(&bobs, &bob_enroll, &Tamper::default());
        assert_eq!(page(&post_gate(cx, &flows, "b", &bob_enroll, &fields).0).status, 200);
        let c = ceremony(false);
        assert_eq!(page(&post_gate(cx, &flows, "a3", &c, &assertion(&bobs, &c, 1, &Tamper::default())).0).status, 403);
        let c = ceremony(false);
        assert_eq!(page(&post_gate(cx, &flows, "a4", &c, &assertion(&key, &c, 5, &Tamper::default())).0).status, 403);
        let c = ceremony(false);
        let stranger = SoftKey::es256();
        let fields = assertion(&stranger, &c, 9, &Tamper::default());
        assert_eq!(page(&post_gate(cx, &flows, "a5", &c, &fields).0).status, 403);
        assert_eq!(gates.calls(), 3, "only the enrollments and the first assertion approved");
        let passkeys: Vec<&str> = gate::take_logged().iter().map(|l| l.passkey).collect();
        assert_eq!(
            passkeys,
            [
                "registered",
                "verified",
                "wrong challenge",
                "registered",
                "another account's credential",
                "counter regression",
                "unknown credential"
            ]
        );
        assert_eq!(kept_passkeys(root.path())[0].counter, 5, "unchanged by the refusals");
    });

    // RS256: a 256-byte signature, 342 characters.
    let root = gate_root(false);
    with_ctx(root.path(), &flows, &gates, |cx| {
        let key = SoftKey::rs256();
        let enroll = ceremony(true);
        let (answer, _) = post_gate(cx, &flows, "r1", &enroll, &registration(&key, &enroll, &Tamper::default()));
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(kept_passkeys(root.path())[0].alg_name(), "RS256");
        let c = ceremony(false);
        let fields = key.assert(&c.expect(), 1, &Tamper::default());
        assert_eq!(URL_SAFE_NO_PAD.encode(&fields.signature).len(), 342);
        assert_eq!(page(&post_gate(cx, &flows, "r2", &c, &webauthn_body(&fields, false)).0).status, 200);
    });
    let _ = gate::take_logged();
}

/// Store a passkey of `key` for the account `subject` (bound to `actor`) at
/// the acme issuer, as a registration stores it, but without counting it.
fn put_passkey(root: &std::path::Path, credential: &str, subject: &str, actor: &str, key: &SoftKey) {
    let conn = crate::server_db::open(root).unwrap();
    let params = rusqlite::params![
        credential,
        ACME_ISSUER,
        subject,
        crate::server_db::key(actor),
        key.alg().cose(),
        key.spki(),
        0,
        1
    ];
    conn.execute(passkeys::INSERT, params).unwrap();
}

/// Fill the acme account up to `n` passkeys.
fn fill_to(root: &std::path::Path, n: usize) {
    let key = SoftKey::es256();
    for i in kept_passkeys(root).len()..n {
        put_passkey(root, &format!("AAAAAAAAAAAA{i:04}"), ACME_SUBJECT, "acme:alice", &key);
    }
    assert_eq!(kept_passkeys(root).len(), n);
}

/// A ceremony using one of the acme account's passkeys and offering to add
/// another, each with a fresh challenge.
fn adding() -> Ceremony {
    use ring::rand::SecureRandom;
    let mut add = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut add).unwrap();
    ceremony(false).with_add(add)
}

/// The fields of a registration added beside an assertion, by name and value.
fn new_pairs(f: &Fields) -> Vec<(&'static str, String)> {
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    vec![
        ("new_credential", b64(&f.credential)),
        ("new_client_data", b64(&f.client_data)),
        ("new_authenticator_data", b64(&f.authenticator_data)),
        ("new_public_key", b64(&f.public_key)),
        ("new_algorithm", f.algorithm.to_string()),
    ]
}

fn encoded(pairs: &[(&str, String)]) -> String {
    let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    form::encode(&pairs)
}

/// `f` as the `new_*` form fields of an added passkey.
fn new_fields(f: &Fields) -> String {
    encoded(&new_pairs(f))
}

/// `asserting`'s assertion in `c` at `counter` (changed by `ta`), and
/// `new`'s registration against `c`'s add challenge (changed by `tr`).
fn add_body(asserting: &SoftKey, new: &SoftKey, c: &Ceremony, counter: u32, ta: &Tamper, tr: &Tamper) -> String {
    format!("{}&{}", assertion(asserting, c, counter, ta), new_fields(&new.register(&c.expect_add(), tr)))
}

/// Register `key` as the acme account's first passkey, by an enrollment
/// POST, and check that it alone was counted: whatever is counted after is
/// the caller's.
fn enrolled(cx: &Ctx<'_>, flows: &Mutex<Flows>, key: &SoftKey) {
    settled();
    let c = ceremony(true);
    let (answer, _) = post_gate(cx, flows, "enrolled", &c, &registration(key, &c, &Tamper::default()));
    assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
    assert_eq!(passkey::take_registered(), 1, "the enrollment, counted once");
    lock(flows).approvals_spent.map.clear();
}

/// The passkeys counted as registered on this thread so far, which are
/// then forgotten: called after fixtures, before the POST a test measures.
fn settled() -> u64 {
    passkey::take_registered()
}

/// What an add refused must leave as it was: the acme account's passkeys
/// with their counters and last use, and the `passkey_registered` events.
fn snapshot(root: &std::path::Path) -> (Vec<(String, u32, Option<i64>)>, usize) {
    let kept = kept_passkeys(root).into_iter().map(|p| (p.credential, p.counter, p.last_used_at)).collect();
    (kept, events_of(root, "passkey_registered").len())
}

#[test]
fn the_add_option_is_offered_for_one_to_ninety_eight_passkeys() {
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    with_ctx(root.path(), &flows, &gates, |cx| {
        for (n, offered) in [(0, false), (1, true), (98, true), (99, false)] {
            fill_to(root.path(), n);
            let passkey::Prepared::Ask { ceremony, credentials } = passkey::prepare(cx, &acme(), "acme:alice").unwrap()
            else {
                panic!("{n}: a ceremony at an https issuer");
            };
            assert_eq!(credentials.len(), n);
            assert_eq!(ceremony.enroll, n == 0, "{n}");
            assert_eq!(ceremony.add.is_some(), offered, "{n}");
            if let Some(add) = ceremony.add {
                assert_ne!(add, ceremony.challenge, "{n}: a challenge of its own");
                assert_eq!(ceremony.expect_add().challenge, &add);
            }
            match passkey::ask(&ceremony, &credentials) {
                pages::PasskeyAsk::Assert { add: Some(add), challenge, .. } => {
                    assert!(offered, "{n}");
                    assert_eq!(add.challenge, URL_SAFE_NO_PAD.encode(ceremony.add.unwrap()));
                    assert_ne!(add.challenge, challenge);
                    assert_eq!(add.user, passkey::user_handle(ACME_ISSUER, ACME_SUBJECT));
                    assert_eq!(add.name, "acme:alice");
                }
                pages::PasskeyAsk::Assert { add: None, .. } => assert!(!offered && n > 0, "{n}"),
                pages::PasskeyAsk::Enroll { .. } => assert_eq!(n, 0),
                pages::PasskeyAsk::Unavailable { .. } => panic!("{n}: unavailable"),
            }
        }
    });
}

#[test]
fn an_added_passkey_answers_its_own_challenge_only() {
    use crate::webauthn::{Refusal, Registration, verify_registration};
    let check = |c: &Ceremony, f: &Fields| {
        let reg = Registration {
            credential: &f.credential,
            client_data: &f.client_data,
            authenticator_data: &f.authenticator_data,
            public_key: &f.public_key,
            algorithm: f.algorithm,
        };
        verify_registration(&c.expect_add(), &reg).map(|_| ())
    };
    let c = ceremony(false).with_add([7; 32]);
    let other = ceremony(false).with_add([8; 32]);
    let key = SoftKey::rs256();
    assert_eq!(check(&c, &key.register(&c.expect_add(), &Tamper::default())), Ok(()));
    // Made with the assertion's challenge, or another approval's add challenge.
    assert_eq!(check(&c, &key.register(&c.expect(), &Tamper::default())), Err(Refusal::WrongChallenge));
    assert_eq!(check(&c, &key.register(&other.expect_add(), &Tamper::default())), Err(Refusal::WrongChallenge));
}

#[test]
fn an_enrolled_account_adds_a_passkey_while_approving() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let (a, b) = (SoftKey::es256(), SoftKey::rs256());
    let ((a_id, a_prefix), (b_id, b_prefix)) = (credential_of(&a), credential_of(&b));
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let _ = gate::take_logged();
        let (calls, registered_before) = (gates.calls(), crate::metrics::PASSKEYS_REGISTERED.get());
        let events = events_of(root.path(), "passkey_registered").len();
        // A's assertion vouches for B's registration: both stored in one write, then the gate approved.
        let c = adding();
        let body = add_body(&a, &b, &c, 3, &Tamper::default(), &Tamper::default());
        assert_eq!(settled(), 0);
        let (answer, _) = post_gate(cx, &flows, "add", &c, &body);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(passkey::take_registered(), 1);
        assert!(crate::metrics::PASSKEYS_REGISTERED.get() > registered_before);
        assert_eq!(gates.calls(), calls + 1);
        let kept = kept_passkeys(root.path());
        let ids: Vec<&str> = kept.iter().map(|p| p.credential.as_str()).collect();
        assert_eq!(ids, [a_id.as_str(), b_id.as_str()]);
        assert_eq!((kept[0].counter, kept[0].last_used_at.is_some()), (3, true));
        assert_eq!((kept[1].alg_name(), kept[1].counter, kept[1].last_used_at), ("RS256", 0, None));
        let registered = events_of(root.path(), "passkey_registered");
        assert_eq!(registered.len(), events + 1);
        let detail = registered.iter().map(|e| e.detail.clone().unwrap_or_default()).find(|d| d.contains("added"));
        assert_eq!(
            detail.as_deref(),
            Some(
                format!("credential {b_prefix} (RS256), added at a browser approval with credential {a_prefix}")
                    .as_str()
            )
        );
        let logged = gate::take_logged();
        assert_eq!(logged.len(), 1);
        assert_eq!(
            (logged[0].outcome, logged[0].credential.as_str(), logged[0].added.as_str(), logged[0].passkey),
            ("approved", a_prefix.as_str(), b_prefix.as_str(), "verified and added")
        );
        let line = format!("{:?}", logged[0]);
        assert!(!line.contains(&a_id) && !line.contains(&b_id), "{line}");

        // B alone approves now.
        let c = ceremony(false);
        let body = assertion(&b, &c, 1, &Tamper::default());
        assert_eq!(settled(), 0);
        assert_eq!(page(&post_gate(cx, &flows, "b", &c, &body).0).status, 200);
        assert_eq!(passkey::take_registered(), 0);
        let logged = gate::take_logged();
        assert_eq!(
            (logged[0].outcome, logged[0].credential.as_str(), logged[0].added.as_str(), logged[0].passkey),
            ("approved", b_prefix.as_str(), "", "verified")
        );

        // Adding offered, not taken: the assertion alone approves, as without the offer.
        let c = adding();
        let body = assertion(&a, &c, 4, &Tamper::default());
        assert_eq!(settled(), 0);
        assert_eq!(page(&post_gate(cx, &flows, "plain", &c, &body).0).status, 200);
        assert_eq!(passkey::take_registered(), 0);
        assert_eq!(kept_passkeys(root.path()).len(), 2);
        assert_eq!(kept_passkeys(root.path())[0].counter, 4);
        let logged = gate::take_logged();
        assert_eq!(
            (logged[0].outcome, logged[0].credential.as_str(), logged[0].added.as_str(), logged[0].passkey),
            ("approved", a_prefix.as_str(), "", "verified")
        );
        assert_eq!(gates.calls(), calls + 3);
    });
}

#[test]
fn an_add_refused_stores_nothing_and_approves_nothing() {
    let _ = gate::take_logged();
    let a = SoftKey::es256();
    let (a_id, a_prefix) = credential_of(&a);
    let bob_key = SoftKey::es256();
    let (bob_id, _) = credential_of(&bob_key);
    let ok = Tamper::default;
    // What a case posts, given its ceremony and the new key; and what it sets up first.
    type Body = Box<dyn Fn(&Ceremony, &SoftKey) -> String>;
    type Prepare = Box<dyn Fn(&std::path::Path, &Ctx<'_>) -> Ceremony>;
    struct Case {
        name: &'static str,
        ceremony: Prepare,
        before_post: Box<dyn Fn(&std::path::Path)>,
        body: Body,
        new: Box<dyn Fn() -> SoftKey>,
        label: &'static str,
        vouched: bool,
    }
    let fresh = || -> Box<dyn Fn() -> SoftKey> { Box::new(SoftKey::es256) };
    let nothing = || -> Box<dyn Fn(&std::path::Path)> { Box::new(|_: &std::path::Path| {}) };
    let with_add = || -> Prepare { Box::new(|_, _| adding()) };
    let a = std::rc::Rc::new(a);
    let full = {
        let a = a.clone();
        move |c: &Ceremony, new: &SoftKey| add_body(&a, new, c, 1, &Tamper::default(), &Tamper::default())
    };
    let tampered = |tr: Tamper| -> Body {
        let a = a.clone();
        Box::new(move |c: &Ceremony, new: &SoftKey| add_body(&a, new, c, 1, &Tamper::default(), &tr))
    };
    let with_pairs = |change: fn(&mut Vec<(&'static str, String)>)| -> Body {
        let a = a.clone();
        Box::new(move |c: &Ceremony, new: &SoftKey| {
            let mut pairs = new_pairs(&new.register(&c.expect_add(), &Tamper::default()));
            change(&mut pairs);
            format!("{}&{}", assertion(&a, c, 1, &Tamper::default()), encoded(&pairs))
        })
    };
    let cases = vec![
        Case {
            name: "on an enrollment",
            ceremony: Box::new(|_, _| ceremony(true)),
            before_post: nothing(),
            body: Box::new(|c: &Ceremony, new: &SoftKey| {
                let other = SoftKey::es256();
                format!(
                    "{}&{}",
                    registration(&other, c, &Tamper::default()),
                    new_fields(&new.register(&c.expect(), &Tamper::default()))
                )
            }),
            new: fresh(),
            label: "adding not offered",
            vouched: false,
        },
        Case {
            name: "on an assertion without the offer",
            ceremony: Box::new(|_, _| ceremony(false)),
            before_post: nothing(),
            body: {
                let a = a.clone();
                Box::new(move |c: &Ceremony, new: &SoftKey| {
                    let r = new.register(&c.expect(), &Tamper::default());
                    format!("{}&{}", assertion(&a, c, 1, &Tamper::default()), new_fields(&r))
                })
            },
            new: fresh(),
            label: "adding not offered",
            vouched: false,
        },
        Case {
            name: "an account at the limit when the page was shown",
            ceremony: Box::new(|root, cx| {
                fill_to(root, passkeys::MAX_PER_ACCOUNT);
                let passkey::Prepared::Ask { ceremony, .. } = passkey::prepare(cx, &acme(), "acme:alice").unwrap()
                else {
                    panic!("a ceremony")
                };
                assert!(ceremony.add.is_none() && !ceremony.enroll);
                *ceremony
            }),
            before_post: nothing(),
            body: {
                let a = a.clone();
                Box::new(move |c: &Ceremony, new: &SoftKey| {
                    let r = new.register(&c.expect(), &Tamper::default());
                    format!("{}&{}", assertion(&a, c, 1, &Tamper::default()), new_fields(&r))
                })
            },
            new: fresh(),
            label: "adding not offered",
            vouched: false,
        },
        Case {
            name: "the limit reached after the page was shown",
            ceremony: with_add(),
            before_post: Box::new(|root| fill_to(root, passkeys::MAX_PER_ACCOUNT)),
            body: Box::new(full.clone()),
            new: fresh(),
            label: "limit reached",
            vouched: true,
        },
        Case {
            name: "four of the five new fields",
            ceremony: with_add(),
            before_post: nothing(),
            body: with_pairs(|p| {
                p.pop();
            }),
            new: fresh(),
            label: "missing fields",
            vouched: true,
        },
        Case {
            name: "new_credential twice",
            ceremony: with_add(),
            before_post: nothing(),
            body: with_pairs(|p| {
                let again = p[0].1.clone();
                p.push(("new_credential", again));
            }),
            new: fresh(),
            label: "malformed fields",
            vouched: true,
        },
        Case {
            name: "the new fields without an assertion",
            ceremony: with_add(),
            before_post: nothing(),
            body: Box::new(|c: &Ceremony, new: &SoftKey| {
                new_fields(&new.register(&c.expect_add(), &Tamper::default()))
            }),
            new: fresh(),
            label: "missing fields",
            vouched: false,
        },
        Case {
            name: "a tampered assertion",
            ceremony: with_add(),
            before_post: nothing(),
            body: {
                let a = a.clone();
                Box::new(move |c: &Ceremony, new: &SoftKey| {
                    let ta = Tamper { challenge: Some(vec![7; 32]), ..Tamper::default() };
                    add_body(&a, new, c, 1, &ta, &Tamper::default())
                })
            },
            new: fresh(),
            label: "wrong challenge",
            vouched: true,
        },
        Case {
            name: "a registration over the assertion's challenge",
            ceremony: with_add(),
            before_post: nothing(),
            body: {
                let a = a.clone();
                Box::new(move |c: &Ceremony, new: &SoftKey| {
                    let r = new.register(&c.expect(), &Tamper::default());
                    format!("{}&{}", assertion(&a, c, 1, &Tamper::default()), new_fields(&r))
                })
            },
            new: fresh(),
            label: "new passkey: wrong challenge",
            vouched: true,
        },
        Case {
            name: "a registration for another approval's add challenge",
            ceremony: with_add(),
            before_post: nothing(),
            body: {
                let a = a.clone();
                Box::new(move |c: &Ceremony, new: &SoftKey| {
                    let r = new.register(&adding().expect_add(), &Tamper::default());
                    format!("{}&{}", assertion(&a, c, 1, &Tamper::default()), new_fields(&r))
                })
            },
            new: fresh(),
            label: "new passkey: wrong challenge",
            vouched: true,
        },
        Case {
            name: "a registration without user verification",
            ceremony: with_add(),
            before_post: nothing(),
            body: tampered(Tamper { flags: Some(0x41), ..ok() }),
            new: fresh(),
            label: "new passkey: user not verified",
            vouched: true,
        },
        Case {
            name: "a registration from another origin",
            ceremony: with_add(),
            before_post: nothing(),
            body: tampered(Tamper { origin: Some("https://evil.example".into()), ..ok() }),
            new: fresh(),
            label: "new passkey: wrong origin",
            vouched: true,
        },
        Case {
            name: "a registration of type webauthn.get",
            ceremony: with_add(),
            before_post: nothing(),
            body: tampered(Tamper { kind: Some("webauthn.get"), ..ok() }),
            new: fresh(),
            label: "new passkey: wrong ceremony type",
            vouched: true,
        },
        Case {
            name: "the asserted credential registered again",
            ceremony: with_add(),
            before_post: nothing(),
            body: Box::new(full.clone()),
            new: {
                let a_credential = a.credential.clone();
                Box::new(move || {
                    let mut k = SoftKey::rs256();
                    k.credential = a_credential.clone();
                    k
                })
            },
            label: "credential taken",
            vouched: true,
        },
        Case {
            name: "another account's credential",
            ceremony: with_add(),
            before_post: nothing(),
            body: Box::new(full.clone()),
            new: {
                let bob_credential = bob_key.credential.clone();
                Box::new(move || {
                    let mut k = SoftKey::es256();
                    k.credential = bob_credential.clone();
                    k
                })
            },
            label: "credential taken",
            vouched: true,
        },
        Case {
            name: "an oversize new_public_key",
            ceremony: with_add(),
            before_post: nothing(),
            body: with_pairs(|p| {
                p[3].1 = "A".repeat(crate::webauthn::encoded_len(crate::webauthn::MAX_PUBLIC_KEY) + 1)
            }),
            new: fresh(),
            label: "malformed fields",
            vouched: true,
        },
    ];
    let value = "c".repeat(64);
    let cookies = format!("__Secure-bd_gate_ab12={value}");
    for (n, case) in cases.iter().enumerate() {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
        let bob = auth::Identity { subject: "00u8".into(), login: "bob".into(), ..acme() };
        auth::bind_account(root.path(), &bob, true, "test").unwrap();
        put_passkey(root.path(), &bob_id, "00u8", "acme:bob", &bob_key);
        with_ctx(root.path(), &flows, &gates, |cx| {
            enrolled(cx, &flows, &a);
            assert_eq!(kept_passkeys(root.path())[0].credential, a_id);
            let c = (case.ceremony)(root.path(), cx);
            let new = (case.new)();
            let body = (case.body)(&c, &new);
            (case.before_post)(root.path());
            let _ = gate::take_logged();
            let (before, calls) = (snapshot(root.path()), gates.calls());
            let refused_before = crate::metrics::APPROVALS_PASSKEY_REFUSED.get();
            assert_eq!(settled(), 0, "{}", case.name);
            let id = format!("refused{n}");
            let (answer, _) = post_gate(cx, &flows, &id, &c, &body);
            assert_eq!(page(&answer).status, 403, "{}: {}", case.name, page(&answer).html);
            assert_eq!(passkey::take_registered(), 0, "{}", case.name);
            assert_eq!(gates.calls(), calls, "{}", case.name);
            assert_eq!(snapshot(root.path()), before, "{}", case.name);
            assert!(crate::metrics::APPROVALS_PASSKEY_REFUSED.get() > refused_before, "{}", case.name);
            let logged = gate::take_logged();
            assert_eq!(logged.len(), 1, "{}", case.name);
            let credential = if case.vouched { a_prefix.as_str() } else { "" };
            assert_eq!(
                (logged[0].outcome, logged[0].passkey, logged[0].credential.as_str(), logged[0].added.as_str()),
                ("passkey refused", case.label, credential, ""),
                "{}",
                case.name
            );
            let (again, _) = gate::approve(cx, "proj", "bd-1", &format!("approval={id}"), &cookies);
            assert_eq!(page(&again).status, 400, "{}", case.name);
            assert!(page(&again).html.contains("already used"), "{}: {}", case.name, page(&again).html);
            assert_eq!(gates.calls(), calls, "{}", case.name);
        });
    }
}

#[test]
fn an_operation_adds_a_passkey_while_approving() {
    use operation::{Outcome, take_recorded_with_passkeys};
    let _ = take_recorded_with_passkeys();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let (a, b) = (SoftKey::es256(), SoftKey::rs256());
    let ((_, a_prefix), (b_id, b_prefix)) = (credential_of(&a), credential_of(&b));
    with_ctx(root.path(), &flows, &gates, |cx| enrolled(cx, &flows, &a));
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let value = "c".repeat(64);
    let cookies = format!("__Secure-bd_op_ab12={value}");
    let request = close_request("proj", "bd-1");
    let one = |outcome: Outcome, detail: &'static str| (outcome, "proj".into(), "close".into(), "bd-1".into(), detail);
    with_ops(root.path(), &flows, &ops, |cx| {
        let post = |id: &str, c: &Ceremony, fields: &str| {
            let approval = OperationApproval { passkey: c.clone(), ..op_approval("ab12", &value, request.clone()) };
            lock(&flows).operations.put(auth::hash(id), approval);
            operation::approve(cx, "proj", "close", "bd-1", &format!("approval={id}&{fields}"), &cookies)
        };
        let c = adding();
        let body = add_body(&a, &b, &c, 1, &Tamper::default(), &Tamper::default());
        assert_eq!(settled(), 0);
        let (answer, _) = post("o1", &c, &body);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(ops.performs().len(), 1);
        assert_eq!(passkey::take_registered(), 1);
        assert_eq!(
            take_recorded_with_passkeys(),
            vec![(one(Outcome::Approved, "performed"), a_prefix.clone(), b_prefix.clone())]
        );
        assert_eq!(kept_passkeys(root.path())[1].credential, b_id);

        // A registration for the assertion's challenge: refused, nothing stored or performed.
        let c = adding();
        let new = SoftKey::es256();
        let body = format!(
            "{}&{}",
            assertion(&a, &c, 2, &Tamper::default()),
            new_fields(&new.register(&c.expect(), &Tamper::default()))
        );
        let (before, refused_before) = (snapshot(root.path()), crate::metrics::OPERATIONS_PASSKEY_REFUSED.get());
        assert_eq!(settled(), 0);
        let (answer, _) = post("o2", &c, &body);
        assert_eq!(page(&answer).status, 403, "{}", page(&answer).html);
        assert_eq!(ops.performs().len(), 1);
        assert_eq!(passkey::take_registered(), 0);
        assert_eq!(snapshot(root.path()), before);
        assert!(crate::metrics::OPERATIONS_PASSKEY_REFUSED.get() > refused_before);
        assert_eq!(
            take_recorded_with_passkeys(),
            vec![(
                one(Outcome::PasskeyRefused, "passkey refused: new passkey: wrong challenge"),
                a_prefix.clone(),
                String::new()
            )]
        );
    });
}

#[test]
fn an_added_passkeys_refusals_are_named_after_the_ceremony() {
    use crate::webauthn::Refusal;
    for r in [
        Refusal::ClientDataTooLong,
        Refusal::ClientDataUnreadable,
        Refusal::WrongType,
        Refusal::WrongChallenge,
        Refusal::WrongOrigin,
        Refusal::CrossOrigin,
        Refusal::TopOrigin,
        Refusal::AuthDataMalformed,
        Refusal::WrongRpId,
        Refusal::UserNotPresent,
        Refusal::UserNotVerified,
        Refusal::NoCredentialData,
        Refusal::CredentialMismatch,
        Refusal::UnsupportedAlgorithm,
        Refusal::BadPublicKey,
        Refusal::BadSignature,
        Refusal::CounterRegression,
    ] {
        assert_eq!(passkey::Why::New(r).label(), format!("new passkey: {}", r.label()));
        assert_eq!(passkey::Why::New(r).detail(), format!("passkey refused: new passkey: {}", r.label()));
        assert_eq!(passkey::Why::Webauthn(r).detail(), format!("passkey refused: {}", r.label()));
    }
    assert_eq!(passkey::Why::NotOffered.label(), "adding not offered");
    assert_eq!(passkey::Why::NotOffered.detail(), "passkey refused: adding not offered");
    assert_eq!(passkey::Why::LimitReached.label(), "limit reached");
    assert_eq!(passkey::Why::LimitReached.detail(), "passkey refused: limit reached");
}

#[test]
fn webauthn_fields_are_capped_before_they_are_decoded() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let key = SoftKey::es256();
    with_ctx(root.path(), &flows, &gates, |cx| {
        let enroll = ceremony(true);
        let (answer, _) = post_gate(cx, &flows, "e", &enroll, &registration(&key, &enroll, &Tamper::default()));
        assert_eq!(page(&answer).status, 200);
        let _ = gate::take_logged();
        let fields = |credential: &str, signature: &str, c: &Ceremony| {
            let real = key.assert(&c.expect(), 1, &Tamper::default());
            form::encode(&[
                ("credential", credential),
                ("client_data", &URL_SAFE_NO_PAD.encode(&real.client_data)),
                ("authenticator_data", &URL_SAFE_NO_PAD.encode(&real.authenticator_data)),
                ("signature", signature),
            ])
        };
        let real_id = URL_SAFE_NO_PAD.encode(&key.credential);
        let sig = URL_SAFE_NO_PAD.encode(key.assert(&ceremony(false).expect(), 1, &Tamper::default()).signature);
        for (n, (credential, signature, passkey)) in [
            // 1023 bytes, 1364 characters: within the cap, an unknown credential.
            (URL_SAFE_NO_PAD.encode([7u8; 1023]), sig.clone(), "unknown credential"),
            (format!("{}A", URL_SAFE_NO_PAD.encode([7u8; 1023])), sig.clone(), "malformed fields"),
            // 600 bytes, 800 characters: within the cap, a bad signature.
            (real_id.clone(), URL_SAFE_NO_PAD.encode([7u8; 600]), "bad signature"),
            (real_id.clone(), format!("{}A", URL_SAFE_NO_PAD.encode([7u8; 600])), "malformed fields"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(matches!(credential.len(), 1364 | 1365) || matches!(signature.len(), 800 | 801));
            let c = ceremony(false);
            let (answer, _) = post_gate(cx, &flows, &format!("cap{n}"), &c, &fields(&credential, &signature, &c));
            assert_eq!(page(&answer).status, 403, "{passkey}");
            let logged = gate::take_logged();
            assert_eq!(logged[0].passkey, passkey, "{n}");
        }
        assert_eq!(gates.calls(), 1);
    });
}

#[test]
fn store_failures_after_decoding_keep_the_credential_prefix() {
    use operation::{Outcome, take_recorded_with_credential};
    let _ = gate::take_logged();
    let _ = take_recorded_with_credential();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let key = SoftKey::es256();
    let (_, prefix) = credential_of(&key);
    with_ctx(root.path(), &flows, &gates, |cx| {
        let enroll = ceremony(true);
        let (answer, _) = post_gate(cx, &flows, "e", &enroll, &registration(&key, &enroll, &Tamper::default()));
        assert_eq!(page(&answer).status, 200);
    });
    let _ = gate::take_logged();
    // The table gone at version 4: every lookup fails, and server.db is not migrated again.
    let conn = rusqlite::Connection::open(crate::server_db::path(root.path())).unwrap();
    conn.execute_batch("DROP TABLE passkeys").unwrap();
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, 4);
    drop(conn);
    with_ctx(root.path(), &flows, &gates, |cx| {
        let c = ceremony(false);
        let (answer, _) = post_gate(cx, &flows, "g", &c, &assertion(&key, &c, 1, &Tamper::default()));
        assert_eq!(page(&answer).status, 500);
    });
    assert_eq!(gates.calls(), 1, "the enrollment only");
    let logged = gate::take_logged();
    assert_eq!(logged.len(), 1);
    assert_eq!((logged[0].outcome, logged[0].credential.as_str()), ("failed", prefix.as_str()));
    // An operation's the same way.
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let value = "c".repeat(64);
    let cookies = format!("__Secure-bd_op_ab12={value}");
    with_ops(root.path(), &flows, &ops, |cx| {
        let c = ceremony(false);
        let approval =
            OperationApproval { passkey: c.clone(), ..op_approval("ab12", &value, close_request("proj", "bd-1")) };
        lock(&flows).operations.put(auth::hash("o"), approval);
        let body = format!("approval=o&{}", assertion(&key, &c, 1, &Tamper::default()));
        let (answer, _) = operation::approve(cx, "proj", "close", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 500);
    });
    assert!(ops.performs().is_empty());
    let recorded = take_recorded_with_credential();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        (recorded[0].0.0, recorded[0].0.4, recorded[0].1.as_str()),
        (Outcome::Failed, "internal error", prefix.as_str())
    );
}

#[test]
fn a_gate_on_an_ip_address_shows_a_notice() {
    let _ = gate::take_logged();
    let before = crate::metrics::APPROVALS_PASSKEY_REFUSED.get();
    let info = GateInfo {
        id: "bd-1".into(),
        title: "Ship it".into(),
        resolved: false,
        armed: true,
        approvers: None,
        holds: vec![],
        part_of: None,
        packet: None,
    };
    let answer =
        gate::unavailable("Acme SSO", &acme(), "acme:alice", "proj", "bd-1", &info, crate::webauthn::NoRp::IpLiteral);
    let p = page(&answer);
    assert!(!p.html.contains("<form") && !p.html.contains("<script"), "{}", p.html);
    assert!(p.html.contains(&pages::escape(pages::PASSKEY_UNAVAILABLE_HOST)), "{}", p.html);
    assert!(crate::metrics::APPROVALS_PASSKEY_REFUSED.get() > before);
    let logged = gate::take_logged();
    assert_eq!(logged.len(), 1);
    assert_eq!(
        (logged[0].outcome, logged[0].credential.as_str(), logged[0].passkey),
        ("passkey refused", "", "unavailable")
    );
    assert_eq!((logged[0].actor.as_str(), logged[0].provider.as_str()), ("acme:alice", "acme"));
}

#[test]
fn gate_cookies_are_strict_to_their_page() {
    let c = "e".repeat(64);
    assert_eq!(
        set_gate_cookie(ISSUER, "proj", "bd-1", "ab12", &c, STEP_TTL),
        format!(
            "__Secure-bd_gate_ab12={c}; Path=/bd/w/proj/gates/bd-1; Max-Age=600; HttpOnly; SameSite=Strict; Secure"
        )
    );
    assert_eq!(
        set_gate_cookie("http://127.0.0.1:7420", "proj", "bd-1", "ab12", &c, STEP_TTL),
        format!("bd_gate_ab12={c}; Path=/w/proj/gates/bd-1; Max-Age=600; HttpOnly; SameSite=Strict")
    );
    assert_eq!(gate_cookie(ISSUER, &format!("__Secure-bd_gate_ab12={c}"), "ab12"), Some(c.as_str()));
    assert_eq!(gate_cookie(ISSUER, &format!("bd_gate_ab12={c}"), "ab12"), None, "unprefixed, on https");
    assert_eq!(gate_cookie(ISSUER, "__Secure-bd_gate_ab12=abc", "ab12"), None);
    assert!(gate::gate_id_ok("bd-1.2_x") && !gate::gate_id_ok("") && !gate::gate_id_ok(".x"));
    assert!(!gate::gate_id_ok(&"a".repeat(129)) && gate::gate_id_ok(&"a".repeat(128)));
}

fn op_then() -> Then {
    let digest = auth::hash("token");
    Then::Operation { workspace: "proj".into(), op: "close".into(), issue: "bd-1".into(), digest, parts: 1 }
}

#[test]
fn an_operation_flow_opens_only_as_an_operation() {
    let sealer = Sealer::new();
    let at = || AtProvider { provider: "github".into(), state: "s".into(), verifier: "v".into(), nonce: "n".into() };
    let op = |at: Option<AtProvider>| Pending { then: op_then(), browser: "b".into(), until: 1, at };
    for (step, pending) in [(OP_BEGIN, op(None)), (CHOOSING, op(None)), (AT_PROVIDER, op(Some(at())))] {
        let sealed = sealer.seal(step, &pending).unwrap();
        let opened = sealer.open(step, &sealed).unwrap();
        assert_eq!(opened, pending, "{step}");
        assert_eq!(opened.then.kind(), Kind::Operation);
        let flow = opened.then.operation().unwrap();
        assert_eq!((flow.workspace.as_str(), flow.op.as_str(), flow.issue.as_str()), ("proj", "close", "bd-1"));
        assert_eq!((flow.digest, flow.parts), (auth::hash("token"), 1));
        for other in [OP_BEGIN, GATE_BEGIN, CHOOSING, AT_PROVIDER].into_iter().filter(|s| *s != step) {
            assert_eq!(sealer.open(other, &sealed), None, "{step} as {other}");
        }
    }
    // An authorization sealed under an operation's AAD is not taken for an operation's flow.
    let authorize = Pending { then: Then::Authorize { query: "q".into() }, browser: "b".into(), until: 1, at: None };
    for (forged_as, step) in [("op:provider", AT_PROVIDER), ("op:op-begin", OP_BEGIN), ("op:choose", CHOOSING)] {
        let forged = sealer.seal(forged_as, &authorize).unwrap();
        assert_eq!(sealer.open(step, &forged), None, "{forged_as}");
    }
    // A gate's flow and an authorization's are no operation's.
    let sealed = sealer.seal(AT_PROVIDER, &gate_pending()).unwrap();
    assert_eq!(sealer.open(AT_PROVIDER, &sealed).unwrap().then.operation(), None);
    let begun = sealer.seal(GATE_BEGIN, &gate_pending()).unwrap();
    assert_eq!(sealer.open(OP_BEGIN, &begun), None);
    let json = serde_json::to_value(op_then()).unwrap();
    assert_eq!(json["then"], "operation");
    assert_eq!(serde_json::from_value::<Then>(json).unwrap(), op_then());
}

#[test]
fn the_longest_operation_flow_fits_its_cookie() {
    let then = Then::Operation {
        workspace: "w".repeat(100),
        op: "discard".into(),
        issue: "i".repeat(128),
        digest: auth::hash("token"),
        parts: MAX_REQUEST_PARTS,
    };
    let at =
        AtProvider { provider: "p".repeat(32), state: "s".repeat(32), verifier: "v".repeat(64), nonce: "n".repeat(32) };
    let pending = Pending { then, browser: auth::hash("browser"), until: i64::MAX, at: Some(at) };
    let sealed = Sealer::new().seal(AT_PROVIDER, &pending).unwrap();
    assert!(sealed.len() <= MAX_SEALED, "{}", sealed.len());
}

#[test]
fn an_operation_link_rides_through_the_sign_in_in_request_cookies() {
    let max = bd_cli::approval_link::MAX_TOKEN;
    let token: String = (0..max).map(|i| ["A", "z", "0", "-", "_"][i % 5]).collect();
    let digest = auth::hash(&token);
    let name = |n: u8| format!("__Secure-bd_opreq_{}_{n}", &digest[..16]);
    assert_eq!(request_parts(max), Some(2));
    assert_eq!(request_parts(0), Some(1));
    assert_eq!(request_parts(REQUEST_PART), Some(1));
    assert_eq!(request_parts(REQUEST_PART + 1), Some(2));
    assert_eq!(request_parts(2 * REQUEST_PART + 1), None);

    let set = set_request_cookies(ISSUER, &digest, &token, 2 * STEP_TTL);
    assert_eq!(set.len(), 2);
    let mut header = String::from("x=1");
    for (n, cookie) in (1u8..).zip(&set) {
        let (pair, attributes) = cookie.split_once("; ").unwrap();
        let (cookie_name, value) = pair.split_once('=').unwrap();
        assert_eq!(cookie_name, name(n));
        assert!(value.len() <= REQUEST_PART, "{n}: {}", value.len());
        assert_eq!(attributes, "Path=/bd/oauth; Max-Age=1200; HttpOnly; SameSite=Lax; Secure");
        header.push_str(&format!("; {pair}"));
    }
    assert_eq!(request_cookies(ISSUER, &header, &digest, 2).as_deref(), Some(token.as_str()));
    // Parts in the other order are joined in theirs.
    let swapped = format!("{}; {}", set[1].split("; ").next().unwrap(), set[0].split("; ").next().unwrap());
    assert_eq!(request_cookies(ISSUER, &swapped, &digest, 2).as_deref(), Some(token.as_str()));
    // A part missing, a character no token has, or the count the flow did not say: none.
    let first = set[0].split("; ").next().unwrap();
    assert_eq!(request_cookies(ISSUER, first, &digest, 2), None);
    assert_eq!(request_cookies(ISSUER, &header.replacen("=A", "=+", 1), &digest, 2), None);
    assert_eq!(request_cookies(ISSUER, &header.replacen("=A", "=A.", 1), &digest, 2), None);
    assert_eq!(request_cookies(ISSUER, &header, &digest, 0), None);
    assert_eq!(request_cookies(ISSUER, &header, &digest, 3), None);
    assert_eq!(request_cookies(ISSUER, &header, &auth::hash("other"), 2), None);
    assert_eq!(request_cookies(ISSUER, &header.replace("__Secure-", ""), &digest, 2), None, "unprefixed, on https");
    // One part, on plain http.
    let http = "http://127.0.0.1:7420";
    let short = "abc_DEF-123";
    let set = set_request_cookies(http, &digest, short, STEP_TTL);
    let opreq = format!("bd_opreq_{}_1", &digest[..16]);
    assert_eq!(set, vec![format!("{opreq}={short}; Path=/oauth; Max-Age=600; HttpOnly; SameSite=Lax")]);
    assert_eq!(request_cookies(http, &format!("{opreq}={short}"), &digest, 1).as_deref(), Some(short));
    // Cleared by the same names.
    assert_eq!(
        clear_request_cookies(ISSUER, &digest, 2),
        vec![
            format!("{}=; Path=/bd/oauth; Max-Age=0; HttpOnly; SameSite=Lax; Secure", name(1)),
            format!("{}=; Path=/bd/oauth; Max-Age=0; HttpOnly; SameSite=Lax; Secure", name(2)),
        ]
    );
    assert_eq!(
        clear_request_cookies(http, &digest, 1),
        vec![format!("{opreq}=; Path=/oauth; Max-Age=0; HttpOnly; SameSite=Lax")]
    );
}

#[test]
fn op_cookies_are_strict_to_their_page() {
    let c = "e".repeat(64);
    assert_eq!(
        set_op_cookie(ISSUER, "proj", "close", "bd-1", "ab12", &c, STEP_TTL),
        format!("__Secure-bd_op_ab12={c}; Path=/bd/w/proj/close/bd-1; Max-Age=600; HttpOnly; SameSite=Strict; Secure")
    );
    assert_eq!(
        set_op_cookie("http://127.0.0.1:7420", "proj", "discard", "bd-1", "ab12", "", Duration::ZERO),
        "bd_op_ab12=; Path=/w/proj/discard/bd-1; Max-Age=0; HttpOnly; SameSite=Strict"
    );
    assert_eq!(op_cookie(ISSUER, &format!("x=1; __Secure-bd_op_ab12={c}"), "ab12"), Some(c.as_str()));
    assert_eq!(op_cookie(ISSUER, &format!("bd_op_ab12={c}"), "ab12"), None, "unprefixed, on https");
    assert_eq!(op_cookie(ISSUER, &format!("__Secure-bd_op_ab13={c}"), "ab12"), None);
    assert_eq!(op_cookie(ISSUER, "__Secure-bd_op_ab12=abc", "ab12"), None);
    assert_eq!(op_cookie(ISSUER, &format!("__Secure-bd_op_ab12={}", "E".repeat(64)), "ab12"), None);
    assert_eq!(op_cookie(ISSUER, &format!("__Secure-bd_gate_ab12={c}"), "ab12"), None, "a gate's is not an op's");
}

#[test]
fn each_outcome_is_recorded_once_per_call() {
    use operation::{Outcome, Who, record, take_recorded};
    let _ = take_recorded();
    let who = Who {
        provider: "github",
        login: "alice",
        subject: "1",
        actor: "github:alice",
        credential: "AAAAAAAAAAAA",
        added: "",
    };
    record(Outcome::Approved, &who, "proj", "close", "bd-1", "performed");
    assert_eq!(
        operation::take_recorded_with_credential(),
        vec![(
            (Outcome::Approved, "proj".into(), "close".into(), "bd-1".into(), "performed"),
            "AAAAAAAAAAAA".to_string()
        )]
    );
    assert_eq!(take_recorded(), vec![], "drained");
    let outcomes = [
        Outcome::Approved,
        Outcome::Refused,
        Outcome::NotReady,
        Outcome::Gone,
        Outcome::Busy,
        Outcome::Failed,
        Outcome::PasskeyRefused,
    ];
    for outcome in outcomes {
        record(outcome, &Who::provider_only("acme"), "proj", "discard", "bd-2", "flow expired");
    }
    let recorded = take_recorded();
    assert_eq!(recorded.iter().map(|r| r.0).collect::<Vec<_>>(), outcomes);
    assert!(recorded.iter().all(|r| (r.1.as_str(), r.2.as_str(), r.3.as_str()) == ("proj", "discard", "bd-2")));
    let labels: Vec<_> = outcomes.iter().map(|o| o.label()).collect();
    assert_eq!(labels, ["approved", "refused", "not_ready", "gone", "busy", "failed", "passkey_refused"]);
    assert_eq!(
        Who::provider_only("acme"),
        Who { provider: "acme", login: "", subject: "", actor: "", credential: "", added: "" }
    );
}

/// What [`FakeOperations::perform`] was asked: the request, the actor and the OIDC approver reference.
type Performing = (OperationRequest, String, Option<String>);

/// Operations answering as told, counting finds and keeping what they were asked to perform.
struct FakeOperations {
    found: OpFound,
    performed: Performed,
    finds: std::sync::Mutex<usize>,
    performs: std::sync::Mutex<Vec<Performing>>,
}

impl FakeOperations {
    fn new(found: OpFound, performed: Performed) -> FakeOperations {
        FakeOperations { found, performed, finds: Default::default(), performs: Default::default() }
    }

    fn finds(&self) -> usize {
        *self.finds.lock().unwrap()
    }

    fn performs(&self) -> Vec<Performing> {
        self.performs.lock().unwrap().clone()
    }
}

impl Operations for FakeOperations {
    fn find(&self, _: &OperationRequest, _: &Approver<'_>) -> Result<OpFound, bd_core::Error> {
        *self.finds.lock().unwrap() += 1;
        Ok(self.found.clone())
    }

    fn perform(
        &self,
        req: &OperationRequest,
        actor: &str,
        oidc_approver: Option<&str>,
    ) -> Result<Performed, bd_core::Error> {
        self.performs.lock().unwrap().push((req.clone(), actor.into(), oidc_approver.map(String::from)));
        Ok(self.performed.clone())
    }
}

fn link_key() -> LinkKey {
    LinkKey::from_bytes(&[9; 32]).unwrap()
}

fn with_ops<T>(
    root: &std::path::Path,
    flows: &Mutex<Flows>,
    operations: &FakeOperations,
    f: impl FnOnce(&Ctx<'_>) -> T,
) -> T {
    with_ops_at(ISSUER, root, flows, operations, f)
}

/// [`with_ops`], at `issuer`.
fn with_ops_at<T>(
    issuer: &str,
    root: &std::path::Path,
    flows: &Mutex<Flows>,
    operations: &FakeOperations,
    f: impl FnOnce(&Ctx<'_>) -> T,
) -> T {
    let documents = super::super::cimd::Documents::new();
    let exists = |_: &str| true;
    let gates = FakeGates::answering(Approved::Resolved);
    let key = link_key();
    f(&Ctx {
        root,
        issuer,
        documents: &documents,
        flows,
        workspace_exists: &exists,
        gates: &gates,
        links: Some(&key),
        operations,
    })
}

/// alice's agent's forced close of `issue` in `ws`, asked now.
fn close_request(ws: &str, issue: &str) -> OperationRequest {
    OperationRequest {
        reason: Some("  why\n".into()),
        force: true,
        ..OperationRequest::new(ws.into(), Op::Close, issue.into(), "alice/agent-1".into(), now_millis())
    }
}

fn sealed(req: &OperationRequest) -> String {
    approval_link::seal(&link_key(), req).unwrap()
}

fn link_query(token: &str) -> String {
    form::encode(&[("request", token)])
}

/// The `Cookie` header pairs of `Set-Cookie` values.
fn sent(set: &[String]) -> String {
    set.iter().map(|c| c.split("; ").next().unwrap()).collect::<Vec<_>>().join("; ")
}

#[test]
fn an_operation_link_goes_on_to_the_chooser_telling_nothing() {
    let _ = operation::take_recorded();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    with_ops(root.path(), &flows, &ops, |cx| {
        // Genuine links for a target that exists and one that does not: the same answer, up to the values.
        let mut shapes = Vec::new();
        for (ws, issue) in [("proj", "bd-1"), ("nosuch", "bd-404.7")] {
            let token = sealed(&close_request(ws, issue));
            let (answer, cookies) = operation::begin(cx, ws, "close", issue, &link_query(&token));
            let Answer::Redirect(url) = &answer else { panic!("{ws}/{issue}: {answer:?}") };
            assert!(url.starts_with(&format!("{ISSUER}/oauth/choose?flow=")), "{url}");
            let opened = lock(&flows).sealer.open(OP_BEGIN, &flow_of(url)).unwrap();
            let flow = opened.then.operation().unwrap();
            let digest = auth::hash(&token);
            assert_eq!(
                (flow.workspace.as_str(), flow.op.as_str(), flow.issue.as_str(), flow.digest.as_str(), flow.parts),
                (ws, "close", issue, digest.as_str(), 1)
            );
            assert_eq!(opened.browser, "", "bound to a browser at the chooser");
            assert_eq!(cookies, set_request_cookies(ISSUER, &digest, &token, 2 * STEP_TTL));
            let shape: Vec<String> = cookies
                .iter()
                .map(|c| {
                    let (pair, attributes) = c.split_once("; ").unwrap();
                    let name = pair.split_once('=').unwrap().0.replace(&digest[..16], "<digest>");
                    format!("{name}; {attributes}")
                })
                .collect();
            shapes.push(shape);
        }
        assert_eq!(shapes[0], shapes[1]);
        assert_eq!(
            shapes[0],
            ["__Secure-bd_opreq_<digest>_1; Path=/bd/oauth; Max-Age=1200; HttpOnly; SameSite=Lax; Secure"]
        );

        // Not genuine, or not for this path: as if there were nothing here.
        let token = sealed(&close_request("proj", "bd-1"));
        let mut tampered = token.clone().into_bytes();
        tampered[20] = if tampered[20] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        for (ws, op, issue, query) in [
            ("proj", "close", "bd-1", link_query(&tampered)),
            ("proj", "close", "bd-1", link_query("garbage")),
            ("proj", "close", "bd-1", String::new()),
            ("proj", "discard", "bd-1", link_query(&token)),
            ("proj", "close", "bd-2", link_query(&token)),
            ("other", "close", "bd-1", link_query(&token)),
            ("proj", "delete", "bd-1", link_query(&token)),
            ("a/b", "close", "bd-1", link_query(&token)),
            ("proj", "close", "../x", link_query(&token)),
        ] {
            let (answer, cookies) = operation::begin(cx, ws, op, issue, &query);
            assert_eq!(page(&answer).status, 404, "{ws}/{op}/{issue}");
            assert!(cookies.is_empty(), "{cookies:?}");
        }
        // Genuine, but past its time.
        let old = OperationRequest::new("proj".into(), Op::Close, "bd-1".into(), "a".into(), now_millis() - TTL - 1);
        let (answer, cookies) = operation::begin(cx, "proj", "close", "bd-1", &link_query(&sealed(&old)));
        assert_eq!((page(&answer).status, cookies.len()), (410, 0));
        // Too long to be one: refused before it is decoded.
        let long = format!("request={}", "A".repeat(MAX_QUERY));
        let (answer, cookies) = operation::begin(cx, "proj", "close", "bd-1", &long);
        assert_eq!((page(&answer).status, cookies.len()), (400, 0));
    });
    // Without a key, there are no links to begin.
    let gates = FakeGates::answering(Approved::Resolved);
    with_ctx(root.path(), &flows, &gates, |cx| {
        let token = sealed(&close_request("proj", "bd-1"));
        assert_eq!(page(&operation::begin(cx, "proj", "close", "bd-1", &link_query(&token)).0).status, 404);
    });
    assert_eq!(ops.finds(), 0, "nothing looked up");
    assert!(lock(&flows).operations.map.is_empty());
    assert_eq!(operation::take_recorded(), vec![], "nothing recorded");
}

#[test]
fn the_chooser_binds_an_operation_flow_to_the_browser_and_goes_on() {
    let _ = operation::take_recorded();
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    with_ops(root.path(), &flows, &ops, |cx| {
        let token = sealed(&close_request("proj", "bd-1"));
        let Answer::Redirect(url) = operation::begin(cx, "proj", "close", "bd-1", &link_query(&token)).0 else {
            panic!()
        };
        let query = form::encode(&[("flow", flow_of(&url).as_str())]);
        let (answer, cookies) = choose(cx, &query, None);
        let Answer::Redirect(to) = answer else { panic!("{answer:?}") };
        assert!(to.starts_with("https://github.com/login/oauth/authorize?"), "{to}");
        assert!(cookies.iter().any(|c| c.starts_with(&format!("{SECURE_COOKIE}="))), "{cookies:?}");
        let flow_cookie = cookies.iter().find(|c| c.starts_with("__Secure-bd_flow_")).unwrap();
        let sealed_flow = flow_cookie.split_once('=').unwrap().1.split(';').next().unwrap();
        let opened = lock(&flows).sealer.open(AT_PROVIDER, sealed_flow).unwrap();
        assert_eq!(opened.then.operation().unwrap().digest, auth::hash(&token));
        assert_eq!(page(&choose(cx, &format!("{query}&provider=github"), None).0).status, 400);
    });
    let root = gate_root(true);
    with_ops(root.path(), &flows, &ops, |cx| {
        let token = sealed(&OperationRequest::new("proj".into(), Op::Discard, "bd-1".into(), "a".into(), now_millis()));
        let Answer::Redirect(url) = operation::begin(cx, "proj", "discard", "bd-1", &link_query(&token)).0 else {
            panic!()
        };
        let browser = "b".repeat(64);
        let (answer, cookies) = choose(cx, &form::encode(&[("flow", flow_of(&url).as_str())]), Some(&browser));
        let p = page(&answer);
        assert_eq!(p.status, 200);
        assert!(p.html.contains("Sign in to approve the discard of bd-1 in proj"), "{}", p.html);
        assert_eq!(cookies, vec![set_cookie(ISSUER, &browser)]);
        let link = p.html.split("href=\"").nth(1).unwrap();
        let opened = lock(&flows).sealer.open(CHOOSING, &flow_of(link)).unwrap();
        assert_eq!(opened.then.operation().unwrap().op, "discard");
    });
    assert_eq!(ops.finds(), 0);
    assert_eq!(operation::take_recorded(), vec![]);
}

/// A flow at `provider` sealed in `flows` (`then`, for the browser `browser`, until `until`): the callback's query
/// (with `extra`) and the `Cookie` header the browser sends with it.
fn at_provider(
    flows: &Mutex<Flows>,
    then: Then,
    provider: &str,
    browser: &str,
    until: i64,
    extra: &[(&str, &str)],
) -> (String, String) {
    let state = "st4te";
    let at = AtProvider { provider: provider.into(), state: state.into(), verifier: "v".into(), nonce: "n".into() };
    let pending = Pending { then, browser: auth::hash(browser), until, at: Some(at) };
    let sealed = lock(flows).sealer.seal(AT_PROVIDER, &pending).unwrap();
    let cookie = sent(&[set_flow_cookie(ISSUER, state, &sealed, STEP_TTL)]);
    let mut query = vec![("state", state), ("code", "c0de")];
    query.extend_from_slice(extra);
    (form::encode(&query), cookie)
}

/// A callback ending early: its root, the provider the flow started with, the one it came back at, the browser it
/// came from, the flow's `until`, the query's extra pairs, and what is recorded.
type EarlyEnd<'a> =
    (&'a std::path::Path, &'a str, &'a str, &'a str, i64, &'a [(&'a str, &'a str)], operation::Outcome, &'a str);

#[test]
fn every_early_end_of_an_operation_callback_is_recorded_once() {
    use operation::{Outcome, take_recorded};
    let _ = take_recorded();
    let browser = "b".repeat(64);
    let other = "c".repeat(64);
    let digest = auth::hash("token");
    let later = now_millis() + 60_000;
    let no_auth = tempfile::tempdir().unwrap();
    let no_oauth = tempfile::tempdir().unwrap();
    std::fs::write(
        no_oauth.path().join("auth.toml"),
        "[github]\nclient_id = \"Iv1.test\"\n[[github.allow]]\nusers = [\"alice\"]\n",
    )
    .unwrap();
    let invalid = tempfile::tempdir().unwrap();
    std::fs::write(invalid.path().join("auth.toml"), "[oauth\n").unwrap();
    let (github, both) = (gate_root(false), gate_root(true));
    let evil = [("iss", "https://evil.example")];
    // root, started with, called back at, browser, until, extra, outcome, detail
    let cases: Vec<EarlyEnd<'_>> = vec![
        (github.path(), "github", "github", &browser, now_millis() - 1, &[], Outcome::Refused, "flow expired"),
        (github.path(), "github", "github", &other, later, &[], Outcome::Refused, "different browser"),
        (both.path(), "github", "acme", &browser, later, &[], Outcome::Refused, "another provider"),
        (no_auth.path(), "github", "github", &browser, later, &[], Outcome::Failed, "sign-in settings unavailable"),
        (no_oauth.path(), "github", "github", &browser, later, &[], Outcome::Failed, "sign-in settings unavailable"),
        (invalid.path(), "github", "github", &browser, later, &[], Outcome::Failed, "sign-in settings unavailable"),
        (both.path(), "acme", "acme", &browser, later, &evil, Outcome::Refused, "another issuer"),
    ];
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    for (root, started, at, sent_from, until, extra, outcome, detail) in cases {
        let flows = Mutex::new(Flows::default());
        let (query, cookie) = at_provider(&flows, op_then(), started, &browser, until, extra);
        let sent_by = if sent_from == browser { browser.as_str() } else { other.as_str() };
        let (answer, set) =
            with_ops(root, &flows, &ops, |cx| callback(cx, at, &query, Some(sent_by), &format!("{cookie}; x=1")));
        let status = match (detail, root == invalid.path()) {
            (_, true) => 500,
            ("sign-in settings unavailable", false) => 404,
            _ => 400,
        };
        assert_eq!(page(&answer).status, status, "{detail}");
        assert_eq!(take_recorded(), vec![(outcome, "proj".into(), "close".into(), "bd-1".into(), detail)], "{detail}");
        for cleared in clear_request_cookies(ISSUER, &digest, 1) {
            assert!(set.contains(&cleared), "{detail}: {set:?}");
        }
        // The same ends for a gate's flow, or with no flow the server sealed, record nothing.
        let (query, cookie) = at_provider(&flows, gate_pending().then, started, &browser, until, extra);
        let (_, set) = with_ops(root, &flows, &ops, |cx| callback(cx, at, &query, Some(sent_by), &cookie));
        assert!(!set.iter().any(|c| c.contains("bd_opreq_")), "{set:?}");
        let tampered = cookie.replacen('=', "=x", 1);
        with_ops(root, &flows, &ops, |cx| callback(cx, at, &query, Some(sent_by), &tampered));
        with_ops(root, &flows, &ops, |cx| callback(cx, at, &query, Some(sent_by), ""));
        assert_eq!(take_recorded(), vec![], "{detail}: not an operation's");
    }
    assert_eq!((ops.finds(), ops.performs().len()), (0, 0));
}

#[test]
fn an_operation_flow_is_known_without_the_settings() {
    let flows = Mutex::new(Flows::default());
    let empty = tempfile::tempdir().unwrap();
    let (query, cookie) = at_provider(&flows, op_then(), "acme", "b", now_millis() - 1, &[]);
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    with_ops(empty.path(), &flows, &ops, |cx| {
        let (flow, provider) = operation::operation_flow(cx, &query, &cookie).expect("expired, and still known");
        assert_eq!((flow.workspace.as_str(), flow.op.as_str(), flow.issue.as_str()), ("proj", "close", "bd-1"));
        assert_eq!(provider, "acme");
        assert_eq!(operation::operation_flow(cx, &query, ""), None);
        assert_eq!(operation::operation_flow(cx, "state=other", &cookie), None);
        let (query, cookie) = at_provider(&flows, gate_pending().then, "acme", "b", now_millis() + 1000, &[]);
        assert_eq!(operation::operation_flow(cx, &query, &cookie), None, "a gate's");
    });
    assert!(!empty.path().join("auth.toml").exists());
}

#[test]
fn a_waiting_operation_approval_is_peeked_only_while_it_waits_at_its_path() {
    let flows = Mutex::new(Flows::default());
    let peek = |id: &str, op: &str, issue: &str| pending_operation(&flows, id, "t", op, issue);
    let request = OperationRequest::new("t".into(), Op::Close, "t-1".into(), "a".into(), now_millis());
    operation::test_put_operation(&flows, "live", request.clone());
    let who = ("github".to_string(), "alice".to_string(), "1".to_string(), "github:alice".to_string());
    assert_eq!(peek("live", "close", "t-1"), Some(who.clone()));
    assert_eq!(peek("live", "close", "t-1"), Some(who), "peeked, not taken");
    assert_eq!(peek("live", "discard", "t-1"), None);
    assert_eq!(peek("live", "close", "t-2"), None);
    assert_eq!(pending_operation(&flows, "live", "other", "close", "t-1"), None);
    assert_eq!(peek("nope", "close", "t-1"), None);
    operation::test_put_operation(&flows, "spent", request.clone());
    lock(&flows).operations_spent.put(auth::hash("spent"), ());
    assert_eq!(peek("spent", "close", "t-1"), None);
    operation::test_put_operation(&flows, "taken", request.clone());
    assert!(lock(&flows).operations.take(&auth::hash("taken")).is_some());
    assert_eq!(peek("taken", "close", "t-1"), None);
    operation::test_put_operation(&flows, "old", request);
    let mut held = lock(&flows);
    let (_, entry) = held.operations.map.remove(&auth::hash("old")).unwrap();
    held.operations.put_until(auth::hash("old"), std::time::Instant::now(), entry);
    drop(held);
    assert_eq!(peek("old", "close", "t-1"), None, "expired");
}

fn admitted_as(kind: auth::Kind) -> crate::oauth::Admitted {
    let mut admitted = sample_code().admitted;
    admitted.grant.kind = kind;
    admitted
}

fn op_flow_for(token: &str, op: &str) -> OpFlow {
    OpFlow {
        workspace: "proj".into(),
        op: op.into(),
        issue: "bd-1".into(),
        digest: auth::hash(token),
        parts: request_parts(token.len()).unwrap(),
    }
}

fn in_the_way(may_open: bool) -> GateInWay {
    GateInWay { id: "bd-9".into(), title: "Ship <it>".into(), approvers: Some(vec!["github:carol".into()]), may_open }
}

fn found_op(gates: Vec<GateInWay>, deletes: Option<(Vec<(String, String)>, usize)>) -> OpFound {
    OpFound::Op(Box::new(OpInfo {
        id: "bd-1".into(),
        title: "Abandon me".into(),
        status: "open".into(),
        part_of: None,
        gates,
        deletes,
    }))
}

#[test]
fn an_operation_page_is_shown_only_to_an_admitted_person_who_may_open_every_gate() {
    use operation::{Outcome, take_recorded};
    let _ = take_recorded();
    let root = gate_root(false);
    let token = sealed(&close_request("proj", "bd-1"));
    let flow = op_flow_for(&token, "close");
    let cookies = format!("x=1; {}", sent(&set_request_cookies(ISSUER, &flow.digest, &token, STEP_TTL)));
    let recorded =
        |outcome: Outcome, detail: &'static str| vec![(outcome, "proj".into(), "close".into(), "bd-1".into(), detail)];
    let run = |ops: &FakeOperations, admitted: Result<crate::oauth::Admitted, bd_core::Error>, cookies: &str| {
        let flows = Mutex::new(Flows::default());
        let mut fresh = None;
        let answer = with_ops(root.path(), &flows, ops, |cx| {
            operation::after_sign_in(cx, "GitHub", "github", admitted, &flow, cookies, &mut fresh)
        });
        let waiting = lock(&flows).operations.map.len();
        (answer, fresh, waiting)
    };

    // Not let in, or not a person's access: refused before anything is looked up.
    let ops = FakeOperations::new(found_op(vec![in_the_way(true)], None), Performed::Closed);
    let (answer, fresh, waiting) = run(&ops, Err(bd_core::Error::Unauthorized("no rule".into())), &cookies);
    assert_eq!((page(&answer).status, fresh, waiting), (403, None, 0));
    assert_eq!(take_recorded(), recorded(Outcome::Refused, "not admitted"));
    let (answer, _, waiting) = run(&ops, Ok(admitted_as(auth::Kind::Agent)), &cookies);
    assert_eq!((page(&answer).status, waiting), (403, 0));
    assert_eq!(take_recorded(), recorded(Outcome::Refused, "not a person's access"));
    assert_eq!(ops.finds(), 0);

    // The link's token must come through the sign-in, and be the one the flow was sealed with.
    let (answer, _, _) = run(&ops, Ok(admitted_as(auth::Kind::Human)), "x=1");
    assert_eq!(page(&answer).status, 400);
    assert_eq!(take_recorded(), recorded(Outcome::Refused, "request cookies missing"));
    let other = sealed(&close_request("proj", "bd-1"));
    let swapped = sent(&set_request_cookies(ISSUER, &flow.digest, &other, STEP_TTL));
    let (answer, _, _) = run(&ops, Ok(admitted_as(auth::Kind::Human)), &swapped);
    assert_eq!(page(&answer).status, 400);
    assert_eq!(take_recorded(), recorded(Outcome::Refused, "request cookies missing"));
    assert_eq!(ops.finds(), 0);

    // A gate the person may not open: refused, naming it and its approvers.
    let ops = FakeOperations::new(found_op(vec![in_the_way(true), in_the_way(false)], None), Performed::Closed);
    let (answer, fresh, waiting) = run(&ops, Ok(admitted_as(auth::Kind::Human)), &cookies);
    let p = page(&answer);
    assert_eq!((p.status, fresh, waiting), (403, None, 0));
    assert!(p.html.contains("bd-9") && p.html.contains("github:carol"), "{}", p.html);
    assert!(!p.html.contains("<form"), "{}", p.html);
    assert_eq!(take_recorded(), recorded(Outcome::Refused, "not an approver"));

    // A target no longer as asked, or gone.
    for (found, status, outcome, detail) in [
        (OpFound::NotHeld, 409, Outcome::NotReady, "no longer held"),
        (OpFound::Changed("bd-1 is a gate.".into()), 409, Outcome::NotReady, "target changed"),
        (OpFound::Done, 409, Outcome::Gone, "already closed"),
        (OpFound::NoIssue, 404, Outcome::Gone, "no such issue"),
        (OpFound::NoWorkspace, 404, Outcome::Gone, "no such workspace"),
    ] {
        let ops = FakeOperations::new(found, Performed::Closed);
        let (answer, fresh, waiting) = run(&ops, Ok(admitted_as(auth::Kind::Human)), &cookies);
        let p = page(&answer);
        assert_eq!((p.status, fresh.is_none(), waiting), (status, true, 0), "{detail}");
        assert!(!p.html.contains("<form"), "{detail}: {}", p.html);
        assert_eq!(take_recorded(), recorded(outcome, detail));
    }

    // Every gate the person may open: the page, with a cookie of its own and the approval kept; nothing recorded.
    let deletes = (vec![("bd-1".to_string(), "Run".to_string())], 1);
    let ops = FakeOperations::new(found_op(vec![in_the_way(true)], Some(deletes)), Performed::Closed);
    let (answer, fresh, waiting) = run(&ops, Ok(admitted_as(auth::Kind::Human)), &cookies);
    let p = page(&answer);
    assert_eq!((p.status, waiting), (200, 1), "{}", p.html);
    assert!(p.html.contains("Approve the close of") && p.html.contains("Ship &lt;it&gt;"), "{}", p.html);
    assert!(p.html.contains("action=\"https://bd.example.com/bd/w/proj/close/bd-1\""), "{}", p.html);
    let fresh = fresh.unwrap();
    assert!(fresh.starts_with("__Secure-bd_op_"), "{fresh}");
    assert!(fresh.ends_with("; Path=/bd/w/proj/close/bd-1; Max-Age=600; HttpOnly; SameSite=Strict; Secure"), "{fresh}");
    assert_eq!(take_recorded(), vec![], "a page shown ends nothing");
    assert_eq!(ops.finds(), 1);
    // The account's first approval registers its passkey, with the page's one script.
    assert!(p.html.contains("data-passkey=\"create\"") && p.html.contains("data-rp=\"bd.example.com\""), "{}", p.html);
    assert_eq!(p.html.matches("<script").count(), 1);
    let script = p.html.split("<script>").nth(1).unwrap().split("</script>").next().unwrap();
    assert_eq!(script, pages::APPROVE);
    // Once it has one, the page asks for it.
    let user = admitted_as(auth::Kind::Human).user;
    let row = passkeys::NewRow {
        credential: "AAAAAAAAAAAAx1zQ",
        issuer: &user.issuer,
        subject: &user.subject,
        provider: &user.provider,
        actor: "github:alice",
        alg: crate::webauthn::Alg::Es256,
        public_key: &SoftKey::es256().spki(),
        counter: 0,
    };
    assert_eq!(passkeys::insert_first(root.path(), &row).unwrap(), passkeys::Inserted::Inserted);
    let (answer, _, waiting) = run(&ops, Ok(admitted_as(auth::Kind::Human)), &cookies);
    let p = page(&answer);
    assert_eq!((p.status, waiting), (200, 1));
    assert!(p.html.contains("data-passkey=\"get\"") && p.html.contains("data-credentials=\"AAAAAAAAAAAAx1zQ\""));
    assert_eq!(take_recorded(), vec![]);

    // An address passkeys cannot be used at: the page says so, has no form, keeps nothing and sets no cookie.
    let at = "http://127.0.0.1:7420";
    let cookies = sent(&set_request_cookies(at, &flow.digest, &token, STEP_TTL));
    let flows = Mutex::new(Flows::default());
    let mut fresh = None;
    let answer = with_ops_at(at, root.path(), &flows, &ops, |cx| {
        operation::after_sign_in(
            cx,
            "GitHub",
            "github",
            Ok(admitted_as(auth::Kind::Human)),
            &flow,
            &cookies,
            &mut fresh,
        )
    });
    let p = page(&answer);
    assert!(!p.html.contains("<form") && !p.html.contains("<script"), "{}", p.html);
    assert!(p.html.contains(&pages::escape(pages::PASSKEY_UNAVAILABLE_HOST)), "{}", p.html);
    assert_eq!((fresh, lock(&flows).operations.map.len()), (None, 0));
    assert_eq!(take_recorded(), recorded(Outcome::PasskeyRefused, "passkeys unavailable at this address"));
}

/// An OIDC account's approval of `request`, bound to the cookie `cookie` of value `value`.
fn op_approval(cookie: &str, value: &str, request: OperationRequest) -> OperationApproval {
    OperationApproval {
        request,
        provider: "acme".into(),
        login: "alice".into(),
        subject: "00u7".into(),
        actor: "acme:alice".into(),
        oidc_approver: Some(reference()),
        browser: auth::hash(value),
        cookie: cookie.into(),
        passkey: ceremony(true),
    }
}

#[test]
fn operation_approvals_are_posted_once_from_their_own_browser_and_recorded_once() {
    use operation::{Outcome, take_recorded, take_recorded_with_credential};
    let _ = take_recorded();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let value = "c".repeat(64);
    let cookies = format!("x=1; __Secure-bd_op_ab12={value}");
    let request = close_request("proj", "bd-1");
    let one =
        |outcome: Outcome, detail: &'static str| vec![(outcome, "proj".into(), "close".into(), "bd-1".into(), detail)];
    let key = SoftKey::es256();
    let (credential, prefix) = credential_of(&key);
    let enroll = ceremony(true);
    let waiting = |id: &str| lock(&flows).operations.get_mut(&auth::hash(id)).is_some();
    with_ops(root.path(), &flows, &ops, |cx| {
        let post = |id: &str, issue: &str, cookies: &str| {
            operation::approve(cx, "proj", "close", issue, &format!("approval={id}"), cookies)
        };
        let unknown = post("nope", "bd-1", &cookies);
        assert_eq!(page(&unknown.0).status, 400);
        assert_eq!(take_recorded(), one(Outcome::Refused, "unknown or expired"));
        let incomplete = operation::approve(cx, "proj", "close", "bd-1", "", &cookies);
        assert_eq!(page(&incomplete.0).status, 400);
        assert_eq!(take_recorded(), one(Outcome::Refused, "form incomplete"));
        let id1 = OperationApproval { passkey: enroll.clone(), ..op_approval("ab12", &value, request.clone()) };
        lock(&flows).operations.put(auth::hash("id1"), id1);
        let fields = registration(&key, &enroll, &Tamper::default());
        // Another browser's: refused before the passkey is looked at, and the approval stays for its own.
        for other in ["", "__Secure-bd_op_ab12=", &format!("__Secure-bd_op_ab12={}", "d".repeat(64))] {
            assert_eq!(page(&post("id1", "bd-1", other).0).status, 403, "{other:?}");
            assert_eq!(take_recorded(), one(Outcome::Refused, "different browser"));
            let body = format!("approval=id1&{fields}");
            assert_eq!(page(&operation::approve(cx, "proj", "close", "bd-1", &body, other).0).status, 403);
            assert_eq!(take_recorded(), one(Outcome::Refused, "different browser"));
        }
        // The approval id twice: incomplete, nothing taken.
        for twice in ["approval=id1&approval=id1", "approval=id1&approval=nope"] {
            let body = format!("{twice}&{fields}");
            assert_eq!(page(&operation::approve(cx, "proj", "close", "bd-1", &body, &cookies).0).status, 400);
            assert_eq!(take_recorded(), one(Outcome::Refused, "form incomplete"));
            assert!(waiting("id1"), "{twice}");
        }
        assert!(kept_passkeys(root.path()).is_empty());
        // Another path: refused.
        assert_eq!(page(&post("id1", "bd-2", &cookies).0).status, 400);
        assert_eq!(
            take_recorded(),
            vec![(Outcome::Refused, "proj".into(), "close".into(), "bd-2".into(), "another operation")]
        );
        assert_eq!(page(&operation::approve(cx, "proj", "discard", "bd-1", "approval=id1", &cookies).0).status, 400);
        assert_eq!(take_recorded().len(), 1);
        assert!(ops.performs().is_empty());
        // The approval's id alone: taken, refused at the passkey, nothing performed.
        lock(&flows).operations.put(auth::hash("idM"), op_approval("ab12", &value, request.clone()));
        assert_eq!(page(&post("idM", "bd-1", &cookies).0).status, 403);
        assert_eq!(
            take_recorded_with_credential(),
            vec![(
                (
                    Outcome::PasskeyRefused,
                    "proj".into(),
                    "close".into(),
                    "bd-1".into(),
                    "passkey refused: missing fields"
                ),
                String::new()
            )]
        );
        assert_eq!(page(&post("idM", "bd-1", &cookies).0).status, 400);
        assert_eq!(take_recorded(), one(Outcome::Refused, "already used"));
        assert!(ops.performs().is_empty());
        // The sealed request and the reference the sign-in proved, whatever else the form says.
        let body =
            format!("approval=id1&{fields}&reason=other&force=false&actor=acme:bob&oidc_approver={}", "x".repeat(8));
        let (answer, set) = operation::approve(cx, "proj", "close", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(ops.performs(), vec![(request.clone(), "acme:alice".to_string(), Some(reference()))]);
        assert_eq!(ops.performs()[0].0.reason.as_deref(), Some("  why\n"), "byte for byte");
        assert_eq!(set, vec![set_op_cookie(ISSUER, "proj", "close", "bd-1", "ab12", "", Duration::ZERO)], "cleared");
        let recorded = take_recorded_with_credential();
        assert_eq!(recorded, vec![(one(Outcome::Approved, "performed").remove(0), prefix.clone())]);
        assert_ne!(prefix, credential);
        assert_eq!(kept_passkeys(root.path()).len(), 1);
        let again = post("id1", "bd-1", &cookies);
        assert_eq!(page(&again.0).status, 400);
        assert!(page(&again.0).html.contains("already used"), "{}", page(&again.0).html);
        assert_eq!(take_recorded(), one(Outcome::Refused, "already used"));
        assert_eq!(ops.performs().len(), 1);
        // A request past its time: taken, refused, nothing performed.
        let mut old = request.clone();
        old.until = now_millis() - 1;
        lock(&flows).operations.put(auth::hash("id2"), op_approval("ab12", &value, old));
        assert_eq!(page(&post("id2", "bd-1", &cookies).0).status, 410);
        assert_eq!(take_recorded(), one(Outcome::Refused, "request expired"));
        assert_eq!(ops.performs().len(), 1);
    });
    for (counter, (performed, status, outcome, detail)) in [
        (Performed::Discarded { count: 3 }, 200, Outcome::Approved, "performed"),
        (Performed::Done, 409, Outcome::Gone, "already closed"),
        (Performed::Gone(OpFound::NoIssue), 404, Outcome::Gone, "no such issue"),
        (Performed::NotHeld, 409, Outcome::NotReady, "no longer held"),
        (Performed::Changed("bd-1 is pinned now.".into()), 409, Outcome::NotReady, "target changed"),
        (Performed::Refused("bd-1 is claimed by bob".into()), 403, Outcome::Refused, "refused by the workspace"),
    ]
    .into_iter()
    .enumerate()
    {
        let ops = FakeOperations::new(OpFound::NoIssue, performed);
        with_ops(root.path(), &flows, &ops, |cx| {
            // The passkey registered by id1, in a ceremony of each approval's own.
            let c = ceremony(false);
            let id3 = OperationApproval { passkey: c.clone(), ..op_approval("ab12", &value, request.clone()) };
            lock(&flows).operations.put(auth::hash("id3"), id3);
            let body = format!("approval=id3&{}", assertion(&key, &c, counter as u32 + 1, &Tamper::default()));
            let (answer, _) = operation::approve(cx, "proj", "close", "bd-1", &body, &cookies);
            assert_eq!(page(&answer).status, status, "{detail}");
            assert_eq!(take_recorded_with_credential(), vec![(one(outcome, detail).remove(0), prefix.clone())]);
            lock(&flows).operations_spent.map.clear();
        });
    }
    // The sign-in settings turned off since the page was shown: taken, failed, recorded.
    let off = tempfile::tempdir().unwrap();
    with_ops(off.path(), &flows, &ops, |cx| {
        lock(&flows).operations.put(auth::hash("id4"), op_approval("ab12", &value, request.clone()));
        let (answer, _) = operation::approve(cx, "proj", "close", "bd-1", "approval=id4", &cookies);
        assert_eq!(page(&answer).status, 404);
        assert_eq!(take_recorded(), one(Outcome::Failed, "sign-in settings unavailable"));
    });
}
