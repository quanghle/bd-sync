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

/// `f` as the `allow_*` fields of a registration under an allowance.
fn allow_pairs(f: &Fields) -> Vec<(&'static str, String)> {
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    vec![
        ("allow_credential", b64(&f.credential)),
        ("allow_client_data", b64(&f.client_data)),
        ("allow_authenticator_data", b64(&f.authenticator_data)),
        ("allow_public_key", b64(&f.public_key)),
        ("allow_algorithm", f.algorithm.to_string()),
    ]
}

/// What a browser posts of an assertion on a page that registers: the fields
/// rendered on every page, empty.
const EMPTY_HIDDEN: &str = "credential=&client_data=&authenticator_data=&signature=&public_key=&algorithm=";

/// `new`'s registration against `c`'s allowance (changed by `t`), as the page
/// posts it.
fn allow_body(new: &SoftKey, c: &Ceremony, t: &Tamper) -> String {
    format!("{EMPTY_HIDDEN}&{}", encoded(&allow_pairs(&new.register(&c.expect_allow(), t))))
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
                pages::PasskeyAsk::Allow { .. } => panic!("{n}: no allowance"),
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

/// The ceremony and credentials of the page the acme account is shown now.
fn opened(cx: &Ctx<'_>) -> (Ceremony, Vec<String>) {
    let passkey::Prepared::Ask { ceremony, credentials } = passkey::prepare(cx, &acme(), "acme:alice").unwrap() else {
        panic!("a ceremony at an https issuer");
    };
    (*ceremony, credentials)
}

/// An admin's allowance for the acme account, of the default length.
fn granted(root: &std::path::Path) -> passkeys::Granted {
    let account = auth::account_named(root, "acme:alice").unwrap();
    passkeys::grant(root, &account, passkeys::ALLOWANCE_DEFAULT).unwrap()
}

/// Every allowance kept, whether live or not, in `server.db`.
fn allowances(root: &std::path::Path) -> Vec<(String, String, String, i64)> {
    let conn = crate::server_db::open(root).unwrap();
    let mut stmt = conn
        .prepare("SELECT issuer, subject, id, expires_at FROM passkey_allowances ORDER BY issuer, subject, id")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

/// Put an allowance `id` for the account `subject` at the acme issuer, ending
/// at `expires_at`, as `grant` keeps it but without its checks or its event.
fn put_allowance(root: &std::path::Path, subject: &str, id: &str, expires_at: i64) {
    let conn = crate::server_db::open(root).unwrap();
    let params = rusqlite::params![ACME_ISSUER, subject, id, 1, expires_at];
    conn.execute(passkeys::ALLOWANCE_PUT, params).unwrap();
}

/// Move every allowance kept to the past.
fn run_out(root: &std::path::Path) {
    let conn = crate::server_db::open(root).unwrap();
    conn.execute("UPDATE passkey_allowances SET expires_at = 1", []).unwrap();
}

/// What a refusal must leave as it was: [`snapshot`]'s, and every allowance.
type KeptAll = ((Vec<(String, u32, Option<i64>)>, usize), Vec<(String, String, String, i64)>);

fn kept_all(root: &std::path::Path) -> KeptAll {
    (snapshot(root), allowances(root))
}

/// In the future, for a ceremony's `until` that plays no part.
fn later() -> i64 {
    now_millis() + 600_000
}

/// Post `body` for a fresh approval asking for `c`, and check it refused and
/// logged as `why`, its label and the credential prefix, with nothing
/// approved, counted or written.
fn refused_as(cx: &Ctx<'_>, flows: &Mutex<Flows>, gates: &FakeGates, c: &Ceremony, body: &str, why: (&str, &str)) {
    static POSTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let (label, credential) = why;
    let (before, calls) = (kept_all(cx.root), gates.calls());
    let refused_before = crate::metrics::APPROVALS_PASSKEY_REFUSED.get();
    let _ = gate::take_logged();
    assert_eq!(settled(), 0, "{label}");
    let id = format!("refused{}", POSTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let (answer, _) = post_gate(cx, flows, &id, c, body);
    assert_eq!(page(&answer).status, 403, "{label}: {}", page(&answer).html);
    assert_eq!(passkey::take_registered(), 0, "{label}");
    assert_eq!(gates.calls(), calls, "{label}");
    assert_eq!(kept_all(cx.root), before, "{label}");
    assert!(crate::metrics::APPROVALS_PASSKEY_REFUSED.get() > refused_before, "{label}");
    let logged = gate::take_logged();
    assert_eq!(logged.len(), 1, "{label}");
    assert_eq!(
        (logged[0].outcome, logged[0].passkey, logged[0].credential.as_str(), logged[0].added.as_str()),
        ("passkey refused", label, credential, ""),
    );
}

#[test]
fn an_allowance_is_offered_for_one_to_ninety_eight_passkeys() {
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let until = later();
    put_allowance(root.path(), ACME_SUBJECT, "feedc0de", until);
    with_ctx(root.path(), &flows, &gates, |cx| {
        for (n, offered) in [(0, false), (1, true), (98, true), (99, false)] {
            fill_to(root.path(), n);
            let (ceremony, credentials) = opened(cx);
            assert_eq!(credentials.len(), n);
            assert_eq!(ceremony.enroll, n == 0, "{n}");
            assert_eq!(ceremony.allowance.is_some(), offered, "{n}");
            match passkey::ask(&ceremony, &credentials) {
                pages::PasskeyAsk::Allow { challenge, rp_id, credentials: shown, register } => {
                    assert!(offered, "{n}");
                    // Never beside adding, and with a challenge of its own; the assertion's stays for the fallback.
                    assert!(ceremony.add.is_none(), "{n}");
                    let offer = ceremony.allowance.as_ref().unwrap();
                    assert_ne!(offer.challenge, ceremony.challenge, "{n}");
                    assert_eq!((offer.id.as_str(), offer.until), ("feedc0de", until), "{n}");
                    assert_eq!(challenge, URL_SAFE_NO_PAD.encode(ceremony.challenge));
                    assert_eq!(register.challenge, URL_SAFE_NO_PAD.encode(offer.challenge));
                    assert_eq!(register.user, passkey::user_handle(ACME_ISSUER, ACME_SUBJECT));
                    assert_eq!((register.name, rp_id), ("acme:alice", ceremony.rp_id.as_str()));
                    assert_eq!(shown, credentials.as_slice());
                }
                pages::PasskeyAsk::Assert { add, .. } => {
                    assert!(!offered && n == 99 && add.is_none(), "{n}: the ordinary page");
                }
                pages::PasskeyAsk::Enroll { .. } => assert_eq!(n, 0),
                pages::PasskeyAsk::Unavailable { .. } => panic!("{n}: unavailable"),
            }
        }
        assert_eq!(allowances(root.path()).len(), 1, "opening a page spends nothing");
    });

    // One that ran out, and another account's, are not offered: the page is the ordinary one, adding included.
    let root = gate_root(false);
    with_ctx(root.path(), &flows, &gates, |cx| {
        fill_to(root.path(), 1);
        put_allowance(root.path(), ACME_SUBJECT, "feedc0de", now_millis() - 1);
        let (ceremony, _) = opened(cx);
        assert!(ceremony.allowance.is_none() && ceremony.add.is_some() && !ceremony.enroll);
        put_allowance(root.path(), "00u8", "feedc0de", later());
        let (ceremony, _) = opened(cx);
        assert!(ceremony.allowance.is_none() && ceremony.add.is_some() && !ceremony.enroll);
    });

    // Where the issuer cannot be a relying party nothing is offered.
    let root = gate_root(false);
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    fill_to(root.path(), 1);
    put_allowance(root.path(), ACME_SUBJECT, "feedc0de", later());
    with_ops_at("https://192.0.2.1", root.path(), &flows, &ops, |cx| {
        let prepared = passkey::prepare(cx, &acme(), "acme:alice").unwrap();
        assert!(matches!(prepared, passkey::Prepared::Unavailable(_)));
    });
}

#[test]
fn the_page_names_neither_the_allowance_nor_when_it_ends() {
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    fill_to(root.path(), 1);
    let grant = granted(root.path());
    with_ctx(root.path(), &flows, &gates, |cx| {
        let (ceremony, credentials) = opened(cx);
        let page = pages::approve_gate(&pages::ApproveGate {
            workspace: "proj",
            gate: "bd-1",
            title: "Ship it",
            holds: &[],
            part_of: None,
            approvers: None,
            provider: "Acme",
            actor: "acme:alice",
            id: "c0ffee",
            action: "https://bd.example.com/w/proj/gates/bd-1",
            packet: None,
            passkey: passkey::ask(&ceremony, &credentials),
        });
        assert!(page.html.contains("data-passkey=\"allow\""), "{}", page.html);
        assert!(!page.html.contains(&grant.id), "{}", page.html);
        assert!(!page.html.contains(&grant.expires_at.to_string()), "{}", page.html);
        // Every field the path reads is one the page renders, and renders disabled.
        for name in passkey::ALLOW_FIELDS {
            assert!(page.html.contains(&format!("name=\"{name}\" value=\"\" disabled")), "{name}: {}", page.html);
        }
    });
}

#[test]
fn an_allowance_registers_a_passkey_with_no_existing_one() {
    use operation::{Outcome, take_recorded_with_passkeys};
    let _ = gate::take_logged();
    let _ = take_recorded_with_passkeys();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let (lost, new) = (SoftKey::es256(), SoftKey::rs256());
    let ((lost_id, _), (new_id, new_prefix)) = (credential_of(&lost), credential_of(&new));
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &lost);
        let _ = gate::take_logged();
        let grant = granted(root.path());
        let (c, _) = opened(cx);
        let (registered_before, calls) = (crate::metrics::PASSKEYS_REGISTERED.get(), gates.calls());
        // A second page, as a second tab: under the same allowance, spent by then.
        let (other, _) = opened(cx);
        assert_eq!(settled(), 0);
        let (answer, _) = post_gate(cx, &flows, "allowed", &c, &allow_body(&new, &c, &Tamper::default()));
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(passkey::take_registered(), 1);
        assert!(crate::metrics::PASSKEYS_REGISTERED.get() > registered_before);
        assert_eq!(gates.calls(), calls + 1);
        assert!(allowances(root.path()).is_empty(), "spent");
        let kept = kept_passkeys(root.path());
        let ids: Vec<&str> = kept.iter().map(|p| p.credential.as_str()).collect();
        assert_eq!(ids, [lost_id.as_str(), new_id.as_str()]);
        assert_eq!((kept[0].counter, kept[0].last_used_at), (0, None), "no assertion in it");
        assert_eq!((kept[1].alg_name(), kept[1].counter, kept[1].last_used_at), ("RS256", 0, None));
        let events = events_of(root.path(), "passkey_registered");
        let detail = events.iter().filter_map(|e| e.detail.clone()).find(|d| d.contains("allowance"));
        assert_eq!(
            detail.unwrap(),
            format!("credential {new_prefix} (RS256), registered at a browser approval under allowance {}", grant.id)
        );
        let logged = gate::take_logged();
        assert_eq!(logged.len(), 1);
        assert_eq!(
            (logged[0].outcome, logged[0].credential.as_str(), logged[0].added.as_str(), logged[0].passkey),
            ("approved", new_prefix.as_str(), "", "registered under allowance")
        );
        let line = format!("{:?}", logged[0]);
        assert!(!line.contains(&new_id), "{line}");

        // The other tab's registration, of another key.
        let another = SoftKey::es256();
        let (_, prefix) = credential_of(&another);
        let body = allow_body(&another, &other, &Tamper::default());
        refused_as(cx, &flows, &gates, &other, &body, ("allowance: ended", &prefix));

        // The next page is the ordinary one, adding included, and the new passkey approves on it.
        let (c, _) = opened(cx);
        assert!(c.allowance.is_none() && c.add.is_some());
        assert_eq!(settled(), 0);
        let fields = assertion(&new, &c, 1, &Tamper::default());
        assert_eq!(page(&post_gate(cx, &flows, "after", &c, &fields).0).status, 200);
        assert_eq!(passkey::take_registered(), 0);
        assert_eq!(gate::take_logged()[0].passkey, "verified");
    });

    // An operation's page spends it the same way.
    let root = gate_root(false);
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let value = "c".repeat(64);
    with_ctx(root.path(), &flows, &gates, |cx| enrolled(cx, &flows, &lost));
    granted(root.path());
    with_ops(root.path(), &flows, &ops, |cx| {
        let (c, _) = opened(cx);
        let approval =
            OperationApproval { passkey: c.clone(), ..op_approval("ab12", &value, close_request("proj", "bd-1")) };
        lock(&flows).operations.put(auth::hash("o"), approval);
        let body = format!("approval=o&{}", allow_body(&new, &c, &Tamper::default()));
        let cookies = format!("__Secure-bd_op_ab12={value}");
        assert_eq!(settled(), 0);
        let (answer, _) = operation::approve(cx, "proj", "close", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(ops.performs().len(), 1);
        assert_eq!(passkey::take_registered(), 1);
        assert!(allowances(root.path()).is_empty(), "spent");
        assert_eq!(kept_passkeys(root.path()).len(), 2);
        let recorded = take_recorded_with_passkeys();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            (recorded[0].0.0, recorded[0].1.as_str(), recorded[0].2.as_str()),
            (Outcome::Approved, new_prefix.as_str(), "")
        );
    });
}

#[test]
fn an_allowance_refused_by_the_store_changes_nothing() {
    let _ = gate::take_logged();
    let a = SoftKey::es256();
    let bob_key = SoftKey::es256();
    let (bob_id, _) = credential_of(&bob_key);
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let bob = auth::Identity { subject: "00u8".into(), login: "bob".into(), ..acme() };
    auth::bind_account(root.path(), &bob, true, "test").unwrap();
    put_passkey(root.path(), &bob_id, "00u8", "acme:bob", &bob_key);
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let grant = granted(root.path());
        put_allowance(root.path(), "00u8", "b0bb0b0b", later());
        let (open, _) = opened(cx);
        assert_eq!(open.allowance.as_ref().unwrap().id, grant.id);

        // Another account's allowance, and an id nobody has, by a page that claims them.
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        for id in ["b0bb0b0b", "0000000000000000"] {
            let c = ceremony(false).with_allowance(id, later());
            let body = allow_body(&new, &c, &Tamper::default());
            refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));
        }
        // A credential id taken, by the account's own passkey and by another account's.
        for credential in [a.credential.clone(), bob_key.credential.clone()] {
            let mut taken = SoftKey::es256();
            taken.credential = credential;
            let (_, prefix) = credential_of(&taken);
            let c = ceremony(false).with_allowance(&grant.id, grant.expires_at);
            let body = allow_body(&taken, &c, &Tamper::default());
            refused_as(cx, &flows, &gates, &c, &body, ("allowance: credential taken", &prefix));
        }
        // The limit reached after the page was shown.
        fill_to(root.path(), passkeys::MAX_PER_ACCOUNT);
        let body = allow_body(&new, &open, &Tamper::default());
        refused_as(cx, &flows, &gates, &open, &body, ("allowance: limit reached", &prefix));
    });
}

#[test]
fn a_forgotten_account_registers_nothing_under_an_open_page() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        granted(root.path());
        let (c, _) = opened(cx);
        assert!(c.allowance.is_some());
        assert!(auth::forget_account(root.path(), ACME_ISSUER, ACME_SUBJECT).unwrap());
        assert!(allowances(root.path()).is_empty(), "erased with the account");
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: no account", &prefix));
        assert!(kept_passkeys(root.path()).is_empty());
    });
}

#[test]
fn removing_the_last_passkey_ends_an_open_pages_allowance() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        granted(root.path());
        let (c, _) = opened(cx);
        let account = auth::account_named(root.path(), "acme:alice").unwrap();
        passkeys::remove(root.path(), &account, None).unwrap();
        assert!(allowances(root.path()).is_empty());
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));
        assert!(kept_passkeys(root.path()).is_empty());
        // And the next page enrolls, as for an account with none.
        let (c, _) = opened(cx);
        assert!(c.enroll && c.allowance.is_none());
    });
}

#[test]
fn an_allowance_is_checked_as_a_first_registration_is() {
    use crate::webauthn::Alg;
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    let ok = Tamper::default;
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let grant = granted(root.path());
        let (c, _) = opened(cx);
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        for (tamper, label) in [
            (Tamper { kind: Some("webauthn.get"), ..ok() }, "allowance: wrong ceremony type"),
            (Tamper { challenge: Some(vec![1; 32]), ..ok() }, "allowance: wrong challenge"),
            (Tamper { origin: Some("https://evil.example".into()), ..ok() }, "allowance: wrong origin"),
            (Tamper { cross_origin: Some(true), ..ok() }, "allowance: cross-origin"),
            (Tamper { top_origin: Some("\"https://evil.example\""), ..ok() }, "allowance: top origin present"),
            (Tamper { duplicate: true, ..ok() }, "allowance: client data unreadable"),
            (Tamper { rp_id: Some("example.com".into()), ..ok() }, "allowance: wrong relying party"),
            (Tamper { flags: Some(0x44), ..ok() }, "allowance: user not present"),
            (Tamper { flags: Some(0x41), ..ok() }, "allowance: user not verified"),
            (Tamper { flags: Some(0x05), ..ok() }, "allowance: no credential data"),
            (Tamper { mismatch: true, ..ok() }, "allowance: credential mismatch"),
        ] {
            let body = allow_body(&new, &c, &tamper);
            refused_as(cx, &flows, &gates, &c, &body, (label, &prefix));
        }

        // What the form says of the key and the data, each changed alone.
        let valid = || allow_pairs(&new.register(&c.expect_allow(), &ok()));
        let change = |i: usize, value: String| {
            let mut pairs = valid();
            pairs[i].1 = value;
            format!("{EMPTY_HIDDEN}&{}", encoded(&pairs))
        };
        let wrong_key = URL_SAFE_NO_PAD.encode(SoftKey::rs256().spki());
        for (i, value, label) in [
            (4, "-8".to_string(), "allowance: unsupported algorithm"),
            (4, Alg::Rs256.cose().to_string(), "allowance: bad public key"),
            (3, wrong_key, "allowance: bad public key"),
            (1, URL_SAFE_NO_PAD.encode([0xff, 0xfe]), "allowance: client data unreadable"),
            (2, URL_SAFE_NO_PAD.encode([0u8; 8]), "allowance: authenticator data malformed"),
        ] {
            refused_as(cx, &flows, &gates, &c, &change(i, value), (label, &prefix));
        }

        // Each ceremony's challenge is its own. A registration for the assertion's challenge:
        let body = format!("{EMPTY_HIDDEN}&{}", encoded(&allow_pairs(&new.register(&c.expect(), &ok()))));
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: wrong challenge", &prefix));
        // for another page's allowance, the same allowance:
        let (other, _) = opened(cx);
        let body = format!("{EMPTY_HIDDEN}&{}", encoded(&allow_pairs(&new.register(&other.expect_allow(), &ok()))));
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: wrong challenge", &prefix));
        // and an assertion for the allowance's challenge.
        let (_, a_prefix) = credential_of(&a);
        let body = webauthn_body(&a.assert(&c.expect_allow(), 1, &ok()), false);
        refused_as(cx, &flows, &gates, &c, &body, ("wrong challenge", &a_prefix));
        assert_eq!(allowances(root.path())[0].2, grant.id, "still live, after all that");
    });
}

#[test]
fn an_allowances_refusals_are_named_after_it() {
    use crate::webauthn::Refusal;
    use passkey::{AllowanceWhy, Why};
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
        let why = Why::Allowance(AllowanceWhy::Webauthn(r));
        assert_eq!(why.label(), format!("allowance: {}", r.label()));
        assert_eq!(why.detail(), format!("passkey refused: allowance: {}", r.label()));
    }
    for (why, phrase) in [
        (AllowanceWhy::NotOffered, "not offered"),
        (AllowanceWhy::MissingFields, "missing fields"),
        (AllowanceWhy::MalformedFields, "malformed fields"),
        (AllowanceWhy::Expired, "expired"),
        (AllowanceWhy::Ended, "ended"),
        (AllowanceWhy::LimitReached, "limit reached"),
        (AllowanceWhy::CredentialTaken, "credential taken"),
        (AllowanceWhy::NoAccount, "no account"),
    ] {
        assert_eq!(Why::Allowance(why).label(), format!("allowance: {phrase}"));
        assert_eq!(Why::Allowance(why).detail(), format!("passkey refused: allowance: {phrase}"));
    }
}

#[test]
fn an_allowances_fields_are_read_once_and_capped() {
    use crate::webauthn::{MAX_AUTH_DATA, MAX_CLIENT_DATA, MAX_CREDENTIAL, MAX_PUBLIC_KEY, encoded_len};
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        granted(root.path());
        let (c, _) = opened(cx);
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        let valid = || allow_pairs(&new.register(&c.expect_allow(), &Tamper::default()));
        let body = |pairs: &[(&'static str, String)]| format!("{EMPTY_HIDDEN}&{}", encoded(pairs));
        for i in 0..5 {
            // Not there, or empty.
            let mut pairs = valid();
            pairs.remove(i);
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: missing fields", ""));
            let mut pairs = valid();
            pairs[i].1.clear();
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: missing fields", ""));
            // Twice, with the same value or another.
            let mut pairs = valid();
            let again = pairs[i].clone();
            pairs.push(again);
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", ""));
            let mut pairs = valid();
            let again = (pairs[i].0, format!("{}A", pairs[i].1));
            pairs.push(again);
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", ""));
        }
        // A duplicate goes before a missing field, as it does for the other fields.
        let mut pairs = valid();
        pairs[1].1.clear();
        let again = pairs[0].clone();
        pairs.push(again);
        refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", ""));
        // Longer than its cap, by one character, whatever it decodes to.
        for (i, cap, credential) in [
            (0, MAX_CREDENTIAL, ""),
            (1, MAX_CLIENT_DATA, prefix.as_str()),
            (2, MAX_AUTH_DATA, prefix.as_str()),
            (3, MAX_PUBLIC_KEY, prefix.as_str()),
        ] {
            let mut pairs = valid();
            pairs[i].1 = "A".repeat(encoded_len(cap) + 1);
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", credential));
            let mut pairs = valid();
            pairs[i].1 = "!".repeat(8);
            refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", credential));
        }
        let mut pairs = valid();
        pairs[4].1 = "ES256".into();
        refused_as(cx, &flows, &gates, &c, &body(&pairs), ("allowance: malformed fields", &prefix));
    });
}

#[test]
fn a_page_spends_the_allowance_it_was_opened_under_or_none() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    let new = SoftKey::es256();
    let (_, prefix) = credential_of(&new);
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let account = auth::account_named(root.path(), "acme:alice").unwrap();

        // The row ran out, but the page says it had time: ended, as anything else ending it would be.
        granted(root.path());
        let (mut c, _) = opened(cx);
        run_out(root.path());
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));
        // Ran out while the page was open: the page's own expiry tells the log.
        c.allowance.as_mut().unwrap().until = now_millis() - 1;
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: expired", &prefix));

        // Cancelled.
        granted(root.path());
        let (c, _) = opened(cx);
        assert!(passkeys::cancel(root.path(), &account).unwrap());
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));

        // Cancelled, then granted again: the new one is not this page's.
        granted(root.path());
        let (c, _) = opened(cx);
        assert!(passkeys::cancel(root.path(), &account).unwrap());
        let regranted = granted(root.path());
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));
        assert_eq!(allowances(root.path())[0].2, regranted.id, "unspent");

        // Replaced: neither is the replacing one.
        let (c, _) = opened(cx);
        assert_eq!(c.allowance.as_ref().unwrap().id, regranted.id);
        let replaced = granted(root.path());
        assert_eq!(replaced.replaced.as_deref(), Some(regranted.id.as_str()));
        let body = allow_body(&new, &c, &Tamper::default());
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: ended", &prefix));
        assert_eq!(allowances(root.path())[0].2, replaced.id, "unspent");

        // A page opened after it spends it.
        let (c, _) = opened(cx);
        let (answer, _) = post_gate(cx, &flows, "after", &c, &allow_body(&new, &c, &Tamper::default()));
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert!(allowances(root.path()).is_empty());
        let _ = (settled(), gate::take_logged());
    });
}

#[test]
fn allowance_fields_are_refused_where_no_allowance_was_offered() {
    let _ = gate::take_logged();
    let a = SoftKey::es256();
    let new = SoftKey::es256();
    let ok = Tamper::default;
    // Valid fields, signed for the page's own challenge, or just the name of one.
    let signed = |c: &Ceremony| encoded(&allow_pairs(&new.register(&c.expect(), &ok())));
    let named = "allow_credential=";
    let unreadable = "allow_credential=%21&allow_algorithm=x&allow_algorithm=y";

    // An account's first page: nothing else on it matters, and nothing is registered.
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    with_ctx(root.path(), &flows, &gates, |cx| {
        let (c, _) = opened(cx);
        assert!(c.enroll);
        for body in [signed(&c), named.to_string(), unreadable.to_string()] {
            refused_as(cx, &flows, &gates, &c, &body, ("allowance: not offered", ""));
        }
        let body = format!("{}&{}", registration(&a, &c, &ok()), signed(&c));
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: not offered", ""));
        assert!(kept_passkeys(root.path()).is_empty());
    });

    // The pages of an account with a passkey, opened with and without an allowance anywhere near them.
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let (before_grant, _) = opened(cx);
        assert!(before_grant.add.is_some() && before_grant.allowance.is_none());
        let grant = granted(root.path());
        let shown = [("an assertion's", ceremony(false)), ("an add's", adding()), ("before the grant", before_grant)];
        for (what, c) in shown {
            for body in [signed(&c), named.to_string(), unreadable.to_string()] {
                refused_as(cx, &flows, &gates, &c, &body, ("allowance: not offered", ""));
            }
            // Beside the page's own ceremony, which would pass, and which is not read.
            let body = format!("{}&{}", assertion(&a, &c, 9, &ok()), signed(&c));
            refused_as(cx, &flows, &gates, &c, &body, ("allowance: not offered", ""));
            assert_eq!(allowances(root.path())[0].2, grant.id, "{what}");
        }
        // And before the fields of adding are looked at.
        let c = adding();
        let body = format!("{}&{}", add_body(&a, &new, &c, 9, &ok(), &ok()), signed(&c));
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: not offered", ""));
        assert_eq!(kept_passkeys(root.path())[0].counter, 0);
    });
}

#[test]
fn one_post_is_one_ceremony_on_an_allowance_page() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    let new = SoftKey::es256();
    let ok = Tamper::default;
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        granted(root.path());
        let (c, _) = opened(cx);
        let registering = encoded(&allow_pairs(&new.register(&c.expect_allow(), &ok())));
        // A full assertion beside it, and each of its fields alone.
        let body = format!("{}&{registering}", assertion(&a, &c, 1, &ok()));
        refused_as(cx, &flows, &gates, &c, &body, ("allowance: malformed fields", ""));
        for field in ["credential", "client_data", "authenticator_data", "signature"] {
            let body = format!("{field}=AAAA&{registering}");
            refused_as(cx, &flows, &gates, &c, &body, ("allowance: malformed fields", ""));
        }
        // A registration added beside an assertion is not this page's either.
        let beside = new_fields(&SoftKey::es256().register(&c.expect(), &ok()));
        refused_as(cx, &flows, &gates, &c, &format!("{registering}&{beside}"), ("adding not offered", ""));
        refused_as(cx, &flows, &gates, &c, &beside, ("adding not offered", ""));

        // Without the assertion's fields, or with them empty as a browser sends them, it registers.
        let (answer, _) = post_gate(cx, &flows, "bare", &c, &registering);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert!(allowances(root.path()).is_empty());
        granted(root.path());
        let (c, _) = opened(cx);
        let (answer, _) = post_gate(cx, &flows, "empty", &c, &allow_body(&SoftKey::es256(), &c, &ok()));
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(kept_passkeys(root.path()).len(), 3);
        let _ = (settled(), gate::take_logged());
    });
}

#[test]
fn an_existing_passkey_keeps_approving_while_an_allowance_is_live() {
    let _ = gate::take_logged();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let gates = FakeGates::answering(Approved::Opened { unblocked: vec![], completed: vec![] });
    let a = SoftKey::es256();
    let (_, prefix) = credential_of(&a);
    with_ctx(root.path(), &flows, &gates, |cx| {
        enrolled(cx, &flows, &a);
        let _ = gate::take_logged();
        let (before_grant, _) = opened(cx);
        let grant = granted(root.path());
        let (allow_page, _) = opened(cx);
        assert!(allow_page.allowance.is_some() && allow_page.add.is_none());
        // On a page opened before the grant, and on the allowance page's secondary path.
        for (n, (c, what)) in [(before_grant, "ordinary"), (allow_page, "allowance")].iter().enumerate() {
            let counter = n as u32 + 1;
            let calls = gates.calls();
            let events = events_of(root.path(), "passkey_registered").len();
            assert_eq!(settled(), 0, "{what}");
            // As a browser posts it: the two fields it does not fill empty, the allowance's disabled.
            let body = format!("{}&public_key=&algorithm=", assertion(&a, c, counter, &Tamper::default()));
            let (answer, _) = post_gate(cx, &flows, what, c, &body);
            assert_eq!(page(&answer).status, 200, "{what}: {}", page(&answer).html);
            assert_eq!(passkey::take_registered(), 0, "{what}");
            assert_eq!(gates.calls(), calls + 1, "{what}");
            let kept = kept_passkeys(root.path());
            assert_eq!(kept.len(), 1, "{what}");
            assert_eq!((kept[0].counter, kept[0].last_used_at.is_some()), (counter, true), "{what}");
            assert_eq!(events_of(root.path(), "passkey_registered").len(), events, "{what}");
            assert_eq!(allowances(root.path())[0].2, grant.id, "{what}: nothing spent");
            let logged = gate::take_logged();
            assert_eq!(
                (logged[0].outcome, logged[0].passkey, logged[0].credential.as_str(), logged[0].added.as_str()),
                ("approved", "verified", prefix.as_str(), ""),
                "{what}"
            );
        }
    });
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
    // The table gone at version 5: every lookup fails, and server.db is not migrated again.
    let conn = rusqlite::Connection::open(crate::server_db::path(root.path())).unwrap();
    conn.execute_batch("DROP TABLE passkeys").unwrap();
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, 5);
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
        passkey: None,
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
        Who { provider: "acme", login: "", subject: "", actor: "", credential: "", added: "", passkey: None }
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

/// The two flows an approval page belongs to, for what both must do alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Approving {
    Gate,
    Operation,
}

const BOTH: [Approving; 2] = [Approving::Gate, Approving::Operation];

/// One approval's log line, as either flow logs it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    outcome: String,
    /// An operation's `detail`: a gate's line has none.
    detail: String,
    credential: String,
    added: String,
    /// A gate's line always has it, an operation's only for an allowance.
    passkey: Option<&'static str>,
}

impl Approving {
    /// Keep an approval (`id`) asking for `c`, as its page was shown.
    fn put(self, flows: &Mutex<Flows>, id: &str, c: &Ceremony) {
        let value = "c".repeat(64);
        match self {
            Approving::Gate => {
                lock(flows).approvals.put(auth::hash(id), approval_with("ab12", &value, c.clone()));
            }
            Approving::Operation => {
                let request = close_request("proj", "bd-1");
                let approval = OperationApproval { passkey: c.clone(), ..op_approval("ab12", &value, request) };
                lock(flows).operations.put(auth::hash(id), approval);
            }
        }
    }

    /// Whether the approval `id` still waits for its POST.
    fn waiting(self, flows: &Mutex<Flows>, id: &str) -> bool {
        let key = auth::hash(id);
        match self {
            Approving::Gate => lock(flows).approvals.get_mut(&key).is_some(),
            Approving::Operation => lock(flows).operations.get_mut(&key).is_some(),
        }
    }

    /// The approval cookie, of value `value`.
    fn cookie(self, value: &str) -> String {
        match self {
            Approving::Gate => format!("__Secure-bd_gate_ab12={value}"),
            Approving::Operation => format!("__Secure-bd_op_ab12={value}"),
        }
    }

    /// The cookies of the browser the approvals [`Approving::put`] keeps are bound to.
    fn cookies(self) -> String {
        self.cookie(&"c".repeat(64))
    }

    fn send(self, cx: &Ctx<'_>, body: &str, cookies: &str) -> (Answer, Vec<String>) {
        match self {
            Approving::Gate => gate::approve(cx, "proj", "bd-1", body, cookies),
            Approving::Operation => operation::approve(cx, "proj", "close", "bd-1", body, cookies),
        }
    }

    /// Post `fields` for a fresh approval (`id`) asking for `c`, from its own browser.
    fn post(self, cx: &Ctx<'_>, flows: &Mutex<Flows>, id: &str, c: &Ceremony, fields: &str) -> (Answer, Vec<String>) {
        self.put(flows, id, c);
        self.send(cx, &format!("approval={id}&{fields}"), &self.cookies())
    }

    /// The page copy of a passkey check that failed.
    fn failed_copy(self) -> &'static str {
        match self {
            Approving::Gate => pages::PASSKEY_FAILED_GATE,
            Approving::Operation => pages::PASSKEY_FAILED_OP,
        }
    }

    /// The lines logged on this thread since the last call.
    fn lines(self) -> Vec<Line> {
        match self {
            Approving::Gate => gate::take_logged()
                .into_iter()
                .map(|l| Line {
                    outcome: l.outcome.to_string(),
                    detail: String::new(),
                    credential: l.credential,
                    added: l.added,
                    passkey: Some(l.passkey),
                })
                .collect(),
            Approving::Operation => operation::take_recorded_with_passkey_field()
                .into_iter()
                .map(|(r, credential, added, passkey)| Line {
                    outcome: r.0.label().to_string(),
                    detail: r.4.to_string(),
                    credential,
                    added,
                    passkey,
                })
                .collect(),
        }
    }

    /// The one line logged on this thread since the last call.
    fn line(self) -> Line {
        let mut lines = self.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        lines.remove(0)
    }

    /// The line of an approval carried out, its passkey ceremony `passkey`.
    fn approved(self, credential: &str, passkey: &'static str) -> Line {
        let (detail, passkey) = match self {
            Approving::Gate => ("", Some(passkey)),
            Approving::Operation => ("performed", passkey.contains("allowance").then_some(passkey)),
        };
        Line {
            outcome: "approved".into(),
            detail: detail.into(),
            credential: credential.into(),
            added: String::new(),
            passkey,
        }
    }

    /// The line of a passkey ceremony refused as `label`.
    fn refused(self, label: &'static str, credential: &str) -> Line {
        let (outcome, detail, passkey) = match self {
            Approving::Gate => ("passkey refused", String::new(), Some(label)),
            Approving::Operation => (
                "passkey_refused",
                format!("passkey refused: {label}"),
                label.starts_with("allowance: ").then_some(label),
            ),
        };
        Line { outcome: outcome.into(), detail, credential: credential.into(), added: String::new(), passkey }
    }
}

/// Forget what this thread logged and counted so far.
fn drained() {
    let _ = gate::take_logged();
    let _ = operation::take_recorded_with_passkey_field();
    settled();
}

/// What the workspace answers an approval: a gate's or an operation's.
enum Answering {
    Gate(Result<Approved, bd_core::Error>),
    Operation(Result<Performed, bd_core::Error>),
}

/// Gates and operations answering as told, else carrying the approval out.
/// When called they read `server.db` over a connection of their own, so they
/// see what had been committed by then.
struct Watching {
    root: std::path::PathBuf,
    gates: Mutex<std::collections::VecDeque<Result<Approved, bd_core::Error>>>,
    operations: Mutex<std::collections::VecDeque<Result<Performed, bd_core::Error>>>,
    seen: Mutex<Vec<KeptAll>>,
}

impl Watching {
    fn new(root: &std::path::Path) -> Watching {
        Watching {
            root: root.to_path_buf(),
            gates: Default::default(),
            operations: Default::default(),
            seen: Default::default(),
        }
    }

    /// The next call answers `answer`.
    fn answer(&self, answer: Answering) {
        match answer {
            Answering::Gate(answer) => self.gates.lock().unwrap().push_back(answer),
            Answering::Operation(answer) => self.operations.lock().unwrap().push_back(answer),
        }
    }

    /// What each call since the last one saw kept.
    fn seen(&self) -> Vec<KeptAll> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl Gates for Watching {
    fn find(&self, _: &str, _: &str, _: &Approver<'_>) -> Result<Found, bd_core::Error> {
        Ok(Found::NoIssue)
    }

    fn approve(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<Approved, bd_core::Error> {
        self.seen.lock().unwrap().push(kept_all(&self.root));
        let next = self.gates.lock().unwrap().pop_front();
        next.unwrap_or(Ok(Approved::Opened { unblocked: vec![], completed: vec![] }))
    }
}

impl Operations for Watching {
    fn find(&self, _: &OperationRequest, _: &Approver<'_>) -> Result<OpFound, bd_core::Error> {
        Ok(OpFound::NoIssue)
    }

    fn perform(&self, _: &OperationRequest, _: &str, _: Option<&str>) -> Result<Performed, bd_core::Error> {
        self.seen.lock().unwrap().push(kept_all(&self.root));
        self.operations.lock().unwrap().pop_front().unwrap_or(Ok(Performed::Closed))
    }
}

fn with_watching<T>(watching: &Watching, flows: &Mutex<Flows>, f: impl FnOnce(&Ctx<'_>) -> T) -> T {
    let documents = super::super::cimd::Documents::new();
    let exists = |_: &str| true;
    f(&Ctx {
        root: &watching.root,
        issuer: ISSUER,
        documents: &documents,
        flows,
        workspace_exists: &exists,
        gates: watching,
        links: None,
        operations: watching,
    })
}

/// The acme account enrolled with `key` and an allowance granted, nothing
/// logged or counted since: the ceremony of the page it is shown now.
fn allowed_page(cx: &Ctx<'_>, flows: &Mutex<Flows>, key: &SoftKey) -> Ceremony {
    enrolled(cx, flows, key);
    granted(cx.root);
    drained();
    let (c, _) = opened(cx);
    assert!(c.allowance.is_some());
    c
}

/// Post `body` in `flow` for a fresh approval asking for `c`, and check it
/// refused as `why`, its label and the credential prefix: the page's copy,
/// the line and the counter, nothing approved and nothing written.
fn refused_in(
    flow: Approving,
    cx: &Ctx<'_>,
    flows: &Mutex<Flows>,
    watching: &Watching,
    c: &Ceremony,
    body: &str,
    why: (&'static str, &str),
) {
    static POSTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    use crate::metrics::{APPROVALS_PASSKEY_REFUSED, OPERATIONS_PASSKEY_REFUSED};
    let (label, credential) = why;
    drained();
    let _ = watching.seen();
    let before = kept_all(cx.root);
    let counter = match flow {
        Approving::Gate => &APPROVALS_PASSKEY_REFUSED,
        Approving::Operation => &OPERATIONS_PASSKEY_REFUSED,
    };
    let refused_before = counter.get();
    let id = format!("in{}", POSTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let (answer, _) = flow.post(cx, flows, &id, c, body);
    assert_eq!(page(&answer).status, 403, "{flow:?} {label}: {}", page(&answer).html);
    let ended = ["allowance: expired", "allowance: ended"].contains(&label);
    let copy = if ended { pages::PASSKEY_ALLOW_ENDED } else { flow.failed_copy() };
    assert!(page(&answer).html.contains(&pages::escape(copy)), "{flow:?} {label}: {}", page(&answer).html);
    assert_eq!(passkey::take_registered(), 0, "{flow:?} {label}");
    assert_eq!(watching.seen(), vec![], "{flow:?} {label}: nothing approved");
    assert_eq!(kept_all(cx.root), before, "{flow:?} {label}: nothing written");
    assert!(counter.get() > refused_before, "{flow:?} {label}");
    assert_eq!(flow.line(), flow.refused(label, credential), "{flow:?} {label}");
}

#[test]
fn what_an_allowance_refusal_says() {
    use crate::webauthn::Refusal;
    use passkey::{AllowanceWhy as A, Why};
    for why in [A::Expired, A::Ended] {
        assert!(Why::Allowance(why).is_allowance() && Why::Allowance(why).ended(), "{why:?}");
    }
    for why in [
        A::NotOffered,
        A::MissingFields,
        A::MalformedFields,
        A::LimitReached,
        A::CredentialTaken,
        A::NoAccount,
        A::Webauthn(Refusal::WrongChallenge),
    ] {
        assert!(Why::Allowance(why).is_allowance() && !Why::Allowance(why).ended(), "{why:?}");
    }
    for why in [
        Why::Missing,
        Why::Malformed,
        Why::Webauthn(Refusal::WrongChallenge),
        Why::UnknownCredential,
        Why::ForeignCredential,
        Why::AlreadyEnrolled,
        Why::CredentialTaken,
        Why::NoAccount,
        Why::Raced,
        Why::NotOffered,
        Why::LimitReached,
        Why::New(Refusal::WrongChallenge),
    ] {
        assert!(!why.is_allowance() && !why.ended(), "{why:?}");
    }
}

#[test]
fn an_allowances_passkey_is_committed_before_the_approval_runs() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let new = SoftKey::es256();
        let (new_id, _) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &SoftKey::es256());
            let _ = watching.seen();
            let (answer, _) = flow.post(cx, &flows, "p", &c, &allow_body(&new, &c, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            let seen = watching.seen();
            assert_eq!(seen.len(), 1, "{flow:?}");
            let ((kept, _), rows) = &seen[0];
            assert!(rows.is_empty(), "{flow:?}: spent by the time the approval ran");
            assert!(kept.iter().any(|(id, _, _)| *id == new_id), "{flow:?}: stored by then");
            assert_eq!(seen[0], kept_all(root.path()), "{flow:?}: and nothing after it");
        });
        drained();
    }
}

#[test]
fn a_workspace_refusal_keeps_the_passkey_and_spends_the_allowance() {
    use Answering::{Gate, Operation};
    let io = || bd_core::Error::Io(std::io::Error::other("disk full"));
    let busy = || bd_core::Error::Busy("locked".into());
    let locked = || bd_core::Error::Locked("locked".into());
    let cases: Vec<(Answering, u16, &str, &str)> = vec![
        (Gate(Ok(Approved::Resolved)), 409, "already resolved", ""),
        (Gate(Ok(Approved::NotArmed)), 409, "not ready", ""),
        (Gate(Ok(Approved::Gone(Found::NoIssue))), 404, "gone", ""),
        (Gate(Ok(Approved::Refused("not an approver".into()))), 403, "refused", ""),
        (Gate(Err(busy())), 503, "busy", ""),
        (Gate(Err(locked())), 503, "busy", ""),
        (Gate(Err(io())), 500, "failed", ""),
        (Operation(Ok(Performed::Done)), 409, "gone", "already closed"),
        (Operation(Ok(Performed::Gone(OpFound::NoIssue))), 404, "gone", "no such issue"),
        (Operation(Ok(Performed::NotHeld)), 409, "not_ready", "no longer held"),
        (Operation(Ok(Performed::Changed("bd-1 is pinned now.".into()))), 409, "not_ready", "target changed"),
        (Operation(Ok(Performed::Refused("claimed".into()))), 403, "refused", "refused by the workspace"),
        (Operation(Err(busy())), 503, "busy", "workspace busy"),
        (Operation(Err(locked())), 503, "busy", "workspace busy"),
        (Operation(Err(io())), 500, "failed", "internal error"),
    ];
    for (answering, status, outcome, detail) in cases {
        let flow = match answering {
            Gate(_) => Approving::Gate,
            Operation(_) => Approving::Operation,
        };
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let (lost, new) = (SoftKey::es256(), SoftKey::es256());
        let (new_id, prefix) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &lost);
            watching.answer(answering);
            let (answer, _) = flow.post(cx, &flows, "p", &c, &allow_body(&new, &c, &Tamper::default()));
            assert_eq!(page(&answer).status, status, "{outcome}: {}", page(&answer).html);
            assert_eq!(passkey::take_registered(), 1, "{outcome}");
            assert!(allowances(root.path()).is_empty(), "{outcome}: spent");
            assert_eq!(kept_passkeys(root.path())[1].credential, new_id, "{outcome}: kept");
            let line = Line {
                outcome: outcome.into(),
                detail: detail.into(),
                credential: prefix.clone(),
                added: String::new(),
                passkey: Some("registered under allowance"),
            };
            assert_eq!(flow.line(), line);
            // The person approves again, on the ordinary page, with the passkey the refusal kept.
            let (c, _) = opened(cx);
            assert!(c.allowance.is_none() && c.add.is_some(), "{outcome}");
            let (answer, _) = flow.post(cx, &flows, "q", &c, &assertion(&new, &c, 1, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{outcome}: {}", page(&answer).html);
            assert_eq!(flow.line(), flow.approved(&prefix, "verified"), "{outcome}");
            assert_eq!(kept_passkeys(root.path())[1].counter, 1, "{outcome}");
            assert_eq!(passkey::take_registered(), 0, "{outcome}");
        });
    }
}

#[test]
fn an_allowances_success_is_logged_and_counted_in_both_flows() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let new = SoftKey::es256();
        let (new_id, prefix) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &SoftKey::es256());
            let registered_before = crate::metrics::PASSKEYS_REGISTERED.get();
            let (answer, _) = flow.post(cx, &flows, "p", &c, &allow_body(&new, &c, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            assert_eq!(passkey::take_registered(), 1, "{flow:?}");
            assert!(crate::metrics::PASSKEYS_REGISTERED.get() > registered_before, "{flow:?}");
            let line = flow.line();
            assert_eq!(line, flow.approved(&prefix, "registered under allowance"), "{flow:?}");
            assert_ne!(line.credential, new_id, "{flow:?}: its prefix alone");
        });
    }
}

#[test]
fn an_allowances_refusals_are_logged_and_counted_in_both_flows() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let a = SoftKey::es256();
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let open = allowed_page(cx, &flows, &a);
            let id = open.allowance.as_ref().unwrap().id.clone();
            let refused = |c: &Ceremony, body: &str, label, credential: &str| {
                refused_in(flow, cx, &flows, &watching, c, body, (label, credential));
            };

            // The ceremony.
            let unverified = Tamper { flags: Some(0x41), ..Tamper::default() };
            refused(&open, &allow_body(&new, &open, &unverified), "allowance: user not verified", &prefix);
            let (other, _) = opened(cx);
            let elsewhere = allow_body(&new, &other, &Tamper::default());
            refused(&open, &elsewhere, "allowance: wrong challenge", &prefix);
            // The fields: nothing decoded, so no prefix to show.
            refused(&open, &format!("{EMPTY_HIDDEN}&allow_credential="), "allowance: missing fields", "");
            let twice = format!("{}&allow_credential=AAAA", allow_body(&new, &open, &Tamper::default()));
            refused(&open, &twice, "allowance: malformed fields", "");
            let ordinary = ceremony(false);
            let body = allow_body(&new, &open, &Tamper::default());
            refused(&ordinary, &body, "allowance: not offered", "");
            // The store's.
            let mut taken = SoftKey::es256();
            taken.credential = a.credential.clone();
            let (_, taken_prefix) = credential_of(&taken);
            let body = allow_body(&taken, &open, &Tamper::default());
            refused(&open, &body, "allowance: credential taken", &taken_prefix);
            // Replaced since the page was shown, and the new one run out by the time another is posted.
            granted(root.path());
            let body = allow_body(&new, &open, &Tamper::default());
            refused(&open, &body, "allowance: ended", &prefix);
            run_out(root.path());
            let past = ceremony(false).with_allowance(&allowances(root.path())[0].2, now_millis() - 1);
            let body = allow_body(&new, &past, &Tamper::default());
            refused(&past, &body, "allowance: expired", &prefix);
            assert_ne!(allowances(root.path())[0].2, id, "{flow:?}");
            granted(root.path());
            let (full, _) = opened(cx);
            fill_to(root.path(), passkeys::MAX_PER_ACCOUNT);
            let body = allow_body(&new, &full, &Tamper::default());
            refused(&full, &body, "allowance: limit reached", &prefix);
            assert!(auth::forget_account(root.path(), ACME_ISSUER, ACME_SUBJECT).unwrap());
            refused(&full, &body, "allowance: no account", &prefix);
        });
    }
}

#[test]
fn only_an_allowances_outcomes_show_on_an_operations_line() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let (a, new) = (SoftKey::es256(), SoftKey::es256());
        let (_, prefix) = credential_of(&a);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &a);
            let live = allowances(root.path());
            // On an allowance's page, the paths that are not its own.
            let (stale, _) = opened(cx);
            let body = assertion(&a, &c, 1, &Tamper::default());
            refused_in(flow, cx, &flows, &watching, &stale, &body, ("wrong challenge", &prefix));
            let body = format!("{}&{}", body, new_fields(&new.register(&c.expect(), &Tamper::default())));
            refused_in(flow, cx, &flows, &watching, &c, &body, ("adding not offered", ""));
            let (answer, _) = flow.post(cx, &flows, "p", &c, &assertion(&a, &c, 1, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            assert_eq!(flow.line(), flow.approved(&prefix, "verified"), "{flow:?}");
            assert_eq!(allowances(root.path()), live, "{flow:?}: unspent");
        });
        drained();
    }
}

#[test]
fn a_store_failure_says_nothing_of_the_allowance() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &SoftKey::es256());
            let body = allow_body(&new, &c, &Tamper::default());
            let live = allowances(root.path());
            // The table gone: the store's checks fail, and the transaction with them.
            let conn = rusqlite::Connection::open(crate::server_db::path(root.path())).unwrap();
            conn.execute_batch("DROP TABLE passkeys").unwrap();
            drop(conn);
            let (answer, _) = flow.post(cx, &flows, "p", &c, &body);
            assert_eq!(page(&answer).status, 500, "{flow:?}: {}", page(&answer).html);
            assert_eq!(passkey::take_registered(), 0, "{flow:?}");
            assert_eq!(allowances(root.path()), live, "{flow:?}: unspent");
            let (outcome, detail, passkey) = match flow {
                Approving::Gate => ("failed", "", Some("store failed")),
                Approving::Operation => ("failed", "internal error", None),
            };
            let line = Line {
                outcome: outcome.into(),
                detail: detail.into(),
                credential: prefix.clone(),
                added: String::new(),
                passkey,
            };
            assert_eq!(flow.line(), line, "{flow:?}");
        });
    }
}

#[test]
fn two_tabs_under_one_allowance_register_one_passkey() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let (first_key, second_key) = (SoftKey::es256(), SoftKey::es256());
        let (_, second_prefix) = credential_of(&second_key);
        with_watching(&watching, &flows, |cx| {
            let first = allowed_page(cx, &flows, &SoftKey::es256());
            let (second, _) = opened(cx);
            let (answer, _) = flow.post(cx, &flows, "p", &first, &allow_body(&first_key, &first, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            let body = allow_body(&second_key, &second, &Tamper::default());
            refused_in(flow, cx, &flows, &watching, &second, &body, ("allowance: ended", &second_prefix));
            assert_eq!(kept_passkeys(root.path()).len(), 2, "{flow:?}: the first tab's alone");
        });
    }
}

#[test]
fn an_allowances_post_is_taken_once_and_its_registration_is_no_good_on_another_page() {
    for flow in BOTH {
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let new = SoftKey::es256();
        let (_, prefix) = credential_of(&new);
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &SoftKey::es256());
            let body = allow_body(&new, &c, &Tamper::default());
            let (answer, _) = flow.post(cx, &flows, "once", &c, &body);
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            let _ = (flow.lines(), watching.seen());
            // The same POST again.
            let before = kept_all(root.path());
            let (answer, _) = flow.send(cx, &format!("approval=once&{body}"), &flow.cookies());
            assert_eq!(page(&answer).status, 400, "{flow:?}");
            assert!(page(&answer).html.contains("already used"), "{flow:?}: {}", page(&answer).html);
            assert_eq!(kept_all(root.path()), before, "{flow:?}");
            assert_eq!(watching.seen(), vec![], "{flow:?}");
            let lines = flow.lines();
            let details: Vec<&str> = lines.iter().map(|l| l.detail.as_str()).collect();
            assert_eq!(details, if flow == Approving::Gate { vec![] } else { vec!["already used"] });
            assert!(lines.iter().all(|l| l.passkey.is_none()), "{flow:?}");
            // The registration captured, on a page of a new allowance, which stays unspent.
            granted(root.path());
            let (next, _) = opened(cx);
            refused_in(flow, cx, &flows, &watching, &next, &body, ("allowance: wrong challenge", &prefix));
            assert_eq!(allowances(root.path()).len(), 1, "{flow:?}");
        });
    }
}

#[test]
fn a_post_refused_before_the_passkey_leaves_the_allowance_alone() {
    for flow in BOTH {
        drained();
        let root = gate_root(false);
        let flows = Mutex::new(Flows::default());
        let watching = Watching::new(root.path());
        let new = SoftKey::es256();
        with_watching(&watching, &flows, |cx| {
            let c = allowed_page(cx, &flows, &SoftKey::es256());
            let _ = watching.seen();
            let before = kept_all(root.path());
            let fields = allow_body(&new, &c, &Tamper::default());
            flow.put(&flows, "id", &c);

            // The approval's id twice, either way: incomplete, nothing taken.
            for twice in ["approval=id&approval=id", "approval=id&approval=nope"] {
                let (answer, _) = flow.send(cx, &format!("{twice}&{fields}"), &flow.cookies());
                assert_eq!(page(&answer).status, 400, "{flow:?} {twice}");
                assert!(page(&answer).html.contains("arrived incomplete"), "{}", page(&answer).html);
            }
            // No cookie, and another browser's.
            for other in [String::new(), flow.cookie(&"d".repeat(64))] {
                let (answer, _) = flow.send(cx, &format!("approval=id&{fields}"), &other);
                assert_eq!(page(&answer).status, 403, "{flow:?} {other:?}");
                assert!(page(&answer).html.contains("different browser"), "{}", page(&answer).html);
            }
            assert!(flow.waiting(&flows, "id"), "{flow:?}: nothing taken");

            // The sign-in settings gone since the page was shown: taken, then refused before the ceremony.
            let (settings, aside) = (root.path().join("auth.toml"), root.path().join("auth.toml.aside"));
            std::fs::rename(&settings, &aside).unwrap();
            let (answer, _) = flow.send(cx, &format!("approval=id&{fields}"), &flow.cookies());
            assert_eq!(page(&answer).status, 404, "{flow:?}");
            assert!(!flow.waiting(&flows, "id"), "{flow:?}");
            std::fs::rename(&aside, &settings).unwrap();

            assert_eq!(kept_all(root.path()), before, "{flow:?}");
            assert_eq!(watching.seen(), vec![], "{flow:?}: nothing approved");
            assert_eq!(passkey::take_registered(), 0, "{flow:?}");
            let lines = flow.lines();
            let details: Vec<&str> = lines.iter().map(|l| l.detail.as_str()).collect();
            let expected = [
                "form incomplete",
                "form incomplete",
                "different browser",
                "different browser",
                "sign-in settings unavailable",
            ];
            assert_eq!(details, if flow == Approving::Gate { &[][..] } else { &expected[..] }, "{flow:?}");
            assert!(lines.iter().all(|l| l.passkey.is_none() && l.credential.is_empty()), "{flow:?}");

            // The row is live: a page opened now spends it.
            let (next, _) = opened(cx);
            let (answer, _) = flow.post(cx, &flows, "next", &next, &allow_body(&new, &next, &Tamper::default()));
            assert_eq!(page(&answer).status, 200, "{flow:?}: {}", page(&answer).html);
            assert!(allowances(root.path()).is_empty(), "{flow:?}");
        });
        drained();
    }
}
