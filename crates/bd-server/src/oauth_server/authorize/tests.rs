use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::super::clients::Client;
use super::super::form;
use super::super::pages;
use crate::auth;
use crate::oauth::OauthConfig;
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
    root
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

/// An OIDC account's approval of bd-1, bound to the cookie `cookie` of value `value`.
fn approval(cookie: &str, value: &str) -> Approval {
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
    }
}

#[test]
fn approvals_are_posted_once_from_their_own_browser() {
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let opened = Approved::Opened { unblocked: vec!["bd-2".into()], completed: vec![] };
    let gates = FakeGates::answering(opened);
    let value = "c".repeat(64);
    let cookies = format!("x=1; __Secure-bd_gate_ab12={value}");
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
        lock(&flows).approvals.put(auth::hash("id1"), approval("ab12", &value));
        // Another browser's: refused, and the approval stays for its own.
        for other in
            ["", "__Secure-bd_gate_ab12=".to_string().as_str(), &format!("__Secure-bd_gate_ab12={}", "d".repeat(64))]
        {
            assert_eq!(page(&post("id1", "bd-1", other).0).status, 403, "{other:?}");
        }
        // Another gate's page: refused.
        assert_eq!(page(&post("id1", "bd-2", &cookies).0).status, 400);
        assert_eq!(gates.calls(), 0);
        // The reference the sign-in proved goes with it, whatever else the form says.
        let other = bd_core::gates::oidc_approver("https://login.example.com", "00u8");
        let body = format!("approval=id1&oidc_approver={other}&actor=acme:bob");
        let (answer, set) = gate::approve(cx, "proj", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        let call: Call = ("proj".into(), "bd-1".into(), "acme:alice".into(), Some(reference()));
        assert_eq!(*gates.calls.lock().unwrap(), [call]);
        assert_eq!(set, vec![set_gate_cookie(ISSUER, "proj", "bd-1", "ab12", "", Duration::ZERO)], "cleared");
        let again = post("id1", "bd-1", &cookies);
        assert_eq!((page(&again.0).status, html(&again).contains("already used")), (400, true));
        assert_eq!(gates.calls(), 1);
    });
    let gates = FakeGates::answering(Approved::NotArmed);
    with_ctx(root.path(), &flows, &gates, |cx| {
        lock(&flows).approvals.put(auth::hash("id2"), approval("ab12", &value));
        let (answer, _) = gate::approve(cx, "proj", "bd-1", "approval=id2", &cookies);
        assert_eq!(page(&answer).status, 409);
        assert!(page(&answer).html.contains("not ready"), "{}", page(&answer).html);
    });
    let mut flows = Flows::default();
    for i in 0..=MAX_FLOWS {
        flows.approvals.put(i.to_string(), approval("ab12", &value));
    }
    assert_eq!(flows.approvals.map.len(), MAX_FLOWS);
    assert!(flows.approvals.take("0").is_none(), "the oldest went first");
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
    let who = Who { provider: "github", login: "alice", subject: "1", actor: "github:alice" };
    record(Outcome::Approved, &who, "proj", "close", "bd-1", "performed");
    assert_eq!(take_recorded(), vec![(Outcome::Approved, "proj".into(), "close".into(), "bd-1".into(), "performed")]);
    assert_eq!(take_recorded(), vec![], "drained");
    let outcomes =
        [Outcome::Approved, Outcome::Refused, Outcome::NotReady, Outcome::Gone, Outcome::Busy, Outcome::Failed];
    for outcome in outcomes {
        record(outcome, &Who::provider_only("acme"), "proj", "discard", "bd-2", "flow expired");
    }
    let recorded = take_recorded();
    assert_eq!(recorded.iter().map(|r| r.0).collect::<Vec<_>>(), outcomes);
    assert!(recorded.iter().all(|r| (r.1.as_str(), r.2.as_str(), r.3.as_str()) == ("proj", "discard", "bd-2")));
    let labels: Vec<_> = outcomes.iter().map(|o| o.label()).collect();
    assert_eq!(labels, ["approved", "refused", "not_ready", "gone", "busy", "failed"]);
    assert_eq!(Who::provider_only("acme"), Who { provider: "acme", login: "", subject: "", actor: "" });
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
    let documents = super::super::cimd::Documents::new();
    let exists = |_: &str| true;
    let gates = FakeGates::answering(Approved::Resolved);
    let key = link_key();
    f(&Ctx {
        root,
        issuer: ISSUER,
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
    }
}

#[test]
fn operation_approvals_are_posted_once_from_their_own_browser_and_recorded_once() {
    use operation::{Outcome, take_recorded};
    let _ = take_recorded();
    let root = gate_root(false);
    let flows = Mutex::new(Flows::default());
    let ops = FakeOperations::new(OpFound::NoIssue, Performed::Closed);
    let value = "c".repeat(64);
    let cookies = format!("x=1; __Secure-bd_op_ab12={value}");
    let request = close_request("proj", "bd-1");
    let one =
        |outcome: Outcome, detail: &'static str| vec![(outcome, "proj".into(), "close".into(), "bd-1".into(), detail)];
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
        lock(&flows).operations.put(auth::hash("id1"), op_approval("ab12", &value, request.clone()));
        // Another browser's: refused, and the approval stays for its own.
        for other in ["", "__Secure-bd_op_ab12=", &format!("__Secure-bd_op_ab12={}", "d".repeat(64))] {
            assert_eq!(page(&post("id1", "bd-1", other).0).status, 403, "{other:?}");
            assert_eq!(take_recorded(), one(Outcome::Refused, "different browser"));
        }
        // Another path: refused.
        assert_eq!(page(&post("id1", "bd-2", &cookies).0).status, 400);
        assert_eq!(
            take_recorded(),
            vec![(Outcome::Refused, "proj".into(), "close".into(), "bd-2".into(), "another operation")]
        );
        assert_eq!(page(&operation::approve(cx, "proj", "discard", "bd-1", "approval=id1", &cookies).0).status, 400);
        assert_eq!(take_recorded().len(), 1);
        assert!(ops.performs().is_empty());
        // The sealed request and the reference the sign-in proved, whatever else the form says.
        let body = format!("approval=id1&reason=other&force=false&actor=acme:bob&oidc_approver={}", "x".repeat(8));
        let (answer, set) = operation::approve(cx, "proj", "close", "bd-1", &body, &cookies);
        assert_eq!(page(&answer).status, 200, "{}", page(&answer).html);
        assert_eq!(ops.performs(), vec![(request.clone(), "acme:alice".to_string(), Some(reference()))]);
        assert_eq!(ops.performs()[0].0.reason.as_deref(), Some("  why\n"), "byte for byte");
        assert_eq!(set, vec![set_op_cookie(ISSUER, "proj", "close", "bd-1", "ab12", "", Duration::ZERO)], "cleared");
        assert_eq!(take_recorded(), one(Outcome::Approved, "performed"));
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
    for (performed, status, outcome, detail) in [
        (Performed::Discarded { count: 3 }, 200, Outcome::Approved, "performed"),
        (Performed::Done, 409, Outcome::Gone, "already closed"),
        (Performed::Gone(OpFound::NoIssue), 404, Outcome::Gone, "no such issue"),
        (Performed::NotHeld, 409, Outcome::NotReady, "no longer held"),
        (Performed::Changed("bd-1 is pinned now.".into()), 409, Outcome::NotReady, "target changed"),
        (Performed::Refused("bd-1 is claimed by bob".into()), 403, Outcome::Refused, "refused by the workspace"),
    ] {
        let ops = FakeOperations::new(OpFound::NoIssue, performed);
        with_ops(root.path(), &flows, &ops, |cx| {
            lock(&flows).operations.put(auth::hash("id3"), op_approval("ab12", &value, request.clone()));
            let (answer, _) = operation::approve(cx, "proj", "close", "bd-1", "approval=id3", &cookies);
            assert_eq!(page(&answer).status, status, "{detail}");
            assert_eq!(take_recorded(), one(outcome, detail));
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
