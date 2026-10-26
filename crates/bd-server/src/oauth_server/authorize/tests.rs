use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::super::clients::Client;
use super::super::form;
use super::super::pages;
use crate::auth;
use crate::oauth::OauthConfig;

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
    fn find(&self, _: &str, _: &str) -> Result<Found, bd_core::Error> {
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
    f(&Ctx { root, issuer: ISSUER, documents: &documents, flows, workspace_exists: &exists, gates })
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
