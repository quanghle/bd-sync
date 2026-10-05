use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::super::clients::Client;
use super::super::form;
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
    let pending = Pending { query: "client_id=x".into(), browser: "b".into(), until: 1, at: Some(at) };
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
