use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bd_core::Timestamp;
use serde_json::Value;

use super::*;

pub(crate) const TEST_KEY: &str = include_str!("../../tests/fixtures/github-app.pem");

/// The RSA key pair of the test fixture.
pub(crate) fn rsa() -> ring::signature::RsaKeyPair {
    use ureq::tls::PemItem;
    let key = ureq::tls::parse_pem(TEST_KEY.as_bytes())
        .find_map(|item| match item {
            Ok(PemItem::PrivateKey(k)) => Some(k),
            _ => None,
        })
        .unwrap();
    ring::signature::RsaKeyPair::from_der(key.der())
        .or_else(|_| ring::signature::RsaKeyPair::from_pkcs8(key.der()))
        .unwrap()
}

/// The JWKS of the test key, as `kid`.
pub(crate) fn rsa_jwks(kid: &str) -> Value {
    let pair = rsa();
    let public = pair.public();
    let components: ring::rsa::PublicKeyComponents<Vec<u8>> = public.into();
    serde_json::json!({ "keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(&components.n), "e": URL_SAFE_NO_PAD.encode(&components.e),
    }]})
}

/// `claims` as an ID token signed with the test key, as `kid`.
pub(crate) fn rs256(kid: &str, claims: &Value) -> String {
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let signed =
        format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let pair = rsa();
    let mut signature = vec![0; pair.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    pair.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, signed.as_bytes(), &mut signature).unwrap();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims(now: i64) -> Value {
    serde_json::json!({
        "iss": "https://idp.example", "aud": "bd-client", "sub": "248289761001", "exp": now + 300, "iat": now,
        "nonce": "n-1", "email": "alice@acme.example", "email_verified": true, "name": "Alice",
    })
}

#[test]
fn providers_error_codes_are_shown_only_when_plain() {
    assert_eq!(error_code("invalid_grant"), "invalid_grant");
    for odd in ["", "bad\nline", "\u{1b}[31mred", "quote\"", &"x".repeat(65)] {
        assert_eq!(error_code(odd), "an error", "{odd:?}");
    }
}

#[test]
fn providers_are_checked() {
    let doc = |text: &str| toml::from_str::<OidcDoc>(text).map_err(|e| e.to_string()).and_then(|d| parse("google", d));
    let o = doc("issuer = \"https://accounts.google.com\"\nclient_id = \"c\"").unwrap();
    assert_eq!((o.label.as_str(), o.scopes.join(" ")), ("google", "openid email profile".to_string()));
    let o = doc(
        "issuer = \"https://idp.example\"\nclient_id = \"c\"\nlabel = \"Acme SSO\"\nscopes = [\"groups\", \"openid\"]",
    )
    .unwrap();
    assert_eq!((o.label.as_str(), o.scopes.join(" ")), ("Acme SSO", "openid groups".to_string()));
    for (bad, says) in [
        ("issuer = \"http://idp.example\"\nclient_id = \"c\"", "not an https URL"),
        ("issuer = \"https://idp.example?x\"\nclient_id = \"c\"", "not an https URL"),
        ("issuer = \"https://idp.example\"\nclient_id = \"\"", "not a client ID"),
        ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nlabel = \"\"", "label"),
        ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nscopes = [\"a b\"]", "not a scope"),
        ("issuer = \"https://idp.example\"\nclient_id = \"c\"\nsecret = \"s\"", "unknown field"),
    ] {
        let e = doc(bad).unwrap_err();
        assert!(e.contains(says), "{bad}: {e}");
    }
    assert!(doc("issuer = \"https://u:p@idp.example\"\nclient_id = \"c\"").unwrap_err().contains("not an https URL"));
    assert!(doc("issuer = \"http://127.0.0.1:80@evil.example\"\nclient_id = \"c\"").is_err(), "not this machine");
    let issuer = "https://idp.example";
    assert!(endpoint_ok("https://idp.example/token", issuer));
    assert!(!endpoint_ok("https://u@idp.example/token", issuer));
    assert!(!endpoint_ok("http://127.0.0.1:9/token", issuer), "no plain http from an https issuer");
    assert!(endpoint_ok("http://127.0.0.1:9/token", "http://127.0.0.1:9"));
    assert!(!endpoint_ok("http://localhost:1@evil.example/token", "http://127.0.0.1:9"));
    let ok = || toml::from_str::<OidcDoc>("issuer = \"https://idp.example\"\nclient_id = \"c\"").unwrap();
    assert!(parse("github", ok()).unwrap_err().contains("choose another name"));
    assert!(parse("Google", ok()).unwrap_err().contains("lowercase"));
}

#[test]
fn rules_let_accounts_in_by_subject_email_domain_or_group_and_refreshes_keep_to_them() {
    use crate::oauth::Decision;
    let doc = |text: &str| {
        let text = format!("issuer = \"https://idp.example\"\nclient_id = \"c\"\ngroups_claim = \"roles\"\n{text}");
        toml::from_str::<OidcDoc>(&text).map_err(|e| e.to_string()).and_then(|d| parse("corp", d))
    };
    let o = doc("[[allow]]\nsubjects = [\"s-admin\"]\nrole = \"admin\"\nkind = \"human\"\n\
         [[allow]]\nemails = [\"Bob@Acme.example\"]\n\
         [[allow]]\nemail_domains = [\"@acme.example\"]\nrole = \"read\"\n\
         [[allow]]\ngroups = [\"eng\"]\nworkspaces = [\"proj\"]\n")
    .unwrap();
    assert_eq!((o.allow.len(), o.groups_claim.as_str()), (4, "roles"));
    let claims = |email: Option<&str>, roles: Value| Claims {
        subject: "s1".into(),
        login: "u-x".into(),
        email: email.map(str::to_string),
        all: serde_json::json!({ "roles": roles }),
    };
    let user = |subject: &str| crate::auth::Identity {
        provider: "corp".into(),
        issuer: "https://idp.example".into(),
        subject: subject.into(),
        login: "u-x".into(),
    };
    let decide = |rules: &[crate::oauth::Rule], facts: &mut dyn crate::oauth::Facts, kept: Option<&str>, ws: &str| {
        crate::oauth::decide(rules, facts, kept, ws).unwrap()
    };
    let at_sign_in = |subject: &str, c: &Claims, ws: &str| {
        let u = user(subject);
        decide(&o.allow, &mut o.facts(&u, c), None, ws)
    };
    let role = |d: &crate::oauth::Decided| match &d.decision {
        Decision::In { grant, via, .. } => Some((grant.role, via.clone())),
        _ => None,
    };
    let none = claims(None, Value::Null);
    assert_eq!(
        role(&at_sign_in("s-admin", &none, "proj")),
        Some((crate::auth::Role::Admin, "corp account u-x".into()))
    );
    assert_eq!(
        role(&at_sign_in("s1", &claims(Some("bob@acme.example"), Value::Null), "x")).unwrap().1,
        "a listed email"
    );
    let domain = at_sign_in("s1", &claims(Some("carol@ACME.example"), Value::Null), "x");
    assert_eq!(role(&domain), Some((crate::auth::Role::Read, "an email at acme.example".into())));
    let group = at_sign_in("s1", &claims(None, serde_json::json!(["ops", "eng"])), "proj");
    assert_eq!(role(&group).unwrap().1, "member of eng");
    let elsewhere = at_sign_in("s1", &claims(None, serde_json::json!("eng")), "other");
    assert!(matches!(elsewhere.decision, Decision::Elsewhere(_)));
    let out = at_sign_in("s1", &claims(Some("eve@evil.example"), Value::Null), "proj");
    assert!(matches!(out.decision, Decision::Out));

    // A refresh has no claims: a subject decides again; a claims rule only as the one that let it in, unchanged.
    let refresh = |rules: &[crate::oauth::Rule], subject: &str, kept: Option<&str>| {
        let u = user(subject);
        decide(rules, &mut crate::oauth::Listed::kept(&u), kept, "proj")
    };
    assert!(role(&refresh(&o.allow, "s-admin", None)).is_some());
    let kept = domain.rule.clone().unwrap();
    assert_eq!(
        role(&refresh(&o.allow, "s1", Some(&kept))),
        Some((crate::auth::Role::Read, "corp account u-x, as at sign-in".into()))
    );
    assert!(matches!(refresh(&o.allow, "s1", None).decision, Decision::Out), "no claims, no rule kept");
    let changed = doc("[[allow]]\nsubjects = [\"s-admin\"]\nrole = \"admin\"\nkind = \"human\"\n\
         [[allow]]\nemail_domains = [\"acme.example\"]\nrole = \"write\"\n")
    .unwrap();
    let again = refresh(&changed.allow, "s1", Some(&kept));
    assert!(matches!(again.decision, Decision::Out), "the rule changed: the sign-in is not kept");

    for (bad, says) in [
        ("[[allow]]\nrole = \"read\"", "lets nobody in"),
        ("[[allow]]\nanyone = true\nsubjects = [\"x\"]", "drop whom it names"),
        ("[[allow]]\nanyone = true\nrole = \"admin\"", "anyone in"),
        ("[[allow]]\nemails = [\"not-an-email\"]", "is not one"),
        ("[[allow]]\nusers = [\"alice\"]", "logins are not proved names"),
        ("[[allow]]\ngroups = [\"eng\"]\nmin_account_age = \"30d\"", "min_account_age is GitHub's"),
        ("[[allow]]\ngroups = [\"a b\"]", "not one"),
        ("[[allow]]\nsubjects = [\"x\"]\nsecret = 1", "unknown field"),
    ] {
        let e = doc(bad).unwrap_err();
        assert!(e.contains(says), "{bad}: {e}");
    }
}

#[test]
fn account_notifications_are_verified_and_read() {
    let now = 1_800_000_000;
    let keys = jwks(&rsa_jwks("k1"));
    let apps = vec!["net.example.app".to_string(), "net.example.app.signin".to_string()];
    let check = |token: &str| account_event(token, &keys, "https://idp.example", &apps, now);
    let notice = |events: Value| {
        serde_json::json!({ "iss": "https://idp.example", "aud": "net.example.app", "iat": now - 60,
            "jti": "j1", "events": events })
    };
    let event = |kind: &str| serde_json::json!({ "type": kind, "sub": "001.abc.9", "event_time": now - 30 });
    // As Apple sends it: the events a string of JSON.
    let revoked = check(&rs256("k1", &notice(event("consent-revoked").to_string().into()))).unwrap();
    assert_eq!(
        revoked,
        AccountEvent {
            kind: AccountChange::ConsentRevoked,
            subject: "001.abc.9".into(),
            at: Timestamp::from_millis((now - 30) * 1000),
        }
    );
    assert_eq!(check(&rs256("k1", &notice(event("account-deleted")))).unwrap().kind, AccountChange::Deleted);
    let email = check(&rs256("k1", &notice(event("email-disabled")))).unwrap();
    assert_eq!(email.kind, AccountChange::Other("email-disabled".into()));
    let mut ms = event("consent-revoked");
    ms["event_time"] = ((now - 30) * 1000).into();
    assert_eq!(check(&rs256("k1", &notice(ms))).unwrap().at, revoked.at, "milliseconds read as such");

    let refused = |c: Value| check(&rs256("k1", &c)).unwrap_err();
    let mut c = notice(event("account-deleted"));
    c["aud"] = "net.other.app".into();
    assert!(refused(c).contains("audience"));
    let mut c = notice(event("account-deleted"));
    c["iss"] = "https://evil.example".into();
    assert!(refused(c).contains("issuer"));
    let mut c = notice(event("account-deleted"));
    c["iat"] = (now - MAX_EVENT_AGE - 1).into();
    assert!(refused(c).contains("too far"), "a replay");
    let mut c = notice(event("account-deleted"));
    c["events"]["sub"] = "".into();
    assert!(refused(c).contains("subject"));
    assert!(check(&rs256("k2", &notice(event("account-deleted")))).is_err(), "another key");
    let unsigned = rs256("k1", &notice(event("account-deleted")));
    let forged = format!("{}.{}", &unsigned[..unsigned.rfind('.').unwrap()], "AAAA");
    assert!(check(&forged).is_err(), "a forged signature");
}

#[test]
fn id_tokens_are_verified_strictly() {
    let now = 1_800_000_000;
    let keys = jwks(&rsa_jwks("k1"));
    assert_eq!(keys.len(), 1);
    let check = |token: &str| verify(token, &keys, "https://idp.example", "bd-client", Some("n-1"), now);
    let good = check(&rs256("k1", &claims(now))).unwrap();
    assert_eq!(
        (good.subject.as_str(), good.login.as_str(), good.email.as_deref()),
        ("248289761001", "u-1978d011ddff", Some("alice@acme.example"))
    );
    assert_eq!(good.all["name"], "Alice");
    let with = |field: &str, value: Value| {
        let mut c = claims(now);
        c[field] = value;
        rs256("k1", &c)
    };
    let login = |token: &str| check(token).unwrap().login;
    assert_eq!(login(&with("preferred_username", "alice".into())), "alice", "a user name first");
    let anonymous = pseudonym("https://idp.example", "248289761001");
    assert!(anonymous.starts_with("u-") && anonymous.len() == 14, "{anonymous}");
    assert_eq!(login(&rs256("k1", &claims(now))), anonymous, "never the email, though verified");
    assert_eq!(check(&rs256("k1", &claims(now))).unwrap().email.as_deref(), Some("alice@acme.example"));
    assert_eq!(check(&with("email_verified", false.into())).unwrap().email, None);
    assert_eq!(login(&with("preferred_username", "alice@contoso.example".into())), anonymous, "Entra's UPN");
    assert_eq!(login(&with("preferred_username", "al\u{202e}ice".into())), anonymous);
    assert_ne!(pseudonym("https://other.example", "248289761001"), anonymous, "per issuer");
    // A user name chosen to be another account's pseudonym is not taken: the account gets its own.
    let squatter = pseudonym("https://idp.example", "someone-else").to_uppercase().replacen("U-", "u-", 1);
    assert_eq!(login(&with("preferred_username", squatter.into())), anonymous);
    assert_eq!(login(&with("preferred_username", "u-abc".into())), "u-abc", "not that form");
    let aud = |aud: Value, azp: Option<&str>| {
        let mut c = claims(now);
        c["aud"] = aud;
        if let Some(azp) = azp {
            c["azp"] = azp.into();
        }
        check(&rs256("k1", &c))
    };
    assert!(aud(serde_json::json!(["bd-client"]), None).is_ok(), "a list of one");
    assert!(
        aud(serde_json::json!(["bd-client", "other"]), Some("bd-client")).unwrap_err().contains("aud"),
        "another audience"
    );
    for (token, says) in [
        (with("iss", "https://evil.example".into()), "issuer"),
        (with("aud", "other".into()), "aud"),
        (with("exp", (now - 600).into()), "expired"),
        (with("iat", (now + 600).into()), "future"),
        (with("nonce", "n-2".into()), "nonce"),
        (with("sub", "".into()), "subject"),
        (rs256("k2", &claims(now)), "no key"),
    ] {
        let e = check(&token).unwrap_err();
        assert!(e.contains(says), "{says}: {e}");
    }
    assert!(aud(serde_json::json!(["bd-client", "other"]), None).unwrap_err().contains("aud"));
    assert!(aud("bd-client".into(), Some("other")).unwrap_err().contains("azp"));
    assert!(
        verify(&rs256("k1", &claims(now)), &keys, "https://idp.example", "bd-client", None, now).is_ok(),
        "no nonce to check"
    );
    // Tampered with, or signed with nothing or a shared secret.
    let token = rs256("k1", &claims(now));
    let parts: Vec<&str> = token.split('.').collect();
    let mut forged = claims(now);
    forged["sub"] = "admin".into();
    let tampered = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(forged.to_string()), parts[2]);
    assert!(check(&tampered).unwrap_err().contains("no key"));
    for alg in ["none", "HS256"] {
        let head = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": alg, "kid": "k1" }).to_string());
        let token = format!("{head}.{}.{}", parts[1], parts[2]);
        assert!(check(&token).unwrap_err().contains("not RS256 or ES256"), "{alg}");
    }
    assert!(check("a.b").is_err());
}

#[test]
fn providers_like_apple_post_their_answers_and_take_signed_secrets() {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let doc = |text: &str| {
        let text = format!("issuer = \"https://appleid.apple.com\"\nclient_id = \"com.example.bd\"\n{text}");
        toml::from_str::<OidcDoc>(&text).map_err(|e| e.to_string()).and_then(|d| parse("apple", d))
    };
    let signed = "[signed_secret]\nkey_file = \"AuthKey.p8\"\nkey_id = \"KEY123\"\nteam_id = \"TEAM123\"\n";
    let mut o = doc(&format!("response_mode = \"form_post\"\n{signed}")).unwrap();
    assert!(o.form_post && doc("").unwrap().signed_secret.is_none() && !doc("").unwrap().form_post);
    assert_eq!(o.secret_files().collect::<Vec<_>>(), [&PathBuf::from("AuthKey.p8")]);
    for (bad, says) in [
        ("response_mode = \"fragment\"", "neither"),
        (&format!("client_secret_file = \"s\"\n{signed}"), "not both"),
        ("[signed_secret]\nkey_file = \"k\"\nkey_id = \"K 1\"\nteam_id = \"T\"", "letters and digits"),
        ("[signed_secret]\nkey_file = \"\"\nkey_id = \"K\"\nteam_id = \"T\"", "key_file is empty"),
        ("[signed_secret]\nkey_file = \"k\"\nkey_id = \"K\"", "team_id"),
    ] {
        let e = doc(bad).unwrap_err();
        assert!(e.contains(says), "{bad}: {e}");
    }

    // The key: a .p8 file, as Apple gives them; another kind of key is refused.
    let dir = tempfile::tempdir().unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(pkcs8.as_ref()));
    std::fs::write(dir.path().join("AuthKey.p8"), pem).unwrap();
    assert!(o.secret().is_err(), "not read yet");
    o.load_secret(dir.path()).unwrap();
    assert!(!format!("{o:?}").contains(&STANDARD.encode(pkcs8.as_ref())[..20]), "never the key");
    let mut rsa_key = o.clone();
    std::fs::write(dir.path().join("rsa.pem"), include_str!("../../tests/fixtures/github-app.pem")).unwrap();
    rsa_key.signed_secret.as_mut().unwrap().key_file = "rsa.pem".into();
    assert!(rsa_key.load_secret(dir.path()).unwrap_err().contains("not a P-256 key"));

    // Each secret: signed for the client, for a few minutes.
    let Secret(jwt) = o.secret().unwrap().unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let part = |i: usize| serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[i]).unwrap()).unwrap();
    assert_eq!(part(0), serde_json::json!({ "alg": "ES256", "kid": "KEY123" }));
    let claims = part(1);
    assert_eq!((&claims["iss"], &claims["sub"]), (&"TEAM123".into(), &"com.example.bd".into()));
    assert_eq!(claims["aud"], "https://appleid.apple.com");
    let now = Timestamp::now().millis() / 1000;
    assert!(claims["exp"].as_i64().unwrap() <= now + SIGNED_FOR && claims["iat"].as_i64().unwrap() <= now);
    let public = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref());
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature).unwrap();

    let md = Metadata {
        authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
        token_endpoint: String::new(),
        jwks_uri: String::new(),
        device_authorization_endpoint: None,
        basic_auth: false,
        iss_parameter: false,
    };
    let url = |o: &Oidc| o.authorization_url(&md, "https://bd.example/oauth/apple/callback", "s", "n", "c");
    assert!(url(&o).contains("&response_mode=form_post"), "{}", url(&o));
    assert!(!url(&doc("").unwrap()).contains("response_mode"));
}

#[test]
fn es256_tokens_are_verified_too() {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref();
    let doc = serde_json::json!({ "keys": [
        { "kty": "EC", "crv": "P-256", "kid": "e1", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..]) },
        { "kty": "oct", "kid": "s1", "k": "c2VjcmV0" },
        { "kty": "RSA", "use": "enc", "kid": "x", "n": "AQAB", "e": "AQAB" },
    ]});
    let keys = jwks(&doc);
    assert_eq!(keys.len(), 1, "only signing keys bd can use");
    let now = 1_800_000_000;
    let head = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": "ES256", "kid": "e1" }).to_string());
    let signed = format!("{head}.{}", URL_SAFE_NO_PAD.encode(claims(now).to_string()));
    let signature = pair.sign(&rng, signed.as_bytes()).unwrap();
    let token = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
    assert!(verify(&token, &keys, "https://idp.example", "bd-client", Some("n-1"), now).is_ok());
}
