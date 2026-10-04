//! GitHub: its API as the App and as the person signing in, the App's
//! key and client secret, memberships, and its web sign-in.

use super::*;

/// GitHub sign-in, as `[github]` configures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Github {
    pub client_id: String,
    /// Where people sign in, with the device flow's endpoints:
    /// `https://github.com`, or a GitHub Enterprise Server.
    pub url: String,
    /// GitHub's REST API.
    pub api_url: String,
    /// The GitHub App's private key file, as written (relative to the root).
    pub private_key: Option<PathBuf>,
    /// The key itself, read by [`load`]: it reads accounts and memberships
    /// at refreshes, for the rules.
    pub app: Option<AppKey>,
    /// The GitHub App's client secret file, as written (relative to the root).
    pub client_secret_file: Option<PathBuf>,
    /// The secret itself, read by [`load`]: the web flow needs it.
    pub client_secret: Option<ClientSecret>,
    /// GitHub user ids that may never sign in, whatever decides.
    pub deny: Vec<String>,
    /// `[[github.allow]]`: who may sign in, unless an authorizer decides.
    pub allow: Vec<Rule>,
}

impl Github {
    /// Whether a rule names organizations or teams, whose memberships an
    /// OAuth app reads with the `read:org` scope.
    pub(super) fn reads_orgs(&self) -> bool {
        self.allow.iter().any(|r| !r.groups.is_empty())
    }
}

/// Memberships GitHub tells: asked as the person signing in ([`Asked`]), or
/// as the App at a refresh ([`Installed`]).
pub(super) trait Memberships {
    fn org(&mut self, org: &str) -> Result<Member>;
    fn team(&mut self, org: &str, team: &str) -> Result<Member>;
}

/// What GitHub proves of an account, for the rules: its id and login as
/// GitHub names it now, when GitHub made it, and its memberships (groups
/// `acme`, `acme/eng`) as rules ask.
pub(super) struct GithubFacts<'a, M: Memberships> {
    pub(super) user: &'a Identity,
    pub(super) created: Option<Timestamp>,
    pub(super) asked: M,
}

impl<M: Memberships> Facts for GithubFacts<'_, M> {
    fn identity(&self) -> &Identity {
        self.user
    }

    fn fresh(&self) -> bool {
        true
    }

    fn age(&self) -> Option<Duration> {
        self.created.map(|at| Duration::from_millis(Timestamp::now().since(at).max(0) as u64))
    }

    fn member(&mut self, group: &str) -> Result<Member> {
        match group.split_once('/') {
            Some((org, team)) => self.asked.team(org, team),
            None => self.asked.org(group),
        }
    }
}

/// A GitHub App's private key (`github.private_key`), which signs the JWTs
/// that get installation tokens.
#[derive(Clone)]
pub struct AppKey {
    pub(super) path: PathBuf,
    pub(super) pair: Arc<ring::signature::RsaKeyPair>,
}

impl std::fmt::Debug for AppKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("AppKey").field("path", &self.path).finish()
    }
}

impl PartialEq for AppKey {
    fn eq(&self, other: &AppKey) -> bool {
        self.path == other.path
    }
}

impl Eq for AppKey {}

impl AppKey {
    /// The RSA key of a PEM file (PKCS#1, as GitHub gives them, or PKCS#8).
    pub(super) fn load(path: &Path) -> std::result::Result<AppKey, String> {
        use ureq::tls::PemItem;
        let at = format!("github.private_key {}", path.display());
        let pem = std::fs::read(path).map_err(|e| format!("{at}: {e}"))?;
        let key = ureq::tls::parse_pem(&pem)
            .find_map(|item| match item {
                Ok(PemItem::PrivateKey(k)) => Some(k),
                _ => None,
            })
            .ok_or_else(|| format!("{at}: no private key in the file"))?;
        let pair = ring::signature::RsaKeyPair::from_der(key.der())
            .or_else(|_| ring::signature::RsaKeyPair::from_pkcs8(key.der()))
            .map_err(|e| format!("{at}: not a usable RSA key, as GitHub Apps' are ({e})"))?;
        Ok(AppKey { path: path.to_path_buf(), pair: Arc::new(pair) })
    }

    /// A JWT for the GitHub App `client_id`: valid for 9 minutes (GitHub
    /// takes at most 10), dated a minute back for clocks that differ.
    pub(super) fn jwt(&self, client_id: &str) -> Result<String> {
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let now = Timestamp::now().millis() / 1000;
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({ "iat": now - 60, "exp": now + 540, "iss": client_id });
        let signed = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let mut signature = vec![0; self.pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        self.pair
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, signed.as_bytes(), &mut signature)
            .map_err(|_| Error::Io(std::io::Error::other("signing a GitHub App JWT failed")))?;
        Ok(format!("{signed}.{}", b64(&signature)))
    }
}

/// A client secret of the GitHub App (`github.client_secret_file`), which
/// GitHub's web flow wants with each code it gives a token for.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret(pub(super) String);

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secret.
        f.write_str("ClientSecret(..)")
    }
}

impl ClientSecret {
    /// The secret in `path`: one line, as GitHub shows it.
    pub(super) fn load(path: &Path) -> std::result::Result<ClientSecret, String> {
        let at = format!("github.client_secret_file {}", path.display());
        let text = std::fs::read_to_string(path).map_err(|e| format!("{at}: {e}"))?;
        let secret = text.trim();
        if secret.is_empty() || secret.len() > 256 || !secret.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("{at}: not a client secret (one line of printable characters)"));
        }
        Ok(ClientSecret(secret.to_string()))
    }
}

/// What GitHub Apps were given, shared by every refresh: installation
/// tokens by installation (`<api_url> <client_id> <id>`), used until
/// [`TOKEN_MARGIN`] before GitHub's `expires_at`; and the installation that
/// serves an organization (`... org:<org>`), or any account (`... *`), kept
/// until GitHub no longer takes it.
#[derive(Default)]
struct Installations {
    tokens: HashMap<String, (String, Instant)>,
    ids: HashMap<String, u64>,
}

static INSTALLATIONS: LazyLock<Mutex<Installations>> = LazyLock::new(Default::default);

fn installations() -> std::sync::MutexGuard<'static, Installations> {
    INSTALLATIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An installation token is no longer used this long before GitHub says it
/// expires, so no request starts with one about to end.
const TOKEN_MARGIN: Duration = Duration::from_secs(5 * 60);

/// The one HTTP client of every GitHub request: its connections (and their
/// TLS sessions) serve the next request to the same host. Its requests carry
/// the account's or the App's token: never on to wherever a redirect points.
static GITHUB_AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(GITHUB_TIMEOUT))
        .user_agent(format!("bd/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
});

/// The GitHub endpoints sign-in uses, each request ending within
/// [`GITHUB_TIMEOUT`], and all of them by `deadline` if there is one.
pub(super) struct Api {
    pub(super) url: String,
    pub(super) api_url: String,
    deadline: Option<Instant>,
}

impl Api {
    pub(super) fn new(github: &Github) -> Api {
        Api { url: github.url.clone(), api_url: github.api_url.clone(), deadline: None }
    }

    /// [`Api::new`], every request of it ending within `budget` from now.
    pub(super) fn within(github: &Github, budget: Duration) -> Api {
        Api { deadline: Some(Instant::now() + budget), ..Api::new(github) }
    }

    /// The time a request to `url` has, or why it has none left.
    fn time(&self, url: &str) -> Result<Duration> {
        let Some(deadline) = self.deadline else { return Ok(GITHUB_TIMEOUT) };
        match deadline.saturating_duration_since(Instant::now()) {
            left if left.is_zero() => {
                Err(Error::Remote(format!("GitHub ({url}) took too long to answer; try again later")))
            }
            left => Ok(left.min(GITHUB_TIMEOUT)),
        }
    }

    /// `request` to `url`, given the time left, with `token` if any.
    fn timed<B>(
        &self,
        request: ureq::RequestBuilder<B>,
        url: &str,
        token: Option<&str>,
    ) -> Result<ureq::RequestBuilder<B>> {
        let request = request.config().timeout_global(Some(self.time(url)?)).build();
        Ok(match token {
            Some(token) => request
                .header("accept", "application/vnd.github+json")
                .header("authorization", &format!("Bearer {token}")),
            None => request.header("accept", "application/json"),
        })
    }

    /// POST a form to a device flow endpoint (`/login/...`): GitHub's answer.
    pub(super) fn form(&self, path: &str, form: &[(&str, &str)]) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.url);
        let sent = self.timed(GITHUB_AGENT.post(&url), &url, None)?.send_form(form.iter().copied());
        answer(&url, sent)
    }

    /// GET an API endpoint with `token`: GitHub's answer.
    pub(super) fn get(&self, token: &str, path: &str) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.api_url);
        let sent = self.timed(GITHUB_AGENT.get(&url), &url, Some(token))?.call();
        answer(&url, sent)
    }

    /// POST to an API endpoint, without a body, with `token`: GitHub's answer.
    pub(super) fn post(&self, token: &str, path: &str) -> Result<(u16, Value)> {
        let url = format!("{}{path}", self.api_url);
        let sent = self.timed(GITHUB_AGENT.post(&url), &url, Some(token))?.send_empty();
        answer(&url, sent)
    }
}

/// A GitHub answer's status, and its JSON body (`null` when it has none).
pub(super) fn answer(
    url: &str,
    sent: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<(u16, Value)> {
    let mut response = sent.map_err(|e| Error::Remote(format!("GitHub ({url}) did not answer: {e}")))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
        .map_err(|e| Error::Remote(format!("GitHub ({url}): reading the answer: {e}")))?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

/// ` (GitHub's message)`, if its answer has one.
pub(super) fn message(body: &Value) -> String {
    let text = body["message"].as_str().or(body["error_description"].as_str()).unwrap_or_default();
    match text.char_indices().nth(MAX_MESSAGE) {
        _ if text.is_empty() => String::new(),
        Some((i, _)) => format!(" ({}…)", crate::agents::show::printable(&text[..i])),
        None => format!(" ({})", crate::agents::show::printable(text)),
    }
}

/// GitHub as the GitHub App of `auth.toml` sees it: what refreshes ask,
/// with installation tokens, never an account's own.
pub(super) struct AppApi<'a> {
    pub(super) api: &'a Api,
    pub(super) github: &'a Github,
    pub(super) key: &'a AppKey,
}

impl AppApi<'_> {
    /// What tells this App's installations and tokens from another's.
    fn app(&self) -> String {
        format!("{} {}", self.github.api_url, self.github.client_id)
    }

    /// The token kept for `installation`, if it is not about to expire.
    fn kept(&self, installation: u64) -> Option<String> {
        let mut all = installations();
        let now = Instant::now();
        all.tokens.retain(|_, (_, until)| now < *until);
        all.tokens.get(&format!("{} {installation}", self.app())).map(|(token, _)| token.clone())
    }

    /// An installation token of the App, and its installation: of its
    /// installation on `org`, or of any for `None` (any kept one will do).
    /// `None` when it is not installed there. Which installation serves an
    /// organization is asked once, and asked again only when GitHub no
    /// longer gives it tokens.
    pub(super) fn token(&self, org: Option<&str>) -> Result<Option<(u64, String)>> {
        let app = self.app();
        let which = match org {
            Some(org) => format!("{app} org:{}", org.to_ascii_lowercase()),
            None => format!("{app} *"),
        };
        let known = installations().ids.get(&which).copied();
        if let Some(token) = known.and_then(|id| self.kept(id).map(|t| (id, t))) {
            return Ok(Some(token));
        }
        if org.is_none() {
            let now = Instant::now();
            let all = installations();
            let any = all.tokens.iter().find(|(k, (_, until))| now < *until && k.starts_with(&format!("{app} ")));
            if let Some((id, token)) =
                any.and_then(|(k, (t, _))| Some((k.rsplit(' ').next()?.parse().ok()?, t.clone())))
            {
                return Ok(Some((id, token)));
            }
        }
        let jwt = self.key.jwt(&self.github.client_id)?;
        if let Some(id) = known {
            match self.mint(&jwt, id) {
                Ok(token) => return Ok(Some((id, token))),
                // Uninstalled or suspended since: found again below.
                Err(_) => drop(installations().ids.remove(&which)),
            }
        }
        let candidates = match org {
            Some(org) => {
                let (status, body) = self.api.get(&jwt, &format!("/orgs/{org}/installation"))?;
                match status {
                    200 => vec![
                        body["id"]
                            .as_u64()
                            .ok_or_else(|| Error::Remote("GitHub answered an installation without its id".into()))?,
                    ],
                    404 => return Ok(None),
                    _ => return Err(self.failed(&format!("find its installation on {org}"), status, &body)),
                }
            }
            None => {
                // Any installation that is not suspended: the first that gives a token.
                let (status, body) = self.api.get(&jwt, "/app/installations?per_page=100")?;
                let Some(all) = body.as_array().filter(|_| status == 200) else {
                    return Err(self.failed("list its installations", status, &body));
                };
                all.iter().filter(|i| i["suspended_at"].is_null()).filter_map(|i| i["id"].as_u64()).collect()
            }
        };
        let mut failure = None;
        for id in candidates {
            // An installation found again may already have a token (another organization's, the same one).
            if let Some(token) = self.kept(id) {
                installations().ids.insert(which, id);
                return Ok(Some((id, token)));
            }
            match self.mint(&jwt, id) {
                Ok(token) => {
                    installations().ids.insert(which, id);
                    return Ok(Some((id, token)));
                }
                Err(e) => failure = Some(e),
            }
        }
        failure.map_or(Ok(None), Err)
    }

    /// A new installation token of `installation`, kept until shortly
    /// before GitHub says it expires.
    fn mint(&self, jwt: &str, installation: u64) -> Result<String> {
        let (status, body) = self.api.post(jwt, &format!("/app/installations/{installation}/access_tokens"))?;
        let Some(token) = body["token"].as_str().filter(|t| status == 201 && !t.is_empty()) else {
            return Err(self.failed("get an installation token", status, &body));
        };
        let left = body["expires_at"]
            .as_str()
            .and_then(|at| Timestamp::parse_rfc3339(at).ok())
            .map(|at| Duration::from_millis(at.since(Timestamp::now()).max(0) as u64))
            .unwrap_or(INSTALLATION_TOKEN_LIFE + TOKEN_MARGIN);
        let until = Instant::now() + left.saturating_sub(TOKEN_MARGIN);
        installations().tokens.insert(format!("{} {installation}", self.app()), (token.to_string(), until));
        Ok(token.to_string())
    }

    /// GET `path` with an installation token (`org`'s, or any): `None` when
    /// the App is not installed there. A token GitHub refuses is not used again.
    pub(super) fn get(&self, org: Option<&str>, path: &str) -> Result<Option<(u16, Value)>> {
        let Some((installation, token)) = self.token(org)? else { return Ok(None) };
        let (status, body) = self.api.get(&token, path)?;
        if status == 401 {
            installations().tokens.remove(&format!("{} {installation}", self.app()));
        }
        Ok(Some((status, body)))
    }

    /// The account with this user id as GitHub names it now, and when
    /// GitHub created it; `None` when it no longer exists.
    pub(super) fn user(&self, id: u64) -> Result<Option<(Identity, Option<Timestamp>)>> {
        let Some((status, body)) = self.get(None, &format!("/user/{id}"))? else {
            tracing::warn!(target: "bd::serve", github = %self.github.url, client_id = %self.github.client_id, "GitHub sign-ins cannot be refreshed: the GitHub App is not installed anywhere, or only suspended");
            return Err(Error::Remote(
                "this bd server's GitHub App is not installed anywhere, or only where it is suspended, so sign-ins \
                 cannot be refreshed: its admin installs it"
                    .into(),
            ));
        };
        let login = body["login"].as_str().filter(|l| github_name(l));
        match (status, login, body["id"].as_u64()) {
            (200, Some(login), Some(got)) if got == id => {
                let created = body["created_at"].as_str().and_then(|at| Timestamp::parse_rfc3339(at).ok());
                let user = github_identity(&self.github.url, login, id);
                Ok(Some((user, created)))
            }
            (404, _, _) => Ok(None),
            _ => Err(self.failed(&format!("read GitHub user {id}"), status, &body)),
        }
    }

    pub(super) fn failed(&self, doing: &str, status: u16, body: &Value) -> Error {
        let detail = message(body);
        tracing::warn!(target: "bd::serve", github = %self.github.url, client_id = %self.github.client_id, status, %detail, "the GitHub App could not {doing}");
        Error::Remote(format!("this bd server's GitHub App could not {doing} (HTTP {status}{detail}); try again later"))
    }
}

/// Memberships asked of GitHub with the App's installation tokens, each at
/// most once. An organization without the App, or one it may not read the
/// members of, does not tell.
pub(super) struct Installed<'a> {
    pub(super) app: &'a AppApi<'a>,
    pub(super) login: &'a str,
    pub(super) seen: HashMap<String, Member>,
}

impl Installed<'_> {
    pub(super) fn ask(&mut self, org: &str, key: String, path: String) -> Result<Member> {
        if let Some(m) = self.seen.get(&key) {
            return Ok(m.clone());
        }
        let member = match self.app.get(Some(org), &path)? {
            None => {
                tracing::warn!(target: "bd::serve", %org, "GitHub App not installed on an organization the rules name: its members' sign-ins are not refreshed");
                Member::Unknown(format!("the GitHub App is not installed on {org}"))
            }
            Some((200, body)) if body["state"] == "active" => Member::Yes,
            Some((200 | 404, _)) => Member::No,
            Some((status @ (401 | 403), body)) => {
                let detail = message(&body);
                tracing::warn!(target: "bd::serve", %org, status, %detail, "the GitHub App may not read the members of an organization the rules name");
                Member::Unknown(format!("GitHub answered {status}{detail}"))
            }
            Some((status, body)) => {
                return Err(self.app.failed(&format!("check a membership of {key}"), status, &body));
            }
        };
        self.seen.insert(key, member.clone());
        Ok(member)
    }
}

impl Memberships for Installed<'_> {
    fn org(&mut self, org: &str) -> Result<Member> {
        self.ask(org, org.to_ascii_lowercase(), format!("/orgs/{org}/memberships/{}", self.login))
    }

    fn team(&mut self, org: &str, team: &str) -> Result<Member> {
        let path = format!("/orgs/{org}/teams/{team}/memberships/{}", self.login);
        self.ask(org, format!("{org}/{team}").to_ascii_lowercase(), path)
    }
}

/// GitHub's page where a person signs in for the web flow, coming back to
/// `callback` with a code and `state`; the code's token is given only with
/// the PKCE verifier whose S256 challenge is `challenge`.
pub fn web_sign_in_url(github: &Github, callback: &str, state: &str, challenge: &str) -> String {
    let mut query = vec![
        ("client_id", github.client_id.as_str()),
        ("redirect_uri", callback),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    if github.reads_orgs() {
        query.push(("scope", "read:org"));
    }
    format!("{}/login/oauth/authorize?{}", github.url, crate::oauth_server::form::encode(&query))
}

/// Finish a web sign-in: get the token GitHub gives for `code` (which came
/// back to `callback`; `verifier` is its PKCE verifier), and see what the
/// rules let its account do in `workspace` ([`admit`]). The GitHub token
/// serves for this only: it is never stored, logged or sent on.
/// `signed_in_as` gets the account's login once GitHub named it.
#[allow(clippy::too_many_arguments)]
pub fn web_sign_in(
    root: &Path,
    sign_in: &SignIn,
    code: &str,
    callback: &str,
    verifier: &str,
    workspace: &str,
    client: &str,
    signed_in_as: &mut Option<String>,
) -> Result<Admitted> {
    let github = github_of(sign_in)?;
    let Some(secret) = &github.client_secret else {
        return Err(Error::Remote("this bd server has no GitHub client secret for web sign-in".into()));
    };
    let api = Api::new(github);
    let form = [
        ("client_id", github.client_id.as_str()),
        ("client_secret", secret.0.as_str()),
        ("code", code),
        ("redirect_uri", callback),
        ("code_verifier", verifier),
    ];
    let (status, body) = api.form("/login/oauth/access_token", &form)?;
    match body["error"].as_str() {
        Some("bad_verification_code") => {
            return Err(Error::invalid("GitHub no longer knows this sign-in (it took too long): start again"));
        }
        Some(_) => return Err(refused(github, "finish a sign-in", status, &body)),
        None => {}
    }
    let Some(access) = body["access_token"].as_str().filter(|t| !t.is_empty()) else {
        return Err(refused(github, "finish a sign-in", status, &body));
    };
    admit(root, sign_in, &api, access, workspace, Some(client), signed_in_as)
}

/// The identity of GitHub account `id`, now `login`, at the GitHub at `url`.
fn github_identity(url: &str, login: &str, id: u64) -> Identity {
    Identity {
        provider: "github".into(),
        issuer: url.to_ascii_lowercase(),
        subject: id.to_string(),
        login: login.to_string(),
    }
}

/// The GitHub user id of a GitHub sign-in's identity.
pub(super) fn github_id(user: &Identity) -> Option<u64> {
    (user.provider == "github").then(|| user.subject.parse().ok()).flatten()
}

/// The account a GitHub token belongs to, at the GitHub `api` talks to,
/// and when GitHub created it (if it says).
pub(super) fn account(api: &Api, token: &str) -> Result<(Identity, Option<Timestamp>)> {
    let (status, body) = api.get(token, "/user")?;
    let login = body["login"].as_str().filter(|l| github_name(l));
    match (status, login, body["id"].as_u64()) {
        (200, Some(login), Some(id)) => {
            let created = body["created_at"].as_str().and_then(|at| Timestamp::parse_rfc3339(at).ok());
            Ok((github_identity(&api.url, login, id), created))
        }
        _ => Err(Error::Remote(format!("GitHub answered {status}{} for the account that signed in", message(&body)))),
    }
}

/// Memberships asked of GitHub with the token of the account signing in,
/// each at most once.
pub(super) struct Asked<'a> {
    pub(super) api: &'a Api,
    pub(super) token: &'a str,
    pub(super) login: &'a str,
    pub(super) seen: HashMap<String, Member>,
}

impl Asked<'_> {
    pub(super) fn ask(&mut self, key: String, path: String) -> Result<Member> {
        if let Some(m) = self.seen.get(&key) {
            return Ok(m.clone());
        }
        let (status, body) = self.api.get(self.token, &path)?;
        let member = match status {
            // A pending invitation is no membership yet.
            200 if body["state"] == "active" => Member::Yes,
            200 | 404 => Member::No,
            // An organization may keep OAuth apps out until an owner approves them; a GitHub App must be installed there.
            401 | 403 => Member::Unknown(format!("GitHub answered {status}{}", message(&body))),
            _ => {
                return Err(Error::Remote(format!(
                    "GitHub answered {status}{} to a membership check of {key}",
                    message(&body)
                )));
            }
        };
        self.seen.insert(key, member.clone());
        Ok(member)
    }
}

impl Memberships for Asked<'_> {
    fn org(&mut self, org: &str) -> Result<Member> {
        self.ask(org.to_ascii_lowercase(), format!("/user/memberships/orgs/{org}"))
    }

    fn team(&mut self, org: &str, team: &str) -> Result<Member> {
        let path = format!("/orgs/{org}/teams/{team}/memberships/{}", self.login);
        self.ask(format!("{org}/{team}").to_ascii_lowercase(), path)
    }
}

// ------------------------------------------------------------ client
