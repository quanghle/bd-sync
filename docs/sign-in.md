# Signing in

Instead of creating every person's access token, a `bd serve` admin can
let people get their own by signing in with an OpenID Connect provider.
`<root>/auth.toml` names the providers and decides who gets in, and with
what access.

People sign in two ways:

- **From the command line**: `bd remote login --provider <name>` shows a
  one-time code to enter at the provider (the OAuth device flow, RFC 8628),
  then saves the token the server issues.
- **In a browser, through an MCP client**: when `[oauth]` turns on
  `bd serve`'s authorization server, MCP clients that sign people in send
  them to a page that offers the providers ([MCP: signing in with
  OAuth](mcp.md#signing-in-with-oauth)).

Either way, bd verifies who signed in itself, binds the account to an
actor for good, and issues a token only if a rule or the admin's
[authorizer](#deciding-with-an-authorizer) lets the account into the
workspace. An account let in by neither gets nothing.

## A first configuration

Register bd as a client ("web application") at the provider:

- redirect URI `<public-url>/oauth/<name>/callback`, for browser sign-in;
- the device authorization grant, for `bd remote login`.

Then write `<root>/auth.toml`:

```toml
[sign_in]
token_ttl = "1h"                        # access tokens expire (default 1h)
refresh_limit = "30d"                   # refreshed for at most this long after signing in (default 30d)
refresh_idle = "7d"                     # and not after this long unused (default 7d)

[oidc.corp]                             # the provider's name in bd: actors are corp:<login>
issuer = "https://id.example.com"       # its discovery document: <issuer>/.well-known/openid-configuration
client_id = "bd-server"
client_secret_file = "corp-secret"      # relative to the root, mode 0600; leave out for a public client
label = "Example Corp"                  # shown on the sign-in page

# Rules, in order: the first that lets an account into the workspace decides its token.
[[oidc.corp.allow]]
subjects = ["248289761001"]             # accounts by their `sub`
role = "admin"
kind = "human"

[[oidc.corp.allow]]
email_domains = ["example.com"]         # a verified email at these domains
workspaces = ["proj"]

[[oidc.corp.allow]]
groups = ["bd-readers"]                 # a value of the ID token's groups claim
role = "read"
```

```bash
bd serve check --root /srv/bd --public-url https://bd.example.com   # validate, print what to register
bd serve --root /srv/bd --public-url https://bd.example.com ...
bd remote login --provider corp                                      # on a client
```

`bd serve check` reads `auth.toml` and the files it names as the server
would, without starting one, and exits 2 on a mistake. With `[oauth]` and
`--public-url`, it also prints each provider's callback URL, account
notification endpoints and the MCP endpoints to give clients.

`bd serve` refuses to start with a mistake in `auth.toml`: an unknown
field, a rule that names nobody, an `http` issuer that is not on this
machine, a secret file it cannot read, two providers with the same issuer,
or `[sign_in]`, `[authorizer]` or `[oauth]` without any provider. After it
starts, it reads the file again when it or a file it names changes (and at
least every 30 seconds), so changes need no restart. A mistake made while
it runs fails sign-ins and refreshes, with the reason in the server log.

## Providers

`[oidc.<name>]`, where `<name>` is 1–32 lowercase letters, digits and
dashes, not starting with a dash:

| field | default | meaning |
|---|---|---|
| `issuer` | required | https URL without query or fragment (http only on this machine); its discovery document is `<issuer>/.well-known/openid-configuration` |
| `client_id` | required | bd's client ID at the provider |
| `client_secret_file` | none (public client) | file holding the client secret, relative to the root |
| `[oidc.<name>.signed_secret]` | | instead of `client_secret_file`, for providers whose client secret is a signed JWT (below) |
| `label` | the name | shown on the sign-in page; plain text, at most 40 characters |
| `scopes` | `["email", "profile"]` | asked for besides `openid` |
| `groups_claim` | `"groups"` | the ID token claim listing an account's groups |
| `response_mode` | `"query"` | `"form_post"` for providers that post their answer to the callback |
| `account_events` | none | accept the provider's account notifications naming these app IDs (below) |
| `deny` | none | subjects (`sub`) that may never sign in |
| `[[oidc.<name>.allow]]` | | rules ([Rules](#rules)) |

A provider without a device flow serves browser sign-in only;
`bd remote login --provider` says so.

**ID tokens** are verified strictly: signed with RS256 or ES256 (never
`none` or a shared secret) by a key from the provider's published key set
(fetched over https and cached for an hour), from the configured issuer,
for bd alone (`aud` exactly the client ID, and `azp`, when present, too),
not expired (120 seconds of clock skew allowed), and, in a browser, with
the nonce of that sign-in. A browser sign-in whose answer names another
issuer (RFC 9207 `iss`) is refused before its code is used. An email counts
only if the provider marked it verified. A provider whose discovery
document or keys cannot be fetched is not asked again for 30 seconds.

**Posted answers.** Some providers return the authorization answer as a
form the browser posts to the callback (`response_mode = "form_post"`).
That post carries none of the sign-in's `SameSite=Lax` cookies, so bd
relays only its `code`, `state`, `error` and `iss` to the callback as a
GET, where the cookie and state are checked as for any other provider.
Posts are refused for providers not configured with `form_post`.

**Signed client secrets.** Some providers take as client secret a JWT the
client signs with a key of its own, instead of a fixed secret. bd signs a
fresh one (ES256, valid for 5 minutes) for each request:

```toml
[oidc.example.signed_secret]
key_file = "signing-key.p8"             # a P-256 private key (PKCS#8), relative to the root
key_id = "ABC123DEFG"                   # the key's ID: the JWT's `kid`
team_id = "DEF123GHIJ"                  # the developer account's ID: the JWT's `iss`
```

The JWT's `sub` is the client ID and its `aud` the issuer.

**Account notifications.** A provider that sends server-to-server account
notifications can post them to `<public-url>/oauth/<name>/events`, as
`{"payload": "<JWT>"}`: a JWT signed by a key of the provider's set, whose
`events` claim (an object, or a JSON string of one) holds `type`, `sub`
and `event_time`. With `account_events` listing the IDs the provider names
the app by, bd checks each notification (signature, issuer, an audience in
the list, issued within the last week) and acts on it:

- `consent-revoked`: the account's sign-ins made before `event_time` end.
- `account-deleted` (or `account-delete`): bd forgets the account and its
  tokens, as `bd serve token revoke --account … --forget` does.

Other notification types are acknowledged and ignored.

## Rules

`[[<name>.allow]]` rules are tried in order; the first that lets an
account into the workspace being signed in to decides its token. A rule
names accounts by what the provider proves:

| field | matches |
|---|---|
| `subjects` | the account's `sub`, which never changes |
| `emails` | a verified email address |
| `email_domains` | a verified email at one of these domains |
| `groups` | a value of the ID token's `groups_claim` |
| `anyone = true` | every account (the last rule only; see below) |

and grants:

| field | default | meaning |
|---|---|---|
| `role` | `write` (`read` for `anyone`) | `read`, `write` or `admin` ([Roles](remote.md#roles-and-what-tokens-may-do)) |
| `kind` | `agent` | `agent` or `human`: only human tokens open human gates |
| `workspaces` | all | the workspaces the token covers |
| `max_claims` | none | the most open issues the token's actors may hold at once |

- A rule that lets an account in, but not into this workspace, leaves it
  to the rules after it. The token a later rule then issues covers this
  workspace only. A workspace the server does not have is refused.
- **`anyone = true`** names nobody else and must be the last rule. Its
  tokens read by default, may write at most (never `admin`), and are
  always `agent` tokens. A rule before it may not give a lower role, or
  (when it writes) fewer `max_claims`, in a workspace they share, so
  members never get less than strangers.
- **`max_claims`** limits the open issues, claimed or assigned, that the
  token's actor and its sub-actors hold. A command that would exceed it
  (`claim`, an assignment, an import, a batch, a playbook run) fails with
  exit 7 and changes nothing. Issues others assign to them count, but never
  stop work on them; closing or releasing in the same command makes room.
  It guards against greed, not malice: a write token can still change
  issues in other ways.
- **`deny`** lists subjects that may never sign in, whatever the rules or
  the authorizer say. A denied account's sign-ins end at their next
  refresh; revoke its tokens to end them at once.

## Accounts and actors

An account is its provider's issuer plus its `sub`. At its first sign-in
it is bound to an actor, `<provider name>:<login>`, for good: the binding
survives renames, expiry and revocation.

- **The login** is the ID token's `preferred_username`, unless that is an
  email, longer than 100 characters, not plain text, or shaped like a
  pseudonym. Then it is a pseudonym: `u-` and 12 hex digits of a hash of
  the issuer and `sub` (`corp:u-3f9a2c1e7b04`), the same for the same
  account every time. A `/` in a login becomes `-`. No email ever becomes
  an actor, since actors stay in workspace histories for good.
- **A token** acts as the account's actor or its sub-actors
  `<actor>/<name>`. Each sign-in gets its own token, named after the actor
  (characters other than letters, digits, `.`, `_` and `-` as `-`, cut to
  55) plus 8 random hex digits, so one account may sign in on several
  machines. Tokens issued to OAuth clients are named
  `oauth-<client>-<actor>-<random>` ([MCP](mcp.md#the-clients-tokens)).
- **One actor, one principal.** A sign-in is refused while its actor
  belongs to another account (one that had the login before) or to a live
  token an admin created. `bd serve token create` refuses an account's
  actor the same way, and refuses any actor whose first segment holds a
  `:`, so admin-created and signed-in actors never collide.
- **Several providers, one person.** Signing in with two providers gives
  two actors: bd cannot tell they are the same person. An admin who knows
  links them:

  ```bash
  bd serve token link other:u-3f9a2c1e7b04 --to corp:alice --root /srv/bd
  ```

  The linked account's tokens are revoked, and its next sign-in acts as
  `corp:alice`. Linked accounts are one principal: neither is refused for
  the other's tokens, and `revoke --account` names them all. Only an
  existing account's actor can be linked to.
- **Names.** `bd serve token name corp:u-3f9a2c1e7b04 "Alice (contractor)"
  --root /srv/bd` gives an account a name of the admin's (at most 64
  characters), shown by `bd serve token accounts`; `--clear` removes it.
  bd takes no name from a provider.
- **Releasing.** `bd serve token revoke --account <actor or login>
  --forget` deletes the account and its tokens and erases them from
  `server.db`'s files ([What bd keeps about
  people](security.md#what-bd-keeps-about-people)). The next account to
  sign in with that login binds the actor again.

```bash
bd serve token accounts --root /srv/bd                    # bindings: provider, subject, actor, login, dates
bd serve token list --root /srv/bd                        # tokens, with their account, expiry and refresh limit
bd serve token revoke --account alice --root /srv/bd      # every token an account got by signing in
bd serve token events --actor corp:alice --kind signed_in,revoked -n 20 --root /srv/bd
```

A change to `auth.toml` applies to the next sign-ins and refreshes: issued
tokens keep their access until they expire, at most `token_ttl`. Revoke to
cut an account off at once.

## Refreshing

Each sign-in also gets a refresh token, saved with the access token on the
client and sent only to `POST /v2/auth/refresh` (OAuth clients use the
token endpoint instead). The client renews the access token on its own
before a command once a fifth of its lifetime is left (10 minutes at
most), or when the server finds it expired; a long-running command (`bd
agents watch`, `bd events --follow`) renews between requests.

Each refresh:

- **decides again**, by the authorizer or the rules, after `deny`. A
  refresh has no fresh ID token, and bd keeps no email or claim, so rules
  by `subjects` or `anyone` are applied again, while a rule by `emails`,
  `email_domains` or `groups` keeps the sign-in only while it is the rule
  that let the account in, unchanged. Removing or changing that rule ends
  those sign-ins at their next refresh. Someone a provider no longer lists
  in a group keeps access until they sign in again (at the latest
  `refresh_limit`); use an authorizer to decide on live data instead. A
  refresh never widens a token's workspaces. Role, kind and `max_claims`
  follow what the deciding rule grants now.
- **rotates both tokens.** The old ones stop working at once, and a
  refresh token works once: one used again, as by someone who copied it,
  revokes the sign-in for everyone holding it. A retry of the same refresh
  is not a reuse: the client saves each refresh's request id before
  sending it, and within 5 minutes the server answers a retry with the same
  new tokens. bd processes of one user on one machine renew one at a time
  (they share `credentials.lock`).
- **is refused**, and the sign-in revoked, when the rules no longer let
  the account in or it is denied. The client keeps its access token until
  it expires, says why on stderr, and stops trying; `bd remote login
  --provider <name>` signs in again.
- **works until** `refresh_limit` after the sign-in, and while no more
  than `refresh_idle` has passed since the last refresh. Each of
  `token_ttl`, `refresh_idle` and `refresh_limit` is 5 minutes to 366 days,
  and each is at most the next.
- An account keeps at most 20 live sign-ins at each client (and 20 from
  `bd remote login`): signing in again revokes the oldest.
- When the server or the provider cannot be reached, nothing changes (exit
  8); the client tries again a minute later while its access token works.

## Deciding with an authorizer

Instead of rules, the admin's own code can decide who may use which
workspace: a directory, a group service, a list bd knows nothing about.
bd still verifies who signed in and binds the actor; the authorizer only
decides access. An `[authorizer]` replaces every provider's rules (a file
with both is refused).

```toml
[authorizer]
command = ["bin/authorize", "--team", "eng"]  # run as is, no shell; relative to the root if it has a /
# url = "https://authz.internal/bd"           # or POST to this instead (http only to this machine)
# token_file = "authz-token"                  # the URL's bearer token, relative to the root
# timeout = "5s"                              # 1s to 60s
# env = ["DIRECTORY_CREDENTIALS"]             # variables passed to the command besides the basics
# refresh_grace = "4h"                        # see below
# max_role = "write"                          # the most it may grant (default write)
# human = false                               # whether it may grant kind human (default no)
# max_claims = 10                             # the most claims its tokens may hold
# workspaces = ["proj"]                       # the only workspaces it is asked about (default all)
```

At each sign-in and refresh, bd sends one JSON object, on the command's
stdin or as the POST body:

```json
{ "version": 1, "event": "sign_in", "workspace": "proj",
  "provider": "corp", "issuer": "https://id.example.com",
  "subject": "248289761001", "login": "alice", "account_created": null,
  "email": "alice@example.com", "claims": { "sub": "248289761001", "groups": ["eng"] },
  "client": "https://mcp-client.example/client.json", "current": null }
```

- `subject` never changes; `login` may, and may once have been another
  account's, so match on `issuer` and `subject` where you can.
- `email` (if verified) and `claims` (all of the ID token's claims) are
  sent at sign-in only, never at refreshes.
- `client` is the MCP client signing the account in (null for
  `bd remote login`).
- At a refresh, `event` is `refresh` and `current` holds the sign-in's
  access: `role`, `kind`, `max_claims`, `signed_in_at`. Timestamps are RFC
  3339 with milliseconds.

It answers with one JSON object, on stdout or as a 200 response:

```json
{ "allow": true, "role": "write", "kind": "agent", "max_claims": 5,
  "via": "member of eng", "reason": "in the eng group" }
```

`role` defaults to `read` and `kind` to `agent`; the token covers the
workspace asked about. `via` (plain text, at most 100 characters) is shown
on the consent page as what let the account in. `reason`, also for a
refusal (`{"allow": false, "reason": "..."}`), goes to the server log only;
the person is told only that the account may not use the workspace.

- **Fail closed.** No answer within `timeout`, a non-zero exit, a status
  other than 200, a redirect, or an answer that is not one JSON object of
  these fields (at most 64 KiB, `max_claims` at least 1) lets no one in;
  the sign-in fails and the log says why. At most 8 are asked at once.
- **Caps.** It can grant no more than `auth.toml` allows: a role above
  `max_role`, kind `human` without `human = true`, or more than
  `max_claims` refuses the account. Workspaces outside `workspaces` are
  refused without asking. A broken or compromised authorizer therefore
  cannot hand out admin tokens or open human gates unless the admin
  allowed it.
- **Identity stays with bd.** It cannot choose or change the actor, `deny`
  applies before it is asked, and it never sees a provider's tokens.
- **The command** runs in the root with a cleared environment: `PATH`,
  `HOME`, `LANG`, the Windows basics (`SystemRoot`, `windir`, `PATHEXT`,
  `TEMP`, `TMP`, `USERPROFILE`) when set, and the variables `env` names. On
  Unix it runs in its own process group, killed once it answers or times
  out, so nothing it starts outlives it. It runs as the user `bd serve`
  runs as. Treat the request as data: it carries names chosen by whoever
  signs in.
- **The URL** gets `Authorization: Bearer <token_file>`, with no proxy and
  no redirects followed.
- **Refreshes** ask again, which is how access ended elsewhere takes
  effect: a refusal revokes the sign-in. When it cannot answer, only that
  refresh fails and the client tries later. With `refresh_grace` (between
  `token_ttl` and `refresh_idle`), a refresh within that long of the
  sign-in's last decision keeps the access it had (capped as above), so a
  short outage does not end sign-ins.
- Its `reason` (cut to 500 characters) and stderr (2 KiB) are logged with
  anything shaped like an email replaced by `<email>`.

## The device flow

`bd remote login --provider <name>` asks the server for a device code
(`POST /v2/auth/<name>/device`), shows the code and the provider's page,
and polls `POST /v2/auth/<name>/token` until it is entered (Ctrl-C
cancels). The server runs the flow with the provider, so the client needs
to reach only the bd server, and the provider's tokens never leave the
server and are never stored. The answer that issued a bd token is kept for
5 minutes, so a client whose answer was lost gets it again by asking again.

- **Phishing.** Whoever enters a code gets the token of the sign-in that
  showed it: enter only codes your own `bd remote login` just showed you,
  never one someone sent you (RFC 8628 §5.4).
- **Tokens saved by `bd remote login` serve every process of that user on
  that machine**, agents included: `kind = "human"` lets those agents
  resolve human gates too.
- `POST /v2/auth/revoke`, sent with a token from signing in, revokes it.
  `bd remote logout` and a replacing sign-in use it.
- The device flow tells whether a workspace exists before sending anyone
  to the provider; the browser flow tells only after the rules let the
  account in.
- At most 8 sign-in requests run at once (others get 503, which clients
  retry); refreshes have 8 slots of their own.
