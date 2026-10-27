# Signing in

Instead of creating every person's access token, a `bd serve` admin can
let people get their own by signing in with an OpenID Connect provider.
`<root>/auth.toml` names the providers and decides who gets in, and with
what access.

People sign in two ways:

- **From the command line**: `bd remote login --provider <name>` shows a
  one-time code to enter at the provider (the OAuth device flow, RFC 8628),
  then saves the token the server issues. With `--human`, a person signing
  in for a token of kind `human` keeps it in the OS keychain instead, and
  renews it there; a token of another kind is revoked and not saved
  ([Person's token in the keychain](remote.md#persons-token-in-the-keychain)).
- **In a browser, through an MCP client**: when `[oauth]` turns on
  `bd serve`'s authorization server, MCP clients that sign people in send
  them to a page that offers the providers ([MCP: signing in with
  OAuth](mcp.md#signing-in-with-oauth)).

Either way, bd verifies who signed in itself, binds the account to an
actor for good, and issues a token only if a rule or the admin's
[authorizer](#deciding-with-an-authorizer) lets the account into the
workspace. An account let in by neither gets nothing.

With `[oauth]`, people can also sign in in a browser to [approve a human
gate](#approving-human-gates-in-the-browser), which issues no token.

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
would, without starting one, and exits 2 on a mistake. With
[`[secrets]`](#secrets-from-a-command) it also runs that command, as the
server would. On Unix it runs the command only when run as the owner of
the root directory, who can already change everything under it. Run as
anyone else, root included, it runs no command, and when `auth.toml` has
`[secrets]` it exits 2 before reading any file `auth.toml` names, naming
the owner to run it as (for example `sudo -u <owner> bd serve check --root
...`). On Windows it makes no such check.
With `[oauth]` and `--public-url`, it also prints each provider's callback URL, account
notification endpoints and the MCP endpoints to give clients.

`bd serve` refuses to start with a mistake in `auth.toml`: an unknown
field, a rule that names nobody, an `http` issuer that is not on this
machine, a secret file it cannot read, two providers with the same issuer,
or `[sign_in]`, `[authorizer]`, `[oauth]` or `[secrets]` without any
provider. (It never waits for a [secrets command](#secrets-from-a-command):
sign-in needing its secrets is unavailable until it answers.) After it
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
| `client_secret_file` | none (public client) | file holding the client secret, relative to the root, or `{ secret = "<name>" }` ([below](#secrets-from-a-command)) |
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
  workspace only. A workspace the server does not have is refused once
  the account is let in, before any token is issued.
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
- **Not identity proof.** The login is what the provider reports at the
  first sign-in, and the actor goes to whichever account signs in first
  with that login. The login and the actor prove neither which person nor
  which account is meant: an account of an OIDC provider is named on a gate's approvers by its issuer
  and subject, never by its actor ([Approvers and OIDC
  accounts](#approvers-and-oidc-accounts)).
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
  Unix it runs in its own process group, killed once it answers and exits
  (it has a second to exit after answering) or times out, and when the
  server stops, so nothing it starts in its group outlives it (on Windows
  the command alone is killed at its timeout, and a stopping server leaves
  it to finish). It runs as the user `bd serve` runs as. In a container,
  run `bd serve` under an init (`docker run --init`, or `tini`): a process
  the command starts in a session of its own is reaped by none other once
  it ends. Treat the request as data: it carries names chosen by whoever
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

## Secrets from a command

Instead of files, the secrets `auth.toml` names (client secrets, the keys
that sign them, the authorizer's `token_file`) can come from the admin's
own command: one that asks a vault or a cloud's secret manager, which bd
knows nothing of. A field takes `{ secret = "<name>" }` instead of a path,
and `[secrets]` names the command:

```toml
[secrets]
command = ["bin/bd-secrets"]            # run as is, no shell; relative to the root if it has a /
# timeout = "10s"                       # 1s to 60s
# env = ["VAULT_CREDENTIALS"]           # variables passed to the command besides the basics
# ttl = "10m"                           # how long an answer is good for, unless it says (1m to 24h)
# max_stale = "1h"                      # how long past that the last answer is used while it fails (at most 7d)

[oidc.corp]
issuer = "https://id.example.com"
client_id = "bd-server"
client_secret_file = { secret = "corp-client-secret" }   # or, under [oidc.corp.signed_secret], key_file = { secret = ... }

[authorizer]
url = "https://authz.internal/bd"
token_file = { secret = "authz-token" }
```

A file with names and no `[secrets]`, or `[secrets]` and no names, is
refused. A name is 1 to 256 printable characters with no spaces, and no
run of more than 32 letters and digits mixing both: one shaped like a
long token or a hex client secret is refused, never quoted, in case a
value was pasted in its place. That is a guard, not a proof: a value
with punctuation in it passes as a name. The server's start line and
`bd serve check`'s summary count the names; a failure names the secret it
is about. bd asks for every name at once, with one JSON object on the
command's stdin:

```json
{ "version": 1, "secrets": ["authz-token", "corp-client-secret"] }
```

It answers with one JSON object on stdout, exactly the names asked, each a
string (a key's PEM text, newlines and all), and optionally how long they
are good for:

```json
{ "secrets": { "authz-token": "...", "corp-client-secret": "..." }, "ttl": "15m" }
```

- **Only what needs a secret waits for it.** `auth.toml`'s settings, its
  secret files and CA certificates load without the command, and a
  mistake in them is one, as without `[secrets]`. Each field naming a
  secret is filled on its own from the command's kept answer; one it
  lacks stays empty (the command is asked for all the names at once: while
  it fails for one, say a name the vault lacks, the others serve on until
  `max_stale` runs out), and only the steps that use it (a sign-in or refresh
  that needs that client secret, the App's key or the authorizer's token)
  fail, the log saying why: a sign-in answers 503, try again, before anyone
  is sent to the provider or a provider's code is spent; a refresh fails
  (502) as when a provider does not answer, and the client refreshes later
  on its own instead of waiting. Metadata,
  revocation, account notifications, admin-issued tokens, workspaces and
  background jobs never wait for it.
- **When it runs.** A keeper per server runs it, in the background only:
  once three quarters of an answer's `ttl` (held to 1m–24h) passed, on its
  own timer, whether requests come or not; at once when `auth.toml` names
  fewer or other secrets or another command, or moves a secret to a field
  that refuses its value; and 30 seconds after the start of an attempt
  that failed. It reads `auth.toml` again before each attempt and when
  the server loads it, so a fixed command or a removed `[secrets]` is
  never asked as it was, and an answer to a command or names `auth.toml`
  no longer asks for is not kept (one that comes while it is invalid or
  being saved is, serving the command that gave it only). While `auth.toml` is invalid it asks nothing. A file
  briefly missing or empty while it is saved forgets nothing;
  `[secrets]` gone for 10 seconds forgets the answer. A new value takes
  effect without a restart.
- **At start**, the server never waits for it: it serves at once, and
  logs the first attempt's outcome when it comes. `bd serve check` waits
  for it, and exits 2 if it fails (run it as the root's owner, above).
- **Fail closed, after a grace.** While it fails, the last answer is used
  until `max_stale` past its `ttl`, with a warning in the log at each
  attempt; then the steps needing its secrets answer 503 until it answers.
  An answer serves the command that gave it, name by name: changing
  `max_stale`, `ttl`, `timeout` or `env` keeps it serving (`max_stale` as
  set now decides how long). It lives in memory only: a restart asks
  again.
- **Strict answers.** A non-zero exit, no answer within `timeout`, an
  answer that is not one JSON object of `secrets` and `ttl` (at most
  256 KiB), a name missing or not asked for, or an empty value is a
  failure. So is an answer whose values the fields refuse (a key must be a
  key, a client secret one line): the last good answer keeps serving, and
  the command is asked again 30 seconds later. Exit non-zero when the
  vault fails: an error printed as a value would be taken for one.
- **Values stay out of sight.** They are kept in memory only, never
  written to a file, and bd itself never logs or shows them. Messages
  name the field and the secret's name, never a value, nor what the
  answer held; `env` names variables
  only, and neither is a `command` written as a string instead of a list.
  The command's stderr is read until it answers or times out (the first
  64 KiB kept, whole lines only; past 1 MiB it is closed, stopping a
  command that floods it), the values it last gave left out, then cut to
  2 KiB for the log. Only those: on its first run, in every `bd serve
  check`, and after a rotation, what it prints of a value it fetched then
  reaches the log as is. So print none on stderr (no `set -x`).
  Requests are told only that sign-in is unavailable, never why.
- **The command** runs as the authorizer's does: in the root, as the user
  `bd serve` runs as, with a cleared environment (`PATH`, `HOME`, `LANG`,
  the Windows basics, and the variables `env` names), in its own process
  group on Unix, killed once it answers and exits, times out, or the
  server stops; on Unix a process it starts that leaves the group holds
  nothing of the server's past the timeout (on Windows, see the
  authorizer's command above).

A command for a vault's command-line client can be a few lines of shell,
for example with `jq`. It fails as a whole when any read fails, so that
the vault's error reaches the log and never stands in for a value. Values
pass through the environment of the one `jq` that needs them, never its
command line, which other users of the machine can read:

```sh
#!/bin/sh
# `vault-cli read <name>` stands for your vault's client: exits non-zero on failure.
set -euf                                  # -f: names are never globbed
answer='{}'
for name in $(jq -r '.secrets[]'); do
  value=$(vault-cli read "$name")
  answer=$(printf '%s' "$answer" | VALUE="$value" jq --arg n "$name" '. + {($n): env.VALUE}')
done
printf '%s' "$answer" | jq '{secrets: ., ttl: "15m"}'
```

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
- Whether a workspace exists is told only to an account the rules (or the
  authorizer) let into it, in the device flow and the browser flow alike:
  before that, a missing workspace is refused like one that exists. So a
  mistyped workspace is reported after signing in at the provider, and an
  account let into all workspaces (`workspaces` left out, or an authorizer
  allowing any name) can learn which names exist. An authorizer may be
  asked about a workspace that does not exist: deny names it does not know.
- At most 8 sign-in requests run at once (others get 503, which clients
  retry); refreshes have 8 slots of their own.

## Approving human gates in the browser

With `[oauth]` and `--public-url`, a person can approve a [human
gate](playbooks.md#gates) in a browser instead of running `bd gate
resolve` with a human token. The gate's page is

```text
<public-url>/w/<workspace>/gates/<gate id>
https://bd.example.com/w/proj/gates/t-12.gate-publish
```

with the gate's exact id (no prefix matching). Opening it starts the
authorization server's browser sign-in: the provider chooser at
`<public-url>/oauth/choose` when there are several browser providers
(OIDC providers, and GitHub with its client secret), or straight to the
provider when there is one, and back at that provider's callback,
`<public-url>/oauth/<name>/callback`. There is no new URL to register,
and `bd serve check` prints none. Without `--public-url`, without
`[oauth]`, or with an `auth.toml` edited since start into one the server
would refuse (`[oauth]` with no browser provider, say), the path answers
404. bd composes the link only where the server offers this page, from
`--public-url`, the workspace and the gate's id, never from stored text
(a gate title cannot supply one): `bd prime` (with a sentence telling
agents to hand the link over, or to ask the person to run `bd gate
review`), a refusal at a human gate (`approve in a browser: <url>` after
the `error:` line, `approval_url` in its JSON), `bd playbook status`, `bd
gate show` and `bd gate list --json`, for the commands `bd serve` runs for
clients and MCP clients only, and only for open human gates that are armed
or escalated ([Approval links](playbooks.md#gates)). Without `--public-url`
or a valid `[oauth]`, none shows one; otherwise build it as above.

**Who may approve.** After the provider says who signed in, the account
is judged for the gate's workspace as a sign-in is: `deny` first, then the
[authorizer](#deciding-with-an-authorizer) (asked with `"event":
"sign_in"` and `"client": null`, as for `bd remote login`) or the
[rules](#rules). Only a grant of kind `human` may approve, whatever its
role; an account let in as an agent, a denied account, or one no rule
lets in gets a refusal page that says nothing about the gate. When the
gate names [approvers](playbooks.md#approvers), the account must also
match one of the approvers: an account of an OIDC provider only by the
identity reference of its issuer and subject, a GitHub account by its
actor (`github:alice`) or a sub-actor of that actor ([Approvers and OIDC
accounts](#approvers-and-oidc-accounts)). An authorizer that may not
grant `human` (`human = false`, the
default) lets no one approve.

**No token.** The account is bound to its actor as at any sign-in, and the
binding is recorded in the audit trail as a `signed_in` event without a
token, its detail naming the gate and workspace (`bd serve token events
--kind signed_in`). No access or refresh token is issued: the sign-in is
good for this approval only.

**Nothing is told before that.** Up to the account's admission, a gate
that exists, a missing workspace, a missing issue, an issue that is not a
gate and a gate that is not human get the same answers. Only an account
granted human access to the workspace learns which: it gets a page saying
there is no such workspace or gate, that it is not a gate or not a human
gate, that the gate is already resolved, or that it is not ready (it is
deferred, or the work it holds back still waits for other work).

**The page** shows the workspace, the gate's id and title, the issues it
holds back (id, title and status), the run or parent it belongs to, its
approvers, and the provider and actor the person is signed in as, never an
email. Titles are cut at 200 characters, and control, direction and
invisible characters are shown escaped, so text an agent wrote cannot pass
for the page's own. It has a single Approve button, under the
consent page's protections: a strict Content Security Policy, no framing,
and a form that is not sent until the page has had focus for 600 ms
([Security](security.md#approving-gates-in-the-browser)).

**The approval packet.** Below those facts and above the Approve button,
the page shows what the approval is about, in a section headed `Approval
packet`: the description, acceptance criteria, design and notes (those
not empty) of the gate and of the issues it holds back (at most 8 of
them; the rest are counted in a notice that gives `bd show <gate id>`
for the full list, and Holds back names up to 20), then its run or parent.
For a gate in a playbook run it also shows the run's earlier steps the
gate and its held steps wait for, followed through `blocks`,
`conditional-blocks` and `waits-for` edges within the same run, and the
records of type `decision` (ADRs) directly under the held steps and those
earlier steps. Each record shows its role, full id, title and status, and
its 8 newest comments (a run's comments include the score judge's
evidence). The packet never follows `related`, `discovered-from` or
other links, never shows later steps, and never reads files, URLs or the
repository. It is read, and shown, only for a person who may approve the
gate: admitted with human access, the gate open and ready to approve, and
one of its approvers when it names them; every other answer is the same
as without it. It is bounded: 32 records, 256 dependency rows read, 8
comments per record, 16 KiB per field or comment, 128 KiB of text in
all, and 512 KiB of page. What a limit leaves out is said where it
happens, naming the record and how to read it in full, `bd show <id>` or
`bd comment list <id>`; when the page's limit is reached, each record
not shown in full still appears with its role, id, title, status and
those two commands. The text is Markdown, which agents write, so it is
shown as untrusted, apart from the page's own text: headings (placed
below the page's own), lists, task lists (as disabled checkboxes),
emphasis, tables, quotes and code. Raw HTML is shown as text, images as
their alt text (nothing is fetched), and only links to `http` and `https`
URLs (opening in a new tab, without a referrer) and to `#` places on the
page are links; any other link is shown as text with its destination.
Control, direction and invisible characters are shown escaped. The
packet is read when the page loads and is not a signed record of what is
approved: the approval is checked against the gate as it is when it is
posted, as before.

**The approval** lasts 10 minutes and works once, from the browser that
signed in: it is bound to a cookie of its own,

```text
bd_gate_<suffix>=<value>; Path=<public-url path>/w/<workspace>/gates/<gate id>; Max-Age=600; HttpOnly; SameSite=Strict
```

named `__Secure-bd_gate_<suffix>`, and `Secure`, on an https public URL.
The `POST` to the same path must say it came from the page: an `Origin`
of the server or `Sec-Fetch-Site: same-origin`, and neither saying
otherwise. In one transaction the server then checks the gate again
(still an open human gate, ready to approve, and the person still one who
may open it) and resolves it as the person's actor, as `bd gate resolve`
does: the held work becomes ready, and a run whose last step it was
closes. The gate's `closed` event names the actor, has the reason
`approved in the browser by <actor>`, and carries `"via": "browser"` in
its data.

**Refusals** end on a page of this server, never a redirect elsewhere, and
write nothing to the workspace. Once the provider has admitted an account
with a human grant, though, the account stays bound to its actor and the
sign-in is audited as a tokenless `signed_in` event in `server.db`, even
when the page then refuses or shows a notice:

| case | status |
|---|---|
| sign-in cancelled at the provider | 403 |
| the provider failed, or returned no code | 502, 400 |
| account denied, let in by no rule, or granted kind `agent` | 403 |
| not one of the gate's approvers (an OIDC account matches only its identity reference, never an actor), at sign-in or when posting (approvers changed since) | 403 |
| a sign-in step or an approval expired, or a link this server did not give | 400 |
| an approval posted again | 400 (`already used`) |
| a post from another site, or with neither `Origin` nor `Sec-Fetch-Site` | 403 |
| a post without the approval's cookie (another browser) | 403; the approval stays usable from its own browser |
| no such workspace, issue or gate, not a gate, not a human gate (after admission) | 404 |
| already resolved | 409 |
| not ready: deferred, or blocked by other work, when signing in or when posting | 409 |
| the server or workspace busy | 503 |

Approval sign-ins share the 8 sign-in slots: the provider's callback and
the approval's `POST` each take one. The server logs each approval
(`gate approval`, with its `outcome`) and refusal (`gate approval
refused`) with the provider, subject, login, actor, workspace and gate,
never an email, and counts them in `/metrics`
([`bd_serve_approvals_total`](observability.md#server-metrics)).

### Approvers and OIDC accounts

A gate's approvers name an account of an OIDC provider by an [identity
reference](playbooks.md#oidc-identity-references) to its issuer and
subject, never by its actor, because the actor proves nothing about the
account behind it:

- **First-sign-in squatting.** An actor `<provider>:<login>` is bound to
  the first account that signs in with that login. At a provider where
  accounts choose or change the `preferred_username`, an account
  can take the login `alice` before the intended person ever signs in to
  bd, and bd then binds `corp:alice` to that account for good. Were
  approvers matched by actor, a gate listing `corp:alice` would open for
  that account, with a browser approval, a token issued earlier, a
  refresh, a retry or a sub-actor. An identity reference matches only the
  account with exactly that issuer and subject, so the squatting account
  is refused on every path, and an OIDC account never matches an actor
  approver at all (linked accounts sharing an actor included).
- **Obtaining the issuer and subject.** The pair must come from a source
  that verifies it independently of the login: the provider's own
  administration (the account's record in the identity provider, read by
  a trusted administrator), the account's own authenticated `bd info
  --json` (`token.account.issuer` and `token.account.subject`, with the
  token from that account's `bd remote login --provider <name>`), or, for
  the server's admin, `bd serve token accounts --root <root>` (each
  binding's subject and issuer). A pair, or a reference, received in a
  message or copied from another gate authenticates nothing: a reference
  is opaque and proves nothing about whose account it names.
- **Setting a reference.** `bd gate create` or `bd gate update` with
  `--oidc-approver <issuer> <subject>`, the values exactly as the
  provider states the pair (`--oidc-approver https://login.example.com
  248289761001`); for a playbook, the canonical string that `bd gate show
  --json` then lists in `spec.approvers`.
- **Logins may change.** A new `preferred_username` changes neither the
  account's actor nor its reference, so the account still matches.
- **Existing username-only lists fail closed.** A gate whose approvers
  name an OIDC account by actor (`corp:alice`), written before identity
  references existed, is opened by no OIDC account, through the browser,
  a token or `bd gate review`. bd converts no list, renames no actor and
  migrates nothing: a human admin, or a human token that still matches an
  entry, replaces the list with `bd gate update`.
- **A squatted actor stays squatted.** The identity rule keeps the
  squatting account from approving, but the actor stays bound to that
  account, and sign-ins of the intended account with the same login are
  refused while that binding lasts ([One actor, one
  principal](#accounts-and-actors)). Recovering the actor is a separate
  task for the server's admin ([Accounts and
  actors](#accounts-and-actors), `bd serve token revoke --account <actor>
  --forget`).
- **References are linkable identifiers.** The same account has the same
  reference on every gate and every server, so references tie gates to
  one account: references are not anonymization.
- **No rollback.** A `bd serve` without identity references, or a fleet
  of mixed versions, matches OIDC accounts by actor again and reads a
  reference as an ordinary actor name: such servers cannot safely guard
  sensitive gates.
