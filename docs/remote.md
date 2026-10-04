# Remote server: one workspace, many machines

Several machines (laptops, CI runners, cloud agents) can share one
workspace through `bd serve`. The database stays on the server; clients send
whole commands, and each command runs there as it would locally, normally as
one `Store::write` transaction. Claims stay atomic, fencing tokens and lease
times come from one clock, and the event log stays gapless. The alternatives
cannot keep those guarantees. Putting `bd.db` on a network file system
breaks SQLite's WAL, which needs every process on one host. Replicating and
merging copies (beads' `bd dolt push/pull`) lets two disconnected machines
claim the same issue.

## Server

```bash
# One directory per workspace under a root: <root>/<name>/.bd/bd.db is served at /w/<name>
mkdir -p /srv/bd/proj && bd -C /srv/bd/proj init --prefix proj
# Or move an existing workspace: bd export -o proj.jsonl, then bd -C /srv/bd/proj import proj.jsonl

# Access tokens live in <root>/server.db (hashes only); each secret is printed once
bd serve token create alice-laptop --as alice --root /srv/bd
bd serve token create alice-desk --as alice --kind human --root /srv/bd   # a person's: approves human gates
bd serve token create ci --as ci --workspace proj --root /srv/bd
bd serve token create dashboard --as dash --role read --root /srv/bd
bd serve token create intern --as intern --max-claims 2 --root /srv/bd   # holds at most 2 issues at once
bd serve token list --root /srv/bd
bd serve token revoke ci --root /srv/bd          # takes effect at once, no restart
# Or let people get their own by signing in, with GitHub or any OIDC provider: <root>/auth.toml (below)
# MCP clients that sign people in with OAuth (ChatGPT, Claude apps): docs/mcp.md

bd serve --root /srv/bd --listen 0.0.0.0:7420 --tls-cert cert.pem --tls-key key.pem
```

Without a public CA, a self-signed certificate works if it is not a CA
certificate (rustls refuses a CA certificate as a server's own); clients then
trust it with `BD_CA_CERT=cert.pem`:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=bd.example.com" \
  -addext "subjectAltName=DNS:bd.example.com" -addext "basicConstraints=critical,CA:FALSE"
```

`bd serve` refuses plain HTTP on a non-loopback address, since tokens would
cross the network unencrypted. Either give it a certificate, or keep the
default `--listen 127.0.0.1:7420` behind a TLS-terminating proxy (Caddy,
nginx, a Cloudflare or Tailscale tunnel), which may also serve it under a path
prefix (`https://example.com/bd/w/proj`). `--insecure-http` allows plain HTTP
on an encrypted private network. `GET /healthz` answers `ok` for load
balancers. A request may carry up to `--max-body-mib` (default 64). Requests
in progress share a 256 MiB memory budget (more if one maximum-size request
needs it), and the server answers 503 when it is used up, which clients
retry. Answers stream: past 64 KiB, a command's output goes to the client
as the command writes it, through less than 1 MiB of buffers per request, so
a large `bd export` costs the server no more memory than a claim. `bd events`
reads and sends a long page a thousand events at a time, and lists (`list`,
`ready`, `blocked`, `show` of several issues, `history`, `comments`) write
their JSON element by element, so they hold their results but no copy of them
as JSON. At most 8
reads stream their answers at once (another is answered 503, which clients
retry), so slow readers cannot take the slots of short commands like claims.
A client that takes nothing for 60 s, or takes a streamed answer slower than
64 KiB/s on average after its first 30 s, loses the rest of it, and its
command ends. A write's answer is held until the write is done (see below).
At most four requests that bring their own playbooks plan at once (another
is answered 503, which clients retry). The server logs one
line per request on stderr; set `BD_LOG` to change that. Ctrl-C or SIGTERM
lets running commands finish first (up to 30 seconds). The server keeps
connections to each database open, so restart it after replacing or moving a
workspace's `bd.db`.

## Signing in

Instead of creating each person's token, an admin can let people get their
own by signing in with a provider `<root>/auth.toml` names: GitHub, or any
OpenID Connect provider (Google, Microsoft Entra, GitLab, Okta, Keycloak, or
a broker such as Dex in front of others). `bd remote login --provider github` (or
`--provider <name>`) shows a one-time code to enter at the provider, and the
server issues an access token if the account may use the workspace: by a
rule of `auth.toml` (GitHub only), or by the admin's own
[authorizer](#deciding-with-an-authorizer). An account let in by neither
gets nothing. MCP clients sign people in the same way in a browser, where a
page offers the providers to choose from ([docs/mcp.md](mcp.md)).

bd proves who signed in, and binds each account to an actor for good (by
its provider's issuer and its id there, never its login or email). How long
tokens last is set once for every provider:

```toml
[sign_in]
token_ttl = "1h"                        # access tokens expire (5m to 366d; default 1h)
refresh_limit = "30d"                   # refreshed for at most this long after the sign-in (default 30d)
refresh_idle = "7d"                     # and not after this long without one (default 7d)
```

Tokens are refreshed ([Refreshing](#refreshing-sign-ins)) when someone can
decide again at each refresh: an authorizer, or GitHub's rules through the
GitHub App's private key. Otherwise people sign in again each `token_ttl`.

### With GitHub

1. Register a [GitHub App](https://github.com/settings/apps) (any homepage
   URL will do, no webhook), and tick **Enable Device Flow** in its settings.
   Give it the **Members** organization permission (read), install it on
   each organization the rules name (with rules that name none, on any
   account), and generate a private key: the server keeps signed-in people's
   tokens fresh with it ([Refreshing](#refreshing-sign-ins)). Without a
   private key, sign-in still works, also with a [GitHub OAuth
   app](https://github.com/settings/developers), but its tokens are
   refreshed only with an authorizer deciding.
2. Write `<root>/auth.toml` on the server:

```toml
[github]
client_id = "Iv23li0123456789abcd"
private_key = "github-app.pem"          # the GitHub App's private key, relative to the root (mode 0600)
# url = "https://ghe.example.com"       # GitHub Enterprise Server; its API defaults to <url>/api/v3 (api_url)
# deny = [12345]                        # GitHub user ids that may never sign in (`bd serve token accounts`)
# client_secret_file = "github-secret"  # the GitHub App's client secret, relative to the root: for [oauth]

# Rules, in order: the first that lets an account into the workspace decides its token.
[[github.allow]]
users = ["alice"]                       # GitHub logins, whatever their case
role = "admin"                          # read, write (default) or admin
kind = "human"                          # agent (default) or human

[[github.allow]]
teams = ["acme/bd-maintainers"]         # <organization>/<team slug>
kind = "human"

[[github.allow]]
orgs = ["acme"]
role = "read"
workspaces = ["proj"]                   # default: every workspace

# [[github.allow]]
# anyone = true                         # any GitHub account, e.g. for an open source project
# workspaces = ["oss"]
# role = "write"                        # read (default here) or write
# min_account_age = "30d"               # GitHub accounts younger than this are not let in by the rule
# max_claims = 3                        # its tokens' actors hold at most 3 issues at once

# [oauth]                               # MCP clients such as ChatGPT sign people in with OAuth (docs/mcp.md)
# redirect_hosts = ["chatgpt.com", "claude.ai"]
# loopback_redirects = true
```

Instead of rules, the admin's own code may decide who gets in: see
[Deciding with an authorizer](#deciding-with-an-authorizer).

The same rules (or authorizer) let people sign in from MCP clients that use
OAuth, such as ChatGPT and the Claude apps, when `[oauth]` turns on `bd serve`'s
authorization server: see [Signing in with
OAuth](mcp.md#signing-in-with-oauth).

`bd serve` checks the file when it starts, and refuses to start with a
mistake in it (an unknown field, a rule that names nobody, an `http` URL to
another host, an `anyone` rule that is not the last or gives more than a rule
before it). After that, each sign-in reads it again, so changes need no
restart; a mistake made meanwhile fails sign-ins and refreshes, with the
reason in the server log only. It also says at start whether tokens are
refreshed.

- A rule lets an account in if `users` lists its login, or if it is an active
  member (not just invited) of one of its `orgs` or `teams`. Memberships are
  read with the account's own GitHub token, so the sign-in asks for the
  `read:org` scope when a rule names organizations or teams. An organization
  that restricts OAuth apps only answers once an owner approves the app
  (organization settings, Third-party access), and one with SAML single
  sign-on only for a GitHub token authorized for it (GitHub offers that on its
  authorization page); until then its members count as no members, and the
  server log says why (also when a later rule lets the account in).
- A rule that lets an account in, but not into the workspace the sign-in is
  for, leaves it to the rules after it; the token a later rule then issues
  covers that workspace only, never one where an earlier rule decides. An
  account no rule lets into that workspace is refused, and so is a workspace the server does not have:
  nothing is issued.
- A rule with `anyone = true` lets in every GitHub account the rules before
  it do not, so it names no users, orgs or teams and must be the last rule.
  Since anyone can create GitHub accounts, its tokens read by default, may
  write at most (never `admin`), and are always `agent` tokens, which cannot
  open human gates. A rule before it may not give a lower role in a workspace
  it shares with it, so members never get less than strangers. Each account
  still gets its own actor; to keep one out, add its user id to `deny` and
  revoke its tokens (below), since revoking alone lets it sign in again.
- Any rule may set `min_account_age` (like `token_ttl`, e.g. `"30d"`): an
  account GitHub created more recently, or whose creation date GitHub does
  not give, is not let in by that rule, and is left to the rules after it.
  If none lets it in, the sign-in is refused with the age it needs. This
  keeps out accounts made on the spot, not determined ones.
- Any rule may set `max_claims`, and `bd serve token create` takes
  `--max-claims N`: the token's actor and its sub-actors may then hold at
  most that many open issues, claimed (`in_progress`) or reserved (assigned),
  so that no one takes the whole ready queue. A command that would make them
  hold more (`claim`, `update --status in_progress` or `--assignee`,
  `create --assignee`, an import, a batch or a playbook run) fails with exit
  7 and changes nothing. Issues others assign to them count, but never stop
  them from working on those, and closing or releasing in the same command
  makes room. An abandoned claim counts until its lease runs out and is
  reclaimed. A rule before an `anyone` rule with `role = "write"` may not
  set fewer `max_claims` than it in a workspace they share. With `role = "write"`, tokens can still
  change issues in other ways, so the limit is a guard against greed, not
  malice.
- The token acts as the account's actor, or its sub-actors `<actor>/<agent>`:
  `<provider>:<login>` with the account's login when it first signed in
  (`github:alice`, `google:alice@acme.com`; a `/` in a login becomes `-`),
  which it keeps when its login changes. The token is named `<provider>-<actor>-<random>` and expires
  after `token_ttl`; each sign-in gets a token of its own, so one account may
  sign in on several machines. When tokens are refreshed, the client renews
  it before
  it expires ([Refreshing](#refreshing-sign-ins)); once it can no longer be
  renewed and expires, commands fail with exit 7 naming the time, and
  `bd remote login --provider <name>` gets a new one.
- An actor belongs to one principal, and to an account for good: the server
  binds each account (by its provider's issuer and its id there: a GitHub
  user id, an OIDC `sub`) to its actor at its first
  sign-in, in `server.db`, and keeps the binding when the account's tokens
  expire or are revoked. A sign-in is refused while its login's actor belongs
  to another account (one that had the login before), or while a live token
  an admin created acts as it or one of its sub-actors. An account that
  `users` lets in by a login it took after another account gave it up is
  refused too, even if bound before under another login, while the login
  names another account's actor, that account's login at its latest
  sign-in, or a live admin-created token's actor: so it does not pass for
  the previous holder. Under another rule (`orgs`, `teams`, `anyone`), such
  an account signs in as its own actor. `bd serve token create` refuses
  an account's actor in the same way. `bd serve token accounts` lists the
  bindings, and `bd serve token revoke --account <login> --forget` releases
  one: it deletes the account and its tokens from `server.db`, leaving no
  trace in its files ([What bd keeps about people](security.md#what-bd-keeps-about-people)),
  and the next account to sign in as that login binds the actor again.
- A change to `auth.toml` (`deny` included) applies to the next sign-ins
  and refreshes: tokens already issued keep their permissions until they
  expire, at most `token_ttl`. To cut an account off at once,
  `bd serve token revoke --account alice --root /srv/bd` revokes every token it
  got by signing in, including those from before a rename (`alice` may be its
  latest login, or name its actor `github:alice`). `bd serve token list` shows each token's
  `account` (provider, issuer, subject, login), expiry, and until when it is
  refreshed. A token leaves the list a week after it ends (revoked, or
  expired and no longer refreshed), at the server's next write. Tokens of
  MCP clients that signed someone in with OAuth also show their `client`,
  and `bd serve token revoke --client <client_id>` revokes all of a
  client's.

### With an OpenID Connect provider

Register bd as a client (a "web application") at the provider, with the
redirect URI `<public-url>/oauth/<name>/callback` for MCP clients'
browser sign-in, and enable its device flow (device authorization grant)
for `bd remote login`. Then name it in `auth.toml`, with an
[authorizer](#deciding-with-an-authorizer), which decides who of those it
vouches for gets in (rules are GitHub's):

```toml
[oidc.google]                           # <name>: 1-32 lowercase letters, digits and dashes; never github
issuer = "https://accounts.google.com"  # its discovery document: <issuer>/.well-known/openid-configuration
client_id = "1234.apps.googleusercontent.com"
client_secret_file = "google-secret"    # relative to the root; leave out for a public client
label = "Google"                        # shown on the sign-in page (default: the name; at most 40 characters)
scopes = ["email", "profile"]           # asked for besides openid (this is the default)

[authorizer]
command = ["bin/authorize"]
```

`bd remote login --provider google` signs in with it. The account is its
`sub` claim at its issuer. Its login, which its actor is made of, is never
an email, since actors stay in workspaces' histories for good: it is the
provider's `preferred_username` unless that is an email (as Microsoft
Entra's is), else a pseudonym of the account, `u-` and 12 hex digits of a
hash of its issuer and `sub` (`google:u-3f9a2c1e7b04`). The same account
always gets the same one. The email, if the provider verified it, is shown
on the consent page and sent to the authorizer at sign-in, and bd keeps it
nowhere: an authorizer that should tell admins who `google:u-3f9a2c1e7b04`
is keeps its own record of it. bd checks each ID token strictly: signed with RS256 or ES256 by a
key of the provider's published set (fetched over https and cached), from
the issuer, for this client alone (`aud` exactly its client ID, and `azp`,
when present, too: a token for several audiences is refused), not
expired, and, in a browser, carrying the nonce of that sign-in. The
authorizer gets the verified email and all the token's claims (`groups`,
a tenant, ...) at sign-in. At a refresh, bd does not ask the provider again:
the authorizer decides on the account as it signed in, so it is the one to
notice an account removed at the provider.

A provider without a device flow serves MCP clients' browser sign-in only:
`bd remote login --provider` with it says so.

#### Sign in with Apple

Apple is an OpenID Connect provider with two differences, which bd
handles. Its answers come back as a form the browser posts to the
callback when scopes are asked for (`response_mode = "form_post"`); bd
sends that answer on to the callback as the GET it would otherwise have
been, keeping only its code and state. And its client secret is a JWT
signed with a key of the developer account, good for at most six months;
bd signs a fresh one for each request from the key:

```toml
[oidc.apple]
issuer = "https://appleid.apple.com"
client_id = "com.example.bd.signin"     # the Services ID
label = "Apple"
scopes = ["email"]
response_mode = "form_post"             # Apple requires it with scopes

account_events = ["com.example.bd"]     # take Apple's account notifications naming these IDs (below)

[oidc.apple.signed_secret]              # instead of client_secret_file
key_file = "AuthKey_ABC123DEFG.p8"      # the Sign in with Apple key, relative to the root
key_id = "ABC123DEFG"                   # its key ID
team_id = "DEF123GHIJ"                  # the developer account's team ID
```

In the Apple Developer account, create an App ID with Sign in with Apple,
a Services ID for it (the `client_id`) with the server's domain and the
return URL `<public-url>/oauth/apple/callback` (https, on a domain that
does not change), and a key for Sign in with Apple (the `.p8` file, which
Apple lets you download once). Apple has no device flow, so its accounts
sign in from MCP clients in a browser only. Apple gives no user name, so
the actor is a pseudonym like `apple:u-3f9a2c1e7b04`. The authorizer gets
the `sub` and the email, often an `@privaterelay.appleid.com` address when
the person chooses to hide theirs (with `is_private_email` among the
claims), to decide on, and the consent page shows the email.

Apple tells the server when someone stops using Sign in with Apple for
the app or deletes their Apple Account, if the App ID's Sign in with Apple
configuration names `<public-url>/oauth/apple/events` as its
server-to-server notification endpoint. With `account_events` listing the
IDs Apple names the app by in them (its primary App ID, and the Services
ID to be sure), bd checks each notification (signed by Apple's keys, for
one of those IDs, issued within the last week) and acts on it: when consent
is revoked, the account's sign-ins from before then end (one made since is
its new consent); when the Apple Account is deleted, bd forgets the account
and its tokens as `revoke --account --forget` does. Notifications about
email forwarding need nothing, as bd keeps no email. Any OIDC provider that
sends notifications in Apple's format can use `account_events` too.

### Deciding with an authorizer

bd always proves who signed in (the provider's sign-in, and the account
bound to its actor). Whether that account may use a workspace, and with
what access, can be left to the admin's own code instead of
`[[github.allow]]` rules, for directories, groups or lists bd knows nothing
about. An `[authorizer]` replaces the rules (a file with both is refused),
and is needed for OIDC providers:

```toml
[authorizer]
command = ["bin/authorize", "--org", "acme"]   # run as is, no shell; relative to the root if it has a /
# url = "https://authz.internal/bd"           # or POST to this instead (http only to this machine)
# token_file = "authz-token"                  # its bearer token, relative to the root
# timeout = "5s"                              # an answer within this (1s to 60s)
# env = ["GOOGLE_APPLICATION_CREDENTIALS"]    # passed to the command besides PATH, HOME and LANG
# refresh_grace = "4h"                        # see below
# max_role = "write"                          # the most it may grant: read, write (default) or admin
# human = false                               # whether it may grant kind human (default no)
# max_claims = 10                             # the most claims its tokens may hold
# workspaces = ["proj"]                       # the only workspaces it may let anyone into (default all)
```

At each sign-in, and at each refresh, bd sends it one JSON object, on the
command's stdin or as the POST body:

```json
{ "version": 1, "event": "sign_in", "workspace": "proj",
  "provider": "github", "issuer": "https://github.com",
  "subject": "583231", "login": "alice", "account_created": "2011-01-25T18:44:36Z",
  "email": null, "claims": null,
  "client": "https://chatgpt.com/oauth/client.json", "current": null }
```

`subject` is the account's id at its `issuer`, which never changes; `login`
may change, and may once have been another account's, so match on
`issuer` and `subject` where you can. For an OIDC provider, `email` is the
account's email if the provider verified it, and `claims` all of its ID
token's claims, at sign-in (not at refreshes). `account_created` is
GitHub's. `client` names the MCP client signing the account
in (null for `bd remote login`). At a refresh, `event` is `refresh` and
`current` holds the access the sign-in has (`role`, `kind`, `max_claims`,
`signed_in_at`). It answers with one JSON object, on stdout or as a 200
response:

```json
{ "allow": true, "role": "write", "kind": "agent", "max_claims": 5,
  "via": "member of bd-users", "reason": "in the bd-users group" }
```

`role` defaults to read and `kind` to agent; the token covers the
workspace asked about. `via` is shown on the consent page as what let the
account in (plain text, 100 characters at most); `reason`, for a refusal
too (`{"allow": false, "reason": "..."}`), goes to the server log only: the
person is told only that the account may not use the workspace.

- **Fail closed.** No answer within `timeout`, a command that exits
  non-zero, an HTTP status other than 200, a redirect, or an answer that is
  not one JSON object of these fields (64 KiB at most) lets no one in. A
  sign-in then fails (`bd remote login` says to sign in again in a moment;
  an MCP client's browser gets a page to try again from), and the server log
  says why, with the command's stderr. At most 8 are asked at once.
- **Caps.** It can grant no more than `auth.toml` allows: a role above
  `max_role`, kind `human` without `human = true`, or more `max_claims` than
  the cap refuses the account, and the log says so. A cap of `max_claims`
  also applies to answers that name none. It is not asked about workspaces
  outside `workspaces`. So a broken or compromised authorizer cannot hand
  out admin tokens or open human gates unless the admin chose to allow it.
- **Identity stays with bd.** It decides access only: it cannot choose or
  change the actor (the account's binding decides, as with rules), and a
  login that once was another account's is refused as it is for a `users`
  rule. `deny` (GitHub user ids) applies before it is asked. It never
  sees a provider's tokens. Every account acts as `<provider>:<login>`
  (`github:alice`, `google:alice@acme.com`), so no provider's users, who
  often choose their own names, can take an admin's actor, or each other's; `bd serve token revoke --account` names one by
  its actor where a login is shared by accounts at several providers.
- **The command** runs in the root, with an environment cleared except
  `PATH`, `HOME`, `LANG` (and Windows' basics) and the variables `env`
  names, so the server's own secrets never reach it. On Unix it runs in a
  process group of its own, killed once it has answered or its time is up:
  whatever it starts in the background does not outlive it, and output a
  background process keeps open does not hold bd past `timeout`. It runs as
  the user `bd serve` runs as, so run that as an unprivileged user. Read the
  request as data: it carries names chosen by whoever signs in.
- **The URL** gets `Authorization: Bearer <token_file>`, with no proxy and
  no redirects followed.
- **Refreshes** ask it again (`event` `refresh`), which is how a membership
  ended elsewhere takes effect. An answer that refuses revokes the sign-in.
  When it cannot answer, only that refresh fails, and the client tries again
  later; with `refresh_grace` (at least `token_ttl`, at most
  `refresh_idle`), a refresh within that long of the sign-in's last decision
  instead keeps the access it had, so a short outage of the authorizer does
  not end sign-ins.

### Refreshing sign-ins

When someone can decide again at each refresh (an authorizer, or GitHub's
rules with `private_key`), each sign-in also gets a refresh token, saved with its
access token on the client and sent only to `POST /v2/auth/refresh`. The
client renews the access token by itself, before a command, once a fifth of
its lifetime is left (10 minutes at most), or when the server finds it
expired first; so does a long-running one (`bd agents watch`, `bd events
--follow`) between its requests. Each refresh:

- asks the authorizer again (above), or applies GitHub's rules again, by
  the workspace the sign-in was for. With the GitHub App, a GitHub account
  is first looked up by its id (a deleted one is revoked, a renamed one
  goes by its new login); without it, and for OIDC providers, the account
  is taken as it signed in. GitHub's rules: `deny`, the rules in order (`users` by the account's current
  login, which the server reads by its GitHub user id; `orgs` and `teams` by
  active membership; `min_account_age`), and what the first matching rule
  grants now: role, kind, workspaces and `max_claims` may change at a
  refresh. GitHub is asked as the GitHub App, with installation tokens: the
  server never keeps anyone's own GitHub token. An organization the App is
  not installed on, or whose members it may not read, does not tell: if
  that decides, the refresh fails for now (exit 8, nothing revoked), and the
  server log says why. Account lookups use any installation of the App that
  is not suspended.
- replaces both the access token and the refresh token: the old ones stop
  working at once. A refresh token works once. One used again, as by someone
  who copied it, revokes the sign-in for everyone holding it. A retry of the
  same refresh is no reuse: the client saves each refresh's request id
  before sending it, and sends it again until an answer is saved, so a
  refresh whose answer was lost (a timeout, Ctrl-C) refreshes again later
  (within 5 minutes, the server answers it with the same new tokens). bd
  processes of one user on one machine renew one at a time (they share
  `credentials.lock`), so they never spend one twice; one whose token still
  works does not wait for another renewing, and a refresh ends within a
  minute.
- is refused, and the sign-in revoked, when the rules no longer let the
  account in, the account is in `deny`, or GitHub no longer has it. The
  client then keeps the access token until it expires, says why on stderr,
  and stops trying; `bd remote login --provider <name>` signs in again.
- works until `refresh_limit` after the sign-in, and while no more than
  `refresh_idle` passed since the last one (a machine off for longer signs
  in again). `token_ttl`, `refresh_idle` and `refresh_limit` must each be at
  most the next.
- fails as a sign-in does when GitHub or the server cannot be reached (exit
  8): nothing changes, and the client tries again a minute later (at its
  next command) while its access token works, then fails with it.

The server runs GitHub's device flow itself, so the client needs to reach only
the bd server, and the GitHub token never leaves the server: it reads the
account and its memberships during the sign-in, and is never stored or
logged. A few things to keep in mind:

- `users` matches current logins: after a rename, update the rule (the
  account keeps its actor). A login given up by renaming can be registered by
  someone else, who is refused while the old account's actor is bound, but
  whom `users` lets in once that binding is released; memberships of
  organizations and teams follow the account itself.
- Tokens saved by `bd remote login` serve every process of that user on that
  machine, agents included, so a rule's `kind = "human"` lets those agents
  resolve human gates too. `agent` is the default.
- Whoever started a sign-in gets its token: enter only codes shown by one's
  own `bd remote login --provider <name>`, never one someone sent
  (RFC 8628 section 5.4).
- The sign-in endpoints, `POST /v2/auth/<provider>/device` and
  `POST /v2/auth/<provider>/token` (`github`, or an OIDC provider's name), need no token, and `POST /v2/auth/refresh`
  takes a refresh token. `POST /v2/auth/revoke`, sent
  with a token, revokes it if it came from sign-in: `bd remote logout` and a
  new sign-in on the same machine use it, so a token people no longer use
  stops working at once rather than when it expires. At most 8 sign-in requests run
  at once (others are answered 503, which clients retry), and GitHub limits
  how many codes an app may have entered per hour. GitHub gives a code's token
  only once, so the server keeps the answer that issued a bd token for 5
  minutes: a client whose answer was lost in transit gets it again by asking
  again.

## Background jobs and backups

`bd serve` keeps every workspace under `--root` up to date by itself, including
workspaces no client has used since it started (it looks for new ones every
30 seconds):

| job | default | flag | what it does |
|---|---|---|---|
| lease reclaim | every minute | `--reclaim-every` | `bd reclaim`: puts claimed issues back in the queue once their lease expired more than `lease.grace` ago (not in workspaces where `lease.auto_reclaim` is `false`) |
| gate checks | every minute | `--gate-check-every` | `bd gate check --type local`: opens timer and issue gates, escalates failures and timeouts |
| GitHub gate checks | every 5 minutes | `--gh-check-every` | `bd gate check --type gh` with the server's `gh` (its `BD_GH` and `gh auth`); each armed GitHub gate costs one or two API calls of that account per check |
| agent sets | every 30 seconds | `--agents-every` | reads each harness's set in `.bd/agents` and appends an `agents_changed` event when its revision changed, which `bd agents watch` clients wait for; a set that cannot be read gets no event and a warning in the log (once per error), and the other sets are still checked ([Agent skills](agents.md#serving-sets)) |
| backups | off | `--backup-dir DIR`, `--backup-every 1h`, `--backup-keep 24` | a snapshot of each workspace, below |
| request records | every hour | | deletes idempotency records older than a day |

`0` or `off` turns a job off. Jobs run the commands' own code as actor
`bd-serve`, so their events (`reclaimed`, `closed`, `gate_escalated`) read like
the commands'. That actor is the server's own: no access token may act as it
or its sub-actors (in any case), and a GitHub account whose actor would be
it cannot sign in. Each workspace's timers are jittered so workspaces do not fire
together, a job never overlaps itself, and only a few jobs run at once, on
threads of their own, so client requests keep their slots. Writes are short
transactions: `gh` runs outside any transaction, and a backup is a read
transaction. A failed job is logged and retried later, backing off up to 32
intervals; it never stops the server. On shutdown no job starts any more,
running `gh` calls are cancelled, and running jobs get 10 seconds to finish.
A job still running after that is abandoned safely: an unfinished transaction
rolls back, and the next backup removes an unfinished one.

With `--backup-dir /backups`, each workspace is copied to
`/backups/<name>/<name>-<UTC time>.db` (e.g. `proj-20261001T214244.014Z.db`)
every `--backup-every`, and all but the newest `--backup-keep` copies are
deleted (`0` keeps them all). A copy is taken with SQLite's `VACUUM INTO`,
which does not hold up writers, and is a compact, self-contained database
file. It is checked (`PRAGMA quick_check`) and flushed to disk under a
temporary name before it is renamed into place, so a file with the final name
is always complete. The copy just written is never deleted, even when older
copies are dated after it (the clock was wrong, then corrected); the server
logs a warning then. Copies hold everything in a workspace, so on Unix they
are readable by the user running `bd serve` only: files are created 0600, and
the directories it creates 0700 (an existing `--backup-dir` keeps its mode).
Keep the directory on another disk, or ship it elsewhere (rsync, restic,
object storage). To restore a workspace from a copy:

```bash
# Stop bd serve first: it keeps the database open, and could open a half-copied file.
cd /srv/bd/proj/.bd
mkdir -p broken && mv bd.db* broken/            # the database and its -wal and -shm files
cp /backups/proj/proj-20261001T214244.014Z.db bd.db
bd -C /srv/bd/proj doctor                        # then start bd serve again
```

The workspace is then as it was at the time of the copy: later changes are
gone, and the sequence numbers of their events are given out again, so
anything following events with a cursor (`bd events --since`) should
re-baseline from `bd export`. To bring a copy up as another workspace while
the server runs, copy it to `<root>/<new name>/.bd/bd.db.tmp`, then rename it
to `bd.db`: a rename is atomic, so the server never sees half a file.

For continuous replication instead of (or besides) periodic copies, run
[Litestream](https://litestream.io) next to `bd serve`, one database per
workspace: `litestream replicate /srv/bd/proj/.bd/bd.db s3://bucket/bd/proj`
(or a config file listing them). It suits bd's settings: WAL mode, a busy
timeout, and `synchronous=NORMAL`. To restore, stop `bd serve`, move the old
files aside as above, and run
`litestream restore -o /srv/bd/proj/.bd/bd.db s3://bucket/bd/proj`.

## Clients

The same `bd` binary is the client. Point a checkout at the server once and
commit the result, so every checkout and agent uses the shared workspace:

```bash
bd remote set https://bd.example.com/w/proj   # writes .bd/remote.toml (--ca-cert ca.pem for a private CA)
bd remote login --provider github             # signs in with GitHub (or another provider), where the server allows it
bd remote login                               # or: prompts for a token from the server's admin, checks it, saves it
bd remote show                                # checks the URL, certificate, token and actor; shows what the token may do
bd ready                                      # every command now runs on the server
BD_ACTOR=alice/agent-2 bd claim --next        # sub-actors: one lease holder per agent
BD_SESSION=agent-3 bd claim --next            # outside an agent harness: acts as <token actor>/agent-3
```

```toml
# .bd/remote.toml
url = "https://bd.example.com/w/proj"
# ca_cert = "ca.pem"    # a private CA, relative to this file
```

A `.bd/remote.toml` takes precedence over a `.bd/bd.db` in the same
directory (`bd remote set` refuses to hide one unless given `--force`), `--db`
always means a local database, and `bd remote unset` removes the file.

The access token comes from `$BD_TOKEN`, else from the tokens saved by
`bd remote login`, never from the repository. `$BD_TOKEN` is bound to no
server, so it is sent only to the workspace URL that `--remote` or
`$BD_REMOTE` names, never to one from a `.bd/remote.toml`: a cloned
repository, a pull request or a submodule could name its own server there and
collect the token. CI and agents set `BD_REMOTE` (with `BD_CA_CERT` for a
private CA: a checkout's `ca_cert` is not read then) and take `BD_TOKEN` from a
secret; people log in once per machine:

```bash
bd remote login --provider github      # sign in with GitHub; or: bd remote login --provider github https://bd.example.com/w/proj
bd remote login --provider google      # sign in with one of the server's OIDC providers
bd remote login                        # the checkout's server; or: bd remote login https://bd.example.com/w/proj
printf %s "$TOKEN" | bd remote login   # a piped token is read from stdin, not from a prompt
bd remote login --workspace-only       # this workspace only, e.g. for a token limited to it
bd remote logout                       # forget it, and revoke it on the server if it came from signing in
```

With `--provider <name>` (`github`, or an OIDC provider of the server's), `login` gets the token from the
server instead of reading one: it shows a one-time code to enter at the
provider (`https://github.com/login/device` for GitHub), waits until it is
entered (Ctrl-C cancels; GitHub's code lasts 15 minutes), and saves the
token the server issues, with its refresh token where the server refreshes
sign-ins, reporting its actor, role, kind, workspaces, expiry, and until
when it is renewed (with `--json`: `actor`, `account` with the `login` and
what let it in as `via`, and `token`). The server must offer that provider,
and must let the account in ([Signing in](#signing-in)); a provider it does
not have, or one without a device flow, is refused with exit 2.

Otherwise the token is never taken from the command line, so it stays out of shell
history and process lists, and it is never printed. `login` reads it from
stdin when stdin is piped, and otherwise prompts without echoing it (on
Windows, pipe it: `Read-Host -MaskInput Token | bd remote login` in
PowerShell 7). It runs `bd info` on the server with the token first and saves
nothing if that fails; `--no-verify` skips the check. Tokens are saved in
`$XDG_CONFIG_HOME/bd/credentials.toml` (default `~/.config/bd/credentials.toml`,
or `%APPDATA%\bd\credentials.toml` on Windows), one per server: the URL up to
`/w/<workspace>`, so `https://bd.example.com/w/proj` and
`https://bd.example.com/w/other` share the token saved for
`https://bd.example.com`, and a path prefix (`https://example.com/bd`) is part
of the server. A `--workspace-only` token takes precedence over its server's,
and `$BD_TOKEN` over both where `$BD_REMOTE` names the server; `bd remote
show` says which one is used. A saved
token is bound to the certificate authorities it was checked against: the
system's, or the CA file in use at login (`ca_cert` in `.bd/remote.toml`, or
`BD_CA_CERT`). It is not sent where another CA would be trusted, so a cloned
repository whose `remote.toml` names its own CA for your server cannot
redirect it; log in again from that checkout if you trust its CA. Setting
`BD_CA_CERT` yourself overrides the check.

On Unix, the file is replaced atomically by one with mode 0600, in a
directory created 0700, and bd refuses to use it if other users can read it. On Windows it is
protected by the per-user permissions of `%APPDATA%`. `bd remote logout`
forgets the token saved for a workspace URL and for its server (`--workspace-only`
keeps the server's), or for a server URL and all its workspaces. A token from
signing in is revoked on its server too (with its refresh token, where
it has one, so also after a refresh whose answer was lost), and so is one
that signing in again replaces: within a few seconds, and only trusting the server as when
the token was saved. If that fails (the server cannot be reached, say), the
token is forgotten all the same and works on the server until it expires. A
token an admin created may serve elsewhere too, so it stays valid until it is
revoked on the server (`bd serve token revoke`).

| variable | meaning |
|---|---|
| `BD_TOKEN` | access token for the workspace `BD_REMOTE` (or `--remote`) names, never sent to a `.bd/remote.toml` URL; takes precedence over tokens saved by `bd remote login` |
| `BD_REMOTE` / `--remote URL` | use this workspace URL instead of `.bd/remote.toml` |
| `BD_CA_CERT` | PEM file of the CA that signed the server certificate |
| `BD_ACTOR` | act as `<token actor>/<name>`; anything else is refused |
| `BD_SESSION` | act as `<token actor>/<name>` (added to the session's part in an agent session); agent sessions send theirs on their own ([Actors](concepts.md#actors)) |
| `BD_REMOTE_RETRY_SECS` | how long to retry an unreachable server (default 30; 0 = once) |
| `BD_INSECURE_HTTP=1` | allow plain `http://` to a non-loopback host |

A token acts as one actor (`--as`; for a token from signing in, the actor
its account is bound to), or as that actor's sub-actors `<actor>/<name>`, so
leases keep naming who holds them. Roles:

| role | may run |
|---|---|
| `read` | read-only commands; its database connection is query-only |
| `write` (default) | every command except the admin ones |
| `admin` | also `config set/unset`, `import`, `events prune`, `doctor`, and taking over other actors' claims (with `--take-over`) |

A token's kind, independent of its role, says who holds it: `agent` (the
default) or `human` (`--kind human`, or `kind = "human"` in an `auth.toml`
rule). Keep human tokens out of agents' environments, since they
can approve. A client sees its own token's name, role, kind, workspaces,
expiry and account in `bd remote show` (its `access` line) and in
`bd info` (`token` in its JSON), never the secret: that tells a refusal
(exit 7) by role or kind apart from one by actor or workspace. The server
enforces roles and kinds in the engine, so a `bd batch`
or a playbook gets the same answer as a single command:

- Taking over a live claim of another actor needs `--take-over`, as
  locally ([Claims](concepts.md#claims-leases-and-recovery)), and an admin token:
  `release`, `update --assignee` or moving the issue out of `in_progress`,
  `close`, `delete`, `import`, discarding or compacting a run with such a
  claim, and `reclaim` with a `--grace` shorter than `lease.grace`. A claim
  held by the token's own actor or one of its sub-actors needs only
  `--take-over`. A token that may not take the claim over is refused (exit
  7) with or without `--take-over`, except a release or reassignment without
  it (exit 4, as before). Dead claims stay reclaimable by any write token
  (`bd reclaim`, `bd claim`), and unclaimed work may be reassigned as
  before. A run or group claimed by another actor stays open, still claimed,
  when its last step closes.
- Opening a human gate needs a human token, whatever the role: `gate
  resolve`, `close`, pinning it, changing its type or condition, or deleting
  it. So does getting the work it holds back past it early: removing that
  edge, `close --force`, pinning or deleting the work (or a group, run or
  epic around it), or moving the work or the gate out of its parent.
  `import` is checked too. Other gates may be resolved by hand with any
  write token.
- `metadata.playbook`, which makes runs and groups close themselves, belongs
  to playbook runs: only an admin token may change it on an existing issue
  (closing such a run or group still checks claims and human gates).
- GitHub gates may only name repositories in the workspace's `gate.repos`,
  which only admins set ([Gates](playbooks.md#gates)); unset, only the workspace's own.

`bd` on the server's host, which opens `bd.db` directly, is not limited by
tokens (`gate.repos`, once set, applies there too).

Every invocation carries a random request id. The client retries connection
failures, timeouts, busy answers and a proxy's gateway errors (such as
Cloudflare's 524 for a command running over 100 s) with the same id; once a
write may have run, it gets the whole retry time again to ask for its stored
answer. The server records the id in the same transaction as the write, and
stores the write's answer (up to 1 MiB of output) before sending it, to
replay it to a retry, so a write whose answer was lost in transit is applied
once. A write's answer is printed once it has arrived whole; a read prints a
long output as it arrives, so a read whose connection breaks after that
fails (exit 8, output incomplete) instead of being retried. Exit codes are
the same as locally, plus 7 (access denied), 8 (server unreachable: the
command did not take effect) and 9 (a write that may have reached the server
lost its answer: more than 1 MiB of output, or no answer before the retries
gave up; it may have taken effect, so check before running it again).

What runs where:

- Input and output files stay on the client: `import FILE` and `batch -f FILE`
  send the file, `--stdin` and `-` send stdin, and `export -o` and
  `playbook extract -o` write the file locally, as `FILE.tmp` renamed into
  place once the command succeeds (so a failed export leaves `FILE` alone).
- A playbook name is looked up in the checkout's `.bd/playbooks` first (next
  to `remote.toml`, or in the nearest `.bd` directory with `--remote` or
  `BD_REMOTE`), then on the server's playbook path (the workspace's
  `.bd/playbooks`, `<root>/<name>/.bd/playbooks`, then the server's
  `$BD_PLAYBOOK_PATH` and user config directory), and only then in your own
  `$BD_PLAYBOOK_PATH` and user config directory. File paths are relative to
  the client's current directory. `playbook show`, `plan` and `run` of a
  playbook found on the client send it along with every file it extends or
  expands, resolved on the client as locally (at most 256 files of 512 KiB,
  8 MiB in all), and the server checks and compiles it as a local run would,
  without reading any other file for it. `playbook list` shows them all in that
  order, marking the server's, and `show` marks a playbook from the server.
  `playbook extract --save` writes into the checkout, with a note when the
  playbook is too large to send. GitHub gates are checked by the server's
  `gh`, for the repositories `gate.repos` allows, also on the server's own
  schedule ([Background jobs](#background-jobs-and-backups)).
- `events --follow` and `events --wait` wait on the server for new events
  ([Followers](#followers)). `init`, `bench` and `serve` only run on the
  machine that holds the database.
- `bd prime`, which session hooks run, gives up within seconds when the
  server is unreachable or there is no access token, and prints a notice instead
  of failing the hook. With `--json` it fails like any other command.
- `bd agents status`, `pull`, `approve` and `watch` run on the client and
  write into the checkout, reading the server's sets with the client's
  token; `bd agents manifest` runs on the server
  ([Agent skills and MCP definitions](agents.md)).

Claims stay atomic however clients reach the database: remote clients, and
local `bd` processes on the server's host, all take the same SQLite write
lock. `bd bench --mode remote` checks this end to end
([Benchmarks](benchmarks.md)).

The protocol (version 2) is one endpoint, so other clients can call it
directly: `POST /w/<name>/v2/exec` with `Authorization: Bearer <token>` and
`{"argv": ["claim", "--next", "--json"], "request_id": "..."}` (`"tool_call":
true` runs it with the actor's own rights only, as `bd mcp` sends a
model's tool calls: never the token's admin or human ones). The answer
(`application/x-ndjson`) has one JSON frame per line, in the order the command
wrote them: `{"stdout": "..."}` for output, `{"file": {"path", "data"}}` for
part of an output file, and last `{"exit": {"exit_code", "stderr", "replayed"}}`.
Blank lines are keep-alives, and an answer without the exit frame was cut
off. An event listing (`events`) also sends `{"cursor": N}` before its exit
frame: the `--since` value that continues after it, past the events its
filters skipped. `["events", "--since", "N", "--wait", "25s", "--json"]` is a
long poll: answered as soon as an event matching its filters follows `N`, or
with no events (and the cursor) when the wait ends. Failures before the
command runs return a non-200 status with the `--json` error shape. Every
answer carries a `bd-protocol: 2` header, which tells bd serve's own answers
(a 503 before the command ran, say) apart from a proxy's.

Each workspace is also an MCP server, at `/w/<name>/mcp` (Streamable HTTP,
with the same bearer tokens): MCP clients such as Claude, ChatGPT or an
agent harness without a shell call bd's coordination tools there, acting as
`<token actor>/mcp` ([MCP server](mcp.md#over-http); setup of each client in
[connecting clients](mcp.md#connecting-clients)). `--public-url URL`
(or `$BD_SERVE_PUBLIC_URL`) is the URL clients reach the server at, path
prefix included (`https://example.com/bd`): MCP endpoints name themselves by
it in their OAuth metadata, and tokens created with `--resource` are bound to
an endpoint's URL under it ([discovery](mcp.md#discovery)). Set it behind a
proxy; without it, the URL is taken from each request's `Host` header.

Printed output never drives a terminal: control characters (except line
ends and tabs) and bidirectional formatting characters in titles,
descriptions, comments or a server's answer are printed as `\uXXXX`, both by
the command and again by the client, so neither stored text nor a server can
move the cursor, clear the screen or set the clipboard. Inside `--json`
strings that escape is the same character. Output files (`-o`) are written
as stored.

## Followers

`bd events --follow` and `bd events --wait` on a remote workspace are long
polls. Each request asks for the events after the client's cursor, and when
none matches yet, the server holds the request until one is committed, then
answers at once: a follower sees an event within milliseconds of its commit,
and an idle follower costs one request per `--max-wait` (25 s by default)
instead of one per poll interval. Each answer says where the next request
continues, so a follower prints every event once and in order, even when an
answer is lost and asked for again: a request that waited is retried for the
whole retry time (`BD_REMOTE_RETRY_SECS`, default 30 s) from its failure,
however long it had waited, and a retry that the server held and then
refused (busy, or shutting down) gets the whole retry time again, up to 5
times in a row, so a follower rides out server restarts. A follower that
falls so far behind that retention deleted events it had not read says so on
stderr and continues from the newest event. Under load, a follower asks at
most once per `--interval-ms` (default 500), so events arrive in batches; a
`--wait` longer than the server's `--max-wait` takes several requests.

A waiting request holds no command slot, database connection, transaction or
memory budget on the server, only its connection and its small request (one
larger than 16 KiB, say with stdin, is answered at once). The server learns of new
events from the commands it runs (clients' writes and its own background
jobs), and, while anyone waits on a workspace, by reading its events head
every 500 ms, for writes by other processes on its host (`bd` opening
`bd.db` directly). One reader per workspace checks for all the requests
waiting on it, and after waking them it waits 100 ms before it checks again,
so a burst of commits wakes them once.

| flag | default | meaning |
|---|---|---|
| `--max-followers N` | 256 | requests waiting at once (0 to 256, half the server's 512 connections); others are answered at once, and their clients poll every `--interval-ms` |
| `--max-wait DURATION` | 25s | the longest a request waits before answering that nothing came (1s to 5m) |

Keep `--max-wait` below the idle timeout of every proxy between clients and
the server: Cloudflare ends requests idle for 100 s, many load balancers
after 60 s, and Google Cloud's after 30 s by default. On shutdown, waiting
requests are answered at once (503, which clients retry), so the server does
not wait for them.
