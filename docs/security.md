# Security

This page collects bd's trust boundaries and safeguards. Each section links
to the page with the details.

## Local workspaces

- **No authentication.** Any process that can open `.bd/bd.db` can read
  and change everything in it. Actor names label who did what and decide
  who holds a claim, but are not verified: claim ownership keeps
  cooperating agents from ending each other's work by mistake, not a
  hostile process out ([Actors](concepts.md#actors)).
- **Nothing leaves the machine.** Logs, metrics and health checks are
  local; a remote workspace talks only to its own `bd serve`
  ([Observability](observability.md)).
- **GitHub gates run `gh` with the credentials of whoever checks them**, so
  `gate.repos` lists the repositories a gate may name; a gate naming
  another is refused when written and escalated instead of probed
  ([Gates](playbooks.md#gates)).

## Remote server

A bd server is the trust boundary of a remote workspace: tokens decide what
each client may do, and the checks run in the engine, so a `bd batch` or a
playbook run gets the same answer as a single command
([Remote server](remote.md)).

- **Transport.** `bd serve` refuses plain HTTP on a non-loopback address
  unless given `--insecure-http`; clients refuse plain `http://` to a
  non-loopback host unless `BD_INSECURE_HTTP=1`.
- **Access tokens.** `<root>/server.db` (SQLite, mode 0600) holds only the
  SHA-256 of each secret; secrets are printed once. `bd serve token revoke`
  takes effect at once.
- **Roles and kinds.** A token's role (`read`, `write`, `admin`) limits the
  commands it runs; a read token's database connection is query-only. Its
  kind (`agent` or `human`) says who holds it: only human tokens open
  human gates, so keep them out of agents' environments.
- **Overrides need the right token.** Taking over another actor's live
  claim needs `--take-over` and an admin token (unless the claim is held by
  the token's own actor or a sub-actor). Getting past a human gate needs a
  human token. Only admins change `metadata.playbook` on existing issues,
  set configuration (`gate.repos` included), import, prune events or run
  `doctor`.
- **Actors are bound to tokens.** A token acts as its actor or its
  sub-actors; `--actor` and `$BD_ACTOR` may name nothing else. The
  server's own actor, `bd-serve`, is reserved.
- **Claim limits.** `max_claims` caps the open issues a token's actors
  hold, so no one takes the whole ready queue. It guards against greed,
  not malice.
- **Resource limits.** Request size, a shared memory budget, command and
  streaming slots, waiting followers, and connections (512, and 64 per
  address) are bounded; slow readers lose their answer, and excess
  requests get 503, which clients retry ([Limits](remote.md#limits)).
- **The server's host is not limited by tokens.** `bd` run there opens
  `bd.db` directly; guard the root directory like the databases it holds.
  `bd serve` warns if the root is open to other users.
- **Backups hold everything.** On Unix, backup files are created 0600 in
  0700 directories; keep them on another disk or ship them elsewhere, and
  encrypted ([Backups](remote.md#backups)).

## Signing in

People can get their own tokens by signing in with an OpenID Connect
provider, under `auth.toml`'s rules or the admin's authorizer
([Signing in](sign-in.md)).

- **bd verifies identity itself** and binds each account to its actor by
  the provider's issuer and the account's `sub`, never by its login or
  email, which can change or pass to someone else.
- **ID tokens are checked strictly**: RS256 or ES256 only, signed by a key
  of the provider's published set fetched over https, from its issuer, for
  bd's client alone (`aud`, and `azp` when present), not expired, and with
  the browser sign-in's nonce. A browser sign-in's answer naming another
  issuer (RFC 9207) is refused before its code is used, and each provider
  has a callback of its own. An email counts only if verified.
- **Secret files** (client secrets, signing keys, the authorizer's token)
  live under the root, read by `bd serve` only; it warns at start about any
  its group or others may read. Keep them mode 0600. A signed client
  secret lasts 5 minutes.
- **An account no rule lets in gets nothing.** An `anyone = true` rule must
  be last; its tokens read by default, may write at most, and are always
  agent tokens. `deny` keeps an account out for good.
- **Actors are bound for good.** A re-registered login cannot pass for its
  previous holder. Signed-in actors carry the provider's name
  (`corp:alice`), and admin-created actors may not contain `:` in their
  first segment, so neither can take the other's. Two accounts share an
  actor only when an admin links them. Only `revoke --account … --forget`
  releases a binding.
- **Tokens expire and rotate.** Access tokens last `token_ttl` (default 1
  hour), and each refresh decides again. Refresh tokens rotate at every
  refresh and work once: a copy used after the original (or the original
  after a copy) revokes the sign-in. A sign-in lasts at most
  `refresh_limit` (30 days) and ends after `refresh_idle` (7 days) unused.
  An account keeps at most 20 live sign-ins per client.
- **Refreshes cannot see everything.** A refresh has no fresh ID token, so
  rules by email or group keep a sign-in while that rule is unchanged:
  someone a provider stops listing keeps access until their next sign-in
  (at the latest `refresh_limit`), unless an authorizer, which is asked at
  every refresh, refuses them. Revoke to cut someone off at once.
- **The device flow can be phished** (RFC 8628 §5.4): whoever enters a
  code gets the token of the sign-in that showed it. Enter only codes your
  own `bd remote login` just showed you.
- **Saved tokens serve every process of that user on that machine**,
  agents included: `kind = "human"` lets those agents resolve human gates.
- **An authorizer decides access, not identity.** Its answer is parsed
  strictly and fails closed, and what it may grant is capped by
  `auth.toml` (`max_role` write, no `human`, unless allowed), so a broken
  or compromised authorizer cannot hand out admin tokens or open human
  gates. It never sees a provider's tokens. A command runs with a cleared
  environment, in a process group killed once it answers or times out; a
  URL needs https (http only to this machine), gets a bearer token, and no
  redirect is followed. Run `bd serve`, and so the authorizer, as an
  unprivileged user.

## OAuth for MCP clients

With `[oauth]`, `bd serve` is an OAuth 2.1 authorization server for MCP
clients that sign people in ([Signing in with
OAuth](mcp.md#signing-in-with-oauth)).

- **Where people are sent back.** Only to redirect URIs `[oauth]` allows:
  `redirect_uris` exactly; https on the hosts of `redirect_hosts` (any
  path: anyone who registers a client may name any page there, so prefer
  `redirect_uris`, and `registration = false` where clients come with
  metadata documents); or, with `loopback_redirects`, http to the person's
  own machine (any local program can listen there, so turn it on only for
  desktop clients that need it). A client's redirect URI must also match
  one it registered or its metadata document names, and is checked against
  `[oauth]` again before a code is issued.
- **The person sees what they approve.** The consent page names the client
  and where its details come from: its metadata document's full URL (which
  says only who can serve a file there), or, for a registered client, a
  warning that anyone can register under any name. It shows the full
  redirect URI, warning when that is the person's own machine or a site
  other than the document's, plus the workspace, the actor, the access and
  how long it lasts. Client names may not hold direction controls,
  invisible characters or spaces other than ASCII's, which could make one
  name pass for another (joiners between visible characters and emoji
  selectors are allowed). A logo is shown only from a metadata document,
  fetched with it and inlined, so the browser asks no other site for
  anything and the logo cannot change between fetches. How the server is
  set up stays off the pages; the consent page names only what let the
  person in.
- **The pages are locked down.** A strict Content Security Policy (styles
  and the one script by hash, images only inline), no framing, and
  referrer policy `same-origin`, so a provider's code and state in a
  callback URL reach no other site.
- **Each step is bound to the browser.** The authorization is bound to the
  browser that started it by a `SameSite=Lax`, `HttpOnly` cookie
  (`__Secure-bd_oauth` on https). Once the person has signed in, the
  consent is bound by a cookie of its own (`bd_consent_<id>`, scoped to the
  consent endpoint), so a cookie value known before sign-in is good for
  nothing. The consent form also refuses a post that does not say it came
  from the page (an `Origin` of the server or `Sec-Fetch-Site:
  same-origin`). The `__Secure-` prefix is used rather than `__Host-`
  because the cookies are scoped to the issuer's path.
- **Against DoubleClickjacking**, the consent form is not sent until the
  page has had focus for 600 ms; the buttons stay enabled for screen
  readers and voice control.
- **Posted provider answers** (`form_post`) carry no `SameSite=Lax` cookie,
  so bd relays only their code, state, error and issuer to the callback as
  a GET, where the cookie and state are checked as usual. Providers not
  configured for it cannot post.
- **Consent comes after signing in.** bd sends the person to the provider
  first, because it uses the provider only to learn who they are: the
  provider grants the client nothing, and bd's consent page, never
  skipped, comes before any code reaches the client.
- **Codes and tokens.** Codes need PKCE (`S256`), last 5 minutes and work
  once; the same code sent again by its own client, with its PKCE
  verifier, revokes the tokens it issued. Tokens are bound to one
  workspace's MCP endpoint (RFC 8707), so they work for its tool calls
  only, which never carry admin or human rights. Refresh tokens rotate with
  no grace period. `bd serve token revoke --client <client_id>` revokes
  every token of a client.
- **Bearer tokens.** Whoever holds a token may use it: tokens are not
  bound to the client holding them (DPoP, mutual TLS), which MCP clients
  do not send. Rotation stands in for that for public clients' refresh
  tokens (RFC 9700 §4.14.2), and access tokens last `token_ttl` and work
  only at their endpoint.
- **Client metadata documents** are fetched over https from public
  addresses only (no loopback, private, link-local or other reserved
  address, checked as the connection is made, so a name cannot resolve to
  a public address for the check and a private one for the fetch), without
  redirects or a proxy, at most 8 KiB in 5 seconds, four hosts at once and
  one fetch per host. A logo is fetched the same way, at most 64 KiB, and
  kept only if its bytes are a PNG, JPEG, GIF or WebP image (no SVG). A
  document is kept for its max-age (at most an hour), and used for up to
  an hour past it only while a fetch from its host is already under way;
  when its host does not answer, the authorization fails. Of the 256
  documents kept in memory, approved clients' go last.
- **Unauthenticated endpoints are bounded.** Registration, authorization,
  the token endpoint and the device flow need no token. At most 500
  registered clients are kept (a new one drops the oldest never used).
  Before anyone signs in, an authorization keeps nothing on the server:
  its state is sealed (ChaCha20-Poly1305, with a key of the running
  server's) into the provider-choice link and a cookie of its own, so no
  flood fills a table and another browser that learns a flow's link or
  state can neither use nor end it. Consents and codes, which only
  accounts the rules let in reach, are kept up to 1024 each. Refreshes run
  in slots of their own. The authorization endpoint does not tell which
  workspaces exist before the rules let an account in. bd does not
  rate-limit these endpoints: do that per address at the proxy ([Behind a
  proxy](mcp.md#behind-a-proxy)).

## What bd keeps about people

bd keeps what it needs to tell who may call it, and no more (data
minimization, as in GDPR Art. 5(1)(c) and OIDC Core §17.1).

- **`<root>/server.db`** holds, for each account that signed in, its
  provider, issuer and subject, its actor, its latest login and when it was
  first and last seen; for each token, the hashes of its secrets, its
  actor, role, workspaces and account; and the registered OAuth clients.
  It never holds a token's secret, a provider's tokens, an ID token or its
  claims, a name from a provider, or an email. The only name is one an
  admin gives an account (`bd serve token name`), erased with it.
- **Logins are never emails.** An account's login is the provider's
  `preferred_username` unless that is an email (or otherwise unsuitable),
  else a pseudonym (`u-` and 12 hex digits of a hash of its issuer and
  subject). Actors are written into workspace histories for good, so no
  email becomes one. A verified email is shown on the consent page and
  sent to the authorizer at sign-in, and kept by neither bd nor its log.
- **Retention.** A token is deleted a week after it ends (revoked, or
  expired and no longer refreshed). An account stays until an admin
  releases it, so that a login given up and taken by someone else never
  passes for its previous holder: the binding is a security record, and
  its login and dates are all it holds. A registered OAuth client never
  used within a day, or unused for 90 days, is deleted.
- **Erasure.** `bd serve token revoke --account <login> --forget` deletes
  the account and every token of it. Deleted rows are overwritten
  (`secure_delete`) and the write-ahead log is emptied, so nothing of them
  stays in the database's files (if `bd serve` is reading at that moment,
  its next checkpoint does it, and the command says so). A provider's
  `account-deleted` notification erases an account the same way. Workspace
  histories keep the actor; copies outside `server.db` (logs, backups) are
  the admin's to expire.
- **Audit trail.** `server.db` records each sign-in, token created,
  refresh, revocation (and why), account forgotten, linked or named, and
  client registered, in the same transaction as the change, for 90 days
  (client registrations, which anyone may make: the latest 5000).
  `bd serve token events` shows it. An event names the actor, provider,
  subject, token and client, never a secret or an email. Forgetting an
  account erases its events too, leaving one that says an account of that
  provider was forgotten, and why.
- **Logs.** `bd serve` logs sign-ins, refreshes, refusals and revocations
  with the provider, subject, login, actor and token name, never a secret,
  a hash or an email. An erased account is not named by its subject. An
  authorizer's reasons and stderr are logged with anything shaped like an
  email replaced by `<email>`. The address a connection came from (a
  proxy's, behind one) is on request lines, refusals and connection-limit
  warnings. `GET /metrics` holds counts only. Keep logs only as long as
  needed, readable by the admin only.
- **At rest.** bd relies on file permissions: `server.db` is created
  0600, and the root should be 0700. Use disk encryption where the machine
  or its disks could be taken, and keep backups encrypted and private: a
  backup of `server.db` holds the accounts and audit trail as they were,
  including accounts forgotten since, so keep only as many copies as
  needed.

## Clients

- **`$BD_TOKEN` goes only where `--remote` or `$BD_REMOTE` points**, never
  to a URL from a `.bd/remote.toml`, which a cloned repository could set
  to its own server ([Clients](remote.md#clients)).
- **Saved tokens** live in `$XDG_CONFIG_HOME/bd/credentials.toml`
  (`%APPDATA%\bd\credentials.toml` on Windows), mode 0600 in a 0700
  directory on Unix; bd refuses a file its group or others can access. A
  saved token is bound to the CAs it was checked against, so a checkout
  naming its own CA for a server cannot redirect it.
- **Tokens never appear on the command line or in output.** `bd remote
  login` reads them from stdin or a prompt without echo; `bd remote show`
  and `bd info` show a token's name, role, kind and expiry, never its
  secret.
- **Output never drives a terminal.** Control and bidirectional formatting
  characters in stored text or a server's answer are printed as `\uXXXX`,
  by the command and again by the client.

## Agent assets

A workspace can serve skills and MCP server definitions to agent harnesses
([Agent assets](agents.md)).

- **Skills and MCP definitions wait for a person.** Skills are code: they
  can run commands, register hooks and pre-approve tools, as an MCP
  definition runs a command. A pull, hook or watch never writes a new or
  changed skill file, executable bit or MCP definition; `bd agents approve`
  shows each in full or as a diff, asks on a terminal, and refuses agent
  sessions and non-terminals with no bypass. A client records only hashes
  it checked against the texts, never a manifest's word for them, and
  writes without approval only the very bytes approved. Guard `.bd/agents`
  on the server like a code deployment all the same ([Trust](agents.md#trust)).
- **No secrets on the server.** MCP servers run and authenticate on the
  client; bd never handles MCP credentials.
- **Strict sets.** Sets are validated on the server and again by clients
  before anything is written: no settings or hooks in MCP files, portable
  paths, symlinks contained in `.bd/agents`, size limits. A pull never
  follows a symlink in a skill directory and never overwrites files it did
  not write.

## Release binaries

Each release has a `SHA256SUMS` file and a signed build-provenance
attestation per archive; [Install](install.md#prebuilt-binaries) shows how
to check both.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through the repository's [private vulnerability
reporting](https://github.com/quanghle/bd-sync/security/advisories/new)
(the Security tab, then "Report a vulnerability").
