# Security

This page collects bd's trust boundaries and safeguards in one place. Each
section links to the page with the details.

## Local workspaces

- **No authentication.** Any process that can open `.bd/bd.db` can read and
  change everything in it. Actor names (`--actor`, `$BD_ACTOR`, the derived
  `<user>/<session>`) label who did what and decide who holds a claim, but
  are not verified: claim ownership keeps cooperating agents from ending
  each other's work by mistake, not a hostile process out
  ([Actors](concepts.md#actors), [Claims](concepts.md#claims-leases-and-recovery)).
- **Nothing leaves the machine.** Logs, metrics and health checks are local;
  a remote workspace talks only to its own `bd serve`
  ([Observability](observability.md)).
- **GitHub gates run `gh` with the credentials of whoever checks them**, so
  `gate.repos` lists the repositories a gate may name; a gate naming another
  is refused when written and escalated instead of probed
  ([Gates](playbooks.md#gates)).

## Remote server

A bd server is the trust boundary of a remote workspace: tokens decide what
each client may do, and the checks run in the engine, so a `bd batch` or a
playbook run gets the same answer as a single command
([Remote server](remote.md)).

- **Transport.** `bd serve` refuses plain HTTP on a non-loopback address
  unless given `--insecure-http`: give it a certificate, or keep it on
  loopback behind a TLS-terminating proxy. Clients refuse plain `http://` to
  a non-loopback host unless `BD_INSECURE_HTTP=1`
  ([Server](remote.md#server)).
- **Access tokens.** `<root>/server.db` (SQLite, mode 0600) holds token
  hashes only, with the accounts and OAuth clients; each
  secret is printed once, at creation. `bd serve token revoke` takes effect
  at once, with no restart.
- **Roles and kinds.** A token's role (`read`, `write`, `admin`) limits the
  commands it runs; a `read` token's database connection is query-only. Its
  kind (`agent` or `human`) says who holds it: only human tokens open human
  gates, so keep them out of agents' environments
  ([Clients](remote.md#clients)).
- **Overrides need the right token.** Taking over another actor's live claim
  needs `--take-over` and an admin token (a token's own actor and its
  sub-actors need only `--take-over`). Getting past a human gate early needs
  a human token. Only admins change `metadata.playbook` on existing issues,
  set configuration (`gate.repos` included), import, prune events or run
  `doctor`.
- **Actors are bound to tokens.** A token acts as its actor or its
  sub-actors `<actor>/<name>`; `--actor` and `$BD_ACTOR` may name nothing
  else. The server's own actor, `bd-serve`, which runs its background jobs,
  is reserved: no token may act as it.
- **Claim limits.** `max_claims` (per token, or per sign-in rule)
  caps the open issues a token's actors hold, so that no one takes the whole
  ready queue. It guards against greed, not malice.
- **Resource limits.** Request bodies (`--max-body-mib`, default 64), a
  shared memory budget, at most 8 streaming reads, at most 4 requests
  bringing their own playbooks, and at most `--max-followers` waiting
  requests; slow or stalled readers lose their answer. Excess requests are
  answered 503, which clients retry ([Followers](remote.md#followers)).
- **The server's host is not limited by tokens.** `bd` run on the host opens
  `bd.db` directly; guard the root directory like the database it is.
- **Backups hold everything.** On Unix, backup files are created 0600 and the
  directories bd creates 0700; keep them on another disk or ship them
  elsewhere ([Background jobs and backups](remote.md#background-jobs-and-backups)).

## Signing in

Sign-in lets people get their own tokens, with GitHub or OpenID Connect
providers that `<root>/auth.toml` names, under its rules or the
admin's authorizer ([Signing in](remote.md#signing-in)).

- bd proves who signed in itself, and binds each account to its actor by
  its provider's issuer and its id there (a GitHub user id, an OIDC `sub`),
  never by its login or email, which can change or pass to someone else.
- OIDC ID tokens are checked strictly: RS256 or ES256 only (never `none`
  or a shared secret), signed by a key of the provider's published set
  fetched over https, from its issuer, for bd's client alone (`aud` exactly
  its client ID, `azp` when present), not expired, and with the browser
  sign-in's nonce. A browser sign-in's answer that names another issuer
  (RFC 9207 `iss`), or lacks it where the provider says it sends it, is
  refused before its code is used; each provider also has a callback of its
  own. An email counts only if the provider verified it, and providers'
  error codes reach messages and the log only when they are plain text. OIDC providers' client secrets are files under
  the root, read by `bd serve` only.
- At refreshes, OIDC providers (and GitHub without its App) are not asked
  again: the authorizer decides on the account as it signed in, and rules by
  subject are applied again, but any other rule keeps the sign-in while it
  is unchanged, so removing someone at the provider takes effect when the
  authorizer refuses them, or at their next sign-in (at the latest
  `refresh_limit`).

- The server runs GitHub's device flow with an OAuth or GitHub App client ID,
  no secret. The account's GitHub token reads its account and memberships
  during the sign-in and is never stored or logged.
- With the GitHub App's key, refreshes ask GitHub afresh as the App, with installation tokens minted
  from its private key (`private_key`). Keep the key file, like every
  sign-in secret (client secrets, the authorizer's token), mode 0600, readable by `bd serve` only; whoever
  has it can read what the App may (organization members). Give the App
  nothing but **Members** (read).
- An account no rule lets in gets nothing. An `anyone = true` rule must be
  the last, and its tokens read by default, may write at most, and are
  always `agent` tokens. `min_account_age` keeps out accounts made on the
  spot; `deny` (GitHub user ids, or an OIDC provider's subjects) keeps out
  an account for good, its sign-ins ending at their next refresh (revoke
  its tokens to end them at once).
- Each account is bound to its actor for good at its first sign-in, so a
  renamed or re-registered login cannot pass for the previous holder. Two
  accounts share an actor only when an admin links them
  (`bd serve token link`), as one person's.
  Actors carry the provider's name (`github:alice`, `google:u-3f9a2c1e7b04`),
  so no provider's users can take an admin-created actor or another
  provider's, and `bd serve token create` refuses actors with a `:` in
  their first segment, so no admin's token keeps an account out. Only `bd serve token revoke --account <login> --forget`
  releases a binding.
- Sign-in access tokens expire (`token_ttl`, default 1 hour), and each
  refresh applies the rules again (where the provider is not asked again, a
  rule other than by subject keeps a sign-in while that rule is unchanged,
  as bd keeps no claims: see
  [Refreshing](remote.md#refreshing-sign-ins)), so someone who leaves a
  GitHub organization (with the App), or whom an authorizer or a subject
  rule no longer lets in, loses access within `token_ttl`; someone a
  provider stops listing under any other rule keeps it until their next
  sign-in, at the latest `refresh_limit`. Refresh tokens rotate at every refresh
  and work once: a copy used after the original (or the original after a
  copy) revokes the sign-in. A sign-in is refreshed for at most
  `refresh_limit` (30 days), and not after `refresh_idle` (7 days) unused.
  An account keeps at most 20 live sign-ins at each client (and 20 of
  `bd remote login`); signing in again revokes the oldest.
  `server.db` keeps only hashes of both. `bd remote logout` and a
  replacing sign-in revoke them on the server; `bd serve token revoke` ends
  refreshes too.
- Whoever started a sign-in gets its token: enter only codes shown by one's
  own `bd remote login --provider <name>`.
- Tokens saved by `bd remote login` serve every process of that user on that
  machine, agents included: a rule's `kind = "human"` lets those agents
  resolve human gates too.

## What bd keeps about people

bd keeps what it needs to tell who may call it, and no more: OIDC Core §17.1
and the GDPR's data minimization (Art. 5(1)(c)) are the guide.

- **`<root>/server.db`** (SQLite, mode 0600) holds, for each account that
  signed in, its provider, issuer and subject (the provider's stable id:
  OIDC Core §5.7), its actor, its latest login and when it was first and
  last seen; for each token, the SHA-256 of its secrets, its actor, role,
  workspaces and that account; and the OAuth clients that registered. It
  never holds a token's secret, a provider's tokens or ID tokens, an ID
  token's claims, a name from a provider, or an email: only a name an
  admin gives an account (`bd serve token name`), erased with it.
- **Logins are never emails.** A GitHub account's login is its public user
  name. An OIDC account's is its provider's `preferred_username`, unless
  that is an email, else a pseudonym of the account (`u-` and 12 hex digits
  of a hash of its issuer and subject), so that no email becomes an actor:
  actors are written into workspaces' histories (events, assignees,
  comments), which keep them for good. The email an OIDC provider verified
  is shown on the consent page and sent to the authorizer at sign-in, and
  kept by neither bd nor its log.
- **Retention.** A token is deleted a week after it ends (revoked, or
  expired and no longer refreshed), at the server's next write. An account
  stays until an admin releases it, so that a login given up and taken by
  someone else never passes for its previous holder: that binding is a
  security record, and its login and dates are all it holds. A registered
  OAuth client never used a day after registering, or unused for 90 days,
  is deleted at the next registration.
- **Erasure.** `bd serve token revoke --account <login> --forget` deletes
  the account and every token of it. Deleted rows are overwritten
  (`PRAGMA secure_delete`) and the write-ahead log is emptied after the
  erasure, so nothing of them stays in the database's files (if `bd serve`
  is reading at that moment, its next checkpoint does it, and the command
  says so). Workspaces' histories keep the actor, which is not an email, and
  copies outside `server.db` (logs, backups) are the admin's to expire.
  With `account_events`, an Apple Account deleted at Apple is forgotten the
  same way, and one that revoked its consent is signed out
  ([Sign in with Apple](remote.md#sign-in-with-apple)).
- **Audit trail.** `server.db` records each sign-in, token created,
  refresh, revocation (with why: by its holder, an admin, a reused refresh
  token, the rules, its provider), account forgotten and client registered,
  in the same transaction as the change, for 90 days (client registrations,
  which anyone may make, the latest 5000 only); `bd serve token events`
  shows it. An event names the actor, the provider and subject, the
  token and the client, never a secret or an email. Forgetting an account
  erases its events too, leaving one that says an account of that provider
  was forgotten, and why.
- **Logs.** `bd serve` logs sign-ins, refreshes, refusals and revocations
  with the provider, the account's subject and login (a user name or a
  pseudonym), its actor and token names, and never a secret, a token's
  hash, or an email. An authorizer's refusal reasons and stderr go to the
  log as it wrote them, so an authorizer should not write emails there
  either. Keep logs only as long as needed (OWASP Logging Cheat Sheet,
  ASVS 16.1.1), readable by the admin only.
- **At rest.** Encryption at rest is a choice for the threat model (GDPR
  Art. 32; OWASP Cryptographic Storage). bd relies on file permissions:
  `server.db` is created 0600, and `bd serve` warns if its root is open to
  other users (chmod 700 it), since the workspaces' databases are there
  too. Use disk encryption where the machine or its disks could be taken,
  and keep backups encrypted and private: `--backup-dir` copies
  `server.db` too (0600, in 0700 directories), so a copy holds the
  accounts and the audit trail as they were, including accounts forgotten
  since; keep only as many copies as needed (`--backup-keep`).

## OAuth for MCP clients

With `[oauth]`, `bd serve` is an OAuth 2.1 authorization server for MCP
clients that sign people in, such as ChatGPT
([Signing in with OAuth](mcp.md#signing-in-with-oauth)). People sign in with
GitHub or an OIDC provider, under the rules or the authorizer, as
above.

- **Secrets.** GitHub's web flow needs a client secret of the GitHub App
  (`client_secret_file`); keep it, like the private key, mode 0600 and
  readable by `bd serve` only. The account's GitHub token is used during
  the sign-in only, as for the device flow. An OIDC provider's client
  secret file, or the `.p8` key that signs Apple's (`signed_secret`), is
  kept the same way; each secret signed from that key lasts a few minutes.
- **Where people are sent back.** Only to redirect URIs `[oauth]` allows:
  those of `redirect_uris` exactly, https on the hosts of `redirect_hosts`
  (any path: anyone who registers a client may name any page there, so
  prefer `redirect_uris`, and `registration = false` where clients come
  with metadata documents, as ChatGPT's and Claude's do), or, with
  `loopback_redirects`, http to the person's own machine. Any local program can listen on a
  loopback port, so turn that on only for desktop clients that need it.
  A client's redirect URI must match one it registered or its metadata
  document names.
- **The person sees what they approve.** The consent page names the client
  and where its details come from: its metadata document's full URL (which
  says only who can serve a file there, not who wrote it), or, for a
  registered client, a warning that anyone can register under any name. It
  shows the full redirect URI the browser returns to, warning when that is
  the person's own machine (any program there could pose as the client) or
  a site other than the document's, the workspace, the actor, the access
  granted and how long it lasts. Client names may not hold direction
  controls, invisible characters or spaces other than the ASCII one, which
  could make one name pass for another; joiners (ZWJ, ZWNJ) between
  visible characters and emoji presentation selectors after one, which
  scripts and emoji need, are allowed. A metadata document whose name
  breaks this rule is shown by its host. It shows a logo only from a
  client's metadata document, which the document's site vouches for, never
  one a registered client claims.
  bd fetches that logo with the document and puts it in the page, so the
  browser asks no other site for anything and the logo cannot change
  between fetches (CIMD draft section 8.8). How the server is set up
  (`auth.toml`, other workspaces, limits, what its log says) stays off the
  pages; the consent page names only the rule that let the person in. The pages are served with
  a strict Content Security Policy (styles and the one script by hash,
  images only inside the page) and may not be framed. Their referrer
  policy is `same-origin`, so the provider's code and state in a callback
  URL reach no other site (not `no-referrer`, under which browsers would
  send the consent form with `Origin: null`). A provider's answer posted
  to a callback (`form_post`, Apple's; refused for providers not
  configured with it) arrives without the sign-in's
  `SameSite=Lax` cookie, so bd sends only its code, state, error and
  issuer on to the callback as a GET, where the cookie and state are
  checked as for any other provider. The consent form refuses a
  post unless it says it came from the page (an `Origin` of the server,
  `Sec-Fetch-Site: same-origin`, and at least one of them), and from any
  browser but the one that started the authorization (a `SameSite=Lax`,
  `HttpOnly` cookie, named `__Secure-bd_oauth` on https so a sibling host
  on plain http cannot plant it, and given a new value once the person
  signed in, so a value known before is good for nothing). The prefix is `__Secure-` rather than `__Host-` because the cookie is
  scoped to the issuer's path, which `__Host-` forbids; a sibling https
  host could still set one for the parent domain, which gains it nothing
  over sending the person the authorization URL itself. Before a code is
  issued, the redirect URI is checked against `[oauth]` again, in case it
  changed during the sign-in. Framing rules do not stop DoubleClickjacking
  (a page asking for a double click that brings the consent page forward
  under the second), so the consent form is not sent until the page has
  had focus for 600 ms; the buttons stay enabled, for screen readers and
  voice control.
- **An authorizer decides access, not identity.** With `[authorizer]`, the
  admin's command or HTTPS endpoint decides who may use which workspace at
  every sign-in and refresh. bd still proves who signed in and binds the
  actor; the authorizer gets identity data only (never a GitHub token), its
  answer is parsed strictly and fails closed, and what it may grant is
  capped by `auth.toml` (`max_role` write, no `human`, unless allowed), so a
  broken or compromised authorizer cannot hand out admin tokens or open
  human gates. Its refusal reasons stay in the server log. A command runs
  with a cleared environment, on Unix in a process group of its own that is killed
  once it answers or runs out of time (nothing it starts outlives it or holds
  bd past its timeout); run `bd serve`, and so it, as an unprivileged user; a URL needs https (http only to loopback),
  gets a bearer token, and redirects are not followed.
- **The device flow can be phished.** `bd remote login` gets the token of
  whoever enters its one-time code at the provider (RFC 8628 section 5.4):
  someone who sends you a code and a link to enter it at gets your access.
  Enter only codes your own `bd remote login` just showed you; the provider's
  page names the application asking.
- **Secret files.** The GitHub App key, client secrets and the authorizer's
  token are files under the root; `bd serve` warns at start about any its
  group or others may read. Keep them mode 0600.
- **Consent comes after signing in.** The MCP specification asks a
  proxy in front of a third-party authorization server to get consent for
  each client before sending the person on to it. bd sends the person to
  the provider first, because it uses the provider only to learn who they
  are: the provider grants the client nothing, and bd's consent page, shown every time and
  never skipped, comes before any code reaches the client.
- **Codes and tokens.** Codes need PKCE (`S256`), last 5 minutes and work
  once; a code sent again revokes the tokens it issued. Tokens are bound to
  one workspace's MCP endpoint (RFC 8707), so they work for its tool calls
  only, which never carry admin or human rights. Refresh tokens rotate at
  every refresh with no grace period: one used twice revokes the sign-in.
  `bd serve token revoke --client <client_id>` revokes every token of a
  client, and `--account <login>` every token of an account.
- **Client metadata documents.** bd fetches a client's metadata document
  over https from public addresses only (no loopback, private, link-local
  or other reserved address, checked as it connects, so a name cannot
  resolve to a public address for the check and a private one for the
  fetch), without redirects or a proxy, at most 8 KiB in 5 seconds, four
  hosts at once and one fetch per host. A document fetched before is used
  for up to an hour past its time only while it cannot be fetched because
  every fetch, or another from its host, is under way; when its host does
  not answer, the authorization fails (CIMD draft section 5.1).
  Those of clients someone approved go last when the
  cache (256 documents, in memory) is full. So anyone naming many
  documents keeps out only clients no one approved since `bd serve`
  started, and slow hosts holding every fetch only clients whose document
  was not fetched or approved in the past hour, unless the client's own
  host has since refused its document or said not to cache it (which
  ends both). A logo is fetched the same way, at most 64 KiB, and kept only
  if its bytes are a PNG, JPEG, GIF or WebP image (no SVG).
- **Bearer tokens.** Access and refresh tokens are bearer tokens: whoever
  holds one may use it. They are not bound to the client holding them
  (DPoP, RFC 9449; mutual TLS, RFC 8705), which MCP clients do not send.
  RFC 9700 §4.14.2 accepts rotation instead for public clients' refresh
  tokens, and bd rotates them, revoking a sign-in whose spent refresh token
  comes back; access tokens last `token_ttl` (an hour by default) and only
  at the MCP endpoint they were issued for.
- **Unauthenticated endpoints.** Registration, authorization, the token
  endpoint and the device flow need no token. bd bounds what they keep:
  500 registered clients (a new one drops the oldest never used). A
  sign-in before anyone signed in keeps nothing on the server: what it
  needs is sealed (ChaCha20-Poly1305, with a key of the running server's)
  into the link that chooses a provider and into a cookie of its own
  while at the provider, so no flood fills a table and none drops a
  sign-in under way, and another browser that learns a flow's link or
  state can neither use it nor end it. Consent pages and codes, which only
  accounts the rules let in reach, are kept up to 1024 each, the oldest
  going first. Refreshes run in slots of their own, which anonymous
  sign-ins never take, and a refresh token of no sign-in is refused before
  any; an OIDC provider whose discovery or keys could not be had is not
  asked again for 30 seconds, and its keys are fetched one request at a
  time. One address holds at most 64 connections (a proxy on the same
  machine is not counted). A code sent again revokes the token it issued
  only when its client sends it with its PKCE verifier. The authorization endpoint
  does not tell which workspaces exist before the rules let an account in
  (the device flow of `bd remote login --provider github` does, before sending
  anyone to GitHub). It does not
  rate-limit them: do that per address at the proxy ([Behind a
  proxy](mcp.md#behind-a-proxy)), on every path with `/oauth/` or
  `/v2/auth/` in it:
  they answer under the public URL's path (`/bd/oauth/…`) or with it
  stripped (`/oauth/…`), and a proxy that strips the prefix turns
  `/bd/bd/oauth/…` into the former.

## Clients

- **`$BD_TOKEN` goes only where `--remote` or `$BD_REMOTE` points**, never
  to a URL from a `.bd/remote.toml`, which a cloned repository, a pull
  request or a submodule could set to its own server
  ([Clients](remote.md#clients)).
- **Saved tokens** live in `$XDG_CONFIG_HOME/bd/credentials.toml`
  (`%APPDATA%\bd\credentials.toml` on Windows). On Unix the file is mode
  0600 in a directory created 0700, and bd refuses a file other users can
  read. A saved token is bound to the certificate authorities it was checked
  against, so a checkout naming its own CA for a server cannot redirect it.
- **Tokens never appear on the command line or in output.** `bd remote
  login` reads them from stdin or a prompt without echo; `bd remote show`
  and `bd info` show a token's name, role, kind and expiry, never its secret.
- **Printed output never drives a terminal.** Control characters and
  bidirectional formatting characters in stored text or a server's answer
  are printed as `\uXXXX`, by the command and again by the client.

## Agent skills and MCP definitions

A workspace can serve skills and MCP server definitions to agent harnesses
([Agent skills and MCP definitions](agents.md)).

- **Skills and MCP definitions wait for a person.** Skills are code: they
  can run commands, register hooks and pre-approve tools, as an MCP
  definition runs a command. A pull, hook or watch never writes a new or
  changed skill file, executable bit or MCP definition; `bd agents approve`
  shows each skill file by file (in full, or as a diff) and each
  definition, asks on a terminal, and refuses agent sessions and
  non-terminals with no bypass ([Approving skills and MCP
  definitions](agents.md#approving-skills-and-mcp-definitions)). A client
  records only hashes it checked against the texts they name, never a
  manifest's word for them, and writes without approval only the very
  bytes approved, line endings included. Guard
  `.bd/agents` on the server like a code deployment all the same
  ([Trust](agents.md#trust)).
- **No secrets on the server.** MCP servers run and authenticate on the
  client; bd never handles MCP credentials.
- **Strict sets.** Sets are validated on the server and again by clients
  before anything is written: no settings or hooks in MCP files, portable
  paths, symlinks contained in `.bd/agents`, size limits. A pull never
  follows a symlink in a skill directory and never overwrites files it did
  not write.

## Release binaries

Each release has a `SHA256SUMS` file and a signed build-provenance
attestation per archive; [Install](install.md#prebuilt-binaries) shows how to
check both.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through [GitHub's private vulnerability reporting](https://github.com/quanghle/bd-sync/security/advisories/new)
(the repository's Security tab, then "Report a vulnerability").
