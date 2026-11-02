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
- **`bd github` runs `gh` with the credentials of whoever runs it** (through
  `bd serve`, the server's, and only with an admin token), and can publish
  workspace content: `github.repos` lists the repositories it may sync,
  checked before any GitHub call, `push --create` publishes only issues
  carrying the `--label` it names, and an issue marker links a bd issue only
  on a GitHub issue opened by the account `gh` is signed in as
  ([GitHub Issues sync](github.md)).

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
- **Approval link key.** `<root>/approval-links.key` (mode 0600) seals
  the requests in close and discard approval links; whoever reads it can
  forge them, so guard it like `server.db` ([Approving a close or discard
  in the browser](#approving-a-close-or-discard-in-the-browser)).
- **Roles and kinds.** A token's role (`read`, `write`, `admin`) limits the
  commands it runs; a read token's database connection is query-only. Its
  kind (`agent` or `human`) says who holds it: only human tokens open
  human gates, so keep them out of agents' environments.
- **Overrides need the right token.** Taking over another actor's live
  claim needs `--take-over` and an admin token (unless the claim is held by
  the token's own actor or a sub-actor). Getting past a human gate needs a
  human token, of one of its approvers when it names them. Only admins change `metadata.playbook` on existing issues,
  set configuration (`gate.repos` included), rename the issue prefix,
  import, sync with GitHub (`bd github`), prune events or run `doctor`.
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
  secret lasts 5 minutes. Instead, the admin's [secrets
  command](sign-in.md#secrets-from-a-command) can fetch them from a vault:
  then they are kept in memory only, never written to a file nor logged by
  bd (the command's stderr is logged when it fails, so it must print none
  there), and used
  at most `max_stale` past their `ttl` while the command fails. While it
  has no answer, the sign-in steps needing them fail closed (503; a
  refresh fails as when a provider does not answer, 502), telling
  requests nothing of why, and the rest of the server runs on.
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

## Approving gates in the browser

With `[oauth]` and `--public-url`, people approve human gates at
`<public-url>/w/<workspace>/gates/<gate id>` after signing in with the
authorization server's providers ([Approving human gates in the
browser](sign-in.md#approving-human-gates-in-the-browser)). The approval is
a human-gate override without a token, so it gets the protections of the
consent page and more.

- **Only people the server would give a human token.** The account is
  judged for the gate's workspace as at a sign-in (`deny`, then the
  authorizer or the rules); only a grant of kind `human` may approve, so
  an agent with an agent-kind grant cannot approve with its own account,
  and an authorizer that may not grant `human` lets no one approve. The
  account is bound to its actor and the binding audited, and no token is
  issued.
- **Login CSRF and flow confusion.** Before sign-in nothing is kept on the
  server: the flow, with what comes after it (the gate, or an MCP client's
  authorization), is sealed with the running server's key, under a label
  of its own for each step and kind, so a flow started for one cannot
  finish as the other. As for the MCP flow, it is bound to the browser
  by the `bd_oauth` cookie and a per-flow cookie with the state, PKCE
  verifier and nonce, and a provider's answer naming another issuer is
  refused.
- **CSRF and clickjacking.** The approval page has a strict Content
  Security Policy (style and its one script by hash, `form-action 'self'`,
  `frame-ancestors 'none'`), and its form is not sent until the page has
  had focus for 600 ms. The `POST` needs an `Origin` of the server or
  `Sec-Fetch-Site: same-origin` (neither saying otherwise), and a cookie
  of its own (`bd_gate_<suffix>`, `__Secure-` on https), `HttpOnly`,
  `SameSite=Strict` and scoped to the gate's path, whose value is known
  only after sign-in. The approval id lasts 10 minutes and works once; one
  posted from another browser is refused without being used up.
- **No existence leak.** The gate's path checks only the shapes of the
  workspace name and id and answers alike for any gate, or none, until the
  account is admitted with human access to that workspace. A gate is found
  by its exact id, never a prefix.
- **What is approved is shown.** The page names the workspace, the gate,
  what it holds back and the run it belongs to, and who the approval is
  recorded as. Titles, which agents write, are escaped, with control,
  direction and invisible characters shown as escapes, so they cannot fake
  the page; the gate posted is the one the approval id was issued for.
  The [approval packet](sign-in.md#approving-human-gates-in-the-browser)
  below them, the gate's, held work's and run's text and comments, is
  read only for a person who passed admission and the gate's checks
  (open, ready to approve, and one of its approvers when it names them),
  and is shown as untrusted, in a section of its own above the form:
  Markdown rendered by the server with raw HTML shown as text, images as
  their alt text (nothing fetched), only `http`/`https` and same-page `#`
  links active, control and invisible characters escaped, under the same
  Content Security Policy and with no script of its own. It is bounded,
  each omission named with `bd show`, and is not a signed record: the
  approval is checked against the gate as it is when posted.
- **Approvers hold on every served path.** A gate's approvers are enforced
  in the engine on every path that can open a human gate or move work
  past it (`gate resolve`, `close`, pins, type changes, edges, moves,
  deletes, run closing, imports), alone, in batches and in playbooks, for
  tokens and browser approvals alike, admins included. A stored list that
  is not valid matches nobody. Only an approver's human token, any
  person's when there are none, or a human admin's may change the list,
  and the change is recorded in the gate's history.
- **OIDC approvers are bound to issuer and subject.** A login, and the
  actor bound at an account's first sign-in, prove nothing: an account
  that takes a login first squats the actor. So an account signed in with
  an OIDC provider matches only an [identity
  reference](playbooks.md#oidc-identity-references) to the exact issuer
  and subject of its ID tokens, never an actor approver, with a token, a
  refreshed token, a retry, a sub-actor, a linked account's shared actor
  or a browser approval alike, and no actor matches a reference. The
  reference comes only from the authenticated token's account or the
  account the browser sign-in admitted, never from the request; the
  browser approval keeps it in server memory from sign-in to the `POST`,
  and the final transaction checks the current approvers against it.
  `bd gate review` derives the same reference from the token's account in
  the `info` answer and applies the same rule, stopping when that account
  cannot be read. Approver lists that name OIDC accounts by actor fail
  closed until an authorized human replaces the list; bd converts nothing
  ([Approvers and OIDC accounts](sign-in.md#approvers-and-oidc-accounts)).
- **Checked again when posting.** The approval resolves the gate in one
  transaction that checks again that it is an open human gate, ready to
  approve (not deferred or blocked again since the page), and that the
  person may open it; otherwise it writes nothing. The `closed` event
  names the person's actor and `"via": "browser"`.
- **A passkey for every approval.** Signing in proves the account at the
  provider; the passkey proves that a person is at the device the account
  registered, each time. Every Approve runs a WebAuthn ceremony with user
  verification required, and the server verifies it before anything is
  approved, after every check above: the client data's type, the
  approval's own challenge (32 random bytes, kept in server memory with
  the approval and good once), the origin (exactly the server's public
  URL's), no cross-origin or `topOrigin` frame, the hash of the relying
  party id (the public URL's host), the user-present and user-verified
  flags, and for a registered passkey that it is the signed-in account's
  (by issuer and subject), its signature under the stored public key
  (ES256 or RS256), and a signature counter that, once non-zero, must
  grow, stored by compare-and-set so two posts of one assertion cannot
  both pass. Each form field counts only when it occurs exactly once, the
  approval id included, and is bounded in length before it is decoded
  (the whole `POST` is at most 16 KiB). There is no fallback: a missing or
  failed ceremony approves nothing (403), and the approval id, taken
  before the check, is used up. User verification is a fingerprint, a
  face or the device's PIN, as the authenticator offers; bd cannot tell
  which, or insist on a biometric. No attestation is asked for or checked:
  bd does not know which authenticator holds a passkey, and does not
  restrict authenticators.
- **Adding a passkey needs one of the account's, unless an admin allows
  it (the next item).** An account with 1 to 98 passkeys may add one at an
  approval, in the same `POST` as a verified assertion of one of its
  passkeys; new passkey fields on a page
  that did not offer adding are refused. The new passkey's registration
  is checked as a first one is (the client data's type, its own challenge,
  a second 32 random bytes kept and spent with the approval, the origin,
  no cross-origin frame, the relying party id hash, the user-present and
  user-verified flags, ES256 or RS256), and only after the assertion has
  passed. Then one `server.db` transaction checks that the account still
  exists, that the asserted passkey is still its own, that it holds fewer
  than 99 passkeys and that the new credential id is not registered, moves
  the asserted passkey's counter by compare-and-set, stores the new
  passkey and records a `passkey_registered` event naming both
  credentials' prefixes. A refusal at any of these checks stores no
  passkey, moves no counter and approves nothing. A workspace failure
  after that transaction (the gate no longer armed, the workspace busy,
  a refusal) keeps the added passkey and approves nothing, as a
  first-use registration is kept: accepted, since the person can approve
  again with either passkey.
- **An admin's allowance stands in for that passkey, once.** `bd serve
  passkey allow-add`, on the server host and never through a token,
  `/v2/exec` or MCP, allows an account with 1 to 98 passkeys to register
  one without an existing one, for 15 minutes unless told otherwise and
  at most an hour. An account has one allowance at most, a row of
  `server.db` that a second grant replaces and `--cancel` ends. Every check
  above that comes before the passkey is unchanged. The page then asks for
  a registration against a third challenge of its own, 32 random bytes kept
  and spent with the approval. Only `allow_*` fields in the `POST` select
  this path, and where the page was not opened under an allowance (an
  ordinary page, a first registration, a page offering the add, one opened
  before the grant) they are refused before anything else in the form is
  read. A `POST` that carries an assertion's fields as well is refused.
  The registration is checked as a first one is (the client data's type,
  that challenge alone, the origin, no cross-origin frame, the relying
  party id hash, the user-present and user-verified flags, ES256 or RS256).
  Then one `server.db` transaction checks that the account still exists,
  that the very allowance the page was opened under is still live (a
  cancel and a new grant make another one), that the account holds fewer
  than 99 passkeys and that the credential id is not registered, removes
  the allowance, stores the passkey and records a `passkey_registered`
  event naming the allowance. So two posts under one allowance register at
  most one passkey. A refusal at any of these checks stores nothing and
  approves nothing. The approval runs only after that commit, and a
  workspace failure after it keeps the passkey, with the allowance spent,
  and approves nothing: the person approves again with the new passkey.
  The page's second button, `Use an existing passkey instead`, is the
  ordinary assertion and leaves the allowance live. A live allowance
  always has a passkey beside it: `allow-add` refuses an account with
  none, and removing an account's last passkey ends its allowance in the
  same transaction, so a first registration cannot be followed by a
  second with no assertion. The allowance's id is no secret: it is never
  accepted from a form and never shown on a page.
- **A link carries one passkey's word to another device, once.** Provider
  account plus link is enough to register one passkey, for 15 minutes;
  neither alone does anything.
  - *Making one.* An approval page for an account with 1 to 98 passkeys and
    no live allowance has an unticked `make_link` box. The field is read
    first: where the page did not offer it (first registrations, 99
    passkeys, a live allowance), it is refused before anything else in the
    form is read, and a duplicate or any value but `1` is refused too. A
    link is made only in that `POST`, after the assertion (and with the add
    box the new passkey's checks) passed, and the passkey vouching for it
    is the asserted one, never one the form names. One `server.db`
    transaction moves that passkey's counter by compare-and-set and stores
    the link: a compare-and-set that moves nothing leaves no link, and a
    link that cannot be written moves no counter and approves nothing. The
    approval runs after that commit, and a workspace refusal keeps the link.
  - *The secret.* 32 random bytes, 64 hex characters, compared by SHA-256,
    which is all `server.db` keeps. It exists in the answer to that `POST`
    alone, with `Cache-Control: no-store`, and the approval id, taken before
    the check, is used up, so nothing shows it again: never in a cookie, a
    sealed flow, a redirect, an event or a log line. The URL comes from the
    configured public URL, never from `Host` or `X-Forwarded-*`.
  - *Opening one.* The secret is a URL fragment,
    `<public url>/oauth/passkey-link#<secret>`, which browsers send in no
    request line and no `Referer`, so a proxy's access log and a link
    preview's fetch do not see it. `GET` answers one constant page whatever
    the URL holds, without reading its query, and its script moves the
    fragment into a form and clears it from the address bar. A person
    presses the button, so a scanner that runs scripts starts nothing. The
    `POST`, whose body is the only request that carries the secret, is
    checked in this order, each before any lookup: approvals offered at all
    (else 404), a same-origin `Origin` or `Sec-Fetch-Site` and the
    browser-bound `bd_oauth` cookie (else one 403, whatever the link), a
    body of at most 1 KiB, a sign-in slot (else 503), usable sign-in
    settings, and one `link` field of exactly 64 lowercase hex characters.
    Only then is its hash looked up, in a unique index. A dead link gets one
    404 notice, keeps nothing, sets no cookie and starts no sign-in. A live
    one goes on to the sign-in with only the row's public id, sealed in a
    flow of its own kind, and is not spent. That flow goes on in
    `/oauth/choose`'s query, which a proxy's access log does see, so it is
    bound at this `POST` to the browser's `bd_oauth` cookie: a logged URL
    does nothing in another browser, which gets a 400, no cookie and no
    sign-in.
  - *The sign-in.* The row is read before the provider's code is exchanged.
    The account is judged for the row's workspace with no client, as for a
    gate. Its issuer and subject must be exactly the row's, before anything
    is bound: another account, the same login at another issuer and an
    account joined by `bd serve token link` get the same 404 notice, bind
    nothing and leave no `signed_in` event. A denied account, one no rule
    lets in and a grant not of kind `human` get that notice too; only the
    log tells them apart. The workspace is only what the rules or the
    authorizer are asked about: no workspace is opened or looked for, and
    no gate is looked at.
  - *Registering.* The page has its own one-time id, a challenge of its own
    (32 random bytes, kept in server memory with the id) and a
    `SameSite=Strict` `bd_passkey_<suffix>` cookie scoped to the `POST`'s
    path. The `POST` needs same-origin, at most 16 KiB, a sign-in slot, the
    id exactly once and the bound cookie, and the id is then taken once. An
    assertion's, an add's, an allowance's or `make_link` field is refused
    before anything is read, and the registration is checked as a first one
    is, with user verification required. Then one `server.db` transaction
    checks that the very link the page was opened under is still live and
    the account's (a replacement has another id), that the account exists,
    that it still holds the vouching passkey, that it holds fewer than 99
    passkeys and that the credential id is not registered, removes the
    link, stores the passkey and records a `passkey_registered` event naming
    the new credential, the link and the vouching credential. So two posts
    register at most one passkey, and a refusal at any of these checks
    writes nothing and leaves the link live, with the page used up.
  - *What it cannot do.* A link approves nothing, gives no access to any
    workspace and issues no token. No approval reads the table, so a live
    link counts as no passkey there. Sealed flows do not open across kinds,
    and an id does not cross between an approval's `POST` and a
    registration's. A link's id is no secret: it names the link in flows,
    logs and events, and is never accepted in place of the secret.
- **Passkeys only at a host name over https.** The relying party id is the
  host of the public URL (`--public-url`, else `[oauth]`'s issuer).
  Browsers refuse passkeys at an IP address, so there, and for plain http
  on any host but `localhost`, the page shows a notice with no Approve
  button, and the refusal is counted and logged
  (`passkey refused`, `passkey=unavailable`).
- **The credential in the logs.** `gate approval` lines carry
  `credential`, the first 12 characters of the credential id once the
  posted one has been read (empty before), so an admin can tell which
  passkey approved or failed, and `added`, the first 12 characters of a
  passkey added at that approval (empty otherwise). Under an allowance
  `credential` is the new passkey's, `added` stays empty, and `passkey`
  says `registered under allowance` or `allowance: <reason>`. Never the
  whole id, the public key, the signature or the client data. A link's
  `passkey link` lines hold prefixes likewise, never its secret or hash.
- **Emails are never shown or logged.** The page shows the provider and
  actor; the logs name the provider, subject, login, actor, workspace and
  gate.
- **Bounded.** The provider's callback and the approval's `POST` share the
  8 sign-in slots, as do a link's two `POST`s; approvals waiting for their
  `POST` are kept in memory, at most 1024, the oldest dropped first, and so
  are a link's registration pages. Refusals end on this server's pages,
  never a redirect elsewhere.
- **Links grant nothing.** `bd prime`, refusals at a human gate, `bd
  playbook status`, `bd gate show` and `bd gate list --json` name a gate's
  approval page when `bd serve` offers one ([Approval
  links](playbooks.md#gates)). The link only leads to the sign-in above;
  whoever opens it must still sign in as a person who may open the gate.
  The server composes it from `--public-url` and the gate's id (letters,
  digits, `.`, `_` and `-` only), never from stored text, and the lines
  that carry it are escaped to one line, so a title an agent wrote cannot
  forge another link or line.
- **People only at the terminal.** `bd gate review` refuses inside an
  agent session and without a terminal on stdin, before it reads any
  token, the remote configuration or a gate, with no flag to get past
  either; remotely it sends only the person's keychain token, never
  `$BD_TOKEN` or a saved one, and it reads each gate again just before
  asking about it. Locally that is a convention: anyone who can write
  `bd.db` can open a gate. Remotely the server's human and approver
  checks back it, as for `bd gate resolve`. What it shows from the server
  is escaped to one line, so a title cannot add a prompt.

Residual risks, accepted:

- **A person may approve without reading.** An agent can send a person
  the link of a gate it wants opened, or paste one of its own that looks
  like it. The page shows what the gate holds back and who is signed in,
  but bd cannot make anyone read it. Open only links you expect, check
  that a link's host and path start with your server's public URL, and
  name approvers on gates that matter. The trusted paths are `bd gate
  show` and `bd gate review`, run in a terminal of your own.
- **Approvers are informational in local workspaces**, as human gates
  are: anyone who can write `bd.db` can open them.
- **A rollback** to a `bd serve` that predates approvers ignores them:
  any human token opens such gates again. A rollback to one that predates
  identity references matches OIDC accounts by actor again, squatted
  actors included, and reads a reference as an ordinary actor name; a
  fleet of mixed versions is as weak as its oldest server. Neither can
  safely authorize sensitive gates. Gates resolved meanwhile stay
  resolved, and open approval pages fail (404).
- **References are linkable identifiers, not anonymization.** The same
  OIDC account has the same reference on every gate and every server, so
  approver lists show which gates name one account, and a known issuer
  and subject give the reference directly.
- **A squatted actor stays bound** to the account that took it: the
  identity rule keeps that account from approving, but recovering the
  actor for the intended account is a separate task for the server's
  admin ([Accounts and actors](sign-in.md#accounts-and-actors)).
- **Passkeys are registered on first use.** An account's first approval
  registers its passkey with the same click, so whoever completes the
  first approval as an account (someone who signed in to the provider as
  it) registers the passkey that account's later approvals need. Watch
  the audit trail's `passkey_registered` events (`bd serve token events
  --kind passkey_registered`, each naming the account, the credential's
  first 12 characters and its algorithm) for registrations no one
  expected, and remove such a passkey with `bd serve passkey remove
  --account <actor or login> [--credential <prefix>]` (without
  `--credential`, every passkey of the account), on the server host; the
  account's next approval registers again. A lost device is recovered the
  same way.
  Without an admin's allowance or a link (both below), another passkey can be
  added only at an
  approval, backed by a verified assertion of one of the account's passkeys in
  the same `POST` (at most 99 an account). So someone holding the provider
  account who
  gets the person to complete the existing passkey's prompt for them (the
  cross-device prompt on the person's phone, say) can add a passkey of
  their own; a phishing page cannot ask for that assertion, as it is bound
  to the server's origin and relying party. Watch for `passkey_registered`
  events whose detail names a vouching credential (`added at a browser
  approval with credential <prefix>`) on an add no one expected, and
  remove the passkey as above.
- **An allowance is a window on the provider account.** Whoever holds the
  provider account while an allowance is live gets a lasting passkey and
  one approval, with no existing passkey. This is the feature, and the
  main risk: it rests on the admin's grant, and is bounded by 15 minutes
  by default, an hour at most, one registration, the audit trail and
  removal. While one is live, an approval needs no existing passkey, so
  what a passkey adds to a sensitive gate is weaker for that window:
  approvers of such gates should treat a grant as an exception. After each
  one, review `passkey_registered` events
  ([Server logs](observability.md#server-logs)), and remove a passkey no
  one recognizes with `bd serve passkey remove --account <actor or login>
  --credential <prefix>`.
- **An admin can be talked into granting.** Confirm the request with the
  person some other way than through the account, and grant only when the
  person is ready.
- **A window can be left open** after the person gave up, or chose an
  existing passkey, which spends nothing. It runs out by itself, `--cancel`
  ends it, and `bd serve passkey list` shows it.
- **The page shows that a window is live** to whoever signed in as the
  account. The owner has to be told, and it tells an attacker who already
  signed in little.
- **The admin who granted is not named** in the events, as for
  `passkey_removed`: `bd serve passkey` runs on the host, as no actor, so
  the host's own logs are the record.
- **A window needs something to approve.** A passkey is registered only
  at an approval, so an account with no gate or operation waiting for it
  cannot use one, and an admin may have to make one.
- **The wrong authenticator can spend it.** On a device with several
  authenticators a person may register the wrong one: that passkey still
  works, or the admin removes it, and can grant again. An authenticator
  may also keep a credential the server refused, which is inert: the
  server holds nothing of it.
- **An allowance survives `bd serve token revoke --account` without
  `--forget`.** Revoking ends tokens, and using an allowance takes a new
  sign-in at the provider. An admin who suspects an account should also run
  `bd serve passkey allow-add --account <actor or login> --cancel`.
- **A person can be talked into handing over a link.** This is the link's
  main risk. Someone who holds the provider account persuades the person,
  as support staff or with a fake prompt, to tick the box at a real approval
  and send the link. The person's own act is the mechanism, so nothing stops
  it: the box is unticked, a real approval and a verified assertion are
  needed, and the page warns against sending the link to anyone, whoever
  asks. It yields one passkey in 15 minutes, and it is audited, but the
  person is not told when a link is used: bd has no channel to them. To stop
  an abuse, an admin runs `bd serve passkey cancel-link --account <actor or
  login>`, then `bd serve passkey remove --account <actor or login>
  --credential <prefix>`, the prefix read from the `credential <prefix>` that
  starts the `passkey_registered` event's detail (the prefix after `vouched
  by` is the passkey that vouched for it).
- **A link and the provider account held together make a passkey.** That is
  the delegation: the provider account is the first factor and the link the
  second. A link stolen with the account is bounded as above.
- **The person cannot cancel a link.** Only an admin can; the person can
  replace it at another approval or wait the 15 minutes.
- **The approval page changed for accounts with 1 to 98 passkeys.** The
  unticked box is a visible change to pages that are pinned byte for byte,
  made on purpose, and no setting takes it away. The rule is that nothing
  else changes unless it is ticked: the pinned pages render without the box,
  a test proves that the page shown, less that one fragment, hashes to the
  pinned value, and an unticked `POST` and all that follows are as before.
- **A proxy that logs `POST` bodies sees the secret.** The fragment keeps it
  out of request lines, not out of the one body that carries it. That is
  unusual, outside bd, and bounded as above.
- **A restored backup can revive a used link.** It takes a restore less than
  15 minutes after the link was made, a link used since, and the provider
  account.
- **Both boxes at 98 passkeys** leave a link that cannot be used: the add
  fills the account. The page says so, and the link registers nothing until
  a passkey is removed.
- **Authorizers see a sign-in with no client** for a link: a `sign_in`
  request for the workspace the link was made in, the shape of a gate's
  approval, though no gate is involved and nothing is opened there.
- **A rollback** to a `bd serve` that predates passkeys approves with the
  click alone again. A rollback to one that predates adding passkeys keeps
  every stored passkey usable (any of an account's passkeys approves) and
  only stops offering the add. A rollback to one that predates allowances
  keeps every stored passkey usable, those registered under an allowance
  included, and ends the live allowances. A rollback to one that predates
  links keeps every stored passkey usable, those registered through a link
  included, and ends the live links: such a server has no link page, so a
  link in anyone's hand gets a 404.

**Upgrading to allowances.** `bd serve` moves `server.db` from schema 4 to
5 at its first start, adding a `passkey_allowances` table (from schema 3
it adds both tables at once). Any `bd serve token` or `bd serve passkey`
command migrates a root as well, and an older `bd serve` refuses schema 5
at its next open of `server.db`. So stop `bd serve`, replace the binary and
start it, in that order, and do not run `bd serve passkey` from a new
binary against a root an older server is still serving.

**Upgrading to links.** `bd serve` moves `server.db` from schema 5 to 6 at
its first start, adding a `passkey_links` table (from an older schema it
adds the missing tables at once). As for allowances, any `bd serve token`
or `bd serve passkey` command migrates a root as well, and an older `bd
serve` refuses schema 6 at its next open of `server.db`: stop `bd serve`,
replace the binary and start it, in that order.

**Rolling back links.** To go back to a bd without them:

1. Stop `bd serve` and back up `server.db`.
2. Run `sqlite3 server.db 'DROP TABLE passkey_links; PRAGMA user_version = 5;'`
   in the root.
3. Start the older bd.

Accounts, tokens, OAuth clients, passkeys, allowances and the audit trail
survive. Passkeys registered through a link are ordinary passkeys and stay
valid; live links are gone; events of the new kinds read as `other`; open
registration pages fail. Setting the version alone, without the `DROP`,
leaves a stale table: the next upgrade fails at start naming the table,
changing nothing, until it is dropped.

**Rolling back allowances.** From schema 6, roll back links first, as above.
Then, to go back to a bd without allowances:

1. Stop `bd serve` and back up `server.db`.
2. Run `sqlite3 server.db 'DROP TABLE passkey_allowances; PRAGMA user_version = 4;'`
   in the root.
3. Start the older bd.

Accounts, tokens, OAuth clients, passkeys and the audit trail survive.
Passkeys registered under an allowance are ordinary passkeys and stay
valid; live allowances are gone; events of the new kinds read as `other`;
open approval pages fail and are opened again. Setting the version alone,
without the `DROP`, leaves a stale table: the next upgrade fails at start
naming the table, changing nothing, until it is dropped.

**Rolling back passkeys.** `bd serve` moved `server.db` from schema 3 to 4
at its first start, adding a `passkeys` table. An older `bd serve`
refuses schema 4, so to go back from schema 5 to a bd that predates
passkeys (from schema 6, roll back links first, as above), both tables go:

1. Stop `bd serve` and back up `server.db`.
2. Run `sqlite3 server.db 'DROP TABLE passkey_allowances; DROP TABLE passkeys; PRAGMA user_version = 3;'`
   in the root.
3. Start the older bd.

From schema 4, the same with no `DROP TABLE passkey_allowances`.
Accounts, tokens, OAuth clients and the audit trail survive; the
passkeys are gone, and each account registers a new one at its first
approval after upgrading again.

## Approving a close or discard in the browser

When `bd close <id> --force` or `bd playbook discard <run>` is refused
only because of open human gates, a `bd serve` that offers gate pages
prints a link where a person can approve that very operation
([Approving a close or
discard](sign-in.md#approving-a-close-or-discard)). It is a second
human-gate override without a token, so it gets the protections of
[gate approval](#approving-gates-in-the-browser) and more.

- **Offered narrowly.** Only for `bd close` of one id with `--force`
  (not `--take-over`) and `bd playbook discard` (not `--take-over` or
  `--dry-run`), and only for a refusal due to open human gates alone,
  none of which has a stored approver list that is not valid (which no
  one could match); a gate naming no approvers, or a valid list,
  qualifies. Never for closing a gate itself, a claim refusal, several
  ids, batches or any other command.
- **The request is sealed, not stored.** The server seals it with
  ChaCha20-Poly1305 under its link key, bound to the path's workspace,
  operation and issue, and it expires 7 days after it was asked. It holds
  exactly what was asked (the operation, the issue, the reason,
  `--failed`, `--force`, the requester and when they asked); nothing in
  it can be changed without the link becoming invalid, and nothing else
  (`--token`, `--if-*` guards) carries over. The `POST` reads nothing
  from the form but the one-time approval id and the passkey's fields.
- **Nothing is looked up before admission.** Opening a link checks only
  the path's shape and the seal: a link this server did not seal, or one
  for another path, answers 404 like an unknown path; an expired one 410;
  a query over 8 KiB 400. Up to the account's admission every genuine
  link gets the same answer, whatever workspace or issue it names.
- **Each step is bound to the browser.** Through the sign-in the request
  rides in `bd_opreq_<digest>_<n>` cookies (`__Secure-` on https;
  `Path=<issuer path>/oauth`, `HttpOnly`, `SameSite=Lax`, 20 minutes),
  checked against a digest the sealed sign-in carries and cleared at the
  provider's callback. The sign-in is sealed under a label of its own, so
  it cannot finish as a gate's approval or an MCP client's authorization.
  The approval's `bd_op_<suffix>` cookie is `HttpOnly`,
  `SameSite=Strict` and scoped to the operation's path, and its one-time
  id lasts 10 minutes.
- **The gate page's protections.** The account is admitted, bound and
  audited as for [gate approval](#approving-gates-in-the-browser) (kind
  `human` only, no token issued), and the page has the same Content
  Security Policy, framing refusal, focus arming, same-origin `POST` and
  shared sign-in slots.
- **The same passkeys.**
  Without an admin's allowance, every Approve needs one of the account's passkeys,
  those its gate approvals use,
  verified as for [gate approval](#approving-gates-in-the-browser) (origin,
  relying party id
  hash, user verification, a per-approval challenge, the signature, the
  counter by compare-and-set, each form field exactly once) after the
  checks of this section, the request's expiry included, and before the
  operation is performed. No attestation is checked, verification may be
  a PIN or a biometric, and there is no fallback: a missing or failed
  ceremony performs nothing (403, outcome `passkey_refused`) and uses the
  approval up. At an IP address, or plain http on a host other than
  `localhost`, the callback shows a notice with no Approve button and
  records `passkey_refused`. An account with 1 to 98 passkeys is offered
  to add one, with the gate page's checks and the same all-or-nothing
  store ([gate approval](#approving-gates-in-the-browser)); a workspace
  failure after the store keeps the added passkey and performs nothing.
  A live allowance works as at a gate, with the same checks and the same
  one transaction spending it and storing the passkey before the operation
  is performed; a workspace failure after it keeps the passkey, with the
  allowance spent, and performs nothing. A link can be made here as at a
  gate, in one transaction with the passkey's counter before the operation
  is performed; a workspace failure after it keeps the link and performs
  nothing.
  First-use registration, adding, allowances and links are the residual
  risks described for gate approval. `operation approval` lines carry
  `credential`, the credential id's first 12 characters once it has been
  read (empty before), `added`, an added passkey's first 12
  characters (empty otherwise), and, only on an allowance's outcome or a
  link's, `passkey`, never the whole id, the public key, the
  signature or the client data.
- **Every gate in the way.** The person must be able to open every open
  human gate the operation gets past: one of its approvers when it names
  them, an OIDC account only by its identity reference. Otherwise the
  page refuses (403), naming each gate it may not open and its
  approvers, and nothing is performed.
- **Checked again, performed exactly.** One transaction, as the person's
  actor with a human, non-admin token's rights, checks the target again
  and runs exactly the sealed close or discard. It never takes over a
  claim: another actor's live claim, the requester's included, refuses
  the approval (403, nothing written). It cascades nothing. The `closed`
  or `deleted` events name the approver's actor, `"via": "browser"` and
  `"requested_by"`.
- **The link key.** `<root>/approval-links.key` holds 32 random bytes,
  created at the first start (mode 0600 on Unix, with a warning at start
  when others can read it), never in `server.db` or its backups, and its
  bytes are never logged. Whoever reads it can forge links for any
  workspace and issue (an admitted person who may open the gates must
  still approve) and can open the sealed requests in links and request
  cookies, reasons included: guard it like `server.db`. Delete it and
  restart `bd serve` to invalidate every link; a root restored without
  it gets a new key.

Residual risks, accepted:

- **A person may approve without reading.** An agent can send a person
  a link to its own refused close or discard. The page shows the
  operation, the issue, the reason, the requester, the gates it gets past
  and a discard's deletes, but bd cannot make anyone read it. Open only
  links you expect, check that a link's host and path start with your
  server's public URL, and name approvers on gates that matter.

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
- **Passkeys.** For each passkey registered at a browser approval (up to
  99 an account),
  `server.db` keeps its credential id, its public key (as
  SubjectPublicKeyInfo), its algorithm (ES256 or RS256), its signature
  counter, when it was registered and last used, and the account it
  belongs to (issuer, subject and actor). It keeps no biometric
  (fingerprints and faces never leave the device), no attestation and no
  AAGUID, so nothing says which authenticator holds it. Forgetting an
  account (`bd serve token revoke --account <login> --forget`, or a
  provider's `account-deleted` notification) erases its passkeys in the
  same transaction.
- **Passkey allowances.** For an account an admin allowed to register a
  passkey (`bd serve passkey allow-add`), `server.db` keeps its issuer and
  subject, a random id, and when the allowance was granted and when it
  ends, at most an hour later. It goes when it is spent, cancelled or
  replaced; one that ran out is pruned at the next write; and forgetting
  the account erases it in the same transaction.
- **Passkey links.** For an account that made a link at an approval,
  `server.db` keeps its issuer and subject, a random id, the SHA-256 of the
  link's secret (never the secret), the whole credential id of the passkey
  that vouched for it, the workspace of that approval, and when the link
  was made and when it ends, 15 minutes later. An account has one at most.
  It goes when it is used, cancelled or replaced, or when the passkey that
  vouched for it or the account's last passkey is removed; one that ran out
  is pruned at the next write; and forgetting the account erases it in the
  same transaction.
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
  the account and every token, passkey, allowance and link of it. Deleted rows are
  overwritten (`secure_delete`) and the write-ahead log is emptied, so
  nothing of them stays in the database's files (if `bd serve` is reading
  at that moment, its next checkpoint does it, and the command says so). A
  provider's `account-deleted` notification erases an account the same
  way. Workspace histories keep the actor; copies outside `server.db`
  (logs, backups) are the admin's to expire.
- **Audit trail.** `server.db` records each sign-in (one to approve a gate
  in a browser too, as a `signed_in` event without a token), token
  created, refresh, revocation (and why), account forgotten, linked or
  named, passkey registered or removed, passkey allowance granted or
  cancelled, passkey link made or ended, and client registered, in the same
  transaction as the change, for 90 days (client registrations, which
  anyone may make: the latest 5000). `bd serve token events` shows it. An
  event names the actor, provider, subject, token and client, never a
  secret or an email. Forgetting an account erases its events too, leaving
  one that says an account of that provider was forgotten, and why.
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
- **A person's token in the OS keychain.** `bd remote login --human`
  keeps a human token in the Secret Service (Linux), the login Keychain
  (macOS) or Credential Manager (Windows), never in a file or an
  environment variable, so it is off disk, out of agents' environment and
  out of the credentials file agents' commands use. It is saved only from a
  terminal outside agent sessions, after the server confirms its kind is
  `human`. bd reads it only outside agent sessions with stdin a terminal,
  and only after the server refused a command for want of a person's or
  admin's rights without committing a write, or for `bd publish`; each
  read waits at most 5 seconds. It is sent only to the URL and the CA
  trust it was saved for, which renewal checks again under
  `credentials.lock` before it uses a re-read item.
- **The keychain is not a security boundary against a determined
  agent.** Any process running as the same user can use an unlocked
  keychain, as the OS lets it, and an agent can run bd under a faked
  terminal with its session variables cleared: the checks above keep a
  well-behaved agent from using a person's token by accident, not a
  hostile one from using it on purpose. Where agents must not get past
  human gates even then, the browser approval a person gives on another
  device (bd-d8iwi.2) is the boundary; keep human tokens off machines
  where untrusted agents run as you.
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
- **Playbooks wait for a person too.** A remote workspace's playbooks steer
  every agent that runs them, so a client uses one only once a person
  approved it on that machine (`bd agents approve`, with the same rules:
  shown whole or as a diff, a terminal, no agent session). The approved
  bytes are kept in `.bd/approved/playbooks` with their hashes in
  `.bd/agents.lock`, checked before each run, and sent with the command:
  the server compiles what the client sent, never its own copy in its
  place (a bundle asking for it, `server_first`, from clients that predate
  approval, is compiled as sent; clients of today refuse to send one). A
  path an approved playbook names must stay inside the approved directory,
  so a playbook cannot make a client send its other files.
  What this guards against is an admin's unreviewed publish reaching
  agents through bd clients. It does not stop an agent that holds a token
  and deliberately goes around its client: requests without a bundle (as
  clients that predate this send, and the MCP endpoint `/w/<name>/mcp`
  would, which has no client to approve with and offers no playbook tool
  today) compile the server's published copy, and `bd agents fetch
  --playbooks` shows the texts. Nor does it stop a compromised server
  binary, which can put any text in front of agents (the issues they read
  included). A person approving without reading remains a risk; a local
  process that can write the checkout can change the approved files as it
  can the skill files.
- **No secrets on the server.** MCP servers run and authenticate on the
  client; bd never handles MCP credentials.
- **Strict sets.** Sets are validated on the server and again by clients
  before anything is written: no settings or hooks in MCP files, portable
  paths, symlinks contained in `.bd/agents`, size limits. A pull never
  follows a symlink in a skill directory and never overwrites files it did
  not write.

## Publishing

[`bd publish`](agents.md#publishing) replaces a workspace's playbooks and
agent sets, which steer every agent's work and reach every checkout.

- **Who.** Through bd serve, only an admin token of a person (role
  `admin`, kind `human`), for dry runs and rollbacks too: an admin agent
  token, a write token and an MCP tool call are refused (exit 7). It is
  not a `bd batch` operation or an MCP tool. Locally, whoever can write the
  workspace's `.bd`. CI that publishes needs a human-kind admin token
  issued for the purpose.
- **What is checked.** The server trusts nothing the client checked.
  Before anything is written, every path must be relative, ASCII and
  `/`-separated, with no `..`, no hidden, empty or Windows-reserved
  components, no control characters, within the depth and length limits,
  and no two paths of an area may differ only in case; symlinks only in
  agent sets, leading to another place inside `agents/` (resolved once
  staged, link by link, as the file system resolves them); 1,024 files and
  16 MiB in all, 512 KiB a file, and each set's limits.
  The bundle is then written into a fresh private staging directory
  (`.bd/.publish-<random>/`, mode 0700, files created exclusively) and
  loaded there by the loaders that serve it: each set as clients would
  read it, each playbook with its `extends` and `expand` held inside the
  published playbooks. Errors, from staging and applying too, name the
  file as the source names it, never a server path. Any error refuses the whole publish and removes the
  staging directory; one a crash leaves is swept by a later publish.
- **How it is applied.** Under the workspace's publish lock, the areas it
  changes are copied to `.bd/publish.prev/` first (with a marker,
  `applying`, until the publish is recorded: a later publish keeps that
  copy rather than a half-written tree, and sweeps the temp files an
  interrupted one left), then each new or changed file is written to a
  temp file and renamed over its place, entries renamed in case only are
  renamed where the file system ignores case (never removed, which would
  remove what was just written), and only then are files the source lacks
  removed. Nothing is written or removed through
  a symlink: directories written into are checked to be real ones, a
  symlink where a file goes is replaced (never followed), and an area that
  is itself a symlink is refused. Readers see each file whole, old or new,
  and never fewer files than either version has. An area left empty in the
  source is refused unless asked for (`--allow-empty`), so a mistaken
  publish cannot remove every client's skills.
- **Undo and audit.** `bd publish --rollback` restores, from
  `.bd/publish.prev`, the areas the last publish changed, through the same
  checks; the `published` event records the actor, each file's SHA-256
  (computed by the server) and the counts, with the source's git commit as
  the client reported it; the server logs a line per publish (counts,
  paths, hashes) and per refusal (exit code, error code and the file
  named, never the message, which can quote a file), never contents, and
  `/metrics` counts them (`bd_serve_publishes_total`).
- **Playbooks are held to their directory** whenever bd serve loads them,
  published or not: a reference leading outside the playbook directories
  (`../`, an absolute path, a symlink out) is refused, as is a file over
  512 KiB.
- **Executable bits from Windows.** Where the file system keeps none
  (Windows; on Unix, a checkout with `core.filemode` false, or a source
  where every file reports mode 0777, as WSL's DrvFs does), a client takes
  the agent sets' executable bits and symlinks from git, and refuses a set
  file git does not record, or a source git cannot read, rather than
  publishing scripts as plain files or every file as a script.
- **What it does not change.** Clients still approve new and changed
  skills, executable bits and MCP definitions. A secret committed to the
  source is published to every reader; `--dry-run` lists every file first.

## Release binaries

Each release has a `SHA256SUMS` file and a signed build-provenance
attestation per archive; [Install](install.md#prebuilt-binaries) shows how
to check both.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through the repository's [private vulnerability
reporting](https://github.com/quanghle/bd-sync/security/advisories/new)
(the Security tab, then "Report a vulnerability").
