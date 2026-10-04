# MCP server

bd serves its coordination loop as [Model Context
Protocol](https://modelcontextprotocol.io) tools, for assistants that reach
bd through MCP rather than a shell: Claude Desktop, ChatGPT, or agent
harnesses configured with MCP servers. Where an agent has a shell, the CLI
with the session-start hook (`bd prime`) does the same with less context,
and nothing here replaces it.

- `bd mcp` serves a workspace over stdio, for a client on the same machine:
  the checkout's local workspace, or its remote one (`.bd/remote.toml`,
  `BD_REMOTE`), with the same token as the CLI.
- `bd serve` serves each workspace at `/w/<workspace>/mcp` over Streamable
  HTTP, for remote clients, with a bd access token as its bearer token
  ([Remote server](remote.md); see [Over HTTP](#over-http)), which a
  client may also get by signing its user in with OAuth ([Signing in with
  OAuth](#signing-in-with-oauth)).

A server is bound to one workspace, chosen by where it runs (`bd mcp`) or
by its URL (`bd serve`): no tool takes a workspace, so a tool call cannot
reach another one. A client that uses several workspaces configures one MCP
server for each.

## Setup

`bd mcp` runs in the checkout: the client starts it there, and it serves
the workspace a bd command run there would use, until its input closes.
`bd mcp --read-only` offers only `ready`, `list`, `show` and `memories`.
Diagnostics go to stderr; stdout carries only protocol messages.

Claude Code, `.mcp.json` (Copilot CLI: `.github/mcp.json`, same form):

```json
{"mcpServers": {"bd": {"command": "bd", "args": ["mcp"]}}}
```

Codex, `.codex/config.toml`:

```toml
[mcp_servers.bd]
command = "bd"
args = ["mcp"]
```

A workspace can serve such a definition to its clients from `.bd/agents`
([Agent assets](agents.md)); as with any MCP definition, it is written only
once the user approves it.

### Actors

`bd mcp` acts as the actor a bd command run in the same environment would:
`--actor`, `$BD_ACTOR`, or the user's actor for the agent session named by
the harness's session variable, `$BD_SESSION` or `--session`, so an agent
that also has a shell holds its claims under one name. When none of those
names a session, the process names its own, `mcp-<8 hex digits>`, and acts
as `<user>/mcp-…` (in a remote workspace, `<token actor>/mcp-…`). Each
process is then its own actor: claims an earlier process held are another
session's, so they expire and are reclaimed, or the user takes them over
from the CLI (`bd prime` lists them).

Tool calls never carry the token's admin or human rights, locally or on a
bd server (whatever kind of token the checkout uses): as for a non-admin
agent token of `bd serve`, a model cannot take over or end another actor's
claim, nor open a human gate.

A message longer than 1 MiB is answered with an error (`-32600`, id
`null`) and skipped; the server keeps serving.

## Over HTTP

`bd serve` serves the MCP endpoint of each workspace it serves at
`https://<host>/w/<workspace>/mcp` (under the same path prefix as
`/w/<workspace>/v2/exec` behind a proxy). Each request authenticates with a
bd access token as a bearer token (`Authorization: Bearer <secret>`), with
the same role, workspace and `--max-claims` limits as the token's CLI
requests: a read token is offered only the read-only tools, and a token
limited to other workspaces is refused (403). A missing, unknown or expired
token is answered with 401 and a `WWW-Authenticate` challenge (see
[Discovery](#discovery)).

[Connecting clients](#connecting-clients) shows the setup of each client.

Tool calls act as `<token actor>/mcp`, a sub-actor of the token's actor, or
as `<token actor>/<name>` for a URL ending `?session=<name>` (letters,
digits, `.`, `_` and `-`), so that several agents sharing a token hold
their claims under their own names; the request cannot name another actor.
As over stdio, tool calls never carry the token's admin or human rights.

Each POST carries one JSON-RPC message (`Content-Type: application/json`,
at most 1 MiB) and is answered with one JSON object; no request opens an
SSE stream, and the server issues no `Mcp-Session-Id`. GET and DELETE are
answered with 405. Each tool call runs as a CLI request does, in one of the
server's command slots (503 when they stay busy).

- A `2026-07-28` request mirrors its body in headers: `MCP-Protocol-Version`
  (the version in `_meta`), `Mcp-Method` (its `method`) and, for
  `tools/call`, `Mcp-Name` (the tool's name, or `=?base64?<name>?=`). One
  missing or not matching the body is answered with 400 and
  `HeaderMismatch` (`-32020`), and the request does not run.
- A `2025-11-25` client sends `initialize`, then names the version in
  `MCP-Protocol-Version`. Each request stands alone (the server keeps no
  session), so a request without `_meta` is served as `2025-11-25` with or
  without `initialize` before it; one without the header is taken as
  `2025-11-25`, and one naming another version is answered with 400 and
  `-32022`.

Statuses: 202 with no body for notifications and responses; 400 for
malformed JSON or messages, header mismatches and unsupported versions;
404 for a `2026-07-28` method the server does not serve; 413 for a body
over 1 MiB; 415 for another `Content-Type`; 200 for every other answer,
tool errors and invalid parameters included. A request with an `Origin`
header (403) or another `Content-Type` (415) is answered with a JSON-RPC
error whose `id` is `null`. Other failures before the message is read (401,
403 for another workspace, 404 for an unknown workspace, 413, 503) carry
bd's error object (`{"error": {"code", "message", "exit_code"}}`) rather
than a JSON-RPC one.

A request with an `Origin` header is refused (403): browsers send one with
every POST, and other clients none, and `bd serve` serves no pages, so a
web page cannot reach the endpoint, even through DNS rebinding. Browser-based
MCP clients are not supported (the server sends no CORS headers). The bearer
token is the protection that matters: a page cannot send it.

### Discovery

Each endpoint is an OAuth protected resource (RFC 9728), whose URL (the
resource) is the server's URL followed by `/w/<workspace>/mcp`. The server's
URL is `bd serve --public-url` (or `$BD_SERVE_PUBLIC_URL`), path prefix
included, such as `https://bd.example.com/bd`. Without it, the server's URL
is taken from each request: `https` with `--tls-cert`, else `http`; the
`Host` header; and the path before `/w/`. `X-Forwarded-*` headers are never
trusted (any client can send them), so behind a TLS-terminating proxy, set
`--public-url`.

The endpoint's metadata is served without a token at the server's URL
followed by `/.well-known/oauth-protected-resource/w/<workspace>/mcp`, and
at the RFC's own location, with the prefix after the well-known part
(`https://bd.example.com/.well-known/oauth-protected-resource/bd/w/proj/mcp`)
for a proxy that forwards it:

```json
{"resource": "https://bd.example.com/bd/w/proj/mcp", "bearer_methods_supported": ["header"],
 "resource_name": "bd workspace proj"}
```

It answers the same whether the workspace exists or not. With `[oauth]` in
`<root>/auth.toml`, it also names the server's own authorization server
(`"authorization_servers": ["https://bd.example.com/bd"]`), where clients
sign people in ([Signing in with OAuth](#signing-in-with-oauth)); without
it, it names none, and tokens come from the server's admin or from GitHub
sign-in ([remote workspaces](remote.md)).

Refusals point clients at it, as RFC 6750 challenges:

- no token: 401 with `WWW-Authenticate: Bearer resource_metadata="<metadata URL>"`;
- an unknown, expired or bound-elsewhere token: 401 with
  `error="invalid_token"` and an `error_description` before `resource_metadata`;
- a token limited to other workspaces: 403 with `error="insufficient_scope"`.

### Tokens bound to an endpoint

A token for an MCP client that should reach one workspace's tools and
nothing else names that endpoint:

```bash
bd serve token create assistant --as alice --resource https://bd.example.com/bd/w/proj/mcp --root /srv/bd
```

The token's workspaces become that workspace alone (`--workspace`, if given,
must allow it). It is refused (401) at any other endpoint, at an endpoint
reached under another URL (normalized: lowercase scheme and host, no default
port, no trailing `/`), and for CLI requests (`/w/<name>/v2/exec`), so a
leaked token works only through MCP's tools. The URL compared is the one the
request computes, so set `--public-url` on a server whose clients reach it
by more than one name. `bd serve token list` shows each token's `resource`.

### Signing in with OAuth

Some MCP clients sign people in rather than send a token they were given:
ChatGPT, the Claude apps, and Claude Code or another client configured
without an `Authorization` header. For them, `bd serve` runs an OAuth 2.1
authorization server when `<root>/auth.toml` has an `[oauth]` table. People
sign in in their browser with GitHub or one of the server's OpenID Connect
providers (a page offers them when there are several), under the same rules
(or [authorizer](remote.md#deciding-with-an-authorizer), which is told the
client) as `bd remote login` ([Signing in](remote.md#signing-in)), approve
the client, and the client gets a token bound to the endpoint it asked for.

1. Set up sign-in ([remote workspaces](remote.md#signing-in)) so that
   tokens are refreshed: an authorizer, or GitHub's rules with the GitHub
   App's private key. Each provider sends people back to
   `<public-url>/oauth/<provider>/callback`: for GitHub, set the App's
   **Callback URL** to the server's public URL followed by
   `/oauth/github/callback` (`https://bd.example.com/bd/oauth/github/callback`)
   and generate a client secret (saved alone in a file under the root, mode
   0600, named by `github.client_secret_file`); for an OIDC provider
   `[oidc.<name>]`, register `/oauth/<name>/callback` as its redirect URI.
2. Add to `<root>/auth.toml`:

   ```toml
   [github]
   # client_id, private_key and rules (or an [authorizer]) as for bd remote login --provider github
   client_secret_file = "github-secret"   # the GitHub App's client secret, relative to the root

   # [oidc.google]                         # and any OIDC providers, decided by an [authorizer]
   # issuer = "https://accounts.google.com"
   # client_id = "..."
   # client_secret_file = "google-secret"

   [oauth]
   redirect_uris = ["https://chatgpt.com/connector_platform_oauth_redirect",
                    "https://claude.ai/api/mcp/auth_callback"]  # these https redirect URIs exactly
   # redirect_hosts = ["chatgpt.com"]              # or any https path on these hosts, without a port
   loopback_redirects = true                       # and http://127.0.0.1, [::1] or localhost, any port
   # registration = false                          # clients come with metadata documents only (default true)
   ```

3. Run `bd serve` with an https `--public-url` (http only on a loopback
   address, for trying it out): it is the issuer, which clients check.

`bd serve` refuses to start with `[oauth]` but tokens that are not
refreshed (no authorizer, and GitHub's rules without `private_key`), no
provider for a browser (GitHub without `client_secret_file`, and no OIDC
provider), no such `--public-url`, or no redirect allowed; and with
`client_secret_file` but no `[oauth]`. Like the rest of `auth.toml`,
`[oauth]` is read again for each request, so it can be changed without a
restart, or removed together with `client_secret_file` to turn the
authorization server off: a `client_secret_file` left without `[oauth]` is
a mistake that fails every GitHub sign-in and refresh, and the endpoints'
metadata, until fixed.

The authorization server's metadata (RFC 8414) is at its RFC location,
`https://bd.example.com/.well-known/oauth-authorization-server/bd` (with no
path in the public URL, `/.well-known/oauth-authorization-server`). A client
that reaches an endpoint without a token goes from the 401 challenge to the
endpoint's metadata, then to the authorization server's, and then:

1. **Identifies itself**, as a public client (no client secret), either way:
   - with a Client ID Metadata Document: its `client_id` is an https URL of
     a JSON document naming its redirect URIs, which bd fetches when it is
     first used: from public addresses only, without following redirects
     or using a proxy, at most 8 KiB within 5 seconds, four hosts at once
     and one fetch per host. bd keeps it for its `Cache-Control` max-age
     (5 minutes by default, an hour at most), and keeps using it for up to
     an hour past that only while it cannot be fetched because every
     fetch, or another from its host, is under way. If its host does not
     answer (or answers 429 or 5xx) the authorization fails, and the copy is
     kept; any other answer that is not a document, or one not to be
     cached, ends it, and whether it was approved (approving a client whose
     document is not to be cached keeps nothing). A `logo_uri` (https) is
     fetched with the document, the same way and within the same 5
     seconds (2 at most for the logo), and kept with it if it is a
     PNG, JPEG, GIF or WebP image of at most 64 KiB; any other is left
     out. Of the 256 documents kept in memory, those of clients
     someone approved since `bd serve` started go last. A
     document may list grant and response types bd does not offer (it
     serves every server its client uses): they are left aside, as long as
     it has the authorization code. The Claude apps and Claude Code
     identify themselves this way, and ChatGPT may.
   - by registering (RFC 7591) at `<public-url>/oauth/register`, without a
     token, unless `registration = false`: up to 8 redirect URIs of 512
     bytes each. Registrations are kept
     in `<root>/server.db`: one never used is dropped after a day,
     and one unused for 90 days after that. With 500 kept, a new
     registration drops the oldest never used, or is refused (503) if all
     are in use.

   Each redirect URI must be one `[oauth]` allows: one of `redirect_uris`
   exactly, https on a host of `redirect_hosts` (any path), without a port,
   or, with `loopback_redirects`, http to
   this machine, whose port is ignored when compared (a desktop client
   listens on whatever port is free). No fragment, no user info. (Browsers
   cannot be redirected to an IPv6 address after a form, so for `[::1]`
   the consent page is followed by one that sends the browser on.)
2. **Sends the person to `<public-url>/oauth/authorize`**, for an
   authorization code with PKCE (`S256` only), naming as `resource`
   (RFC 8707, required) the endpoint it wants, one of this server's. The browser signs
   in with GitHub or an OIDC provider (chosen on a page when the server
   offers several), which sends it back to that provider's callback. If a
   rule or the authorizer lets the account into the workspace, a consent page shows what the client will
   get: the client's name and where its details come from (its metadata
   document's full URL, with the logo the document names, or, for a
   registered client, the client itself, with a warning that its name is
   not verified), the full redirect URI the browser goes back to (with a
   warning when it is this machine, or a site other than the document's),
   the workspace, the provider and login signed in with, the actor, the access its role gives,
   what let the account in, and how long access lasts
   (`refresh_limit`, `refresh_idle`). A small script keeps the form from
   being sent until the page has had focus for 600 ms, against
   double-click tricks; the buttons stay enabled, so screen readers and
   voice control work, and without scripts the form is sent as it is. Approving sends the browser back to the client with a code and the
   issuer (`iss`, RFC 9207); denying, with `access_denied`.
3. **Redeems the code** at `<public-url>/oauth/token` within 5 minutes, with
   its `client_id` and PKCE verifier, and its redirect URI if it sends one
   (OAuth 2.1 clients do not). A code is good for one request, refused or
   not, except one the server could not answer (500, or 503 when busy):
   it can be sent again.

An account the rules refuse gets a page saying why, with a link back to the
client. A workspace the server does not have is told (`invalid_target`)
only after the rules let the person's account in, so the authorization
endpoint does not tell strangers which workspaces exist. An authorization in
progress is bound to the browser that started it (an `HttpOnly`,
`SameSite=Lax` cookie, `__Secure-bd_oauth` on an https public URL,
`bd_oauth` on http), and each step must follow within 10 minutes. Until
someone signs in, the server keeps nothing of it: the request is sealed
into the link that chooses a provider and, at the provider, into a cookie
of the flow's own, so no number of authorizations fills anything. The
steps after it, which only accounts the rules let in reach, keep up to
1024 consent pages and 1024 codes each in memory, the oldest going first.
A restart ends every authorization in progress
([One server](remote.md#one-server)).

The client's tokens:

- act as the account's actor, as a sign-in by `bd remote login` does, and tool calls as `<actor>/mcp` (see [Actors](#actors)), with what
  the rule grants: role, kind, `max_claims`. They are bound to the endpoint
  ([Tokens bound to an endpoint](#tokens-bound-to-an-endpoint)), so they
  work there only, for that workspace, and never for CLI requests.
- expire after `token_ttl`, and are refreshed at the token endpoint by the
  client they were issued to, with the rules or the authorizer deciding
  again as for any sign-in ([Refreshing](remote.md#refreshing-sign-ins)), until
  `refresh_limit` or `refresh_idle`. Each refresh replaces both tokens.
- are protected against replay: a code works once, and any request naming
  it ends it; a code sent again revokes the tokens it issued. A refresh
  token works once, with no grace period: one sent again revokes the
  sign-in. A client that lost a refresh's answer has the person authorize it
  again. An OAuth refresh token is refused at `/v2/auth/refresh`, the CLI's.
- can be revoked by the client (RFC 7009) at `<public-url>/oauth/revoke`, by
  either secret: this ends the sign-in. The endpoint answers 200 to anything
  else and leaves tokens other than OAuth clients' alone.

Admins see each such token in `bd serve token list`, named
`oauth-<client>-<actor>-<random>` with its `client`.
`bd serve token revoke --client <client_id>` revokes every token of a
client, and `bd serve token revoke --account <login>` every token of an
account, OAuth clients' included. The endpoints under `/oauth/` need no
token, so rate-limit them per address at the proxy (see [Behind a
proxy](#behind-a-proxy)).

### Connecting clients

Create a token for the client on the server's host, bound to the endpoint
it uses, and keep its secret in an environment variable rather than in a
file:

```bash
bd serve token create laptop-agents --as alice --resource https://bd.example.com/w/proj/mcp --root /srv/bd
export BD_TOKEN=bd_...   # the printed secret
```

Clients that send a fixed `Authorization` header:

- Claude Code, in `.mcp.json` (Claude Code expands `${BD_TOKEN}` from its
  environment), then `claude mcp list` shows `✔ Connected`:

  ```json
  {"mcpServers": {"bd": {"type": "http", "url": "https://bd.example.com/w/proj/mcp",
    "headers": {"Authorization": "Bearer ${BD_TOKEN}"}}}}
  ```

- Codex, reading the token from the environment on each start:

  ```bash
  codex mcp add bd --url https://bd.example.com/w/proj/mcp --bearer-token-env-var BD_TOKEN
  ```

- Copilot CLI (stores the secret in `~/.copilot/mcp-config.json`):

  ```bash
  copilot mcp add --transport http bd https://bd.example.com/w/proj/mcp --header "Authorization: Bearer $BD_TOKEN"
  ```

Clients that sign people in with OAuth need `[oauth]` ([Signing in with
OAuth](#signing-in-with-oauth)); they connect to the endpoint's URL, find
the authorization server by themselves, and open the browser for the person
to sign in and approve:

- Claude apps (claude.ai, Claude Desktop, Claude mobile): add a custom
  connector with the endpoint's URL. They come back to
  `https://claude.ai/api/mcp/auth_callback`, so `redirect_hosts` needs
  `claude.ai`. Organizations in Anthropic's beta of request headers may
  instead have an Owner enter an `Authorization` header once; that header is
  the whole organization's, so give it a token of a shared actor
  (`--as team-claude`), with `--max-claims` if the organization should hold
  only so many issues at once.
- ChatGPT (developer mode): create an app for the endpoint's URL, with OAuth
  authentication. ChatGPT comes back to
  `https://chatgpt.com/connector_platform_oauth_redirect` (bd names its
  issuer in every answer, RFC 9207), so `redirect_hosts` needs
  `chatgpt.com`.
- Claude Code without the header: `claude mcp add --transport http bd
  https://bd.example.com/w/proj/mcp`, then `/mcp` to sign in. It comes back
  to this machine on a port of its choosing, so it needs
  `loopback_redirects = true`.

Without `[oauth]`, such a client fails at its sign-in, as the endpoint
names no authorization server.

Agents sharing a token add `?session=<name>` to the URL to hold their claims
under their own names (`https://bd.example.com/w/proj/mcp?session=reviewer`);
a token bound with `--resource` works under any `?session`.

### Behind a proxy

A proxy that serves bd under a path prefix may forward requests with the
prefix or without it. Set `--public-url` to the URL clients use, prefix
included, so that endpoints name themselves by it whatever reaches the
server, and forward the RFC 9728 and RFC 8414 locations of the metadata
too. With Caddy:

```text
example.com {
    @bd path /bd/* /.well-known/oauth-protected-resource/bd/* /.well-known/oauth-authorization-server/bd
    handle @bd {
        reverse_proxy 127.0.0.1:7420
    }
}
```

```bash
bd serve --root /srv/bd --public-url https://example.com/bd
curl -s https://example.com/.well-known/oauth-protected-resource/bd/w/proj/mcp
curl -s https://example.com/.well-known/oauth-authorization-server/bd   # with [oauth]
```

Clients then use `https://example.com/bd/w/proj/mcp`, and tokens are bound
to that URL. No MCP request waits for events (the server opens no SSE
streams), so a proxy's idle timeout only needs to exceed a tool call's run.

With `[oauth]`, anyone can call the endpoints under `/bd/oauth/` without a
token: registering clients, starting sign-ins, sending codes. So can
anyone call the sign-in endpoints under `/bd/v2/auth/` (the device flow of
`bd remote login --provider`). bd bounds what they keep (registered
clients; a sign-in before anyone signed in keeps nothing on the server),
how many run at once (refreshes have slots of their own, which no sign-in
takes), and how many connections one address holds, but does not limit
how often a caller sends requests; the proxy should, per client address
(nginx `limit_req`, or a Caddy rate-limit plugin), on `/oauth/` and
`/v2/auth/` paths. They answer at
the public URL's path followed by `/oauth/` (`/bd/oauth/…`), or at
`/oauth/…` for a proxy that strips the prefix, and nowhere else. A proxy
that strips it forwards `/bd/bd/oauth/…` as `/bd/oauth/…`, so limit every
request whose path has `/oauth/` in it, not only those under `/bd/oauth/`.

### Retries

MCP gives a tool call no request id to deduplicate by (as `bd`'s CLI
requests have), so a client that resends a call after losing its answer
runs it again:

- `create` creates a second issue;
- `claim` of the issue it already claimed fails with `already_claimed`,
  naming its own actor: the lease token is lost, but the holder may still
  `release` or `close` the issue without it, and claim it again;
- `close` of a closed issue succeeds with `already_closed: true`.

After a lost answer, `show` or `list` tells whether a write took effect.

## Protocol

bd implements MCP itself (JSON-RPC 2.0 over serde, no SDK) and speaks two
revisions:

- `2026-07-28`, the stateless revision. Every request carries its protocol
  version and client capabilities in `_meta`, and `server/discover` lists
  the versions served. A request naming another version in `_meta`
  (`2025-11-25` included: it is not stateless) is answered with
  `UnsupportedProtocolVersionError` (`-32022`), whose data lists the
  versions served and the one requested. Results carry `resultType`, the
  server's `serverInfo` in `_meta`, and the tool list `ttlMs` and
  `cacheScope`.
- `2025-11-25`, the session-based revision, for clients that start with
  `initialize`. Its answer names `2025-11-25` whatever version the client
  asked for (the client disconnects if it cannot speak it), with the
  server's capabilities, `serverInfo` and `instructions`. From then on,
  until the stdio process ends, requests without `_meta` are served in that
  revision's format, without the stateless fields. Over HTTP, which keeps
  no sessions, the `MCP-Protocol-Version` header names it instead.

A request without `_meta` before `initialize` is refused with `-32602`,
except `ping`. Methods served: `initialize`, `ping`, `tools/list` and
`tools/call` in both revisions, and `server/discover` in `2026-07-28`.

Only tools are served: no resources, prompts, subscriptions, sampling,
elicitation or tasks, and HTTP requests are answered with
`application/json`, never an SSE stream ([Over HTTP](#over-http)). The tool list does not change
while a server runs (`listChanged` is false) and is returned in a fixed
order.

The server's `instructions` give the loop in a few lines:

> bd tracks this workspace's work. Loop: `ready`, then `claim` an issue and
> keep the `token` it returns, work, `heartbeat` with that token during long
> work, and `close` with a reason (or `release` to give it back). A claim
> refused as held means another actor works on it: pick other work. Record
> follow-up work with `create` (`deps: ["discovered-from:<id>"]`), ordering
> with `dep_add`, and durable project insights with `remember`.

## Tools

Each tool runs the bd command of the same name in-process, as `bd serve`
runs a CLI request, so it gets the same validation, claim rules, policy
checks and events as the command line. Tool names are plain (`ready`, not
`bd_ready`): clients prefix them with the server's name.

| tool | runs | arguments | read-only |
|---|---|---|---|
| `ready` | `bd ready` | `limit` (default 10, at most 100), `label` (all of these), `type`, `assignee`, `unassigned`, `parent` | yes |
| `list` | `bd list` | `status` (list of `open`, `in_progress`, `blocked`, `deferred`, `closed`, `pinned`; default hides closed and pinned), `search`, `label`, `label_any`, `type`, `assignee`, `parent`, `blocked`, `sort` (`priority`, `created`, `updated`), `limit` (default 20, at most 100) | yes |
| `show` | `bd show` | `ids` (1 to 20) | yes |
| `create` | `bd create` | `title` (required), `description`, `type`, `priority` (0 to 4), `labels`, `parent`, `deps` (`ID` blocks, or `TYPE:ID`), `assignee`, `claim` | no |
| `update` | `bd update` | `id` (required), `title`, `description`, `design`, `acceptance`, `notes`, `append_notes`, `status` (`open`, `blocked`, `deferred`, `pinned`), `priority`, `type`, `assignee` (`""` unassigns), `add_labels`, `remove_labels`, `parent` (`""` detaches), `due`, `defer`, `if_revision` | no |
| `claim` | `bd claim` | `id`, or `next: true` with the filters `label`, `type` and `parent` | no |
| `heartbeat` | `bd heartbeat` | `id`, `token` (both required) | no |
| `close` | `bd close` | `ids` (1 to 20), `reason` (both required), `failed`, `token` | no |
| `release` | `bd release` | `id` (required), `reason`, `token` | no |
| `reopen` | `bd reopen` | `ids` (1 to 20, required), `reason` | no |
| `comment` | `bd comment add` | `id`, `text` (both required) | no |
| `dep_add` | `bd dep add` | `issue`, `depends_on` (both required), `type` (default `blocks`; `parent-child`, `conditional-blocks`, `waits-for`, `related`, `discovered-from`, `tracks`, `caused-by`, `validates`, `supersedes`, `duplicates`, `replies-to`) | no |
| `remember` | `bd remember` | `text` (required), `key` (replaces that memory) | no |
| `memories` | `bd memories` | `query` | yes |

Read-only tools carry `readOnlyHint`; the others carry `destructiveHint:
false`, since none deletes anything (`reopen` and `claim` undo `close` and
`release`). `--read-only` offers only the read-only tools; with a read
token every write fails anyway, as `unauthorized`.

Left out, as they belong to people or administrators, or would let a
model get past what the CLI asks of agents: taking over or ending other
actors' claims (`--take-over`), `--force`, `delete`, `defer` beyond
`update`, gates (`gate resolve` opens human gates), `playbook`, `batch`,
`import`/`export`, `config`, `doctor`, `events prune`, `agents`, `serve`,
`remote` and `forget`.

### Leases and tokens

`claim` (and `create` with `claim: true`) returns the lease's fencing
`token` and when it expires (`lease.ttl`, 5 minutes by default).
`heartbeat` needs the token, and `close` and `release` take it: given, they
apply only while that lease is held, so a model that lost its claim to a
reclaim stops instead of closing another holder's work. `show` reports a
claim's holder and expiry, not its token.

### Results

Results are compact JSON in one text block (no `structuredContent`, no
output schemas), so that what the model reads is short and said once:

- fields that are null, empty strings, empty lists or empty objects are
  left out, and the JSON has no indentation;
- `ready` and `list` return `{"issues": [...]}` with summaries (`id`,
  `title`, `status`, `priority`, `type`, `assignee`, `labels`), and
  `more: true` when the limit cut the list; `show` returns the full issues: their texts, dependencies,
  dependents, children, blockers, comments and lease;
- writes return the changed issue's summary and what the change caused:
  `close` the issues it unblocked, `claim` the token and expiry, `dep_add`
  whether the issue is now blocked. An empty answer (`claim` with `next`
  and nothing ready) is `{"message": "nothing matched"}`.

### Errors

A bd error is a tool result with `isError: true`, so the model sees it and
can act on it: its text is the CLI's JSON error (`{"code", "message",
"exit_code"}`, [exit codes](commands.md#exit-codes)), such as a claim held
by another actor (exit 4, naming the holder), closing another actor's
claim (`unauthorized`, exit 7, naming the holder), releasing it
(`not_owner`, exit 4) or a stale
`if_revision` (exit 13). Invalid arguments (unknown, missing, of the wrong
type or out of range) are such results too, with code `invalid` (exit 2),
so the model can correct the call. Unknown tools, malformed requests and
unsupported protocol versions are JSON-RPC errors.

### Context cost

The tool list (names, descriptions and input schemas) is written by hand,
with one-line descriptions and no output schemas, and costs about 1,500
tokens (6.4 KB); a test keeps it under 6.5 KB. The `instructions` add
about 120 tokens. Clients that load tools on
demand pay less. Most of a session's MCP context is results, which is why
lists return summaries and every result leaves out empty fields.
