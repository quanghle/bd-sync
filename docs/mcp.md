# MCP server

bd serves its coordination loop as [Model Context
Protocol](https://modelcontextprotocol.io) tools, for assistants that reach
bd through MCP rather than a shell. Where an agent has a shell, the CLI
with a session-start hook (`bd prime`) does the same with less context.

- **`bd mcp`** serves a workspace over stdio to a client on the same
  machine: the checkout's local workspace, or its remote one, with the same
  token as the CLI.
- **`bd serve`** serves each workspace at `/w/<name>/mcp` over Streamable
  HTTP, with a bd access token as the bearer token. A client may get that
  token by [signing its user in with OAuth](#signing-in-with-oauth).

A server is bound to one workspace, chosen by where `bd mcp` runs or by the
URL: no tool takes a workspace, so a tool call cannot reach another one. A
client that uses several workspaces configures one MCP server for each.

## Over stdio: `bd mcp`

The client starts `bd mcp` in the checkout; it serves the workspace a bd
command run there would use, until its input closes. `bd mcp --read-only`
offers only the read-only tools. Diagnostics go to stderr; stdout carries
only protocol messages. A message over 1 MiB is answered with an error
(`-32600`, id `null`) and skipped.

The usual client configuration:

```json
{"mcpServers": {"bd": {"command": "bd", "args": ["mcp"]}}}
```

A workspace can serve such a definition to its checkouts' agent harnesses
from `.bd/agents`; as with any MCP definition, it is written only once the
user approves it ([Agent assets](agents.md)).

**Actor.** `bd mcp` acts as a bd command run in the same environment would:
`--actor`, `$BD_ACTOR`, or the user's actor for the agent session that a
harness variable, `$BD_SESSION` or `--session` names, so an agent with
both a shell and MCP holds its claims under one name. When nothing names a
session, the process names its own, `mcp-<8 hex digits>` (acting as
`<user>/mcp-…`, or `<token actor>/mcp-…` remotely). Claims an earlier
process held then belong to another session: they expire and are
reclaimed, or the user takes them over from the CLI.

**Remote workspaces.** In a checkout with a remote workspace, `bd mcp`
forwards each tool call to the server as a CLI request with its own request
id, so its retries apply a write once ([Retries and exit
codes](remote.md#retries-and-exit-codes)).

## Over HTTP: `bd serve`

Each workspace's endpoint is `https://<host>[/<prefix>]/w/<name>/mcp`.
Every request carries a bd access token (`Authorization: Bearer
<secret>`), with the same role, workspaces and `--max-claims` as the
token's CLI requests: a read token is offered only the read-only tools.

**Actor.** Tool calls act as `<token actor>/mcp`, or `<token actor>/<name>`
for a URL ending `?session=<name>` (letters, digits, `.`, `_` and `-`, at
most 128 characters, not starting or ending with `-` or `.`), so several
agents sharing a token hold their claims under their own names.

**Transport.** Each POST carries one JSON-RPC message (`Content-Type:
application/json`, at most 1 MiB) and gets one JSON object back. There is
no SSE stream and no `Mcp-Session-Id`; methods other than POST get 405.
Each tool call runs in one of the server's command slots, as a CLI request
does.

- A `2026-07-28` request mirrors its body in headers:
  `MCP-Protocol-Version`, `Mcp-Method` and, for `tools/call`, `Mcp-Name`
  (the tool's name, or `=?base64?<name>?=`). A missing or mismatched header
  is answered 400 with `-32020` (HeaderMismatch), and the request does not
  run.
- A `2025-11-25` request (no `_meta`) names its version in
  `MCP-Protocol-Version`; one without the header is taken as `2025-11-25`.
  Each request stands alone, so `initialize` is optional over HTTP (and
  its header is not checked). Another version in the header is answered
  400 with `-32022`, except `2026-07-28` on a request without `_meta`,
  which is a header mismatch (`-32020`).

**Browsers are refused.** A request with an `Origin` header gets 403:
browsers send one with every POST and other clients none, so a web page
cannot reach the endpoint, even through DNS rebinding. The server sends no
CORS headers.

**Statuses**, in the order they are checked:

| status | when | body |
|---|---|---|
| 405 | not a POST | bd error, `Allow: POST` |
| 403 | an `Origin` header | JSON-RPC `-32600`, id `null` |
| 401 | no token, or an unknown, expired or wrongly bound one | bd error, with a `WWW-Authenticate` challenge ([Discovery](#discovery)) |
| 403 | a token limited to other workspaces | bd error, `insufficient_scope` challenge |
| 404 | an unknown workspace | bd error |
| 400 | an invalid `?session` | bd error |
| 415 | another `Content-Type` | JSON-RPC `-32600`, id `null` |
| 413 | a body over 1 MiB | bd error |
| 503 | busy | bd error |
| 400, 408 | an unreadable body, or one that came too late | bd error |
| 400 | invalid JSON (`-32700`), an invalid message (`-32600`), a header mismatch (`-32020`), an unsupported version (`-32022`) | JSON-RPC error |
| 202 | a notification or a response | empty |
| 404 | a `2026-07-28` method that is not served (`-32601`) | JSON-RPC error |
| 200 | everything else, tool errors and invalid parameters included | JSON-RPC result or error |

A bd error is `{"error": {"code", "message", "exit_code"}}`.

### Discovery

Each endpoint is an OAuth protected resource (RFC 9728). Its resource URL
is the server's URL followed by `/w/<name>/mcp`. The server's URL is
`bd serve --public-url` (or `$BD_SERVE_PUBLIC_URL`), path prefix included,
such as `https://bd.example.com/bd`. Without it, it is taken from each
request: `https` with `--tls-cert`, else `http`; the `Host` header; and the
path before `/w/`. `X-Forwarded-*` headers are never trusted, so behind a
TLS-terminating proxy, set `--public-url`.

The metadata is served without a token at the server's URL followed by
`/.well-known/oauth-protected-resource/w/<name>/mcp`, and at the RFC's own
location, with the prefix after the well-known part
(`https://bd.example.com/.well-known/oauth-protected-resource/bd/w/proj/mcp`):

```json
{"resource": "https://bd.example.com/bd/w/proj/mcp", "bearer_methods_supported": ["header"],
 "resource_name": "bd workspace proj"}
```

It answers the same whether the workspace exists or not. With `[oauth]` in
`auth.toml`, it also names the server's own authorization server
(`"authorization_servers": ["https://bd.example.com/bd"]`).

Refusals point clients at it (RFC 6750 challenges):

- no token: 401, `WWW-Authenticate: Bearer resource_metadata="<metadata URL>"`;
- an unknown, expired or wrongly bound token: 401 with
  `error="invalid_token"` and an `error_description`;
- a token limited to other workspaces: 403 with `error="insufficient_scope"`.

### Tokens bound to an endpoint

A token that should reach one workspace's tools and nothing else names
that endpoint (RFC 8707):

```bash
bd serve token create assistant --as alice --resource https://bd.example.com/bd/w/proj/mcp --root /srv/bd
```

Its workspaces become that workspace alone. It is refused (401) at any
other endpoint, at this endpoint reached under another URL (compared
normalized: lowercase scheme and host, no default port, no trailing `/`),
at `/metrics`, and for CLI requests, so a leaked token works only through
the tools. The URL compared is the one the server computes, so set
`--public-url` when clients reach the server by several names.
`bd serve token list` shows each token's `resource`. A bound token works
under any `?session`.

### Connecting clients

Create a token for the client on the server's host, bound to its
endpoint, and keep the secret in an environment variable rather than a
file:

```bash
bd serve token create laptop-agents --as alice --resource https://bd.example.com/w/proj/mcp --root /srv/bd
export BD_TOKEN=bdt_...   # the printed secret
```

Then configure the client with the endpoint's URL and the header
`Authorization: Bearer <secret>`. Many clients take a definition of this
form, expanding `${BD_TOKEN}` from their environment:

```json
{"mcpServers": {"bd": {"type": "http", "url": "https://bd.example.com/w/proj/mcp",
  "headers": {"Authorization": "Bearer ${BD_TOKEN}"}}}}
```

Clients that sign people in themselves need [OAuth](#signing-in-with-oauth):
they are given only the endpoint's URL, find the authorization server from
the 401 challenge, and open a browser for the person to sign in and
approve. A client that comes back to a fixed web address needs that
redirect URI allowed in `[oauth]`; a desktop client that listens on this
machine needs `loopback_redirects = true`. Without `[oauth]`, such clients
fail at sign-in, as the endpoint names no authorization server.

When a whole organization's client shares one header, give it a token of
a shared actor (`--as team-assistant`), with `--max-claims` if it should
hold only so many issues at once.

## Signing in with OAuth

Some MCP clients sign people in rather than send a token they were given.
For them, `bd serve` runs an OAuth 2.1 authorization server when
`<root>/auth.toml` has an `[oauth]` table. People sign in in their browser
with one of the server's [sign-in providers](sign-in.md), under the same
rules or authorizer (which is told the client) as `bd remote login`,
approve the client, and the client gets a token bound to the endpoint it
asked for.

### Setting it up

1. Configure [sign-in](sign-in.md): at least one provider, with rules or
   an authorizer. Register `<public-url>/oauth/<provider>/callback` as each
   provider's redirect URI.
2. Add `[oauth]` to `auth.toml`:

   ```toml
   [oauth]
   redirect_uris = ["https://assistant.example/oauth/callback"]  # these https redirect URIs exactly
   # redirect_hosts = ["assistant.example"]         # or any https path on these hosts
   loopback_redirects = true                        # and http://127.0.0.1, [::1] or localhost, any port
   # registration = false                           # only clients with metadata documents (default true)
   ```

3. Run `bd serve` with an https `--public-url` (http only on a loopback
   address, for trying it out): it is the issuer, which clients check.

| field | default | meaning |
|---|---|---|
| `redirect_uris` | none | https URIs allowed exactly (DNS host, no port, user info or fragment) |
| `redirect_hosts` | none | hosts (DNS names of at least two labels, no IP or port) on which any https path is allowed |
| `loopback_redirects` | `false` | allow `http://127.0.0.1`, `[::1]` and `localhost` on any port, for desktop clients |
| `registration` | `true` | allow dynamic client registration (RFC 7591) |

At least one kind of redirect must be allowed. `bd serve` refuses to start
with `[oauth]` but no sign-in provider, or without a suitable
`--public-url`. `bd serve check --root DIR --public-url URL` prints the
callback URLs to register and the MCP endpoints to give clients. Like the
rest of `auth.toml`, `[oauth]` is read again when the file changes, so it
can be added or removed without a restart.

### The flow

The authorization server's metadata (RFC 8414) is at
`https://bd.example.com/.well-known/oauth-authorization-server/bd` (with
no path in the public URL, `/.well-known/oauth-authorization-server`). A
client that reaches an endpoint without a token follows the 401 challenge
to the endpoint's metadata, then the authorization server's, and then:

1. **Identifies itself**, as a public client (no client secret):
   - **with a client ID metadata document**: its `client_id` is an https
     URL (at most 1024 characters, a path other than `/`, no query or
     fragment) of a JSON document naming its redirect URIs (at most 32)
     and token auth method `none`. bd fetches it when first used (see
     [Security](security.md#oauth-for-mcp-clients) for how), keeps it for
     its `Cache-Control` max-age (5 minutes by default, an hour at most),
     and fetches its `logo_uri` with it. Grant and response types bd does
     not offer are ignored, as long as the document has the authorization
     code.
   - **by registering** at `<public-url>/oauth/register` (RFC 7591, no
     token; 404 with `registration = false`): up to 8 redirect URIs of 512
     bytes each, a `client_name` of at most 100 characters. Registered
     clients get ids `bdc_…` and are kept in `server.db`: one never used is
     dropped after a day, one unused for 90 days after that. With 500
     kept, a new registration drops the oldest never used, or is refused
     (503) if all are in use.

   Every redirect URI must be one `[oauth]` allows. For a loopback URI the
   port is ignored when compared, since a desktop client listens on
   whatever port is free.
2. **Sends the person to `<public-url>/oauth/authorize`** for an
   authorization code with PKCE (`S256` only), naming as `resource`
   (RFC 8707, required) the endpoint it wants. The browser signs in with a
   provider (chosen at `/oauth/choose` when there are several), which
   sends it back to the provider's callback. If the rules or the
   authorizer let the account into the workspace, a consent page shows:
   the client's name and where its details come from (its metadata
   document's full URL and logo, or, for a registered client, a warning
   that its name is not verified), the full redirect URI (with a warning
   when it is this machine, or a site other than the document's), the
   workspace, the provider and the account (its verified email, else its
   login), the actor, the access granted, what
   let the account in, and how long access lasts. Approving sends the
   browser back with a code and the issuer (`iss`, RFC 9207); denying,
   with `access_denied`.
3. **Redeems the code** at `<public-url>/oauth/token` within 5 minutes,
   with its `client_id`, PKCE verifier, its redirect URI if it sends one,
   and optionally the same `resource`. A code is good for one request,
   refused or not, except one the server failed to answer (500, or 503
   when busy), which can be sent again.

An account the rules refuse gets a page saying so, with a link back to the
client. A workspace the server does not have is reported
(`invalid_target`) only after the rules let the account in, so strangers
cannot probe which workspaces exist. Each step must follow within 10
minutes, and a restart ends authorizations in progress.

### The client's tokens

- act as the account's actor, and tool calls as `<actor>/mcp`, with what
  the rule grants (role, kind, `max_claims`). They are bound to the
  endpoint, so they work there only, and never for CLI requests;
- expire after `token_ttl`, and are refreshed at the token endpoint by the
  client they were issued to, deciding again as for any sign-in
  ([Refreshing](sign-in.md#refreshing)), until `refresh_limit` or
  `refresh_idle`. Each refresh replaces both tokens;
- resist replay: a code works once, and the same code sent again by its
  own client with its PKCE verifier revokes the tokens it issued. A
  refresh token works once, with no grace period: one sent again revokes
  the sign-in. A client that lost a refresh's answer has the person
  authorize again. OAuth refresh tokens are refused at the CLI's
  `/v2/auth/refresh`;
- can be revoked by the client (RFC 7009) at `<public-url>/oauth/revoke`,
  by either secret, ending the sign-in. It answers 200 for any token
  (leaving tokens other than OAuth clients' alone), and 400 for a request
  without a `token`.

Admins see these tokens in `bd serve token list`, named
`oauth-<client label>-<actor>-<random>` with their `client`.
`bd serve token revoke --client <client_id>` revokes every token of a
client, and `--account <login>` every token of an account.

### Behind a proxy

A proxy that serves bd under a path prefix may forward requests with the
prefix or without it. Set `--public-url` to the URL clients use, prefix
included, and forward these paths to bd:

- `/<prefix>/*`: the workspaces, MCP endpoints and OAuth endpoints;
- `/.well-known/oauth-protected-resource/<prefix>/*`: the endpoints'
  metadata at the RFC's location;
- `/.well-known/oauth-authorization-server/<prefix>`: the authorization
  server's metadata, with `[oauth]`.

```bash
bd serve --root /srv/bd --public-url https://example.com/bd
curl -s https://example.com/.well-known/oauth-protected-resource/bd/w/proj/mcp
curl -s https://example.com/.well-known/oauth-authorization-server/bd   # with [oauth]
```

Clients then use `https://example.com/bd/w/proj/mcp`, and tokens are bound
to that URL. No MCP request waits for events, so the proxy's idle timeout
only needs to exceed a tool call's run.

**Rate limits.** With `[oauth]`, anyone can call the endpoints under
`/oauth/` without a token (registering clients, starting sign-ins,
sending codes), and the device-flow endpoints under `/v2/auth/` too. bd
bounds what they keep and how many run at once, but not how often a caller
sends requests: rate-limit them per client address at the proxy. They
answer under the public URL's path (`/bd/oauth/…`) or with it stripped
(`/oauth/…`), so limit every request whose path contains `/oauth/` or
`/v2/auth/`.

## Protocol

bd implements MCP itself (JSON-RPC 2.0, no SDK) and speaks two revisions:

- **`2026-07-28`**, stateless. Every request carries its protocol version
  and client capabilities in `_meta`
  (`io.modelcontextprotocol/protocolVersion`, `…/clientCapabilities`).
  Methods: `server/discover` (supported versions, capabilities,
  instructions), `ping`, `tools/list`, `tools/call`; anything else,
  `initialize` included, gets `-32601`. Results carry `resultType`, the
  server's `serverInfo` in `_meta`, and `ttlMs` (one hour) and
  `cacheScope` on `server/discover` (`public`) and `tools/list`
  (`private`). A request naming another version in `_meta` gets `-32022`,
  with the `supported` and `requested` versions in its data.
- **`2025-11-25`**, session-based, for clients that start with
  `initialize`. The answer names `2025-11-25` whatever version was asked,
  with capabilities, `serverInfo` and `instructions`. Over stdio, requests
  without `_meta` are then served in that revision until the process ends;
  before `initialize`, only `ping` is (anything else gets `-32602`). Over
  HTTP, every request counts as initialized.

Only tools are served: no resources, prompts, subscriptions, sampling,
elicitation or tasks. The tool list never changes while a server runs
(`listChanged` false) and comes in a fixed order. Batches are refused
(`-32600`), `params` must be an object, and invalid JSON gets `-32700`.

The server's `instructions`:

> bd tracks this workspace's work. Loop: `ready`, then `claim` an issue and
> keep the `token` it returns, work, `heartbeat` with that token during long
> work, and `close` with a reason (or `release` to give it back). A claim
> refused as held means another actor works on it: pick other work. Record
> follow-up work with `create` (`deps: ["discovered-from:<id>"]`), ordering
> with `dep_add`, and durable project insights with `remember`.

## Tools

Each tool runs the bd command of the same name in-process, with the same
validation, claim rules, policy checks and events as the command line.
Tool names are plain (`ready`, not `bd_ready`); clients prefix them with
the server's name.

| tool | runs | arguments | read-only |
|---|---|---|---|
| `ready` | `bd ready` | `limit` (1–100, default 10), `label` (all of these), `type`, `assignee`, `unassigned`, `parent` | yes |
| `list` | `bd list` | `status` (list of `open`, `in_progress`, `blocked`, `deferred`, `closed`, `pinned`; default hides closed and pinned), `search`, `label`, `label_any`, `type`, `assignee`, `parent`, `blocked`, `sort` (`priority`, `created`, `updated`), `limit` (1–100, default 20) | yes |
| `show` | `bd show` | `ids` (1–20, required) | yes |
| `create` | `bd create` | `title` (required), `description`, `type` (default task), `priority` (0–4, default 2), `labels`, `parent`, `deps` (`ID`, which blocks, or `TYPE:ID`), `assignee`, `claim` | no |
| `update` | `bd update` | `id` (required), `title`, `description`, `design`, `acceptance`, `notes`, `append_notes`, `status` (`open`, `blocked`, `deferred`, `pinned`), `priority`, `type`, `assignee` (`""` unassigns), `add_labels`, `remove_labels`, `parent` (`""` detaches), `due`, `defer`, `if_revision` | no |
| `claim` | `bd claim` | `id`, or `next: true` with the filters `label`, `type` and `parent` | no |
| `heartbeat` | `bd heartbeat` | `id`, `token` (both required) | no |
| `close` | `bd close` | `ids` (1–20) and `reason` (both required), `failed`, `token` | no |
| `release` | `bd release` | `id` (required), `reason`, `token` | no |
| `reopen` | `bd reopen` | `ids` (1–20, required), `reason` | no |
| `comment` | `bd comment add` | `id`, `text` (both required) | no |
| `dep_add` | `bd dep add` | `issue`, `depends_on` (both required), `type` (default `blocks`; any [dependency type](concepts.md#dependency-types) but custom ones) | no |
| `remember` | `bd remember` | `text` (required), `key` (replaces that memory) | no |
| `memories` | `bd memories` | `query` | yes |

- List arguments (`label`, `label_any`, `labels`, `deps`, `add_labels`,
  `remove_labels`) take at most 20 non-blank items. `title` and `text` must
  not be blank. Unknown arguments are refused; `null` counts as absent.
- `update` needs at least one field to change besides `id` and
  `if_revision`. `claim` takes `id` or `next`, not both, and filters only
  with `next`.
- Read-only tools carry `readOnlyHint`; the others `destructiveHint:
  false`, since none deletes anything. `--read-only` offers only the
  read-only tools; with a read token every write fails anyway.

**Left out**, as they belong to people or administrators, or would let a
model get past what the CLI asks of agents: taking over or ending other
actors' claims (`--take-over`), `--force`, `delete`, `defer` beyond
`update`, gates, playbooks, `batch`, `import`/`export`, `config`,
`doctor`, `events prune`, `agents`, `serve`, `remote` and `forget`. Tool
calls never carry the token's admin or human rights, locally or on a
server, so a model cannot take over another actor's claim or open a human
gate.

### Leases and tokens

`claim` (and `create` with `claim: true`) returns the lease's fencing
`token` and when it expires (`lease.ttl`, 5 minutes by default).
`heartbeat` needs the token, and `close` and `release` take it: given,
they apply only while that lease is held, so a model that lost its claim
to a reclaim stops instead of closing another holder's work. `show` reports
a claim's holder and expiry, not its token.

### Results

Results are compact JSON in one text block (no `structuredContent`, no
output schemas), so the model reads each thing once:

- null fields, empty strings, empty lists and empty objects are left out
  (an empty `ready` is `{}`), and the JSON has no indentation;
- `ready` and `list` return `{"issues": [...]}` with summaries (`id`,
  `title`, `status`, `priority`, `type`, `assignee`, `labels`), and
  `more: true` when the limit cut the list; `show` returns full issues
  with their texts, dependencies, dependents, children, blockers, comments
  and lease;
- writes return the changed issue's summary and what the change caused:
  `close` the issues it unblocked, `claim` the token and expiry, `dep_add`
  whether the issue is now blocked. Nothing to claim is
  `{"message": "nothing matched"}`;
- control and bidirectional formatting characters are escaped as `\u…`; a
  call may print at most 4 MiB.

### Errors

A bd error is a tool result with `isError: true`, so the model sees it and
can act on it. Its text is the CLI's JSON error (`{"code", "message",
"exit_code"}`, [exit codes](commands.md#exit-codes)):

- a claim held by another actor: `already_claimed`, exit 4, naming the
  holder;
- releasing another actor's claim: `not_owner`, exit 4;
- closing another actor's claim: `unauthorized`, exit 7, naming the
  holder; or, over a server, `not_owner`, exit 4, when the holder is the
  token's own actor or another of its sub-actors (another `?session`);
- a stale `if_revision`: exit 13;
- invalid arguments (unknown, missing, wrong type or out of range):
  `invalid`, exit 2, so the model can correct the call.

Unknown tools, a write tool on a read-only server, malformed requests and
unsupported protocol versions are JSON-RPC errors instead.

### Retries

MCP gives a tool call no request id to deduplicate by, so a client that
resends a call after losing its answer runs it again: `create` creates a
second issue; `claim` of the issue it already holds fails with
`already_claimed` naming its own actor (the holder may still `release` or
`close` without the token, and claim again); `close` of a closed issue
succeeds with `already_closed: true`. After a lost answer, `show` or
`list` tells whether a write took effect. (`bd mcp` in a remote workspace
forwards each call with its own request id, so its own retries to the
server are safe.)

### Context cost

The tool list (names, descriptions and input schemas) is written by hand,
with one-line descriptions and no output schemas, and costs about 1,500
tokens (6.4 KB; a test keeps it under 6.5 KB). The `instructions` add
about 120 tokens. Most of a session's MCP context is results, which is why
lists return summaries and results leave out empty fields.
