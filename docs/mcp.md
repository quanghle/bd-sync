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
  ([Remote server](remote.md); see [Over HTTP](#over-http)).

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

It answers the same whether the workspace exists or not, and names no
authorization server: tokens come from the server's admin or from GitHub
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

- Claude apps (claude.ai, Claude Desktop): custom connectors sign in with
  OAuth, or, for organizations in Anthropic's beta of request headers, send
  an `Authorization` header that an organization Owner enters once. That
  header is the whole organization's, so give it a token of a shared actor
  (`--as team-claude`), with `--max-claims` if the organization should hold
  only so many issues at once.
- ChatGPT (developer mode apps) connects with OAuth or without
  authentication only, so it cannot connect until `bd serve` runs an OAuth
  authorization server. A client that tries OAuth sign-in on a 401 (ChatGPT,
  or Claude Code without the header) fails at client registration meanwhile.

Agents sharing a token add `?session=<name>` to the URL to hold their claims
under their own names (`https://bd.example.com/w/proj/mcp?session=reviewer`);
a token bound with `--resource` works under any `?session`.

### Behind a proxy

A proxy that serves bd under a path prefix may forward requests with the
prefix or without it. Set `--public-url` to the URL clients use, prefix
included, so that endpoints name themselves by it whatever reaches the
server, and forward the RFC 9728 location of the metadata too. With Caddy:

```text
example.com {
    @bd path /bd/* /.well-known/oauth-protected-resource/bd/*
    handle @bd {
        reverse_proxy 127.0.0.1:7420
    }
}
```

```bash
bd serve --root /srv/bd --public-url https://example.com/bd
curl -s https://example.com/.well-known/oauth-protected-resource/bd/w/proj/mcp
```

Clients then use `https://example.com/bd/w/proj/mcp`, and tokens are bound
to that URL. No MCP request waits for events (the server opens no SSE
streams), so a proxy's idle timeout only needs to exceed a tool call's run.

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
