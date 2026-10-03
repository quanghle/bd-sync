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
- Planned: `bd serve` serving each workspace at `/w/<workspace>/mcp` over
  Streamable HTTP, for remote clients, with a bd access token as its bearer
  token ([Remote server](remote.md)).

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
  revision's format, without the stateless fields.

A request without `_meta` before `initialize` is refused with `-32602`,
except `ping`. Methods served: `initialize`, `ping`, `tools/list` and
`tools/call` in both revisions, and `server/discover` in `2026-07-28`.

Only tools are served: no resources, prompts, subscriptions, sampling,
elicitation or tasks, and HTTP requests are answered with
`application/json`, never an SSE stream. The tool list does not change
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
