# Observability

Everything is local: nothing is sent anywhere (a remote workspace talks
only to its own `bd serve`).

## Logs

Diagnostics go to stderr. `BD_LOG` filters them (`BD_LOG=bd=debug` shows
per-transaction lock-wait, exec and commit timings), and `--log-format
json` (or `BD_LOG_FORMAT=json`) emits structured logs. Colors appear only
on a terminal (`NO_COLOR` turns them off).

## Timing

`--timing` (or `BD_TIMING=1`) prints a per-command breakdown. Commands and
write transactions slower than `--slow-ms` (default 250) log `bd::slow`
warnings; slow write transactions also increment the `slow_writes`
counter.

## Workspace metrics

`bd metrics` prints Prometheus text (`--format json` for JSON):

- issues by status, ready count by priority, blocked and deferred counts;
- lease health: active, expired, expiring soon, reclaimable, oldest
  heartbeat age;
- event totals, and the last 24 hours by op;
- durable counters: `claim_conflicts`, `cas_conflicts`, `lease_lost`,
  `not_owner`, `reclaims`, `auto_prunes`, `slow_writes`;
- lead time, cycle time and queue-wait percentiles;
- database and WAL size.

## Health

`bd doctor [--fix] [--full]` checks:

- SQLite `quick_check` (`integrity_check` with `--full`), foreign keys,
  WAL mode and schema version;
- the status and lease invariants;
- blocked-flag drift against an independent full recompute;
- dependency cycles, event-sequence continuity and stale leases;
- open issues under a closed parent (a warning: left by `bd close --force`
  or `bd reopen --force`; reopen the parent or close the issue);
- with feature specs on, spec parts not in the shape `bd spec` writes
  (`malformed_specs`, a warning: `bd spec drift` lists each problem and its
  fix).

`--fix` repairs leases and blocked flags in one transaction. Problems exit
with code 1; warnings (stale leases, open issues under a closed parent,
malformed spec parts) do not.

## Server logs

`bd serve` logs under the target `bd::serve`:

- **Requests**: one line per request, with `peer` (the address it came
  from; a proxy's, behind one), `request` (the client's request id, which
  ties retries together), and `waited_ms` for a request that waited for
  events. MCP tool calls log `mcp tool call`.
- **Refusals**: one `request refused` line per request refused for its
  token: `peer` and `why` for an unknown token, plus the `token` name for
  an expired one, and `token`, `workspace` and `why` for what a token may
  not do (a read token writing, another actor, another workspace). A
  request with no token is not logged, since MCP clients send one to learn
  where to sign in.
- **Startup**: the address it listens on (also printed on stdout), its
  background job settings, which sign-in methods are on, and warnings about
  a root or secret file open to other users.
- **Background jobs**: one line per job run that changed something
  (`reclaimed expired leases`, `checked gates`, `agent sets changed`,
  `backed up`, `pruned request records`), with the workspace, counts,
  issue ids and `ms`. Failures are warnings (`background job failed`,
  `gate check failed` with the gate and the `gh` error, `agent set cannot
  be read`).
- **Sign-in**: sign-ins, refreshes, refusals and revocations, with the
  provider, subject, login, actor and token name, never a secret or an
  email ([What bd keeps about people](security.md#what-bd-keeps-about-people)).
  [Gate approvals in the browser](sign-in.md#approving-human-gates-in-the-browser)
  log `gate approval` with its `outcome` (`approved`, `refused`, `already
  resolved`, `not ready`, ...) and `gate approval refused` lines, with the
  provider, subject, login, actor, workspace and gate.
- **Sign-in secrets** ([from a command](sign-in.md#secrets-from-a-command)):
  at start, which command fetches how many secrets, then (once known, the
  server serving meanwhile) that it answered, or why the steps needing
  them are unavailable until it does; each failed attempt (every 30
  seconds) as a warning (`the [secrets] command's last answer serves until
  secrets.max_stale runs out` with how long, or `sign-in needing the
  [secrets] command's secrets is unavailable until it answers`); a step
  refused for want of one, at most once a minute with how many were left
  out (`sign-in needs a secret the [secrets] command has not given`,
  `field`, `skipped`); fields refusing a kept answer (`the fields refuse
  the [secrets] command's kept answer: asked again`), at most once a
  minute. Misconfigured sign-in seen by anonymous requests (metadata, the
  authorization server, device-flow sign-ins), and account notifications
  that cannot be handled, are likewise logged at most once a minute.
- **Limits**: connections refused over the total or per-address limit are
  warned of at most once every 10 seconds per limit, with how many were
  left out (`skipped`).
- **Panics**: one entry each (target `bd::panic`, with the message,
  location and, with `RUST_BACKTRACE=1`, a backtrace).

`BD_LOG=bd::serve=debug` adds jobs that found nothing to do, requests that
start waiting for events or find too many followers, TLS and connection
failures, and streaming details.

## Server metrics

`GET /metrics` on `bd serve`, with an admin token (`Authorization: Bearer
…`; not one bound to an MCP endpoint), answers its counters since start in
Prometheus text:

| metric | meaning |
|---|---|
| `bd_serve_responses_total{class}` | responses by status class (`1xx`…`5xx`) |
| `bd_serve_busy_total` | 503s, which clients retry |
| `bd_serve_refused_total{reason}` | requests refused for their token: `unknown_token`, `expired_token`, `forbidden` |
| `bd_serve_connections_total` | connections accepted |
| `bd_serve_connections_refused_total{limit}` | connections refused: `peer`, `total` |
| `bd_serve_connections_open` | connections open now |
| `bd_serve_commands_total` | commands run |
| `bd_serve_tool_calls_total` | MCP tool calls |
| `bd_serve_publishes_total{outcome}` | `bd publish` runs (dry runs aside), `applied` or `refused` |
| `bd_serve_approvals_total{outcome}` | human gates [approved in the browser](sign-in.md#approving-human-gates-in-the-browser), `approved`, or approvals `refused` (an account not let in, whose actor is taken, not granted kind `human` or not an approver, a refusal when posting, a post from another site); notices (expired, used, resolved, not ready, not found) are not counted |
| `bd_serve_panics_total` | panics |
| `bd_serve_start_time_seconds` | when the server started |

Counts only: no actor, token, workspace or address is a label. It answers
only at `/metrics`, never under a path prefix. Workspace metrics come from
`bd metrics`, above.
