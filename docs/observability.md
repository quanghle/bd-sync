# Observability

Everything is local; nothing is sent anywhere (a remote workspace talks only to its own `bd serve`).

- **Logs**: `BD_LOG=bd=debug bd …` shows per-transaction lock-wait, exec, and commit timings on stderr. `--log-format json` emits structured logs. Colors appear only on a terminal (`NO_COLOR` turns them off), so redirected logs stay plain text.
- **Server logs**: `bd serve` logs (target `bd::serve`) one line per request (with `peer`, the address it came from, a proxy's behind one; `request`, the client's request id, by which its retries are told; and `waited_ms` for a request that waited for events), one `request refused` line per request refused for its access token (`peer` and `why` for an unknown or expired one, never its secret) or for what the token may not do (its `token`, `workspace` and `why`: a read token writing, another actor, another workspace; a request with no token is not logged, as MCP clients send one to learn where to sign in), its background job settings at startup, and one line per background job that changed something (`reclaimed expired leases`, `checked gates`, `agent sets changed`, `backed up`, `pruned request records`, with the workspace, counts, issue ids, and `ms`). Failures are warnings (`background job failed`, `gate check failed` with the gate and the `gh` error, `agent set cannot be read` with the harness and error). Connections refused over `MAX_CONNECTIONS` or the per-address limit are warned of at most once every 10 seconds per limit, with how many were left out (`skipped`). A panic is logged as one entry (target `bd::panic`, with its message, location and, with `RUST_BACKTRACE=1`, a backtrace), JSON logs included. `BD_LOG=bd::serve=debug` also logs the jobs that found nothing to do, and each request that starts `waiting for events` or finds `too many followers`.
- **Server metrics**: `GET /metrics` on `bd serve`, with an admin token (`Authorization: Bearer …`), answers its counters since it started in Prometheus text: `bd_serve_responses_total` by status class, `bd_serve_busy_total` (503s, which clients retry), `bd_serve_refused_total` by reason (`unknown_token`, `expired_token`, `forbidden`), `bd_serve_connections_total`, `bd_serve_connections_refused_total` by limit (`peer`, `total`), `bd_serve_connections_open`, `bd_serve_panics_total`, `bd_serve_commands_total`, `bd_serve_tool_calls_total` and `bd_serve_start_time_seconds`. Counts only: no actor, token, workspace or address is a label. Workspace metrics are `bd metrics`, below.
- **Timing**: `--timing` (or `BD_TIMING=1`) prints a per-command breakdown. Commands and transactions slower than `--slow-ms` (default 250) log `bd::slow` warnings and increment the `slow_writes` counter.
- **Metrics**: `bd metrics` prints Prometheus text, `--format json` prints JSON:
  - issues by status, ready count by priority, blocked/deferred counts
  - lease health (active, expired, expiring soon, reclaimable, oldest heartbeat age)
  - event totals and the last 24h by op
  - durable contention counters (`claim_conflicts`, `cas_conflicts`, `lease_lost`, `not_owner`, `reclaims`)
  - lead time, cycle time, and queue-wait percentiles
  - database and WAL size
- **Health**: `bd doctor [--fix] [--full]` checks:
  - SQLite `quick_check`/`integrity_check`, foreign keys, WAL mode, schema version
  - status and lease invariants
  - blocked-flag drift against an independent full recompute
  - dependency cycles, event-sequence continuity, stale leases

  `--fix` repairs leases and blocked flags in one transaction.
