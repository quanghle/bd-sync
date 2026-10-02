# Observability

Everything is local; nothing is sent anywhere (a remote workspace talks only to its own `bd serve`).

- **Logs**: `BD_LOG=bd=debug bd …` shows per-transaction lock-wait, exec, and commit timings on stderr. `--log-format json` emits structured logs. Colors appear only on a terminal (`NO_COLOR` turns them off), so redirected logs stay plain text.
- **Server logs**: `bd serve` logs (target `bd::serve`) one line per request (with `waited_ms` for a request that waited for events), its background job settings at startup, and one line per background job that changed something (`reclaimed expired leases`, `checked gates`, `agent sets changed`, `backed up`, `pruned request records`, with the workspace, counts, issue ids, and `ms`). Failures are warnings (`background job failed`, `gate check failed` with the gate and the `gh` error, `agent set cannot be read` with the harness and error). `BD_LOG=bd::serve=debug` also logs the jobs that found nothing to do, and each request that starts `waiting for events` or finds `too many followers`.
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
